# xila-package-builder

The native `xila-package` command creates **self-contained Xila application
bundles** from a developer-managed source directory. An application bundle is
just a directory: no VFS installation, activation database, or install hook.

## Recommended workflow

### 1. Initialize the developer source directory

```sh
xila-package bundle init ./weather community.weather 1.0.0 wasm32-wasip1 1 \
  --entrypoint bin/weather.wasm \
  --display-name Weather \
  --icon resources/icon.png
```

`init` creates `weather/xila-package.json` plus `bin/` and `resources/`.
The developer manifest includes identity, version, ABI, capability requests
and application metadata, **but no generated hashes or signatures**. Edit it
directly and place the compiled executable and any resources in the source tree:

```text
weather/
  xila-package.json             # developer configuration (editable)
  bin/weather.wasm               # compiled binary
  resources/icon.png
  resources/translations/en.json
  resources/fonts/font.bin
```

Editor schema: [developer-manifest.schema.json](../../schemas/developer-manifest.schema.json).
For a standalone executable package, pass `--standalone`; its generated
runtime manifest will contain `"application": null`.

### 2. Build the bundle

```sh
xila-package bundle build ./weather ./Weather.app
xila-package bundle verify ./Weather.app
xila-package bundle archive ./Weather.app ./Weather.xpk
```

The resulting bundle is independent from the source:

```text
Weather.app/
  .xila/manifest.json          # generated runtime manifest and full inventory
  .xila/manifest.sig           # present only when signed
  bin/weather.wasm
  resources/icon.png
  resources/translations/en.json
  resources/fonts/font.bin
```

The build tool scans **all regular payload files**, excluding the developer
manifest, and creates a canonical runtime manifest with **path, size and
SHA-256 for each binary and resource**. It verifies the output contents before
publishing the bundle directory. It rejects unexpected metadata, symlinks,
invalid entrypoints/icons and unsafe paths. The optional `.xpk` is a
deterministic USTAR distribution archive of the same tree, not an installation
transaction.

### 3. Sign the complete bundle (optional for local development)

To sign during build, explicitly supply a developer-owned Ed25519 private
key as a file containing a **raw 32-byte seed**, stored **outside the
source directory**:

```sh
xila-package bundle build ./weather ./Weather.app --signing-key ./signing/private.seed
xila-package bundle verify ./Weather.app --public-key ./signing/public.key
xila-package bundle archive ./Weather.app ./Weather.xpk
```

The verifying key is a raw **32-byte Ed25519 public key**. The builder never
generates a private identity silently, and never copies a private key into
the bundle. The developer or release infrastructure manages key creation,
storage, recovery and trust separately. Avoid checking private keys into git.

For a hardware signer, KMS or separate signing job, export the exact
domain-separated signing message and attach the returned detached signature:

```sh
xila-package bundle build ./weather ./Weather.app
xila-package bundle signing-payload ./Weather.app ./to-sign.bin
# Sign ./to-sign.bin externally with ordinary Ed25519 (not Ed25519ph);
# write a raw 64-byte signature to ./signature.bin
xila-package bundle attach-signature ./Weather.app ./signature.bin ./signing/public.key
xila-package bundle verify ./Weather.app --public-key ./signing/public.key
xila-package bundle archive ./Weather.app ./Weather.xpk
```

**What is signed?** Only the exact generated `.xila/manifest.json` bytes
(using `signed_message_into` for domain separation), **not just the Wasm,
and not the TAR padding**. This manifest contains SHA-256 hashes for every
bundle file, including icons, translations, fonts and assets. Altering any
one of them invalidates the bundle, even though the Ed25519 signature file
itself is only 64 bytes and remains unchanged. The detached signature is kept
in `.xila/manifest.sig` to avoid signing itself.

A bundle without `.xila/manifest.sig` is for unsigned local development.
Verification **without** `--public-key` checks file integrity, not publisher
identity. Only verification with a caller-trusted public key authenticates
a signature. No trust policy or key-distribution service is implemented here.

## Compatibility and scope

The legacy `xila-package manifest generate/update/application` and
`xila-package pack SOURCE MANIFEST ARCHIVE [SIGNATURE]` commands remain
available for existing scripts and the old reusable Wasm workflow; they work
directly with the generated runtime manifest format. Prefer `bundle init`
and `bundle build` for new applications.

Xila VFS operations will eventually be implemented in an app under
`xila-project/applications`, and Shell will discover unpacked bundles.
Neither feature is part of this host-side build implementation.
