# xila-package-builder

The native `xila-package` command creates **self-contained Xila application
bundles** from a developer-managed source directory. An application bundle is
just a directory: no VFS installation, activation database, or install hook.

The crate is also a library: `CommandLine` is the parsed command line,
`execute` runs it and `run` parses and runs raw arguments. Other host tools,
such as the `xila package` subcommand of
[`xila-project/tools`](https://github.com/xila-project/tools), embed it so that
they run exactly the same code as `xila-package`.

## Recommended workflow

### 1. Initialize the developer source directory

```sh
xila-package bundle init ./weather example.xila.weather 1.0.0 wasm32-wasip1 --xila-version 0.1 \
  --entrypoint executables/weather.wasm \
  --display-name Weather \
  --icon resources/icon.png
```

`init` creates `weather/xila-package.json` plus `executables/` and `resources/`.
The developer manifest includes identity, package version, minimum Xila
version, capability requests and application metadata. The builder generates
hashes and signatures. Edit the manifest directly and place the compiled
executable and any resources in the source tree:

```text
weather/
  xila-package.json             # developer configuration (editable)
  executables/weather.wasm               # compiled binary
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
  executables/weather.wasm
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

**A bundle is its archive, extracted.** Like a macOS `.app`, the directory is
self-contained and runnable as is: extracting a `.xpk` yields exactly this
tree, which the installer moves to `/applications/bundles/<package-id>/`.
`executables/` mirrors Xila's `/applications/executables`, and bundle-local
paths such as `@bundle/executables/weather.wasm` in `shortcut.json` resolve
against the bundle directory. Use `bundle archive` rather than a plain `tar`:
`.xila/manifest.json` must be the first entry (followed by `.xila/manifest.sig`
when signed) so devices can verify the archive while streaming it.

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
the bundle. The developer or release infrastructure manages key storage,
recovery and trust separately. Avoid checking private keys into git.

To create a key pair explicitly:

```sh
xila-package key generate ./signing/private.seed ./signing/public.key
xila-package key public ./signing/private.seed ./signing/public.key  # re-derive later
```

`key` commands are stateless: they only write the paths given, never
overwrite an existing file, and create the seed owner-only (`0600`) on Unix.
Generate a separate key pair for each package identifier. Store the private seed as a secret in the repository that builds that package.

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

### 4. Publish a package entry

Generate the entry from the signed archive and its raw public key.

```sh
xila-package registry entry ./Weather.xpk ./signing/public.key https://xila.example/Weather.xpk ./1.0.0.json
xila-package registry verify ./1.0.0.json ./Weather.xpk
```

The entry pins the package key, archive URL, SHA-256 and size. It copies the
identity, compatibility, capabilities and optional catalog metadata from the
signed manifest. Set `metadata.author` in the developer manifest to display
the author. `registry verify` uses the key in the entry to check the archive
signature and file hashes and compares the signed manifest with the entry.

For first publication, submit the namespace ownership claim for the
identifier. Check the claim's structure locally.

```sh
xila-package registry check-owner ./1.0.0.json ./claim.json
```

The registry submission process checks control of the domain or account.
Continue to use the same package key for later versions. To rotate it,
generate a new key and sign the next generation with the previous seed.

```sh
xila-package key generate ./signing/next.seed ./signing/next.pub
mkdir -p ./registry/rotations/example/xila/weather
xila-package registry rotate example.xila.weather 2 ./signing/private.seed ./signing/next.pub ./registry/rotations/example/xila/weather/2.json
xila-package bundle build ./weather ./Weather-next.app --signing-key ./signing/next.seed
xila-package bundle archive ./Weather-next.app ./Weather-next.xpk
xila-package registry entry ./Weather-next.xpk ./signing/next.pub https://xila.example/Weather-next.xpk ./1.1.0.json --generation 2
xila-package registry check-rotation ./registry ./1.0.0.json ./1.1.0.json
```

Set the developer manifest's version to `1.1.0` before building the new
archive. Submit the rotation JSON and its `.sig` together. Store entries in
`packages/<identifier with dots as slashes>/<version>.json`.

```sh
xila-package registry check ./registry --previous ./approved-registry --archives ./downloads
```

`check` validates the entries and rotation histories. With `--previous`, it
preserves the approved entries and rotations and checks that new versions use
the current key. `--archives` takes the downloaded archives, named after their
URLs. The command reads these files locally.

### 5. Sign the registry (registry maintainers)

Devices pin a **root** key and trust nothing else; see
[registry-trust.md](../../docs/registry-trust.md) for the model and file formats.

To start a new registry from scratch, `registry init` creates the layout
(`root.json`, `root.json.sig`, `root.pub`, `rotations/`, `packages/`),
generates the root and repository keys, and lists the repository key in
`root.json`. The private seeds go to a directory you choose, outside the
registry, created owner-only (`0600` files); keep the root seed offline:

```sh
xila-package registry init ./registry ~/.xila-registry-keys
```

The steps below do the same by hand, which is also how a root is rotated.

```sh
# Offline, with the root key: name the online repository key (version must increase).
xila-package key generate ./root.seed ./root.pub
xila-package key generate ./repository.seed ./repository.pub
xila-package registry root ./root.seed root-2026 ./repository.pub repository-2026 1 ./registry/root.json

# On publication, with the repository key: check, then sign into a new directory.
xila-package registry sign ./registry ./root.pub ./repository.seed ./_site --expires-in-days 30
xila-package registry verify-signed ./_site ./root.pub
```

`registry root` writes `root.json` and `root.json.sig`. `registry sign`
checks the registry, signs its entries, copies the package-signed rotations
and creates the signed index. The index uses the signing time unless you
supply `--version`. `verify-signed` checks the published files and rotation
chains from the pinned root. It checks expiry with the current time by
default. Pass `--now 0` to skip the expiry check.

## Compatibility and scope

The legacy `xila-package manifest generate/update/application` and
`xila-package pack SOURCE MANIFEST ARCHIVE [SIGNATURE]` commands remain
available for existing scripts and the old reusable Wasm workflow; they work
directly with the generated runtime manifest format. Pass `--xila-version`
with a `major.minor` value to `manifest generate` or `bundle init`. Prefer `bundle init`
and `bundle build` for new applications.

The target given to `bundle init` is a Rust target triple, dots included
(`thumbv8m.main-none-eabihf`). To check whether a package built for one target
runs on a device target, as devices do before installing it (see
[target compatibility](../../docs/registry-trust.md#target-compatibility)):

```sh
xila-package target compatible riscv32imc-unknown-none-elf riscv32imac-unknown-none-elf
```

Xila VFS operations will eventually be implemented in an app under
`xila-project/applications`, and Shell will discover unpacked bundles.
Neither feature is part of this host-side build implementation.
