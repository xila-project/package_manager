# xila-package-builder

Native `xila-package` command-line tool for creating and inspecting Xila
package archives. It is **host-only** and uses `getargs-derive` for typed
subcommands and built-in help.

## Example commands

```sh
xila-package manifest generate ./app ./manifest.json community.weather 1.0.0 wasm32-wasip1 1
xila-package manifest update ./app ./manifest.json
# Optional: turn a standalone payload package into a discoverable app
xila-package manifest application ./manifest.json bin/weather.wasm Weather
xila-package pack ./app ./manifest.json ./weather.xpk
```

The source directory contains application files and the manifest JSON
is stored outside that directory. `manifest update` recalculates file sizes
and digests while preserving the manifest identity and capabilities;
`manifest application` adds an entrypoint and display metadata to the same
experimental v1 manifest. Configure this **before** signing;
`pack` verifies the archive through the separate TAR reader.

An optional final argument to `pack` provides an externally generated,
raw 64-byte Ed25519 signature. The builder does not sign packages or
decide which keys are trusted, and unsigned archives are development-only.

## Building self-contained application bundles

A Xila **application** is a complete, relocatable directory (analogous to a
macOS .app), **not** an install transaction. No Xila VFS, Shell/Launcher, Dock,
or install hooks are involved in building.

After generating/updating a manifest and declaring its application metadata:

```sh
xila-package bundle build ./app ./manifest.json ./Weather.app
xila-package bundle archive ./Weather.app ./Weather.xpk
```

The resulting directory is immediately self-contained:

```text
Weather.app/
  .xila/manifest.json             # canonical experimental v1 JSON
  .xila/manifest.sig              # optional detached Ed25519 signature
  bin/weather.wasm                # app entrypoint (declared in manifest)
  share/icons/weather.png         # declared resources
```

The bundle builder validates the complete source-file inventory, lengths and
SHA-256 before copying, then verifies every file after copying. It refuses
symlinks, unexpected or undeclared files, nested outputs, and existing
destinations. It builds in a private sibling directory and publishes only
when complete. The archive subcommand validates the bundle's manifest,
declared payloads and metadata before reusing the deterministic TAR writer.
An archive contains exactly the same relative paths as the directory, so
unpacking it produces a directly discoverable bundle.

**Executable versus application:** a standalone executable package may have
`application: null`; an application has an `application` object that identifies its
entrypoint and optional icon inside the bundle. Bundle construction does not
execute the program and does not add Dock shortcuts.

Optional external signing remains supported:

```sh
xila-package bundle build ./app ./manifest.json ./Weather.app ./manifest.sig
xila-package bundle archive ./Weather.app ./Weather.xpk
```

The raw 64-byte signature must have been created over the exact manifest
using `signed_message_into` before building. This host tool preserves it
unchanged; it does not generate signing keys or determine which keys are trusted.
A signature is absent in unsigned development bundles.

For compatibility, `xila-package pack SOURCE MANIFEST ARCHIVE [SIGNATURE]`
still builds the TAR directly without an intermediate directory.

## Automated packaging

Other GitHub repositories can use the
[reusable Wasm packaging workflow](https://github.com/Xila-Project/package_manager/blob/main/docs/reusable-wasm-package-workflow.md)
to stage a compiled Wasm, update its manifest, and optionally upload a
GitHub Actions artifact or attach the package to a GitHub Release.
This workflow is separate from the device-side installer.
