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
manifest (upgrading v1 to v2). Configure this **before** signing;
`pack` verifies the archive through the separate TAR reader.

An optional final argument to `pack` provides an externally generated,
raw 64-byte Ed25519 signature. The builder does not sign packages or
decide which keys are trusted, and unsigned archives are development-only.

## Automated packaging

Other GitHub repositories can use the
[reusable Wasm packaging workflow](https://github.com/Xila-Project/package_manager/blob/main/docs/reusable-wasm-package-workflow.md)
to stage a compiled Wasm, update its manifest, and optionally upload a
GitHub Actions artifact or attach the package to a GitHub Release.
This workflow is separate from the device-side installer.
