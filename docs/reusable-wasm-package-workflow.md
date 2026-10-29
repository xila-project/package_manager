# Reusable Xila Wasm packaging workflow

Call the published reusable workflow from another GitHub repository to produce a
validated Xila package from an existing **Wasm Actions artifact** and a
**versioned Xila archive manifest**. It does not compile your Wasm, run the
application or publish the package to `xila-project/packages`.

## Caller example

```yaml
name: Publish weather package
on:
  push:
    tags: [v*]

jobs:
  build-wasm:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      # Example: substitute your actual Wasm build command here.
      - run: cargo build --release --target wasm32-wasip1
      - uses: actions/upload-artifact@v7
        with:
          name: weather-wasm
          path: target/wasm32-wasip1/release/weather.wasm

  package:
    needs: build-wasm
    permissions:
      contents: write # only needed for publish-release
    uses: Xila-Project/package_manager/.github/workflows/package-wasm.yml@main
    with:
      wasm-artifact: weather-wasm
      manifest-path: packaging/manifest.json
      # wasm-path: weather.wasm    # optional if artifact has one .wasm file
      artifact-name: weather-package
      upload-artifact: true
      publish-release: true
      release-tag: ${{ github.ref_name }}
```

For a pull request, set `publish-release: false` and grant only
`contents: read`. For a production release, pin the reusable workflow
revision to an immutable Git commit, and optionally set `builder-ref` to
that same reviewed revision rather than the default `main`.

A **previous job must upload** the Wasm file using
`actions/upload-artifact`. The reusable workflow downloads it from the
same workflow run; ordinary files left on a different job's runner are
not shared between jobs. The manifest is read from the calling repository
at `manifest-path`, unless `manifest-artifact` is provided to download
a manifest produced by an earlier job.

## Required manifest

Use the current `xila-package-manifest` JSON wire format (not the
registry TOML declaration). It must declare exactly **one** file ending in
`.wasm`. In this first iteration, other assets and multiple payloads are
not supported.

```json
{
  "format_version": 1,
  "name": "community.weather",
  "version": "1.0.0",
  "target": "wasm32-wasip1",
  "minimum_xila_abi": 1,
  "capabilities": [],
  "files": [{
    "path": "bin/weather.wasm",
    "size": 0,
    "sha256": "0000000000000000000000000000000000000000000000000000000000000000"
  }]
}
```

The placeholders are acceptable because the workflow stages the Wasm at
the declared path, runs `xila-package manifest update` to compute its
actual SHA-256 and size, then calls `xila-package pack`. The resulting
archive is checked through the existing Rust reader. The source JSON
is never modified in your repository.

## Publication behavior

By default it uploads `<name>-<version>-<target>.xpk` and
`<name>-<version>-<target>.xpk.sha256` as a 14-day GitHub Actions
artifact. Set `upload-artifact: false` if the archive should not be
retained unless used internally for release publication.

Setting `publish-release: true` attaches both files to a GitHub Release
in the **calling repository**, creating the release if necessary. The
`release-tag` must already exist and reference the exact commit running
the workflow. The called workflow refuses to publish for pull request
events and does not create tags or overwrite release assets. The calling
job must explicitly grant `contents: write`; the package-building job
itself only has read access.

The output values `filename`, `sha256`, and `artifact-name` are
available as `needs.package.outputs.filename`, etc. This packaging
workflow is independent from release-plz: use your own release-plz
process to create versioned tags, then attach your package artifacts
using this workflow.

**Security and format status:** By default, CI packages are unsigned.
On trusted `main` pushes only, `sign-artifact: true` generates an ephemeral
Ed25519 key *per package job*, signs the canonical manifest, verifies the
package, and publishes the signed archive together with its SHA-256 checksum
and raw 32-byte public key. The Actions artifact contains:

- `<name>-<version>-<target>.xpk`
- `<name>-<version>-<target>.xpk.sha256`
- `<name>-<version>-<target>.xpk.pub`

Verify locally with `xila-package verify archive.xpk archive.xpk.pub`.
The ephemeral private key never leaves the signing job, and the public key
is **not trusted** simply because it is shipped beside the archive.
An installer must independently decide whether to allow unrecognized
signers. Pull-request artifacts remain unsigned; tagged-release signing
still uses OpenBao with a separately pinned release key.

