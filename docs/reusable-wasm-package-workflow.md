# Reusable Xila Wasm packaging workflow

Call the published reusable workflow from another GitHub repository to produce a
validated Xila package from an existing **Wasm Actions artifact** and a
**versioned Xila archive manifest**. It does not compile your Wasm, run the
application or publish the package to `xila-project/registry`.

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

To reuse a published Linux x86_64 `xila-package` executable instead of
installing Rust and compiling `xila-package-builder` in every `package` and
`sign` job, set both `builder-release` (for example
`xila-package-builder-v0.4.0`) and `builder-sha256` (the lowercase hexadecimal
SHA-256 digest of `xila-package-x86_64-unknown-linux-gnu.tar.gz`). When set,
both `package` and `sign` download that release archive, verify its SHA-256
digest, check that `xila-package --version` matches the release tag, and skip
compiling from source. When omitted, the workflow compiles
`xila-package-builder` from `builder-ref`. Keep `builder-ref` pinned so the
Python staging and signing helper scripts come from a reviewed commit. The
release must be compatible with those scripts: pin `builder-ref` to the commit
that `builder-release` points to, otherwise an older release that lacks a
command the scripts call would only fail in `sign`, on `main`.

```yaml
    with:
      wasm-artifact: weather-wasm
      manifest-path: packaging/manifest.json
      builder-ref: <pinned-commit>
      builder-release: xila-package-builder-v0.4.0
      builder-sha256: 02905040ef0c241c0cb6b006b729a0ee255b66b7e38ff938c8c12dac5df18554
```

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
  "format_version": 2,
  "name": "example.xila.weather",
  "version": "1.0.0",
  "target": "wasm32-wasip1",
  "xila_version": "0.1",
  "capabilities": [],
  "files": [{
    "path": "executables/weather.wasm",
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

Setting `publish-release: true` signs the package (see below) and attaches
the `.xpk`, `.sha256` and `.pub` files to a GitHub Release in the **calling
repository**, creating the release if necessary. The `release-tag` must
already exist and reference the exact commit running the workflow. Publishing
is allowed on pushes to `main` (release-plz creates tags from the main push
itself, and tags created with `GITHUB_TOKEN` trigger no workflow) and on tag
pushes. The called workflow refuses to publish for pull request events and
does not create tags or overwrite release assets. The calling
job must explicitly grant `contents: write`; the package-building job
itself only has read access.

The output values `filename`, `sha256`, and `artifact-name` are
available as `needs.package.outputs.filename`, etc. This packaging
workflow is independent from release-plz. With release-plz, a simpler option
is to package with `sign-artifact: true` on `main`, run release-plz after the
package jobs, and `gh release upload` the already signed artifacts for each
entry of its `releases` output.

**Security and format status:** By default, CI packages are unsigned.
On trusted `main` pushes, `sign-artifact: true` (and `publish-release: true`) requires the caller
to pass the `XILA_DEV_SIGNING_SEED_B64` Actions secret (base64 of a 32-byte
Ed25519 private seed). It signs the canonical manifest, verifies the package,
and publishes the signed archive together with its SHA-256 checksum and
raw 32-byte public key. The **same public key** is stable across builds until
that secret is rotated. The Actions artifact contains:

- `<name>-<version>-<target>.xpk`
- `<name>-<version>-<target>.xpk.sha256`
- `<name>-<version>-<target>.xpk.pub`

Verify locally with `xila-package verify archive.xpk archive.xpk.pub`.
Generate a key with `xila-package key generate` for each release package.
Store the base64-encoded 32-byte private seed as `XILA_DEV_SIGNING_SEED_B64`
in the repository that calls the workflow. Forward the secret explicitly.
Pull request artifacts remain unsigned. Devices obtain the package public key
from the signed registry entry and check it against their installed key on an
upgrade. See the [registry trust model](registry-trust.md).
