<h1>
<picture>
  <source media="(prefers-color-scheme: dark)" srcset=".github/brand/header-dark.svg">
  <img src=".github/brand/header-light.svg" alt="Xila Package manager — Build, sign and verify application packages." width="1280">
</picture>
</h1>

[Documentation](https://www.xila.dev/docs/) ·
[Try Xila](https://platforms.xila.dev/) ·
[Community](https://matrix.to/#/#xila:anneraud.fr)

[![Rust coverage](https://codecov.io/gh/Xila-Project/package_manager/graph/badge.svg)](https://codecov.io/gh/Xila-Project/package_manager) [![vulnerabilities](https://vulnerabilities.xila.dev/badges/5923a3a90dc8e7923e4941652aec7295.svg)](https://vulnerabilities.xila.dev/public/7ed98e8bb26a0399ff4974fa6da0743e)

Shared Rust workspace for building, signing and validating Xila application bundles, and for the platform-independent part of installing them; VFS integration is deliberately out of scope. It is reused by [Xila Core](https://github.com/xila-project/core) and the [package registry](https://github.com/xila-project/registry), without depending on either consumer.

## Workspace

| Crate | Responsibility |
| --- | --- |
| `xila-package-verification` | `no_std` incremental SHA-256 and strict Ed25519 verification, migrated from Xila Core |
| `xila-package-manifest` | Shared versioned schema and validation via Miniserde JSON (`no_std + alloc`) |
| `xila-package-bundle` | `no_std + alloc` streaming hashes, file inventory and signing helpers, reusable with Xila VFS |
| `xila-package-reader` | Full-buffer TAR inspection with `tar-no-std`, file hashes and optional signature verification |
| `xila-package-writer` | Host-only deterministic USTAR writer |
| `xila-package-builder` | Host-only `xila-package` executable to initialize source folders, build standalone bundles, sign and archive them; also a library, reused by the `xila package` subcommand of [`tools`](https://github.com/xila-project/tools) |
| `xila-package-manager` | `no_std + alloc` registry trust chain (`trust`), crash-consistent installation transactions (install, upgrade, removal and recovery; see [installation transactions](docs/installation-transactions.md)) and a bounded, deterministic dependency planner (`planner`, default feature) that turns install requests into ordered steps for the local installer |

The **experimental version 2 runtime JSON Schema** is maintained in
[`schemas/package-manifest.schema.json`](schemas/package-manifest.schema.json).
For editor validation of a **generated bundle** manifest, use the following optional field:

```json
{
  "$schema": "https://raw.githubusercontent.com/xila-project/package_manager/main/schemas/package-manifest.schema.json",
  "format_version": 2
}
```

This snippet shows the schema hint only, not a complete manifest.
`manifest generate` emits `$schema` for the legacy workflow. New `bundle init` source folders instead reference `schemas/developer-manifest.schema.json`. The schema helps developers
and CI catch structural mistakes; it does not authenticate package content or
grant runtime capabilities.

Both manifests and registry entries declare `xila_version` as a string such as
`"0.1"`. For Xila 0.x, the running major and minor versions must match the
declaration. Starting at 1.0, the running major must match and the running minor
must be at least the declared minor. Patch releases share the same compatibility.
Format version 1 documents must be regenerated for format version 2.

**Current format is experimental.** A production signing envelope, canonical schema, streaming reader and installer trust policy are not yet frozen. In particular, the reader is not a bounded-memory network-streaming installer for microcontrollers, and unsigned packages must not be trusted. Review the [container and signature design proposal](docs/package-container-proposal.md) and [format-tracking issue](https://github.com/xila-project/core/issues/402).

## Portable logic reused by Xila

The existing `xila-package-manifest` crate uses `miniserde` for both the
developer-authored JSON and the signed runtime JSON, just like Xila Core.

The `xila-package` CLI uses `getargs`/`getargs-derive`, as does Xila's
command-line Shell. The parser now avoids the optional `std` feature, since
`from_args` can parse borrowed strings without it.

The new `xila-package-bundle` crate uses the existing
`xila-package-verification` SHA-256/Ed25519 primitives for incremental
file hashing, complete inventories and signature-message verification.
It contains **no `std::fs` or `tar` dependency**. The native builder
retains directory traversal, file copying, signing-key file reads and TAR
creation; these can be replaced with Xila-specific adapters later without
changing the portable bundle and manifest formats.

## Native bundle build workflow

There are **two distinct manifests**:

- The developer edits `weather/xila-package.json`, which contains identity,
  runtime requirements and application metadata only.
- The builder generates `Weather.app/.xila/manifest.json`, which contains
  the full inventory of **all** executables and resources (paths, sizes,
  SHA-256), and optionally `.xila/manifest.sig` authenticating that manifest.

```sh
cargo run -p xila-package-builder -- bundle init ./weather community.weather 1.0.0 wasm32-wasip1 --xila-version 0.1 --entrypoint executables/weather.wasm --display-name Weather --icon resources/icon.png
# Place the compiled executable in weather/executables/ and your assets in weather/resources/.
cargo run -p xila-package-builder -- bundle build ./weather ./Weather.app
cargo run -p xila-package-builder -- bundle verify ./Weather.app
cargo run -p xila-package-builder -- bundle archive ./Weather.app ./Weather.xpk
```

For signed releases, pass `--signing-key /secure/private.seed` to `bundle
build` (raw 32-byte Ed25519 private seed) or export a signing payload and
attach an externally produced detached signature with `bundle signing-payload`
and `bundle attach-signature`. Every resource is covered through the signed
manifest hashes, not only the Wasm. See
[complete builder workflow](crates/builder/README.md) and the
[developer manifest JSON Schema](schemas/developer-manifest.schema.json).

The unpacked `.app` directory is the **bundle**; `.xpk` is merely its
deterministic distribution archive. The existing `pack` command is retained
for compatibility. This repository does not implement VFS integration, Shell
discovery or process spawning; the device adapts `xila-package-manager`'s
installation transactions to its file system.

## Development

Install [mise](https://mise.jdx.dev/) 2026.9.2 or newer:

```sh
mise trust
mise install
mise run check
mise run clippy
mise run test
mise run format:check
```

**Rust version.** Development and CI pin Rust 1.97.0 and Cargo declares 1.97 as
the MSRV (`rust-version`), following the esp-rs Xtensa toolchain base. Use only
language features and `std` or `core` APIs available in Rust 1.97. Raise the
version only when esp-rs publishes a new base, and update every Xila repository
together. Rust native executables that use `build-std` use a separate nightly
toolchain ([xila-project/core#687](https://github.com/xila-project/core/issues/687)).

The workspace uses [mr-boxington](https://mr-boxington.jdx.dev/) for compilation caching. The `mr_boxington = true` configuration avoids requiring a global Cargo wrapper. Use `mise exec -- cargo …` when the shell is not activated.

GitHub Actions runs formatting, compilation, Clippy, and tests for pull requests and main-branch pushes. The cache stores the Cargo target directory in target mode. Host-only dependencies must not be introduced into the microcontroller-facing crates.

See [verification migration notes](docs/verification-migration.md) for the cross-repository extraction and [Core issue #536](https://github.com/xila-project/core/issues/536) for related follow-up.

## Versioning, GitHub releases and coverage

The Cargo packages are **private to this Git workspace**: every crate sets `publish = false`. Release-plz operates in `git_only = true` mode and tracks only the native `xila-package-builder` binary. It may create a version bump pull request and a GitHub Release, but it never sends any crate to crates.io. The release workflow attaches archives of the `xila-package` executable for Linux x86_64/ARM64, macOS ARM64 and Windows x86_64, with SHA-256 checksums. Releases are prepared on `main` and occur after merging the release-plz version bump pull request.

### Reusable WebAssembly packaging workflow

Caller repositories can invoke [`.github/workflows/package-wasm.yml`](.github/workflows/package-wasm.yml) pinned by commit hash. By default, each `package` and `sign` job installs Rust `1.97.0` and builds `xila-package-builder` from `builder-ref` (default `main`). To skip compiling from source and reuse a published Linux x86_64 release executable, pass both `builder-release` (for example `xila-package-builder-v0.4.0`) and `builder-sha256` (the lowercase hexadecimal SHA-256 digest of `xila-package-x86_64-unknown-linux-gnu.tar.gz`). Both inputs are required together; the workflow verifies the archive digest and `xila-package --version` output before staging or signing. See [reusable WebAssembly packaging workflow](docs/reusable-wasm-package-workflow.md) for all inputs and signing guarantees.

### Bootstrap the first GitHub Release (one time)

The initial `xila-package-builder` version is already `0.1.0`, so `release-plz release-pr` computes the same version and creates no version-bump PR. Its normal `release_always = false` policy then prevents `release-plz release` from releasing arbitrary commits.

After reviewing and merging the bootstrap workflow PR, explicitly run the workflow **once on `main`**:

```sh
gh workflow run release.yml \
  --repo Xila-Project/package_manager \
  --ref main \
  -f bootstrap_initial_release=true
```

You can also open **Actions → Native binary release → Run workflow**, select
`main`, and enable **bootstrap_initial_release**. The workflow confirms that
the builder is still `0.1.0` and the initial tag does not exist. Only for
this manual run it creates a temporary `release-plz` configuration enabling
`release_always`, allowing the first GitHub tag and release
`xila-package-builder-v0.1.0` to be generated along with native binary assets.
The repository's `release-plz.toml` is **not** changed; future releases
continue to require release-plz release PRs. A second attempt with an existing
tag fails rather than republishing it.

This is a **Git-only release**, never a crates.io publication. Review the
[GitHub Release](https://github.com/Xila-Project/package_manager/releases)
and [workflow run](https://github.com/Xila-Project/package_manager/actions/workflows/release.yml)
to verify its tag and uploaded Linux/macOS/Windows assets. The normal
version-bump PR flow starts after the initial tag exists.

GitHub Actions generates Rust coverage with `cargo-llvm-cov` and publishes the report to Codecov. Configure `CODECOV_TOKEN` as a repository secret for reliable uploads; coverage reports are also retained as GitHub Actions artifacts. See `.github/workflows/coverage.yml`.

**Integration caution:** Xila Core currently pins the original `verification` crate revision. The renamed package `xila-package-verification` requires a separate dependency-alias update before Core changes its pinned revision. Existing Core builds remain functional with their original commit.

<!-- xila:footer:start -->

---

Part of **[Xila](https://www.xila.dev/)** ·
[Repositories](https://github.com/xila-project) ·
[Community](https://matrix.to/#/#xila:anneraud.fr)

Special thanks to [Martin Legand](https://www.behance.net/martinlegand) for generously designing the Xila logo.

<!-- xila:footer:end -->
