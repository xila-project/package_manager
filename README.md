# Xila package manager

[![Rust coverage](https://codecov.io/gh/Xila-Project/package_manager/graph/badge.svg)](https://codecov.io/gh/Xila-Project/package_manager)

Shared Rust workspace for building, inspecting and eventually installing Xila application packages. It is reused by [Xila Core](https://github.com/xila-project/core) and the [community registry](https://github.com/xila-project/packages), without depending on either consumer.

## Workspace

| Crate | Responsibility |
| --- | --- |
| `xila-package-verification` | `no_std` incremental SHA-256 and strict Ed25519 verification, migrated from Xila Core |
| `xila-package-manifest` | Shared versioned schema and validation via Miniserde JSON (`no_std + alloc`) |
| `xila-package-reader` | Full-buffer TAR inspection with `tar-no-std`, file hashes and optional signature verification |
| `xila-package-writer` | Host-only deterministic USTAR writer |
| `xila-package-builder` | Host-only `xila-package` executable to generate, update and package applications |
| `xila-package-manager` | Initial platform-independent library scaffold; installer and repository components are not yet implemented |

**Current format is experimental.** A production signing envelope, canonical schema, streaming reader and installer trust policy are not yet frozen. In particular, the reader is not a bounded-memory network-streaming installer for microcontrollers, and unsigned packages must not be trusted. Review the [container and signature design proposal](docs/package-container-proposal.md) and [format-tracking issue](https://github.com/xila-project/core/issues/402).

## Native packaging workflow

```sh
cargo run -p xila-package-builder -- manifest generate ./app ./manifest.json xila.calculator 1.0.0 wasm32-wasip1 1
cargo run -p xila-package-builder -- manifest update ./app ./manifest.json
cargo run -p xila-package-builder -- pack ./app ./manifest.json ./calculator.xpk
```

The first version handles ordinary uncompressed files and produces development archives. An optional externally generated detached signature is supported, but publisher trust and key management are **not** implemented by this command.

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

The workspace uses Rust 1.99.0 and [mr-boxington](https://mr-boxington.jdx.dev/) for compilation caching. The `mr_boxington = true` configuration avoids requiring a global Cargo wrapper. Use `mise exec -- cargo …` when the shell is not activated.

GitHub Actions runs formatting, compilation, Clippy, and tests for pull requests and main-branch pushes. The cache stores the Cargo target directory in target mode. Host-only dependencies must not be introduced into the microcontroller-facing crates.

See [verification migration notes](docs/verification-migration.md) for the cross-repository extraction and [Core issue #536](https://github.com/xila-project/core/issues/536) for related follow-up.

## Versioning, GitHub releases and coverage

The Cargo packages are **private to this Git workspace**: every crate sets `publish = false`. Release-plz operates in `git_only = true` mode and tracks only the native `xila-package-builder` binary. It may create a version bump pull request and a GitHub Release, but it never sends any crate to crates.io. The release workflow attaches archives of the `xila-package` executable for Linux, macOS and Windows, with SHA-256 checksums. Releases are prepared on `main` and occur after merging the release-plz version bump pull request.

GitHub Actions generates Rust coverage with `cargo-llvm-cov` and publishes the report to Codecov. Configure `CODECOV_TOKEN` as a repository secret for reliable uploads; coverage reports are also retained as GitHub Actions artifacts. See `.github/workflows/coverage.yml`.

**Integration caution:** Xila Core currently pins the original `verification` crate revision. The renamed package `xila-package-verification` requires a separate dependency-alias update before Core changes its pinned revision. Existing Core builds remain functional with their original commit.
