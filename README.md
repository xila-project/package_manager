# Xila package manager

This repository contains the shared Rust workspace for Xila package-management
libraries. Its crates are intended for reuse by both Xila core and the package
repository tooling. Archive, manifest, and signature contracts are not defined
by this initial scaffold.

## Workspace

- `crates/package-manager`: initial `no_std` library scaffold without a public
  package-format or verification API yet.
- `Cargo.toml`: a virtual Cargo workspace. New libraries placed under `crates/`
  are automatically picked up by its `crates/*` member pattern.

The workspace uses Rust 1.99.0 (2024 edition), aligned with Xila core. It does
not need a C toolchain or native dependencies at this stage.

## Development

Install [mise](https://mise.jdx.dev/) **2026.9.2 or newer**, then from the
repository root run:

```sh
mise trust
mise install
mise run check
mise run clippy
mise run test
mise run format:check
```

`mise run format` applies rustfmt changes. `mise run build` builds every crate.

The project pins both Rust and [mr-boxington](https://mr-boxington.jdx.dev/).
The `mr_boxington = true` Rust tool option makes Cargo use the build cache in
`mise run` and `mise exec -- cargo ...` without installing a global Cargo
wrapper. In a shell without mise activation, call `mise exec -- cargo ...` to
use the same toolchain and cache. Do not add `sccache` or another Rust compiler
wrapper on top of mr-boxington.

## Continuous integration

GitHub Actions runs formatting, workspace checking, Clippy, and tests for pull
requests and pushes to `main`. `jdx/mr-boxington-action` restores and saves the
workspace's Cargo `target/` cache in `target` mode. Pull requests can restore
existing cache entries; trusted pushes to the default branch can populate it.

The initial library deliberately contains no manifest parser, archive logic, or
cryptographic API: those should be designed and tested before implementation.
