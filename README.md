# Xila Package Manager

Shared Rust libraries and host-side tooling for packaging, verifying, installing and distributing Xila applications.

This repository is intended to be consumed by both [Xila Core](https://github.com/xila-project/core) and the [community package registry](https://github.com/xila-project/packages). It must not depend on either consumer.

## Status

**Architecture design: not yet an implementable package specification.** Read the [package container and trust proposal](docs/package-container-proposal.md) before introducing binary formats or signatures.

The existing [verification crate](https://github.com/xila-project/core/tree/main/libraries/verification) has already been implemented in Xila Core. It should be migrated and reused here, without duplicating its SHA-256 or Ed25519 implementation.

Related tracking issues:
- [Extract shared crates to this repository](https://github.com/xila-project/core/issues/536)
- [Select the package archive and manifest format](https://github.com/xila-project/core/issues/402)
- [Local package installation](https://github.com/xila-project/core/issues/491)
- [Repository metadata and downloads](https://github.com/xila-project/core/issues/492)
- [Host-side package construction](https://github.com/xila-project/core/issues/494)

## Planned responsibilities

- Define one canonical versioned package manifest, one signed-byte definition, and a bounded archive reader.
- Provide reusable cryptographic verification without imposing installation or device-permission policy.
- Offer an offline installer with injected filesystem adapters, independent of Xila Core.
- Optionally resolve immutable package identifiers and versions through authenticated static repository metadata.
- Supply host tools to create, inspect, verify and publish packages.

Xila Core continues to own its native package-management command, device and filesystem adapters, trusted key policy, and executable loader. The registry repository continues to own contribution review and publication workflows.

All microcontroller-facing library paths should be compatible with `no_std`, feature-gated for optional functionality, and bounded in heap, stack and storage use.

No workspace crates have been introduced in this proposal pull request because the archive format and migration boundaries have not yet been finalized.
