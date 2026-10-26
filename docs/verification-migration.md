# Verification crate migration

Copied existing SHA-256 and strict Ed25519 sources, tests and examples unchanged from `xila/core/libraries/verification`. The shared crate retains its name `verification` and its `no_std` interfaces.

This completes only the destination-side extraction. A separate Core pull request must switch consumers to a **pinned immutable commit** before the original implementation can be removed safely. Keep the local copy functional until that dependent change is merged.

The existing Cargo workspace, mise and mr-boxington setup is retained. Continuous integration temporarily refreshes the dependency lockfile; commit a generated lockfile when available. Tracking: https://github.com/xila-project/core/issues/536.
