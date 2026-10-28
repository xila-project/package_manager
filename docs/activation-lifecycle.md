# Offline signed package installation and activation

This document describes the working `xila-package-manager::{installer,lifecycle}`
implementation. `installer::install` authenticates a signed local TAR, writes
a non-executable staging bundle, reads and verifies its persisted bytes, and
publishes an activation record using a caller-supplied `Store` backend.
`resolve_active`, `activate_existing`, `uninstall_active` and
`discard_staging` implement reading, rollback, removal and interrupted
transaction cleanup. All of these functions perform real storage operations.

**No Xila VFS adapter is implemented yet**, as that integration is intentionally
held until the upstream `tar-no-std` streaming API is available. The existing
reader currently requires an entire borrowed TAR archive in memory; a fully
streaming source and device-side filesystem adapter remain work in
[core#402](https://github.com/xila-project/core/issues/402) and
[core#491](https://github.com/xila-project/core/issues/491).

## Layout and ownership

```text
/applications/bundles/<package-id>/<version>/
    .xila/manifest.json       # exact signed manifest bytes
    .xila/manifest.sig        # original detached signature
    bin/...                   # immutable package-owned files
    resources/...
/applications/bundles/<package-id>/.staging-<nonce>/
                                # untrusted, non-executable staging
/applications/active/<package-id>
                                # protected activation record
/applications/active/.pending-<package-id>-<nonce>
                                # temporary activation file
/data/applications/<package-id> # system-owned mutable state (not removed on upgrade)
/users/<uid>/applications/...  # user settings/state (not removed on uninstall)
```

Installations are **version-directory scoped**, so different packages can
contain the same relative filename without colliding. The package identity
and version derive from the validated experimental v1 manifest. The version
must additionally be safe as one path component: `.` and `..` are rejected.
No install script or Wasm `__install` hook is part of this contract.

## Activation record

The active-version pointer is a protected, small JSON record:

```json
{
  "format_version": 1,
  "package": "xila.calculator",
  "version": "1.0.0",
  "manifest_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
}
```

The digest binds **the exact persisted manifest bytes**, including an
optional `$schema` hint. It does not authenticate a publisher and is not a
license to execute arbitrary content. The active record must reside in an
OS-owned non-writable namespace. A future loader must additionally validate
the publisher trust decision, verify content against the installed manifest,
enforce task/user execute permissions, and eliminate mutable-code TOCTOU.

The Rust `ActivationRecord::decode` caps records at 1024 bytes, checks the
format version, identifiers, version path and digest. Its `resolve_application`
method produces a **candidate** entrypoint for an application (or returns
`NoApplication` for a standalone executable package). It does not spawn a
task, grant any permissions or inspect file contents.

## Preflight

`Policy` checks target, minimum Xila ABI, declared requested capabilities
against a trusted allow-list and denies external system entrypoints by
default. The manifest is never the source of the allow-list, and granting
a capability at installation cannot bypass execution-time authorization.

`preflight(manifest, policy, transaction_nonce, storage_guarantees)`
returns deterministic staging/version/activation paths without mutating the
filesystem or reserving space. The installer rejects destination collisions
through its `Store::rename_new` operation at commit time. A unique nonce only prevents routine
staging name reuse; the backend must still use create-exclusive semantics.

## Implemented commit sequence

1. Select a trusted publisher key/policy outside the archive, validate
   target/ABI/capabilities, and preflight ownership, free space and paths.
2. Create exclusive staging beneath the same bundle filesystem. Write
   non-executable files through a **bounded streaming verifier**. Reject
   unexpected entries, symlinks, hardlinks, duplicates, mount crossings,
   truncated or unverified bytes.
3. Sync file content and metadata. Persist the **original** signed manifest
   and detached signature. Do not mutate or reserialize signed bytes.
4. Atomically publish staging to a *new*, immutable version directory.
   Never replace a version that already exists without reconciling ownership.
5. Write/flush/sync the candidate activation record in the active directory.
   Atomically **replace** the existing active record. Only this step makes
   the newly verified version eligible for future launch.
6. Sync the parent directory per the verified backend contract; preserve
   previously active versions for rollback and retain all user-owned data.
7. On restart, validate the active record and its target bundle. Quarantine
   incomplete staging; never automatically launch a merely present version.

This sequence is implemented by `installer::install` with `Store` operations.
It still depends on actual backend guarantees: a mock/host test does **not**
prove physical-flash power-loss safety. Caller-supplied trusted keys are
verified with Ed25519; the manifest digest is checked again from persisted
storage and each staged payload is read back and SHA-256 verified.

The current source is a borrowed whole-archive buffer, not incremental input.
Payload writes and read-back use 4 KiB chunks; metadata decoding retains the
existing 64 KiB upper limit. This does not meet the final whole-package
memory bound of an embedded streaming installer.

## Portable atomicity verification

`StorageGuarantees::default()` denies all transactional operations. A
platform-specific adapter must affirm, for the *actual mounted filesystems*:

- bundle staging and final directories reside on the same mount;
- new-directory rename is atomic and refuses an existing destination;
- activation record replacement cannot expose partial content;
- sync of both files and parent directories has tested durability semantics;
- path traversal, symlinks, and mount crossing cannot escape protected roots.

The mere presence of a VFS `rename` function does **not** prove the above.
A LittleFS rename guarantee is not automatically applicable to HostFS,
network mounts, FAT, arbitrary block devices or different mounted roots.
The in-memory `Store` integration test injects errors at **every operation**
of an upgrade, including partial append writes; after simulated restart it
reverifies that the active version is either the old or the newly verified
one. It also tests install, rollback, uninstall, signature rejection,
persisted-payload tampering and preservation of user data. Device-side
brownout and write-cache tests are separately required.

## Recovery and future integration

`classify_recovery` currently returns conservative discovery states:
`Active`, `InactiveVersion`, `UntrustedStaging` and `Unavailable`.
It intentionally performs no filesystem I/O or deletion. The real
`resolve_active` implementation reads the authoritative active-record file,
verifies the signed manifest and all installed file hashes before returning a
launch candidate. `discard_staging` removes a named incomplete transaction;
published-but-inactive versions remain available for rollback.

The remaining integration tasks are **not** implemented by this PR:
bounded streaming TAR input (pending upstream), a real device filesystem
adapter, a global enumerated installed-package ownership database, a
persistent trusted-key store, true per-user authorization and process
execution, and physical-platform atomicity tests on native + ESP32-S3.
The current package-local version directory itself is the ownership
boundary, so upgrades and removals never touch application user data.
