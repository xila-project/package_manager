# Xila self-contained application bundles (v2 draft)

> This is an incremental schema/contract proposal, **not** a working device
> installer. It must be reconciled with the streaming container decision in
> [core #402](https://github.com/xila-project/core/issues/402) before freezing
> the on-disk format or using it for production publication.

## Separate three concepts

- **Package**: a versioned, integrity-checked distribution container; the
  package manifest is authoritative for package identity, version, ABI,
  capabilities and declared file hashes.
- **Application**: optional metadata in the same manifest. Its stable
  identity is the package `name` and it resolves an entrypoint, a fallback
  display name, an optional icon and launcher visibility. An application is
  **not** an executable.
- **Executable**: runs independently with the existing
  `executable::execute` API. A v2 package with `application: null` is a
  legitimate distribution of one or more standalone binaries.

No second `Info.plist`-style file containing duplicate identity/version
metadata is required. An installed application retains the **exact original
manifest bytes** and detached signature for later inspection.

## Proposed logical layout

The current TAR envelope places `.xila/manifest.json` first, optionally
followed by `.xila/manifest.sig`, and then all declared ordinary payload
files. This manifest-first order also works for a future streaming container
(such as CPIO newc); the envelope format is not fixed by this proposal.

```text
calculator.xpk
  .xila/manifest.json
  .xila/manifest.sig
  executables/calculator.wasm
  resources/icon.png
  resources/locales/fr.json
```

The archive paths are always relative to the **bundle root**. The package
manager must reject absolute paths, traversal, undeclared files, symlinks and
special entries; it must not execute install scripts or a Wasm `__install`
export.

An example of the manifest's application metadata:

```json
{
  "format_version": 2,
  "name": "xila.calculator",
  "version": "1.0.0",
  "target": "wasm32-wasip1",
  "minimum_xila_abi": 1,
  "capabilities": [],
  "files": [
    {
      "path": "executables/calculator.wasm",
      "size": 1234,
      "sha256": "<64 lowercase hex digits>"
    },
    {
      "path": "resources/icon.png",
      "size": 123,
      "sha256": "<64 lowercase hex digits>"
    }
  ],
  "application": {
    "entrypoint": "executables/calculator.wasm",
    "display_name": "Calculator",
    "icon": "resources/icon.png",
    "show_in_launcher": true
  }
}
```

For a standalone CLI package, set `application` to JSON `null`. A trusted
built-in application may instead reference a separately mounted executable,
for example `/system/executables/settings`; the executable must already
exist and be authorized independently. The *presence* of a system executable
path is not a capability or security exemption.

## Proposed installed paths (to be implemented in Core/Platforms)

```text
/applications/bundles/<stable-id>/<version>/
  .xila/manifest.json
  .xila/manifest.sig
  executables/...
  resources/...
/applications/active/<stable-id>    # small activation record; version + digest
/data/applications/...             # persistent system-owned app data
/users/<uid>/applications/<id>/    # user-owned config/data/cache
```

`<stable-id>` is the validated package name (not a numeric task ID).
Versions remain separate. During installation:

1. Resolve trust **outside** the untrusted archive and authenticate the
   metadata according to installation policy. Reject incompatible ABI/target.
2. Stream entries into staging on the **same filesystem** as the final bundle.
   Enforce bounded sizes/counts and validate every declared file digest.
3. Close/sync written content. Persist manifest/signature without
   reserializing or modifying the signed bytes.
4. Rename staging to its immutable version directory. Only then update the
   activation record via a staged write + atomic rename. Recovery must
   classify orphan staging dirs, inactive complete versions and active
   versions and **never** activate partially verified content.
5. Uninstall/deactivate only package-owned code. Do not delete user-owned
   state, configuration, cached settings or dock preferences.

LittleFS documents atomic rename with power-loss safety; this does **not**
prove that every Xila VFS mount supports atomic renaming, cross-filesystem
moves or durable sync. Test its actual adapter and failure injection before
claiming transactional updates or rollback.

The format of the activation record, collision handling, version ordering,
signature trust policy and full streaming installer belong to Core's
[installer issue #491](https://github.com/xila-project/core/issues/491).
Never infer authority merely from a cryptographic signature.

## GUI and launch contracts

- Launcher discovers **active installed** application manifests, showing
  only those with `show_in_launcher: true`. It does not consume
  installation-created shortcut JSON.
- The Dock is based on live windows and **per-user pinned application IDs**,
  not on all installed apps or mutable executable paths.
- The launcher resolves the active bundle version and relative entrypoint,
  then dispatches to existing `executable::execute`. Wasm uses the existing
  host/WASI permissions and private directories; a native executable can be
  pre-mounted and referenced by path.
- Prefer a scan on launcher opening with a small in-memory cache, invalidated
  only after package activation/deactivation. Do not add a persistent index
  or daemon before measuring I/O/RAM.
- Remove guest `__install` and the `wasm --install` mode **only after**
  platform seeding and launcher migrations pass their integration tests.

## Schema compatibility and signatures

- Legacy v1 manifests deserialize as `application: None`. Their archived
  JSON and domain `XILA-PACKAGE-MANIFEST-V1\0` remain unchanged.
- New v2 manifests require the `application` field (object or null).
  The signed message uses the domain
  `XILA-PACKAGE-MANIFEST-V2\0`, the little-endian u32 byte length,
  then the **exact stored JSON bytes**. No JSON reserialization during
  verification. v1 and v2 signatures are deliberately non-interchangeable.
- `application.entrypoint` and optional icon must resolve to declared
  files for bundle-local resources. All declared files remain
  SHA-256-verified; an external system entrypoint is never counted as a
  package-owned file.
- Application display metadata does not grant capabilities, override
  authorization, or identify a trusted publisher.

## Remaining work

- **package_manager**: decide streaming TAR versus CPIO (Core #402),
  bounded reader, streaming writer, encrypted/trusted publication checks,
  signature envelope, manifest migration and builder CLI for application
  metadata.
- **core**: versioned staging, trust-aware installer, activation record,
  stable application identity mapped to task/private storage and a
  `launch_application(id, args)` adapter.
- **applications**: launcher and Dock migration, drop old shortcuts and
  `__install` path after integration is ready.
- **platforms**: seed preinstalled bundles, native entrypoint references,
  boot/rollback tests on native, ESP32-S3 measurements.
- **packages**: validate publication metadata and bind archive digest/size
  as described by package_manager #19.
- **website**: document the final schema and migration only after CI and
  integration pass.

The current experimental container is a whole-buffer TAR reader, so this
PR alone **does not satisfy** the streaming/RAM requirements and must not be
misrepresented as a complete installation feature.
