# Registry trust model

How a device decides that registry metadata is authentic and current. Package
archives keep their own developer signature; this document covers what sits
above it. Formats are **experimental v1**.

## Keys

| Key | Kept | Signs | Trusted because |
|---|---|---|---|
| Root | offline | `root.json` | pinned on the device (first version), then listed in the previous `root.json` |
| Repository | registry publication CI | `index.json`, every entry, every developer key file | listed in the trusted `root.json` |
| Developer | the publisher | each `.xpk` manifest and its file inventory | its key file is signed by a repository key, and its `namespaces` cover the package |

A key may not be both a root key and a repository key, so the online key can
never sign a new root. Up to 4 keys per role.

## Files

Published at the registry root (`registry.xila.dev`):

```text
root.json            + root.json.sig            root key
index.json           + index.json.sig           repository key
keys/developers/<id>.json            + .sig     repository key
packages/<labels…>/<version>.json    + .sig     repository key
```

Every `.sig` is a raw 64-byte Ed25519 signature (strict verification) over

```text
DOMAIN || u32_le(len(file)) || exact file bytes
```

with a distinct domain per document kind, so a signature for one kind never
verifies as another:

| File | Domain |
|---|---|
| `root.json` | `XILA-REGISTRY-ROOT-V1\0` |
| `index.json` | `XILA-REGISTRY-INDEX-V1\0` |
| entry | `XILA-REGISTRY-ENTRY-V1\0` |
| developer key | `XILA-REGISTRY-DEVELOPER-KEY-V1\0` |

Schemas: [registry-root](../schemas/registry-root.schema.json),
[registry-index](../schemas/registry-index.schema.json),
[registry-entry](../schemas/registry-entry.schema.json),
[developer-key](../schemas/developer-key.schema.json).

- **`root.json`**: `version` (strictly increasing), `root_keys` (allowed to sign
  the next version) and `repository_keys`.
- **`index.json`**: `version` (signing time in Unix seconds, so it increases
  between publications), `expires` (Unix seconds) and every developer key and
  entry with its `path`, `sha256` and `size`, sorted by path.

## Device verification

`xila_package_manager::trust` (`no_std + alloc`) implements these steps;
`xila-package registry verify-signed` runs them on a whole directory.

1. `TrustedRoot::bootstrap`: `root.json` signed by a pinned root key, version
   at least the persisted one. Later versions go through `TrustedRoot::update`
   one at a time, each signed by a root key of the previous one.
2. `verify_index`: signed by a repository key; version at least the highest
   persisted one (**rollback**); not expired when the device has a trustworthy
   clock (**freeze**). Persist the accepted version.
3. `verify_developer_key` / `verify_entry`: the file's own signature, then
   `check_listed` against the index (**mix-and-match**: every file must be the
   one listed in this snapshot).
4. `publisher_key`: the entry's `publisher` is the key file's `id` and the key's
   `namespaces` contain the package's first label. The returned key verifies
   the archive's manifest signature; the entry's SHA-256 and size pin the
   archive bytes.

A device too small to hold the index may skip step 2 and the `check_listed`
part of step 3: the per-file signatures still prove origin, but not freshness.

## Several repositories

A device can use several registries. Each configured repository
([repository.schema.json](../schemas/repository.schema.json)) has a local
`name`, an HTTPS `url`, the `root_key` trusted for it and the highest
`root_version` and `index_version` accepted.

- **Adding a repository** pins its root key. Pass the key obtained out of band,
  or accept it on first use: `TrustedRoot::first_use` checks that `root.json` is
  signed by one of its own root keys and returns that key; the device shows its
  `fingerprint` and pins it only after the user confirms. The transport does
  not authenticate the server, so the fingerprint is what must be compared.
  `xila-package registry fingerprint root.pub` prints the expected value.
- **Resolving** a package: `candidates` lists the entry paths to try (an exact
  version, or every listed semantic version newest first), and `compatible`
  keeps the first entry matching the device's target and ABI. A name found in
  several repositories is ambiguous: the user must choose the repository.
- **Origin**: each installed package records its repository and archive hash
  ([package-origin.schema.json](../schemas/package-origin.schema.json)). Updates
  are only taken from that repository, so adding a repository cannot replace an
  installed package.

## Limits and follow-ups

- Root rotation needs every intermediate `root.json` version; the registry
  publishes only the current one so far.
- Rollback protection depends on the device persisting versions; on unprotected
  flash this is best effort.
- No developer-key revocation list yet: remove the key file and re-sign, which
  devices with a fresh index will notice.
- Signatures do not grant capabilities or permissions; installation policy is
  a separate decision.
