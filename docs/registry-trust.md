# Registry trust model

How a device decides that registry metadata is authentic and current. Package
archives keep their own developer signature; this document covers what sits
above it. Registry entries use experimental format version 2. The root and
index use format version 1.

## Keys

| Key | Kept | Signs | Trusted because |
|---|---|---|---|
| Root | offline | `root.json` | pinned on the device (first version), then listed in the previous `root.json` |
| Repository | registry publication CI | `index.json`, every entry, every developer key file, every namespace file | listed in the trusted `root.json` |
| Developer | the publisher | each `.xpk` manifest and its file inventory | its key file is signed by a repository key, the namespace file covering the package lists it (see [Identifiers and namespaces](#identifiers-and-namespaces)), and its `kinds` cover the package |

A key may not be both a root key and a repository key, so the online key can
never sign a new root. Up to 4 keys per role.

## Files

Published at the registry root (`registry.xila.dev`):

```text
root.json            + root.json.sig            root key
index.json           + index.json.sig           repository key
keys/developers/<id>.json            + .sig     repository key
namespaces/<namespace>.json          + .sig     repository key
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
| namespace file | `XILA-REGISTRY-NAMESPACE-V1\0` |

Schemas: [registry-root](../schemas/registry-root.schema.json),
[registry-index](../schemas/registry-index.schema.json),
[registry-entry](../schemas/registry-entry.schema.json),
[developer-key](../schemas/developer-key.schema.json),
[registry-namespace](../schemas/registry-namespace.schema.json).

- **`root.json`**: `version` (strictly increasing), `root_keys` (allowed to sign
  the next version) and `repository_keys`.
- **`index.json`**: `version` (signing time in Unix seconds, so it increases
  between publications), `expires` (Unix seconds) and every developer key and
  entry with its `path`, `sha256` and `size`, sorted by path.
- **`namespaces/<namespace>.json`** (format version 1): the `namespace`, its
  `owner` and the `developer_keys` allowed to publish in it.

## Device verification

`xila_package_manager::trust` (`no_std + alloc`) implements these steps;
`xila-package registry verify-signed` runs them on a whole directory.

1. `TrustedRoot::bootstrap`: `root.json` signed by a pinned root key, version
   at least the persisted one. Later versions go through `TrustedRoot::update`
   one at a time, each signed by a root key of the previous one.
2. `verify_index`: signed by a repository key; version at least the highest
   persisted one (**rollback**); not expired when the device has a trustworthy
   clock (**freeze**). Persist the accepted version.
3. `verify_developer_key` / `verify_namespace` / `verify_entry`: the file's own signature, then
   `check_listed` against the index (**mix-and-match**: every file must be the
   one listed in this snapshot).
4. `namespace_publisher_key`: the entry's `publisher` is the key file's `id`,
   the namespace file covering the identifier (`namespace_candidates` lists
   the listed path to fetch) names that key in `developer_keys`, or, for a
   legacy `xila.<name>` identifier, the key's own `namespaces` is `["xila"]`,
   and the key's `kinds` contain the package's kind (below). `publisher_key`
   is the same check without a namespace file, so only the legacy rule. The
   returned key verifies
   the archive's manifest signature; the entry's SHA-256 and size pin the
   archive bytes.

A device too small to hold the index may skip step 2 and the `check_listed`
part of step 3: the per-file signatures still prove origin, but not freshness.

## Identifiers and namespaces

A package identifier is reverse-DNS with at least three components, such as
`org.example.weather` or `io.github.alice.weather`. Components use lowercase
letters, digits, `-` and `_`, start and end with a letter or digit, and are at
most 63 bytes; the identifier is at most 96 bytes. Mixed case is not allowed:
identifiers become paths, and FAT file systems ignore case. The namespace is
every component except the last.

A namespace file `namespaces/<namespace>.json` records who owns a namespace
and which developer keys may publish in it. A listed key may publish every
identifier that starts with the namespace's components: `org.example` covers
`org.example.weather` and `org.example.tools.clock`, but not
`org.examples.weather`. A namespace has at least two components, so no file
can claim a whole top-level domain. Namespace files may not overlap (one
owner per identifier) and may list only existing developer keys. Adding a
developer or rotating a key therefore edits the namespace file only, never an
identifier or a key file.

The `owner` must match the namespace: a `domain` owner is the namespace
reversed (`example.org` owns `org.example`, and may not contain `_`), and a
`github` or `gitlab` owner is the account of an `io.github.<account>` or
`io.gitlab.<account>` namespace. Registry CI proves the ownership, a domain by
a token file under `https://<domain>/.well-known/` and an account by the
account itself, so namespaces are never allocated by hand.

**Legacy rule**, until Xila's own packages migrate: the two-component
identifiers `xila.<name>` stay valid, have no namespace file, and are granted
by a developer key whose own `namespaces` field is `["xila"]`. That field
accepts no other value and is optional; it is removed with the migration.

`xila-package registry check` and `xila-package registry verify-signed`
enforce all of the above; `registry sign` signs namespace files with their own
domain and lists them in the index.

## Package kinds

A package is **Wasm** when its target starts with `wasm32-` or `wasm64-` and
**native** otherwise (an unknown target counts as native). Wasm runs confined
by the runtime; native code on a microcontroller without a memory protection
unit runs fully trusted, so authorizing a key for it is a separate decision.

A developer key lists the kinds it may publish in `kinds` (`"wasm"`,
`"native"`). An absent or null `kinds` means Wasm only, so existing key files
keep their meaning and native publication always needs an explicit grant. A key
that is not authorized for the kind of an entry's target fails `publisher_key`,
`xila-package registry check` and `xila-package registry verify-signed`.

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
  keeps the first entry compatible with the device's target and running Xila
  version. A name found in
  several repositories is ambiguous: the user must choose the repository.
- **Origin**: each installed package records its repository and archive hash
  ([package-origin.schema.json](../schemas/package-origin.schema.json)). Updates
  are only taken from that repository, so adding a repository cannot replace an
  installed package.
  Installing, upgrading and removing a package, and recording its origin, are
  crash-consistent transactions: see
  [installation transactions](installation-transactions.md).

## Limits and follow-ups

- Root rotation needs every intermediate `root.json` version; the registry
  publishes only the current one so far.
- Rollback protection depends on the device persisting versions; on unprotected
  flash this is best effort.
- No developer-key revocation list yet: remove the key file and re-sign, which
  devices with a fresh index will notice.
- Signatures do not grant capabilities or permissions; installation policy is
  a separate decision.
