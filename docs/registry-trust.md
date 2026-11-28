# Registry trust model

Each package has its own Ed25519 signing key. The repository key authenticates
a registry entry that pins the package key for one identifier and version.
The package key authenticates the manifest. The manifest authenticates each
file by SHA-256.

## Keys and files

| Key | Signs | Source of trust |
|---|---|---|
| Root | `root.json` | Pinned on the device or listed in the previous trusted root |
| Repository | `index.json` and registry entries | Listed in the trusted root |
| Package | Package manifests and rotations to the next generation | Pinned in a signed registry entry on first installation, then recorded in the installed origin |

Use separate keys for these roles. Each package identifier uses distinct keys,
including its retired keys.

Paths are relative to the registry root. Replace the dots in an identifier
with directory separators. For example, the entry for
`dev.xila.clock` version `1.0.0` is `packages/dev/xila/clock/1.0.0.json`.

| File | Format version | Signature domain |
|---|---|---|
| `root.json` | 1 | `XILA-REGISTRY-ROOT-V1\0` |
| `index.json` | 2 | `XILA-REGISTRY-INDEX-V2\0` |
| `packages/<identifier>/<version>.json` | 3 | `XILA-REGISTRY-ENTRY-V3\0` |
| `rotations/<identifier>/<generation>.json` | 1 | `XILA-PACKAGE-KEY-ROTATION-V1\0` |

Each detached `.sig` contains a raw 64-byte Ed25519 signature over the domain
above, followed by the JSON length as a little-endian 32-bit integer, followed
by the exact JSON bytes. The index lists each entry and rotation by path,
SHA-256 and size, sorted by path. A rotation's detached signature comes from
the previous package key and is copied to the published site.

The [entry schema](../schemas/registry-entry.schema.json) defines
`package_key` as a generation and a canonical base64 encoding of the raw
32-byte Ed25519 public key. The entry also pins the archive URL, SHA-256 and
size. The [rotation schema](../schemas/registry-rotation.schema.json) defines
the identifier, next generation, previous key and new key. The first key is
generation 1. Generations increase by one, up to 33. Each rotation document can
contain up to 1024 bytes.

## First publication

An identifier uses at least three lowercase components, such as
`dev.xila.clock` or `io.github.alice.weather`. The namespace is every
component except the last. Components contain lowercase ASCII letters, digits,
hyphens and underscores. Each component starts and ends with a letter or a
digit and has at most 63 bytes. The complete identifier has at most 96 bytes.

The first entry pins generation 1 after registry submission checks ownership of
the exact namespace. The [claim schema](../schemas/registry-namespace.schema.json)
accepts these owner kinds.

- A `domain` owner proves control through a token at
  `https://<domain>/.well-known/`. The namespace is the reversed domain,
  with no underscores.
- A `github` or `gitlab` owner proves control of the account named by
  `io.github.<account>` or `io.gitlab.<account>`.

`registry check-owner` checks the claim against the entry. The registry
submission process performs the external ownership check before acceptance.
The manifest can carry an optional `metadata.author` for catalog display.

## Later publications and rotation

Keep approved entries and rotations immutable. Run `registry check` with
`--previous` pointing to the approved checkout to enforce this rule and require
new versions to use the current generation. Use `--archives` to check the
archive digest, manifest signature and file hashes. The checker validates
each generation in order and rejects reused keys.

To transfer or rotate a key, create and sign the next rotation with the current
seed. Add both the JSON and its detached signature to the checkout. Use the new
key and generation for subsequent versions of the same identifier. Keep the
rotation history available so a device can skip package versions.

If the current seed is lost, the namespace owner must prove ownership again
through the registry's recovery process. The regular rotation and installer
paths require the previous key's signature. Recovery cannot upgrade an
existing installation through those paths. Any registry recovery policy must
address existing devices separately.

The migration uses the new entry, index and origin formats and reverse-DNS
identifiers for all packages. The old developer-key and namespace
authorization formats are retired. Published releases and tags are preserved.

## Device verification

1. Authenticate `root.json` with `TrustedRoot::bootstrap` from the pinned root.
   Pass the highest accepted root version. Apply later root versions in order
   with `TrustedRoot::update`.
2. Authenticate the index with `verify_index`. Pass the highest accepted
   index version and the current time if available. Persist the accepted
   versions and check each entry and rotation with `check_listed`.
3. Authenticate the selected entry with `verify_entry`. Check that the
   requested identifier and version match the entry. Obtain its signing key
   with `package_key`.
4. Check the archive size and digest. Verify the manifest signature with the
   entry's package key, check the manifest against the entry, and verify each
   file hash. Seal the verified staging directory.
5. Record the verified key in the new origin. For an upgrade, fetch the rotation
   records and signatures from the generation after the installed origin
   through the offered generation. Pass these records in order to
   `installation::activate`. It checks continuity against the stored origin
   before writing the installation journal. The journal commits the new
   bundle and origin together or restores the previous origin on rollback.

With no index, the entry signature authenticates its origin. Index version and
expiry checks require the index. Archive signatures authenticate content.
The registry and device apply deployment policy separately, including
permission to install native code.

## Installation planning

`xila_package_manager::planner` (feature `planner`, `no_std + alloc`) chooses
what to install. `IndexCatalog` lists the versions of a package from the
authenticated index, newest first, and fetches only the entries it considers,
running `verify_entry` and `check_listed` on each. `plan` then:

- keeps an installed version that satisfies every requirement, unless the
  package was requested with `Options::upgrade`;
- otherwise selects the first version that satisfies every requirement known
  so far and is `compatible` with the device target and running Xila release;
- never revisits a selection: a later requirement that it does not satisfy is
  an `Error::Conflict`, as is a kept package whose dependency would change to
  a version it does not accept;
- rejects dependency cycles, downgrades (unless allowed), entries for another
  package or version than the one asked for, and work beyond `Limits`
  (packages, fetched entries, dependencies per package, depth).

The result lists `Install`, `Upgrade` and `Downgrade` steps, each package after
its dependencies, with the authenticated entry. For each step the caller
downloads the archive, checks its size and SHA-256, verifies it with
the entry's `package_key` and hands it to the local installer, which owns every
change to the device.

Dependency requirements are written `*`, `=VERSION`, `>=VERSION` or
`^VERSION`. Registry entries and manifests do not declare dependencies yet, so
`IndexCatalog` candidates currently have none; the planner already handles
them for other catalogs, such as `MemoryCatalog`.

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
- **Origin**: each installed package records its repository, archive hash and package key
  ([package-origin.schema.json](../schemas/package-origin.schema.json)). Updates
  require the same repository and package key continuity.
  Installing, upgrading and removing a package, and recording its origin, are
  crash-consistent transactions: see
  [installation transactions](installation-transactions.md).

## Target compatibility

A package's `target` is a Rust target triple, dots included
(`thumbv8m.main-none-eabihf`). `wasm32-*` and `wasm64-*` packages run in the
virtual machine; every other target is native and runs directly on the
processor.

`compatible` checks the target with
`xila_package_manifest::target_compatible`, and the Xila version. Equal
targets match. Otherwise everything after the architecture (vendor, operating
system, binary interface) must be equal, and the device architecture must
provide every instruction the package may use:

- RISC-V: same width, same base (`i` or `e`), same floating-point extensions
  (`f`, `d`, `q`, which set the calling convention), and the package's other
  extensions a subset of the device's (`g` is `imafd`). `riscv32imc` runs on
  `riscv32imac`, not the reverse.
- Arm M-profile: `thumbv6m` runs on every later profile, `thumbv7m` on
  `thumbv7em` and `thumbv8m.main`, and `thumbv8m.base` on `thumbv8m.main`.
  `thumbv7em` needs `thumbv7em`, since the DSP extension is optional in
  `thumbv8m.main`.
- Any other architecture (WebAssembly, Xtensa) matches exactly.

`xila-package target compatible <package> <device>` applies the same rule.

The package's `xila_version` is also its native binary interface version:
there is no separate number per target, so a native package is rebuilt for
each Xila release it supports.

## Limits and follow-ups

- Root rotation needs every intermediate `root.json` version; the registry
  publishes only the current one so far.
- Rollback protection depends on the device persisting versions; on unprotected
  flash this is best effort.
- Signatures do not grant capabilities or permissions; installation policy is
  a separate decision.
