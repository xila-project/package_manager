# Installation transactions

`xila_package_manager::installation` (`no_std + alloc`) installs, upgrades and
removes verified bundles on a device so that an interruption, such as a power
loss, at any step leaves a working, consistent state. It only assumes that a
single rename is atomic: file systems such as LittleFS have no multi-file
transactions.

The device keeps archive extraction, verification, networking and privilege
checks. It verifies a package into a sealed staging directory, then hands it to
`installation::activate`, which takes over through a small `Storage` trait
(exists, rename, remove, read, write and list).

Registry origins record the verified package signing key and generation.
Activation checks upgrades against the previous origin before writing the
journal. Pass the ordered rotation records for generations after the
installed key through the offered key. Recovery restores the previous key
with the previous origin when an upgrade rolls back.

## Layout

| Path | Content |
| --- | --- |
| `<bundles>/<name>` | Installed bundle of package `<name>`. |
| `<bundles>/.incoming-*` | Verified, sealed staging directory. |
| `<bundles>/.previous-<name>` | Bundle being replaced by an upgrade. |
| `<bundles>/.removing-<name>` | Bundle being removed. |
| `<bundles>/.download-*` | Downloaded archive waiting to be verified. |
| `<origins>/<name>.json` | Where the package came from ([schema](../schemas/package-origin.schema.json)). |
| `<journal>` | The transaction in flight ([schema](../schemas/package-transaction.schema.json)). |

Xila uses `/applications/bundles`, `/configuration/system/packages/installed`
and `/configuration/system/packages/transaction.json`.

## Operations

Each operation writes its journal first and removes it last. One routine
applies a journal, both the first time and during recovery: it looks at which
directories exist and continues from there, so it may stop and run again at any
step.

- **Install:** staging → bundle, record the origin.
- **Upgrade:** bundle → previous, staging → bundle, record the new origin,
  delete the previous bundle. The upgrade must offer a strictly higher semantic
  version from the repository recorded in the origin (bundles seeded without an
  origin accept any verified version). If the verified staging directory
  disappears before the swap completes, the previous bundle and its origin come
  back, so the device always keeps a working version.
- **Remove:** bundle → removing, delete the origin, delete the bundle.

Records (journal and origins) are replaced through a `.new` sibling: write it,
remove the record, rename the sibling. A reader takes the record, or else a
complete sibling; an incomplete one is a write that never took effect.

## Recovery

`installation::recover` finishes or undoes the journaled transaction, then
deletes every temporary entry of the bundles directory. A malformed journal is
reported and kept, and blocks new operations: recovery never guesses. Run it
before creating a staging directory (for example at the start of each package
command, or at boot), never while an operation is running.

## User data

Operations only touch the bundle directory, the temporary entries above and
the package's origin record. User data lives elsewhere and is kept by upgrades
and removals. Files a new version no longer ships disappear with the old bundle.

## Tests

`crates/manager/tests/installation.rs` runs every operation over an in-memory
storage that loses power after any number of writes, including halfway through
a file write, then recovers, itself interrupted at every step once. After each
case, the bundle and its origin agree, no temporary entry or journal is left,
user data is unchanged, and an upgrade always leaves the old or the new
version installed.
