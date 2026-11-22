//! Crash-consistent activation, upgrade and removal of verified bundles.
//!
//! The device verifies a package into a sealed staging directory inside the
//! bundles directory (see [`STAGING_PREFIX`]); this module then makes it the
//! installed bundle, replaces an older version, or removes a bundle, and
//! records where each installed package came from ([`Origin`]).
//!
//! Only single renames are assumed to be atomic, so every operation is a short
//! sequence of renames inside the bundles directory, described beforehand by a
//! [`Transaction`] journal. One routine applies a transaction both the first
//! time and during [`recover`]: it inspects which directories exist and
//! continues from there, so it can be interrupted and run again at any step.
//!
//! - **Install:** staging → bundle, then record the origin.
//! - **Upgrade:** bundle → previous, staging → bundle, record the new origin,
//!   then delete the previous bundle. If the verified staging directory is
//!   gone before the swap completes, the previous bundle and origin come back.
//! - **Remove:** bundle → removing, delete the origin, then delete it.
//!
//! Upgrades and removals only touch the bundle directory and its origin
//! record: user data, which lives outside the bundles directory, is kept.
//! Files the new version no longer ships disappear with the old bundle.
//!
//! The caller serializes transactions (one at a time per device), keeps the
//! journal and origins on storage only privileged tasks can write, and runs
//! [`recover`] before creating a staging directory, since recovery removes
//! every temporary entry of the bundles directory. No background task is
//! needed: running recovery before the next package operation is enough.

use alloc::{format, string::String, vec::Vec};
use core::fmt;

use xila_package_manifest::{
    self as manifest, MAX_MANIFEST_BYTES, Operation, Origin, PREVIOUS_PREFIX, REMOVING_PREFIX,
    STAGING_PREFIX, SemanticVersion, TRANSACTION_FORMAT_VERSION, TRANSACTION_SCHEMA_URL,
    Transaction, decode_origin, decode_transaction, encode_origin, encode_transaction,
    is_temporary_entry, is_temporary_name,
};

/// Suffix of the sibling written before a record replaces the current one.
pub const RECORD_SUFFIX: &str = ".new";

/// Storage primitives the installer needs; paths are absolute.
///
/// Xila executors poll futures on one thread, so they need not be `Send`.
#[allow(async_fn_in_trait)]
pub trait Storage {
    type Error: fmt::Debug;

    /// Whether a file or directory exists at `path`.
    async fn exists(&mut self, path: &str) -> core::result::Result<bool, Self::Error>;

    /// Atomically rename `from` to `to`, within one directory. `to` must not exist.
    async fn rename(&mut self, from: &str, to: &str) -> core::result::Result<(), Self::Error>;

    /// Remove a file, or a directory and everything in it. A missing path is
    /// not an error.
    async fn remove(&mut self, path: &str) -> core::result::Result<(), Self::Error>;

    /// Read a whole file of at most `limit` bytes; `None` when it does not exist.
    async fn read(
        &mut self,
        path: &str,
        limit: usize,
    ) -> core::result::Result<Option<Vec<u8>>, Self::Error>;

    /// Create or truncate `path`, write `bytes` and make them durable before
    /// returning. A torn write must not affect any other path.
    async fn write(&mut self, path: &str, bytes: &[u8]) -> core::result::Result<(), Self::Error>;

    /// Names of the entries of a directory, without `.` and `..`.
    async fn list(&mut self, path: &str) -> core::result::Result<Vec<String>, Self::Error>;
}

/// Where installed packages and their records live. Every directory exists.
#[derive(Clone, Copy, Debug)]
pub struct Layout<'a> {
    /// Directory of installed bundles, e.g. `/applications/bundles`.
    pub bundles: &'a str,
    /// Directory of origin records (`<name>.json`).
    pub origins: &'a str,
    /// Path of the transaction journal.
    pub journal: &'a str,
}

impl Layout<'_> {
    /// Path of an entry (bundle or temporary directory) of the bundles directory.
    pub fn bundle(&self, name: &str) -> String {
        format!("{}/{name}", self.bundles)
    }

    /// Path of the origin record of `name`.
    pub fn origin(&self, name: &str) -> String {
        format!("{}/{name}.json", self.origins)
    }
}

/// Why a package operation failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error<E> {
    /// The storage failed; the operation may be resumed by [`recover`].
    Storage(E),
    /// A journal or origin record is malformed.
    Record(manifest::Error),
    /// An interrupted transaction must be recovered first.
    Pending,
    /// The staging directory is missing or not a staging directory name.
    InvalidStaging,
    /// The package is installed; upgrade it instead.
    AlreadyInstalled { version: Option<String> },
    /// The package is not installed.
    NotInstalled,
    /// An upgrade must have a strictly higher semantic version.
    NotNewer { installed: String, offered: String },
    /// An upgrade must come from the repository the package was installed from.
    OtherRepository {
        installed: Option<String>,
        offered: Option<String>,
    },
}

impl<E> From<manifest::Error> for Error<E> {
    fn from(error: manifest::Error) -> Self {
        Self::Record(error)
    }
}

fn source(repository: &Option<String>) -> &str {
    repository.as_deref().unwrap_or("a local archive")
}

impl<E: fmt::Debug> fmt::Display for Error<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(error) => write!(f, "storage failed: {error:?}"),
            Self::Record(error) => write!(f, "invalid installation record: {error:?}"),
            Self::Pending => f.write_str("an interrupted package operation must be recovered"),
            Self::InvalidStaging => f.write_str("invalid staging directory"),
            Self::AlreadyInstalled { version: Some(v) } => {
                write!(f, "version {v} is already installed; upgrade it instead")
            }
            Self::AlreadyInstalled { version: None } => {
                f.write_str("it is already installed; upgrade it instead")
            }
            Self::NotInstalled => f.write_str("it is not installed"),
            Self::NotNewer { installed, offered } => write!(
                f,
                "version {offered} is not newer than the installed {installed}"
            ),
            Self::OtherRepository { installed, offered } => write!(
                f,
                "it was installed from {}, not from {}",
                source(installed),
                source(offered)
            ),
        }
    }
}

pub type Result<T, E> = core::result::Result<T, Error<E>>;

/// How a transaction ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The operation took effect.
    Completed,
    /// The operation was undone: the previous state is back.
    RolledBack,
}

/// What [`recover`] did.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Recovery {
    /// The interrupted transaction, if any, and how it ended.
    pub transaction: Option<(Transaction, Outcome)>,
    /// Temporary entries deleted from the bundles directory.
    pub removed: Vec<String>,
}

/// Whether [`activate`] may replace an installed bundle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Fail if the package is installed.
    Install,
    /// Fail unless the package is installed; see [`check_upgrade`].
    Upgrade,
}

/// What [`activate`] replaced.
#[derive(Clone, Debug, PartialEq)]
pub enum Activated {
    Installed,
    Upgraded {
        /// `None` for a bundle installed without an origin (seeded in the image).
        previous: Option<Origin>,
    },
}

fn failed<E>(error: E) -> Error<E> {
    Error::Storage(error)
}

fn record_new(path: &str) -> String {
    format!("{path}{RECORD_SUFFIX}")
}

/// Read a record written by [`write_record`]. A complete sibling replaces a
/// missing record; an incomplete one means the write never took effect.
async fn read_record<S: Storage, T>(
    storage: &mut S,
    path: &str,
    decode: fn(&[u8]) -> core::result::Result<T, manifest::Error>,
) -> Result<Option<T>, S::Error> {
    if let Some(bytes) = storage
        .read(path, MAX_MANIFEST_BYTES)
        .await
        .map_err(failed)?
    {
        return Ok(Some(decode(&bytes)?));
    }
    match storage
        .read(&record_new(path), MAX_MANIFEST_BYTES)
        .await
        .map_err(failed)?
    {
        Some(bytes) => Ok(decode(&bytes).ok()),
        None => Ok(None),
    }
}

/// Replace a record: after an interruption, it reads as the old or the new one.
async fn write_record<S: Storage>(
    storage: &mut S,
    path: &str,
    bytes: &[u8],
) -> Result<(), S::Error> {
    let new = record_new(path);
    storage.write(&new, bytes).await.map_err(failed)?;
    storage.remove(path).await.map_err(failed)?;
    storage.rename(&new, path).await.map_err(failed)
}

/// Delete a record. The sibling goes first, so it cannot resurrect it.
async fn remove_record<S: Storage>(storage: &mut S, path: &str) -> Result<(), S::Error> {
    storage.remove(&record_new(path)).await.map_err(failed)?;
    storage.remove(path).await.map_err(failed)
}

async fn set_origin<S: Storage>(
    storage: &mut S,
    layout: &Layout<'_>,
    name: &str,
    origin: Option<&Origin>,
) -> Result<(), S::Error> {
    let path = layout.origin(name);
    match origin {
        Some(origin) => write_record(storage, &path, encode_origin(origin)?.as_bytes()).await,
        None => remove_record(storage, &path).await,
    }
}

/// The recorded origin of an installed package.
pub async fn origin<S: Storage>(
    storage: &mut S,
    layout: &Layout<'_>,
    name: &str,
) -> Result<Option<Origin>, S::Error> {
    read_record(storage, &layout.origin(name), decode_origin).await
}

/// Whether `offered` may replace the installed package described by `installed`.
pub fn check_upgrade<E>(
    installed: Option<&Origin>,
    offered: &Origin,
) -> core::result::Result<(), Error<E>> {
    let Some(installed) = installed else {
        // A bundle seeded without an origin may take any verified version.
        return Ok(());
    };
    if installed.repository != offered.repository {
        return Err(Error::OtherRepository {
            installed: installed.repository.clone(),
            offered: offered.repository.clone(),
        });
    }
    let newer = match (
        SemanticVersion::parse(&installed.version),
        SemanticVersion::parse(&offered.version),
    ) {
        (Some(installed), Some(offered)) => offered > installed,
        _ => false,
    };
    if !newer {
        return Err(Error::NotNewer {
            installed: installed.version.clone(),
            offered: offered.version.clone(),
        });
    }
    Ok(())
}

async fn pending<S: Storage>(storage: &mut S, layout: &Layout<'_>) -> Result<(), S::Error> {
    // A malformed journal is pending too: it must not be silently overwritten.
    match read_record(storage, layout.journal, decode_transaction).await {
        Ok(None) => Ok(()),
        Ok(Some(_)) | Err(Error::Record(_)) => Err(Error::Pending),
        Err(error) => Err(error),
    }
}

async fn exists<S: Storage>(storage: &mut S, path: Option<&str>) -> Result<bool, S::Error> {
    match path {
        Some(path) => storage.exists(path).await.map_err(failed),
        None => Ok(false),
    }
}

/// Apply `transaction` from whatever step it reached. Idempotent.
async fn run<S: Storage>(
    storage: &mut S,
    layout: &Layout<'_>,
    transaction: &Transaction,
) -> Result<Outcome, S::Error> {
    let name = transaction.name.as_str();
    let bundle = layout.bundle(name);
    let staging = transaction.staging.as_deref().map(|s| layout.bundle(s));
    let previous = transaction.previous.as_deref().map(|p| layout.bundle(p));
    let mut has_staging = exists(storage, staging.as_deref()).await?;
    let mut has_bundle = exists(storage, Some(&bundle)).await?;
    let mut has_previous = exists(storage, previous.as_deref()).await?;

    match transaction.operation {
        Operation::Install => {
            let staging = staging.as_deref().ok_or(Error::InvalidStaging)?;
            if has_staging && has_bundle {
                // Unreachable while transactions are serialized: keep the bundle.
                storage.remove(staging).await.map_err(failed)?;
                return Ok(Outcome::RolledBack);
            }
            if has_staging {
                storage.rename(staging, &bundle).await.map_err(failed)?;
                has_bundle = true;
            }
            if !has_bundle {
                set_origin(storage, layout, name, None).await?;
                return Ok(Outcome::RolledBack);
            }
            set_origin(storage, layout, name, transaction.origin.as_ref()).await?;
            Ok(Outcome::Completed)
        }
        Operation::Upgrade => {
            let staging = staging.as_deref().ok_or(Error::InvalidStaging)?;
            let previous = previous.as_deref().ok_or(Error::InvalidStaging)?;
            if has_staging && has_bundle && has_previous {
                // Unreachable: the previous path is cleared before the journal.
                storage.remove(previous).await.map_err(failed)?;
                has_previous = false;
            }
            if has_staging && has_bundle {
                storage.rename(&bundle, previous).await.map_err(failed)?;
                has_bundle = false;
                has_previous = true;
            }
            if has_staging {
                storage.rename(staging, &bundle).await.map_err(failed)?;
                has_staging = false;
                has_bundle = true;
            }
            debug_assert!(!has_staging);
            if has_bundle {
                set_origin(storage, layout, name, transaction.origin.as_ref()).await?;
                storage.remove(previous).await.map_err(failed)?;
                return Ok(Outcome::Completed);
            }
            // The verified staging directory is gone before the swap finished.
            if has_previous {
                storage.rename(previous, &bundle).await.map_err(failed)?;
            }
            set_origin(storage, layout, name, transaction.previous_origin.as_ref()).await?;
            Ok(Outcome::RolledBack)
        }
        Operation::Remove => {
            let removing = previous.as_deref().ok_or(Error::InvalidStaging)?;
            if has_bundle {
                if has_previous {
                    storage.remove(removing).await.map_err(failed)?;
                }
                storage.rename(&bundle, removing).await.map_err(failed)?;
            }
            set_origin(storage, layout, name, None).await?;
            storage.remove(removing).await.map_err(failed)?;
            Ok(Outcome::Completed)
        }
    }
}

/// Journal `transaction`, apply it and close the journal.
async fn execute<S: Storage>(
    storage: &mut S,
    layout: &Layout<'_>,
    transaction: &Transaction,
) -> Result<Outcome, S::Error> {
    let encoded = encode_transaction(transaction)?;
    if let Some(previous) = &transaction.previous {
        // Left over by an operation that failed before its journal existed.
        storage
            .remove(&layout.bundle(previous))
            .await
            .map_err(failed)?;
    }
    write_record(storage, layout.journal, encoded.as_bytes()).await?;
    let outcome = run(storage, layout, transaction).await?;
    remove_record(storage, layout.journal).await?;
    Ok(outcome)
}

fn transaction(operation: Operation, name: &str) -> Transaction {
    Transaction {
        schema: Some(TRANSACTION_SCHEMA_URL.into()),
        format_version: TRANSACTION_FORMAT_VERSION,
        operation,
        name: name.into(),
        staging: None,
        previous: None,
        origin: None,
        previous_origin: None,
    }
}

/// Make the verified, sealed bundle in `staging` (a name inside the bundles
/// directory) the installed version of `origin.name`.
pub async fn activate<S: Storage>(
    storage: &mut S,
    layout: &Layout<'_>,
    staging: &str,
    origin: Origin,
    mode: Mode,
) -> Result<Activated, S::Error> {
    origin.validate()?;
    if !is_temporary_name(staging, STAGING_PREFIX)
        || !storage
            .exists(&layout.bundle(staging))
            .await
            .map_err(failed)?
    {
        return Err(Error::InvalidStaging);
    }
    pending(storage, layout).await?;
    let name = origin.name.clone();
    let installed = storage
        .exists(&layout.bundle(&name))
        .await
        .map_err(failed)?;
    let previous_origin = if installed {
        self::origin(storage, layout, &name).await?
    } else {
        None
    };
    let mut journal = match (mode, installed) {
        (Mode::Install, false) => transaction(Operation::Install, &name),
        (Mode::Install, true) => {
            return Err(Error::AlreadyInstalled {
                version: previous_origin.map(|origin| origin.version),
            });
        }
        (Mode::Upgrade, false) => return Err(Error::NotInstalled),
        (Mode::Upgrade, true) => {
            check_upgrade(previous_origin.as_ref(), &origin)?;
            let mut journal = transaction(Operation::Upgrade, &name);
            journal.previous = Some(format!("{PREVIOUS_PREFIX}{name}"));
            journal.previous_origin = previous_origin.clone();
            journal
        }
    };
    journal.staging = Some(staging.into());
    journal.origin = Some(origin);
    match execute(storage, layout, &journal).await? {
        Outcome::RolledBack => Err(Error::InvalidStaging),
        Outcome::Completed if mode == Mode::Install => Ok(Activated::Installed),
        Outcome::Completed => Ok(Activated::Upgraded {
            previous: previous_origin,
        }),
    }
}

/// Remove an installed bundle and its origin record; returns that origin.
pub async fn remove<S: Storage>(
    storage: &mut S,
    layout: &Layout<'_>,
    name: &str,
) -> Result<Option<Origin>, S::Error> {
    let mut journal = transaction(Operation::Remove, name);
    journal.previous = Some(format!("{REMOVING_PREFIX}{name}"));
    journal.validate()?;
    pending(storage, layout).await?;
    if !storage.exists(&layout.bundle(name)).await.map_err(failed)? {
        return Err(Error::NotInstalled);
    }
    let previous_origin = origin(storage, layout, name).await?;
    journal.previous_origin = previous_origin.clone();
    execute(storage, layout, &journal).await?;
    Ok(previous_origin)
}

/// Finish or undo an interrupted transaction, then delete every temporary
/// entry (staging, previous, removing and download) of the bundles directory.
///
/// Run it before creating a staging directory, never during an operation.
pub async fn recover<S: Storage>(
    storage: &mut S,
    layout: &Layout<'_>,
) -> Result<Recovery, S::Error> {
    let mut recovery = Recovery::default();
    if let Some(transaction) = read_record(storage, layout.journal, decode_transaction).await? {
        let outcome = run(storage, layout, &transaction).await?;
        remove_record(storage, layout.journal).await?;
        recovery.transaction = Some((transaction, outcome));
    } else {
        // An incomplete journal sibling is a write that never took effect.
        remove_record(storage, layout.journal).await?;
    }
    let mut entries = storage.list(layout.bundles).await.map_err(failed)?;
    entries.sort();
    for entry in entries {
        if is_temporary_entry(&entry) {
            storage
                .remove(&layout.bundle(&entry))
                .await
                .map_err(failed)?;
            recovery.removed.push(entry);
        }
    }
    Ok(recovery)
}
