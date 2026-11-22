//! Installation transactions over an in-memory storage that can lose power
//! after any number of writes, including in the middle of a file write.

use std::{
    collections::BTreeMap,
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};

use xila_package_manager::installation::{self, Activated, Error, Layout, Mode, Outcome, Storage};
use xila_package_manifest::{
    ORIGIN_SCHEMA_URL, Operation, Origin, REPOSITORY_FORMAT_VERSION, is_temporary_entry,
};

const LAYOUT: Layout<'static> = Layout {
    bundles: "/applications/bundles",
    origins: "/configuration/system/packages/installed",
    journal: "/configuration/system/packages/transaction.json",
};
const NAME: &str = "xila.clock";
const BUNDLE: &str = "/applications/bundles/xila.clock";
const STAGING: &str = ".incoming-1";
const DATA: &str = "/users/administrator/.local/xila.clock/settings.json";

/// Poll a future that never waits (the memory storage is synchronous).
fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let mut context = Context::from_waker(Waker::noop());
    match future.as_mut().poll(&mut context) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("memory storage never waits"),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Failure {
    PowerLoss,
    NotFound,
    AlreadyExists,
    NotADirectory,
}

/// Files (`Some`) and directories (`None`) by absolute path.
#[derive(Clone, Default)]
struct Memory {
    entries: BTreeMap<String, Option<Vec<u8>>>,
    /// Writes left before power is lost; `None` never loses power.
    budget: Option<usize>,
    off: bool,
    writes: usize,
}

fn parent(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(parent, _)| parent)
}

impl Memory {
    fn new() -> Self {
        let mut memory = Self::default();
        for directory in [
            "/applications",
            LAYOUT.bundles,
            "/configuration",
            "/configuration/system",
            "/configuration/system/packages",
            LAYOUT.origins,
            "/users",
            "/users/administrator",
            "/users/administrator/.local",
            "/users/administrator/.local/xila.clock",
        ] {
            memory.entries.insert(directory.into(), None);
        }
        memory
            .entries
            .insert(DATA.into(), Some(b"{\"alarm\":7}".to_vec()));
        memory
    }

    fn directory(&mut self, path: &str) {
        self.entries.insert(path.into(), None);
    }

    fn file(&mut self, path: &str, bytes: &[u8]) {
        self.entries.insert(path.into(), Some(bytes.to_vec()));
    }

    /// A verified bundle of `version` with an entrypoint named after it.
    fn bundle(&mut self, path: &str, version: &str) {
        self.directory(path);
        self.directory(&format!("{path}/executables"));
        self.file(&format!("{path}/version"), version.as_bytes());
        self.file(
            &format!("{path}/executables/clock-{version}.wasm"),
            b"\0asm",
        );
    }

    fn staged(&mut self, version: &str) {
        self.bundle(&format!("{}/{STAGING}", LAYOUT.bundles), version);
    }

    fn version(&self, path: &str) -> Option<String> {
        self.entries
            .get(&format!("{path}/version"))
            .and_then(|bytes| bytes.as_deref())
            .map(|bytes| String::from_utf8(bytes.to_vec()).unwrap())
    }

    fn paths_below(&self, path: &str) -> Vec<String> {
        let prefix = format!("{path}/");
        self.entries
            .keys()
            .filter(|key| key.as_str() == path || key.starts_with(&prefix))
            .cloned()
            .collect()
    }

    fn power(&self) -> Result<(), Failure> {
        if self.off {
            Err(Failure::PowerLoss)
        } else {
            Ok(())
        }
    }

    /// Count one write; `true` when power is lost during it.
    fn lose_power(&mut self) -> bool {
        self.writes += 1;
        match &mut self.budget {
            Some(0) => {
                self.off = true;
                true
            }
            Some(budget) => {
                *budget -= 1;
                false
            }
            None => false,
        }
    }

    fn restart(&mut self) {
        self.off = false;
        self.budget = None;
    }

    fn require_directory(&self, path: &str) -> Result<(), Failure> {
        match self.entries.get(path) {
            Some(None) => Ok(()),
            Some(Some(_)) => Err(Failure::NotADirectory),
            None => Err(Failure::NotFound),
        }
    }
}

impl Storage for Memory {
    type Error = Failure;

    async fn exists(&mut self, path: &str) -> Result<bool, Failure> {
        self.power()?;
        Ok(self.entries.contains_key(path))
    }

    async fn rename(&mut self, from: &str, to: &str) -> Result<(), Failure> {
        self.power()?;
        if !self.entries.contains_key(from) {
            return Err(Failure::NotFound);
        }
        if self.entries.contains_key(to) {
            return Err(Failure::AlreadyExists);
        }
        self.require_directory(parent(to))?;
        if self.lose_power() {
            return Err(Failure::PowerLoss);
        }
        for path in self.paths_below(from) {
            let value = self.entries.remove(&path).unwrap();
            self.entries
                .insert(format!("{to}{}", &path[from.len()..]), value);
        }
        Ok(())
    }

    async fn remove(&mut self, path: &str) -> Result<(), Failure> {
        self.power()?;
        let paths = self.paths_below(path);
        if paths.is_empty() {
            return Ok(());
        }
        // A tree is deleted one entry at a time, deepest first.
        for path in paths.into_iter().rev() {
            if self.lose_power() {
                return Err(Failure::PowerLoss);
            }
            self.entries.remove(&path);
        }
        Ok(())
    }

    async fn read(&mut self, path: &str, limit: usize) -> Result<Option<Vec<u8>>, Failure> {
        self.power()?;
        match self.entries.get(path) {
            None => Ok(None),
            Some(None) => Err(Failure::NotADirectory),
            Some(Some(bytes)) => Ok(Some(bytes[..bytes.len().min(limit)].to_vec())),
        }
    }

    async fn write(&mut self, path: &str, bytes: &[u8]) -> Result<(), Failure> {
        self.power()?;
        self.require_directory(parent(path))?;
        if self.lose_power() {
            // Torn write: only the first half reached the storage.
            self.file(path, &bytes[..bytes.len() / 2]);
            return Err(Failure::PowerLoss);
        }
        self.file(path, bytes);
        Ok(())
    }

    async fn list(&mut self, path: &str) -> Result<Vec<String>, Failure> {
        self.power()?;
        self.require_directory(path)?;
        let prefix = format!("{path}/");
        Ok(self
            .entries
            .keys()
            .filter_map(|key| key.strip_prefix(&prefix))
            .filter(|rest| !rest.contains('/'))
            .map(Into::into)
            .collect())
    }
}

fn origin(version: &str, repository: Option<&str>) -> Origin {
    Origin {
        schema: Some(ORIGIN_SCHEMA_URL.into()),
        format_version: REPOSITORY_FORMAT_VERSION,
        repository: repository.map(Into::into),
        name: NAME.into(),
        version: version.into(),
        archive_sha256: "a".repeat(64),
    }
}

fn installed_origin(memory: &mut Memory) -> Option<Origin> {
    block_on(installation::origin(memory, &LAYOUT, NAME)).unwrap()
}

fn activate(memory: &mut Memory, version: &str, mode: Mode) -> Result<Activated, Error<Failure>> {
    block_on(installation::activate(
        memory,
        &LAYOUT,
        STAGING,
        origin(version, Some("xila")),
        mode,
    ))
}

/// A device with `version` installed from the `xila` repository.
fn installed(version: &str) -> Memory {
    let mut memory = Memory::new();
    memory.staged(version);
    assert_eq!(
        activate(&mut memory, version, Mode::Install),
        Ok(Activated::Installed)
    );
    memory
}

/// After recovery, the device is in a consistent state; returns its version.
fn assert_consistent(memory: &mut Memory) -> Option<String> {
    let journal = LAYOUT.journal;
    assert!(!memory.entries.contains_key(journal), "journal left");
    assert!(
        !memory.entries.contains_key(&format!("{journal}.new")),
        "journal sibling left"
    );
    let entries = block_on(memory.list(LAYOUT.bundles)).unwrap();
    assert!(
        entries.iter().all(|entry| !is_temporary_entry(entry)),
        "temporary entries left: {entries:?}"
    );
    assert_eq!(
        memory.entries.get(DATA),
        Some(&Some(b"{\"alarm\":7}".to_vec())),
        "user data changed"
    );
    let version = memory.version(BUNDLE);
    let origin = installed_origin(memory);
    assert_eq!(
        origin.map(|origin| origin.version),
        version,
        "origin disagrees with the bundle"
    );
    if let Some(version) = &version {
        // Exactly the files of that version: nothing obsolete survives.
        let entrypoints: Vec<_> = memory
            .paths_below(&format!("{BUNDLE}/executables"))
            .into_iter()
            .skip(1)
            .collect();
        assert_eq!(
            entrypoints,
            [format!("{BUNDLE}/executables/clock-{version}.wasm")]
        );
    }
    version
}

/// Interrupt `operation` after every possible number of writes, recover
/// (itself interrupted at every step once), and check the result each time.
fn interrupt_everywhere(
    prepare: impl Fn() -> Memory,
    operation: impl Fn(&mut Memory) -> bool,
    allowed: &[Option<&str>],
) -> Vec<Option<String>> {
    let mut outcomes = Vec::new();
    for budget in 0.. {
        let mut memory = prepare();
        memory.budget = Some(budget);
        let succeeded = operation(&mut memory);
        if !memory.off {
            assert!(succeeded, "operation failed without a power loss");
            assert!(budget > 0);
            break;
        }
        assert!(!succeeded);
        // Power returns, and recovery may itself be interrupted.
        for recovery_budget in 0.. {
            let mut device = memory.clone();
            device.restart();
            device.budget = Some(recovery_budget);
            let recovered = block_on(installation::recover(&mut device, &LAYOUT)).is_ok();
            device.restart();
            if !recovered {
                block_on(installation::recover(&mut device, &LAYOUT)).unwrap();
            }
            let version = assert_consistent(&mut device);
            assert!(
                allowed.contains(&version.as_deref()),
                "unexpected {version:?} after {budget} writes"
            );
            outcomes.push(version);
            if recovered {
                break;
            }
        }
    }
    outcomes
}

#[test]
fn installs_a_verified_bundle_and_records_its_origin() {
    let mut memory = installed("0.1.0");
    assert_eq!(assert_consistent(&mut memory).as_deref(), Some("0.1.0"));
    assert_eq!(
        installed_origin(&mut memory).unwrap().repository.as_deref(),
        Some("xila")
    );
    memory.staged("0.1.0");
    assert_eq!(
        activate(&mut memory, "0.1.0", Mode::Install),
        Err(Error::AlreadyInstalled {
            version: Some("0.1.0".into())
        })
    );
    // A failed activation leaves its staging directory to recovery.
    let recovery = block_on(installation::recover(&mut memory, &LAYOUT)).unwrap();
    assert_eq!(recovery.transaction, None);
    assert_eq!(recovery.removed, [STAGING]);
    assert_eq!(assert_consistent(&mut memory).as_deref(), Some("0.1.0"));
}

#[test]
fn rejects_invalid_staging_directories() {
    let mut memory = Memory::new();
    assert_eq!(
        activate(&mut memory, "0.1.0", Mode::Install),
        Err(Error::InvalidStaging)
    );
    memory.bundle("/applications/bundles/elsewhere", "0.1.0");
    let result = block_on(installation::activate(
        &mut memory,
        &LAYOUT,
        "elsewhere",
        origin("0.1.0", None),
        Mode::Install,
    ));
    assert_eq!(result, Err(Error::InvalidStaging));
    assert_eq!(
        activate(&mut Memory::new(), "0.1.0", Mode::Upgrade),
        Err(Error::InvalidStaging)
    );
    let mut memory = Memory::new();
    memory.staged("0.1.0");
    assert_eq!(
        activate(&mut memory, "0.1.0", Mode::Upgrade),
        Err(Error::NotInstalled)
    );
}

#[test]
fn upgrade_replaces_the_bundle_and_keeps_user_data() {
    let mut memory = installed("0.1.0");
    memory.staged("0.2.0");
    assert_eq!(
        activate(&mut memory, "0.2.0", Mode::Upgrade),
        Ok(Activated::Upgraded {
            previous: Some(origin("0.1.0", Some("xila")))
        })
    );
    // The 0.1.0 entrypoint is gone with the old bundle; the data stays.
    assert_eq!(assert_consistent(&mut memory).as_deref(), Some("0.2.0"));
}

#[test]
fn upgrade_requires_a_newer_version_from_the_same_repository() {
    let mut memory = installed("0.2.0");
    memory.staged("0.2.0");
    for version in ["0.2.0", "0.1.9", "0.2.0-beta.1", "latest"] {
        assert!(matches!(
            activate(&mut memory, version, Mode::Upgrade),
            Err(Error::NotNewer { .. })
        ));
    }
    let other = block_on(installation::activate(
        &mut memory,
        &LAYOUT,
        STAGING,
        origin("0.3.0", Some("community")),
        Mode::Upgrade,
    ));
    assert_eq!(
        other,
        Err(Error::OtherRepository {
            installed: Some("xila".into()),
            offered: Some("community".into())
        })
    );
    let local = block_on(installation::activate(
        &mut memory,
        &LAYOUT,
        STAGING,
        origin("0.3.0", None),
        Mode::Upgrade,
    ));
    assert!(matches!(local, Err(Error::OtherRepository { .. })));
    assert_eq!(
        format!("{}", local.unwrap_err()),
        "it was installed from xila, not from a local archive"
    );
    block_on(installation::recover(&mut memory, &LAYOUT)).unwrap();
    assert_eq!(assert_consistent(&mut memory).as_deref(), Some("0.2.0"));
}

#[test]
fn bundles_seeded_without_an_origin_can_be_upgraded_and_removed() {
    let mut memory = Memory::new();
    memory.bundle(BUNDLE, "0.0.1");
    memory.staged("0.1.0");
    assert_eq!(
        activate(&mut memory, "0.1.0", Mode::Upgrade),
        Ok(Activated::Upgraded { previous: None })
    );
    assert_eq!(assert_consistent(&mut memory).as_deref(), Some("0.1.0"));

    let mut memory = Memory::new();
    memory.bundle(BUNDLE, "0.0.1");
    assert_eq!(
        block_on(installation::remove(&mut memory, &LAYOUT, NAME)),
        Ok(None)
    );
    assert_eq!(assert_consistent(&mut memory), None);
}

#[test]
fn remove_deletes_the_bundle_and_origin_but_keeps_user_data() {
    let mut memory = installed("0.1.0");
    assert_eq!(
        block_on(installation::remove(&mut memory, &LAYOUT, NAME)),
        Ok(Some(origin("0.1.0", Some("xila"))))
    );
    assert_eq!(assert_consistent(&mut memory), None);
    assert!(memory.paths_below(BUNDLE).is_empty());
    assert_eq!(
        block_on(installation::remove(&mut memory, &LAYOUT, NAME)),
        Err(Error::NotInstalled)
    );
    assert!(matches!(
        block_on(installation::remove(&mut memory, &LAYOUT, "../system")),
        Err(Error::Record(_))
    ));
}

#[test]
fn recovery_removes_abandoned_temporary_entries_only() {
    let mut memory = installed("0.1.0");
    memory.bundle("/applications/bundles/.incoming-7", "0.9.0");
    memory.file("/applications/bundles/.download-3.xpk", b"partial");
    memory.bundle("/applications/bundles/.removing-xila.other", "0.1.0");
    memory.directory("/applications/bundles/.hidden");
    let recovery = block_on(installation::recover(&mut memory, &LAYOUT)).unwrap();
    assert_eq!(
        recovery.removed,
        [".download-3.xpk", ".incoming-7", ".removing-xila.other"]
    );
    assert!(memory.entries.contains_key("/applications/bundles/.hidden"));
    assert_eq!(assert_consistent(&mut memory).as_deref(), Some("0.1.0"));
}

#[test]
fn a_pending_or_malformed_journal_blocks_new_operations() {
    let mut memory = installed("0.1.0");
    memory.file(LAYOUT.journal, b"{not json");
    memory.staged("0.2.0");
    assert_eq!(
        activate(&mut memory, "0.2.0", Mode::Upgrade),
        Err(Error::Pending)
    );
    assert_eq!(
        block_on(installation::remove(&mut memory, &LAYOUT, NAME)),
        Err(Error::Pending)
    );
    // Recovery refuses to guess; the journal is kept for inspection.
    assert!(matches!(
        block_on(installation::recover(&mut memory, &LAYOUT)),
        Err(Error::Record(_))
    ));
    assert!(memory.entries.contains_key(LAYOUT.journal));

    // An incomplete sibling, without a journal, is a write that never happened.
    let mut memory = installed("0.1.0");
    memory.file(&format!("{}.new", LAYOUT.journal), b"{\"format_ver");
    let recovery = block_on(installation::recover(&mut memory, &LAYOUT)).unwrap();
    assert_eq!(recovery.transaction, None);
    assert_eq!(assert_consistent(&mut memory).as_deref(), Some("0.1.0"));
}

#[test]
fn interrupted_install_either_completes_or_leaves_nothing() {
    let prepare = || {
        let mut memory = Memory::new();
        memory.staged("0.1.0");
        memory
    };
    let outcomes = interrupt_everywhere(
        prepare,
        |memory| activate(memory, "0.1.0", Mode::Install).is_ok(),
        &[None, Some("0.1.0")],
    );
    // Early interruptions roll back, later ones roll forward.
    assert!(outcomes.contains(&None));
    assert!(outcomes.contains(&Some("0.1.0".into())));
}

#[test]
fn interrupted_upgrade_keeps_a_working_version_at_every_step() {
    let prepare = || {
        let mut memory = installed("0.1.0");
        memory.staged("0.2.0");
        memory
    };
    let outcomes = interrupt_everywhere(
        prepare,
        |memory| activate(memory, "0.2.0", Mode::Upgrade).is_ok(),
        // Never nothing: the previous version stays until the new one is active.
        &[Some("0.1.0"), Some("0.2.0")],
    );
    assert!(outcomes.contains(&Some("0.1.0".into())));
    assert!(outcomes.contains(&Some("0.2.0".into())));
}

#[test]
fn interrupted_remove_is_finished_by_recovery() {
    let outcomes = interrupt_everywhere(
        || installed("0.1.0"),
        |memory| block_on(installation::remove(memory, &LAYOUT, NAME)).is_ok(),
        &[None, Some("0.1.0")],
    );
    assert!(outcomes.contains(&None));
}

#[test]
fn recovery_reports_the_interrupted_transaction() {
    // Power is lost right after the journal and the first rename of an upgrade.
    let mut memory = installed("0.1.0");
    memory.staged("0.2.0");
    // Journal: sibling write, (no) removal, rename; then bundle → previous.
    memory.budget = Some(3);
    assert!(activate(&mut memory, "0.2.0", Mode::Upgrade).is_err());
    assert!(!memory.entries.contains_key(BUNDLE), "bundle moved aside");
    memory.restart();
    let recovery = block_on(installation::recover(&mut memory, &LAYOUT)).unwrap();
    let (transaction, outcome) = recovery.transaction.unwrap();
    assert_eq!(transaction.operation, Operation::Upgrade);
    assert_eq!(outcome, Outcome::Completed);
    assert_eq!(assert_consistent(&mut memory).as_deref(), Some("0.2.0"));

    // The staging directory vanished mid-upgrade: the previous version returns.
    let mut memory = installed("0.1.0");
    memory.staged("0.2.0");
    memory.budget = Some(3);
    assert!(activate(&mut memory, "0.2.0", Mode::Upgrade).is_err());
    memory.restart();
    block_on(memory.remove(&format!("{}/{STAGING}", LAYOUT.bundles))).unwrap();
    let recovery = block_on(installation::recover(&mut memory, &LAYOUT)).unwrap();
    assert_eq!(recovery.transaction.unwrap().1, Outcome::RolledBack);
    assert_eq!(assert_consistent(&mut memory).as_deref(), Some("0.1.0"));
}
