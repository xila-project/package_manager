use ed25519_dalek::{Signer, SigningKey};
use std::{
    cell::Cell,
    collections::{BTreeMap, BTreeSet},
    string::{String, ToString},
    vec::Vec,
};
use xila_package_manager::{
    installer::{self, Store, StoreError},
    lifecycle::{Policy, StorageGuarantees},
};
use xila_package_manifest::{Application, FORMAT_VERSION, Manifest, ManifestFile, SCHEMA_URL};
use xila_package_verification::{PublicKey, Sha256Verifier};
use xila_package_writer::{SourceFile, write_package};

/// In-memory durable filesystem emulator, including partial append faults.
/// This tests the portable algorithm, not actual device power-loss atomicity.
#[derive(Clone)]
struct MemoryStore {
    directories: BTreeSet<String>,
    files: BTreeMap<String, Vec<u8>>,
    operations: Cell<usize>,
    fail_at: Option<usize>,
}

impl MemoryStore {
    fn new() -> Self {
        Self {
            directories: BTreeSet::from(["/".to_string()]),
            files: BTreeMap::new(),
            operations: Cell::new(0),
            fail_at: None,
        }
    }

    fn fail_operation(&self) -> bool {
        let index = self.operations.get();
        self.operations.set(index + 1);
        self.fail_at == Some(index)
    }

    fn parent(path: &str) -> &str {
        match path.rsplit_once('/') {
            Some(("", _)) => "/",
            Some((p, _)) => p,
            None => "/",
        }
    }

    fn inject_at(&mut self, step: usize) {
        self.operations.set(0);
        self.fail_at = Some(step);
    }

    fn restore_after_crash(&mut self) {
        self.fail_at = None;
        self.operations.set(0);
    }
}

impl Store for MemoryStore {
    fn guarantees(&self) -> StorageGuarantees {
        StorageGuarantees {
            same_bundle_mount: true,
            atomic_new_directory_rename: true,
            atomic_activation_replace: true,
            durable_writes_and_directory_sync: true,
            contained_namespace: true,
        }
    }

    fn exists(&self, path: &str) -> Result<bool, StoreError> {
        if self.fail_operation() {
            return Err(StoreError::Io);
        }
        Ok(self.files.contains_key(path) || self.directories.contains(path))
    }

    fn create_directory(&mut self, path: &str) -> Result<(), StoreError> {
        if self.fail_operation() {
            return Err(StoreError::Io);
        }
        if self.files.contains_key(path) {
            return Err(StoreError::AlreadyExists);
        }
        if !self.directories.contains(Self::parent(path)) {
            return Err(StoreError::NotFound);
        }
        self.directories.insert(path.to_string());
        Ok(())
    }

    fn create_directory_new(&mut self, path: &str) -> Result<(), StoreError> {
        if self.fail_operation() {
            return Err(StoreError::Io);
        }
        if self.directories.contains(path) || self.files.contains_key(path) {
            return Err(StoreError::AlreadyExists);
        }
        if !self.directories.contains(Self::parent(path)) {
            return Err(StoreError::NotFound);
        }
        self.directories.insert(path.to_string());
        Ok(())
    }

    fn create_file_new(&mut self, path: &str) -> Result<(), StoreError> {
        if self.fail_operation() {
            return Err(StoreError::Io);
        }
        if self.files.contains_key(path) || self.directories.contains(path) {
            return Err(StoreError::AlreadyExists);
        }
        if !self.directories.contains(Self::parent(path)) {
            return Err(StoreError::NotFound);
        }
        self.files.insert(path.to_string(), Vec::new());
        Ok(())
    }

    fn append(&mut self, path: &str, chunk: &[u8]) -> Result<(), StoreError> {
        if self.fail_operation() {
            // Simulate a partial write and an abrupt reboot before fsync.
            if let Some(data) = self.files.get_mut(path) {
                data.extend_from_slice(&chunk[..chunk.len() / 2]);
            }
            return Err(StoreError::Io);
        }
        self.files
            .get_mut(path)
            .ok_or(StoreError::NotFound)?
            .extend_from_slice(chunk);
        Ok(())
    }

    fn read_at(&self, path: &str, offset: u64, dst: &mut [u8]) -> Result<usize, StoreError> {
        if self.fail_operation() {
            return Err(StoreError::Io);
        }
        let file = self.files.get(path).ok_or(StoreError::NotFound)?;
        let position: usize = offset.try_into().map_err(|_| StoreError::Io)?;
        if position >= file.len() {
            return Ok(0);
        }
        let len = (file.len() - position).min(dst.len());
        dst[..len].copy_from_slice(&file[position..position + len]);
        Ok(len)
    }

    fn sync_file(&mut self, path: &str) -> Result<(), StoreError> {
        if self.fail_operation() {
            return Err(StoreError::Io);
        }
        if !self.files.contains_key(path) {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    fn sync_directory(&mut self, path: &str) -> Result<(), StoreError> {
        if self.fail_operation() {
            return Err(StoreError::Io);
        }
        if !self.directories.contains(path) {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    fn rename_new(&mut self, from: &str, to: &str) -> Result<(), StoreError> {
        if self.fail_operation() {
            return Err(StoreError::Io);
        }
        if self.files.contains_key(to) || self.directories.contains(to) {
            return Err(StoreError::AlreadyExists);
        }
        if !self.directories.contains(Self::parent(to)) {
            return Err(StoreError::NotFound);
        }
        if !self.directories.remove(from) {
            return Err(StoreError::NotFound);
        }
        self.directories.insert(to.to_string());
        let prefix = format!("{from}/");
        let old_dirs: Vec<_> = self
            .directories
            .iter()
            .filter(|k| k.starts_with(&prefix))
            .cloned()
            .collect();
        for key in old_dirs {
            self.directories.remove(&key);
            self.directories
                .insert(format!("{to}{}", &key[from.len()..]));
        }
        let old_files: Vec<_> = self
            .files
            .keys()
            .filter(|k| k.starts_with(&prefix))
            .cloned()
            .collect();
        for key in old_files {
            let value = self.files.remove(&key).unwrap();
            self.files
                .insert(format!("{to}{}", &key[from.len()..]), value);
        }
        Ok(())
    }

    fn replace_file(&mut self, from: &str, to: &str) -> Result<(), StoreError> {
        if self.fail_operation() {
            return Err(StoreError::Io);
        }
        if self.directories.contains(to) {
            return Err(StoreError::AlreadyExists);
        }
        let value = self.files.remove(from).ok_or(StoreError::NotFound)?;
        self.files.insert(to.to_string(), value);
        Ok(())
    }

    fn remove_file(&mut self, path: &str) -> Result<(), StoreError> {
        if self.fail_operation() {
            return Err(StoreError::Io);
        }
        self.files.remove(path).ok_or(StoreError::NotFound)?;
        Ok(())
    }

    fn remove_tree(&mut self, path: &str) -> Result<(), StoreError> {
        if self.fail_operation() {
            return Err(StoreError::Io);
        }
        if !self.directories.remove(path) {
            return Err(StoreError::NotFound);
        }
        let prefix = format!("{path}/");
        self.directories.retain(|k| !k.starts_with(&prefix));
        self.files.retain(|k, _| !k.starts_with(&prefix));
        Ok(())
    }
}

fn signed_fixture(version: &str, payload: &[u8]) -> (Vec<u8>, PublicKey, Manifest) {
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let public = PublicKey::from_bytes(&key.verifying_key().to_bytes()).unwrap();
    let mut sha = Sha256Verifier::new();
    sha.update(payload).unwrap();
    let digest = sha.finalize().unwrap();
    let sha256 = digest
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let manifest = Manifest {
        schema: Some(SCHEMA_URL.to_string()),
        format_version: FORMAT_VERSION,
        name: "xila.calculator".into(),
        version: version.into(),
        target: "wasm32-wasip1".into(),
        minimum_xila_abi: 1,
        capabilities: vec![],
        files: vec![ManifestFile {
            path: "bin/calculator.wasm".into(),
            size: payload.len() as u64,
            sha256,
        }],
        application: Some(Application {
            entrypoint: "bin/calculator.wasm".into(),
            display_name: "Calculator".into(),
            icon: String::new(),
            show_in_launcher: true,
        }),
    };
    let json = xila_package_manifest::encode(&manifest).unwrap();
    let mut buf = vec![0u8; xila_package_manifest::SIGNED_DOMAIN.len() + 4 + json.len()];
    let message = xila_package_manifest::signed_message_into(json.as_bytes(), &mut buf).unwrap();
    let sig = key.sign(message).to_bytes();
    let mut archive = Vec::new();
    write_package(
        &mut archive,
        &manifest,
        &[SourceFile {
            path: "bin/calculator.wasm",
            bytes: payload,
        }],
        Some(&sig),
    )
    .unwrap();
    (archive, public, manifest)
}

fn policy() -> Policy<'static> {
    Policy {
        target: "wasm32-wasip1",
        xila_abi: 1,
        allowed_capabilities: &[],
        allow_external_entrypoints: false,
    }
}

#[test]
fn install_verify_rollback_and_uninstall_preserve_user_state() {
    let (v1, key, _) = signed_fixture("1.0.0", b"abc");
    let (v2, _, _) = signed_fixture("2.0.0", b"def");
    let mut fs = MemoryStore::new();
    let installed = installer::install(&mut fs, &v1, &key, &policy(), 1).unwrap();
    assert_eq!(installed.version, "1.0.0");
    assert_eq!(
        installer::resolve_active(&fs, "xila.calculator", &key, &policy())
            .unwrap()
            .entrypoint,
        "/applications/bundles/xila.calculator/1.0.0/bin/calculator.wasm"
    );
    // App data must remain independent of package installation/uninstallation.
    fs.create_directory("/data").unwrap();
    fs.create_directory("/data/applications").unwrap();
    fs.create_directory("/data/applications/xila.calculator")
        .unwrap();
    fs.create_file_new("/data/applications/xila.calculator/settings")
        .unwrap();
    fs.append("/data/applications/xila.calculator/settings", b"saved")
        .unwrap();

    installer::install(&mut fs, &v2, &key, &policy(), 2).unwrap();
    assert!(
        installer::resolve_active(&fs, "xila.calculator", &key, &policy())
            .unwrap()
            .entrypoint
            .contains("/2.0.0/")
    );
    installer::activate_existing(&mut fs, "xila.calculator", "1.0.0", &key, &policy(), 3).unwrap();
    assert!(
        installer::resolve_active(&fs, "xila.calculator", &key, &policy())
            .unwrap()
            .entrypoint
            .contains("/1.0.0/")
    );
    installer::uninstall_active(&mut fs, "xila.calculator", &key, &policy()).unwrap();
    assert!(matches!(
        installer::resolve_active(&fs, "xila.calculator", &key, &policy()),
        Err(installer::Error::MissingActiveRecord)
    ));
    assert!(
        fs.exists("/applications/bundles/xila.calculator/2.0.0")
            .unwrap()
    );
    assert_eq!(
        fs.files["/data/applications/xila.calculator/settings"],
        b"saved"
    );
}

#[test]
fn invalid_signature_hash_capabilities_and_downgrade_fail_closed() {
    let (mut archive, key, _) = signed_fixture("1.0.0", b"abc");
    let mut fs = MemoryStore::new();
    let wrong_key = SigningKey::from_bytes(&[8u8; 32]);
    let wrong_public = PublicKey::from_bytes(&wrong_key.verifying_key().to_bytes()).unwrap();
    assert!(installer::install(&mut fs, &archive, &wrong_public, &policy(), 1).is_err());
    assert!(fs.files.is_empty());
    let index = archive.windows(3).position(|w| w == b"abc").unwrap();
    archive[index] ^= 1;
    assert!(installer::install(&mut fs, &archive, &key, &policy(), 1).is_err());
    assert!(fs.files.is_empty());
    let (archive, _, _) = signed_fixture("1.0.0", b"abc");
    let denied = Policy {
        target: "unknown",
        ..policy()
    };
    assert!(installer::install(&mut fs, &archive, &key, &denied, 1).is_err());
    assert!(fs.files.is_empty());
    installer::install(&mut fs, &archive, &key, &policy(), 1).unwrap();
    let path = "/applications/bundles/xila.calculator/1.0.0/bin/calculator.wasm";
    fs.files.get_mut(path).unwrap()[0] ^= 1;
    assert!(matches!(
        installer::resolve_active(&fs, "xila.calculator", &key, &policy()),
        Err(installer::Error::CorruptInstalledFile)
    ));
}

#[test]
fn interruption_at_each_io_operation_never_exposes_unverified_content() {
    let (old_archive, key, _) = signed_fixture("1.0.0", b"old");
    let (new_archive, _, new_manifest) = signed_fixture("2.0.0", b"new");
    let mut base = MemoryStore::new();
    installer::install(&mut base, &old_archive, &key, &policy(), 1).unwrap();

    let mut successful = base.clone();
    successful.operations.set(0);
    installer::install(&mut successful, &new_archive, &key, &policy(), 2).unwrap();
    let count = successful.operations.get();

    for cut in 0..count {
        let mut rebooted = base.clone();
        rebooted.inject_at(cut);
        let outcome = installer::install(&mut rebooted, &new_archive, &key, &policy(), 2);
        assert!(outcome.is_err(), "cut {cut} unexpectedly succeeded");
        rebooted.restore_after_crash();
        let candidate = installer::resolve_active(&rebooted, "xila.calculator", &key, &policy())
            .unwrap_or_else(|e| panic!("cut {cut} yielded invalid active: {e:?}"));
        assert!(
            candidate.entrypoint.contains("/1.0.0/") || candidate.entrypoint.contains("/2.0.0/"),
            "cut {cut} produced unexpected active pointer"
        );
        // Partial staging is strictly inert. A known failed transaction can
        // be cleaned up; a complete-but-inactive version is kept for recovery.
        installer::discard_staging(&mut rebooted, &new_manifest, &policy(), 2).unwrap();
        let again =
            installer::resolve_active(&rebooted, "xila.calculator", &key, &policy()).unwrap();
        assert_eq!(candidate, again);
    }
}

#[test]
fn installation_requires_verified_backend_guarantees() {
    let (archive, key, _) = signed_fixture("1.0.0", b"abc");
    struct UnsafeStore(MemoryStore);
    impl Store for UnsafeStore {
        fn guarantees(&self) -> StorageGuarantees {
            StorageGuarantees::default()
        }
        fn exists(&self, p: &str) -> Result<bool, StoreError> {
            self.0.exists(p)
        }
        fn create_directory(&mut self, p: &str) -> Result<(), StoreError> {
            self.0.create_directory(p)
        }
        fn create_directory_new(&mut self, p: &str) -> Result<(), StoreError> {
            self.0.create_directory_new(p)
        }
        fn create_file_new(&mut self, p: &str) -> Result<(), StoreError> {
            self.0.create_file_new(p)
        }
        fn append(&mut self, p: &str, b: &[u8]) -> Result<(), StoreError> {
            self.0.append(p, b)
        }
        fn read_at(&self, p: &str, o: u64, b: &mut [u8]) -> Result<usize, StoreError> {
            self.0.read_at(p, o, b)
        }
        fn sync_file(&mut self, p: &str) -> Result<(), StoreError> {
            self.0.sync_file(p)
        }
        fn sync_directory(&mut self, p: &str) -> Result<(), StoreError> {
            self.0.sync_directory(p)
        }
        fn rename_new(&mut self, a: &str, b: &str) -> Result<(), StoreError> {
            self.0.rename_new(a, b)
        }
        fn replace_file(&mut self, a: &str, b: &str) -> Result<(), StoreError> {
            self.0.replace_file(a, b)
        }
        fn remove_file(&mut self, p: &str) -> Result<(), StoreError> {
            self.0.remove_file(p)
        }
        fn remove_tree(&mut self, p: &str) -> Result<(), StoreError> {
            self.0.remove_tree(p)
        }
    }
    let mut unsafe_store = UnsafeStore(MemoryStore::new());
    assert!(installer::install(&mut unsafe_store, &archive, &key, &policy(), 1).is_err());
    assert!(unsafe_store.0.files.is_empty());
}
