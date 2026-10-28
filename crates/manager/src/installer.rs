//! Offline, authenticated package installation with a platform-independent
//! filesystem adapter. No VFS implementation or network dependency is used.
//!
//! The current archive reader takes a borrowed *whole TAR archive* until its
//! upstream streaming API lands. File writes and re-verification use fixed
//! 4096-byte buffers; no payload is copied into a second RAM buffer.

use crate::lifecycle::{
    self, ACTIVE_ROOT, ActivationRecord, BUNDLES_ROOT, LaunchTarget, MAX_ACTIVATION_BYTES, Plan,
    Policy, StorageGuarantees,
};
use alloc::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use tar_no_std::TarArchiveRef;
use xila_package_manifest::{
    MANIFEST_PATH, MAX_MANIFEST_BYTES, Manifest, SIGNATURE_PATH, SIGNED_DOMAIN,
};
use xila_package_verification::{ContentVerifier, PublicKey};

pub const IO_CHUNK: usize = 4096;

/// An adapter must implement exclusive file/directory creation, reject
/// symlinks/mount escapes, and provide real durability and atomicity guarantees.
/// All paths passed to it are absolute and validated by the package manifest.
pub trait Store {
    fn guarantees(&self) -> StorageGuarantees;
    fn exists(&self, path: &str) -> Result<bool, StoreError>;
    /// Idempotently create a trusted parent directory (reject a preexisting
    /// non-directory or symlink).
    fn create_directory(&mut self, path: &str) -> Result<(), StoreError>;
    /// Fail if the directory already exists.
    fn create_directory_new(&mut self, path: &str) -> Result<(), StoreError>;
    fn create_file_new(&mut self, path: &str) -> Result<(), StoreError>;
    /// Append all bytes or return an error. Partial writes are permissible on
    /// failure; the incomplete file must not become executable.
    fn append(&mut self, path: &str, chunk: &[u8]) -> Result<(), StoreError>;
    /// Return zero only at EOF. Never read outside the requested file.
    fn read_at(&self, path: &str, offset: u64, buffer: &mut [u8]) -> Result<usize, StoreError>;
    fn sync_file(&mut self, path: &str) -> Result<(), StoreError>;
    fn sync_directory(&mut self, path: &str) -> Result<(), StoreError>;
    /// Atomic, no-replace move; source and destination share the same mount.
    fn rename_new(&mut self, source: &str, destination: &str) -> Result<(), StoreError>;
    /// Atomic replace of one file; source and destination share the same mount.
    fn replace_file(&mut self, source: &str, destination: &str) -> Result<(), StoreError>;
    fn remove_file(&mut self, path: &str) -> Result<(), StoreError>;
    fn remove_tree(&mut self, path: &str) -> Result<(), StoreError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreError {
    NotFound,
    AlreadyExists,
    PermissionDenied,
    Unsupported,
    Io,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Lifecycle(lifecycle::Error),
    Archive(xila_package_reader::Error),
    Storage(StoreError),
    InvalidStoredManifest,
    InvalidStoredSignature,
    CorruptInstalledFile,
    MissingActiveRecord,
    IdentityMismatch,
}

impl From<StoreError> for Error {
    fn from(value: StoreError) -> Self {
        Self::Storage(value)
    }
}

impl From<lifecycle::Error> for Error {
    fn from(value: lifecycle::Error) -> Self {
        Self::Lifecycle(value)
    }
}

fn directory(path: &str) -> Result<&str, Error> {
    path.rsplit_once('/')
        .map(|(prefix, _)| if prefix.is_empty() { "/" } else { prefix })
        .ok_or(Error::Lifecycle(lifecycle::Error::InvalidPath))
}

fn ensure_directories<S: Store>(store: &mut S, path: &str) -> Result<(), Error> {
    // create_directory is explicitly idempotent and must check directory
    // identity and prevent traversal; it is NOT a mkdir-if-anything-exists.
    for (index, byte) in path.bytes().enumerate().skip(1) {
        if byte == b'/' {
            store.create_directory(&path[..index])?;
        }
    }
    store.create_directory(path)?;
    Ok(())
}

fn copy_verified<S: Store>(store: &mut S, path: &str, data: &[u8]) -> Result<(), Error> {
    ensure_directories(store, directory(path)?)?;
    store.create_file_new(path)?;
    for chunk in data.chunks(IO_CHUNK) {
        store.append(path, chunk)?;
    }
    store.sync_file(path)?;
    Ok(())
}

fn read_bounded<S: Store>(store: &S, path: &str, maximum: usize) -> Result<Vec<u8>, Error> {
    let mut result = Vec::new();
    let mut buffer = [0u8; IO_CHUNK];
    loop {
        // Read one byte beyond the max to detect oversized files without a
        // filesystem metadata/size API.
        let remaining = maximum.saturating_add(1).saturating_sub(result.len());
        if remaining == 0 {
            return Err(Error::CorruptInstalledFile);
        }
        let len = store.read_at(
            path,
            result.len() as u64,
            &mut buffer[..remaining.min(IO_CHUNK)],
        )?;
        if len == 0 {
            return Ok(result);
        }
        if len > remaining {
            return Err(Error::CorruptInstalledFile);
        }
        result.extend_from_slice(&buffer[..len]);
        if result.len() > maximum {
            return Err(Error::CorruptInstalledFile);
        }
    }
}

fn sha256_from_hex(hex: &str) -> Result<[u8; 32], Error> {
    let mut result = [0u8; 32];
    if hex.len() != 64 {
        return Err(Error::CorruptInstalledFile);
    }
    for (i, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
        let a = (pair[0] as char)
            .to_digit(16)
            .ok_or(Error::CorruptInstalledFile)?;
        let b = (pair[1] as char)
            .to_digit(16)
            .ok_or(Error::CorruptInstalledFile)?;
        result[i] = (a * 16 + b) as u8;
    }
    Ok(result)
}

fn verify_payload<S: Store>(store: &S, path: &str, size: u64, hash: &str) -> Result<(), Error> {
    let mut verifier = ContentVerifier::new(size, sha256_from_hex(hash)?)
        .map_err(|_| Error::CorruptInstalledFile)?;
    let mut offset = 0u64;
    let mut buffer = [0u8; IO_CHUNK];
    loop {
        let bytes = store.read_at(path, offset, &mut buffer)?;
        if bytes == 0 {
            break;
        }
        offset = offset
            .checked_add(bytes as u64)
            .ok_or(Error::CorruptInstalledFile)?;
        verifier
            .update(&buffer[..bytes])
            .map_err(|_| Error::CorruptInstalledFile)?;
    }
    verifier.verify().map_err(|_| Error::CorruptInstalledFile)
}

fn verify_directory<S: Store>(
    store: &S,
    directory: &str,
    key: &PublicKey,
    policy: &Policy<'_>,
) -> Result<(Manifest, Vec<u8>), Error> {
    let raw = read_bounded(
        store,
        &format!("{directory}/{MANIFEST_PATH}"),
        MAX_MANIFEST_BYTES,
    )?;
    let manifest = xila_package_manifest::decode(&raw).map_err(|_| Error::InvalidStoredManifest)?;
    policy.check(&manifest)?;
    let sig = read_bounded(store, &format!("{directory}/{SIGNATURE_PATH}"), 64)?;
    let signature: &[u8; 64] = sig
        .as_slice()
        .try_into()
        .map_err(|_| Error::InvalidStoredSignature)?;
    let mut signed = vec![0u8; SIGNED_DOMAIN.len() + 4 + raw.len()];
    let signed = xila_package_manifest::signed_message_into(&raw, &mut signed)
        .map_err(|_| Error::InvalidStoredManifest)?;
    key.verify(signed, signature)
        .map_err(|_| Error::InvalidStoredSignature)?;
    for file in &manifest.files {
        verify_payload(
            store,
            &format!("{directory}/{}", file.path),
            file.size,
            &file.sha256,
        )?;
    }
    Ok((manifest, raw))
}

fn sync_staging_directories<S: Store>(
    store: &mut S,
    stage: &str,
    manifest: &Manifest,
) -> Result<(), Error> {
    let metadata_parent = format!("{stage}/.xila");
    store.sync_directory(&metadata_parent)?;
    for file in &manifest.files {
        let path = format!("{stage}/{}", file.path);
        let parent = directory(&path)?;
        // Parent may be nested; sync bottom-up to persist all created links.
        let mut current = parent;
        loop {
            store.sync_directory(current)?;
            if current == stage {
                break;
            }
            current = directory(current)?;
            if current.len() < stage.len() {
                break;
            }
        }
    }
    store.sync_directory(stage)?;
    Ok(())
}

fn publish_record<S: Store>(
    store: &mut S,
    plan: &Plan,
    record: &ActivationRecord,
) -> Result<(), Error> {
    ensure_directories(store, ACTIVE_ROOT)?;
    copy_verified(
        store,
        &plan.temporary_activation_path,
        record.encode()?.as_bytes(),
    )?;
    store.sync_directory(ACTIVE_ROOT)?;
    store.replace_file(
        &plan.temporary_activation_path,
        &plan.activation_record_path,
    )?;
    store.sync_directory(ACTIVE_ROOT)?;
    Ok(())
}

/// Install a genuinely Ed25519-authenticated package and activate it.
///
/// This already performs storage I/O and a complete verified transaction.
/// Currently accepts a borrowed complete TAR because the upstream
/// tar-no-std streaming reader is not yet available; no VFS code is used.
/// On failure before activation an old active record remains untouched.
/// Inactive published versions and staging leftovers are recoverable.
pub fn install<S: Store>(
    store: &mut S,
    archive: &[u8],
    key: &PublicKey,
    policy: &Policy<'_>,
    nonce: u64,
) -> Result<ActivationRecord, Error> {
    // Verify signature, all TAR names/types, declared lengths and hashes
    // before touching destination storage. Only caller-selected keys are used.
    let manifest = xila_package_reader::verify_signed(archive, key).map_err(Error::Archive)?;
    let plan = lifecycle::preflight(&manifest, policy, nonce, store.guarantees())?;
    // Required platform-owned roots; never create app/user state directories.
    ensure_directories(store, &plan.bundle_parent)?;
    ensure_directories(store, ACTIVE_ROOT)?;
    if store.exists(&plan.version_directory)? {
        return Err(Error::Lifecycle(lifecycle::Error::BundleAlreadyExists));
    }
    store.create_directory_new(&plan.staging_directory)?;

    // Archive was authenticated and verified above; it stays borrowed and
    // immutable for the entire extraction below.
    let tar = TarArchiveRef::new(archive).map_err(|_| Error::Archive(xila_package_reader::Error::InvalidArchive))?;
    let mut entries = tar.entries();
    let manifest_entry = entries.next().ok_or(Error::InvalidStoredManifest)?;
    let signature_entry = entries.next().ok_or(Error::InvalidStoredSignature)?;
    let raw_manifest = manifest_entry.data();
    let signature = signature_entry.data();
    copy_verified(
        store,
        &format!("{}/{MANIFEST_PATH}", plan.staging_directory),
        raw_manifest,
    )?;
    copy_verified(
        store,
        &format!("{}/{SIGNATURE_PATH}", plan.staging_directory),
        signature,
    )?;
    for file in &manifest.files {
        let entry = entries.next().ok_or(Error::CorruptInstalledFile)?;
        // The reader has already verified order, path, size and hash.
        copy_verified(
            store,
            &format!("{}/{}", plan.staging_directory, file.path),
            entry.data(),
        )?;
    }
    sync_staging_directories(store, &plan.staging_directory, &manifest)?;

    // Read back *stored* bytes and independently verify them, including the
    // actual detached signature and each payload's on-disk SHA-256.
    let (staged, persisted_raw) = verify_directory(store, &plan.staging_directory, key, policy)?;
    if staged != manifest || persisted_raw != raw_manifest {
        return Err(Error::CorruptInstalledFile);
    }
    let record = ActivationRecord::for_manifest_bytes(&persisted_raw)?;
    store.sync_directory(&plan.staging_directory)?;
    // No-replace publication is an indispensable adapter guarantee.
    store.rename_new(&plan.staging_directory, &plan.version_directory)?;
    store.sync_directory(&plan.bundle_parent)?;
    publish_record(store, &plan, &record)?;
    Ok(record)
}

fn checked_id(package: &str) -> Result<(), Error> {
    // Use activation's identifier validator to avoid trusting arbitrary paths.
    let record = ActivationRecord {
        format_version: lifecycle::ACTIVATION_FORMAT,
        package: package.to_string(),
        version: "1".to_string(),
        manifest_sha256: "0".repeat(64),
    };
    record.validate().map_err(Error::Lifecycle)
}

fn current_record<S: Store>(store: &S, package: &str) -> Result<ActivationRecord, Error> {
    checked_id(package)?;
    let path = format!("{ACTIVE_ROOT}/{package}");
    if !store.exists(&path)? {
        return Err(Error::MissingActiveRecord);
    }
    let raw = read_bounded(store, &path, MAX_ACTIVATION_BYTES)?;
    let record = ActivationRecord::decode(&raw)?;
    if record.package != package {
        return Err(Error::IdentityMismatch);
    }
    Ok(record)
}

/// Verify the persisted activation record, detached signature and all installed
/// payloads before returning an application candidate. No task is spawned;
/// OS execution permissions must still be enforced by a future adapter.
pub fn resolve_active<S: Store>(
    store: &S,
    package: &str,
    key: &PublicKey,
    policy: &Policy<'_>,
) -> Result<LaunchTarget, Error> {
    store.guarantees().require_crash_safe()?;
    let record = current_record(store, package)?;
    let root = format!("{BUNDLES_ROOT}/{}/{}", record.package, record.version);
    let (manifest, raw) = verify_directory(store, &root, key, policy)?;
    if manifest.name != record.package || manifest.version != record.version {
        return Err(Error::IdentityMismatch);
    }
    record
        .resolve_application(&raw, policy)
        .map_err(Error::Lifecycle)
}

/// Re-activate an existing verified version (rollback/upgrade) without
/// reinstalling or deleting any user data. Package and version must match
/// the signed manifest stored at the destination.
pub fn activate_existing<S: Store>(
    store: &mut S,
    package: &str,
    version: &str,
    key: &PublicKey,
    policy: &Policy<'_>,
    nonce: u64,
) -> Result<ActivationRecord, Error> {
    checked_id(package)?;
    if version == "."
        || version == ".."
        || version.contains('/')
        || xila_package_manifest::validate_path(version).is_err()
    {
        return Err(Error::Lifecycle(lifecycle::Error::InvalidVersionPath));
    }
    if nonce == 0 {
        return Err(Error::Lifecycle(lifecycle::Error::InvalidTransaction));
    }
    store.guarantees().require_crash_safe()?;
    let dir = format!("{BUNDLES_ROOT}/{package}/{version}");
    let (manifest, raw) = verify_directory(store, &dir, key, policy)?;
    if manifest.name != package || manifest.version != version {
        return Err(Error::IdentityMismatch);
    }
    let record = ActivationRecord::for_manifest_bytes(&raw)?;
    let plan = lifecycle::preflight(&manifest, policy, nonce, store.guarantees())?;
    publish_record(store, &plan, &record)?;
    Ok(record)
}

/// Remove only the active package's immutable version, keeping older
/// inactive versions and all user/system application data. After the
/// deactivation sync, a power loss cannot expose the deleted active bundle.
pub fn uninstall_active<S: Store>(
    store: &mut S,
    package: &str,
    key: &PublicKey,
    policy: &Policy<'_>,
) -> Result<(), Error> {
    store.guarantees().require_crash_safe()?;
    let record = current_record(store, package)?;
    let dir = format!("{BUNDLES_ROOT}/{package}/{}", record.version);
    let (manifest, raw) = verify_directory(store, &dir, key, policy)?;
    if manifest.name != package || manifest.version != record.version { return Err(Error::IdentityMismatch); }
    let expected_record = ActivationRecord::for_manifest_bytes(&raw)?;
    if record != expected_record { return Err(Error::IdentityMismatch); }
    store.remove_file(&format!("{ACTIVE_ROOT}/{package}"))?;
    store.sync_directory(ACTIVE_ROOT)?;
    store.remove_tree(&dir)?;
    store.sync_directory(&format!("{BUNDLES_ROOT}/{package}"))?;
    Ok(())
}

/// Remove an abandoned, untrusted staging directory for a known transaction
/// nonce. Never deletes published versions or modifies the active pointer.
pub fn discard_staging<S: Store>(
    store: &mut S,
    manifest: &Manifest,
    policy: &Policy<'_>,
    nonce: u64,
) -> Result<bool, Error> {
    let plan = lifecycle::preflight(manifest, policy, nonce, store.guarantees())?;
    if !store.exists(&plan.staging_directory)? {
        return Ok(false);
    }
    store.remove_tree(&plan.staging_directory)?;
    store.sync_directory(&plan.bundle_parent)?;
    Ok(true)
}
