//! Device-independent application package lifecycle contract.
//!
//! This is a policy, path and activation *planning* layer, not an archive
//! extractor or filesystem driver. A trusted system component must implement
//! staged writes, payload authentication, filesystem capability checks, and
//! activation publication. In particular, merely constructing a Plan does not
//! make bytes executable.

use alloc::{format, string::String};
use miniserde::{Deserialize, Serialize};
use xila_package_manifest::{Manifest, decode, validate, validate_path};
use xila_package_verification::Sha256Verifier;

/// Bundle versions are immutable and live under this namespace.
pub const BUNDLES_ROOT: &str = "/applications/bundles";
/// The active version is recorded separately from the installed versions.
pub const ACTIVE_ROOT: &str = "/applications/active";
pub const ACTIVATION_FORMAT: u32 = 1;
pub const MAX_ACTIVATION_BYTES: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidManifest,
    InvalidActivation,
    InvalidVersionPath,
    InvalidTransaction,
    TargetMismatch,
    AbiIncompatible,
    CapabilityDenied,
    ExternalEntrypointDenied,
    InsufficientStorageGuarantees,
    BundleAlreadyExists,
    IntegrityMismatch,
    NoApplication,
    InvalidPath,
}

/// The package's declared capabilities are requests, not grants.
/// A trusted caller must supply its own allow-list, separate from the manifest.
#[derive(Debug, Clone, Copy)]
pub struct Policy<'a> {
    pub target: &'a str,
    pub xila_abi: u32,
    pub allowed_capabilities: &'a [&'a str],
    /// False for downloads; true only for explicitly trusted OS provisioning.
    pub allow_external_entrypoints: bool,
}

impl Policy<'_> {
    pub fn check(&self, manifest: &Manifest) -> Result<(), Error> {
        validate(manifest).map_err(|_| Error::InvalidManifest)?;
        if manifest.target != self.target {
            return Err(Error::TargetMismatch);
        }
        if manifest.minimum_xila_abi > self.xila_abi {
            return Err(Error::AbiIncompatible);
        }
        if manifest
            .capabilities
            .iter()
            .any(|requested| !self.allowed_capabilities.contains(&requested.as_str()))
        {
            return Err(Error::CapabilityDenied);
        }
        if !self.allow_external_entrypoints
            && manifest
                .application
                .as_ref()
                .is_some_and(|app| app.entrypoint.starts_with('/'))
        {
            return Err(Error::ExternalEntrypointDenied);
        }
        Ok(())
    }
}

/// Backend guarantees for the *specific source and destination mounts* of a
/// transaction. None of these can be inferred simply from a VFS rename API.
/// The platform adapter must establish these properties through tests/audit.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StorageGuarantees {
    /// Stage and version directory share a mount; rename cannot cross it.
    pub same_bundle_mount: bool,
    /// Directory publication is atomic when destination does not exist.
    pub atomic_new_directory_rename: bool,
    /// Replacing the active-record file cannot expose partial contents.
    pub atomic_activation_replace: bool,
    /// File close+sync and directory metadata survive the tested power-loss model.
    pub durable_writes_and_directory_sync: bool,
    /// Backend rejects symlinks and mount traversal under the protected roots.
    pub contained_namespace: bool,
}

impl StorageGuarantees {
    /// Fail closed: do not promise rollback without evidence.
    pub fn require_crash_safe(self) -> Result<(), Error> {
        if self.same_bundle_mount
            && self.atomic_new_directory_rename
            && self.atomic_activation_replace
            && self.durable_writes_and_directory_sync
            && self.contained_namespace
        {
            Ok(())
        } else {
            Err(Error::InsufficientStorageGuarantees)
        }
    }
}

/// A checked plan is not a verified archive. The trusted installer must:
/// authenticate the publisher, stage and verify all payloads, sync, publish
/// the immutable bundle, then atomically replace the activation record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub bundle_parent: String,
    pub staging_directory: String,
    pub version_directory: String,
    pub activation_record_path: String,
    pub temporary_activation_path: String,
}

/// Preflight only: no I/O, trust acceptance or space reservation occurs here.
/// The caller must check final-path nonexistence atomically during commit,
/// never use this as an authoritative conflict check.
pub fn preflight(
    manifest: &Manifest,
    policy: &Policy<'_>,
    transaction_nonce: u64,
    storage: StorageGuarantees,
) -> Result<Plan, Error> {
    policy.check(manifest)?;
    storage.require_crash_safe()?;
    if transaction_nonce == 0 {
        return Err(Error::InvalidTransaction);
    }
    // Manifest versions are valid display strings, but "."/".." may not
    // become standalone filesystem components.
    if manifest.version.contains('/') || validate_path(&manifest.version).is_err() {
        return Err(Error::InvalidVersionPath);
    }
    let parent = format!("{BUNDLES_ROOT}/{}", manifest.name);
    Ok(Plan {
        staging_directory: format!("{parent}/.staging-{transaction_nonce:016x}"),
        version_directory: format!("{parent}/{}", manifest.version),
        activation_record_path: format!("{ACTIVE_ROOT}/{}", manifest.name),
        temporary_activation_path: format!(
            "{ACTIVE_ROOT}/.pending-{}-{transaction_nonce:016x}",
            manifest.name
        ),
        bundle_parent: parent,
    })
}

/// The entire active-version pointer, stored in a protected OS-owned file.
/// Its digest is of the *exact* persisted manifest bytes, including $schema.
/// It is an integrity binding, not a signature or proof of publisher trust.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivationRecord {
    pub format_version: u32,
    pub package: String,
    pub version: String,
    pub manifest_sha256: String,
}

fn hash_hex(bytes: &[u8]) -> Result<String, Error> {
    let mut hasher = Sha256Verifier::new();
    hasher.update(bytes).map_err(|_| Error::IntegrityMismatch)?;
    let digest = hasher.finalize().map_err(|_| Error::IntegrityMismatch)?;
    let mut result = String::with_capacity(64);
    use core::fmt::Write;
    for b in digest {
        write!(result, "{b:02x}").map_err(|_| Error::InvalidActivation)?;
    }
    Ok(result)
}

impl ActivationRecord {
    /// Only call after an authenticated archive was completely staged and
    /// verified. This function by itself does not authenticate it.
    pub fn for_manifest_bytes(raw_manifest: &[u8]) -> Result<Self, Error> {
        let manifest = decode(raw_manifest).map_err(|_| Error::InvalidManifest)?;
        if manifest.version.contains('/') || validate_path(&manifest.version).is_err() {
            return Err(Error::InvalidVersionPath);
        }
        Ok(Self {
            format_version: ACTIVATION_FORMAT,
            package: manifest.name,
            version: manifest.version,
            manifest_sha256: hash_hex(raw_manifest)?,
        })
    }

    pub fn validate(&self) -> Result<(), Error> {
        if self.format_version != ACTIVATION_FORMAT
            || self.manifest_sha256.len() != 64
            || !self
                .manifest_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || self.version.contains('/')
            || validate_path(&self.version).is_err()
        {
            return Err(Error::InvalidActivation);
        }
        // Use the manifest validator as the canonical package-ID check,
        // without duplicating its evolving reverse-DNS rules here.
        let package_is_safe = self.package.len() <= 96
            && self.package.contains('.')
            && self.package.split('.').all(|part| {
                !part.is_empty()
                    && !part.starts_with('-')
                    && !part.ends_with('-')
                    && part
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            });
        if !package_is_safe {
            return Err(Error::InvalidActivation);
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<String, Error> {
        self.validate()?;
        let serialized = miniserde::json::to_string(self);
        if serialized.len() > MAX_ACTIVATION_BYTES {
            return Err(Error::InvalidActivation);
        }
        Ok(serialized)
    }

    pub fn decode(raw: &[u8]) -> Result<Self, Error> {
        if raw.len() > MAX_ACTIVATION_BYTES {
            return Err(Error::InvalidActivation);
        }
        let text = core::str::from_utf8(raw).map_err(|_| Error::InvalidActivation)?;
        let record: Self = miniserde::json::from_str(text).map_err(|_| Error::InvalidActivation)?;
        record.validate()?;
        Ok(record)
    }

    /// Integrity-check active metadata and derive an executable path for an
    /// application. Caller must additionally authenticate the installed
    /// bundle, enforce execution permissions and prevent mutable-code TOCTOU.
    /// Never launch directly from this unchecked filesystem path alone.
    pub fn resolve_application(
        &self,
        raw_manifest: &[u8],
        policy: &Policy<'_>,
    ) -> Result<LaunchTarget, Error> {
        self.validate()?;
        if hash_hex(raw_manifest)? != self.manifest_sha256 {
            return Err(Error::IntegrityMismatch);
        }
        let manifest = decode(raw_manifest).map_err(|_| Error::InvalidManifest)?;
        policy.check(&manifest)?;
        if manifest.name != self.package || manifest.version != self.version {
            return Err(Error::IntegrityMismatch);
        }
        let app = manifest.application.as_ref().ok_or(Error::NoApplication)?;
        let entrypoint = if app.entrypoint.starts_with('/') {
            app.entrypoint.clone()
        } else {
            format!(
                "{BUNDLES_ROOT}/{}/{}/{}",
                self.package, self.version, app.entrypoint
            )
        };
        Ok(LaunchTarget {
            package: self.package.clone(),
            entrypoint,
            show_in_launcher: app.show_in_launcher,
        })
    }
}

/// UI discovery hint and candidate path, not an execution capability.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LaunchTarget {
    pub package: String,
    pub entrypoint: String,
    pub show_in_launcher: bool,
}

/// Recovery classification is deliberately conservative: the active pointer
/// is the only authority for selecting a version. Orphan staging and fully
/// published but inactive versions are never launched automatically.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recovery {
    /// A valid active record points to a complete, still-authenticated bundle.
    Active,
    /// A complete version exists but is not activated; candidate for cleanup.
    InactiveVersion,
    /// Staging is incomplete or its authenticity is unproven; remove/quarantine.
    UntrustedStaging,
    /// No proven version is available. Do not run anything.
    Unavailable,
}

pub fn classify_recovery(
    active_record_valid: bool,
    active_bundle_fully_verified: bool,
    published_version_present: bool,
    staging_present: bool,
) -> Recovery {
    if active_record_valid && active_bundle_fully_verified {
        Recovery::Active
    } else if published_version_present {
        Recovery::InactiveVersion
    } else if staging_present {
        Recovery::UntrustedStaging
    } else {
        Recovery::Unavailable
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{string::ToString, vec};
    use xila_package_manifest::{Application, FORMAT_VERSION, ManifestFile, SCHEMA_URL};

    fn manifest() -> Manifest {
        Manifest {
            schema: Some(SCHEMA_URL.to_string()),
            format_version: FORMAT_VERSION,
            name: "org.xila.calculator".to_string(),
            version: "1.2.3".to_string(),
            target: "wasm32-wasip1".to_string(),
            minimum_xila_abi: 2,
            capabilities: vec!["graphics".to_string()],
            files: vec![ManifestFile {
                path: "bin/calculator.wasm".to_string(),
                size: 3,
                sha256: "a".repeat(64),
            }],
            application: Some(Application {
                entrypoint: "bin/calculator.wasm".to_string(),
                display_name: "Calculator".to_string(),
                icon: String::new(),
                show_in_launcher: true,
            }),
        }
    }

    fn policy() -> Policy<'static> {
        Policy {
            target: "wasm32-wasip1",
            xila_abi: 2,
            allowed_capabilities: &["graphics"],
            allow_external_entrypoints: false,
        }
    }

    fn guaranteed_storage() -> StorageGuarantees {
        StorageGuarantees {
            same_bundle_mount: true,
            atomic_new_directory_rename: true,
            atomic_activation_replace: true,
            durable_writes_and_directory_sync: true,
            contained_namespace: true,
        }
    }

    #[test]
    fn activation_round_trip_and_launch_resolution() {
        let manifest = manifest();
        let raw = xila_package_manifest::encode(&manifest).unwrap();
        let record = ActivationRecord::for_manifest_bytes(raw.as_bytes()).unwrap();
        let stored = record.encode().unwrap();
        let recovered = ActivationRecord::decode(stored.as_bytes()).unwrap();
        assert_eq!(recovered, record);
        let target = recovered
            .resolve_application(raw.as_bytes(), &policy())
            .unwrap();
        assert_eq!(
            target.entrypoint,
            "/applications/bundles/org.xila.calculator/1.2.3/bin/calculator.wasm"
        );
        assert!(target.show_in_launcher);
    }

    #[test]
    fn signed_metadata_binding_rejects_tampering_and_confusion() {
        let m = manifest();
        let raw = xila_package_manifest::encode(&m).unwrap();
        let mut record = ActivationRecord::for_manifest_bytes(raw.as_bytes()).unwrap();
        let mut modified = m.clone();
        modified.version = "1.2.4".to_string();
        let changed = xila_package_manifest::encode(&modified).unwrap();
        assert_eq!(
            record.resolve_application(changed.as_bytes(), &policy()),
            Err(Error::IntegrityMismatch)
        );
        record.version = "1.2.4".to_string();
        assert_eq!(
            record.resolve_application(raw.as_bytes(), &policy()),
            Err(Error::IntegrityMismatch)
        );
        record.manifest_sha256 = "bad".to_string();
        assert_eq!(record.validate(), Err(Error::InvalidActivation));
    }

    #[test]
    fn policy_fail_closed() {
        let m = manifest();
        assert!(policy().check(&m).is_ok());
        let wrong_target = Policy {
            target: "xtensa-esp32",
            ..policy()
        };
        assert_eq!(wrong_target.check(&m), Err(Error::TargetMismatch));
        let old_abi = Policy {
            xila_abi: 1,
            ..policy()
        };
        assert_eq!(old_abi.check(&m), Err(Error::AbiIncompatible));
        let denied = Policy {
            allowed_capabilities: &[],
            ..policy()
        };
        assert_eq!(denied.check(&m), Err(Error::CapabilityDenied));
        let mut system = m.clone();
        system.application.as_mut().unwrap().entrypoint =
            "/system/executables/calculator".to_string();
        assert_eq!(
            policy().check(&system),
            Err(Error::ExternalEntrypointDenied)
        );
    }

    #[test]
    fn path_preflight_and_version_traversal() {
        let m = manifest();
        let plan = preflight(&m, &policy(), 42, guaranteed_storage()).unwrap();
        assert_eq!(
            plan.staging_directory,
            "/applications/bundles/org.xila.calculator/.staging-000000000000002a"
        );
        assert_eq!(
            plan.activation_record_path,
            "/applications/active/org.xila.calculator"
        );
        assert_eq!(
            preflight(&m, &policy(), 0, guaranteed_storage()),
            Err(Error::InvalidTransaction)
        );
        let mut bad = m.clone();
        bad.version = "..".to_string();
        assert_eq!(
            preflight(&bad, &policy(), 42, guaranteed_storage()),
            Err(Error::InvalidVersionPath)
        );
        bad.version = "1.2.3/escape".to_string();
        assert_eq!(
            preflight(&bad, &policy(), 42, guaranteed_storage()),
            Err(Error::InvalidManifest)
        );
    }

    #[test]
    fn default_storage_never_claims_atomicity() {
        let m = manifest();
        assert_eq!(
            preflight(&m, &policy(), 1, StorageGuarantees::default()),
            Err(Error::InsufficientStorageGuarantees)
        );
        for n in 0..5 {
            let mut guarantees = guaranteed_storage();
            match n {
                0 => guarantees.same_bundle_mount = false,
                1 => guarantees.atomic_new_directory_rename = false,
                2 => guarantees.atomic_activation_replace = false,
                3 => guarantees.durable_writes_and_directory_sync = false,
                _ => guarantees.contained_namespace = false,
            }
            assert!(guarantees.require_crash_safe().is_err());
        }
    }

    #[test]
    fn uninstalled_and_partial_bundles_are_never_autoactivated() {
        assert_eq!(classify_recovery(true, true, true, true), Recovery::Active);
        assert_eq!(
            classify_recovery(true, false, true, true),
            Recovery::InactiveVersion
        );
        assert_eq!(
            classify_recovery(false, false, false, true),
            Recovery::UntrustedStaging
        );
        assert_eq!(
            classify_recovery(false, false, false, false),
            Recovery::Unavailable
        );
    }

    #[test]
    fn standalone_package_does_not_become_an_application() {
        let mut m = manifest();
        m.application = None;
        let raw = xila_package_manifest::encode(&m).unwrap();
        let record = ActivationRecord::for_manifest_bytes(raw.as_bytes()).unwrap();
        assert_eq!(
            record.resolve_application(raw.as_bytes(), &policy()),
            Err(Error::NoApplication)
        );
    }
}
