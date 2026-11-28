//! Registry entries: where a released archive lives and which package key
//! signed it, for one package version.
//!
//! An entry is generated from a signed `.xpk` (never written by hand) and will
//! be signed by the repository key. It pins the archive by SHA-256 and size, so
//! the signed runtime manifest inside is covered transitively; its copied
//! identity fields must still equal that manifest at install time.

use alloc::{string::String, vec::Vec};
use miniserde::{Deserialize, Serialize};

use crate::{
    Error, MAX_MANIFEST_BYTES, Manifest, Metadata, PackageKey, XilaVersion, decode_versioned,
    metadata::is_https_url,
};

/// Editor-facing JSON Schema; a tooling hint, never a trust anchor.
pub const REGISTRY_ENTRY_SCHEMA_URL: &str = "https://raw.githubusercontent.com/xila-project/package_manager/main/schemas/registry-entry.schema.json";
/// Current experimental registry entry format version.
pub const REGISTRY_FORMAT_VERSION: u32 = 3;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Archive {
    /// HTTPS download URL of the immutable `.xpk`.
    pub url: String,
    /// Lowercase hexadecimal SHA-256 of the whole archive.
    pub sha256: String,
    /// Exact archive size in bytes.
    pub size: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RegistryEntry {
    #[serde(rename = "$schema")]
    pub schema: Option<String>,
    pub format_version: u32,
    pub name: String,
    pub version: String,
    pub target: String,
    /// Minimum compatible Xila release, copied from the signed manifest.
    pub xila_version: XilaVersion,
    pub capabilities: Vec<String>,
    /// Launcher name when the package is an application.
    pub display_name: Option<String>,
    pub metadata: Option<Metadata>,
    /// Public key and generation pinned for this version of the package.
    pub package_key: PackageKey,
    pub archive: Archive,
}

pub(crate) fn valid_key_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && !value.starts_with('-')
        && !value.ends_with('-')
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl RegistryEntry {
    /// Describe `archive` from its already verified runtime manifest.
    pub fn from_manifest(
        manifest: &Manifest,
        package_key: PackageKey,
        archive: Archive,
    ) -> Result<Self, Error> {
        crate::validate(manifest)?;
        let entry = Self {
            schema: Some(REGISTRY_ENTRY_SCHEMA_URL.into()),
            format_version: REGISTRY_FORMAT_VERSION,
            name: manifest.name.clone(),
            version: manifest.version.clone(),
            target: manifest.target.clone(),
            xila_version: manifest.xila_version,
            capabilities: manifest.capabilities.clone(),
            display_name: manifest
                .application
                .as_ref()
                .map(|application| application.display_name.clone()),
            metadata: manifest.metadata.clone(),
            package_key,
            archive,
        };
        entry.validate()?;
        Ok(entry)
    }

    pub fn validate(&self) -> Result<(), Error> {
        if self
            .schema
            .as_deref()
            .is_some_and(|url| url != REGISTRY_ENTRY_SCHEMA_URL)
        {
            return Err(Error::InvalidSchema);
        }
        if self.format_version != REGISTRY_FORMAT_VERSION {
            return Err(Error::UnsupportedVersion);
        }
        crate::validate_identity(&self.name, &self.version, &self.target)?;
        crate::validate_capabilities(&self.capabilities)?;
        if self
            .display_name
            .as_deref()
            .is_some_and(|name| name.trim().is_empty() || name.len() > 128)
        {
            return Err(Error::InvalidApplication);
        }
        if let Some(metadata) = &self.metadata {
            metadata.validate()?;
        }
        self.package_key.validate()?;
        if !is_https_url(&self.archive.url)
            || !valid_digest(&self.archive.sha256)
            || self.archive.size == 0
        {
            return Err(Error::InvalidRegistryEntry);
        }
        Ok(())
    }

    /// Require every field copied from the archive to equal its signed manifest.
    pub fn check_manifest(&self, manifest: &Manifest) -> Result<(), Error> {
        let display_name = manifest
            .application
            .as_ref()
            .map(|application| &application.display_name);
        if self.name != manifest.name
            || self.version != manifest.version
            || self.target != manifest.target
            || self.xila_version != manifest.xila_version
            || self.capabilities != manifest.capabilities
            || self.display_name.as_ref() != display_name
            || self.metadata != manifest.metadata
        {
            return Err(Error::RegistryMismatch);
        }
        Ok(())
    }
}

pub fn decode_registry_entry(bytes: &[u8]) -> Result<RegistryEntry, Error> {
    let entry: RegistryEntry = decode_versioned(bytes, REGISTRY_FORMAT_VERSION)?;
    entry.validate()?;
    Ok(entry)
}

pub fn encode_registry_entry(entry: &RegistryEntry) -> Result<String, Error> {
    entry.validate()?;
    let json = miniserde::json::to_string(entry);
    if json.len() > MAX_MANIFEST_BYTES {
        return Err(Error::TooLarge);
    }
    Ok(json)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Application, FORMAT_VERSION, ManifestFile, SCHEMA_URL};

    fn manifest() -> Manifest {
        Manifest {
            schema: Some(SCHEMA_URL.into()),
            format_version: FORMAT_VERSION,
            name: "dev.xila.clock".into(),
            version: "0.1.0".into(),
            target: "wasm32-wasip1".into(),
            xila_version: XilaVersion::new(0, 1),
            capabilities: Vec::new(),
            files: alloc::vec![ManifestFile {
                path: "executables/clock.wasm".into(),
                size: 4,
                sha256: "a".repeat(64),
            }],
            application: Some(Application {
                entrypoint: "executables/clock.wasm".into(),
                display_name: "Clock".into(),
                icon: String::new(),
                show_in_launcher: true,
            }),
            metadata: Some(Metadata {
                summary: "Shows the time".into(),
                license: "MIT".into(),
                source: "https://github.com/xila-project/applications".into(),
                homepage: None,
                author: Some("Xila Project".into()),
            }),
        }
    }

    fn package_key() -> PackageKey {
        PackageKey::new(1, &[42; 32]).unwrap()
    }

    fn archive() -> Archive {
        Archive {
            url: "https://github.com/xila-project/applications/releases/download/dev.xila.clock-v0.1.0/dev.xila.clock-0.1.0-wasm32-wasip1.xpk".into(),
            sha256: "b".repeat(64),
            size: 1024,
        }
    }

    #[test]
    fn entry_round_trips_and_matches_its_manifest() {
        let manifest = manifest();
        let entry = RegistryEntry::from_manifest(&manifest, package_key(), archive()).unwrap();
        assert_eq!(entry.display_name.as_deref(), Some("Clock"));
        let encoded = encode_registry_entry(&entry).unwrap();
        assert!(encoded.contains(r#""xila_version":"0.1""#));
        let decoded = decode_registry_entry(encoded.as_bytes()).unwrap();
        assert_eq!(decoded, entry);
        assert!(decoded.check_manifest(&manifest).is_ok());
    }

    #[test]
    fn copied_fields_must_equal_the_signed_manifest() {
        let entry = RegistryEntry::from_manifest(&manifest(), package_key(), archive()).unwrap();
        let mut other = manifest();
        other.version = "0.2.0".into();
        assert_eq!(entry.check_manifest(&other), Err(Error::RegistryMismatch));
        let mut other = manifest();
        other.xila_version = XilaVersion::new(0, 2);
        assert_eq!(entry.check_manifest(&other), Err(Error::RegistryMismatch));
        let mut other = manifest();
        other.metadata.as_mut().unwrap().license = "GPL-3.0".into();
        assert_eq!(entry.check_manifest(&other), Err(Error::RegistryMismatch));
    }

    #[test]
    fn rejects_invalid_location() {
        let base = RegistryEntry::from_manifest(&manifest(), package_key(), archive()).unwrap();
        for change in [
            |e: &mut RegistryEntry| e.archive.url = "http://xila.example/a.xpk".into(),
            |e: &mut RegistryEntry| e.archive.sha256 = "B".repeat(64),
            |e: &mut RegistryEntry| e.archive.size = 0,
        ] {
            let mut entry = base.clone();
            change(&mut entry);
            assert_eq!(entry.validate(), Err(Error::InvalidRegistryEntry));
        }
    }
}
