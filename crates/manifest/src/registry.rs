//! Registry entries: where a released archive lives and which developer key
//! published it, for one package version.
//!
//! An entry is generated from a signed `.xpk` (never written by hand) and will
//! be signed by the repository key. It pins the archive by SHA-256 and size, so
//! the signed runtime manifest inside is covered transitively; its copied
//! identity fields must still equal that manifest at install time.

use alloc::{string::String, vec::Vec};
use miniserde::{Deserialize, Serialize};

use crate::{Error, MAX_MANIFEST_BYTES, Manifest, Metadata, metadata::is_https_url};

/// Editor-facing JSON Schema; a tooling hint, never a trust anchor.
pub const REGISTRY_ENTRY_SCHEMA_URL: &str = "https://raw.githubusercontent.com/xila-project/package_manager/main/schemas/registry-entry.schema.json";
/// Current experimental registry entry format version.
pub const REGISTRY_FORMAT_VERSION: u32 = 1;

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
    pub minimum_xila_abi: u32,
    pub capabilities: Vec<String>,
    /// Launcher name when the package is an application.
    pub display_name: Option<String>,
    pub metadata: Option<Metadata>,
    /// Developer key identifier (`keys/developers/<publisher>.json` in xila-project/registry).
    pub publisher: String,
    pub archive: Archive,
}

pub(crate) fn valid_publisher(value: &str) -> bool {
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
        publisher: &str,
        archive: Archive,
    ) -> Result<Self, Error> {
        crate::validate(manifest)?;
        let entry = Self {
            schema: Some(REGISTRY_ENTRY_SCHEMA_URL.into()),
            format_version: REGISTRY_FORMAT_VERSION,
            name: manifest.name.clone(),
            version: manifest.version.clone(),
            target: manifest.target.clone(),
            minimum_xila_abi: manifest.minimum_xila_abi,
            capabilities: manifest.capabilities.clone(),
            display_name: manifest
                .application
                .as_ref()
                .map(|application| application.display_name.clone()),
            metadata: manifest.metadata.clone(),
            publisher: publisher.into(),
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
        if !valid_publisher(&self.publisher)
            || !is_https_url(&self.archive.url)
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
            || self.minimum_xila_abi != manifest.minimum_xila_abi
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
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(Error::TooLarge);
    }
    let source = core::str::from_utf8(bytes).map_err(|_| Error::InvalidJson)?;
    let entry: RegistryEntry = miniserde::json::from_str(source).map_err(|_| Error::InvalidJson)?;
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
            name: "xila.clock".into(),
            version: "0.1.0".into(),
            target: "wasm32-wasip1".into(),
            minimum_xila_abi: 1,
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
            }),
        }
    }

    fn archive() -> Archive {
        Archive {
            url: "https://github.com/xila-project/applications/releases/download/xila.clock-v0.1.0/xila.clock-0.1.0-wasm32-wasip1.xpk".into(),
            sha256: "b".repeat(64),
            size: 1024,
        }
    }

    #[test]
    fn entry_round_trips_and_matches_its_manifest() {
        let manifest = manifest();
        let entry = RegistryEntry::from_manifest(&manifest, "xila-project", archive()).unwrap();
        assert_eq!(entry.display_name.as_deref(), Some("Clock"));
        let decoded =
            decode_registry_entry(encode_registry_entry(&entry).unwrap().as_bytes()).unwrap();
        assert_eq!(decoded, entry);
        assert!(decoded.check_manifest(&manifest).is_ok());
    }

    #[test]
    fn copied_fields_must_equal_the_signed_manifest() {
        let entry = RegistryEntry::from_manifest(&manifest(), "xila-project", archive()).unwrap();
        let mut other = manifest();
        other.version = "0.2.0".into();
        assert_eq!(entry.check_manifest(&other), Err(Error::RegistryMismatch));
        let mut other = manifest();
        other.metadata.as_mut().unwrap().license = "GPL-3.0".into();
        assert_eq!(entry.check_manifest(&other), Err(Error::RegistryMismatch));
    }

    #[test]
    fn rejects_invalid_location_or_publisher() {
        let base = RegistryEntry::from_manifest(&manifest(), "xila-project", archive()).unwrap();
        for change in [
            |e: &mut RegistryEntry| e.archive.url = "http://example.com/a.xpk".into(),
            |e: &mut RegistryEntry| e.archive.sha256 = "B".repeat(64),
            |e: &mut RegistryEntry| e.archive.size = 0,
            |e: &mut RegistryEntry| e.publisher = "Xila Project".into(),
        ] {
            let mut entry = base.clone();
            change(&mut entry);
            assert_eq!(entry.validate(), Err(Error::InvalidRegistryEntry));
        }
    }
}
