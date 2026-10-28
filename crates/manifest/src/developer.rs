//! Editable source configuration; not packaged and never trusted as a
//! signed runtime manifest. The builder derives the *complete* file inventory
//! and hashes from the payload directory when producing bundle metadata.

use alloc::{string::String, vec::Vec};
use miniserde::{Deserialize, Serialize};

use crate::{
    Application, Error, FORMAT_VERSION, MAX_MANIFEST_BYTES, Manifest, ManifestFile, SCHEMA_URL,
    validate, validate_path,
};

pub const DEVELOPER_MANIFEST_FILENAME: &str = "xila-package.json";
pub const DEVELOPER_SCHEMA_URL: &str = "https://raw.githubusercontent.com/xila-project/package_manager/main/schemas/developer-manifest.schema.json";

/// Developer-authored application settings. There are deliberately no file
/// hashes, sizes, signature or artifact paths here: those are build outputs.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DeveloperManifest {
    #[serde(rename = "$schema")]
    pub schema: Option<String>,
    pub format_version: u32,
    pub name: String,
    pub version: String,
    pub target: String,
    pub minimum_xila_abi: u32,
    pub capabilities: Vec<String>,
    pub application: Option<Application>,
}

impl DeveloperManifest {
    pub fn validate(&self) -> Result<(), Error> {
        if self
            .schema
            .as_deref()
            .is_some_and(|url| url != DEVELOPER_SCHEMA_URL)
        {
            return Err(Error::InvalidSchema);
        }
        if self.format_version != FORMAT_VERSION {
            return Err(Error::UnsupportedVersion);
        }
        if self.name.len() > 96
            || !self.name.contains('.')
            || self.name.split('.').any(|component| {
                component.is_empty()
                    || component.starts_with('-')
                    || component.ends_with('-')
                    || !component.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                    })
            })
            || self.version.is_empty()
            || self.version.len() > 64
            || !self
                .version
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b".+-".contains(&byte))
        {
            return Err(Error::InvalidIdentifier);
        }
        if self.target.is_empty()
            || self.target.len() > 64
            || !self
                .target
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte))
        {
            return Err(Error::InvalidTarget);
        }
        if self.capabilities.len() > 32
            || self
                .capabilities
                .iter()
                .any(|capability| capability.is_empty() || capability.len() > 64)
        {
            return Err(Error::InvalidFileList);
        }
        if let Some(application) = &self.application {
            if application.display_name.trim().is_empty() || application.display_name.len() > 128 {
                return Err(Error::InvalidApplication);
            }
            let entrypoint = if application.entrypoint.starts_with('/') {
                application
                    .entrypoint
                    .strip_prefix("/system/executables/")
                    .or_else(|| {
                        application
                            .entrypoint
                            .strip_prefix("/applications/executables/")
                    })
                    .ok_or(Error::InvalidApplication)?
            } else {
                &application.entrypoint
            };
            validate_path(entrypoint).map_err(|_| Error::InvalidApplication)?;
            if !application.icon.is_empty() {
                validate_path(&application.icon).map_err(|_| Error::InvalidApplication)?;
            }
        }
        Ok(())
    }

    /// Produce a fully validated runtime manifest by binding the developer's
    /// settings to the *actual* inventory, including resources and executables.
    pub fn into_bundle_manifest(self, files: Vec<ManifestFile>) -> Result<Manifest, Error> {
        self.validate()?;
        let manifest = Manifest {
            schema: Some(SCHEMA_URL.into()),
            format_version: self.format_version,
            name: self.name,
            version: self.version,
            target: self.target,
            minimum_xila_abi: self.minimum_xila_abi,
            capabilities: self.capabilities,
            files,
            application: self.application,
        };
        validate(&manifest)?;
        Ok(manifest)
    }
}

/// Decode the source configuration. The input is never read at runtime.
pub fn decode_developer(bytes: &[u8]) -> Result<DeveloperManifest, Error> {
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(Error::TooLarge);
    }
    let source = core::str::from_utf8(bytes).map_err(|_| Error::InvalidJson)?;
    let manifest: DeveloperManifest =
        miniserde::json::from_str(source).map_err(|_| Error::InvalidJson)?;
    manifest.validate()?;
    Ok(manifest)
}

pub fn encode_developer(manifest: &DeveloperManifest) -> Result<String, Error> {
    manifest.validate()?;
    let text = miniserde::json::to_string(manifest);
    if text.len() > MAX_MANIFEST_BYTES {
        return Err(Error::TooLarge);
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{string::ToString, vec};

    fn example() -> DeveloperManifest {
        DeveloperManifest {
            schema: Some(DEVELOPER_SCHEMA_URL.to_string()),
            format_version: FORMAT_VERSION,
            name: "community.weather".to_string(),
            version: "1.0.0".to_string(),
            target: "wasm32-wasip1".to_string(),
            minimum_xila_abi: 1,
            capabilities: vec![],
            application: Some(Application {
                entrypoint: "bin/weather.wasm".to_string(),
                display_name: "Weather".to_string(),
                icon: "resources/icon.png".to_string(),
                show_in_launcher: true,
            }),
        }
    }

    #[test]
    fn developer_manifest_round_trip_without_hashes() {
        let source = example();
        let encoded = encode_developer(&source).unwrap();
        assert!(!encoded.contains("sha256"));
        assert!(!encoded.contains("files"));
        assert_eq!(decode_developer(encoded.as_bytes()), Ok(source));
    }

    #[test]
    fn signed_bundle_manifest_binds_resources_and_entrypoint() {
        let source = example();
        assert_eq!(
            source.clone().into_bundle_manifest(vec![]),
            Err(Error::InvalidApplication)
        );
        let files = vec![
            ManifestFile {
                path: "bin/weather.wasm".into(),
                size: 3,
                sha256: "a".repeat(64),
            },
            ManifestFile {
                path: "resources/icon.png".into(),
                size: 4,
                sha256: "b".repeat(64),
            },
        ];
        let manifest = source.into_bundle_manifest(files).unwrap();
        assert_eq!(manifest.files.len(), 2);
        assert!(manifest.application.is_some());
    }

    #[test]
    fn reject_unsafe_source_metadata() {
        let mut source = example();
        source.application.as_mut().unwrap().icon = "../secrets".into();
        assert_eq!(source.validate(), Err(Error::InvalidApplication));
        source = example();
        source.name = "Invalid".into();
        assert_eq!(source.validate(), Err(Error::InvalidIdentifier));
        source = example();
        source.schema = Some("https://example.com/schema".into());
        assert_eq!(source.validate(), Err(Error::InvalidSchema));
    }
}
