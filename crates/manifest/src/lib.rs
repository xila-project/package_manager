#![no_std]
#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

extern crate alloc;
use alloc::{string::String, vec::Vec};
use miniserde::{Deserialize, Serialize};

/// Current experimental manifest format version.
pub const FORMAT_VERSION: u32 = 1;
/// Maximum accepted manifest JSON byte length.
pub const MAX_MANIFEST_BYTES: usize = 64 * 1024;
/// Maximum number of payload files in a manifest.
pub const MAX_FILES: usize = 128;
/// Required first TAR entry holding the JSON manifest.
pub const MANIFEST_PATH: &str = ".xila/manifest.json";
/// Optional detached 64-byte Ed25519 signature archive entry.
pub const SIGNATURE_PATH: &str = ".xila/manifest.sig";
/// Domain separator proposed for signing exact manifest bytes.
pub const SIGNED_DOMAIN: &[u8] = b"XILA-PACKAGE-MANIFEST-V1\0";

/// Reasons a package manifest or path is rejected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    TooLarge,
    InvalidJson,
    UnsupportedVersion,
    InvalidIdentifier,
    InvalidPath,
    DuplicatePath,
    InvalidDigest,
    InvalidSize,
    InvalidTarget,
    InvalidFileList,
    InvalidApplication,
}

/// A complete Xila archive manifest describing identity and every payload file.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Manifest {
    pub format_version: u32,
    pub name: String,
    pub version: String,
    pub target: String,
    pub minimum_xila_abi: u32,
    pub capabilities: Vec<String>,
    pub files: Vec<ManifestFile>,
    /// `None` means a standalone executable/data package, not an application.
    /// Encoded as JSON null for packages without an application.
    pub application: Option<Application>,
}

/// Application-specific metadata; identity/version/ABI/capabilities remain on
/// the parent manifest so installed bundles have only one source of truth.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Application {
    /// Bundle-relative executable, or a preinstalled system executable path.
    /// A system reference does not grant the caller elevated privileges.
    pub entrypoint: String,
    /// Fallback name; localized resources may override its presentation.
    pub display_name: String,
    /// Bundle-relative declared icon path; empty selects an OS fallback.
    pub icon: String,
    /// Discovery in the launcher, never an instruction to pin to the Dock.
    pub show_in_launcher: bool,
}

/// One payload file and the expected hash of its uncompressed bytes.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ManifestFile {
    pub path: String,
    pub size: u64,
    /// Lowercase hexadecimal SHA-256 of logical bytes (no decompression in v1).
    pub sha256: String,
}

/// Reject unsafe relative paths, reserved metadata names, and traversal.
pub fn validate_path(path: &str) -> Result<(), Error> {
    if path.is_empty()
        || path.len() > 200
        || path.starts_with('/')
        || path.contains('\\')
        || path.bytes().any(|b| b < 0x20 || b == 0x7f)
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        || path.starts_with(".xila/")
    {
        return Err(Error::InvalidPath);
    }
    Ok(())
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 96
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
        && value
            .split('.')
            .all(|part| !part.is_empty() && !part.starts_with('-') && !part.ends_with('-'))
        && value.contains('.')
}

/// Validate structural constraints; this does not authenticate publishers.
pub fn validate(manifest: &Manifest) -> Result<(), Error> {
    if manifest.format_version != FORMAT_VERSION {
        return Err(Error::UnsupportedVersion);
    }
    if !valid_identifier(&manifest.name)
        || manifest.version.is_empty()
        || manifest.version.len() > 64
        || !manifest
            .version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".+-".contains(&b))
    {
        return Err(Error::InvalidIdentifier);
    }
    if manifest.target.is_empty()
        || manifest.target.len() > 64
        || !manifest
            .target
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
    {
        return Err(Error::InvalidTarget);
    }
    if manifest.files.len() > MAX_FILES
        || manifest.capabilities.len() > 32
        || manifest
            .capabilities
            .iter()
            .any(|c| c.is_empty() || c.len() > 64)
    {
        return Err(Error::InvalidFileList);
    }
    let mut total = 0_u64;
    for (i, entry) in manifest.files.iter().enumerate() {
        validate_path(&entry.path)?;
        if manifest.files[..i]
            .iter()
            .any(|previous| previous.path == entry.path)
        {
            return Err(Error::DuplicatePath);
        }
        if entry.sha256.len() != 64
            || !entry
                .sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Error::InvalidDigest);
        }
        total = total.checked_add(entry.size).ok_or(Error::InvalidSize)?;
        if total > 256 * 1024 * 1024 {
            return Err(Error::InvalidSize);
        }
    }
    if manifest.files.is_empty() && manifest.application.is_none() {
        return Err(Error::InvalidFileList);
    }
    if let Some(app) = &manifest.application {
        if app.display_name.trim().is_empty() || app.display_name.len() > 128 {
            return Err(Error::InvalidApplication);
        }
        if app.entrypoint.starts_with('/') {
            // External/native entrypoints are only references to executables
            // already provisioned by the OS, never package-owned payloads.
            let suffix = app
                .entrypoint
                .strip_prefix("/system/executables/")
                .or_else(|| app.entrypoint.strip_prefix("/applications/executables/"))
                .ok_or(Error::InvalidApplication)?;
            validate_path(suffix).map_err(|_| Error::InvalidApplication)?;
        } else {
            validate_path(&app.entrypoint).map_err(|_| Error::InvalidApplication)?;
            if !manifest.files.iter().any(|f| f.path == app.entrypoint) {
                return Err(Error::InvalidApplication);
            }
        }
        if !app.icon.is_empty() {
            validate_path(&app.icon).map_err(|_| Error::InvalidApplication)?;
            if !manifest.files.iter().any(|f| f.path == app.icon) {
                return Err(Error::InvalidApplication);
            }
        }
    }
    Ok(())
}

/// Parse bounded Miniserde JSON using `alloc`, then validate its structure.
pub fn decode(bytes: &[u8]) -> Result<Manifest, Error> {
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(Error::TooLarge);
    }
    let source = core::str::from_utf8(bytes).map_err(|_| Error::InvalidJson)?;
    let value: Manifest =
        miniserde::json::from_str(source).map_err(|_| Error::InvalidJson)?;
    validate(&value)?;
    Ok(value)
}

/// Serialize a validated manifest to bounded JSON for use inside TAR.
pub fn encode(value: &Manifest) -> Result<String, Error> {
    validate(value)?;
    let json = miniserde::json::to_string(value);
    if json.len() > MAX_MANIFEST_BYTES {
        return Err(Error::TooLarge);
    }
    Ok(json)
}

/// Prepare the signature message from the exact stored manifest bytes,
/// without reserializing the JSON or allocating internally.
pub fn signed_message_into<'a>(bytes: &[u8], output: &'a mut [u8]) -> Result<&'a [u8], Error> {
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(Error::TooLarge);
    }
    let prefix = SIGNED_DOMAIN.len();
    let len = prefix + 4 + bytes.len();
    if output.len() < len {
        return Err(Error::TooLarge);
    }
    output[..prefix].copy_from_slice(SIGNED_DOMAIN);
    output[prefix..prefix + 4].copy_from_slice(&(bytes.len() as u32).to_le_bytes());
    output[prefix + 4..len].copy_from_slice(bytes);
    Ok(&output[..len])
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{string::ToString, vec};

    pub fn example() -> Manifest {
        Manifest {
            format_version: FORMAT_VERSION,
            name: "xila.calculator".to_string(),
            version: "1.0.0".to_string(),
            target: "wasm32-wasip1".to_string(),
            minimum_xila_abi: 1,
            capabilities: vec![],
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
    #[test]
    fn round_trip() {
        let m = example();
        let json = encode(&m).unwrap();
        assert_eq!(decode(json.as_bytes()).unwrap(), m);
    }
    #[test]
    fn reject_unsafe_paths_and_duplicates() {
        let mut m = example();
        m.files[0].path = "../escape".to_string();
        assert_eq!(validate(&m), Err(Error::InvalidPath));
        m = example();
        m.files.push(m.files[0].clone());
        assert_eq!(validate(&m), Err(Error::DuplicatePath));
    }
    #[test]
    fn reject_invalid_application_references() {
        let mut m = example();
        m.application.as_mut().unwrap().entrypoint = "../escape".to_string();
        assert_eq!(validate(&m), Err(Error::InvalidApplication));
        m.application.as_mut().unwrap().entrypoint = "bin/absent.wasm".to_string();
        assert_eq!(validate(&m), Err(Error::InvalidApplication));
        m.application.as_mut().unwrap().entrypoint = "/system/executables/clock".to_string();
        assert_eq!(validate(&m), Ok(()));
        m.application.as_mut().unwrap().icon = "resources/missing.png".to_string();
        assert_eq!(validate(&m), Err(Error::InvalidApplication));
    }

    #[test]
    fn standalone_package_has_no_application() {
        let mut m = example();
        m.application = None;
        assert_eq!(decode(encode(&m).unwrap().as_bytes()), Ok(m));
        m.files.clear();
        assert_eq!(validate(&m), Err(Error::InvalidFileList));
    }

    #[test]
    fn native_system_application_may_reference_an_existing_executable() {
        let mut m = example();
        m.files.clear();
        m.application.as_mut().unwrap().entrypoint = "/system/executables/settings".to_string();
        assert_eq!(validate(&m), Ok(()));
        assert_eq!(decode(encode(&m).unwrap().as_bytes()), Ok(m));
    }

    #[test]
    fn reject_large_input_and_validate_signed_message() {
        let json = encode(&example()).unwrap();
        let mut bytes = vec![0; SIGNED_DOMAIN.len() + 4 + json.len()];
        let message = signed_message_into(json.as_bytes(), &mut bytes).unwrap();
        assert!(message.starts_with(SIGNED_DOMAIN));
        assert_eq!(
            &message[SIGNED_DOMAIN.len()..SIGNED_DOMAIN.len() + 4],
            &(json.len() as u32).to_le_bytes()
        );
        assert_eq!(
            decode(&vec![b' '; MAX_MANIFEST_BYTES + 1]),
            Err(Error::TooLarge)
        );
    }
}
