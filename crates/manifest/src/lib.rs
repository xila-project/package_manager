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
    if manifest.files.is_empty()
        || manifest.files.len() > MAX_FILES
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
    Ok(())
}

/// Parse bounded Miniserde JSON using `alloc`, then validate its structure.
pub fn decode(bytes: &[u8]) -> Result<Manifest, Error> {
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(Error::TooLarge);
    }
    let source = core::str::from_utf8(bytes).map_err(|_| Error::InvalidJson)?;
    let value: Manifest = miniserde::json::from_str(source).map_err(|_| Error::InvalidJson)?;
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

/// Proposed message, bound to exact stored bytes. No reserialization before verification.
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
            format_version: 1,
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
