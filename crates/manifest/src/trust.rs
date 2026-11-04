//! Registry trust metadata: the root of trust and the signed index.
//!
//! Three roles, each with its own Ed25519 key:
//!
//! - the **root** key (kept offline) signs `root.json`, which names the keys
//!   allowed to sign the next root version and the online repository keys;
//! - a **repository** key signs `index.json`, every registry entry and every
//!   developer key file;
//! - a **developer** key signs package manifests (see [`crate::DeveloperKey`]).
//!
//! Every signature is a detached raw 64-byte Ed25519 signature over
//! [`signed_message`]: a per-document domain separator, the little-endian
//! 32-bit length and the exact file bytes. Devices pin the root key and verify
//! root → repository key → index/entry/developer key → package signature →
//! file hashes.

use alloc::{string::String, vec::Vec};
use miniserde::{Deserialize, Serialize};

use crate::{Error, MAX_MANIFEST_BYTES, developer_key::decode_key, registry::valid_publisher};

/// Editor-facing JSON Schemas; tooling hints, never trust anchors.
pub const ROOT_SCHEMA_URL: &str = "https://raw.githubusercontent.com/xila-project/package_manager/main/schemas/registry-root.schema.json";
pub const INDEX_SCHEMA_URL: &str = "https://raw.githubusercontent.com/xila-project/package_manager/main/schemas/registry-index.schema.json";
/// Current experimental format version of `root.json` and `index.json`.
pub const TRUST_FORMAT_VERSION: u32 = 1;

/// Registry file names, relative to the registry root.
pub const ROOT_PATH: &str = "root.json";
pub const INDEX_PATH: &str = "index.json";
/// Detached signatures live next to the signed file, with this suffix.
pub const SIGNATURE_SUFFIX: &str = ".sig";

/// Domain separators: a signature for one document kind never verifies as another.
pub const ROOT_DOMAIN: &[u8] = b"XILA-REGISTRY-ROOT-V1\0";
pub const INDEX_DOMAIN: &[u8] = b"XILA-REGISTRY-INDEX-V1\0";
pub const ENTRY_DOMAIN: &[u8] = b"XILA-REGISTRY-ENTRY-V1\0";
pub const DEVELOPER_KEY_DOMAIN: &[u8] = b"XILA-REGISTRY-DEVELOPER-KEY-V1\0";

/// Maximum keys per role in `root.json`; verifiers try each, so keep it small.
pub const MAX_ROLE_KEYS: usize = 4;
/// Maximum `index.json` size and file count. Small devices can skip the index
/// and verify a single entry's own signature instead (without freshness).
pub const MAX_INDEX_BYTES: usize = 1024 * 1024;
pub const MAX_INDEX_FILES: usize = 8192;

/// Domain-separated message signed for `bytes`.
pub fn signed_message(domain: &[u8], bytes: &[u8]) -> Result<Vec<u8>, Error> {
    let length = u32::try_from(bytes.len()).map_err(|_| Error::TooLarge)?;
    let mut message = Vec::with_capacity(domain.len() + 4 + bytes.len());
    message.extend_from_slice(domain);
    message.extend_from_slice(&length.to_le_bytes());
    message.extend_from_slice(bytes);
    Ok(message)
}

/// A named Ed25519 public key in canonical base64.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NamedKey {
    pub id: String,
    pub public_key: String,
}

impl NamedKey {
    pub fn public_key_bytes(&self) -> Result<[u8; 32], Error> {
        decode_key(&self.public_key).ok_or(Error::InvalidRoot)
    }
}

/// `root.json`: signed by a root key listed in the previously trusted root
/// (or, for the first root, by a key pinned on the device).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Root {
    #[serde(rename = "$schema")]
    pub schema: Option<String>,
    pub format_version: u32,
    /// Strictly increasing; devices refuse a lower or equal version.
    pub version: u64,
    /// Keys allowed to sign the **next** root version (rotation and revocation).
    pub root_keys: Vec<NamedKey>,
    /// Online keys allowed to sign the index, entries and developer keys.
    pub repository_keys: Vec<NamedKey>,
}

fn valid_keys(keys: &[NamedKey]) -> bool {
    !keys.is_empty()
        && keys.len() <= MAX_ROLE_KEYS
        && keys.iter().enumerate().all(|(index, key)| {
            valid_publisher(&key.id)
                && decode_key(&key.public_key).is_some()
                && keys[..index]
                    .iter()
                    .all(|other| other.id != key.id && other.public_key != key.public_key)
        })
}

impl Root {
    pub fn validate(&self) -> Result<(), Error> {
        if self
            .schema
            .as_deref()
            .is_some_and(|url| url != ROOT_SCHEMA_URL)
        {
            return Err(Error::InvalidSchema);
        }
        if self.format_version != TRUST_FORMAT_VERSION {
            return Err(Error::UnsupportedVersion);
        }
        // A key may not hold both roles: the online key must never be able to
        // sign a new root.
        let shared = self.root_keys.iter().any(|root| {
            self.repository_keys
                .iter()
                .any(|repository| repository.public_key == root.public_key)
        });
        if self.version == 0
            || !valid_keys(&self.root_keys)
            || !valid_keys(&self.repository_keys)
            || shared
        {
            return Err(Error::InvalidRoot);
        }
        Ok(())
    }
}

/// One file listed in the index.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IndexFile {
    /// Path relative to the registry root, e.g. `packages/xila/clock/0.1.0.json`.
    pub path: String,
    /// Lowercase hexadecimal SHA-256 of the exact file bytes.
    pub sha256: String,
    pub size: u64,
}

/// `index.json`: a snapshot of every developer key and entry, signed by a
/// repository key. Devices keep the highest version seen (rollback) and, when
/// they have a trustworthy clock, refuse an expired index (freeze).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Index {
    #[serde(rename = "$schema")]
    pub schema: Option<String>,
    pub format_version: u32,
    /// Strictly increasing between publications (the signing time in seconds).
    pub version: u64,
    /// Expiry as Unix seconds (UTC).
    pub expires: u64,
    /// Sorted by path, without duplicates.
    pub files: Vec<IndexFile>,
}

/// Registry-relative path of a key or entry file: `keys/developers/<id>.json`
/// or `packages/<labels…>/<version>.json`, without `.`/`..` segments.
pub fn valid_listed_path(path: &str) -> bool {
    let segment = |value: &str| {
        !value.is_empty()
            && value != "."
            && value != ".."
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'+'))
    };
    path.len() <= 512
        && path.ends_with(".json")
        && (path.starts_with("keys/developers/") || path.starts_with("packages/"))
        && path.split('/').all(segment)
}

pub(crate) fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl Index {
    pub fn validate(&self) -> Result<(), Error> {
        if self
            .schema
            .as_deref()
            .is_some_and(|url| url != INDEX_SCHEMA_URL)
        {
            return Err(Error::InvalidSchema);
        }
        if self.format_version != TRUST_FORMAT_VERSION {
            return Err(Error::UnsupportedVersion);
        }
        let files = self.files.len() <= MAX_INDEX_FILES
            && self.files.iter().all(|file| {
                valid_listed_path(&file.path)
                    && valid_digest(&file.sha256)
                    && file.size > 0
                    && file.size <= MAX_MANIFEST_BYTES as u64
            })
            && self
                .files
                .windows(2)
                .all(|pair| pair[0].path.as_bytes() < pair[1].path.as_bytes());
        if self.version == 0 || self.expires <= self.version || !files {
            return Err(Error::InvalidIndex);
        }
        Ok(())
    }

    /// The listed file at `path`, if any (binary search; files are sorted).
    pub fn file(&self, path: &str) -> Option<&IndexFile> {
        self.files
            .binary_search_by(|file| file.path.as_bytes().cmp(path.as_bytes()))
            .ok()
            .map(|index| &self.files[index])
    }
}

fn decode<T: miniserde::Deserialize>(bytes: &[u8], limit: usize) -> Result<T, Error> {
    if bytes.len() > limit {
        return Err(Error::TooLarge);
    }
    let source = core::str::from_utf8(bytes).map_err(|_| Error::InvalidJson)?;
    miniserde::json::from_str(source).map_err(|_| Error::InvalidJson)
}

pub fn decode_root(bytes: &[u8]) -> Result<Root, Error> {
    let root: Root = decode(bytes, MAX_MANIFEST_BYTES)?;
    root.validate()?;
    Ok(root)
}

pub fn encode_root(root: &Root) -> Result<String, Error> {
    root.validate()?;
    Ok(miniserde::json::to_string(root))
}

pub fn decode_index(bytes: &[u8]) -> Result<Index, Error> {
    let index: Index = decode(bytes, MAX_INDEX_BYTES)?;
    index.validate()?;
    Ok(index)
}

pub fn encode_index(index: &Index) -> Result<String, Error> {
    index.validate()?;
    let json = miniserde::json::to_string(index);
    if json.len() > MAX_INDEX_BYTES {
        return Err(Error::TooLarge);
    }
    Ok(json)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    const KEY_A: &str = "6D1cvlGzCAITQrmkWjJgn97DW1s6p3zvDNe8a87pcbc=";
    // RFC 8032 test 1 public key.
    const KEY_B: &str = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";

    fn root() -> Root {
        Root {
            schema: Some(ROOT_SCHEMA_URL.into()),
            format_version: TRUST_FORMAT_VERSION,
            version: 1,
            root_keys: vec![NamedKey {
                id: "root-2026".into(),
                public_key: KEY_A.into(),
            }],
            repository_keys: vec![NamedKey {
                id: "repository-2026".into(),
                public_key: KEY_B.into(),
            }],
        }
    }

    fn index() -> Index {
        Index {
            schema: Some(INDEX_SCHEMA_URL.into()),
            format_version: TRUST_FORMAT_VERSION,
            version: 1_800_000_000,
            expires: 1_802_592_000,
            files: vec![
                IndexFile {
                    path: "keys/developers/xila-project.json".into(),
                    sha256: "a".repeat(64),
                    size: 300,
                },
                IndexFile {
                    path: "packages/xila/clock/0.1.0.json".into(),
                    sha256: "b".repeat(64),
                    size: 700,
                },
            ],
        }
    }

    #[test]
    fn messages_are_domain_separated_and_length_prefixed() {
        let message = signed_message(ENTRY_DOMAIN, b"{}").unwrap();
        assert_eq!(&message[..ENTRY_DOMAIN.len()], ENTRY_DOMAIN);
        assert_eq!(
            &message[ENTRY_DOMAIN.len()..ENTRY_DOMAIN.len() + 4],
            &2u32.to_le_bytes()
        );
        assert_ne!(message, signed_message(INDEX_DOMAIN, b"{}").unwrap());
        // No domain is a prefix of another.
        let domains = [
            ROOT_DOMAIN,
            INDEX_DOMAIN,
            ENTRY_DOMAIN,
            DEVELOPER_KEY_DOMAIN,
        ];
        for (i, a) in domains.iter().enumerate() {
            for b in &domains[i + 1..] {
                assert!(!a.starts_with(b) && !b.starts_with(a));
            }
        }
    }

    #[test]
    fn root_and_index_round_trip() {
        let encoded = encode_root(&root()).unwrap();
        assert_eq!(decode_root(encoded.as_bytes()).unwrap(), root());
        let encoded = encode_index(&index()).unwrap();
        let decoded = decode_index(encoded.as_bytes()).unwrap();
        assert_eq!(decoded, index());
        assert_eq!(
            decoded.file("packages/xila/clock/0.1.0.json").unwrap().size,
            700
        );
        assert!(decoded.file("packages/xila/clock/0.2.0.json").is_none());
    }

    #[test]
    fn rejects_invalid_roots() {
        for change in [
            |r: &mut Root| r.version = 0,
            |r: &mut Root| r.root_keys.clear(),
            |r: &mut Root| r.repository_keys.clear(),
            |r: &mut Root| r.repository_keys[0].public_key = KEY_A.into(),
            |r: &mut Root| r.root_keys[0].public_key = "AAAA".into(),
            |r: &mut Root| r.root_keys[0].id = "Root".into(),
            |r: &mut Root| {
                let key = r.repository_keys[0].clone();
                r.repository_keys.push(key);
            },
        ] {
            let mut value = root();
            change(&mut value);
            assert_eq!(value.validate(), Err(Error::InvalidRoot));
        }
        let mut value = root();
        value.format_version = 2;
        assert_eq!(value.validate(), Err(Error::UnsupportedVersion));
    }

    #[test]
    fn rejects_invalid_indexes() {
        for change in [
            |i: &mut Index| i.version = 0,
            |i: &mut Index| i.expires = i.version,
            |i: &mut Index| i.files.reverse(),
            |i: &mut Index| {
                let file = i.files[0].clone();
                i.files.push(file);
            },
            |i: &mut Index| i.files[0].path = "packages/../root.json".into(),
            |i: &mut Index| i.files[0].path = "root.json".into(),
            |i: &mut Index| i.files[0].path = "/packages/xila/clock/0.1.0.json".into(),
            |i: &mut Index| i.files[0].sha256 = "A".repeat(64),
            |i: &mut Index| i.files[0].size = 0,
        ] {
            let mut value = index();
            change(&mut value);
            assert_eq!(value.validate(), Err(Error::InvalidIndex));
        }
    }
}
