//! Registry trust chain: pinned root key → `root.json` → repository key →
//! `index.json`, registry entries and developer keys → developer key allowed to
//! publish a package.
//!
//! This module only authenticates metadata. Verifying the archive itself
//! (size, SHA-256, manifest signature with [`publisher_key`], file hashes) and
//! deciding what an installed package may do stay separate steps.
//!
//! Callers persist [`TrustedRoot::version`] and the highest accepted index
//! version, and pass them back: without that state, rollback cannot be detected.

use alloc::{format, string::String, vec::Vec};
use core::fmt;

use xila_package_manifest::{
    self as manifest, DEVELOPER_KEY_DOMAIN, DeveloperKey, ENTRY_DOMAIN, INDEX_DOMAIN, Index,
    NamedKey, ROOT_DOMAIN, RegistryEntry, Root, decode_developer_key, decode_index,
    decode_registry_entry, decode_root, signed_message,
};
use xila_package_verification::{PublicKey, Sha256Verifier};

/// Why registry metadata was rejected. None of these may be ignored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// The document itself is malformed.
    Metadata(manifest::Error),
    /// No trusted key produced this signature (or it is not 64 bytes).
    InvalidSignature,
    /// The root or index version is older than one already accepted.
    Rollback,
    /// The index expired (only checked when the caller knows the time).
    Expired,
    /// The file is absent from the index, or differs from its listed hash/size.
    NotListed,
    /// The developer key does not match the entry's publisher or namespace.
    Unauthorized,
}

impl From<manifest::Error> for Error {
    fn from(error: manifest::Error) -> Self {
        Self::Metadata(error)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Metadata(error) => write!(f, "invalid registry metadata: {error:?}"),
            Self::InvalidSignature => f.write_str("signature not made by a trusted key"),
            Self::Rollback => f.write_str("metadata version is older than an accepted one"),
            Self::Expired => f.write_str("registry index has expired"),
            Self::NotListed => f.write_str("file is not listed in the index with this hash"),
            Self::Unauthorized => f.write_str("developer key may not publish this package"),
        }
    }
}

pub type Result<T> = core::result::Result<T, Error>;

fn signature(bytes: &[u8]) -> Result<[u8; 64]> {
    bytes.try_into().map_err(|_| Error::InvalidSignature)
}

fn keys(named: &[NamedKey]) -> Result<Vec<PublicKey>> {
    named
        .iter()
        .map(|key| {
            PublicKey::from_bytes(&key.public_key_bytes()?)
                .map_err(|_| Error::Metadata(manifest::Error::InvalidRoot))
        })
        .collect()
}

fn verify_any(keys: &[PublicKey], domain: &[u8], bytes: &[u8], sig: &[u8]) -> Result<()> {
    let signature = signature(sig)?;
    let message = signed_message(domain, bytes)?;
    keys.iter()
        .any(|key| key.verify(&message, &signature).is_ok())
        .then_some(())
        .ok_or(Error::InvalidSignature)
}

/// An authenticated `root.json` and its parsed keys.
pub struct TrustedRoot {
    root: Root,
    root_keys: Vec<PublicKey>,
    repository_keys: Vec<PublicKey>,
}

impl TrustedRoot {
    fn from_root(root: Root) -> Result<Self> {
        Ok(Self {
            root_keys: keys(&root.root_keys)?,
            repository_keys: keys(&root.repository_keys)?,
            root,
        })
    }

    /// Accept a first `root.json` signed by one of the keys pinned on the
    /// device. `minimum_version` is the root version already persisted, if any.
    pub fn bootstrap(
        bytes: &[u8],
        sig: &[u8],
        pinned: &[[u8; 32]],
        minimum_version: u64,
    ) -> Result<Self> {
        let pinned = pinned
            .iter()
            .map(|key| PublicKey::from_bytes(key).map_err(|_| Error::InvalidSignature))
            .collect::<Result<Vec<_>>>()?;
        verify_any(&pinned, ROOT_DOMAIN, bytes, sig)?;
        let root = decode_root(bytes)?;
        if root.version < minimum_version {
            return Err(Error::Rollback);
        }
        Self::from_root(root)
    }

    /// Accept a repository's `root.json` on first use, before any key is
    /// pinned: it must be signed by one of its **own** root keys. This only
    /// proves consistency, not identity: show [`fingerprint`] of the returned
    /// key to the user and pin it only once they confirm it matches a value
    /// obtained another way (the transport may not authenticate the server).
    pub fn first_use(bytes: &[u8], sig: &[u8]) -> Result<(Self, [u8; 32])> {
        let root = decode_root(bytes)?;
        let trusted = Self::from_root(root)?;
        let signature = signature(sig)?;
        let message = signed_message(ROOT_DOMAIN, bytes)?;
        let signer = trusted
            .root_keys
            .iter()
            .position(|key| key.verify(&message, &signature).is_ok())
            .ok_or(Error::InvalidSignature)?;
        let key = trusted.root.root_keys[signer].public_key_bytes()?;
        Ok((trusted, key))
    }

    /// Move to the next `root.json`: it must have a higher version and be
    /// signed by a root key of **this** root. Apply each version in turn.
    pub fn update(&self, bytes: &[u8], sig: &[u8]) -> Result<Self> {
        verify_any(&self.root_keys, ROOT_DOMAIN, bytes, sig)?;
        let root = decode_root(bytes)?;
        if root.version <= self.root.version {
            return Err(Error::Rollback);
        }
        Self::from_root(root)
    }

    pub fn root(&self) -> &Root {
        &self.root
    }

    pub fn version(&self) -> u64 {
        self.root.version
    }

    /// Authenticate `index.json`. `minimum_version` is the highest index
    /// version already accepted (an equal version is the same publication).
    /// `now` is the current Unix time, or `None` without a trustworthy clock.
    pub fn verify_index(
        &self,
        bytes: &[u8],
        sig: &[u8],
        minimum_version: u64,
        now: Option<u64>,
    ) -> Result<Index> {
        verify_any(&self.repository_keys, INDEX_DOMAIN, bytes, sig)?;
        let index = decode_index(bytes)?;
        if index.version < minimum_version {
            return Err(Error::Rollback);
        }
        if now.is_some_and(|now| now >= index.expires) {
            return Err(Error::Expired);
        }
        Ok(index)
    }

    /// Authenticate one registry entry by its own signature. Without an index
    /// this proves origin, not freshness: also call [`check_listed`] when an
    /// index is available.
    pub fn verify_entry(&self, bytes: &[u8], sig: &[u8]) -> Result<RegistryEntry> {
        verify_any(&self.repository_keys, ENTRY_DOMAIN, bytes, sig)?;
        Ok(decode_registry_entry(bytes)?)
    }

    /// Authenticate one developer key file by its own signature.
    pub fn verify_developer_key(&self, bytes: &[u8], sig: &[u8]) -> Result<DeveloperKey> {
        verify_any(&self.repository_keys, DEVELOPER_KEY_DOMAIN, bytes, sig)?;
        Ok(decode_developer_key(bytes)?)
    }
}

fn hex_digest(value: &str) -> Option<[u8; 32]> {
    let digit = |b: u8| match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    };
    let bytes = value.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut output = [0u8; 32];
    for (out, pair) in output.iter_mut().zip(bytes.chunks(2)) {
        *out = digit(pair[0])? << 4 | digit(pair[1])?;
    }
    Some(output)
}

/// Require `bytes` to be exactly the file the index lists at `path`.
pub fn check_listed(index: &Index, path: &str, bytes: &[u8]) -> Result<()> {
    let file = index.file(path).ok_or(Error::NotListed)?;
    let expected = hex_digest(&file.sha256).ok_or(Error::NotListed)?;
    let mut hasher = Sha256Verifier::new();
    hasher.update(bytes).map_err(|_| Error::NotListed)?;
    let digest = hasher.finalize().map_err(|_| Error::NotListed)?;
    if file.size != bytes.len() as u64 || digest != expected {
        return Err(Error::NotListed);
    }
    Ok(())
}

/// The developer key that must have signed the archive described by `entry`.
pub fn publisher_key(entry: &RegistryEntry, key: &DeveloperKey) -> Result<PublicKey> {
    if entry.publisher != key.id || !key.authorizes(&entry.name) {
        return Err(Error::Unauthorized);
    }
    PublicKey::from_bytes(&key.public_key_bytes()?).map_err(|_| Error::Unauthorized)
}

/// Human-comparable fingerprint of a public key: the first 16 bytes of its
/// SHA-256 as eight groups of four hexadecimal digits.
pub fn fingerprint(public_key: &[u8; 32]) -> String {
    let mut hasher = Sha256Verifier::new();
    // A 32-byte input cannot exceed SHA-256's length limit.
    let _ = hasher.update(public_key);
    let digest = hasher.finalize().unwrap_or([0; 32]);
    let mut output = String::with_capacity(39);
    for (index, pair) in digest[..16].chunks(2).enumerate() {
        if index > 0 {
            output.push(' ');
        }
        output.push_str(&format!("{:02x}{:02x}", pair[0], pair[1]));
    }
    output
}

/// Whether an entry can be installed on a device running `target` with
/// Xila ABI `abi`.
pub fn compatible(entry: &RegistryEntry, target: &str, abi: u32) -> bool {
    entry.target == target && entry.minimum_xila_abi <= abi
}

/// Registry-relative paths of the entries to try for `name`: the exact
/// `version` if given (it must be listed), otherwise every listed semantic
/// version newest first (prereleases excluded). Fetch them in order and keep
/// the first [`compatible`] one.
pub fn candidates(index: &Index, name: &str, version: Option<&str>) -> Result<Vec<String>> {
    match version {
        Some(version) => {
            let path = entry_path(name, version);
            index.file(&path).ok_or(Error::NotListed)?;
            Ok(alloc::vec![path])
        }
        None => Ok(manifest::index_versions(index, name, false)
            .into_iter()
            .map(|version| entry_path(name, version))
            .collect()),
    }
}

/// Registry-relative path of the entry for `name` at `version`.
pub fn entry_path(name: &str, version: &str) -> String {
    format!("packages/{}/{version}.json", name.replace('.', "/"))
}

/// Registry-relative path of the developer key `id`.
pub fn developer_key_path(id: &str) -> String {
    format!("keys/developers/{id}.json")
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{string::ToString, vec};
    use ed25519_dalek::{Signer, SigningKey};
    use xila_package_manifest::{
        Archive, INDEX_SCHEMA_URL, IndexFile, ROOT_SCHEMA_URL, TRUST_FORMAT_VERSION, encode_index,
        encode_registry_entry, encode_root,
    };

    const DEVELOPER: &str = r#"{"id":"xila-project","author":"Xila Project","algorithm":"ed25519","public_key":"6D1cvlGzCAITQrmkWjJgn97DW1s6p3zvDNe8a87pcbc=","openssh":null,"namespaces":["xila"]}"#;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn base64(bytes: &[u8; 32]) -> String {
        const TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut output = String::new();
        for chunk in bytes.chunks(3) {
            let mut block = [0u8; 3];
            block[..chunk.len()].copy_from_slice(chunk);
            let value = u32::from_be_bytes([0, block[0], block[1], block[2]]);
            for index in 0..4 {
                if index <= chunk.len() {
                    output.push(TABLE[(value >> (18 - 6 * index) & 63) as usize] as char);
                } else {
                    output.push('=');
                }
            }
        }
        output
    }

    fn named(id: &str, key: &SigningKey) -> NamedKey {
        NamedKey {
            id: id.into(),
            public_key: base64(&key.verifying_key().to_bytes()),
        }
    }

    fn sign(key: &SigningKey, domain: &[u8], bytes: &[u8]) -> Vec<u8> {
        key.sign(&signed_message(domain, bytes).unwrap())
            .to_bytes()
            .to_vec()
    }

    fn root_json(version: u64, root: &SigningKey, repository: &SigningKey) -> String {
        encode_root(&Root {
            schema: Some(ROOT_SCHEMA_URL.into()),
            format_version: TRUST_FORMAT_VERSION,
            version,
            root_keys: vec![named("root", root)],
            repository_keys: vec![named("repository", repository)],
        })
        .unwrap()
    }

    fn entry() -> RegistryEntry {
        RegistryEntry {
            schema: None,
            format_version: 1,
            name: "xila.clock".into(),
            version: "0.1.0".into(),
            target: "wasm32-wasip1".into(),
            minimum_xila_abi: 1,
            capabilities: vec![],
            display_name: Some("Clock".into()),
            metadata: None,
            publisher: "xila-project".into(),
            archive: Archive {
                url: "https://example.com/clock.xpk".into(),
                sha256: "c".repeat(64),
                size: 10,
            },
        }
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        let mut hasher = Sha256Verifier::new();
        hasher.update(bytes).unwrap();
        hasher
            .finalize()
            .unwrap()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    fn trusted() -> TrustedRoot {
        let root = root_json(1, &key(1), &key(2));
        let pinned = [key(1).verifying_key().to_bytes()];
        TrustedRoot::bootstrap(
            root.as_bytes(),
            &sign(&key(1), ROOT_DOMAIN, root.as_bytes()),
            &pinned,
            0,
        )
        .unwrap()
    }

    #[test]
    fn bootstrap_requires_a_pinned_root_key() {
        let root = root_json(1, &key(1), &key(2));
        let pinned = [key(1).verifying_key().to_bytes()];
        let by_repository = sign(&key(2), ROOT_DOMAIN, root.as_bytes());
        assert_eq!(
            TrustedRoot::bootstrap(root.as_bytes(), &by_repository, &pinned, 0).err(),
            Some(Error::InvalidSignature)
        );
        let good = sign(&key(1), ROOT_DOMAIN, root.as_bytes());
        assert_eq!(
            TrustedRoot::bootstrap(root.as_bytes(), &good, &pinned, 2).err(),
            Some(Error::Rollback)
        );
        assert_eq!(trusted().version(), 1);
    }

    #[test]
    fn root_rotation_needs_the_previous_root_key_and_a_higher_version() {
        let trusted = trusted();
        // Rotate both keys: version 2 signed by the old root key.
        let next = root_json(2, &key(3), &key(4));
        let rotated = trusted
            .update(
                next.as_bytes(),
                &sign(&key(1), ROOT_DOMAIN, next.as_bytes()),
            )
            .unwrap();
        assert_eq!(rotated.version(), 2);
        // The new root key alone cannot introduce itself.
        assert_eq!(
            trusted
                .update(
                    next.as_bytes(),
                    &sign(&key(3), ROOT_DOMAIN, next.as_bytes())
                )
                .err(),
            Some(Error::InvalidSignature)
        );
        // Replaying the same version is a rollback.
        let same = root_json(1, &key(1), &key(4));
        assert_eq!(
            trusted
                .update(
                    same.as_bytes(),
                    &sign(&key(1), ROOT_DOMAIN, same.as_bytes())
                )
                .err(),
            Some(Error::Rollback)
        );
        // After rotation the old repository key is no longer trusted.
        let entry = encode_registry_entry(&entry()).unwrap();
        assert_eq!(
            rotated
                .verify_entry(
                    entry.as_bytes(),
                    &sign(&key(2), ENTRY_DOMAIN, entry.as_bytes())
                )
                .err(),
            Some(Error::InvalidSignature)
        );
    }

    #[test]
    fn entries_and_developer_keys_need_the_repository_key_and_their_domain() {
        let trusted = trusted();
        let entry = encode_registry_entry(&entry()).unwrap();
        let bytes = entry.as_bytes();
        assert!(
            trusted
                .verify_entry(bytes, &sign(&key(2), ENTRY_DOMAIN, bytes))
                .is_ok()
        );
        for bad in [
            sign(&key(1), ENTRY_DOMAIN, bytes),         // root key
            sign(&key(2), DEVELOPER_KEY_DOMAIN, bytes), // wrong domain
            sign(&key(2), ENTRY_DOMAIN, b"other"),      // other bytes
            vec![0; 63],                                // truncated
        ] {
            assert_eq!(
                trusted.verify_entry(bytes, &bad).err(),
                Some(Error::InvalidSignature)
            );
        }
        let developer = DEVELOPER.as_bytes();
        let key_file = trusted
            .verify_developer_key(developer, &sign(&key(2), DEVELOPER_KEY_DOMAIN, developer))
            .unwrap();
        assert!(publisher_key(&self::entry(), &key_file).is_ok());
    }

    #[test]
    fn index_rejects_rollback_expiry_and_unlisted_files() {
        let trusted = trusted();
        let entry = encode_registry_entry(&entry()).unwrap();
        let path = entry_path("xila.clock", "0.1.0");
        assert_eq!(path, "packages/xila/clock/0.1.0.json");
        let index = encode_index(&Index {
            schema: Some(INDEX_SCHEMA_URL.into()),
            format_version: TRUST_FORMAT_VERSION,
            version: 100,
            expires: 200,
            files: vec![IndexFile {
                path: path.clone(),
                sha256: sha256_hex(entry.as_bytes()),
                size: entry.len() as u64,
            }],
        })
        .unwrap();
        let sig = sign(&key(2), INDEX_DOMAIN, index.as_bytes());
        let index_bytes = index.as_bytes();
        let accepted = trusted
            .verify_index(index_bytes, &sig, 100, Some(150))
            .unwrap();
        assert!(trusted.verify_index(index_bytes, &sig, 0, None).is_ok());
        assert_eq!(
            trusted.verify_index(index_bytes, &sig, 101, None).err(),
            Some(Error::Rollback)
        );
        assert_eq!(
            trusted.verify_index(index_bytes, &sig, 0, Some(200)).err(),
            Some(Error::Expired)
        );
        assert_eq!(
            trusted
                .verify_index(
                    index_bytes,
                    &sign(&key(2), ENTRY_DOMAIN, index_bytes),
                    0,
                    None
                )
                .err(),
            Some(Error::InvalidSignature)
        );

        assert!(check_listed(&accepted, &path, entry.as_bytes()).is_ok());
        let mut changed = entry.clone().into_bytes();
        changed[0] = b' ';
        assert_eq!(
            check_listed(&accepted, &path, &changed).err(),
            Some(Error::NotListed)
        );
        assert_eq!(
            check_listed(&accepted, &developer_key_path("other"), entry.as_bytes()).err(),
            Some(Error::NotListed)
        );
    }

    #[test]
    fn first_use_requires_a_self_consistent_root_and_reports_its_key() {
        let root = root_json(1, &key(1), &key(2));
        let (trusted, signer) = TrustedRoot::first_use(
            root.as_bytes(),
            &sign(&key(1), ROOT_DOMAIN, root.as_bytes()),
        )
        .unwrap();
        assert_eq!(signer, key(1).verifying_key().to_bytes());
        assert_eq!(trusted.version(), 1);
        // Signed by its repository key (or anyone else): refused.
        assert_eq!(
            TrustedRoot::first_use(
                root.as_bytes(),
                &sign(&key(2), ROOT_DOMAIN, root.as_bytes())
            )
            .err(),
            Some(Error::InvalidSignature)
        );
        let print = fingerprint(&signer);
        assert_eq!(print.len(), 39);
        assert_eq!(print.split(' ').count(), 8);
        assert_ne!(print, fingerprint(&key(2).verifying_key().to_bytes()));
    }

    #[test]
    fn candidates_and_compatibility() {
        let file = |path: &str| IndexFile {
            path: path.into(),
            sha256: "a".repeat(64),
            size: 1,
        };
        let index = Index {
            schema: Some(INDEX_SCHEMA_URL.into()),
            format_version: TRUST_FORMAT_VERSION,
            version: 1,
            expires: 2,
            files: vec![
                file("packages/xila/clock/0.1.0.json"),
                file("packages/xila/clock/0.2.0.json"),
                file("packages/xila/clock/nightly.json"),
            ],
        };
        assert_eq!(
            candidates(&index, "xila.clock", None).unwrap(),
            [
                "packages/xila/clock/0.2.0.json",
                "packages/xila/clock/0.1.0.json"
            ]
        );
        assert_eq!(
            candidates(&index, "xila.clock", Some("nightly")).unwrap(),
            ["packages/xila/clock/nightly.json"]
        );
        assert_eq!(
            candidates(&index, "xila.clock", Some("9.9.9")).err(),
            Some(Error::NotListed)
        );
        let entry = entry();
        assert!(compatible(&entry, "wasm32-wasip1", 1));
        assert!(compatible(&entry, "wasm32-wasip1", 2));
        assert!(!compatible(&entry, "wasm32-wasip1", 0));
        assert!(!compatible(&entry, "thumbv7em-none-eabi", 1));
    }

    #[test]
    fn publisher_must_match_and_cover_the_namespace() {
        let developer = decode_developer_key(DEVELOPER.as_bytes()).unwrap();
        let mut other = entry();
        other.publisher = "someone".into();
        assert_eq!(
            publisher_key(&other, &developer).err(),
            Some(Error::Unauthorized)
        );
        let mut other = entry();
        other.name = "community.clock".into();
        assert_eq!(
            publisher_key(&other, &developer).err(),
            Some(Error::Unauthorized)
        );
        assert_eq!(Error::Expired.to_string(), "registry index has expired");
    }
}
