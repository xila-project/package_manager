//! Registry trust from the pinned root to the package key in a signed entry.
//!
//! Use [`package_key`] to verify the archive signature before checking file
//! hashes. Upgrades must also pass [`verify_key_continuity`] against the
//! installed key. Persist the highest root and index versions to detect
//! metadata rollback.

use alloc::{format, string::String, vec::Vec};
use core::fmt;

pub use xila_package_manifest::rotation::rotation_path;
use xila_package_manifest::{
    self as manifest, ENTRY_DOMAIN, INDEX_DOMAIN, Index, MAX_KEY_GENERATION, NamedKey, PackageKey,
    ROOT_DOMAIN, ROTATION_DOMAIN, RegistryEntry, Root, XilaVersion, decode_index,
    decode_registry_entry, decode_root, decode_rotation, decode_sha256, signed_message,
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
    /// The package key is invalid or the rotation chain does not authorize it.
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
            Self::Unauthorized => {
                f.write_str("package key is invalid or is not authorized by the installed key")
            }
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
        if bytes.len() > manifest::MAX_MANIFEST_BYTES {
            return Err(manifest::Error::TooLarge.into());
        }
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
        if bytes.len() > manifest::MAX_MANIFEST_BYTES {
            return Err(manifest::Error::TooLarge.into());
        }
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
        if bytes.len() > manifest::MAX_INDEX_BYTES {
            return Err(manifest::Error::TooLarge.into());
        }
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
        if bytes.len() > manifest::MAX_MANIFEST_BYTES {
            return Err(manifest::Error::TooLarge.into());
        }
        verify_any(&self.repository_keys, ENTRY_DOMAIN, bytes, sig)?;
        let entry = decode_registry_entry(bytes)?;
        package_key(&entry)?;
        let package_key = entry.package_key.public_key_bytes()?;
        if self
            .root
            .root_keys
            .iter()
            .chain(&self.root.repository_keys)
            .any(|key| key.public_key_bytes() == Ok(package_key))
        {
            return Err(Error::Unauthorized);
        }
        Ok(entry)
    }
}

/// Require `bytes` to be exactly the file the index lists at `path`.
pub fn check_listed(index: &Index, path: &str, bytes: &[u8]) -> Result<()> {
    let file = index.file(path).ok_or(Error::NotListed)?;
    let expected = decode_sha256(&file.sha256).map_err(|_| Error::NotListed)?;
    let mut hasher = Sha256Verifier::new();
    hasher.update(bytes).map_err(|_| Error::NotListed)?;
    let digest = hasher.finalize().map_err(|_| Error::NotListed)?;
    if file.size != bytes.len() as u64 || digest != expected {
        return Err(Error::NotListed);
    }
    Ok(())
}

/// The public key that must verify the package manifest described by `entry`.
/// Obtain the entry from [`TrustedRoot::verify_entry`] before using this on a device.
pub fn package_key(entry: &RegistryEntry) -> Result<PublicKey> {
    parse_package_key(&entry.package_key)
}

pub(crate) fn parse_package_key(key: &PackageKey) -> Result<PublicKey> {
    key.validate()?;
    PublicKey::from_bytes(&key.public_key_bytes()?).map_err(|_| Error::Unauthorized)
}

/// The exact rotation JSON and its detached Ed25519 signature.
#[derive(Clone, Copy)]
pub struct SignedRotation<'a> {
    pub bytes: &'a [u8],
    pub signature: &'a [u8],
}

/// Verify the next generation against the current key and the exact package
/// identifier. A record cannot change the identifier or skip a generation.
pub fn verify_rotation(
    name: &str,
    current: &PackageKey,
    signed: SignedRotation<'_>,
) -> Result<PackageKey> {
    if signed.bytes.len() > manifest::MAX_ROTATION_BYTES {
        return Err(manifest::Error::TooLarge.into());
    }
    let current_key = parse_package_key(current)?;
    verify_any(
        core::slice::from_ref(&current_key),
        ROTATION_DOMAIN,
        signed.bytes,
        signed.signature,
    )?;
    let rotation = decode_rotation(signed.bytes)?;
    if rotation.name != name
        || rotation.generation != current.generation + 1
        || rotation.previous_key_bytes()? != current.public_key_bytes()?
    {
        return Err(Error::Unauthorized);
    }
    let next = PackageKey {
        generation: rotation.generation,
        public_key: rotation.new_key,
    };
    parse_package_key(&next)?;
    Ok(next)
}

/// Require the offered key to equal the installed key or the end of a
/// complete forward chain. Pass only the records after the installed generation
/// up to the offered generation, in order. Both keys must have been obtained
/// from verified package origins or entries.
pub fn verify_key_continuity(
    name: &str,
    installed: &PackageKey,
    offered: &PackageKey,
    rotations: &[SignedRotation<'_>],
) -> Result<()> {
    parse_package_key(installed)?;
    offered.validate()?;
    if offered
        .generation
        .checked_sub(installed.generation)
        .map(|count| count as usize)
        != Some(rotations.len())
    {
        return Err(Error::Unauthorized);
    }
    let mut current = installed.clone();
    let mut seen = [[0; 32]; MAX_KEY_GENERATION as usize];
    seen[0] = installed.public_key_bytes()?;
    for (index, signed) in rotations.iter().enumerate() {
        current = verify_rotation(name, &current, *signed)?;
        let raw = current.public_key_bytes()?;
        if seen[..=index].contains(&raw) {
            return Err(Error::Unauthorized);
        }
        seen[index + 1] = raw;
    }
    if seen[rotations.len()] != offered.public_key_bytes()? {
        return Err(Error::Unauthorized);
    }
    Ok(())
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

/// Whether an entry can be installed on a device whose target is `target`
/// and whose Xila release is `running`, following
/// [`manifest::target_compatible`] and [`manifest::compatible`].
pub fn compatible(entry: &RegistryEntry, target: &str, running: XilaVersion) -> bool {
    manifest::target_compatible(&entry.target, target)
        && manifest::compatible(entry.xila_version, running)
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

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use ed25519_dalek::{Signer, SigningKey};
    use xila_package_manifest::{
        Archive, INDEX_FORMAT_VERSION, INDEX_SCHEMA_URL, IndexFile, ROOT_SCHEMA_URL,
        TRUST_FORMAT_VERSION, encode_index, encode_registry_entry, encode_root,
    };

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn named(id: &str, key: &SigningKey) -> NamedKey {
        NamedKey {
            id: id.into(),
            public_key: manifest::encode_public_key(&key.verifying_key().to_bytes()),
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
            format_version: manifest::REGISTRY_FORMAT_VERSION,
            name: "dev.xila.clock".into(),
            version: "0.1.0".into(),
            target: "wasm32-wasip1".into(),
            xila_version: XilaVersion::new(0, 1),
            capabilities: vec![],
            display_name: Some("Clock".into()),
            metadata: None,
            package_key: PackageKey::new(1, &key(3).verifying_key().to_bytes()).unwrap(),
            archive: Archive {
                url: "https://xila.example/clock.xpk".into(),
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
    fn entries_need_the_repository_key_and_the_entry_domain() {
        let trusted = trusted();
        let entry = entry();
        let encoded = encode_registry_entry(&entry).unwrap();
        let bytes = encoded.as_bytes();
        assert_eq!(
            trusted.verify_entry(bytes, &sign(&key(2), ENTRY_DOMAIN, bytes)),
            Ok(entry)
        );
        for signature in [
            sign(&key(3), ENTRY_DOMAIN, bytes),
            sign(&key(2), INDEX_DOMAIN, bytes),
        ] {
            assert_eq!(
                trusted.verify_entry(bytes, &signature),
                Err(Error::InvalidSignature)
            );
        }
        let repository_entry = RegistryEntry {
            package_key: PackageKey::new(1, &key(2).verifying_key().to_bytes()).unwrap(),
            ..self::entry()
        };
        let encoded = encode_registry_entry(&repository_entry).unwrap();
        let bytes = encoded.as_bytes();
        assert_eq!(
            trusted.verify_entry(bytes, &sign(&key(2), ENTRY_DOMAIN, bytes)),
            Err(Error::Unauthorized)
        );
    }

    #[test]
    fn index_rejects_rollback_expiry_and_unlisted_files() {
        let trusted = trusted();
        let entry = encode_registry_entry(&entry()).unwrap();
        let path = entry_path("dev.xila.clock", "0.1.0");
        assert_eq!(path, "packages/dev/xila/clock/0.1.0.json");
        let index = encode_index(&Index {
            schema: Some(INDEX_SCHEMA_URL.into()),
            format_version: INDEX_FORMAT_VERSION,
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
            check_listed(
                &accepted,
                &rotation_path("example.xila.other", 2),
                entry.as_bytes()
            )
            .err(),
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
    fn candidates_are_ordered_and_can_select_a_version() {
        let file = |path: &str| IndexFile {
            path: path.into(),
            sha256: "a".repeat(64),
            size: 1,
        };
        let index = Index {
            schema: Some(INDEX_SCHEMA_URL.into()),
            format_version: INDEX_FORMAT_VERSION,
            version: 1,
            expires: 2,
            files: vec![
                file("packages/dev/xila/clock/0.1.0.json"),
                file("packages/dev/xila/clock/0.2.0.json"),
                file("packages/dev/xila/clock/nightly.json"),
            ],
        };
        assert_eq!(
            candidates(&index, "dev.xila.clock", None).unwrap(),
            [
                "packages/dev/xila/clock/0.2.0.json",
                "packages/dev/xila/clock/0.1.0.json"
            ]
        );
        assert_eq!(
            candidates(&index, "dev.xila.clock", Some("nightly")).unwrap(),
            ["packages/dev/xila/clock/nightly.json"]
        );
        assert_eq!(
            candidates(&index, "dev.xila.clock", Some("9.9.9")).err(),
            Some(Error::NotListed)
        );
    }

    #[test]
    fn entry_compatibility_checks_target_and_running_xila_version() {
        let mut entry = entry();
        assert!(compatible(&entry, "wasm32-wasip1", XilaVersion::new(0, 1)));
        assert!(!compatible(&entry, "wasm32-wasip1", XilaVersion::new(0, 2)));
        assert!(!compatible(
            &entry,
            "thumbv7em-none-eabi",
            XilaVersion::new(0, 1)
        ));
        entry.xila_version = XilaVersion::new(1, 3);
        assert!(compatible(&entry, "wasm32-wasip1", XilaVersion::new(1, 9)));
        entry.target = "riscv32imc-unknown-none-elf".into();
        assert!(compatible(
            &entry,
            "riscv32imac-unknown-none-elf",
            XilaVersion::new(1, 3)
        ));
        assert!(!compatible(
            &entry,
            "riscv32imac-unknown-none-elf",
            XilaVersion::new(2, 0)
        ));
        assert!(!compatible(&entry, "wasm32-wasip1", XilaVersion::new(1, 3)));
    }
    const PACKAGE_NAME: &str = "dev.xila.clock";

    fn pin(generation: u32, seed: u8) -> PackageKey {
        PackageKey::new(generation, &key(seed).verifying_key().to_bytes()).unwrap()
    }

    fn rotation(name: &str, generation: u32, previous: u8, next: u8) -> (String, Vec<u8>) {
        let record = manifest::Rotation {
            schema: None,
            format_version: manifest::ROTATION_FORMAT_VERSION,
            name: name.into(),
            generation,
            previous_key: pin(generation - 1, previous).public_key,
            new_key: pin(generation, next).public_key,
        };
        let bytes = manifest::encode_rotation(&record).unwrap();
        let signature = sign(&key(previous), ROTATION_DOMAIN, bytes.as_bytes());
        (bytes, signature)
    }

    fn signed(record: &(String, Vec<u8>)) -> SignedRotation<'_> {
        SignedRotation {
            bytes: record.0.as_bytes(),
            signature: &record.1,
        }
    }

    #[test]
    fn rotations_require_authentication_before_json_parsing() {
        let current = pin(1, 3);
        let rotation = rotation(PACKAGE_NAME, 2, 3, 4);
        for bytes in [rotation.0.as_bytes(), b"{"] {
            assert_eq!(
                verify_rotation(
                    PACKAGE_NAME,
                    &current,
                    SignedRotation {
                        bytes,
                        signature: &[],
                    }
                ),
                Err(Error::InvalidSignature)
            );
        }
        let invalid = ("{".into(), sign(&key(3), ROTATION_DOMAIN, b"{"));
        assert_eq!(
            verify_rotation(PACKAGE_NAME, &current, signed(&invalid)),
            Err(Error::Metadata(manifest::Error::InvalidJson))
        );
        let oversized = [b' '; manifest::MAX_ROTATION_BYTES + 1];
        assert_eq!(
            verify_rotation(
                PACKAGE_NAME,
                &current,
                SignedRotation {
                    bytes: &oversized,
                    signature: &[],
                }
            ),
            Err(Error::Metadata(manifest::Error::TooLarge))
        );
    }

    #[test]
    fn rotation_chain_rejects_old_repeated_and_reordered_records() {
        let first = rotation(PACKAGE_NAME, 2, 3, 4);
        let second = rotation(PACKAGE_NAME, 3, 4, 5);
        let first = signed(&first);
        let second = signed(&second);
        let generation_one = pin(1, 3);
        let generation_three = pin(3, 5);
        assert!(
            verify_key_continuity(
                PACKAGE_NAME,
                &generation_one,
                &generation_three,
                &[first, second]
            )
            .is_ok()
        );

        for current in [pin(2, 4), generation_three.clone()] {
            assert_eq!(
                verify_rotation(PACKAGE_NAME, &current, first),
                Err(Error::InvalidSignature)
            );
        }
        for records in [[first, first], [second, first]] {
            assert_eq!(
                verify_key_continuity(PACKAGE_NAME, &generation_one, &generation_three, &records),
                Err(Error::InvalidSignature)
            );
        }

        // A signature made by the current key cannot change the generation in the record.
        let signature = sign(&key(4), ROTATION_DOMAIN, first.bytes);
        assert_eq!(
            verify_rotation(
                PACKAGE_NAME,
                &pin(2, 4),
                SignedRotation {
                    bytes: first.bytes,
                    signature: &signature,
                }
            ),
            Err(Error::Unauthorized)
        );
    }

    #[test]
    fn rotations_reject_key_loops_and_other_identifiers() {
        let current = pin(1, 3);
        let first = rotation(PACKAGE_NAME, 2, 3, 4);
        let second = rotation(PACKAGE_NAME, 3, 4, 3);
        assert_eq!(
            verify_key_continuity(
                PACKAGE_NAME,
                &current,
                &pin(3, 3),
                &[signed(&first), signed(&second)]
            ),
            Err(Error::Unauthorized)
        );
        assert_eq!(
            verify_rotation("dev.xila.weather", &current, signed(&first)),
            Err(Error::Unauthorized)
        );

        let self_rotation = first.0.replace(&pin(2, 4).public_key, &current.public_key);
        let signature = sign(&key(3), ROTATION_DOMAIN, self_rotation.as_bytes());
        assert_eq!(
            verify_rotation(PACKAGE_NAME, &current, signed(&(self_rotation, signature))),
            Err(Error::Metadata(manifest::Error::InvalidRotation))
        );
    }
}
