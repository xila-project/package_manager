//! Generate and check registry entries for released, signed archives.
//!
//! Entries are derived from the archive itself so the registry never restates
//! (and can never contradict) the developer-signed manifest by hand.

use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fmt::Write as _,
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use xila_package_manager::trust::{self, TrustedRoot};
use xila_package_manifest::{
    Archive, ENTRY_DOMAIN, INDEX_DOMAIN, INDEX_FORMAT_VERSION, INDEX_PATH, INDEX_SCHEMA_URL, Index,
    IndexFile, MAX_MANIFEST_BYTES, MAX_ROTATION_BYTES, NamedKey, PackageKey, ROOT_DOMAIN,
    ROOT_PATH, ROOT_SCHEMA_URL, ROTATION_DOMAIN, ROTATION_FORMAT_VERSION, ROTATION_SCHEMA_URL,
    RegistryEntry, Root, Rotation, SIGNATURE_SUFFIX, TRUST_FORMAT_VERSION, decode_namespace,
    decode_registry_entry, decode_rotation, encode_index, encode_public_key, encode_registry_entry,
    encode_root, encode_rotation, signed_message,
};
use xila_package_verification::PublicKey;

use crate::{Result, invalid, manifest_error, package_verification_error};

fn read_bounded(path: &Path, limit: usize) -> std::io::Result<Vec<u8>> {
    let file = fs::File::open(path)?;
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(invalid(&format!(
            "{}: file exceeds its size limit",
            path.display()
        )));
    }
    Ok(bytes)
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .fold(String::with_capacity(64), |mut hex, byte| {
            let _ = write!(hex, "{byte:02x}");
            hex
        })
}

/// Write the registry entry for `archive`, at `url`, and pin its signing key.
pub fn entry(
    archive: &Path,
    public_key: &Path,
    generation: u32,
    url: &str,
    output: &Path,
) -> Result<()> {
    let bytes = fs::read(archive)?;
    let raw_key = read_raw_public_key(public_key)?;
    let key = PublicKey::from_bytes(&raw_key).map_err(|_| invalid("invalid Ed25519 public key"))?;
    let manifest =
        xila_package_reader::verify_signed(&bytes, &key).map_err(package_verification_error)?;
    let location = Archive {
        url: url.into(),
        sha256: sha256_hex(&bytes),
        size: bytes.len() as u64,
    };
    let pin = PackageKey::new(generation, &raw_key)
        .map_err(|error| manifest_error("invalid package key", error))?;
    let entry = RegistryEntry::from_manifest(&manifest, pin, location)
        .map_err(|error| manifest_error("invalid registry entry", error))?;
    let text = encode_registry_entry(&entry).map_err(|_| invalid("invalid registry entry"))?;
    write_new_file(output, text.as_bytes())
}

fn verify_archive(entry: &RegistryEntry, bytes: &[u8]) -> Result<()> {
    let key = trust::package_key(entry).map_err(|error| invalid(&error.to_string()))?;
    if bytes.len() as u64 != entry.archive.size || sha256_hex(bytes) != entry.archive.sha256 {
        return Err(invalid("archive size or SHA-256 differs from the registry entry").into());
    }
    let manifest =
        xila_package_reader::verify_signed(bytes, &key).map_err(package_verification_error)?;
    entry
        .check_manifest(&manifest)
        .map_err(|_| invalid("registry entry differs from the signed package manifest"))?;
    Ok(())
}

fn read_entry(path: &Path) -> Result<RegistryEntry> {
    let bytes = read_bounded(path, MAX_MANIFEST_BYTES)?;
    decode_registry_entry(&bytes).map_err(|error| {
        failure(
            path,
            &manifest_error("invalid registry entry", error).to_string(),
        )
    })
}

/// Check that `entry` describes exactly `archive`, signed by the pinned key.
pub fn verify(entry: &Path, archive: &Path) -> Result<()> {
    verify_archive(&read_entry(entry)?, &fs::read(archive)?)
}

/// Check the shape of the ownership claim for a first publication. Registry
/// submission must verify control of the domain or account independently.
pub fn check_owner(entry: &Path, claim: &Path) -> Result<()> {
    let entry = read_entry(entry)?;
    let claim = decode_namespace(&read_bounded(claim, MAX_MANIFEST_BYTES)?)
        .map_err(|error| manifest_error("invalid namespace ownership claim", error))?;
    if entry.package_key.generation != 1 || !claim.matches_identifier(&entry.name) {
        return Err(invalid(
            "first publication needs generation 1 and a claim for its exact namespace",
        )
        .into());
    }
    Ok(())
}

fn sorted_entries(directory: &Path) -> Result<Vec<PathBuf>> {
    let mut paths = fs::read_dir(directory)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    paths.sort();
    Ok(paths)
}

fn collect_json(directory: &Path, output: &mut Vec<PathBuf>, rotations: bool) -> Result<()> {
    for path in sorted_entries(directory)? {
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.is_dir() {
            collect_json(&path, output, rotations)?;
        } else if metadata.is_file()
            && path
                .extension()
                .is_some_and(|extension| extension == "json")
        {
            output.push(path);
        } else if rotations
            && metadata.is_file()
            && path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(".json.sig"))
        {
            match fs::symlink_metadata(path.with_extension("")) {
                Ok(record) if record.is_file() => {}
                Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                    return Err(error.into());
                }
                _ => return Err(failure(&path, "rotation signature has no record")),
            }
        } else if !(metadata.is_file() && path.file_name().is_some_and(|name| name == ".gitkeep")) {
            return Err(invalid(&format!("unexpected registry file: {}", path.display())).into());
        }
    }
    Ok(())
}

fn failure(path: &Path, message: &str) -> Box<dyn std::error::Error> {
    invalid(&format!("{}: {message}", path.display())).into()
}

struct RotationFile {
    record: Rotation,
    bytes: Vec<u8>,
    signature: Vec<u8>,
}

impl RotationFile {
    fn read(path: &Path) -> Result<Self> {
        let bytes = read_bounded(path, MAX_ROTATION_BYTES)?;
        Self::from_bytes(path, bytes)
    }

    fn from_bytes(path: &Path, bytes: Vec<u8>) -> Result<Self> {
        let signature_file = signature_path(path);
        let signature = match read_bounded(&signature_file, 64) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(failure(&signature_file, "rotation signature is missing"));
            }
            result => result?,
        };
        if signature.len() != 64 {
            return Err(failure(
                &signature_file,
                "rotation signature must be 64 bytes",
            ));
        }
        let record = decode_rotation(&bytes).map_err(|error| {
            failure(path, &manifest_error("invalid rotation", error).to_string())
        })?;
        if encode_rotation(&record).as_deref() != Ok(core::str::from_utf8(&bytes)?) {
            return Err(failure(
                path,
                "rotation is not canonical; regenerate it with `xila-package registry rotate`",
            ));
        }
        Ok(Self {
            record,
            bytes,
            signature,
        })
    }

    fn signed(&self) -> trust::SignedRotation<'_> {
        trust::SignedRotation {
            bytes: &self.bytes,
            signature: &self.signature,
        }
    }
}

#[derive(Default)]
struct PackageHistory {
    entries: Vec<RegistryEntry>,
    rotations: BTreeMap<u32, RotationFile>,
}

#[derive(Default)]
struct RegistryHistory {
    packages: BTreeMap<String, PackageHistory>,
}

impl RegistryHistory {
    fn add_entry(&mut self, relative: &str, entry: RegistryEntry) -> Result<()> {
        if relative != trust::entry_path(&entry.name, &entry.version) {
            return Err(invalid(&format!("{relative}: entry is not at its own path")).into());
        }
        self.packages
            .entry(entry.name.clone())
            .or_default()
            .entries
            .push(entry);
        Ok(())
    }

    fn add_rotation(&mut self, relative: &str, rotation: RotationFile) -> Result<()> {
        let record = &rotation.record;
        if relative != trust::rotation_path(&record.name, record.generation) {
            return Err(invalid(&format!("{relative}: rotation is not at its own path")).into());
        }
        self.packages
            .entry(record.name.clone())
            .or_default()
            .rotations
            .insert(record.generation, rotation);
        Ok(())
    }

    fn verify(&self) -> Result<()> {
        let mut key_owners = BTreeMap::new();
        for (name, history) in &self.packages {
            let fail = |message: &str| invalid(&format!("{name}: {message}"));
            let first = history
                .entries
                .iter()
                .find(|entry| entry.package_key.generation == 1)
                .ok_or_else(|| fail("package history must include a generation 1 entry"))?;
            trust::package_key(first).map_err(|error| fail(&error.to_string()))?;
            let mut keys = vec![first.package_key.clone()];
            for rotation in history.rotations.values() {
                let next = trust::verify_rotation(
                    name,
                    keys.last().expect("initial key"),
                    rotation.signed(),
                )
                .map_err(|error| {
                    fail(&format!(
                        "rotation to generation {}: {error}",
                        rotation.record.generation
                    ))
                })?;
                keys.push(next);
            }
            for key in &keys {
                let public_key = key
                    .public_key_bytes()
                    .map_err(|error| manifest_error("invalid package key", error))?;
                if let Some(owner) = key_owners.insert(public_key, name) {
                    return Err(fail(&format!("package key already used by {owner}")).into());
                }
            }
            for entry in &history.entries {
                let public_key = entry
                    .package_key
                    .public_key_bytes()
                    .map_err(|error| manifest_error("invalid package key", error))?;
                if keys
                    .get(entry.package_key.generation as usize - 1)
                    .is_none_or(|key| key.public_key_bytes() != Ok(public_key))
                {
                    return Err(fail(&format!(
                        "version {} does not use the pinned package key",
                        entry.version
                    ))
                    .into());
                }
            }
        }
        Ok(())
    }
}

fn relative_path<'a>(root: &Path, path: &'a Path) -> Result<&'a str> {
    path.strip_prefix(root)
        .ok()
        .and_then(Path::to_str)
        .ok_or_else(|| failure(path, "invalid registry path"))
}

fn registry_files(root: &Path, directory: &str) -> Result<Vec<PathBuf>> {
    let rotations = directory == "rotations";
    let directory = root.join(directory);
    match fs::symlink_metadata(&directory) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Ok(metadata) if metadata.is_dir() => {}
        Ok(_) => return Err(failure(&directory, "expected a directory")),
        Err(error) => return Err(error.into()),
    }
    let mut files = Vec::new();
    collect_json(&directory, &mut files, rotations)?;
    Ok(files)
}

fn reject_legacy_layout(root: &Path) -> Result<()> {
    for name in ["keys", "namespaces"] {
        let path = root.join(name);
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) => return Err(failure(&path, "obsolete registry directory")),
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

/// Check the canonical entries and the package key history in a registry
/// checkout. With `archives`, verify the archives named by the entry URLs.
pub fn check(root: &Path, archives: Option<&Path>, previous: Option<&Path>) -> Result<()> {
    if !fs::metadata(root)?.is_dir() {
        return Err(failure(root, "expected a registry directory"));
    }
    reject_legacy_layout(root)?;
    let mut history = RegistryHistory::default();
    let entries = registry_files(root, "packages")?;
    let rotations = registry_files(root, "rotations")?;
    for path in &entries {
        let bytes = read_bounded(path, MAX_MANIFEST_BYTES)?;
        let entry = decode_registry_entry(&bytes).map_err(|error| {
            failure(
                path,
                &manifest_error("invalid registry entry", error).to_string(),
            )
        })?;
        if encode_registry_entry(&entry).as_deref() != Ok(core::str::from_utf8(&bytes)?) {
            return Err(failure(
                path,
                "entry is not canonical; regenerate it with `xila-package registry entry`",
            ));
        }
        if let Some(archives) = archives {
            let name = entry
                .archive
                .url
                .rsplit('/')
                .next()
                .filter(|name| !name.is_empty() && *name != "." && *name != "..")
                .ok_or_else(|| failure(path, "archive URL has no file name"))?;
            verify_archive(&entry, &fs::read(archives.join(name))?)
                .map_err(|error| failure(path, &error.to_string()))?;
        }
        history.add_entry(relative_path(root, path)?, entry)?;
    }
    for path in &rotations {
        history.add_rotation(relative_path(root, path)?, RotationFile::read(path)?)?;
    }
    history.verify()?;
    if let Some(previous) = previous {
        check_publication(root, previous, &history)?;
    }
    println!(
        "Checked {} package entries and {} key rotations",
        entries.len(),
        rotations.len()
    );
    Ok(())
}

/// Compare with an approved checkout. A new version must use the current key,
/// and existing entries and rotations must remain byte-for-byte identical.
fn check_publication(root: &Path, previous: &Path, history: &RegistryHistory) -> Result<()> {
    if !fs::metadata(previous)?.is_dir() {
        return Err(failure(
            previous,
            "expected the approved registry directory",
        ));
    }
    reject_legacy_layout(previous)?;
    for (directory, limit) in [
        ("packages", MAX_MANIFEST_BYTES),
        ("rotations", MAX_ROTATION_BYTES),
    ] {
        for old in registry_files(previous, directory)? {
            let relative = relative_path(previous, &old)?;
            let new = root.join(relative);
            let changed = |limit, old: &Path, new: &Path| -> Result<bool> {
                Ok(read_bounded(old, limit)? != read_bounded(new, limit)?)
            };
            if changed(limit, &old, &new)?
                || (directory == "rotations"
                    && changed(64, &signature_path(&old), &signature_path(&new))?)
            {
                return Err(failure(&new, "published registry file changed"));
            }
        }
    }
    for (name, package) in &history.packages {
        let latest_generation = package
            .rotations
            .last_key_value()
            .map_or(1, |(generation, _)| *generation);
        for entry in &package.entries {
            let relative = trust::entry_path(name, &entry.version);
            if entry.package_key.generation != latest_generation
                && !previous.join(&relative).try_exists()?
            {
                return Err(failure(
                    &root.join(relative),
                    "new version must use the current package key",
                ));
            }
        }
    }
    Ok(())
}

/// Write a rotation signed by the previous key and its detached signature.
pub fn rotate(
    name: &str,
    generation: u32,
    previous_seed: &Path,
    new_public_key: &Path,
    output: &Path,
) -> Result<()> {
    let previous = crate::key::read_seed(previous_seed)?;
    let raw_key = read_raw_public_key(new_public_key)?;
    PublicKey::from_bytes(&raw_key).map_err(|_| invalid("invalid new Ed25519 public key"))?;
    let rotation = Rotation {
        schema: Some(ROTATION_SCHEMA_URL.into()),
        format_version: ROTATION_FORMAT_VERSION,
        name: name.into(),
        generation,
        previous_key: encode_public_key(&previous.verifying_key().to_bytes()),
        new_key: encode_public_key(&raw_key),
    };
    let text =
        encode_rotation(&rotation).map_err(|error| manifest_error("invalid rotation", error))?;
    let signature = sign_bytes(&previous, ROTATION_DOMAIN, text.as_bytes())?;
    write_new_file(output, text.as_bytes())?;
    if let Err(error) = write_new_file(&signature_path(output), &signature) {
        fs::remove_file(output)?;
        return Err(error);
    }
    Ok(())
}

/// Check the chain of rotations between two entries of the same package.
/// The previous entry must be the trusted pin.
pub fn check_rotation(root: &Path, previous: &Path, offered: &Path) -> Result<()> {
    let previous = read_entry(previous)?;
    let offered = read_entry(offered)?;
    if previous.name != offered.name {
        return Err(invalid("entries refer to different package identifiers").into());
    }
    let start = previous.package_key.generation + 1;
    let end = offered.package_key.generation;
    let records = (start..=end)
        .map(|generation| {
            let path = trust::rotation_path(&previous.name, generation);
            RotationFile::read(&root.join(path))
        })
        .collect::<Result<Vec<_>>>()?;
    let rotations: Vec<_> = records.iter().map(RotationFile::signed).collect();
    trust::verify_key_continuity(
        &previous.name,
        &previous.package_key,
        &offered.package_key,
        &rotations,
    )
    .map_err(|error| invalid(&error.to_string()))?;
    Ok(())
}

fn read_raw_public_key(path: &Path) -> Result<[u8; 32]> {
    Ok(read_bounded(path, 32)?
        .try_into()
        .map_err(|_| invalid("public key must be exactly 32 raw bytes"))?)
}

fn signature_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(SIGNATURE_SUFFIX);
    PathBuf::from(name)
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    if let Err(error) = file.write_all(bytes) {
        drop(file);
        fs::remove_file(path)?;
        return Err(error.into());
    }
    Ok(())
}

fn sign_bytes(key: &SigningKey, domain: &[u8], bytes: &[u8]) -> Result<[u8; 64]> {
    let message = signed_message(domain, bytes).map_err(|_| invalid("document too large"))?;
    Ok(key.sign(&message).to_bytes())
}

fn now() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| invalid("system clock is before 1970"))?
        .as_secs())
}

/// Write `output` (`root.json`) and its signature: version `version`, signed by
/// `root_seed`, naming that key as root key and `repository_public_key` as the
/// repository key. Run offline; never overwrites.
pub fn root(
    root_seed: &Path,
    root_id: &str,
    repository_public_key: &Path,
    repository_id: &str,
    version: u64,
    output: &Path,
) -> Result<()> {
    let root_key = crate::key::read_seed(root_seed)?;
    let root = Root {
        schema: Some(ROOT_SCHEMA_URL.into()),
        format_version: TRUST_FORMAT_VERSION,
        version,
        root_keys: vec![NamedKey {
            id: root_id.into(),
            public_key: encode_public_key(&root_key.verifying_key().to_bytes()),
        }],
        repository_keys: vec![NamedKey {
            id: repository_id.into(),
            public_key: encode_public_key(&read_raw_public_key(repository_public_key)?),
        }],
    };
    let text = encode_root(&root).map_err(|_| {
        invalid("invalid root (version 0, bad identifier, or one key in both roles)")
    })?;
    let signature = sign_bytes(&root_key, ROOT_DOMAIN, text.as_bytes())?;
    let signature_file = signature_path(output);
    if signature_file.exists() {
        return Err(invalid("root signature output already exists").into());
    }
    write_new_file(output, text.as_bytes())?;
    write_new_file(&signature_file, &signature)?;
    Ok(())
}

/// Sign a checked registry into the new directory `output`: copy `root.json`
/// (already root-signed), sign every entry, copy the signed rotations and
/// write a signed `index.json` valid for `expires_in_days`. `version` defaults to the
/// current Unix time, so successive publications increase.
pub fn sign(
    registry: &Path,
    root_public_key: &Path,
    repository_seed: &Path,
    output: &Path,
    version: Option<u64>,
    expires_in_days: u64,
) -> Result<()> {
    check(registry, None, None)?;
    write_signed_site(
        registry,
        root_public_key,
        repository_seed,
        output,
        version,
        expires_in_days,
    )
}

/// Publish an already checked registry and verify the resulting files.
fn write_signed_site(
    registry: &Path,
    root_public_key: &Path,
    repository_seed: &Path,
    output: &Path,
    version: Option<u64>,
    expires_in_days: u64,
) -> Result<()> {
    let pinned = [read_raw_public_key(root_public_key)?];
    let root_bytes = read_bounded(&registry.join(ROOT_PATH), MAX_MANIFEST_BYTES)?;
    let root_signature = read_bounded(&signature_path(&registry.join(ROOT_PATH)), 64)?;
    let trusted = TrustedRoot::bootstrap(&root_bytes, &root_signature, &pinned, 0)
        .map_err(|error| invalid(&format!("{ROOT_PATH}: {error}")))?;
    let key = crate::key::read_seed(repository_seed)?;
    let public = key.verifying_key().to_bytes();
    if !trusted
        .root()
        .repository_keys
        .iter()
        .any(|listed| listed.public_key_bytes() == Ok(public))
    {
        return Err(invalid("the signing key is not a repository key of root.json").into());
    }

    let version = match version {
        Some(version) => version,
        None => now()?,
    };
    let expires = expires_in_days
        .checked_mul(86_400)
        .and_then(|seconds| version.checked_add(seconds))
        .filter(|_| expires_in_days > 0)
        .ok_or_else(|| invalid("expiry must be at least one day"))?;

    fs::create_dir(output)?;
    write_new_file(&output.join(ROOT_PATH), &root_bytes)?;
    write_new_file(&signature_path(&output.join(ROOT_PATH)), &root_signature)?;

    let mut files = Vec::new();
    for (directory, is_rotation) in [("packages", false), ("rotations", true)] {
        for path in registry_files(registry, directory)? {
            let relative = relative_path(registry, &path)?;
            let (bytes, signature) = if is_rotation {
                let rotation = RotationFile::read(&path)?;
                (rotation.bytes, rotation.signature)
            } else {
                let bytes = read_bounded(&path, MAX_MANIFEST_BYTES)?;
                let signature = sign_bytes(&key, ENTRY_DOMAIN, &bytes)?.to_vec();
                (bytes, signature)
            };
            let destination = output.join(relative);
            fs::create_dir_all(destination.parent().expect("listed files have a parent"))?;
            write_new_file(&destination, &bytes)?;
            write_new_file(&signature_path(&destination), &signature)?;
            files.push(IndexFile {
                path: relative.into(),
                sha256: sha256_hex(&bytes),
                size: bytes.len() as u64,
            });
        }
    }
    files.sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));
    let index = encode_index(&Index {
        schema: Some(INDEX_SCHEMA_URL.into()),
        format_version: INDEX_FORMAT_VERSION,
        version,
        expires,
        files,
    })
    .map_err(|_| invalid("invalid index"))?;
    write_new_file(&output.join(INDEX_PATH), index.as_bytes())?;
    write_new_file(
        &signature_path(&output.join(INDEX_PATH)),
        &sign_bytes(&key, INDEX_DOMAIN, index.as_bytes())?,
    )?;
    verify_signed(output, root_public_key, Some(version))
}

/// Canonicalize `path` without requiring it to exist yet: every component that
/// exists is resolved (symlinks included) as the path is rebuilt, and missing
/// trailing components are appended as they are. `..` pops the previous
/// component, so `a/missing/../b` resolves to `a/b`, exactly as the operating
/// system would once `a/missing` exists; `/..` resolves to `/`. A symbolic
/// link whose target does not exist is dangling and refused, because the
/// operating system would refuse any path through it.
fn canonicalize(path: &Path) -> Result<PathBuf> {
    use std::path::Component;
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut resolved = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::ParentDir => {
                // The root has no parent: the operating system resolves /..
                // to /, so a failed pop leaves the root in place.
                resolved.pop();
            }
            Component::Normal(name) => {
                resolved.push(name);
                match resolved.canonicalize() {
                    Ok(canonical) => resolved = canonical,
                    Err(_) if fs::symlink_metadata(&resolved).is_ok() => {
                        return Err(invalid("a symbolic link in the path is dangling").into());
                    }
                    Err(_) => {}
                }
            }
            _ => resolved.push(component.as_os_str()),
        }
    }
    Ok(resolved)
}

/// Create `directory` and its missing parents; on Unix the leaf directory gets
/// `leaf_mode`. Every directory created is recorded in `created`, so a later
/// failure can remove exactly what this run made.
fn create_directories(
    directory: &Path,
    leaf_mode: Option<u32>,
    created: &mut Vec<PathBuf>,
) -> Result<()> {
    let mut missing = Vec::new();
    let mut ancestor = directory;
    while fs::symlink_metadata(ancestor).is_err() {
        missing.push(ancestor.to_path_buf());
        ancestor = ancestor.parent().unwrap_or(Path::new("/"));
    }
    for path in missing.iter().rev() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            let mut builder = fs::DirBuilder::new();
            if path.as_path() == directory
                && let Some(mode) = leaf_mode
            {
                builder.mode(mode);
            }
            builder.create(path)?;
        }
        #[cfg(not(unix))]
        {
            let _ = leaf_mode;
            fs::create_dir(path)?;
        }
        created.push(path.clone());
    }
    Ok(())
}

/// Create a new registry in `directory` with the layout of
/// `xila-project/registry`: a root-signed `root.json`, `root.pub`, an empty
/// `rotations` and an empty `packages`. A root key and a repository key
/// are generated; their private seeds go to `key_directory`, which must be
/// outside the registry (it is never published). Every validation runs before
/// anything is created, so a rejected run leaves no trace and can simply be
/// retried. An existing key directory is used as it is: it must already be
/// empty and owner-only (0700), and its permissions are never changed. If a
/// later step fails, only what this run created is removed again. The
/// repository key is the one `root.json` lists for signing.
pub fn init(
    directory: &Path,
    key_directory: &Path,
    root_id: &str,
    repository_id: &str,
) -> Result<()> {
    // A dangling symbolic link anywhere in either path is refused by
    // canonicalize below, before anything is created.
    if let Ok(metadata) = fs::metadata(directory) {
        if !metadata.is_dir() {
            return Err(invalid("registry directory exists and is not a directory").into());
        }
        if fs::read_dir(directory)?.next().is_some() {
            return Err(invalid("registry directory exists and is not empty").into());
        }
    }
    if let Ok(metadata) = fs::metadata(key_directory) {
        if !metadata.is_dir() {
            return Err(invalid("key directory exists and is not a directory").into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = metadata.permissions().mode() & 0o777;
            if mode != 0o700 {
                let message = format!("key directory exists with mode {mode:04o}; expected 0700");
                return Err(invalid(&message).into());
            }
        }
        if fs::read_dir(key_directory)?.next().is_some() {
            return Err(invalid("key directory exists and is not empty").into());
        }
    }
    let registry = canonicalize(directory)?;
    let keys = canonicalize(key_directory)?;
    if keys.starts_with(&registry) || registry.starts_with(&keys) {
        return Err(invalid("the key directory must be outside the registry").into());
    }

    let mut created: Vec<PathBuf> = Vec::new();
    let result = create_registry(&registry, &keys, root_id, repository_id, &mut created);
    if result.is_err() {
        remove_created(&created);
    }
    result?;

    let root_seed = keys.join("root.seed");
    let root_public = registry.join("root.pub");
    println!("Created registry {}", registry.display());
    println!(
        "Root key {}",
        trust::fingerprint(&read_raw_public_key(&root_public)?)
    );
    println!(
        "Private keys written to {} (keep them outside the registry):",
        keys.display()
    );
    println!("  {} (root key: keep offline)", root_seed.display());
    println!(
        "  {} (repository key: signs publications)",
        keys.join("repository.seed").display()
    );
    Ok(())
}

/// Remove the paths a failed run created, deepest first. A path that cannot
/// be removed is reported on stderr (it can hold a private key); the failure
/// of the run itself is what the caller returns.
fn remove_created(created: &[PathBuf]) {
    for path in created.iter().rev() {
        let Ok(metadata) = fs::symlink_metadata(path) else {
            continue;
        };
        let removed = if metadata.is_dir() {
            fs::remove_dir(path)
        } else {
            fs::remove_file(path)
        };
        if let Err(error) = removed {
            eprintln!("warning: could not remove {}: {error}", path.display());
        }
    }
}

/// The creating half of [`init`]: every file and directory it makes is
/// recorded in `created`, in creation order.
fn create_registry(
    registry: &Path,
    keys: &Path,
    root_id: &str,
    repository_id: &str,
    created: &mut Vec<PathBuf>,
) -> Result<()> {
    if fs::symlink_metadata(keys).is_err() {
        create_directories(keys, Some(0o700), created)?;
    }
    if fs::symlink_metadata(registry).is_err() {
        create_directories(registry, None, created)?;
    }
    let root_seed = keys.join("root.seed");
    let repository_seed = keys.join("repository.seed");
    let repository_public = keys.join("repository.pub");
    let root_public = registry.join("root.pub");
    // Record a key pair only once it exists: a failed generate may leave a
    // pre-existing file untouched, and that file must not be removed.
    crate::key::generate(&root_seed, &root_public)?;
    created.push(root_seed.clone());
    created.push(root_public.clone());
    crate::key::generate(&repository_seed, &repository_public)?;
    created.push(repository_seed.clone());
    created.push(repository_public.clone());
    create_directories(&registry.join("rotations"), None, created)?;
    create_directories(&registry.join("packages"), None, created)?;
    // root() writes these two files itself; record them beforehand so a
    // partial write is removed again (create_new guarantees this run made
    // them, so removing them is safe).
    let root_json = registry.join(ROOT_PATH);
    created.push(root_json.clone());
    created.push(signature_path(&root_json));
    root(
        &root_seed,
        root_id,
        &repository_public,
        repository_id,
        1,
        &root_json,
    )
}

fn collect_site(root: &Path, directory: &Path, output: &mut Vec<String>) -> Result<()> {
    for path in sorted_entries(directory)? {
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.is_dir() {
            collect_site(root, &path, output)?;
        } else if metadata.is_file() {
            let relative = path
                .strip_prefix(root)
                .ok()
                .and_then(Path::to_str)
                .ok_or_else(|| invalid("registry path is not UTF-8"))?;
            output.push(relative.to_owned());
        } else {
            return Err(failure(&path, "unexpected file type"));
        }
    }
    Ok(())
}

/// Print `trust::fingerprint` of a raw public key file.
pub fn fingerprint(public_key: &Path) -> Result<()> {
    println!("{}", trust::fingerprint(&read_raw_public_key(public_key)?));
    Ok(())
}

/// Verify a signed registry from the pinned root, including each entry and
/// rotation, package key continuity and the exact index file listing.
pub fn verify_signed(site: &Path, root_public_key: &Path, now: Option<u64>) -> Result<()> {
    reject_legacy_layout(site)?;
    let pinned = [read_raw_public_key(root_public_key)?];
    let read_signed = |relative: &str, limit| -> Result<(Vec<u8>, Vec<u8>)> {
        let path = site.join(relative);
        Ok((
            read_bounded(&path, limit)?,
            read_bounded(&signature_path(&path), 64)?,
        ))
    };
    let (root, root_signature) = read_signed(ROOT_PATH, MAX_MANIFEST_BYTES)?;
    let trusted = TrustedRoot::bootstrap(&root, &root_signature, &pinned, 0)
        .map_err(|error| invalid(&format!("{ROOT_PATH}: {error}")))?;
    let (index, index_signature) = read_signed(INDEX_PATH, xila_package_manifest::MAX_INDEX_BYTES)?;
    let index = trusted
        .verify_index(&index, &index_signature, 0, now)
        .map_err(|error| invalid(&format!("{INDEX_PATH}: {error}")))?;

    let mut present = Vec::new();
    for directory in ["packages", "rotations"] {
        let path = site.join(directory);
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Ok(metadata) if metadata.is_dir() => collect_site(site, &path, &mut present)?,
            Ok(_) => return Err(failure(&path, "expected a directory")),
            Err(error) => return Err(error.into()),
        }
    }
    for path in &present {
        let listed = path.strip_suffix(SIGNATURE_SUFFIX).unwrap_or(path);
        if index.file(listed).is_none() {
            return Err(invalid(&format!("{path}: not listed in {INDEX_PATH}")).into());
        }
    }

    let mut history = RegistryHistory::default();
    for file in &index.files {
        let fail = |error: trust::Error| invalid(&format!("{}: {error}", file.path));
        if file.path.starts_with("rotations/") {
            let path = site.join(&file.path);
            let bytes = read_bounded(&path, MAX_ROTATION_BYTES)?;
            trust::check_listed(&index, &file.path, &bytes).map_err(fail)?;
            let rotation = RotationFile::from_bytes(&path, bytes)?;
            history.add_rotation(&file.path, rotation)?;
        } else {
            let (bytes, signature) = read_signed(&file.path, MAX_MANIFEST_BYTES)?;
            trust::check_listed(&index, &file.path, &bytes).map_err(fail)?;
            let entry = trusted.verify_entry(&bytes, &signature).map_err(fail)?;
            history.add_entry(&file.path, entry)?;
        }
    }
    history.verify()?;
    println!(
        "Verified signed registry: root v{} (root key {}), index v{} (expires {}), {} package entries and key rotations",
        trusted.version(),
        trust::fingerprint(&pinned[0]),
        index.version,
        index.expires,
        index.files.len(),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_registry(directory: &Path) {
        fs::create_dir_all(directory.join("packages/dev/xila/clock")).unwrap();
        let entry = RegistryEntry {
            schema: Some(xila_package_manifest::REGISTRY_ENTRY_SCHEMA_URL.into()),
            format_version: xila_package_manifest::REGISTRY_FORMAT_VERSION,
            name: "dev.xila.clock".into(),
            version: "0.1.0".into(),
            target: "wasm32-wasip1".into(),
            xila_version: xila_package_manifest::XilaVersion::new(0, 1),
            capabilities: vec![],
            display_name: Some("Clock".into()),
            metadata: None,
            package_key: PackageKey::new(
                1,
                &ed25519_dalek::SigningKey::from_bytes(&[42; 32])
                    .verifying_key()
                    .to_bytes(),
            )
            .unwrap(),
            archive: Archive {
                url: "https://xila.example/clock.xpk".into(),
                sha256: "c".repeat(64),
                size: 10,
            },
        };
        fs::write(
            directory.join("packages/dev/xila/clock/0.1.0.json"),
            encode_registry_entry(&entry).unwrap(),
        )
        .unwrap();
    }

    struct Keys {
        _directory: tempfile::TempDir,
        root_seed: PathBuf,
        root_public: PathBuf,
        repository_seed: PathBuf,
        repository_public: PathBuf,
    }

    fn new_keys() -> Keys {
        let directory = tempfile::tempdir().unwrap();
        let path = |name: &str| directory.path().join(name);
        crate::key::generate(&path("root.seed"), &path("root.pub")).unwrap();
        crate::key::generate(&path("repository.seed"), &path("repository.pub")).unwrap();
        Keys {
            root_seed: path("root.seed"),
            root_public: path("root.pub"),
            repository_seed: path("repository.seed"),
            repository_public: path("repository.pub"),
            _directory: directory,
        }
    }

    #[test]
    fn signs_and_verifies_a_registry_and_rejects_tampering() {
        let keys = new_keys();
        let temp = tempfile::tempdir().unwrap();
        let registry = temp.path().join("registry");
        write_registry(&registry);
        root(
            &keys.root_seed,
            "root-test",
            &keys.repository_public,
            "repository-test",
            1,
            &registry.join(ROOT_PATH),
        )
        .unwrap();
        // Never overwrites.
        assert!(
            root(
                &keys.root_seed,
                "root-test",
                &keys.repository_public,
                "repository-test",
                2,
                &registry.join(ROOT_PATH),
            )
            .is_err()
        );

        let site = temp.path().join("site");
        sign(
            &registry,
            &keys.root_public,
            &keys.repository_seed,
            &site,
            Some(1_000),
            30,
        )
        .unwrap();
        assert!(
            site.join("packages/dev/xila/clock/0.1.0.json.sig")
                .is_file()
        );
        assert!(!site.join("keys").exists());
        verify_signed(&site, &keys.root_public, Some(1_000)).unwrap();
        assert!(verify_signed(&site, &keys.root_public, Some(1_000 + 30 * 86_400)).is_err());
        // The repository key is not the root of trust.
        assert!(verify_signed(&site, &keys.repository_public, None).is_err());

        let entry = site.join("packages/dev/xila/clock/0.1.0.json");
        let original = fs::read(&entry).unwrap();
        fs::write(
            &entry,
            String::from_utf8(original.clone())
                .unwrap()
                .replace("Clock", "Clocx"),
        )
        .unwrap();
        assert!(verify_signed(&site, &keys.root_public, None).is_err());
        fs::write(&entry, &original).unwrap();
        fs::write(site.join("packages/dev/xila/clock/0.2.0.json"), &original).unwrap();
        assert!(verify_signed(&site, &keys.root_public, None).is_err());
        fs::remove_file(site.join("packages/dev/xila/clock/0.2.0.json")).unwrap();
        verify_signed(&site, &keys.root_public, None).unwrap();
    }

    #[test]
    fn sign_requires_a_listed_repository_key() {
        let keys = new_keys();
        let other = new_keys();
        let temp = tempfile::tempdir().unwrap();
        let registry = temp.path().join("registry");
        write_registry(&registry);
        root(
            &keys.root_seed,
            "root-test",
            &keys.repository_public,
            "repository-test",
            1,
            &registry.join(ROOT_PATH),
        )
        .unwrap();
        for (root_public, seed) in [
            (&keys.root_public, &other.repository_seed),
            (&keys.root_public, &keys.root_seed),
            (&other.root_public, &keys.repository_seed),
        ] {
            assert!(
                sign(
                    &registry,
                    root_public,
                    seed,
                    &temp.path().join("site"),
                    Some(1),
                    30
                )
                .is_err()
            );
            let _ = fs::remove_dir_all(temp.path().join("site"));
        }
        // One key may not hold both roles.
        assert!(
            root(
                &keys.root_seed,
                "root-test",
                &keys.root_public,
                "repository-test",
                1,
                &temp.path().join("other-root.json"),
            )
            .is_err()
        );
    }

    #[test]
    fn hashes_as_lowercase_hex() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn canonicalize_resolves_dot_and_dotdot_components() {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().canonicalize().unwrap();
        assert_eq!(
            canonicalize(&temp.path().join("a/./b/../c")).unwrap(),
            base.join("a").join("c")
        );
        assert_eq!(
            canonicalize(&temp.path().join("missing/../x")).unwrap(),
            base.join("x")
        );
        // The root has no parent: the operating system resolves /.. to /.
        assert_eq!(canonicalize(Path::new("/..")).unwrap(), PathBuf::from("/"));
        assert_eq!(
            canonicalize(Path::new("/../..")).unwrap(),
            PathBuf::from("/")
        );
    }

    #[test]
    fn init_validates_before_creating_and_cleans_up_on_failure() {
        let temp = tempfile::tempdir().unwrap();
        let registry = temp.path().join("registry");
        let keys = temp.path().join("keys");

        // A path that exists but is not a directory is refused.
        let file = temp.path().join("file");
        fs::write(&file, b"").unwrap();
        let error = init(&file, &keys, "root", "repository")
            .unwrap_err()
            .to_string();
        assert!(error.contains("not a directory"), "{error}");
        let error = init(&registry, &file, "root", "repository")
            .unwrap_err()
            .to_string();
        assert!(error.contains("not a directory"), "{error}");
        assert!(!registry.exists());

        // A dangling symbolic link is refused with a clear message, as the
        // last component of either path or anywhere inside it.
        #[cfg(unix)]
        {
            let dangling = temp.path().join("dangling");
            std::os::unix::fs::symlink(temp.path().join("absent"), &dangling).unwrap();
            let error = init(&dangling, &keys, "root", "repository")
                .unwrap_err()
                .to_string();
            assert!(error.contains("dangling"), "{error}");
            let error = init(&registry, &dangling, "root", "repository")
                .unwrap_err()
                .to_string();
            assert!(error.contains("dangling"), "{error}");
            assert!(!registry.exists());

            // a/dl/../keys with dl -> nowhere: the operating system refuses
            // that path (ENOENT), so it must not be silently read as a/keys.
            let linked = temp.path().join("linked");
            fs::create_dir(&linked).unwrap();
            std::os::unix::fs::symlink(linked.join("nowhere"), linked.join("dl")).unwrap();
            let error = init(
                &linked.join("reg"),
                &linked.join("dl/../keys"),
                "root",
                "repository",
            )
            .unwrap_err()
            .to_string();
            assert!(error.contains("dangling"), "{error}");
            assert!(!linked.join("reg").exists());
            assert!(!linked.join("keys").exists());

            // a/link/reg with link -> keys (not yet existing): the link is
            // dangling now, and creating the key directory would make it
            // live, putting the registry inside the key directory.
            let linked2 = temp.path().join("linked2");
            fs::create_dir(&linked2).unwrap();
            std::os::unix::fs::symlink(linked2.join("keys"), linked2.join("link")).unwrap();
            let error = init(
                &linked2.join("link/reg"),
                &linked2.join("keys"),
                "root",
                "repository",
            )
            .unwrap_err()
            .to_string();
            assert!(error.contains("dangling"), "{error}");
            assert!(!linked2.join("keys").exists());
            assert!(!linked2.join("reg").exists());
        }

        // A `..` after a missing component is resolved, not dropped:
        // existing/missing/../registry/keys is existing/registry/keys, inside
        // the registry, so the run is refused and nothing is created.
        fs::create_dir(temp.path().join("existing")).unwrap();
        let dotted_registry = temp.path().join("existing/registry");
        let dotted_keys = temp.path().join("existing/missing/../registry/keys");
        let error = init(&dotted_registry, &dotted_keys, "root", "repository")
            .unwrap_err()
            .to_string();
        assert!(error.contains("outside the registry"), "{error}");
        assert!(!temp.path().join("existing/missing").exists());
        assert!(!dotted_registry.exists());

        // A key directory inside the registry is refused before anything is
        // created, so a retry with a valid key directory succeeds.
        let error = init(&registry, &registry.join("keys"), "root", "repository")
            .unwrap_err()
            .to_string();
        assert!(error.contains("outside the registry"), "{error}");
        assert!(!registry.exists());
        init(&registry, &keys, "root", "repository").unwrap();
        assert!(registry.join(ROOT_PATH).is_file());
        assert!(keys.join("root.seed").is_file());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&keys).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700);
        }

        // An already existing empty registry directory is used as it is.
        let preexisting = temp.path().join("preexisting");
        fs::create_dir(&preexisting).unwrap();
        let preexisting_keys = temp.path().join("preexisting-keys");
        init(&preexisting, &preexisting_keys, "root", "repository").unwrap();
        assert!(preexisting.join(ROOT_PATH).is_file());
        assert!(preexisting_keys.join("repository.seed").is_file());

        // An existing key directory keeps its permissions: not 0700 is refused
        // untouched (Unix), and a non-empty one is refused as well.
        let other = temp.path().join("other");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&keys, fs::Permissions::from_mode(0o755)).unwrap();
            let error = init(&other, &keys, "root", "repository")
                .unwrap_err()
                .to_string();
            assert!(error.contains("0700"), "{error}");
            let mode = fs::metadata(&keys).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o755);
            assert!(!other.exists());
            fs::set_permissions(&keys, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let error = init(&other, &keys, "root", "repository")
            .unwrap_err()
            .to_string();
        assert!(error.contains("not empty"), "{error}");
        assert!(!other.exists());

        // A failure after the keys were generated (an invalid root id fails
        // when root.json is written) removes only what the run created: the
        // directories it made are gone, a pre-existing key directory stays.
        let fourth = temp.path().join("fourth");
        let fresh = temp.path().join("fresh");
        let error = init(&fourth, &fresh, "Not A Valid Id", "repository")
            .unwrap_err()
            .to_string();
        assert!(error.contains("invalid root"), "{error}");
        assert!(!fourth.exists());
        assert!(!fresh.exists());

        let kept = temp.path().join("kept");
        fs::create_dir(&kept).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&kept, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let fifth = temp.path().join("fifth");
        let error = init(&fifth, &kept, "Not A Valid Id", "repository")
            .unwrap_err()
            .to_string();
        assert!(error.contains("invalid root"), "{error}");
        assert!(!fifth.exists());
        assert!(kept.is_dir());
        assert!(fs::read_dir(&kept).unwrap().next().is_none());

        // A pre-existing empty registry directory survives a failed run,
        // still empty; only the key directory this run made is removed.
        let kept_registry = temp.path().join("kept-registry");
        fs::create_dir(&kept_registry).unwrap();
        let kept_keys = temp.path().join("kept-keys");
        let error = init(&kept_registry, &kept_keys, "Not A Valid Id", "repository")
            .unwrap_err()
            .to_string();
        assert!(error.contains("invalid root"), "{error}");
        assert!(kept_registry.is_dir());
        assert!(fs::read_dir(&kept_registry).unwrap().next().is_none());
        assert!(!kept_keys.exists());
    }

    #[cfg(unix)]
    #[test]
    fn cleanup_warns_when_a_created_path_cannot_be_removed() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let directory = temp.path().join("locked");
        fs::create_dir(&directory).unwrap();
        let file = directory.join("root.seed");
        fs::write(&file, b"seed").unwrap();
        // Without write permission on the parent, neither removal succeeds.
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o500)).unwrap();
        remove_created(&[file.clone(), directory.clone()]);
        assert!(file.exists());
        assert!(directory.exists());
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    }
}
