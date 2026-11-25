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
    io::Write,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use xila_package_manager::trust::{self, TrustedRoot};
use xila_package_manifest::{
    Archive, DEVELOPER_KEY_DOMAIN, DeveloperKey, ENTRY_DOMAIN, INDEX_DOMAIN, INDEX_PATH,
    INDEX_SCHEMA_URL, Index, IndexFile, Manifest, NAMESPACE_DOMAIN, NAMESPACES_DIRECTORY, NamedKey,
    Namespace, PackageKind, ROOT_DOMAIN, ROOT_PATH, ROOT_SCHEMA_URL, RegistryEntry, Root,
    SIGNATURE_SUFFIX, TRUST_FORMAT_VERSION, decode_developer_key, decode_namespace,
    decode_registry_entry, encode_index, encode_registry_entry, encode_root, is_legacy_identifier,
    namespace_covers, namespace_path, signed_message,
};
use xila_package_verification::PublicKey;

use crate::{Result, invalid, manifest_error, package_verification_error};

fn read_public_key(path: &Path) -> Result<PublicKey> {
    let raw: [u8; 32] = fs::read(path)?
        .try_into()
        .map_err(|_| invalid("public key must be exactly 32 raw bytes"))?;
    Ok(PublicKey::from_bytes(&raw).map_err(|_| invalid("invalid Ed25519 public key"))?)
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .fold(String::with_capacity(64), |mut hex, byte| {
            let _ = write!(hex, "{byte:02x}");
            hex
        })
}

fn verified_manifest(archive: &[u8], public_key: &Path) -> Result<Manifest> {
    Ok(
        xila_package_reader::verify_signed(archive, &read_public_key(public_key)?)
            .map_err(package_verification_error)?,
    )
}

/// Write the registry entry for `archive`, published by `publisher` at `url`.
pub fn entry(
    archive: &Path,
    public_key: &Path,
    publisher: &str,
    url: &str,
    output: &Path,
) -> Result<()> {
    let bytes = fs::read(archive)?;
    let manifest = verified_manifest(&bytes, public_key)?;
    let location = Archive {
        url: url.into(),
        sha256: sha256_hex(&bytes),
        size: bytes.len() as u64,
    };
    let entry = RegistryEntry::from_manifest(&manifest, publisher, location)
        .map_err(|_| invalid("invalid registry entry (publisher, URL or metadata)"))?;
    let text = encode_registry_entry(&entry).map_err(|_| invalid("invalid registry entry"))?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)?;
    file.write_all(text.as_bytes())?;
    Ok(())
}

fn verify_archive(entry: &RegistryEntry, bytes: &[u8], key: &PublicKey) -> Result<()> {
    if bytes.len() as u64 != entry.archive.size || sha256_hex(bytes) != entry.archive.sha256 {
        return Err(invalid("archive size or SHA-256 differs from the registry entry").into());
    }
    let manifest =
        xila_package_reader::verify_signed(bytes, key).map_err(package_verification_error)?;
    entry
        .check_manifest(&manifest)
        .map_err(|_| invalid("registry entry differs from the signed package manifest"))?;
    Ok(())
}

/// Check that `entry` describes exactly `archive`, signed by `public_key`.
pub fn verify(entry: &Path, archive: &Path, public_key: &Path) -> Result<()> {
    let entry = decode_registry_entry(&fs::read(entry)?)
        .map_err(|error| manifest_error("invalid registry entry", error))?;
    verify_archive(&entry, &fs::read(archive)?, &read_public_key(public_key)?)
}

fn sorted_entries(directory: &Path) -> Result<Vec<PathBuf>> {
    let mut paths = fs::read_dir(directory)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    paths.sort();
    Ok(paths)
}

fn collect_json(directory: &Path, output: &mut Vec<PathBuf>) -> Result<()> {
    for path in sorted_entries(directory)? {
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.is_dir() {
            collect_json(&path, output)?;
        } else if metadata.is_file()
            && path
                .extension()
                .is_some_and(|extension| extension == "json")
        {
            output.push(path);
        } else if !(metadata.is_file() && path.file_name().is_some_and(|name| name == ".gitkeep")) {
            return Err(invalid(&format!("unexpected registry file: {}", path.display())).into());
        }
    }
    Ok(())
}

fn failure(path: &Path, message: &str) -> Box<dyn std::error::Error> {
    invalid(&format!("{}: {message}", path.display())).into()
}

/// The namespace file covering `name`, if any (they never overlap).
fn covering<'a>(namespaces: &'a BTreeMap<String, Namespace>, name: &str) -> Option<&'a Namespace> {
    namespaces
        .values()
        .find(|namespace| namespace_covers(&namespace.namespace, name))
}

/// Check that a new namespace file overlaps no other one and lists only known
/// developer keys.
fn check_namespace(
    namespace: &Namespace,
    namespaces: &BTreeMap<String, Namespace>,
    keys: &BTreeMap<String, DeveloperKey>,
) -> std::result::Result<(), String> {
    if let Some(other) = namespaces.keys().find(|other| {
        xila_package_manifest::namespace::namespaces_overlap(other, &namespace.namespace)
    }) {
        return Err(format!(
            "namespace {} overlaps namespace {other}; one owner per identifier",
            namespace.namespace
        ));
    }
    if let Some(unknown) = namespace
        .developer_keys
        .iter()
        .find(|key| !keys.contains_key(*key))
    {
        return Err(format!("unknown developer key {unknown}"));
    }
    Ok(())
}

/// Why `key` may not publish `entry`, if it may not.
fn authorization_failure(
    entry: &RegistryEntry,
    key: &DeveloperKey,
    namespace: Option<&Namespace>,
) -> Option<String> {
    if !key.authorizes(&entry.name, namespace) {
        return Some(match namespace {
            None if !is_legacy_identifier(&entry.name) => format!(
                "no namespace file covers {}; add {NAMESPACES_DIRECTORY}/<namespace>.json",
                entry.name
            ),
            None => format!(
                "publisher {} may not publish {} (legacy namespace not granted)",
                key.id, entry.name
            ),
            Some(namespace) => format!(
                "publisher {} may not publish {}: not listed in namespace {}",
                key.id, entry.name, namespace.namespace
            ),
        });
    }
    let kind = PackageKind::of_target(&entry.target);
    (!key.authorizes_kind(kind)).then(|| {
        format!(
            "publisher {} is not authorized for {} packages (target {})",
            key.id,
            kind.name(),
            entry.target
        )
    })
}

/// Check a registry checkout: developer keys (`keys/developers/<id>.json`),
/// namespace files (`namespaces/<namespace>.json`, optional) and entries
/// (`packages/<name, dots as />/<version>.json`). Namespace files may not
/// overlap and may list only known keys. Each entry must be canonical, sit at
/// its own path, and name a publisher listed in the namespace file covering
/// its identifier (or, for a legacy `xila.<name>` identifier, a key granted
/// the legacy namespace) and authorized for its kind. With `archives`, a
/// directory of the downloaded `.xpk` files (named after their URLs), each
/// archive is also verified against its entry.
pub fn check(root: &Path, archives: Option<&Path>) -> Result<()> {
    let mut keys: BTreeMap<String, DeveloperKey> = BTreeMap::new();
    for path in sorted_entries(&root.join("keys/developers"))? {
        let key = decode_developer_key(&fs::read(&path)?)
            .map_err(|_| failure(&path, "invalid developer key"))?;
        if path.file_name().and_then(|name| name.to_str()) != Some(&format!("{}.json", key.id)) {
            return Err(failure(&path, "file name must be <id>.json"));
        }
        keys.insert(key.id.clone(), key);
    }

    let mut namespaces: BTreeMap<String, Namespace> = BTreeMap::new();
    let directory = root.join(NAMESPACES_DIRECTORY);
    if fs::symlink_metadata(&directory).is_ok() {
        for path in sorted_entries(&directory)? {
            if !fs::symlink_metadata(&path)?.is_file() {
                return Err(failure(
                    &path,
                    "namespace files may not be in subdirectories",
                ));
            }
            let namespace = decode_namespace(&fs::read(&path)?).map_err(|error| {
                failure(
                    &path,
                    &manifest_error("invalid namespace file", error).to_string(),
                )
            })?;
            if path.file_name().and_then(|name| name.to_str())
                != Some(&format!("{}.json", namespace.namespace))
            {
                return Err(failure(&path, "file name must be <namespace>.json"));
            }
            check_namespace(&namespace, &namespaces, &keys)
                .map_err(|message| failure(&path, &message))?;
            namespaces.insert(namespace.namespace.clone(), namespace);
        }
    }

    let packages = root.join("packages");
    let mut files = Vec::new();
    collect_json(&packages, &mut files)?;
    for path in &files {
        let bytes = fs::read(path)?;
        let entry = decode_registry_entry(&bytes).map_err(|error| {
            failure(
                path,
                &manifest_error("invalid registry entry", error).to_string(),
            )
        })?;
        let canonical =
            encode_registry_entry(&entry).map_err(|_| failure(path, "invalid registry entry"))?;
        if canonical.as_bytes() != bytes {
            return Err(failure(
                path,
                "entry is not canonical; regenerate it with `xila-package registry entry`",
            ));
        }
        let mut expected = packages.clone();
        expected.extend(entry.name.split('.'));
        expected.push(format!("{}.json", entry.version));
        if *path != expected {
            return Err(failure(
                path,
                &format!(
                    "entry for {} {} must be at {}",
                    entry.name,
                    entry.version,
                    expected.display()
                ),
            ));
        }
        let key = keys
            .get(&entry.publisher)
            .ok_or_else(|| failure(path, &format!("unknown publisher {}", entry.publisher)))?;
        if let Some(message) =
            authorization_failure(&entry, key, covering(&namespaces, &entry.name))
        {
            return Err(failure(path, &message));
        }
        if let Some(archives) = archives {
            let name = entry
                .archive
                .url
                .rsplit('/')
                .next()
                .filter(|name| !name.is_empty() && *name != "." && *name != "..")
                .ok_or_else(|| failure(path, "archive URL has no file name"))?;
            let raw = key
                .public_key_bytes()
                .map_err(|_| failure(path, "invalid publisher key"))?;
            let public =
                PublicKey::from_bytes(&raw).map_err(|_| failure(path, "invalid publisher key"))?;
            verify_archive(&entry, &fs::read(archives.join(name))?, &public)
                .map_err(|error| failure(path, &error.to_string()))?;
        }
    }
    println!(
        "Checked {} developer key(s), {} namespace(s) and {} registry entr{}{}",
        keys.len(),
        namespaces.len(),
        files.len(),
        if files.len() == 1 { "y" } else { "ies" },
        if archives.is_some() {
            ", including their archives and signatures"
        } else {
            ""
        }
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Repository signatures: root.json, index.json and detached .sig files.
// ---------------------------------------------------------------------------

fn read_raw_public_key(path: &Path) -> Result<[u8; 32]> {
    Ok(fs::read(path)?
        .try_into()
        .map_err(|_| invalid("public key must be exactly 32 raw bytes"))?)
}

fn base64(bytes: &[u8; 32]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(44);
    for chunk in bytes.chunks(3) {
        let mut block = [0u8; 3];
        block[..chunk.len()].copy_from_slice(chunk);
        let value = u32::from_be_bytes([0, block[0], block[1], block[2]]);
        for index in 0..4 {
            output.push(if index <= chunk.len() {
                TABLE[(value >> (18 - 6 * index) & 63) as usize] as char
            } else {
                '='
            });
        }
    }
    output
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
    file.write_all(bytes)?;
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
            public_key: base64(&root_key.verifying_key().to_bytes()),
        }],
        repository_keys: vec![NamedKey {
            id: repository_id.into(),
            public_key: base64(&read_raw_public_key(repository_public_key)?),
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
/// (already root-signed), sign every developer key, namespace file and
/// entry, and write a
/// signed `index.json` valid for `expires_in_days`. `version` defaults to the
/// current Unix time, so successive publications increase.
pub fn sign(
    registry: &Path,
    root_public_key: &Path,
    repository_seed: &Path,
    output: &Path,
    version: Option<u64>,
    expires_in_days: u64,
) -> Result<()> {
    check(registry, None)?;
    write_signed_site(
        registry,
        root_public_key,
        repository_seed,
        output,
        version,
        expires_in_days,
    )
}

/// The part of [`sign`] after `check`. It ends with `verify_signed`, which
/// enforces the same publisher rules, so tests can reach that check alone.
fn write_signed_site(
    registry: &Path,
    root_public_key: &Path,
    repository_seed: &Path,
    output: &Path,
    version: Option<u64>,
    expires_in_days: u64,
) -> Result<()> {
    let pinned = [read_raw_public_key(root_public_key)?];
    let root_bytes = fs::read(registry.join(ROOT_PATH))?;
    let root_signature = fs::read(signature_path(&registry.join(ROOT_PATH)))?;
    let trusted = TrustedRoot::bootstrap(&root_bytes, &root_signature, &pinned, 0)
        .map_err(|error| invalid(&format!("{ROOT_PATH}: {error}")))?;
    let key = crate::key::read_seed(repository_seed)?;
    let public = base64(&key.verifying_key().to_bytes());
    if !trusted
        .root()
        .repository_keys
        .iter()
        .any(|listed| listed.public_key == public)
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

    let mut listed = Vec::new();
    for (directory, domain) in [
        ("keys/developers", DEVELOPER_KEY_DOMAIN),
        (NAMESPACES_DIRECTORY, NAMESPACE_DOMAIN),
        ("packages", ENTRY_DOMAIN),
    ] {
        let directory = registry.join(directory);
        if domain == NAMESPACE_DOMAIN && fs::symlink_metadata(&directory).is_err() {
            continue;
        }
        let mut paths = Vec::new();
        collect_json(&directory, &mut paths)?;
        listed.extend(paths.into_iter().map(|path| (path, domain)));
    }
    let mut files = Vec::with_capacity(listed.len());
    for (path, domain) in &listed {
        let relative = path
            .strip_prefix(registry)
            .ok()
            .and_then(Path::to_str)
            .ok_or_else(|| invalid("registry path is not UTF-8"))?
            .to_owned();
        let bytes = fs::read(path)?;
        let destination = output.join(&relative);
        fs::create_dir_all(destination.parent().expect("listed files have a parent"))?;
        write_new_file(&destination, &bytes)?;
        write_new_file(
            &signature_path(&destination),
            &sign_bytes(&key, domain, &bytes)?,
        )?;
        files.push(IndexFile {
            path: relative,
            sha256: sha256_hex(&bytes),
            size: bytes.len() as u64,
        });
    }
    files.sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));
    let index = encode_index(&Index {
        schema: Some(INDEX_SCHEMA_URL.into()),
        format_version: TRUST_FORMAT_VERSION,
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
/// `keys/developers` and an empty `packages`. A root key and a repository key
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
    create_directories(&registry.join("keys/developers"), None, created)?;
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

/// Verify a signed registry the way a device would, from the pinned
/// `root_public_key`: root, index (and its expiry at `now`, if given), every
/// listed file and its own signature, namespace files (no overlap, known
/// keys), and each entry's publisher against the namespace file covering it.
/// Rejects unlisted files.
pub fn verify_signed(site: &Path, root_public_key: &Path, now: Option<u64>) -> Result<()> {
    let pinned = [read_raw_public_key(root_public_key)?];
    let read_signed = |relative: &str| -> Result<(Vec<u8>, Vec<u8>)> {
        let path = site.join(relative);
        let read = |path: &Path| {
            fs::read(path).map_err(|error| invalid(&format!("{}: {error}", path.display())))
        };
        Ok((read(&path)?, read(&signature_path(&path))?))
    };
    let (root, root_signature) = read_signed(ROOT_PATH)?;
    let trusted = TrustedRoot::bootstrap(&root, &root_signature, &pinned, 0)
        .map_err(|error| invalid(&format!("{ROOT_PATH}: {error}")))?;
    let (index, index_signature) = read_signed(INDEX_PATH)?;
    let index = trusted
        .verify_index(&index, &index_signature, 0, now)
        .map_err(|error| invalid(&format!("{INDEX_PATH}: {error}")))?;

    let mut present = Vec::new();
    for directory in ["keys", NAMESPACES_DIRECTORY, "packages"] {
        if site.join(directory).is_dir() {
            collect_site(site, &site.join(directory), &mut present)?;
        }
    }
    for path in &present {
        let listed = path.strip_suffix(SIGNATURE_SUFFIX).unwrap_or(path);
        if index.file(listed).is_none() {
            return Err(invalid(&format!("{path}: not listed in {INDEX_PATH}")).into());
        }
    }

    let mut developers: BTreeMap<String, DeveloperKey> = BTreeMap::new();
    for file in index
        .files
        .iter()
        .filter(|file| file.path.starts_with("keys/"))
    {
        let (bytes, signature) = read_signed(&file.path)?;
        let fail = |error: trust::Error| invalid(&format!("{}: {error}", file.path));
        trust::check_listed(&index, &file.path, &bytes).map_err(fail)?;
        let key = trusted
            .verify_developer_key(&bytes, &signature)
            .map_err(fail)?;
        if file.path != trust::developer_key_path(&key.id) {
            return Err(invalid(&format!("{}: file name must be <id>.json", file.path)).into());
        }
        developers.insert(key.id.clone(), key);
    }
    let mut namespaces: BTreeMap<String, Namespace> = BTreeMap::new();
    for file in index
        .files
        .iter()
        .filter(|file| file.path.starts_with("namespaces/"))
    {
        let (bytes, signature) = read_signed(&file.path)?;
        let fail = |error: trust::Error| invalid(&format!("{}: {error}", file.path));
        trust::check_listed(&index, &file.path, &bytes).map_err(fail)?;
        let namespace = trusted.verify_namespace(&bytes, &signature).map_err(fail)?;
        if file.path != namespace_path(&namespace.namespace) {
            return Err(invalid(&format!(
                "{}: file name must be <namespace>.json",
                file.path
            ))
            .into());
        }
        check_namespace(&namespace, &namespaces, &developers)
            .map_err(|message| invalid(&format!("{}: {message}", file.path)))?;
        namespaces.insert(namespace.namespace.clone(), namespace);
    }
    let mut entries = 0usize;
    for file in index
        .files
        .iter()
        .filter(|file| file.path.starts_with("packages/"))
    {
        let (bytes, signature) = read_signed(&file.path)?;
        let fail = |error: trust::Error| invalid(&format!("{}: {error}", file.path));
        trust::check_listed(&index, &file.path, &bytes).map_err(fail)?;
        let entry = trusted.verify_entry(&bytes, &signature).map_err(fail)?;
        if file.path != trust::entry_path(&entry.name, &entry.version) {
            return Err(invalid(&format!("{}: entry is not at its own path", file.path)).into());
        }
        let developer = developers.get(&entry.publisher).ok_or_else(|| {
            invalid(&format!(
                "{}: unknown publisher {}",
                file.path, entry.publisher
            ))
        })?;
        trust::namespace_publisher_key(&entry, developer, covering(&namespaces, &entry.name))
            .map_err(fail)?;
        entries += 1;
    }
    println!(
        "Verified signed registry: root v{} (root key {}), index v{} (expires {}), {} developer key(s), {} namespace(s), {} entr{}",
        trusted.version(),
        trust::fingerprint(&pinned[0]),
        index.version,
        index.expires,
        developers.len(),
        namespaces.len(),
        entries,
        if entries == 1 { "y" } else { "ies" }
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_registry(directory: &Path) {
        fs::create_dir_all(directory.join("keys/developers")).unwrap();
        fs::create_dir_all(directory.join("packages/xila/clock")).unwrap();
        fs::write(
            directory.join("keys/developers/xila.json"),
            r#"{"id":"xila","author":"Xila Project","algorithm":"ed25519","public_key":"6D1cvlGzCAITQrmkWjJgn97DW1s6p3zvDNe8a87pcbc=","openssh":null,"namespaces":["xila"]}"#,
        )
        .unwrap();
        let entry = RegistryEntry {
            schema: Some(xila_package_manifest::REGISTRY_ENTRY_SCHEMA_URL.into()),
            format_version: xila_package_manifest::FORMAT_VERSION,
            name: "xila.clock".into(),
            version: "0.1.0".into(),
            target: "wasm32-wasip1".into(),
            xila_version: xila_package_manifest::XilaVersion::new(0, 1),
            capabilities: vec![],
            display_name: Some("Clock".into()),
            metadata: None,
            publisher: "xila".into(),
            archive: Archive {
                url: "https://xila.example/clock.xpk".into(),
                sha256: "c".repeat(64),
                size: 10,
            },
        };
        fs::write(
            directory.join("packages/xila/clock/0.1.0.json"),
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
        assert!(site.join("packages/xila/clock/0.1.0.json.sig").is_file());
        assert!(site.join("keys/developers/xila.json.sig").is_file());
        verify_signed(&site, &keys.root_public, Some(1_000)).unwrap();
        assert!(verify_signed(&site, &keys.root_public, Some(1_000 + 30 * 86_400)).is_err());
        // The repository key is not the root of trust.
        assert!(verify_signed(&site, &keys.repository_public, None).is_err());

        let entry = site.join("packages/xila/clock/0.1.0.json");
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
        fs::write(site.join("packages/xila/clock/0.2.0.json"), &original).unwrap();
        assert!(verify_signed(&site, &keys.root_public, None).is_err());
        fs::remove_file(site.join("packages/xila/clock/0.2.0.json")).unwrap();
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
    fn native_entries_need_a_developer_key_authorized_for_native() {
        let keys = new_keys();
        let temp = tempfile::tempdir().unwrap();
        let registry = temp.path().join("registry");
        write_registry(&registry);
        let entry_path = registry.join("packages/xila/clock/0.1.0.json");
        let entry = decode_registry_entry(fs::read(&entry_path).unwrap().as_slice()).unwrap();
        let native = RegistryEntry {
            target: "thumbv7em-none-eabi".into(),
            ..entry
        };
        fs::write(&entry_path, encode_registry_entry(&native).unwrap()).unwrap();

        // Without `kinds` a key may publish Wasm only.
        let error = check(&registry, None).unwrap_err().to_string();
        assert!(
            error.contains("not authorized for native packages"),
            "{error}"
        );

        let key_path = registry.join("keys/developers/xila.json");
        let key = fs::read_to_string(&key_path).unwrap();
        fs::write(
            &key_path,
            key.replace(
                r#""namespaces":["xila"]"#,
                r#""namespaces":["xila"],"kinds":["wasm"]"#,
            ),
        )
        .unwrap();
        assert!(check(&registry, None).is_err());

        fs::write(
            &key_path,
            key.replace(
                r#""namespaces":["xila"]"#,
                r#""namespaces":["xila"],"kinds":["wasm","native"]"#,
            ),
        )
        .unwrap();
        check(&registry, None).unwrap();

        // Signed metadata is verified with the same rule: a key without the
        // native grant cannot be used to sign or verify a native entry.
        fs::write(&key_path, &key).unwrap();
        root(
            &keys.root_seed,
            "root-test",
            &keys.repository_public,
            "repository-test",
            1,
            &registry.join(ROOT_PATH),
        )
        .unwrap();
        let denied = temp.path().join("denied");
        let error = sign(
            &registry,
            &keys.root_public,
            &keys.repository_seed,
            &denied,
            Some(1_000),
            30,
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("not authorized for native packages"),
            "{error}"
        );
        let unchecked = temp.path().join("unchecked");
        let error = write_signed_site(
            &registry,
            &keys.root_public,
            &keys.repository_seed,
            &unchecked,
            Some(1_000),
            30,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("may not publish this package"), "{error}");
        fs::write(
            &key_path,
            key.replace(
                r#""namespaces":["xila"]"#,
                r#""namespaces":["xila"],"kinds":["wasm","native"]"#,
            ),
        )
        .unwrap();
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
        verify_signed(&site, &keys.root_public, Some(1_000)).unwrap();
    }

    const NAMESPACE: &str = r#"{"$schema":null,"format_version":1,"namespace":"example.xila","owner":{"kind":"domain","name":"xila.example"},"developer_keys":["xila"]}"#;

    /// A registry with one reverse-DNS entry, `example.xila.weather`, covered
    /// by `namespaces/example.xila.json`.
    fn write_namespaced_registry(directory: &Path) {
        write_registry(directory);
        let legacy = directory.join("packages/xila/clock/0.1.0.json");
        let entry = decode_registry_entry(&fs::read(&legacy).unwrap()).unwrap();
        let weather = RegistryEntry {
            name: "example.xila.weather".into(),
            ..entry
        };
        fs::create_dir_all(directory.join("packages/example/xila/weather")).unwrap();
        fs::write(
            directory.join("packages/example/xila/weather/0.1.0.json"),
            encode_registry_entry(&weather).unwrap(),
        )
        .unwrap();
        fs::create_dir_all(directory.join("namespaces")).unwrap();
        fs::write(directory.join("namespaces/example.xila.json"), NAMESPACE).unwrap();
    }

    fn check_error(registry: &Path) -> String {
        check(registry, None).unwrap_err().to_string()
    }

    #[test]
    fn namespace_files_authorize_reverse_domain_entries() {
        let temp = tempfile::tempdir().unwrap();
        let registry = temp.path().join("registry");
        write_namespaced_registry(&registry);
        check(&registry, None).unwrap();
        let namespace = registry.join("namespaces/example.xila.json");

        // Denied: no namespace file covers the entry.
        fs::remove_file(&namespace).unwrap();
        let error = check_error(&registry);
        assert!(
            error.contains("no namespace file covers example.xila.weather"),
            "{error}"
        );

        // Denied: the namespace file does not list the publisher.
        let alice = registry.join("keys/developers/alice.json");
        fs::write(
            &alice,
            r#"{"id":"alice","author":"Alice","algorithm":"ed25519","public_key":"11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=","openssh":null}"#,
        )
        .unwrap();
        fs::write(&namespace, NAMESPACE.replace(r#"["xila"]"#, r#"["alice"]"#)).unwrap();
        let error = check_error(&registry);
        assert!(
            error.contains("not listed in namespace example.xila"),
            "{error}"
        );

        // Denied: a namespace file listing an unknown key.
        fs::write(
            &namespace,
            NAMESPACE.replace(r#"["xila"]"#, r#"["mallory"]"#),
        )
        .unwrap();
        let error = check_error(&registry);
        assert!(error.contains("unknown developer key mallory"), "{error}");

        // Denied: a file name that is not its namespace, and an owner that
        // does not match the namespace.
        fs::remove_file(&namespace).unwrap();
        fs::write(registry.join("namespaces/example.other.json"), NAMESPACE).unwrap();
        let error = check_error(&registry);
        assert!(
            error.contains("file name must be <namespace>.json"),
            "{error}"
        );
        fs::remove_file(registry.join("namespaces/example.other.json")).unwrap();
        fs::write(
            &namespace,
            NAMESPACE.replace("xila.example", "other.example"),
        )
        .unwrap();
        let error = check_error(&registry);
        assert!(error.contains("invalid namespace file"), "{error}");

        // Denied: overlapping namespace files.
        fs::write(&namespace, NAMESPACE).unwrap();
        fs::write(
            registry.join("namespaces/example.xila.tools.json"),
            NAMESPACE
                .replace(r#""example.xila""#, r#""example.xila.tools""#)
                .replace("xila.example", "tools.xila.example"),
        )
        .unwrap();
        let error = check_error(&registry);
        assert!(error.contains("overlaps namespace example.xila"), "{error}");
        fs::remove_file(registry.join("namespaces/example.xila.tools.json")).unwrap();

        // Denied: a namespace file in a subdirectory.
        fs::create_dir_all(registry.join("namespaces/example")).unwrap();
        let error = check_error(&registry);
        assert!(error.contains("may not be in subdirectories"), "{error}");
        fs::remove_dir(registry.join("namespaces/example")).unwrap();
        check(&registry, None).unwrap();

        // The legacy grant never covers reverse-DNS identifiers: with the
        // namespace file removed, the xila key's ["xila"] is not enough.
        fs::remove_file(&namespace).unwrap();
        assert!(check(&registry, None).is_err());
    }

    #[test]
    fn legacy_entries_need_the_legacy_grant() {
        let temp = tempfile::tempdir().unwrap();
        let registry = temp.path().join("registry");
        write_registry(&registry);
        let key_path = registry.join("keys/developers/xila.json");
        let key = fs::read_to_string(&key_path).unwrap();
        fs::write(&key_path, key.replace(r#","namespaces":["xila"]"#, "")).unwrap();
        let error = check_error(&registry);
        assert!(error.contains("legacy namespace not granted"), "{error}");
        // A namespace file cannot grant the legacy namespace.
        fs::create_dir_all(registry.join("namespaces")).unwrap();
        fs::write(
            registry.join("namespaces/xila.json"),
            NAMESPACE.replace(r#""example.xila""#, r#""xila""#),
        )
        .unwrap();
        let error = check_error(&registry);
        assert!(error.contains("invalid namespace file"), "{error}");
    }

    #[test]
    fn signs_and_verifies_namespace_files() {
        let keys = new_keys();
        let temp = tempfile::tempdir().unwrap();
        let registry = temp.path().join("registry");
        write_namespaced_registry(&registry);
        root(
            &keys.root_seed,
            "root-test",
            &keys.repository_public,
            "repository-test",
            1,
            &registry.join(ROOT_PATH),
        )
        .unwrap();
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
        assert!(site.join("namespaces/example.xila.json.sig").is_file());
        let index = fs::read_to_string(site.join(INDEX_PATH)).unwrap();
        assert!(
            index.contains(r#""path":"namespaces/example.xila.json""#),
            "{index}"
        );
        verify_signed(&site, &keys.root_public, Some(1_000)).unwrap();

        // Denied: a namespace file altered after signing (index hash and
        // signature both break).
        let namespace = site.join("namespaces/example.xila.json");
        let original = fs::read(&namespace).unwrap();
        fs::write(&namespace, NAMESPACE.replace(r#"["xila"]"#, r#"["alice"]"#)).unwrap();
        assert!(verify_signed(&site, &keys.root_public, None).is_err());
        fs::write(&namespace, &original).unwrap();

        // Denied: an entry signature replayed as the namespace signature.
        let signature = signature_path(&namespace);
        let original_signature = fs::read(&signature).unwrap();
        fs::write(
            &signature,
            sign_bytes(
                &crate::key::read_seed(&keys.repository_seed).unwrap(),
                ENTRY_DOMAIN,
                &original,
            )
            .unwrap(),
        )
        .unwrap();
        let error = verify_signed(&site, &keys.root_public, None)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("signature not made by a trusted key"),
            "{error}"
        );
        fs::write(&signature, &original_signature).unwrap();

        // Denied: an unlisted namespace file.
        fs::write(site.join("namespaces/example.other.json"), NAMESPACE).unwrap();
        let error = verify_signed(&site, &keys.root_public, None)
            .unwrap_err()
            .to_string();
        assert!(error.contains("not listed"), "{error}");
        fs::remove_file(site.join("namespaces/example.other.json")).unwrap();
        verify_signed(&site, &keys.root_public, None).unwrap();

        // Signed metadata follows the same rule as `check`: a namespace file
        // that does not list the publisher fails verification even when
        // signed (here bypassing `check`).
        fs::write(
            registry.join("keys/developers/alice.json"),
            r#"{"id":"alice","author":"Alice","algorithm":"ed25519","public_key":"11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=","openssh":null}"#,
        )
        .unwrap();
        fs::write(
            registry.join("namespaces/example.xila.json"),
            NAMESPACE.replace(r#"["xila"]"#, r#"["alice"]"#),
        )
        .unwrap();
        let error = write_signed_site(
            &registry,
            &keys.root_public,
            &keys.repository_seed,
            &temp.path().join("unchecked"),
            Some(1_000),
            30,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("may not publish this package"), "{error}");
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
