//! Host-side Xila package authoring tool. Archives are unsigned unless an
//! externally generated 64-byte Ed25519 signature is explicitly supplied.
use std::{
    env, fmt::Write as _, fs::{self, File}, io::{self, Read},
    path::{Path, PathBuf},
};
use package_manifest::{Manifest, ManifestFile, FORMAT_VERSION};
use package_writer::SourceFile;
use verification::Sha256Verifier;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn usage() -> io::Error {
    invalid("Usage:\n  xila-package manifest generate <directory> <manifest.json> <namespace.name> <version> <target> <minimum-xila-abi>\n  xila-package manifest update <directory> <manifest.json>\n  xila-package pack <directory> <manifest.json> <package.xpk> [signature.bin]")
}

fn hash_file(path: &Path) -> Result<(u64, String)> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256Verifier::new();
    let mut total = 0_u64;
    let mut buffer = [0u8; 8192];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 { break; }
        total = total.checked_add(read as u64).ok_or_else(|| invalid("file too large"))?;
        hasher.update(&buffer[..read]).map_err(|_| invalid("hash failure"))?;
    }
    let mut hex = String::with_capacity(64);
    for b in hasher.finalize().map_err(|_| invalid("hash finalization failure"))? {
        write!(&mut hex, "{b:02x}")?;
    }
    Ok((total, hex))
}

fn collect_files(root: &Path, current: &Path, output: &mut Vec<ManifestFile>) -> Result<()> {
    let mut paths = fs::read_dir(current)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<io::Result<Vec<_>>>()?;
    paths.sort();
    for path in paths {
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            return Err(invalid("symbolic links are not allowed").into());
        }
        if metadata.is_dir() {
            collect_files(root, &path, output)?;
            continue;
        }
        if !metadata.is_file() { return Err(invalid("special files are not allowed").into()); }
        let relative = path.strip_prefix(root)?;
        let mut components = Vec::new();
        for component in relative.iter() {
            components.push(component.to_str().ok_or_else(|| invalid("non-UTF8 path"))?);
        }
        let name = components.join("/");
        package_manifest::validate_path(&name).map_err(|_| invalid("unsafe file path"))?;
        let (size, sha256) = hash_file(&path)?;
        output.push(ManifestFile { path: name, size, sha256 });
        if output.len() > package_manifest::MAX_FILES {
            return Err(invalid("too many files").into());
        }
    }
    Ok(())
}

fn write_manifest(output: &Path, manifest: &Manifest) -> Result<()> {
    let text = package_manifest::encode(manifest)
        .map_err(|_| invalid("manifest failed validation"))?;
    fs::write(output, text)?;
    Ok(())
}

fn generate(source: &Path, output: &Path, name: &str, version: &str,
            target: &str, minimum_xila_abi: u32) -> Result<()> {
    let root = source.canonicalize()?;
    if output.exists() && output.canonicalize()?.starts_with(&root) {
        return Err(invalid("output manifest must reside outside the source directory").into());
    }
    let mut files = Vec::new();
    collect_files(&root, &root, &mut files)?;
    files.sort_by(|a, b| a.path.cmp(&b.path));
    let manifest = Manifest {
        format_version: FORMAT_VERSION,
        name: name.into(), version: version.into(), target: target.into(),
        minimum_xila_abi, capabilities: vec![], files,
    };
    write_manifest(output, &manifest)
}

fn update(source: &Path, manifest_path: &Path) -> Result<()> {
    let bytes = fs::read(manifest_path)?;
    let mut manifest = package_manifest::decode(&bytes)
        .map_err(|_| invalid("invalid existing manifest"))?;
    let root = source.canonicalize()?;
    let mut files = Vec::new();
    collect_files(&root, &root, &mut files)?;
    files.sort_by(|a, b| a.path.cmp(&b.path));
    manifest.files = files;
    write_manifest(manifest_path, &manifest)
}

fn safe_file(root: &Path, path: &str) -> Result<PathBuf> {
    package_manifest::validate_path(path).map_err(|_| invalid("unsafe file path"))?;
    let mut current = root.to_path_buf();
    for part in path.split('/') {
        current.push(part);
        let metadata = fs::symlink_metadata(&current)?;
        if metadata.file_type().is_symlink() {
            return Err(invalid("symlink in source path").into());
        }
    }
    if !fs::symlink_metadata(&current)?.is_file() {
        return Err(invalid("expected regular file").into());
    }
    Ok(current)
}

fn pack(source: &Path, manifest_path: &Path, output: &Path, signature: Option<&Path>) -> Result<()> {
    let root = source.canonicalize()?;
    let manifest = package_manifest::decode(&fs::read(manifest_path)?)
        .map_err(|_| invalid("invalid manifest"))?;
    let mut bytes = Vec::new();
    for declared in &manifest.files {
        bytes.push(fs::read(safe_file(&root, &declared.path)?)?);
    }
    let sources: Vec<_> = manifest.files.iter().zip(bytes.iter())
        .map(|(declared, bytes)| SourceFile {
            path: &declared.path, bytes,
        }).collect();

    let signature = if let Some(path) = signature {
        let signature = fs::read(path)?;
        let signature: [u8; 64] = signature.try_into()
            .map_err(|_| invalid("signature must be exactly 64 bytes"))?;
        Some(signature)
    } else { None };

    // Write to a sibling temporary file first; do not leave a partial archive.
    let temporary = output.with_extension("xpk.tmp");
    let operation = (|| -> Result<()> {
        let file = File::create(&temporary)?;
        package_writer::write_package(file, &manifest, &sources, signature.as_ref())?;
        // The reader is a second implementation of framing/inventory checks.
        let archive = fs::read(&temporary)?;
        package_reader::inspect_unsigned(&archive).map_err(|_| invalid("archive verification failed"))?;
        fs::rename(&temporary, output)?;
        Ok(())
    })();
    if operation.is_err() { let _ = fs::remove_file(&temporary); }
    operation
}

fn run() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    match args.as_slice() {
        [_, a, b, directory, output, name, version, target, min]
            if a == "manifest" && b == "generate" =>
        {
            generate(Path::new(directory), Path::new(output), name, version, target, min.parse()?)
        }
        [_, a, b, directory, path] if a == "manifest" && b == "update" =>
            update(Path::new(directory), Path::new(path)),
        [_, a, directory, manifest, output] if a == "pack" =>
            pack(Path::new(directory), Path::new(manifest), Path::new(output), None),
        [_, a, directory, manifest, output, signature] if a == "pack" =>
            pack(Path::new(directory), Path::new(manifest), Path::new(output), Some(Path::new(signature))),
        _ => Err(usage().into()),
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("xila-package: {error}");
        std::process::exit(1);
    }
}
