#![doc = include_str!("../README.md")]
mod bundle;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InventoryMode {
    Legacy,
    Developer,
    Bundle,
}
use getargs_derive::{GetArgs, Subcommand};
use std::{
    env,
    fmt::Write as _,
    fs::{self, File},
    io::{self, Read},
    path::{Path, PathBuf},
};
use xila_package_manifest::{Application, FORMAT_VERSION, Manifest, ManifestFile};
use xila_package_verification::Sha256Verifier;
use xila_package_writer::SourceFile;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn hash_file(path: &Path) -> Result<(u64, String)> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256Verifier::new();
    let mut total = 0_u64;
    let mut buffer = [0u8; 8192];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| invalid("file too large"))?;
        hasher
            .update(&buffer[..read])
            .map_err(|_| invalid("hash failure"))?;
    }
    let mut hex = String::with_capacity(64);
    for b in hasher
        .finalize()
        .map_err(|_| invalid("hash finalization failure"))?
    {
        write!(&mut hex, "{b:02x}")?;
    }
    Ok((total, hex))
}

fn collect_files(
    root: &Path,
    current: &Path,
    output: &mut Vec<ManifestFile>,
    mode: InventoryMode,
) -> Result<()> {
    let mut paths = fs::read_dir(current)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<io::Result<Vec<_>>>()?;
    paths.sort();
    for path in paths {
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            return Err(invalid("symbolic links are not allowed").into());
        }
        if current == root {
            if path.file_name().is_some_and(|name| name == ".xila") {
                if mode == InventoryMode::Bundle && metadata.is_dir() {
                    continue;
                }
                return Err(invalid(".xila is reserved for bundle metadata").into());
            }
            if mode == InventoryMode::Developer
                && path.file_name().is_some_and(|name| name == xila_package_manifest::DEVELOPER_MANIFEST_FILENAME)
            {
                if !metadata.is_file() {
                    return Err(invalid("developer manifest is not a regular file").into());
                }
                continue;
            }
        }
        if metadata.is_dir() {
            collect_files(root, &path, output, mode)?;
            continue;
        }
        if !metadata.is_file() {
            return Err(invalid("special files are not allowed").into());
        }
        let relative = path.strip_prefix(root)?;
        let mut components = Vec::new();
        for component in relative.iter() {
            components.push(component.to_str().ok_or_else(|| invalid("non-UTF8 path"))?);
        }
        let name = components.join("/");
        xila_package_manifest::validate_path(&name).map_err(|_| invalid("unsafe file path"))?;
        let (size, sha256) = hash_file(&path)?;
        output.push(ManifestFile {
            path: name,
            size,
            sha256,
        });
        if output.len() > xila_package_manifest::MAX_FILES {
            return Err(invalid("too many files").into());
        }
    }
    Ok(())
}

fn write_manifest(output: &Path, manifest: &Manifest) -> Result<()> {
    let text = xila_package_manifest::encode(manifest)
        .map_err(|_| invalid("manifest failed validation"))?;
    fs::write(output, text)?;
    Ok(())
}

fn generate(
    source: &Path,
    output: &Path,
    name: &str,
    version: &str,
    target: &str,
    minimum_xila_abi: u32,
) -> Result<()> {
    let root = source.canonicalize()?;
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    if parent.canonicalize()?.starts_with(&root) {
        return Err(invalid("output manifest must reside outside the source directory").into());
    }
    let mut files = Vec::new();
    collect_files(&root, &root, &mut files, InventoryMode::Legacy)?;
    files.sort_by(|a, b| a.path.cmp(&b.path));
    let manifest = Manifest {
        schema: Some(xila_package_manifest::SCHEMA_URL.into()),
        format_version: FORMAT_VERSION,
        name: name.into(),
        version: version.into(),
        target: target.into(),
        minimum_xila_abi,
        capabilities: vec![],
        files,
        application: None,
    };
    write_manifest(output, &manifest)
}

fn update(source: &Path, manifest_path: &Path) -> Result<()> {
    let bytes = fs::read(manifest_path)?;
    let mut manifest =
        xila_package_manifest::decode(&bytes).map_err(|_| invalid("invalid existing manifest"))?;
    let root = source.canonicalize()?;
    if manifest_path.canonicalize()?.starts_with(&root) {
        return Err(invalid("manifest must reside outside the source directory").into());
    }
    let mut files = Vec::new();
    collect_files(&root, &root, &mut files, InventoryMode::Legacy)?;
    files.sort_by(|a, b| a.path.cmp(&b.path));
    manifest.files = files;
    write_manifest(manifest_path, &manifest)
}

/// Mark an existing package as an application without duplicating its
/// identity/version/ABI and without executing its code.
fn set_application(
    manifest_path: &Path,
    entrypoint: &str,
    display_name: &str,
    icon: Option<&str>,
    hidden: bool,
) -> Result<()> {
    let bytes = fs::read(manifest_path)?;
    let mut manifest =
        xila_package_manifest::decode(&bytes).map_err(|_| invalid("invalid existing manifest"))?;
    // Adding application metadata changes the exact bytes. Any detached
    // signature must be produced *after* this operation.
    manifest.application = Some(Application {
        entrypoint: entrypoint.into(),
        display_name: display_name.into(),
        icon: icon.unwrap_or_default().into(),
        show_in_launcher: !hidden,
    });
    write_manifest(manifest_path, &manifest)
}

fn safe_file(root: &Path, path: &str) -> Result<PathBuf> {
    xila_package_manifest::validate_path(path).map_err(|_| invalid("unsafe file path"))?;
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

fn pack(
    source: &Path,
    manifest_path: &Path,
    output: &Path,
    signature: Option<&Path>,
) -> Result<()> {
    let root = source.canonicalize()?;
    let raw_manifest = fs::read(manifest_path)?;
    let manifest =
        xila_package_manifest::decode(&raw_manifest).map_err(|_| invalid("invalid manifest"))?;
    if signature.is_some() {
        let canonical =
            xila_package_manifest::encode(&manifest).map_err(|_| invalid("invalid manifest"))?;
        if canonical.as_bytes() != raw_manifest {
            return Err(invalid("cannot attach a signature to a noncanonical manifest").into());
        }
    }
    let mut bytes = Vec::new();
    for declared in &manifest.files {
        bytes.push(fs::read(safe_file(&root, &declared.path)?)?);
    }
    let sources: Vec<_> = manifest
        .files
        .iter()
        .zip(bytes.iter())
        .map(|(declared, bytes)| SourceFile {
            path: &declared.path,
            bytes,
        })
        .collect();

    let signature = if let Some(path) = signature {
        let signature = fs::read(path)?;
        let signature: [u8; 64] = signature
            .try_into()
            .map_err(|_| invalid("signature must be exactly 64 bytes"))?;
        Some(signature)
    } else {
        None
    };

    // Write to a sibling temporary file first; do not leave a partial archive.
    let temporary = output.with_extension("xpk.tmp");
    let operation = (|| -> Result<()> {
        let file = File::create(&temporary)?;
        xila_package_writer::write_package(file, &manifest, &sources, signature.as_ref())?;
        // The reader is a second implementation of framing/inventory checks.
        let archive = fs::read(&temporary)?;
        xila_package_reader::inspect_unsigned(&archive)
            .map_err(|_| invalid("archive verification failed"))?;
        fs::rename(&temporary, output)?;
        Ok(())
    })();
    if operation.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    operation
}

/// Build and inspect packages for Xila.
#[derive(Debug, GetArgs)]
#[command(name = "xila-package", version)]
struct Cli<'a> {
    #[command(subcommand)]
    command: Command<'a>,
}

#[derive(Debug, Subcommand)]
enum Command<'a> {
    /// Generate or update a package manifest.
    Manifest(ManifestCommand<'a>),
    /// Build an unpacked, self-contained application bundle or archive it.
    Bundle(BundleCommand<'a>),
    /// Create an archive from the validated manifest and source files.
    Pack {
        /// Directory containing the application payload files.
        directory: &'a str,
        /// Path to the manifest JSON file.
        manifest: &'a str,
        /// Destination archive path.
        output: &'a str,
        /// Optional 64-byte Ed25519 signature prepared outside this tool.
        signature: Option<&'a str>,
    },
}

#[derive(Debug, GetArgs)]
struct BundleCommand<'a> {
    #[command(subcommand)]
    command: BundleOperation<'a>,
}

#[derive(Debug, Subcommand)]
enum BundleOperation<'a> {
    /// Construct a directory bundle containing manifest, executables and resources.
    Build {
        /// Directory containing payload files.
        directory: &'a str,
        /// Canonical manifest JSON produced by 'manifest generate/update'.
        manifest: &'a str,
        /// Output self-contained bundle directory (for example Weather.app).
        output: &'a str,
        /// Optional externally generated detached 64-byte Ed25519 signature.
        signature: Option<&'a str>,
    },
    /// Create a deterministic .xpk archive from an already-built directory bundle.
    Archive {
        /// Path to the self-contained bundle directory.
        directory: &'a str,
        /// Destination .xpk archive.
        output: &'a str,
    },
}

#[derive(Debug, GetArgs)]
struct ManifestCommand<'a> {
    #[command(subcommand)]
    command: ManifestOperation<'a>,
}

#[derive(Debug, Subcommand)]
enum ManifestOperation<'a> {
    /// Generate a manifest for an application directory.
    Generate {
        /// Directory containing payload files.
        directory: &'a str,
        /// Output path for the manifest JSON file.
        manifest: &'a str,
        /// Package identifier, for example xila.calculator.
        name: &'a str,
        /// Package version.
        version: &'a str,
        /// Target architecture.
        target: &'a str,
        /// Minimum Xila runtime application binary interface version.
        minimum_xila_abi: u32,
    },
    /// Add application metadata to an existing manifest without code execution.
    Application {
        /// Manifest JSON file (upgraded to v2).
        manifest: &'a str,
        /// Bundle-relative executable, or trusted preinstalled system path.
        entrypoint: &'a str,
        /// Fallback application name shown to users.
        display_name: &'a str,
        /// Bundle-relative icon from the manifest file inventory.
        #[arg(long)]
        icon: Option<&'a str>,
        /// Hide from the launcher without making it unlaunchable.
        #[arg(long)]
        hidden: bool,
    },
    /// Refresh file sizes and hashes in an existing manifest.
    Update {
        /// Directory containing payload files.
        directory: &'a str,
        /// Path of the manifest to update.
        manifest: &'a str,
    },
}

fn run() -> Result<()> {
    let args: Vec<String> = env::args().skip(1).collect();
    let cli = match Cli::from_args(args.iter().map(String::as_str)) {
        Ok(cli) => cli,
        Err(error) if error.is_help() || error.is_version() => {
            println!("{error}");
            return Ok(());
        }
        Err(error) => return Err(invalid(&error.to_string()).into()),
    };
    match cli.command {
        Command::Manifest(ManifestCommand { command }) => match command {
            ManifestOperation::Generate {
                directory,
                manifest,
                name,
                version,
                target,
                minimum_xila_abi,
            } => generate(
                Path::new(directory),
                Path::new(manifest),
                name,
                version,
                target,
                minimum_xila_abi,
            ),
            ManifestOperation::Update {
                directory,
                manifest,
            } => update(Path::new(directory), Path::new(manifest)),
            ManifestOperation::Application {
                manifest,
                entrypoint,
                display_name,
                icon,
                hidden,
            } => set_application(Path::new(manifest), entrypoint, display_name, icon, hidden),
        },
        Command::Bundle(BundleCommand { command }) => match command {
            BundleOperation::Build {
                directory,
                manifest,
                output,
                signature,
            } => bundle::build(
                Path::new(directory),
                Path::new(manifest),
                Path::new(output),
                signature.map(Path::new),
            ),
            BundleOperation::Archive { directory, output } => {
                bundle::archive(Path::new(directory), Path::new(output))
            }
        },
        Command::Pack {
            directory,
            manifest,
            output,
            signature,
        } => pack(
            Path::new(directory),
            Path::new(manifest),
            Path::new(output),
            signature.map(Path::new),
        ),
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("xila-package: {error}");
        std::process::exit(1);
    }
}
