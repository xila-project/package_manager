//! Stateless Ed25519 key management.
//!
//! Keys are plain files at caller-chosen paths: a raw 32-byte private seed and
//! a raw 32-byte public key, the formats every other `xila-package` command
//! accepts. Nothing is stored or looked up implicitly.

use ed25519_dalek::SigningKey;
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::Path,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub const SEED_LENGTH: usize = 32;

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

/// Create a new file, never replacing an existing one. Private seeds are
/// created owner-only on Unix before any byte is written.
fn create_new(path: &Path, private: bool) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    #[cfg(not(unix))]
    let _ = private;
    options.open(path).map_err(|error| match error.kind() {
        io::ErrorKind::AlreadyExists => io::Error::new(
            error.kind(),
            format!("{} already exists; refusing to overwrite", path.display()),
        ),
        _ => error,
    })
}

fn write_new(path: &Path, bytes: &[u8], private: bool) -> io::Result<()> {
    let mut file = create_new(path, private)?;
    let result = file.write_all(bytes).and_then(|()| file.sync_all());
    if result.is_err() {
        drop(file);
        let _ = fs::remove_file(path);
    }
    result
}

/// Read a raw private seed, refusing symlinks, special files and wrong sizes.
pub fn read_seed(path: &Path) -> Result<SigningKey> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() {
        return Err(invalid("signing key must be a regular file").into());
    }
    let seed: [u8; SEED_LENGTH] = fs::read(path)?
        .try_into()
        .map_err(|_| invalid("signing key must be a raw 32-byte Ed25519 seed"))?;
    Ok(SigningKey::from_bytes(&seed))
}

fn distinct(seed: &Path, public_key: &Path) -> Result<()> {
    if seed == public_key {
        return Err(invalid("seed and public key paths must differ").into());
    }
    Ok(())
}

/// Generate a fresh key pair from the operating system's CSPRNG.
pub fn generate(seed_path: &Path, public_key_path: &Path) -> Result<()> {
    distinct(seed_path, public_key_path)?;
    if fs::symlink_metadata(public_key_path).is_ok() {
        return Err(invalid("public key output already exists").into());
    }
    let mut seed = [0u8; SEED_LENGTH];
    getrandom::fill(&mut seed).map_err(|_| invalid("operating system randomness unavailable"))?;
    let key = SigningKey::from_bytes(&seed);
    write_new(seed_path, &seed, true)?;
    seed.fill(0);
    if let Err(error) = write_new(public_key_path, &key.verifying_key().to_bytes(), false) {
        let _ = fs::remove_file(seed_path);
        return Err(error.into());
    }
    Ok(())
}

/// Derive the raw public key of an existing private seed.
pub fn public(seed_path: &Path, public_key_path: &Path) -> Result<()> {
    distinct(seed_path, public_key_path)?;
    let key = read_seed(seed_path)?;
    write_new(public_key_path, &key.verifying_key().to_bytes(), false)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;

    #[test]
    fn generated_pair_signs_and_verifies() {
        let temp = tempfile::tempdir().unwrap();
        let (seed, public_key) = (temp.path().join("dev.seed"), temp.path().join("dev.pub"));
        generate(&seed, &public_key).unwrap();

        assert_eq!(fs::read(&seed).unwrap().len(), SEED_LENGTH);
        let raw: [u8; 32] = fs::read(&public_key).unwrap().try_into().unwrap();
        let verifier = xila_package_verification::PublicKey::from_bytes(&raw).unwrap();
        let signature = read_seed(&seed).unwrap().sign(b"payload").to_bytes();
        assert!(verifier.verify(b"payload", &signature).is_ok());
        assert!(verifier.verify(b"tampered", &signature).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn seed_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let seed = temp.path().join("dev.seed");
        generate(&seed, &temp.path().join("dev.pub")).unwrap();
        assert_eq!(
            fs::metadata(&seed).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn generation_is_random() {
        let temp = tempfile::tempdir().unwrap();
        for name in ["a", "b"] {
            generate(
                &temp.path().join(name),
                &temp.path().join(format!("{name}.pub")),
            )
            .unwrap();
        }
        assert_ne!(
            fs::read(temp.path().join("a")).unwrap(),
            fs::read(temp.path().join("b")).unwrap()
        );
    }

    #[test]
    fn public_matches_generated_key() {
        let temp = tempfile::tempdir().unwrap();
        let (seed, generated) = (temp.path().join("dev.seed"), temp.path().join("dev.pub"));
        generate(&seed, &generated).unwrap();
        let derived = temp.path().join("derived.pub");
        public(&seed, &derived).unwrap();
        assert_eq!(fs::read(generated).unwrap(), fs::read(derived).unwrap());
    }

    #[test]
    fn never_overwrites_existing_files() {
        let temp = tempfile::tempdir().unwrap();
        let (seed, public_key) = (temp.path().join("dev.seed"), temp.path().join("dev.pub"));
        fs::write(&seed, b"keep").unwrap();
        assert!(generate(&seed, &public_key).is_err());
        assert_eq!(fs::read(&seed).unwrap(), b"keep");
        assert!(!public_key.exists());

        fs::remove_file(&seed).unwrap();
        fs::write(&public_key, b"keep").unwrap();
        assert!(generate(&seed, &public_key).is_err());
        assert!(
            !seed.exists(),
            "seed must not be left without its public key"
        );
        assert_eq!(fs::read(&public_key).unwrap(), b"keep");
    }

    #[test]
    fn rejects_malformed_seeds() {
        let temp = tempfile::tempdir().unwrap();
        let seed = temp.path().join("short.seed");
        fs::write(&seed, [0u8; 31]).unwrap();
        assert!(public(&seed, &temp.path().join("out.pub")).is_err());
        assert!(public(&seed, &seed).is_err());
        assert!(read_seed(temp.path()).is_err());
    }
}
