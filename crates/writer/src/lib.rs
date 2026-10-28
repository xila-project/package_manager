#![doc = include_str!("../README.md")]

use std::io::{self, Write};
use tar::{Builder, EntryType, Header};
use xila_package_bundle::verify_bytes;
use xila_package_manifest::{MANIFEST_PATH, Manifest, SIGNATURE_PATH};

/// Path and bytes for a single file matching a manifest entry.
pub struct SourceFile<'a> {
    pub path: &'a str,
    pub bytes: &'a [u8],
}

fn bad_input(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn append<W: Write>(archive: &mut Builder<W>, path: &str, bytes: &[u8]) -> io::Result<()> {
    // The shared profile intentionally stays below USTAR's 100-byte name field;
    // append_data may silently create GNU long-name extensions, so use append.
    if !path.is_ascii() || path.len() > 99 || path.is_empty() {
        return Err(bad_input("unsupported USTAR file name"));
    }
    let mut header = Header::new_ustar();
    header.set_path(path)?;
    header.set_entry_type(EntryType::Regular);
    header.set_size(bytes.len() as u64);
    header.set_mode(0o644);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_cksum();
    archive.append(&header, bytes)
}

/// Build a development package. A signature is optional ONLY for unsigned
/// development inspection; untrusted packages must never be installed.
///
/// The caller signs the exact JSON output from xila_package_manifest::encode after
/// applying the domain-separated message from signed_message_into. This writer
/// does not possess private keys and does not silently create signatures.
pub fn write_package<W: Write>(
    output: W,
    manifest: &Manifest,
    payloads: &[SourceFile<'_>],
    signature: Option<&[u8; 64]>,
) -> io::Result<()> {
    let json =
        xila_package_manifest::encode(manifest).map_err(|_| bad_input("invalid manifest"))?;
    if payloads.len() != manifest.files.len() {
        return Err(bad_input("incorrect file count"));
    }
    for (source, declared) in payloads.iter().zip(manifest.files.iter()) {
        if source.path != declared.path || source.bytes.len() as u64 != declared.size {
            return Err(bad_input("file inventory or size mismatch"));
        }
        if !source.path.is_ascii() || source.path.len() > 99 {
            return Err(bad_input("file path does not fit USTAR"));
        }
        verify_bytes(declared, source.bytes)
            .map_err(|_| bad_input("incorrect file size or digest"))?;
    }
    let mut archive = Builder::new(output);
    append(&mut archive, MANIFEST_PATH, json.as_bytes())?;
    if let Some(signature) = signature {
        append(&mut archive, SIGNATURE_PATH, signature)?;
    }
    for source in payloads {
        append(&mut archive, source.path, source.bytes)?;
    }
    archive.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use xila_package_manifest::{Manifest, ManifestFile};

    fn fixture() -> Manifest {
        Manifest {
            schema: Some(xila_package_manifest::SCHEMA_URL.into()),
            format_version: xila_package_manifest::FORMAT_VERSION,
            name: "xila.calculator".into(),
            version: "1.0.0".into(),
            target: "wasm32-wasip1".into(),
            minimum_xila_abi: 1,
            capabilities: vec![],
            files: vec![ManifestFile {
                path: "bin/calculator.wasm".into(),
                size: 3,
                sha256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".into(),
            }],
            application: None,
        }
    }

    #[test]
    fn round_trip_between_writer_and_reader() {
        let mut output = vec![];
        let file = SourceFile {
            path: "bin/calculator.wasm",
            bytes: b"abc",
        };
        write_package(&mut output, &fixture(), &[file], None).unwrap();
        let inspected = xila_package_reader::inspect_unsigned(&output).unwrap();
        assert_eq!(inspected, fixture());
    }

    #[test]
    fn reproducible_and_rejects_corruption() {
        let file = SourceFile {
            path: "bin/calculator.wasm",
            bytes: b"abc",
        };
        let mut first = vec![];
        let mut second = vec![];
        write_package(
            &mut first,
            &fixture(),
            &[SourceFile {
                path: file.path,
                bytes: file.bytes,
            }],
            None,
        )
        .unwrap();
        write_package(&mut second, &fixture(), &[file], None).unwrap();
        assert_eq!(first, second);
        assert!(
            write_package(
                vec![],
                &fixture(),
                &[SourceFile {
                    path: "bin/calculator.wasm",
                    bytes: b"abd"
                }],
                None
            )
            .is_err()
        );
        let offset = first
            .windows(3)
            .position(|window| window == b"abc")
            .unwrap();
        first[offset] ^= 1; // mutate the actual file payload
        assert!(xila_package_reader::inspect_unsigned(&first).is_err());
    }
}
