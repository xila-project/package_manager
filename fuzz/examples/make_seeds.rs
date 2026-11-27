//! Generate the seed archives for the `archive` and `archive_roundtrip`
//! fuzz targets: a signed package, an unsigned one and a few damaged
//! variants. Usage: `cargo run --release --example make_seeds -- <corpus-root>`.

use std::path::Path;

use ed25519_dalek::{Signer, SigningKey};
use xila_package_bundle::{FileHasher, signing_message};
use xila_package_manifest::{Application, FORMAT_VERSION, Manifest, SCHEMA_URL, XilaVersion};
use xila_package_verification::PublicKey;
use xila_package_writer::{SourceFile, write_package};

fn manifest() -> Manifest {
    let wasm = b"\0asm\x01\0\0\0seed".to_vec();
    let icon = b"seed-icon".to_vec();
    let mut executable = FileHasher::new("executables/seed.wasm").unwrap();
    executable.update(&wasm).unwrap();
    let mut resource = FileHasher::new("resources/icon.png").unwrap();
    resource.update(&icon).unwrap();
    Manifest {
        schema: Some(SCHEMA_URL.into()),
        format_version: FORMAT_VERSION,
        name: "example.xila.seed".into(),
        version: "0.1.0".into(),
        target: "wasm32-wasip1".into(),
        xila_version: XilaVersion::new(0, 1),
        capabilities: vec![],
        files: vec![executable.finish().unwrap(), resource.finish().unwrap()],
        application: Some(Application {
            entrypoint: "executables/seed.wasm".into(),
            display_name: "Seed".into(),
            icon: "resources/icon.png".into(),
            show_in_launcher: true,
        }),
        metadata: None,
    }
}

fn write(directory: &Path, name: &str, bytes: &[u8]) {
    std::fs::create_dir_all(directory).unwrap();
    std::fs::write(directory.join(name), bytes).unwrap();
}

fn main() {
    let corpus_root = std::env::args()
        .nth(1)
        .expect("usage: make_seeds <corpus-root>");
    let manifest = manifest();
    let signing = SigningKey::from_bytes(&[7_u8; 32]);
    let public = PublicKey::from_bytes(&signing.verifying_key().to_bytes()).unwrap();
    let json = xila_package_manifest::encode(&manifest).unwrap();
    let signature = signing
        .sign(&signing_message(json.as_bytes()).unwrap())
        .to_bytes();
    let wasm = b"\0asm\x01\0\0\0seed";
    let icon = b"seed-icon";
    let sources = [
        SourceFile {
            path: "executables/seed.wasm",
            bytes: wasm,
        },
        SourceFile {
            path: "resources/icon.png",
            bytes: icon,
        },
    ];

    let mut signed = Vec::new();
    write_package(&mut signed, &manifest, &sources, Some(&signature)).unwrap();
    let mut unsigned = Vec::new();
    write_package(&mut unsigned, &manifest, &sources, None).unwrap();

    let mut bad_signature = signed.clone();
    let signature_block = 1 + json.len().div_ceil(512) + 1;
    bad_signature[signature_block * 512] ^= 0xff;
    let truncated = signed[..signed.len() - 512].to_vec();
    let mut padded = signed.clone();
    padded.extend_from_slice(&[0xff; 512]);

    for target in ["archive", "archive_roundtrip"] {
        let directory = Path::new(&corpus_root).join(target);
        write(&directory, "signed.xpk", &signed);
        write(&directory, "unsigned.xpk", &unsigned);
        write(&directory, "bad-signature.xpk", &bad_signature);
        write(&directory, "truncated.xpk", &truncated);
        write(&directory, "padded.xpk", &padded);
    }
    let mut fingerprint = String::new();
    for byte in signing.verifying_key().to_bytes() {
        fingerprint.push_str(&format!("{byte:02x}"));
    }
    println!(
        "wrote seed archives under {corpus_root} (key {})",
        &fingerprint[..16]
    );
    let _ = public;
}
