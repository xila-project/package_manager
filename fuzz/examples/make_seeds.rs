//! Generate the seed corpus for the fuzz targets: a signed package, an
//! unsigned one and a few damaged variants for the archive targets, plus a
//! fully signed trust-chain document for the trust_chain target.
//! Usage: `cargo run --release --example make_seeds -- <corpus-root>`.

use std::path::Path;

use ed25519_dalek::{Signer, SigningKey};
use xila_package_bundle::{FileHasher, encode_sha256, signing_message};
use xila_package_manifest::{
    Application, Archive, ENTRY_DOMAIN, FORMAT_VERSION, INDEX_DOMAIN, INDEX_FORMAT_VERSION,
    INDEX_SCHEMA_URL, Index, IndexFile, Manifest, NamedKey, PackageKey, REGISTRY_ENTRY_SCHEMA_URL,
    REGISTRY_FORMAT_VERSION, ROOT_DOMAIN, ROOT_SCHEMA_URL, ROTATION_DOMAIN,
    ROTATION_FORMAT_VERSION, RegistryEntry, Root, Rotation, SCHEMA_URL, TRUST_FORMAT_VERSION,
    XilaVersion, encode_index, encode_public_key, encode_registry_entry, encode_root,
    encode_rotation, signed_message,
};
use xila_package_verification::{PublicKey, Sha256Verifier};
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

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256Verifier::new();
    hasher.update(bytes).unwrap();
    encode_sha256(&hasher.finalize().unwrap())
}

/// A signed root, index, entry and rotation, with their signatures first.
fn trust_chain_seed() -> Vec<u8> {
    let root_key = SigningKey::from_bytes(&[1_u8; 32]);
    let repository_key = SigningKey::from_bytes(&[2_u8; 32]);
    let package_key = SigningKey::from_bytes(&[3_u8; 32]);
    let sign = |key: &SigningKey, domain: &[u8], bytes: &[u8]| {
        key.sign(&signed_message(domain, bytes).unwrap()).to_bytes()
    };

    let root = Root {
        schema: Some(ROOT_SCHEMA_URL.into()),
        format_version: TRUST_FORMAT_VERSION,
        version: 1,
        root_keys: vec![NamedKey {
            id: "root-next".into(),
            public_key: encode_public_key(&root_key.verifying_key().to_bytes()),
        }],
        repository_keys: vec![NamedKey {
            id: "repository".into(),
            public_key: encode_public_key(&repository_key.verifying_key().to_bytes()),
        }],
    };
    let root_bytes = encode_root(&root).unwrap();
    let root_signature = sign(&root_key, ROOT_DOMAIN, root_bytes.as_bytes());

    let pin = PackageKey::new(1, &package_key.verifying_key().to_bytes()).unwrap();
    let next = SigningKey::from_bytes(&[4_u8; 32]);
    let rotation = Rotation {
        schema: None,
        format_version: ROTATION_FORMAT_VERSION,
        name: "example.xila.seed".into(),
        generation: 2,
        previous_key: pin.public_key.clone(),
        new_key: encode_public_key(&next.verifying_key().to_bytes()),
    };
    let rotation_bytes = encode_rotation(&rotation).unwrap();
    let rotation_signature = sign(&package_key, ROTATION_DOMAIN, rotation_bytes.as_bytes());

    let entry = RegistryEntry {
        schema: Some(REGISTRY_ENTRY_SCHEMA_URL.into()),
        format_version: REGISTRY_FORMAT_VERSION,
        name: "example.xila.seed".into(),
        version: "0.1.0".into(),
        target: "wasm32-wasip1".into(),
        xila_version: XilaVersion::new(0, 1),
        capabilities: vec![],
        display_name: Some("Seed".into()),
        metadata: None,
        package_key: pin,
        archive: Archive {
            url: "https://releases.example.com/example.xila.seed-0.1.0.xpk".into(),
            sha256: "a".repeat(64),
            size: 1024,
        },
    };
    let entry_bytes = encode_registry_entry(&entry).unwrap();
    let entry_signature = sign(&repository_key, ENTRY_DOMAIN, entry_bytes.as_bytes());

    let listed = |path: &str, bytes: &str| IndexFile {
        path: path.into(),
        sha256: sha256_hex(bytes.as_bytes()),
        size: bytes.len() as u64,
    };
    let index = Index {
        schema: Some(INDEX_SCHEMA_URL.into()),
        format_version: INDEX_FORMAT_VERSION,
        version: 1_800_000_000,
        expires: 1_802_592_000,
        files: vec![
            listed("packages/example/xila/seed/0.1.0.json", &entry_bytes),
            listed("rotations/example/xila/seed/2.json", &rotation_bytes),
        ],
    };
    let index_bytes = encode_index(&index).unwrap();
    let index_signature = sign(&repository_key, INDEX_DOMAIN, index_bytes.as_bytes());

    let mut seed = Vec::new();
    for signature in [
        root_signature,
        index_signature,
        entry_signature,
        rotation_signature,
    ] {
        seed.extend_from_slice(&signature);
    }
    for part in [root_bytes, index_bytes, entry_bytes] {
        seed.extend_from_slice(part.as_bytes());
        seed.push(0);
    }
    seed.extend_from_slice(rotation_bytes.as_bytes());
    seed
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
    write(
        &Path::new(&corpus_root).join("trust_chain"),
        "signed-chain",
        &trust_chain_seed(),
    );
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
