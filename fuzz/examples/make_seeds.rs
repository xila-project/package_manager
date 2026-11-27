//! Generate the seed corpus for the fuzz targets: a signed package, an
//! unsigned one and a few damaged variants for the archive targets, plus a
//! fully signed trust-chain document for the trust_chain target.
//! Usage: `cargo run --release --example make_seeds -- <corpus-root>`.

use std::path::Path;

use ed25519_dalek::{Signer, SigningKey};
use xila_package_bundle::{FileHasher, encode_sha256, signing_message};
use xila_package_manifest::{
    Application, Archive, DEVELOPER_KEY_DOMAIN, DEVELOPER_KEY_SCHEMA_URL, DeveloperKey,
    ENTRY_DOMAIN, FORMAT_VERSION, INDEX_DOMAIN, INDEX_SCHEMA_URL, Index, IndexFile, Manifest,
    NAMESPACE_DOMAIN, NAMESPACE_FORMAT_VERSION, NAMESPACE_SCHEMA_URL, NamedKey, Namespace,
    NamespaceOwner, REGISTRY_ENTRY_SCHEMA_URL, REGISTRY_FORMAT_VERSION, ROOT_DOMAIN,
    ROOT_SCHEMA_URL, RegistryEntry, Root, SCHEMA_URL, TRUST_FORMAT_VERSION, XilaVersion,
    encode_index, encode_namespace, encode_registry_entry, encode_root, signed_message,
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

/// Canonical base64 (with padding) of a 32-byte key, as used in key files.
fn base64_key(bytes: &[u8; 32]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(44);
    for chunk in bytes.chunks(3) {
        let mut block = [0_u8; 3];
        block[..chunk.len()].copy_from_slice(chunk);
        let value = u32::from_be_bytes([0, block[0], block[1], block[2]]);
        output.push(TABLE[(value >> 18) as usize & 63] as char);
        output.push(TABLE[(value >> 12) as usize & 63] as char);
        output.push(if chunk.len() > 1 {
            TABLE[(value >> 6) as usize & 63] as char
        } else {
            '='
        });
        output.push(if chunk.len() > 2 {
            TABLE[value as usize & 63] as char
        } else {
            '='
        });
    }
    output
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256Verifier::new();
    hasher.update(bytes).unwrap();
    encode_sha256(&hasher.finalize().unwrap())
}

/// A complete, correctly signed trust chain as one NUL-separated document:
/// root, root signature, index, index signature, entry, entry signature,
/// developer key, key signature, namespace, namespace signature.
fn trust_chain_seed() -> Vec<u8> {
    let root_key = SigningKey::from_bytes(&[1_u8; 32]);
    let repository_key = SigningKey::from_bytes(&[2_u8; 32]);
    let developer_key = SigningKey::from_bytes(&[3_u8; 32]);
    let sign = |key: &SigningKey, domain: &[u8], bytes: &[u8]| {
        key.sign(&signed_message(domain, bytes).unwrap()).to_bytes()
    };

    let root = Root {
        schema: Some(ROOT_SCHEMA_URL.into()),
        format_version: TRUST_FORMAT_VERSION,
        version: 1,
        root_keys: vec![NamedKey {
            id: "root-next".into(),
            public_key: base64_key(&root_key.verifying_key().to_bytes()),
        }],
        repository_keys: vec![NamedKey {
            id: "repository".into(),
            public_key: base64_key(&repository_key.verifying_key().to_bytes()),
        }],
    };
    let root_bytes = encode_root(&root).unwrap();
    let root_signature = sign(&root_key, ROOT_DOMAIN, root_bytes.as_bytes());

    let developer = DeveloperKey {
        schema: Some(DEVELOPER_KEY_SCHEMA_URL.into()),
        id: "xila".into(),
        author: "Xila Project".into(),
        algorithm: "ed25519".into(),
        public_key: base64_key(&developer_key.verifying_key().to_bytes()),
        openssh: None,
        namespaces: Some(vec!["xila".into()]),
        kinds: Some(vec!["wasm".into(), "native".into()]),
    };
    developer.validate().unwrap();
    let developer_bytes = miniserde::json::to_string(&developer);
    let developer_signature = sign(
        &repository_key,
        DEVELOPER_KEY_DOMAIN,
        developer_bytes.as_bytes(),
    );

    let namespace = Namespace {
        schema: Some(NAMESPACE_SCHEMA_URL.into()),
        format_version: NAMESPACE_FORMAT_VERSION,
        namespace: "example.xila".into(),
        owner: NamespaceOwner {
            kind: "domain".into(),
            name: "xila.example".into(),
        },
        developer_keys: vec!["xila".into()],
    };
    let namespace_bytes = encode_namespace(&namespace).unwrap();
    let namespace_signature = sign(
        &repository_key,
        NAMESPACE_DOMAIN,
        namespace_bytes.as_bytes(),
    );

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
        publisher: "xila".into(),
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
        replacements: None,
        schema: Some(INDEX_SCHEMA_URL.into()),
        format_version: TRUST_FORMAT_VERSION,
        version: 1_800_000_000,
        expires: 1_802_592_000,
        files: vec![
            listed("keys/developers/xila.json", &developer_bytes),
            listed("namespaces/example.xila.json", &namespace_bytes),
            listed("packages/example/xila/seed/0.1.0.json", &entry_bytes),
        ],
    };
    let index_bytes = encode_index(&index).unwrap();
    let index_signature = sign(&repository_key, INDEX_DOMAIN, index_bytes.as_bytes());

    let mut seed = Vec::new();
    for part in [
        root_bytes.into_bytes(),
        root_signature.to_vec(),
        index_bytes.into_bytes(),
        index_signature.to_vec(),
        entry_bytes.into_bytes(),
        entry_signature.to_vec(),
        developer_bytes.into_bytes(),
        developer_signature.to_vec(),
        namespace_bytes.into_bytes(),
        namespace_signature.to_vec(),
    ] {
        seed.extend_from_slice(&part);
        seed.push(0);
    }
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
