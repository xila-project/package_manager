#![no_main]

use ed25519_dalek::{Signer, SigningKey};
use libfuzzer_sys::fuzz_target;
use xila_package_bundle::{FileHasher, Inventory, signing_message};
use xila_package_manifest as manifest;
use xila_package_reader::{StreamingVerifier, inspect_unsigned, verify_signed};
use xila_package_verification::PublicKey;
use xila_package_writer::{SourceFile, write_package};

// Archive round-trip: build a package from the decoded manifest with payload
// bytes derived from the input, then parse it back. Every reader must return
// the same manifest that was written.
fuzz_target!(|data: &[u8]| {
    let Ok(parsed) = manifest::decode(data) else {
        return;
    };
    if parsed.files.is_empty()
        || parsed
            .files
            .iter()
            .any(|file| !file.path.is_ascii() || file.path.len() > 99)
    {
        return;
    }
    let total: u64 = parsed.files.iter().map(|file| file.size).sum();
    if total > 64 * 1024 {
        return;
    }

    let mut owned: Vec<(String, Vec<u8>)> = Vec::new();
    let mut inventory = Inventory::new();
    for file in &parsed.files {
        let size = file.size as usize;
        let mut bytes = Vec::with_capacity(size);
        for index in 0..size {
            bytes.push(if data.is_empty() {
                0
            } else {
                data[index % data.len()]
            });
        }
        let mut hasher = FileHasher::new(&file.path).unwrap();
        hasher.update(&bytes).unwrap();
        inventory.push(hasher.finish().unwrap()).unwrap();
        owned.push((file.path.clone(), bytes));
    }
    let mut rebuilt = parsed.clone();
    rebuilt.files = inventory.into_files();
    manifest::validate(&rebuilt).unwrap();

    let sources: Vec<SourceFile<'_>> = owned
        .iter()
        .map(|(path, bytes)| SourceFile {
            path,
            bytes: bytes.as_slice(),
        })
        .collect();
    let signing = SigningKey::from_bytes(&[7_u8; 32]);
    let public = PublicKey::from_bytes(&signing.verifying_key().to_bytes()).unwrap();
    // A valid compact manifest just under the size limit can grow past it
    // when optional fields are encoded as explicit null, so encoding can
    // fail even though decoding succeeded.
    let Ok(json) = manifest::encode(&rebuilt) else {
        return;
    };
    let signature = signing
        .sign(&signing_message(json.as_bytes()).unwrap())
        .to_bytes();

    let mut archive = Vec::new();
    if write_package(&mut archive, &rebuilt, &sources, Some(&signature)).is_err() {
        return;
    }
    assert_eq!(
        inspect_unsigned(&archive).as_ref(),
        Ok(&rebuilt),
        "unsigned round-trip mismatch"
    );
    assert_eq!(
        verify_signed(&archive, &public).as_ref(),
        Ok(&rebuilt),
        "signed round-trip mismatch"
    );

    let mut verifier = StreamingVerifier::new(Some(&public));
    for block in archive.as_chunks::<512>().0 {
        verifier.push(block).unwrap();
    }
    assert_eq!(
        verifier.finish().as_ref(),
        Ok(&rebuilt),
        "streaming round-trip mismatch"
    );
});
