#![no_main]

use libfuzzer_sys::fuzz_target;
use xila_package_manager::trust::{
    SignedRotation, TrustedRoot, check_listed, package_key, verify_rotation,
};
use xila_package_manifest::index_packages;

// Signatures have a fixed length and can contain any byte. Read them from
// the prefix so a zero in a signature does not truncate the seed.
fuzz_target!(|data: &[u8]| {
    let Some((signatures, documents)) = data.split_at_checked(64 * 4) else {
        return;
    };
    let mut signatures = signatures.chunks_exact(64);
    let mut documents = documents.splitn(4, |&byte| byte == 0);
    let (Some(root), Some(index), Some(entry), Some(rotation)) = (
        documents.next(),
        documents.next(),
        documents.next(),
        documents.next(),
    ) else {
        return;
    };
    let root_signature = signatures.next().unwrap();
    let index_signature = signatures.next().unwrap();
    let entry_signature = signatures.next().unwrap();
    let rotation_signature = signatures.next().unwrap();
    let signing = ed25519_dalek::SigningKey::from_bytes(&[1_u8; 32]);
    let pinned = signing.verifying_key().to_bytes();

    if let Ok(trusted) = TrustedRoot::bootstrap(root, root_signature, &[pinned], 0) {
        let _ = trusted.update(root, root_signature);
        if let Ok(index) = trusted.verify_index(index, index_signature, 0, None) {
            let _ = check_listed(&index, "packages/example/xila/seed/0.1.0.json", entry);
            let _ = index_packages(&index);
        }
        if let Ok(entry) = trusted.verify_entry(entry, entry_signature) {
            let _ = package_key(&entry);
            let _ = verify_rotation(
                &entry.name,
                &entry.package_key,
                SignedRotation {
                    bytes: rotation,
                    signature: rotation_signature,
                },
            );
        }
    }
    let _ = TrustedRoot::first_use(root, root_signature);
});
