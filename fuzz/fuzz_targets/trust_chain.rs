#![no_main]

use libfuzzer_sys::fuzz_target;
use xila_package_manager::trust::{
    TrustedRoot, check_listed, namespace_publisher_key, publisher_key,
};
use xila_package_manifest::index_packages;

// Registry trust chain on untrusted bytes. The input is NUL-separated
// segments: root, root signature, index, index signature, entry, entry
// signature, developer key, key signature, namespace, namespace signature.
fuzz_target!(|data: &[u8]| {
    let segments: Vec<&[u8]> = data.split(|&byte| byte == 0).collect();
    let Ok(
        [
            root,
            root_signature,
            index,
            index_signature,
            entry,
            entry_signature,
            developer_key,
            key_signature,
            namespace,
            namespace_signature,
        ],
    ) = <[&[u8]; 10]>::try_from(segments.as_slice())
    else {
        return;
    };

    let signing = ed25519_dalek::SigningKey::from_bytes(&[7_u8; 32]);
    let pinned_bytes = signing.verifying_key().to_bytes();

    if let Ok((trusted, _)) = TrustedRoot::first_use(root, root_signature) {
        // A repeated root is a rollback, never a crash.
        let _ = trusted.update(root, root_signature);

        if let Ok(index) = trusted.verify_index(index, index_signature, 0, None) {
            let _ = check_listed(&index, "root.json", root);
            let _ = index_packages(&index);
        }

        if let (Ok(entry), Ok(key)) = (
            trusted.verify_entry(entry, entry_signature),
            trusted.verify_developer_key(developer_key, key_signature),
        ) {
            let _ = publisher_key(&entry, &key);
            if let Ok(namespace) = trusted.verify_namespace(namespace, namespace_signature) {
                let _ = namespace_publisher_key(&entry, &key, Some(&namespace));
                let _ = namespace_publisher_key(&entry, &key, None);
            }
        }
        let _ = trusted.verify_developer_key(developer_key, key_signature);
        let _ = trusted.verify_namespace(namespace, namespace_signature);
    }

    let _ = TrustedRoot::bootstrap(root, root_signature, &[pinned_bytes], 0);
});
