#![no_main]

use libfuzzer_sys::fuzz_target;
use xila_package_bundle::{FileHasher, Inventory, decode_sha256, encode_sha256, verify_bytes};

// File inventory: chunked file hashing with fuzzed chunk boundaries, the
// inventory accumulator and content verification against declared entries.
fuzz_target!(|data: &[u8]| {
    let split = data
        .iter()
        .position(|&byte| byte == b'\n')
        .unwrap_or(data.len());
    let (path_bytes, rest) = data.split_at(split);
    let Ok(path) = core::str::from_utf8(path_bytes) else {
        return;
    };
    let Ok(mut hasher) = FileHasher::new(path) else {
        return;
    };
    if rest.is_empty() {
        return;
    }
    let chunk_size = usize::from(rest[0] % 255) + 1;
    let payload = &rest[1..];
    for chunk in payload.chunks(chunk_size) {
        let _ = hasher.update(chunk);
    }
    let Ok(file) = hasher.finish() else {
        return;
    };

    // The declared entry verifies against exactly its own bytes.
    assert_eq!(verify_bytes(&file, payload), Ok(()));
    // A single flipped byte must not verify.
    if !payload.is_empty() {
        let mut altered = payload.to_vec();
        altered[0] ^= 1;
        assert!(verify_bytes(&file, &altered).is_err());
    }

    let mut inventory = Inventory::new();
    assert!(inventory.push(file.clone()).is_ok());
    assert!(
        inventory.push(file.clone()).is_err(),
        "duplicate path accepted"
    );
    let files = inventory.into_files();
    assert_eq!(files.len(), 1);

    // Digest encoding round-trips through the strict decoder.
    if let Ok(digest) = file.digest() {
        assert_eq!(
            decode_sha256(&encode_sha256(&digest)).as_ref(),
            Ok(&digest),
            "digest round-trip mismatch"
        );
    }
});
