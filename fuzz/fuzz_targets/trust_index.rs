#![no_main]

use libfuzzer_sys::fuzz_target;
use xila_package_manifest as manifest;
use xila_package_manifest::trust::valid_listed_path;
use xila_package_manifest::{decode_index, index_packages, index_versions};

// index.json parsing and its round-trip, plus the lookups run on a decoded
// index (binary search, listed-path validation, package and version listing).
fuzz_target!(|data: &[u8]| {
    if let Ok(text) = core::str::from_utf8(data) {
        let _ = valid_listed_path(text);
    }
    if let Ok(index) = decode_index(data) {
        if let Ok(encoded) = manifest::encode_index(&index) {
            assert_eq!(
                decode_index(encoded.as_bytes()).as_ref(),
                Ok(&index),
                "index round-trip mismatch"
            );
        }
        for file in &index.files {
            assert_eq!(index.file(&file.path), Some(file));
            assert!(valid_listed_path(&file.path));
        }
        assert!(index.file("root.json").is_none());
        let _ = index_packages(&index);
        let _ = index_versions(&index, "xila.clock", true);
        let _ = index_versions(&index, "xila.clock", false);
    }
});
