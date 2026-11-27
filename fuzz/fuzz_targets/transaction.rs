#![no_main]

use libfuzzer_sys::fuzz_target;
use xila_package_manifest as manifest;
use xila_package_manifest::{
    DOWNLOAD_PREFIX, PREVIOUS_PREFIX, REMOVING_PREFIX, STAGING_PREFIX, decode_transaction,
    is_temporary_entry, is_temporary_name,
};

// Installation transaction journal parsing and its round-trip.
fuzz_target!(|data: &[u8]| {
    if let Ok(text) = core::str::from_utf8(data) {
        let _ = is_temporary_entry(text);
        for prefix in [
            STAGING_PREFIX,
            PREVIOUS_PREFIX,
            REMOVING_PREFIX,
            DOWNLOAD_PREFIX,
        ] {
            let _ = is_temporary_name(text, prefix);
        }
    }
    if let Ok(transaction) = decode_transaction(data) {
        if let Ok(encoded) = manifest::encode_transaction(&transaction) {
            assert_eq!(
                decode_transaction(encoded.as_bytes()).as_ref(),
                Ok(&transaction),
                "transaction round-trip mismatch"
            );
        }
    }
});
