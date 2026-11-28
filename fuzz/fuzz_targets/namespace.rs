#![no_main]

use libfuzzer_sys::fuzz_target;
use xila_package_manifest::{decode_namespace, encode_namespace};

fuzz_target!(|data: &[u8]| {
    if let Ok(claim) = decode_namespace(data) {
        let encoded = encode_namespace(&claim).unwrap();
        assert_eq!(decode_namespace(encoded.as_bytes()).as_ref(), Ok(&claim));
        let identifier = format!("{}.package", claim.namespace);
        let _ = claim.matches_identifier(&identifier);
    }
});
