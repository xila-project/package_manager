#![no_main]

use libfuzzer_sys::fuzz_target;
use xila_package_manifest as manifest;
use xila_package_manifest::decode_namespace;

// Namespace file parsing (namespaces/<namespace>.json) and its round-trip.
fuzz_target!(|data: &[u8]| {
    if let Ok(namespace) = decode_namespace(data) {
        if let Ok(encoded) = manifest::encode_namespace(&namespace) {
            assert_eq!(
                decode_namespace(encoded.as_bytes()).as_ref(),
                Ok(&namespace),
                "namespace round-trip mismatch"
            );
        }
        for (publisher, identifier) in [
            ("alice", "example.xila.weather"),
            ("mallory", "example.xila.weather"),
            ("alice", "example.other.weather"),
            ("alice", "xila.clock"),
        ] {
            let _ = namespace.authorizes(publisher, identifier);
        }
    }
});
