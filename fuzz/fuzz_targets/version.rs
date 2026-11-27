#![no_main]

use libfuzzer_sys::fuzz_target;
use xila_package_manager::planner::VersionRequirement;
use xila_package_manifest as manifest;
use xila_package_manifest::metadata::is_https_url;
use xila_package_manifest::{
    SemanticVersion, XilaVersion, compatible, is_legacy_identifier, namespace_covers,
    namespace_paths, target_compatible, valid_identifier,
};

// Version and identifier parsing: XilaVersion, SemanticVersion ordering,
// VersionRequirement, identifiers, namespaces, targets and URL checks.
fuzz_target!(|data: &[u8]| {
    let Ok(text) = core::str::from_utf8(data) else {
        return;
    };

    if let Ok(version) = text.parse::<XilaVersion>() {
        assert_eq!(
            version.to_string().parse::<XilaVersion>().as_ref(),
            Ok(&version),
            "xila version round-trip mismatch"
        );
        let _ = compatible(version, XilaVersion::new(0, 1));
        let _ = compatible(XilaVersion::new(1, 3), version);
    }

    if let Some((first, second)) = text.split_once('\n') {
        if let (Some(a), Some(b)) = (
            SemanticVersion::parse(first),
            SemanticVersion::parse(second),
        ) {
            // Ordering is antisymmetric.
            assert_eq!(b.cmp(&a), a.cmp(&b).reverse());
            assert_eq!(a.partial_cmp(&b), Some(a.cmp(&b)));
        }
    }

    if let Ok(requirement) = text.parse::<VersionRequirement>() {
        assert_eq!(
            requirement
                .to_string()
                .parse::<VersionRequirement>()
                .as_ref(),
            Ok(&requirement),
            "version requirement round-trip mismatch"
        );
        for version in ["1.2.3", "0.0.3", "2.0.0", "1.0.0-rc.1", "nightly"] {
            let _ = requirement.matches(version);
        }
    }

    let _ = valid_identifier(text);
    let _ = is_legacy_identifier(text);
    let _ = manifest::identifier_namespace(text);
    let _ = namespace_covers(text, "example.xila");
    let _ = namespace_paths(text);
    let _ = target_compatible(text, "wasm32-wasip1");
    let _ = target_compatible("riscv32imc-unknown-none-elf", text);
    let _ = is_https_url(text);
});
