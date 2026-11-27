//! Developer (publisher) key files: `keys/developers/<id>.json` in the
//! registry. A developer key signs package manifests; it is not a trust anchor
//! on its own. It may publish an identifier when the namespace file covering
//! that identifier lists it (see [`crate::namespace`]), or, under the legacy
//! rule, a `xila.<name>` identifier when its own `namespaces` lists `xila`.

use alloc::{string::String, vec::Vec};
use miniserde::{Deserialize, Serialize};

use crate::{
    Error, LEGACY_NAMESPACE, MAX_MANIFEST_BYTES, Namespace, is_legacy_identifier,
    registry::valid_publisher,
};

/// Editor-facing JSON Schema; a tooling hint, never a trust anchor.
pub const DEVELOPER_KEY_SCHEMA_URL: &str = "https://raw.githubusercontent.com/xila-project/package_manager/main/schemas/developer-key.schema.json";
/// The only supported signature algorithm.
pub const ED25519: &str = "ed25519";

/// What a package executes, which decides the developer authorization it needs.
///
/// WebAssembly runs confined by the Wasm runtime; native code on a
/// microcontroller without a memory protection unit runs fully trusted, so a
/// developer key must be authorized for it explicitly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PackageKind {
    Wasm,
    Native,
}

impl PackageKind {
    /// The kind of a package target: `wasm32-*` and `wasm64-*` are Wasm and
    /// everything else, including an unknown target, is native so that it
    /// needs the stricter authorization.
    pub fn of_target(target: &str) -> Self {
        if target.starts_with("wasm32-") || target.starts_with("wasm64-") {
            Self::Wasm
        } else {
            Self::Native
        }
    }

    /// The name used in the `kinds` field of a developer key.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Wasm => "wasm",
            Self::Native => "native",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DeveloperKey {
    #[serde(rename = "$schema")]
    pub schema: Option<String>,
    /// Identifier referenced by registry entries (`publisher`); also the file name.
    pub id: String,
    /// Human-readable author name; informational only.
    pub author: String,
    pub algorithm: String,
    /// Raw 32-byte Ed25519 public key, standard base64 with padding.
    pub public_key: String,
    /// The same key in OpenSSH form, for convenience; informational only.
    pub openssh: Option<String>,
    /// Legacy grant: `["xila"]` lets this key publish the two-component
    /// `xila.<name>` identifiers. No other value is accepted: reverse-DNS
    /// namespaces are granted by namespace files, so adding a developer never
    /// changes a key file. Remove once Xila's packages are migrated.
    pub namespaces: Option<Vec<String>>,
    /// Package kinds this key may publish: `wasm` and/or `native`. Absent means
    /// `wasm` only, so native executables always need an explicit grant.
    pub kinds: Option<Vec<String>>,
}

fn base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Decode the canonical 44-character base64 form of 32 bytes.
pub(crate) fn decode_key(encoded: &str) -> Option<[u8; 32]> {
    let bytes = encoded.as_bytes();
    if bytes.len() != 44 || bytes[43] != b'=' {
        return None;
    }
    let mut output = [0u8; 33];
    for (chunk, out) in bytes[..44].chunks(4).zip(output.chunks_mut(3)) {
        let mut accumulator = 0u32;
        for (index, &byte) in chunk.iter().enumerate() {
            let value = if byte == b'=' && index == 3 {
                0
            } else {
                base64_value(byte)?
            };
            accumulator = (accumulator << 6) | u32::from(value);
        }
        out.copy_from_slice(&accumulator.to_be_bytes()[1..]);
    }
    // Reject non-canonical encodings: the unused low bits must be zero.
    if base64_value(bytes[42])? & 0b11 != 0 || output[32] != 0 {
        return None;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&output[..32]);
    Some(key)
}

impl DeveloperKey {
    pub fn validate(&self) -> Result<(), Error> {
        if self
            .schema
            .as_deref()
            .is_some_and(|url| url != DEVELOPER_KEY_SCHEMA_URL)
        {
            return Err(Error::InvalidSchema);
        }
        let author = !self.author.trim().is_empty()
            && self.author.len() <= 128
            && !self.author.chars().any(char::is_control);
        let openssh = self
            .openssh
            .as_deref()
            .is_none_or(|key| key.starts_with("ssh-ed25519 ") && key.len() <= 256);
        if !valid_publisher(&self.id)
            || !author
            || self.algorithm != ED25519
            || decode_key(&self.public_key).is_none()
            || !openssh
            || !self.valid_legacy_namespaces()
            || !self.valid_kinds()
        {
            return Err(Error::InvalidDeveloperKey);
        }
        Ok(())
    }

    fn valid_legacy_namespaces(&self) -> bool {
        self.namespaces
            .as_ref()
            .is_none_or(|namespaces| namespaces.len() == 1 && namespaces[0] == LEGACY_NAMESPACE)
    }

    fn valid_kinds(&self) -> bool {
        self.kinds.as_ref().is_none_or(|kinds| {
            !kinds.is_empty()
                && kinds.len() <= 2
                && kinds.iter().all(|kind| {
                    kind == PackageKind::Wasm.name() || kind == PackageKind::Native.name()
                })
                && (kinds.len() == 1 || kinds[0] != kinds[1])
        })
    }

    /// The raw Ed25519 public key.
    pub fn public_key_bytes(&self) -> Result<[u8; 32], Error> {
        decode_key(&self.public_key).ok_or(Error::InvalidDeveloperKey)
    }

    /// Legacy rule: whether this key's own `namespaces` grant the legacy
    /// identifier `name` (`xila.<name>`). Never true for a reverse-DNS
    /// identifier.
    pub fn authorizes_legacy(&self, name: &str) -> bool {
        is_legacy_identifier(name)
            && self.namespaces.as_ref().is_some_and(|namespaces| {
                namespaces
                    .iter()
                    .any(|namespace| namespace == LEGACY_NAMESPACE)
            })
    }

    /// Whether this key may publish the package identifier `name`: the
    /// `namespace` file covering it lists this key, or the legacy rule
    /// applies. `namespace` is the verified namespace file covering `name`,
    /// if any; a file for another namespace grants nothing.
    pub fn authorizes(&self, name: &str, namespace: Option<&Namespace>) -> bool {
        namespace.is_some_and(|namespace| namespace.authorizes(&self.id, name))
            || self.authorizes_legacy(name)
    }
}

impl DeveloperKey {
    /// Whether this key may publish packages of `kind`.
    pub fn authorizes_kind(&self, kind: PackageKind) -> bool {
        match &self.kinds {
            None => kind == PackageKind::Wasm,
            Some(kinds) => kinds.iter().any(|allowed| allowed == kind.name()),
        }
    }

    /// Whether this key may publish the package `name` built for `target`:
    /// its identifier (see [`Self::authorizes`]) and its kind must both be
    /// authorized.
    pub fn authorizes_package(
        &self,
        name: &str,
        target: &str,
        namespace: Option<&Namespace>,
    ) -> bool {
        self.authorizes(name, namespace) && self.authorizes_kind(PackageKind::of_target(target))
    }
}

pub fn decode_developer_key(bytes: &[u8]) -> Result<DeveloperKey, Error> {
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(Error::TooLarge);
    }
    let source = core::str::from_utf8(bytes).map_err(|_| Error::InvalidJson)?;
    crate::check_nesting_depth(source)?;
    let key: DeveloperKey = miniserde::json::from_str(source).map_err(|_| Error::InvalidJson)?;
    key.validate()?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    const XILA: &str = r#"{
  "id": "xila",
  "author": "Xila Project",
  "algorithm": "ed25519",
  "public_key": "6D1cvlGzCAITQrmkWjJgn97DW1s6p3zvDNe8a87pcbc=",
  "openssh": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOg9XL5RswgCE0K5pFoyYJ/ew1tbOqd87wzXvGvO6XG3 xila",
  "namespaces": ["xila"]
}"#;

    #[test]
    fn decodes_the_published_xila_key() {
        let key = decode_developer_key(XILA.as_bytes()).unwrap();
        // Same bytes as the OpenSSH blob's trailing 32-byte key.
        assert_eq!(
            key.public_key_bytes().unwrap()[..4],
            [0xe8, 0x3d, 0x5c, 0xbe]
        );
        assert!(key.authorizes("xila.clock", None));
        assert!(key.authorizes("xila.pixel-painter", None));
        assert!(!key.authorizes("community.weather", None));
        assert!(!key.authorizes("xilaclock", None));
        assert!(!key.authorizes("xilax.clock", None));
        // The legacy grant covers two-component identifiers only.
        assert!(!key.authorizes("xila.tools.clock", None));
        assert!(!key.authorizes("example.xila.weather", None));
    }

    fn namespace(keys: &[&str]) -> Namespace {
        Namespace {
            schema: None,
            format_version: crate::NAMESPACE_FORMAT_VERSION,
            namespace: "example.xila".into(),
            owner: crate::NamespaceOwner {
                kind: "domain".into(),
                name: "xila.example".into(),
            },
            developer_keys: keys.iter().map(|key| (*key).into()).collect(),
        }
    }

    #[test]
    fn namespace_files_authorize_listed_keys_by_prefix() {
        let mut key = decode_developer_key(XILA.as_bytes()).unwrap();
        key.namespaces = None;
        key.validate().unwrap();
        let listed = namespace(&["xila"]);
        listed.validate().unwrap();
        assert!(key.authorizes("example.xila.weather", Some(&listed)));
        assert!(key.authorizes("example.xila.tools.clock", Some(&listed)));
        assert!(key.authorizes_package("example.xila.weather", "wasm32-wasip1", Some(&listed)));
        // Denied: no namespace file, a file that does not list the key, an
        // identifier outside the file's namespace, the legacy identifiers
        // without the legacy grant, and native code without the native grant.
        assert!(!key.authorizes("example.xila.weather", None));
        assert!(!key.authorizes("example.xila.weather", Some(&namespace(&["alice"]))));
        assert!(!key.authorizes("example.xilas.weather", Some(&listed)));
        assert!(!key.authorizes("example.other.weather", Some(&listed)));
        assert!(!key.authorizes("xila.clock", Some(&listed)));
        assert!(!key.authorizes_package(
            "example.xila.weather",
            "thumbv7em-none-eabi",
            Some(&listed)
        ));
    }

    #[test]
    fn namespaces_field_is_optional_and_legacy_only() {
        let json = XILA.replace(
            r#",
  "namespaces": ["xila"]"#,
            "",
        );
        let key = decode_developer_key(json.as_bytes()).unwrap();
        assert_eq!(key.namespaces, None);
        assert!(!key.authorizes("xila.clock", None));
        for namespaces in [
            r#"[]"#,
            r#"["example.xila"]"#,
            r#"["community"]"#,
            r#"["xila", "xila"]"#,
            r#"["xila", "example.xila"]"#,
        ] {
            let json = XILA.replace(r#"["xila"]"#, namespaces);
            assert_eq!(
                decode_developer_key(json.as_bytes()),
                Err(Error::InvalidDeveloperKey),
                "{namespaces}"
            );
        }
    }

    #[test]
    fn kinds_default_to_wasm_and_native_needs_an_explicit_grant() {
        assert_eq!(PackageKind::of_target("wasm32-wasip1"), PackageKind::Wasm);
        assert_eq!(
            PackageKind::of_target("wasm32-unknown-unknown"),
            PackageKind::Wasm
        );
        assert_eq!(
            PackageKind::of_target("thumbv7em-none-eabi"),
            PackageKind::Native
        );
        assert_eq!(
            PackageKind::of_target("x86_64-unknown-linux-gnu"),
            PackageKind::Native
        );
        assert_eq!(PackageKind::of_target("unknown"), PackageKind::Native);
        assert_eq!(
            PackageKind::of_target("wasm64-unknown-unknown"),
            PackageKind::Wasm
        );
        // Anything that is not exactly a Wasm prefix fails closed to native.
        for target in [
            "",
            "wasm32",
            "wasm",
            "WASM32-wasip1",
            "Wasm32-wasip1",
            "wasm32_wasip1",
            "xwasm32-wasip1",
            "native",
        ] {
            assert_eq!(
                PackageKind::of_target(target),
                PackageKind::Native,
                "{target}"
            );
        }

        let mut key = decode_developer_key(XILA.as_bytes()).unwrap();
        assert_eq!(key.kinds, None);
        assert!(key.authorizes_package("xila.clock", "wasm32-wasip1", None));
        assert!(!key.authorizes_package("xila.clock", "thumbv7em-none-eabi", None));

        key.kinds = Some(alloc::vec!["native".into()]);
        key.validate().unwrap();
        assert!(!key.authorizes_package("xila.clock", "wasm32-wasip1", None));
        assert!(key.authorizes_package("xila.clock", "thumbv7em-none-eabi", None));
        assert!(!key.authorizes_package("other.clock", "thumbv7em-none-eabi", None));

        key.kinds = Some(alloc::vec!["wasm".into(), "native".into()]);
        key.validate().unwrap();
        assert!(key.authorizes_package("xila.clock", "wasm32-wasip1", None));
        assert!(key.authorizes_package("xila.clock", "thumbv7em-none-eabi", None));
    }

    #[test]
    fn decodes_the_kinds_field() {
        let json = XILA.replace(
            r#""namespaces": ["xila"]"#,
            r#""namespaces": ["xila"], "kinds": ["wasm", "native"]"#,
        );
        let key = decode_developer_key(json.as_bytes()).unwrap();
        assert!(key.authorizes_kind(PackageKind::Native));
        let json = XILA.replace(
            r#""namespaces": ["xila"]"#,
            r#""namespaces": ["xila"], "kinds": null"#,
        );
        assert!(
            !decode_developer_key(json.as_bytes())
                .unwrap()
                .authorizes_kind(PackageKind::Native)
        );
    }

    #[test]
    fn rejects_malformed_keys() {
        let base = decode_developer_key(XILA.as_bytes()).unwrap();
        for change in [
            |k: &mut DeveloperKey| k.id = "Xila Project".into(),
            |k: &mut DeveloperKey| k.author = " ".into(),
            |k: &mut DeveloperKey| k.algorithm = "rsa".into(),
            |k: &mut DeveloperKey| k.public_key = "AAAA".into(),
            // Last character must leave the unused low bits zero.
            |k: &mut DeveloperKey| {
                k.public_key = "6D1cvlGzCAITQrmkWjJgn97DW1s6p3zvDNe8a87pcbd=".into()
            },
            |k: &mut DeveloperKey| {
                k.public_key = "6D1cvlGzCAITQrmkWjJgn97DW1s6p3zvDNe8a87pcb!=".into()
            },
            |k: &mut DeveloperKey| k.namespaces = Some(Vec::new()),
            |k: &mut DeveloperKey| k.namespaces = Some(alloc::vec!["Xila".into()]),
            |k: &mut DeveloperKey| k.namespaces = Some(alloc::vec!["example.xila".into()]),
            |k: &mut DeveloperKey| k.openssh = Some("ssh-rsa AAAA".into()),
            |k: &mut DeveloperKey| k.kinds = Some(Vec::new()),
            |k: &mut DeveloperKey| k.kinds = Some(alloc::vec!["arm".into()]),
            |k: &mut DeveloperKey| k.kinds = Some(alloc::vec!["wasm".into(), "wasm".into()]),
            |k: &mut DeveloperKey| {
                k.kinds = Some(alloc::vec!["wasm".into(), "native".into(), "wasm".into()])
            },
        ] {
            let mut key = base.clone();
            change(&mut key);
            assert_eq!(key.validate(), Err(Error::InvalidDeveloperKey));
        }
    }
}
