//! Package identifiers and the namespaces that own them.
//!
//! Identifiers are reverse-DNS names with at least three lowercase
//! components, such as `example.xila.weather` or `io.github.alice.weather`. The
//! namespace is every component except the last one. Identifiers become paths
//! on devices, and FAT file systems ignore case, so only lowercase letters,
//! digits, `-` and `_` are allowed.
//!
//! Each namespace is recorded once, in `namespaces/<namespace>.json` in the
//! registry, signed by the repository key. The file names the owner, whose
//! ownership registry CI proves, and lists the developer keys allowed to
//! publish in it. A listed key may publish every identifier that starts with
//! the namespace (`example.xila` covers `example.xila.weather` and
//! `example.xila.tools.clock`), so adding a developer or rotating a key changes
//! neither the identifiers nor the key files.
//!
//! Legacy rule, until the one-time migration of Xila's own packages: the
//! two-component identifiers `xila.<name>` stay valid, and a developer key
//! grants them through its own `namespaces` field. See [`LEGACY_NAMESPACE`].

use alloc::{format, string::String, vec::Vec};
use miniserde::{Deserialize, Serialize};

use crate::{Error, decode_versioned, registry::valid_publisher};

/// Editor-facing JSON Schema; a tooling hint, never a trust anchor.
pub const NAMESPACE_SCHEMA_URL: &str = "https://raw.githubusercontent.com/xila-project/package_manager/main/schemas/registry-namespace.schema.json";
/// Current experimental namespace file format version.
pub const NAMESPACE_FORMAT_VERSION: u32 = 1;
/// Directory of the namespace files, relative to the registry root.
pub const NAMESPACES_DIRECTORY: &str = "namespaces";

/// Legacy namespace of Xila's own packages (`xila.calculator`). It is the only
/// namespace with a single component, the only one whose identifiers have
/// two components, and the only one a developer key may list in its own
/// `namespaces` field. Remove it once those packages move to a reverse-DNS
/// namespace.
pub const LEGACY_NAMESPACE: &str = "xila";
/// Minimum number of components of a reverse-DNS identifier.
pub const MINIMUM_IDENTIFIER_COMPONENTS: usize = 3;
/// Minimum number of components of a namespace (`example.xila`).
pub const MINIMUM_NAMESPACE_COMPONENTS: usize = MINIMUM_IDENTIFIER_COMPONENTS - 1;
/// Maximum identifier and namespace length in bytes.
pub const MAX_IDENTIFIER_LENGTH: usize = 96;
/// Maximum number of developer keys listed in one namespace file.
pub const MAX_NAMESPACE_DEVELOPER_KEYS: usize = 32;

/// Owner kinds, recorded in [`NamespaceOwner::kind`].
pub const DOMAIN_OWNER: &str = "domain";
pub const GITHUB_OWNER: &str = "github";
pub const GITLAB_OWNER: &str = "gitlab";

fn valid_component(component: &str) -> bool {
    let bytes = component.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 63
        && bytes[0].is_ascii_alphanumeric()
        && bytes[bytes.len() - 1].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|&b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

fn valid_reverse_domain_name(value: &str, minimum_components: usize) -> bool {
    value.len() <= MAX_IDENTIFIER_LENGTH
        && value.split('.').count() >= minimum_components
        && value.split('.').all(valid_component)
}

/// Whether `value` is a legacy two-component `xila.<name>` identifier.
pub fn is_legacy_identifier(value: &str) -> bool {
    value.len() <= MAX_IDENTIFIER_LENGTH
        && value
            .split_once('.')
            .is_some_and(|(namespace, name)| namespace == LEGACY_NAMESPACE && valid_component(name))
}

/// Whether `value` is a valid package identifier: reverse-DNS with at least
/// three components, or a legacy `xila.<name>` identifier.
pub fn valid_identifier(value: &str) -> bool {
    valid_reverse_domain_name(value, MINIMUM_IDENTIFIER_COMPONENTS) || is_legacy_identifier(value)
}

/// Whether `value` is a valid reverse-DNS namespace (at least two components).
/// The legacy namespace is not one: it has no namespace file.
pub fn valid_namespace(value: &str) -> bool {
    // Leave room for at least one more component (`.x`).
    value.len() + 2 <= MAX_IDENTIFIER_LENGTH
        && valid_reverse_domain_name(value, MINIMUM_NAMESPACE_COMPONENTS)
}

/// The namespace of a valid identifier: every component except the last.
pub fn identifier_namespace(identifier: &str) -> Option<&str> {
    valid_identifier(identifier)
        .then(|| identifier.rsplit_once('.').map(|(namespace, _)| namespace))
        .flatten()
}

/// Whether `namespace` covers `identifier`: the identifier is valid and starts
/// with the namespace's components. Prefixes only match whole components, so
/// `example.xila` covers neither `example.xilas.weather` nor itself.
pub fn namespace_covers(namespace: &str, identifier: &str) -> bool {
    valid_namespace(namespace)
        && valid_identifier(identifier)
        && identifier
            .strip_prefix(namespace)
            .is_some_and(|rest| rest.len() > 1 && rest.starts_with('.'))
}

/// Whether one namespace contains the other (or both are equal). The registry
/// allows a single owner per identifier, so namespace files may not overlap.
pub fn namespaces_overlap(first: &str, second: &str) -> bool {
    let contains = |outer: &str, inner: &str| {
        inner
            .strip_prefix(outer)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with('.'))
    };
    contains(first, second) || contains(second, first)
}

/// Registry-relative path of the namespace file of `namespace`.
pub fn namespace_path(namespace: &str) -> String {
    format!("{NAMESPACES_DIRECTORY}/{namespace}.json")
}

/// Paths of the namespace files that could cover `identifier`, shortest
/// namespace first. At most one exists, since namespace files do not overlap.
/// Empty for an invalid or legacy identifier.
pub fn namespace_paths(identifier: &str) -> Vec<String> {
    let mut paths = Vec::new();
    if !valid_reverse_domain_name(identifier, MINIMUM_IDENTIFIER_COMPONENTS) {
        return paths;
    }
    for (position, _) in identifier.match_indices('.') {
        let namespace = &identifier[..position];
        if valid_namespace(namespace) {
            paths.push(namespace_path(namespace));
        }
    }
    paths
}

/// Who owns a namespace, and so how registry CI proves it: a `domain` by a
/// token file under `https://<name>/.well-known/`, and a `github` or `gitlab`
/// account by the account itself.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NamespaceOwner {
    /// `domain`, `github` or `gitlab`.
    pub kind: String,
    /// The domain (`xila.example` for `example.xila`) or the account name
    /// (`alice` for `io.github.alice`).
    pub name: String,
}

impl NamespaceOwner {
    /// Whether this owner is the one `namespace` implies: the reversed domain,
    /// or the account of an `io.github.<account>` or `io.gitlab.<account>`
    /// namespace. Accounts never own a namespace through a domain proof, and a
    /// domain may not contain `_`.
    pub fn matches(&self, namespace: &str) -> bool {
        let account = |prefix: &str| {
            namespace
                .strip_prefix(prefix)
                .is_some_and(|account| !account.contains('.') && account == self.name)
        };
        match self.kind.as_str() {
            DOMAIN_OWNER => {
                !namespaces_overlap(namespace, "io.github")
                    && !namespaces_overlap(namespace, "io.gitlab")
                    && !namespace.contains('_')
                    && self.name.split('.').rev().eq(namespace.split('.'))
            }
            GITHUB_OWNER => account("io.github.") && !self.name.contains('_'),
            GITLAB_OWNER => account("io.gitlab."),
            _ => false,
        }
    }
}

/// `namespaces/<namespace>.json`: the owner of a namespace and the developer
/// keys allowed to publish in it, signed by the repository key.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Namespace {
    #[serde(rename = "$schema")]
    pub schema: Option<String>,
    pub format_version: u32,
    /// Reverse-DNS namespace, such as `example.xila`; also the file name.
    pub namespace: String,
    pub owner: NamespaceOwner,
    /// Identifiers of the developer keys (`keys/developers/<id>.json`) allowed
    /// to publish identifiers in this namespace.
    pub developer_keys: Vec<String>,
}

impl Namespace {
    pub fn validate(&self) -> Result<(), Error> {
        if self
            .schema
            .as_deref()
            .is_some_and(|url| url != NAMESPACE_SCHEMA_URL)
        {
            return Err(Error::InvalidSchema);
        }
        if self.format_version != NAMESPACE_FORMAT_VERSION {
            return Err(Error::UnsupportedVersion);
        }
        let keys = !self.developer_keys.is_empty()
            && self.developer_keys.len() <= MAX_NAMESPACE_DEVELOPER_KEYS
            && self.developer_keys.iter().enumerate().all(|(index, key)| {
                valid_publisher(key) && !self.developer_keys[..index].contains(key)
            });
        if !valid_namespace(&self.namespace) || !self.owner.matches(&self.namespace) || !keys {
            return Err(Error::InvalidNamespace);
        }
        Ok(())
    }

    /// Whether this namespace lets the developer key `publisher` publish
    /// `identifier`.
    pub fn authorizes(&self, publisher: &str, identifier: &str) -> bool {
        namespace_covers(&self.namespace, identifier)
            && self.developer_keys.iter().any(|key| key == publisher)
    }
}

pub fn decode_namespace(bytes: &[u8]) -> Result<Namespace, Error> {
    let namespace: Namespace = decode_versioned(bytes, NAMESPACE_FORMAT_VERSION)?;
    namespace.validate()?;
    Ok(namespace)
}

pub fn encode_namespace(namespace: &Namespace) -> Result<String, Error> {
    namespace.validate()?;
    Ok(miniserde::json::to_string(namespace))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{string::ToString, vec};

    fn example() -> Namespace {
        Namespace {
            schema: Some(NAMESPACE_SCHEMA_URL.into()),
            format_version: NAMESPACE_FORMAT_VERSION,
            namespace: "example.xila".into(),
            owner: NamespaceOwner {
                kind: DOMAIN_OWNER.into(),
                name: "xila.example".into(),
            },
            developer_keys: vec!["example-release".into(), "alice".into()],
        }
    }

    #[test]
    fn accepts_reverse_domain_identifiers() {
        for identifier in [
            "example.xila.weather",
            "io.github.alice.weather",
            "example.xila.tools.clock",
            "example.xila.pixel-painter",
            "example.xila.pixel_painter",
            "dev.x1.app2",
        ] {
            assert!(valid_identifier(identifier), "{identifier}");
            assert!(!is_legacy_identifier(identifier), "{identifier}");
        }
        assert_eq!(
            identifier_namespace("example.xila.weather"),
            Some("example.xila")
        );
        assert_eq!(
            identifier_namespace("example.xila.tools.clock"),
            Some("example.xila.tools")
        );
    }

    #[test]
    fn accepts_legacy_xila_identifiers_only_with_two_components() {
        assert!(is_legacy_identifier("xila.calculator"));
        assert!(valid_identifier("xila.pixel-painter"));
        assert_eq!(identifier_namespace("xila.calculator"), Some("xila"));
        // The legacy rule is for the xila namespace only.
        for identifier in ["community.weather", "example.weather", "xilax.clock"] {
            assert!(!is_legacy_identifier(identifier), "{identifier}");
            assert!(!valid_identifier(identifier), "{identifier}");
        }
        // Three xila components follow the reverse-DNS rule, not the legacy one.
        assert!(!is_legacy_identifier("xila.tools.clock"));
    }

    #[test]
    fn rejects_invalid_identifiers() {
        let long = format!("example.xila.{}", "a".repeat(MAX_IDENTIFIER_LENGTH));
        for identifier in [
            "",
            "weather",
            "example.xila",
            "Example.xila.weather",
            "example.Xila.weather",
            "example.xila.Weather",
            "example..weather",
            ".example.xila.weather",
            "example.xila.weather.",
            "example.xila.-weather",
            "example.xila.weather-",
            "example.xila._weather",
            "example.xila.weather_",
            "example.xila.wea ther",
            "example.xila.wea/ther",
            "example.xila.wéather",
            "xila.",
            "xila.Clock",
            "xila.-clock",
            long.as_str(),
        ] {
            assert!(!valid_identifier(identifier), "{identifier:?}");
            assert_eq!(identifier_namespace(identifier), None, "{identifier:?}");
        }
    }

    #[test]
    fn namespaces_cover_identifiers_by_whole_component_prefix() {
        assert!(namespace_covers("example.xila", "example.xila.weather"));
        assert!(namespace_covers("example.xila", "example.xila.tools.clock"));
        assert!(namespace_covers(
            "io.github.alice",
            "io.github.alice.weather"
        ));
        for (namespace, identifier) in [
            ("example.xila", "example.xilas.weather"),
            ("example.xila", "example.xila"),
            ("example.xila", "example.xil.weather"),
            ("example.xila", "example.other.weather"),
            ("io.github.alice", "io.github.alicex.weather"),
            // A single component is never a namespace, so `example` cannot claim
            // every `example.*` identifier.
            ("example", "example.xila.weather"),
            // The legacy namespace has no namespace file.
            ("xila", "xila.calculator"),
            ("example.xila", "example.xila.Weather"),
        ] {
            assert!(
                !namespace_covers(namespace, identifier),
                "{namespace} {identifier}"
            );
        }
    }

    #[test]
    fn lists_the_namespace_files_that_could_cover_an_identifier() {
        assert_eq!(
            namespace_paths("example.xila.tools.clock"),
            vec![
                "namespaces/example.xila.json".to_string(),
                "namespaces/example.xila.tools.json".to_string(),
            ]
        );
        assert!(namespace_paths("xila.calculator").is_empty());
        assert!(namespace_paths("Invalid").is_empty());
        assert!(namespaces_overlap("example.xila", "example.xila.tools"));
        assert!(namespaces_overlap("example.xila.tools", "example.xila"));
        assert!(namespaces_overlap("example.xila", "example.xila"));
        assert!(!namespaces_overlap("example.xila", "example.xilas"));
    }

    #[test]
    fn namespace_files_round_trip_and_authorize_listed_keys() {
        let namespace = example();
        let encoded = encode_namespace(&namespace).unwrap();
        let decoded = decode_namespace(encoded.as_bytes()).unwrap();
        assert_eq!(decoded, namespace);
        assert!(decoded.authorizes("alice", "example.xila.weather"));
        assert!(decoded.authorizes("example-release", "example.xila.tools.clock"));
        // Denied: an unlisted key, an identifier outside the namespace, or
        // the namespace itself.
        assert!(!decoded.authorizes("mallory", "example.xila.weather"));
        assert!(!decoded.authorizes("alice", "example.xilas.weather"));
        assert!(!decoded.authorizes("alice", "example.other.weather"));
        assert!(!decoded.authorizes("alice", "example.xila"));
        assert!(!decoded.authorizes("alice", "xila.calculator"));
    }

    #[test]
    fn owners_must_match_their_namespace() {
        let owner = |kind: &str, name: &str| NamespaceOwner {
            kind: kind.into(),
            name: name.into(),
        };
        assert!(owner("domain", "xila.example").matches("example.xila"));
        assert!(owner("domain", "tools.xila.example").matches("example.xila.tools"));
        assert!(owner("github", "alice").matches("io.github.alice"));
        assert!(owner("gitlab", "alice_b").matches("io.gitlab.alice_b"));
        for (owner, namespace) in [
            (owner("domain", "other.example"), "example.xila"),
            (owner("domain", "example.xila"), "example.xila"),
            (owner("domain", "xila.example"), "example.xila.tools"),
            (owner("domain", "github.io"), "io.github"),
            (owner("domain", "gitlab.io"), "io.gitlab"),
            (owner("domain", "alice.github.io"), "io.github.alice"),
            (owner("domain", "my_site.example"), "example.my_site"),
            (owner("github", "bob"), "io.github.alice"),
            (owner("github", "alice"), "io.gitlab.alice"),
            (owner("github", "alice"), "io.github.alice.tools"),
            (owner("github", "alice_b"), "io.github.alice_b"),
            (owner("gitlab", "alice"), "io.github.alice"),
            (owner("email", "alice"), "io.github.alice"),
        ] {
            assert!(!owner.matches(namespace), "{owner:?} {namespace}");
        }
    }

    #[test]
    fn rejects_malformed_namespace_files() {
        for change in [
            |n: &mut Namespace| n.namespace = "example".into(),
            |n: &mut Namespace| n.namespace = "xila".into(),
            |n: &mut Namespace| n.namespace = "Example.Xila".into(),
            |n: &mut Namespace| n.namespace = "example.xila.".into(),
            |n: &mut Namespace| n.owner.name = "other.example".into(),
            |n: &mut Namespace| n.owner.kind = "github".into(),
            |n: &mut Namespace| n.developer_keys.clear(),
            |n: &mut Namespace| n.developer_keys.push("alice".into()),
            |n: &mut Namespace| n.developer_keys.push("Alice".into()),
            |n: &mut Namespace| {
                n.developer_keys = (0..=MAX_NAMESPACE_DEVELOPER_KEYS)
                    .map(|index| format!("key-{index}"))
                    .collect()
            },
        ] {
            let mut namespace = example();
            change(&mut namespace);
            assert_eq!(
                namespace.validate(),
                Err(Error::InvalidNamespace),
                "{namespace:?}"
            );
        }
        let mut namespace = example();
        namespace.schema = Some("https://xila.example/schema.json".into());
        assert_eq!(namespace.validate(), Err(Error::InvalidSchema));
        let mut namespace = example();
        namespace.format_version = 2;
        assert_eq!(namespace.validate(), Err(Error::UnsupportedVersion));
        let encoded = miniserde::json::to_string(&namespace);
        assert_eq!(
            decode_namespace(encoded.as_bytes()),
            Err(Error::UnsupportedVersion)
        );
        assert_eq!(decode_namespace(b"{}"), Err(Error::InvalidJson));
    }
}
