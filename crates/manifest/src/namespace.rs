//! Reverse-DNS package identifiers and namespace ownership claims.

use alloc::string::String;
use miniserde::{Deserialize, Serialize};

use crate::{Error, decode_versioned};

pub const NAMESPACE_SCHEMA_URL: &str = "https://raw.githubusercontent.com/xila-project/package_manager/main/schemas/registry-namespace.schema.json";
pub const NAMESPACE_FORMAT_VERSION: u32 = 2;
pub const MINIMUM_IDENTIFIER_COMPONENTS: usize = 3;
pub const MINIMUM_NAMESPACE_COMPONENTS: usize = MINIMUM_IDENTIFIER_COMPONENTS - 1;
pub const MAX_IDENTIFIER_LENGTH: usize = 96;

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

/// Whether `value` is a reverse-DNS package identifier.
pub fn valid_identifier(value: &str) -> bool {
    valid_reverse_domain_name(value, MINIMUM_IDENTIFIER_COMPONENTS)
}

/// Whether `value` has at least two components and room for a package name.
pub fn valid_namespace(value: &str) -> bool {
    value.len() <= MAX_IDENTIFIER_LENGTH - 2
        && valid_reverse_domain_name(value, MINIMUM_NAMESPACE_COMPONENTS)
}

/// The namespace of a valid identifier: every component except the last.
pub fn identifier_namespace(identifier: &str) -> Option<&str> {
    valid_identifier(identifier)
        .then(|| identifier.rsplit_once('.'))
        .flatten()
        .map(|(namespace, _)| namespace)
}

fn account_namespace(namespace: &str, provider: &str) -> bool {
    namespace == provider
        || namespace
            .strip_prefix(provider)
            .is_some_and(|suffix| suffix.starts_with('.'))
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
        valid_namespace(namespace)
            && match self.kind.as_str() {
                DOMAIN_OWNER => {
                    !account_namespace(namespace, "io.github")
                        && !account_namespace(namespace, "io.gitlab")
                        && !namespace.contains('_')
                        && self.name.split('.').rev().eq(namespace.split('.'))
                }
                GITHUB_OWNER => account("io.github.") && !self.name.contains('_'),
                GITLAB_OWNER => account("io.gitlab."),
                _ => false,
            }
    }
}

/// Namespace ownership claim for the first publication of a package.
/// Registry submission must verify control of the domain or account.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Namespace {
    #[serde(rename = "$schema")]
    pub schema: Option<String>,
    pub format_version: u32,
    pub namespace: String,
    pub owner: NamespaceOwner,
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
        if !self.owner.matches(&self.namespace) {
            return Err(Error::InvalidNamespace);
        }
        Ok(())
    }

    /// Check that this claim names the exact namespace of the package.
    pub fn matches_identifier(&self, identifier: &str) -> bool {
        identifier_namespace(identifier) == Some(self.namespace.as_str()) && self.validate().is_ok()
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

    #[test]
    fn first_publication_uses_the_exact_namespace_owner() {
        for (namespace, kind, name) in [
            ("example.xila", DOMAIN_OWNER, "xila.example"),
            ("io.github.alice", GITHUB_OWNER, "alice"),
            ("io.gitlab.alice", GITLAB_OWNER, "alice"),
        ] {
            let mut claim = Namespace {
                schema: None,
                format_version: NAMESPACE_FORMAT_VERSION,
                namespace: namespace.into(),
                owner: NamespaceOwner {
                    kind: kind.into(),
                    name: name.into(),
                },
            };
            let identifier = alloc::format!("{namespace}.clock");
            assert!(claim.matches_identifier(&identifier));
            assert!(!claim.matches_identifier(&alloc::format!("{namespace}.nested.clock")));
            assert_eq!(
                decode_namespace(encode_namespace(&claim).unwrap().as_bytes()),
                Ok(claim.clone())
            );
            claim.owner.name = "other".into();
            assert!(!claim.matches_identifier(&identifier));
        }
        let domain = NamespaceOwner {
            kind: DOMAIN_OWNER.into(),
            name: "alice.github.io".into(),
        };
        assert!(!domain.matches("io.github.alice"));
        assert!(!valid_identifier("xila.clock"));
    }
}
