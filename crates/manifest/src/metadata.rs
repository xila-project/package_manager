//! Descriptive package information for catalogs and registries.
//!
//! It is written once in the developer manifest, carried into the signed
//! runtime manifest, and copied into registry entries. It never grants trust.

use alloc::string::String;
use miniserde::{Deserialize, Serialize};

use crate::Error;

/// Maximum length of a URL in metadata or registry entries.
pub const MAX_URL_LENGTH: usize = 256;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Metadata {
    /// One-line description shown in catalogs.
    pub summary: String,
    /// SPDX license expression, e.g. `MIT` or `Apache-2.0 OR MIT`.
    pub license: String,
    /// HTTPS URL of the source repository.
    pub source: String,
    /// Optional HTTPS project homepage.
    pub homepage: Option<String>,
}

/// Whether `value` is a bounded `https://` URL without whitespace or controls.
pub fn is_https_url(value: &str) -> bool {
    value.len() <= MAX_URL_LENGTH
        && value.strip_prefix("https://").is_some_and(|rest| {
            !rest.is_empty() && !rest.chars().any(|c| c.is_whitespace() || c.is_control())
        })
}

impl Metadata {
    pub fn validate(&self) -> Result<(), Error> {
        let summary = !self.summary.trim().is_empty()
            && self.summary.len() <= 256
            && !self.summary.chars().any(char::is_control);
        let license = !self.license.trim().is_empty()
            && self.license.len() <= 64
            && self
                .license
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".+-() ".contains(&b));
        let homepage = self.homepage.as_deref().is_none_or(is_https_url);
        if summary && license && is_https_url(&self.source) && homepage {
            Ok(())
        } else {
            Err(Error::InvalidMetadata)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metadata() -> Metadata {
        Metadata {
            summary: "Shows the time".into(),
            license: "Apache-2.0 OR MIT".into(),
            source: "https://github.com/xila-project/applications".into(),
            homepage: None,
        }
    }

    #[test]
    fn accepts_complete_metadata() {
        assert!(metadata().validate().is_ok());
        let mut with_homepage = metadata();
        with_homepage.homepage = Some("https://xila.dev".into());
        assert!(with_homepage.validate().is_ok());
    }

    #[test]
    fn rejects_unsafe_or_empty_fields() {
        for change in [
            |m: &mut Metadata| m.summary = " ".into(),
            |m: &mut Metadata| m.summary = "line\nbreak".into(),
            |m: &mut Metadata| m.license = "MIT; rm".into(),
            |m: &mut Metadata| m.source = "http://github.com/x".into(),
            |m: &mut Metadata| m.source = "https://".into(),
            |m: &mut Metadata| m.homepage = Some("https://a b".into()),
        ] {
            let mut value = metadata();
            change(&mut value);
            assert_eq!(value.validate(), Err(Error::InvalidMetadata));
        }
    }
}
