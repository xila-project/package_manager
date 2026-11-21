use alloc::{borrow::Cow, string::ToString};
use core::{fmt, str::FromStr};
use miniserde::{Deserialize, Serialize, de::Visitor, make_place, ser::Fragment};

/// The major and minor components of a Xila release.
///
/// The text and JSON representations use `major.minor`. Each component is a
/// decimal integer from 0 through 65535, without leading zeros.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct XilaVersion {
    pub major: u16,
    pub minor: u16,
}

impl XilaVersion {
    pub const fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }
}

/// A string did not represent a Xila version in `major.minor` form.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidXilaVersion;

impl fmt::Display for InvalidXilaVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("expected major.minor with decimal components from 0 through 65535")
    }
}

impl core::error::Error for InvalidXilaVersion {}

impl FromStr for XilaVersion {
    type Err = InvalidXilaVersion;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        fn component(value: &str) -> Result<u16, InvalidXilaVersion> {
            if !value.bytes().all(|byte| byte.is_ascii_digit())
                || (value.len() > 1 && value.starts_with('0'))
            {
                return Err(InvalidXilaVersion);
            }
            value.parse().map_err(|_| InvalidXilaVersion)
        }

        let (major, minor) = value.split_once('.').ok_or(InvalidXilaVersion)?;
        Ok(Self::new(component(major)?, component(minor)?))
    }
}

impl fmt::Display for XilaVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}", self.major, self.minor)
    }
}

impl Serialize for XilaVersion {
    fn begin(&self) -> Fragment<'_> {
        Fragment::Str(Cow::Owned(self.to_string()))
    }
}

impl Deserialize for XilaVersion {
    fn begin(output: &mut Option<Self>) -> &mut dyn Visitor {
        make_place!(VersionPlace);

        impl Visitor for VersionPlace<XilaVersion> {
            fn string(&mut self, value: &str) -> miniserde::Result<()> {
                self.out = Some(value.parse().map_err(|_| miniserde::Error)?);
                Ok(())
            }
        }

        VersionPlace::new(output)
    }
}

/// Check whether the running Xila release satisfies a package's declared minimum.
///
/// Before 1.0, both releases must have major version zero and the same minor
/// version. Starting at 1.0, the major versions must match and the running minor
/// version must be at least the declared minor version. Patch versions are ignored.
pub const fn compatible(declared: XilaVersion, running: XilaVersion) -> bool {
    declared.major == running.major
        && if declared.major == 0 {
            declared.minor == running.minor
        } else {
            declared.minor <= running.minor
        }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_serializes_xila_versions() {
        for (text, expected) in [
            ("0.0", XilaVersion::new(0, 0)),
            ("0.1", XilaVersion::new(0, 1)),
            ("1.42", XilaVersion::new(1, 42)),
            ("65535.65535", XilaVersion::new(65535, 65535)),
        ] {
            assert_eq!(text.parse(), Ok(expected));
            assert_eq!(expected.to_string(), text);
            let json = alloc::format!("\"{text}\"");
            assert_eq!(miniserde::json::to_string(&expected), json);
            assert_eq!(
                miniserde::json::from_str::<XilaVersion>(&json).unwrap(),
                expected
            );
        }
    }

    #[test]
    fn rejects_invalid_xila_versions() {
        for text in [
            "", "1", "1.2.3", ".2", "1.", "+1.2", "1.+2", "-1.2", " 1.2", "1. 2", "1.2 ", "1.2\n",
            "01.2", "1.02", "65536.0", "0.65536", "１.2",
        ] {
            assert_eq!(
                text.parse::<XilaVersion>(),
                Err(InvalidXilaVersion),
                "{text:?}"
            );
            let json = miniserde::json::to_string(text);
            assert!(
                miniserde::json::from_str::<XilaVersion>(&json).is_err(),
                "{json}"
            );
        }
        for json in ["1", "null", "{}", "[]"] {
            assert!(
                miniserde::json::from_str::<XilaVersion>(json).is_err(),
                "{json}"
            );
        }
    }

    #[test]
    fn checks_compatibility_at_major_and_minor_boundaries() {
        for (declared, running, expected) in [
            ("0.1", "0.1", true),
            ("0.1", "0.2", false),
            ("0.2", "0.1", false),
            ("1.3", "1.2", false),
            ("1.3", "1.3", true),
            ("1.3", "1.9", true),
            ("1.3", "2.0", false),
            ("0.9", "1.0", false),
        ] {
            assert_eq!(
                compatible(declared.parse().unwrap(), running.parse().unwrap()),
                expected,
                "{declared} on {running}"
            );
        }
    }
}
