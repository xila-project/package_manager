# Releases

The package manager is an independent leaf repository. Its crates use their own
SemVer versions and per-crate tags such as `xila-package-builder-vX.Y.Z`. Before
1.0, a breaking change bumps a crate's minor version and compatible changes
bump its patch version. Publish these crates before the Xila SDK and Tools.
Package and registry format versions follow their own lifecycles. Run
`mise run release:package` to check the crates.io archives. The manifest and
verification libraries come first, then bundle and manager, then writer,
reader and builder.

Packages declare the minimum Xila version as `major.minor`. Before Xila 1.0 the
minor must match. From 1.0 onward the major must match and the running minor
must be at least the declared minor.

See [the Xila release policy](https://github.com/xila-project/core/issues/276).
