#![no_std]
#![forbid(unsafe_code)]
//! # Xila package manager
//!
//! Platform-independent coordination layer for future Xila application
//! installation and repository operations.
//!
//! **This crate currently has no public installer API.** The existing
//! subcrates provide:
//!
//! - `xila-package-manifest`: a versioned `no_std + alloc` archive schema.
//! - `xila-package-reader`: full-buffer TAR inspection and verification.
//! - `xila-package-verification`: cryptographic primitives.
//! - `xila-package-writer`: host-only TAR creation.
//! - `xila-package-builder`: host-only command-line packaging.
//!
//! The eventual embedded installer will require explicit abstractions for
//! filesystems, networking, trust roots, and atomic installation. No platform
//! dependency or speculative API is introduced by this placeholder.
//!
//! See the [Xila package-management tracking issue](https://github.com/xila-project/core/issues/308).
