//! # RunLicense SDK for Rust
//!
//! License verification SDK for Rust crates using the RunLicense system.
//!
//! ## Quick Start
//!
//! 1. Place your RunLicense public key at `keys/runlicense.key` in your crate root.
//! 2. Your end users place their license at `runlicense/<namespace>/license.json`.
//! 3. Call `verify_license!("your-namespace")` at startup.
//!
//! ```rust,ignore
//! use runlicense_sdk::verify_license;
//!
//! fn init() -> Result<(), Box<dyn std::error::Error>> {
//!     let license = verify_license!("myorg/mycrate")?;
//!     println!("Licensed to customer: {}", license.customer_id);
//!     Ok(())
//! }
//! ```
//!
//! ## License File Discovery
//!
//! The SDK searches for `runlicense/<namespace>/license.json` in:
//! 1. `RUNLICENSE_DIR` environment variable (if set)
//! 2. The directory containing the running executable
//! 3. The current working directory
//!
//! This namespaced approach allows multiple licensed crates to coexist —
//! each crate uses its own namespace and finds its own license file.
//!
//! ## Phone-Home Validation
//!
//! By default, `verify_license!` performs server-side phone-home validation
//! in addition to offline signature and expiry checks. This provides an
//! extra layer of security against license tampering.
//!
//! To disable phone-home (offline-only verification):
//!
//! ```toml
//! [dependencies]
//! runlicense-sdk-rust = { version = "0.1", default-features = false }
//! ```

pub mod types;

#[doc(hidden)]
pub mod __internal;

#[cfg(test)]
mod tests;

pub use types::{LicenseError, LicensePayload};

/// Verify a license by namespace.
///
/// Discovers the license file at `runlicense/<namespace>/license.json`,
/// verifies the Ed25519 signature, checks that the license is active and
/// not expired, and performs phone-home validation with the activation server.
///
/// The public key is embedded at compile time from `keys/runlicense.key`
/// in the consuming crate's root directory.
///
/// # Example
///
/// ```rust,ignore
/// let payload = runlicense_sdk::verify_license!("myorg/mycrate")?;
/// ```
#[macro_export]
macro_rules! verify_license {
    ($namespace:expr) => {{
        let public_key = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/keys/runlicense.key"));
        $crate::__internal::verify_license_with_key($namespace, public_key)
    }};
}

/// Verify a license from a JSON string directly.
///
/// Use this when you already have the license JSON (e.g., loaded from a
/// custom location or received from an API). Performs the same verification
/// as [`verify_license!`] including phone-home, but without filesystem-based
/// token caching.
///
/// # Example
///
/// ```rust,ignore
/// let json = std::fs::read_to_string("path/to/license.json")?;
/// let payload = runlicense_sdk::verify_license_json!(&json)?;
/// ```
#[macro_export]
macro_rules! verify_license_json {
    ($json:expr) => {{
        let public_key = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/keys/runlicense.key"));
        $crate::__internal::verify_license_json_with_key($json, public_key)
    }};
}
