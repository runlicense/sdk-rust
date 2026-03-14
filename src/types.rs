use serde::{Deserialize, Serialize};
use std::fmt;

/// The outer license file structure containing a signed payload.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct LicenseFile {
    /// JSON-encoded LicensePayload as a string
    pub payload: String,
    /// Base64-encoded Ed25519 signature of the payload string
    pub signature: String,
}

/// The decoded license payload with all license details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicensePayload {
    pub license_id: String,
    pub product_id: String,
    pub customer_id: String,
    pub status: String,
    pub expiry_date: Option<String>,
    pub allowed_features: Option<serde_json::Value>,
    pub usage_limit: Option<u64>,
    pub token_ttl: Option<u64>,
    pub activation_url: Option<String>,
}

/// A validation token returned by the phone-home server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationToken {
    pub license_id: String,
    pub nonce: String,
    pub issued_at: String,
    pub expires_at: String,
}

/// Errors that can occur during license verification.
#[derive(Debug)]
pub enum LicenseError {
    /// Could not find the license file at the expected path.
    LicenseFileNotFound(String),
    /// Could not read the license file.
    LicenseFileUnreadable(String),
    /// The license JSON is malformed.
    InvalidJson(String),
    /// The public key is invalid.
    InvalidPublicKey,
    /// The signature encoding is invalid.
    InvalidSignature,
    /// The signature does not match the payload (tampered or wrong key).
    SignatureMismatch,
    /// The license status is not "active".
    LicenseNotActive(String),
    /// The license has expired.
    LicenseExpired(String),
    /// No activation URL configured for phone-home.
    NoActivationUrl,
    /// Phone-home request failed.
    PhoneHomeFailed(String),
    /// The validation token from the server is invalid.
    InvalidValidationToken,
    /// The nonce in the validation token does not match.
    ValidationTokenNonceMismatch,
    /// The validation token has expired.
    ValidationTokenExpired,
    /// The license ID in the validation token does not match.
    ValidationTokenLicenseMismatch,
    /// The server rejected the license.
    ServerRejected(String),
}

impl fmt::Display for LicenseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LicenseFileNotFound(path) => write!(f, "license file not found: {}", path),
            Self::LicenseFileUnreadable(err) => write!(f, "could not read license file: {}", err),
            Self::InvalidJson(err) => write!(f, "invalid license JSON: {}", err),
            Self::InvalidPublicKey => write!(f, "invalid public key"),
            Self::InvalidSignature => write!(f, "invalid signature encoding"),
            Self::SignatureMismatch => {
                write!(f, "signature verification failed — license may be tampered")
            }
            Self::LicenseNotActive(status) => {
                write!(f, "license is not active (status: {})", status)
            }
            Self::LicenseExpired(date) => write!(f, "license expired on {}", date),
            Self::NoActivationUrl => write!(f, "no activation URL configured for phone-home"),
            Self::PhoneHomeFailed(err) => write!(f, "phone-home validation failed: {}", err),
            Self::InvalidValidationToken => write!(f, "invalid validation token from server"),
            Self::ValidationTokenNonceMismatch => {
                write!(
                    f,
                    "validation token nonce mismatch — possible replay attack"
                )
            }
            Self::ValidationTokenExpired => write!(f, "validation token has expired"),
            Self::ValidationTokenLicenseMismatch => {
                write!(f, "validation token license ID mismatch")
            }
            Self::ServerRejected(msg) => write!(f, "server rejected license: {}", msg),
        }
    }
}

impl std::error::Error for LicenseError {}
