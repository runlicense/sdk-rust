use crate::types::{LicenseError, LicenseFile, LicensePayload};
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use std::path::PathBuf;

#[cfg(feature = "phone-home")]
pub(crate) mod phone_home;

/// Validate that a namespace doesn't contain path traversal components.
fn validate_namespace(namespace: &str) -> Result<(), LicenseError> {
    for component in namespace.split('/') {
        if component == ".." || component == "." || component.is_empty() {
            return Err(LicenseError::LicenseFileNotFound(format!(
                "invalid namespace '{}': must not contain '..' or '.' components or empty segments",
                namespace
            )));
        }
    }
    Ok(())
}

/// Discover the license file path for a given namespace.
///
/// Search order:
/// 1. `RUNLICENSE_DIR` environment variable (if set)
/// 2. Relative to the executable's directory
/// 3. Relative to the current working directory
///
/// The license file is expected at: `<base>/runlicense/<namespace>/license.json`
pub fn discover_license_path(namespace: &str) -> Result<PathBuf, LicenseError> {
    validate_namespace(namespace)?;

    let relative = PathBuf::from("runlicense")
        .join(namespace)
        .join("license.json");

    // 1. Check RUNLICENSE_DIR env var
    if let Ok(dir) = std::env::var("RUNLICENSE_DIR") {
        let path = PathBuf::from(&dir).join(namespace).join("license.json");
        if path.exists() {
            return Ok(path);
        }
    }

    // 2. Check relative to executable directory
    if let Ok(exe) = std::env::current_exe() {
        if let Some(exe_dir) = exe.parent() {
            let path = exe_dir.join(&relative);
            if path.exists() {
                return Ok(path);
            }
        }
    }

    // 3. Check relative to current working directory
    if let Ok(cwd) = std::env::current_dir() {
        let path = cwd.join(&relative);
        if path.exists() {
            return Ok(path);
        }
    }

    Err(LicenseError::LicenseFileNotFound(format!(
        "searched for runlicense/{}/license.json in RUNLICENSE_DIR, executable directory, and working directory",
        namespace
    )))
}

/// Load and parse the license file from disk.
pub fn load_license_file(namespace: &str) -> Result<(String, PathBuf), LicenseError> {
    let path = discover_license_path(namespace)?;
    let contents = std::fs::read_to_string(&path)
        .map_err(|e| LicenseError::LicenseFileUnreadable(e.to_string()))?;
    Ok((contents, path))
}

/// Verify the Ed25519 signature of a license payload.
pub fn verify_signature(
    license_json: &str,
    public_key_b64: &str,
) -> Result<LicensePayload, LicenseError> {
    let b64 = base64::engine::general_purpose::STANDARD;

    // Parse the license file envelope
    let license_file: LicenseFile =
        serde_json::from_str(license_json).map_err(|e| LicenseError::InvalidJson(e.to_string()))?;

    // Decode the public key
    let key_bytes = b64
        .decode(public_key_b64.trim())
        .map_err(|_| LicenseError::InvalidPublicKey)?;
    let key_array: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| LicenseError::InvalidPublicKey)?;
    let verifying_key =
        VerifyingKey::from_bytes(&key_array).map_err(|_| LicenseError::InvalidPublicKey)?;

    // Decode the signature
    let sig_bytes = b64
        .decode(&license_file.signature)
        .map_err(|_| LicenseError::InvalidSignature)?;
    let sig_array: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| LicenseError::InvalidSignature)?;
    let signature = Signature::from_bytes(&sig_array);

    // Verify
    verifying_key
        .verify(license_file.payload.as_bytes(), &signature)
        .map_err(|_| LicenseError::SignatureMismatch)?;

    // Parse the payload
    let payload: LicensePayload = serde_json::from_str(&license_file.payload)
        .map_err(|e| LicenseError::InvalidJson(format!("payload: {}", e)))?;

    Ok(payload)
}

/// Check that the license is active and not expired.
pub fn verify_status_and_expiry(payload: &LicensePayload) -> Result<(), LicenseError> {
    if payload.status != "active" {
        return Err(LicenseError::LicenseNotActive(payload.status.clone()));
    }

    // ISO 8601 string comparison works for date ordering
    if let Some(ref expiry) = payload.expiry_date {
        let now = now_iso8601();
        if now > *expiry {
            return Err(LicenseError::LicenseExpired(expiry.clone()));
        }
    }

    Ok(())
}

/// Full license verification from a JSON string and public key.
///
/// Steps:
/// 1. Verify Ed25519 signature
/// 2. Check status is "active"
/// 3. Check expiry date
/// 4. Phone-home to activation server (if `activation_url` is set and `phone-home` feature is enabled)
pub fn verify_license_json_with_key(
    license_json: &str,
    public_key_b64: &str,
) -> Result<LicensePayload, LicenseError> {
    let payload = verify_signature(license_json, public_key_b64)?;
    verify_status_and_expiry(&payload)?;

    #[cfg(feature = "phone-home")]
    if payload.activation_url.is_some() {
        // Phone-home without caching (no filesystem path available)
        phone_home::phone_home(&payload, public_key_b64)?;
    }

    Ok(payload)
}

/// Full license verification from namespace and public key.
///
/// Steps:
/// 1. Discover and load license file
/// 2. Verify Ed25519 signature
/// 3. Check status is "active"
/// 4. Check expiry date
/// 5. Phone-home to activation server (if `activation_url` is set and `phone-home` feature is enabled)
///
/// When phone-home is enabled, the signed validation token is cached alongside
/// the license file for offline grace periods. The cached token is
/// cryptographically verified on reload to prevent forgery.
pub fn verify_license_with_key(
    namespace: &str,
    public_key_b64: &str,
) -> Result<LicensePayload, LicenseError> {
    let (json, path) = load_license_file(namespace)?;
    let payload = verify_signature(&json, public_key_b64)?;
    verify_status_and_expiry(&payload)?;

    #[cfg(feature = "phone-home")]
    if payload.activation_url.is_some() {
        let cache_dir = path.parent().unwrap_or(std::path::Path::new("."));
        match phone_home::phone_home(&payload, public_key_b64) {
            Ok((_token, raw_token)) => {
                phone_home::cache_token(cache_dir, &raw_token);
            }
            Err(e) => {
                // Grace period: load cached token and re-verify its signature
                if let Some(_cached) =
                    phone_home::load_cached_token(cache_dir, public_key_b64, &payload.license_id)
                {
                    eprintln!(
                        "[runlicense] phone-home failed, using cached token (signature verified)"
                    );
                    return Ok(payload);
                }
                return Err(e);
            }
        }
    }

    let _ = path;

    Ok(payload)
}

/// Get the current time as an ISO 8601 string (UTC).
///
/// Uses a minimal implementation to avoid heavy datetime dependencies.
pub(crate) fn now_iso8601() -> String {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    timestamp_to_iso8601(duration.as_secs())
}

/// Convert a Unix timestamp to an ISO 8601 string (UTC).
pub(crate) fn timestamp_to_iso8601(secs: u64) -> String {
    let days = secs / 86400;
    let time_secs = secs % 86400;
    let hours = time_secs / 3600;
    let minutes = (time_secs % 3600) / 60;
    let seconds = time_secs % 60;

    let (year, month, day) = days_to_ymd(days);

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hours, minutes, seconds
    )
}

/// Convert days since Unix epoch to (year, month, day).
///
/// Algorithm from <http://howardhinnant.github.io/date_algorithms.html>
fn days_to_ymd(days_since_epoch: u64) -> (u64, u64, u64) {
    let z = days_since_epoch + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}
