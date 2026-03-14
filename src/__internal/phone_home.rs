use crate::types::{LicenseError, LicensePayload, ValidationToken};
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use std::path::Path;
use std::time::Duration;

/// Request timeout for phone-home validation.
const PHONE_HOME_TIMEOUT: Duration = Duration::from_secs(30);

/// Perform phone-home validation against the activation server.
///
/// Returns the validated token and the raw signed token string for caching.
pub(crate) fn phone_home(
    payload: &LicensePayload,
    public_key_b64: &str,
) -> Result<(ValidationToken, String), LicenseError> {
    let activation_url = payload
        .activation_url
        .as_deref()
        .ok_or(LicenseError::NoActivationUrl)?;

    let nonce = generate_nonce();

    let body = serde_json::json!({ "nonce": nonce });

    let agent = ureq::AgentBuilder::new()
        .timeout(PHONE_HOME_TIMEOUT)
        .build();

    let response = match agent
        .post(activation_url)
        .set("Content-Type", "application/json")
        .send_string(&body.to_string())
    {
        Ok(resp) => resp,
        Err(ureq::Error::Status(code, resp)) => {
            let body = resp.into_string().unwrap_or_default();
            return Err(LicenseError::ServerRejected(format!(
                "HTTP {} — {}",
                code, body
            )));
        }
        Err(e) => return Err(LicenseError::PhoneHomeFailed(e.to_string())),
    };

    let response_str = response
        .into_string()
        .map_err(|e| LicenseError::PhoneHomeFailed(e.to_string()))?;
    let response_body: serde_json::Value = serde_json::from_str(&response_str)
        .map_err(|e| LicenseError::PhoneHomeFailed(e.to_string()))?;

    let token_str = response_body["token"]
        .as_str()
        .ok_or(LicenseError::InvalidValidationToken)?;

    // Parse and verify the token (format: base64(payload).base64(signature))
    let token = verify_token(token_str, public_key_b64, &nonce, &payload.license_id)?;

    Ok((token, token_str.to_string()))
}

/// Verify a signed validation token from the server.
pub(crate) fn verify_token(
    token_str: &str,
    public_key_b64: &str,
    expected_nonce: &str,
    expected_license_id: &str,
) -> Result<ValidationToken, LicenseError> {
    let b64 = base64::engine::general_purpose::STANDARD;

    let parts: Vec<&str> = token_str.splitn(2, '.').collect();
    if parts.len() != 2 {
        return Err(LicenseError::InvalidValidationToken);
    }

    let token_payload_bytes = b64
        .decode(parts[0])
        .map_err(|_| LicenseError::InvalidValidationToken)?;
    let token_sig_bytes = b64
        .decode(parts[1])
        .map_err(|_| LicenseError::InvalidValidationToken)?;

    // Verify signature
    let key_bytes = b64
        .decode(public_key_b64.trim())
        .map_err(|_| LicenseError::InvalidValidationToken)?;
    let key_array: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| LicenseError::InvalidValidationToken)?;
    let verifying_key =
        VerifyingKey::from_bytes(&key_array).map_err(|_| LicenseError::InvalidValidationToken)?;
    let sig_array: [u8; 64] = token_sig_bytes
        .try_into()
        .map_err(|_| LicenseError::InvalidValidationToken)?;
    let signature = Signature::from_bytes(&sig_array);

    verifying_key
        .verify(&token_payload_bytes, &signature)
        .map_err(|_| LicenseError::InvalidValidationToken)?;

    // Parse token payload
    let token_payload_str =
        String::from_utf8(token_payload_bytes).map_err(|_| LicenseError::InvalidValidationToken)?;
    let token: ValidationToken = serde_json::from_str(&token_payload_str)
        .map_err(|_| LicenseError::InvalidValidationToken)?;

    // Validate nonce
    if token.nonce != expected_nonce {
        return Err(LicenseError::ValidationTokenNonceMismatch);
    }

    // Validate license ID
    if token.license_id != expected_license_id {
        return Err(LicenseError::ValidationTokenLicenseMismatch);
    }

    // Validate expiry
    let now = super::now_iso8601();
    if token.expires_at <= now {
        return Err(LicenseError::ValidationTokenExpired);
    }

    Ok(token)
}

/// Generate a hex-encoded random nonce.
fn generate_nonce() -> String {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).expect("failed to generate random nonce");
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Cache the raw signed token string to disk.
///
/// We store the original signed token (not parsed JSON) so that on reload
/// we can re-verify the signature, preventing forgery of cached tokens.
pub(crate) fn cache_token(cache_dir: &Path, raw_token: &str) {
    let path = cache_dir.join(".runlicense_token");
    let _ = std::fs::write(&path, raw_token);
}

/// Load and cryptographically verify a cached token from disk.
///
/// The cached file contains the raw signed token string (`base64.base64`).
/// We re-verify the signature before trusting it, so an attacker who writes
/// a forged token file gains nothing.
pub(crate) fn load_cached_token(
    cache_dir: &Path,
    public_key_b64: &str,
    expected_license_id: &str,
) -> Option<ValidationToken> {
    let path = cache_dir.join(".runlicense_token");
    let raw_token = std::fs::read_to_string(&path).ok()?;

    // Re-verify the signature — skip nonce check since this is a cached token
    // and the nonce was already validated when it was first received.
    let b64 = base64::engine::general_purpose::STANDARD;

    let parts: Vec<&str> = raw_token.trim().splitn(2, '.').collect();
    if parts.len() != 2 {
        return None;
    }

    let token_payload_bytes = b64.decode(parts[0]).ok()?;
    let token_sig_bytes = b64.decode(parts[1]).ok()?;

    // Verify signature
    let key_bytes = b64.decode(public_key_b64.trim()).ok()?;
    let key_array: [u8; 32] = key_bytes.try_into().ok()?;
    let verifying_key = VerifyingKey::from_bytes(&key_array).ok()?;
    let sig_array: [u8; 64] = token_sig_bytes.try_into().ok()?;
    let signature = Signature::from_bytes(&sig_array);

    verifying_key
        .verify(&token_payload_bytes, &signature)
        .ok()?;

    // Parse and validate
    let token_str = String::from_utf8(token_payload_bytes).ok()?;
    let token: ValidationToken = serde_json::from_str(&token_str).ok()?;

    // Verify license ID matches
    if token.license_id != expected_license_id {
        return None;
    }

    // Verify not expired
    let now = super::now_iso8601();
    if token.expires_at <= now {
        return None;
    }

    Some(token)
}
