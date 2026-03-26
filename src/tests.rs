#[cfg(test)]
mod tests {
    use crate::__internal::*;
    use crate::types::*;
    use base64::Engine;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

    // ── Test helpers ──────────────────────────────────────────────────

    fn gen_keypair() -> (SigningKey, String) {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key_b64 = B64.encode(signing_key.verifying_key().to_bytes());
        (signing_key, public_key_b64)
    }

    fn make_license(signing_key: &SigningKey, payload: &str) -> String {
        let signature = signing_key.sign(payload.as_bytes());
        let sig_b64 = B64.encode(signature.to_bytes());
        serde_json::json!({
            "payload": payload,
            "signature": sig_b64,
        })
        .to_string()
    }

    fn make_payload_json(
        status: &str,
        expiry_date: Option<&str>,
        features: Option<serde_json::Value>,
        activation_url: Option<&str>,
    ) -> String {
        serde_json::json!({
            "license_id": "lic_test_123",
            "product_id": "prod_test",
            "customer_id": "cust_test",
            "status": status,
            "expiry_date": expiry_date,
            "allowed_features": features,
            "usage_limit": null,
            "token_ttl": 3600,
            "activation_url": activation_url,
        })
        .to_string()
    }

    fn make_active_license(signing_key: &SigningKey) -> String {
        let payload = make_payload_json("active", None, None, None);
        make_license(signing_key, &payload)
    }

    fn make_active_license_with_expiry(signing_key: &SigningKey, expiry: &str) -> String {
        let payload = make_payload_json("active", Some(expiry), None, None);
        make_license(signing_key, &payload)
    }

    fn make_active_license_with_features(
        signing_key: &SigningKey,
        features: serde_json::Value,
    ) -> String {
        let payload = make_payload_json("active", None, Some(features), None);
        make_license(signing_key, &payload)
    }

    /// Set the RUNLICENSE_DIR env var for the duration of a closure.
    ///
    /// SAFETY: Caller must ensure no concurrent env var access (use #[serial_test::serial]).
    fn with_runlicense_dir<T>(dir: &str, f: impl FnOnce() -> T) -> T {
        // SAFETY: These tests run serially via #[serial_test::serial],
        // preventing concurrent env var mutation.
        unsafe { std::env::set_var("RUNLICENSE_DIR", dir) };
        let result = f();
        unsafe { std::env::remove_var("RUNLICENSE_DIR") };
        result
    }

    #[cfg(feature = "phone-home")]
    fn make_validation_token(
        signing_key: &SigningKey,
        license_id: &str,
        nonce: &str,
        expires_at: &str,
    ) -> String {
        let token_payload = serde_json::json!({
            "license_id": license_id,
            "nonce": nonce,
            "issued_at": now_iso8601(),
            "expires_at": expires_at,
        });
        let payload_bytes = token_payload.to_string().into_bytes();
        let signature = signing_key.sign(&payload_bytes);
        format!(
            "{}.{}",
            B64.encode(&payload_bytes),
            B64.encode(signature.to_bytes())
        )
    }

    // ── Signature verification tests ──────────────────────────────────

    #[test]
    fn valid_signature_roundtrip() {
        let (sk, pk) = gen_keypair();
        let license = make_active_license(&sk);
        let result = verify_signature(&license, &pk);
        assert!(result.is_ok());
        let payload = result.unwrap();
        assert_eq!(payload.license_id, "lic_test_123");
        assert_eq!(payload.product_id, "prod_test");
        assert_eq!(payload.customer_id, "cust_test");
        assert_eq!(payload.status, "active");
    }

    #[test]
    fn wrong_key_rejected() {
        let (sk, _pk) = gen_keypair();
        let (_sk2, pk2) = gen_keypair();
        let license = make_active_license(&sk);
        let result = verify_signature(&license, &pk2);
        assert!(matches!(result, Err(LicenseError::SignatureMismatch)));
    }

    #[test]
    fn tampered_payload_rejected() {
        let (sk, pk) = gen_keypair();
        let license = make_active_license(&sk);

        let mut parsed: serde_json::Value = serde_json::from_str(&license).unwrap();
        parsed["payload"] = serde_json::Value::String(
            make_payload_json("active", None, None, None).replace("lic_test_123", "lic_stolen"),
        );
        let tampered = parsed.to_string();

        let result = verify_signature(&tampered, &pk);
        assert!(matches!(result, Err(LicenseError::SignatureMismatch)));
    }

    #[test]
    fn tampered_signature_rejected() {
        let (sk, pk) = gen_keypair();
        let license = make_active_license(&sk);

        let mut parsed: serde_json::Value = serde_json::from_str(&license).unwrap();
        let sig = parsed["signature"].as_str().unwrap().to_string();
        let mut sig_chars: Vec<char> = sig.chars().collect();
        let last = sig_chars.last_mut().unwrap();
        *last = if *last == 'A' { 'B' } else { 'A' };
        parsed["signature"] = serde_json::Value::String(sig_chars.into_iter().collect());
        let tampered = parsed.to_string();

        let result = verify_signature(&tampered, &pk);
        assert!(result.is_err());
    }

    #[test]
    fn malformed_json_rejected() {
        let (_sk, pk) = gen_keypair();
        let result = verify_signature("not json", &pk);
        assert!(matches!(result, Err(LicenseError::InvalidJson(_))));
    }

    #[test]
    fn missing_payload_field_rejected() {
        let (_sk, pk) = gen_keypair();
        let json = r#"{"signature": "abc"}"#;
        let result = verify_signature(json, &pk);
        assert!(matches!(result, Err(LicenseError::InvalidJson(_))));
    }

    #[test]
    fn missing_signature_field_rejected() {
        let (_sk, pk) = gen_keypair();
        let json = r#"{"payload": "abc"}"#;
        let result = verify_signature(json, &pk);
        assert!(matches!(result, Err(LicenseError::InvalidJson(_))));
    }

    #[test]
    fn invalid_public_key_rejected() {
        let (sk, _pk) = gen_keypair();
        let license = make_active_license(&sk);

        // Too short
        let result = verify_signature(&license, "dG9vc2hvcnQ=");
        assert!(matches!(result, Err(LicenseError::InvalidPublicKey)));

        // Not valid base64
        let result = verify_signature(&license, "!!!not-base64!!!");
        assert!(matches!(result, Err(LicenseError::InvalidPublicKey)));

        // Empty
        let result = verify_signature(&license, "");
        assert!(matches!(result, Err(LicenseError::InvalidPublicKey)));
    }

    #[test]
    fn invalid_signature_encoding_rejected() {
        let (_sk, pk) = gen_keypair();
        let json = serde_json::json!({
            "payload": make_payload_json("active", None, None, None),
            "signature": "!!!not-base64!!!",
        })
        .to_string();
        let result = verify_signature(&json, &pk);
        assert!(matches!(result, Err(LicenseError::InvalidSignature)));
    }

    #[test]
    fn signature_too_short_rejected() {
        let (_sk, pk) = gen_keypair();
        let json = serde_json::json!({
            "payload": make_payload_json("active", None, None, None),
            "signature": B64.encode(b"tooshort"),
        })
        .to_string();
        let result = verify_signature(&json, &pk);
        assert!(matches!(result, Err(LicenseError::InvalidSignature)));
    }

    #[test]
    fn invalid_payload_json_in_envelope() {
        let (sk, pk) = gen_keypair();
        let license = make_license(&sk, "not a json payload");
        let result = verify_signature(&license, &pk);
        assert!(matches!(result, Err(LicenseError::InvalidJson(_))));
    }

    #[test]
    fn public_key_with_whitespace_accepted() {
        let (sk, pk) = gen_keypair();
        let license = make_active_license(&sk);
        let pk_with_whitespace = format!("  {}  \n", pk);
        let result = verify_signature(&license, &pk_with_whitespace);
        assert!(result.is_ok());
    }

    // ── Status and expiry tests ───────────────────────────────────────

    #[test]
    fn active_status_accepted() {
        let (sk, pk) = gen_keypair();
        let license = make_active_license(&sk);
        let result = verify_license_json_with_key(&license, &pk);
        assert!(result.is_ok());
    }

    #[test]
    fn suspended_status_rejected() {
        let (sk, pk) = gen_keypair();
        let payload = make_payload_json("suspended", None, None, None);
        let license = make_license(&sk, &payload);
        let result = verify_license_json_with_key(&license, &pk);
        assert!(matches!(result, Err(LicenseError::LicenseNotActive(s)) if s == "suspended"));
    }

    #[test]
    fn revoked_status_rejected() {
        let (sk, pk) = gen_keypair();
        let payload = make_payload_json("revoked", None, None, None);
        let license = make_license(&sk, &payload);
        let result = verify_license_json_with_key(&license, &pk);
        assert!(matches!(result, Err(LicenseError::LicenseNotActive(s)) if s == "revoked"));
    }

    #[test]
    fn expired_status_rejected() {
        let (sk, pk) = gen_keypair();
        let payload = make_payload_json("expired", None, None, None);
        let license = make_license(&sk, &payload);
        let result = verify_license_json_with_key(&license, &pk);
        assert!(matches!(result, Err(LicenseError::LicenseNotActive(s)) if s == "expired"));
    }

    #[test]
    fn empty_status_rejected() {
        let (sk, pk) = gen_keypair();
        let payload = make_payload_json("", None, None, None);
        let license = make_license(&sk, &payload);
        let result = verify_license_json_with_key(&license, &pk);
        assert!(matches!(result, Err(LicenseError::LicenseNotActive(_))));
    }

    #[test]
    fn future_expiry_accepted() {
        let (sk, pk) = gen_keypair();
        let license = make_active_license_with_expiry(&sk, "2099-12-31T23:59:59Z");
        let result = verify_license_json_with_key(&license, &pk);
        assert!(result.is_ok());
    }

    #[test]
    fn past_expiry_rejected() {
        let (sk, pk) = gen_keypair();
        let license = make_active_license_with_expiry(&sk, "2020-01-01T00:00:00Z");
        let result = verify_license_json_with_key(&license, &pk);
        assert!(
            matches!(result, Err(LicenseError::LicenseExpired(d)) if d == "2020-01-01T00:00:00Z")
        );
    }

    #[test]
    fn null_expiry_accepted() {
        let (sk, pk) = gen_keypair();
        let license = make_active_license(&sk);
        let result = verify_license_json_with_key(&license, &pk);
        assert!(result.is_ok());
    }

    // ── Payload field tests ───────────────────────────────────────────

    #[test]
    fn allowed_features_parsed() {
        let (sk, pk) = gen_keypair();
        let features = serde_json::json!({"pro": true, "max_users": 100});
        let license = make_active_license_with_features(&sk, features.clone());
        let result = verify_license_json_with_key(&license, &pk);
        assert!(result.is_ok());
        let payload = result.unwrap();
        assert_eq!(payload.allowed_features, Some(features));
    }

    #[test]
    fn null_features_accepted() {
        let (sk, pk) = gen_keypair();
        let license = make_active_license(&sk);
        let result = verify_license_json_with_key(&license, &pk);
        let payload = result.unwrap();
        assert!(payload.allowed_features.is_none());
    }

    #[test]
    fn usage_limit_parsed() {
        let (sk, pk) = gen_keypair();
        let payload_str = serde_json::json!({
            "license_id": "lic_test",
            "product_id": "prod_test",
            "customer_id": "cust_test",
            "status": "active",
            "expiry_date": null,
            "allowed_features": null,
            "usage_limit": 5000,
            "token_ttl": null,
            "activation_url": null,
        })
        .to_string();
        let license = make_license(&sk, &payload_str);
        let result = verify_license_json_with_key(&license, &pk);
        let payload = result.unwrap();
        assert_eq!(payload.usage_limit, Some(5000));
    }

    #[test]
    fn activation_url_parsed() {
        let (sk, pk) = gen_keypair();
        let payload_str = make_payload_json(
            "active",
            None,
            None,
            Some("https://api.runlicense.com/activate"),
        );
        let license = make_license(&sk, &payload_str);
        // Use verify_signature to test field parsing without triggering phone-home
        let payload = verify_signature(&license, &pk).unwrap();
        assert_eq!(
            payload.activation_url.as_deref(),
            Some("https://api.runlicense.com/activate")
        );
    }

    // ── Full verification pipeline tests ──────────────────────────────

    #[test]
    fn full_pipeline_valid_license() {
        let (sk, pk) = gen_keypair();
        let license = make_active_license_with_expiry(&sk, "2099-12-31T23:59:59Z");
        let result = verify_license_json_with_key(&license, &pk);
        assert!(result.is_ok());
        let payload = result.unwrap();
        assert_eq!(payload.status, "active");
        assert_eq!(payload.expiry_date.as_deref(), Some("2099-12-31T23:59:59Z"));
    }

    #[test]
    fn full_pipeline_signature_checked_before_status() {
        let (sk, _pk) = gen_keypair();
        let (_sk2, pk2) = gen_keypair();
        let license = make_active_license(&sk);
        let result = verify_license_json_with_key(&license, &pk2);
        assert!(matches!(result, Err(LicenseError::SignatureMismatch)));
    }

    #[test]
    fn full_pipeline_status_checked_before_expiry() {
        let (sk, pk) = gen_keypair();
        let payload = make_payload_json("suspended", Some("2099-12-31T23:59:59Z"), None, None);
        let license = make_license(&sk, &payload);
        let result = verify_license_json_with_key(&license, &pk);
        assert!(matches!(result, Err(LicenseError::LicenseNotActive(_))));
    }

    // ── License file discovery tests ──────────────────────────────────
    //
    // These tests modify process-global state (env vars, CWD) and must
    // run serially to avoid races.

    #[test]
    fn discover_nonexistent_namespace() {
        let result = discover_license_path("nonexistent/namespace");
        assert!(matches!(result, Err(LicenseError::LicenseFileNotFound(_))));
    }

    #[test]
    #[serial_test::serial]
    fn discover_via_env_var() {
        let dir = tempfile::tempdir().unwrap();
        let ns = "testorg/testcrate";
        let license_dir = dir.path().join(ns);
        std::fs::create_dir_all(&license_dir).unwrap();
        std::fs::write(license_dir.join("license.json"), "{}").unwrap();

        let result =
            with_runlicense_dir(dir.path().to_str().unwrap(), || discover_license_path(ns));

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), license_dir.join("license.json"));
    }

    #[test]
    #[serial_test::serial]
    fn discover_via_cwd() {
        let dir = tempfile::tempdir().unwrap();
        let ns = "testorg/testcrate";
        let license_dir = dir.path().join("runlicense").join(ns);
        std::fs::create_dir_all(&license_dir).unwrap();
        std::fs::write(license_dir.join("license.json"), "{}").unwrap();

        let original_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(dir.path()).unwrap();
        let result = discover_license_path(ns);
        std::env::set_current_dir(original_dir).unwrap();

        assert!(result.is_ok());
    }

    #[test]
    #[serial_test::serial]
    fn env_var_takes_precedence_over_cwd() {
        let env_dir = tempfile::tempdir().unwrap();
        let cwd_dir = tempfile::tempdir().unwrap();
        let ns = "testorg/testcrate";

        let env_license_dir = env_dir.path().join(ns);
        std::fs::create_dir_all(&env_license_dir).unwrap();
        std::fs::write(env_license_dir.join("license.json"), r#"{"source":"env"}"#).unwrap();

        let cwd_license_dir = cwd_dir.path().join("runlicense").join(ns);
        std::fs::create_dir_all(&cwd_license_dir).unwrap();
        std::fs::write(cwd_license_dir.join("license.json"), r#"{"source":"cwd"}"#).unwrap();

        let original_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(cwd_dir.path()).unwrap();

        let result = with_runlicense_dir(env_dir.path().to_str().unwrap(), || {
            discover_license_path(ns)
        });

        std::env::set_current_dir(original_dir).unwrap();

        assert!(result.is_ok());
        let path = result.unwrap();
        assert!(path.starts_with(env_dir.path()));
    }

    #[test]
    #[serial_test::serial]
    fn load_and_verify_license_from_disk() {
        let (sk, pk) = gen_keypair();
        let license_json = make_active_license(&sk);

        let dir = tempfile::tempdir().unwrap();
        let ns = "testorg/disktest";
        let license_dir = dir.path().join(ns);
        std::fs::create_dir_all(&license_dir).unwrap();
        std::fs::write(license_dir.join("license.json"), &license_json).unwrap();

        let result = with_runlicense_dir(dir.path().to_str().unwrap(), || {
            verify_license_with_key(ns, &pk)
        });

        assert!(result.is_ok());
        assert_eq!(result.unwrap().license_id, "lic_test_123");
    }

    #[test]
    fn load_unreadable_namespace_fails() {
        let result = verify_license_with_key("does/not/exist", "irrelevant");
        assert!(matches!(result, Err(LicenseError::LicenseFileNotFound(_))));
    }

    // ── Nested namespace tests ────────────────────────────────────────

    #[test]
    #[serial_test::serial]
    fn deeply_nested_namespace() {
        let (sk, pk) = gen_keypair();
        let license_json = make_active_license(&sk);

        let dir = tempfile::tempdir().unwrap();
        let ns = "org/team/subcrate";
        let license_dir = dir.path().join(ns);
        std::fs::create_dir_all(&license_dir).unwrap();
        std::fs::write(license_dir.join("license.json"), &license_json).unwrap();

        let result = with_runlicense_dir(dir.path().to_str().unwrap(), || {
            verify_license_with_key(ns, &pk)
        });

        assert!(result.is_ok());
    }

    #[test]
    fn multiple_namespaces_coexist() {
        let (sk1, pk1) = gen_keypair();
        let (sk2, pk2) = gen_keypair();

        let license1 = make_active_license(&sk1);
        let payload2 = serde_json::json!({
            "license_id": "lic_other",
            "product_id": "prod_other",
            "customer_id": "cust_other",
            "status": "active",
            "expiry_date": null,
            "allowed_features": null,
            "usage_limit": null,
            "token_ttl": null,
            "activation_url": null,
        })
        .to_string();
        let license2 = make_license(&sk2, &payload2);

        let r1 = verify_license_json_with_key(&license1, &pk1);
        let r2 = verify_license_json_with_key(&license2, &pk2);

        assert!(r1.is_ok());
        assert_eq!(r1.unwrap().license_id, "lic_test_123");
        assert!(r2.is_ok());
        assert_eq!(r2.unwrap().license_id, "lic_other");

        // Cross-key verification should fail
        assert!(matches!(
            verify_license_json_with_key(&license1, &pk2),
            Err(LicenseError::SignatureMismatch)
        ));
        assert!(matches!(
            verify_license_json_with_key(&license2, &pk1),
            Err(LicenseError::SignatureMismatch)
        ));
    }

    #[test]
    #[serial_test::serial]
    fn wrong_key_for_namespace_rejected() {
        let (sk1, _pk1) = gen_keypair();
        let (_sk2, pk2) = gen_keypair();
        let license = make_active_license(&sk1);

        let dir = tempfile::tempdir().unwrap();
        let ns = "testorg/wrongkey";
        let license_dir = dir.path().join(ns);
        std::fs::create_dir_all(&license_dir).unwrap();
        std::fs::write(license_dir.join("license.json"), &license).unwrap();

        let result = with_runlicense_dir(dir.path().to_str().unwrap(), || {
            verify_license_with_key(ns, &pk2)
        });

        assert!(matches!(result, Err(LicenseError::SignatureMismatch)));
    }

    // ── ISO 8601 / date tests ─────────────────────────────────────────

    #[test]
    fn now_iso8601_format() {
        let now = now_iso8601();
        assert_eq!(now.len(), 20);
        assert!(now.ends_with('Z'));
        assert_eq!(&now[4..5], "-");
        assert_eq!(&now[7..8], "-");
        assert_eq!(&now[10..11], "T");
        assert_eq!(&now[13..14], ":");
        assert_eq!(&now[16..17], ":");
    }

    #[test]
    fn now_iso8601_reasonable_year() {
        let now = now_iso8601();
        let year: u32 = now[0..4].parse().unwrap();
        assert!(year >= 2024 && year <= 2100);
    }

    #[test]
    fn iso8601_string_comparison_works_for_ordering() {
        assert!("2020-01-01T00:00:00Z" < "2025-06-15T12:00:00Z");
        assert!("2025-06-15T12:00:00Z" < "2099-12-31T23:59:59Z");
        assert!("2025-01-01T00:00:00Z" < "2025-01-01T00:00:01Z");
        assert!("2025-01-01T23:59:59Z" < "2025-01-02T00:00:00Z");
    }

    #[test]
    fn timestamp_to_iso8601_known_dates() {
        // Unix epoch
        assert_eq!(timestamp_to_iso8601(0), "1970-01-01T00:00:00Z");
        // 2000-01-01 00:00:00 UTC
        assert_eq!(timestamp_to_iso8601(946684800), "2000-01-01T00:00:00Z");
        // 2024-01-01 00:00:00 UTC
        assert_eq!(timestamp_to_iso8601(1704067200), "2024-01-01T00:00:00Z");
        // 2024-02-29 12:30:45 UTC (leap year)
        assert_eq!(timestamp_to_iso8601(1709209845), "2024-02-29T12:30:45Z");
        // 2025-12-31 23:59:59 UTC
        assert_eq!(timestamp_to_iso8601(1767225599), "2025-12-31T23:59:59Z");
    }

    // ── Error display tests ───────────────────────────────────────────

    #[test]
    fn error_display_messages() {
        let err = LicenseError::LicenseFileNotFound("some/path".to_string());
        assert_eq!(err.to_string(), "license file not found: some/path");

        let err = LicenseError::SignatureMismatch;
        assert!(err.to_string().contains("signature verification failed"));

        let err = LicenseError::LicenseNotActive("revoked".to_string());
        assert!(err.to_string().contains("revoked"));

        let err = LicenseError::LicenseExpired("2024-01-01T00:00:00Z".to_string());
        assert!(err.to_string().contains("2024-01-01"));
    }

    #[test]
    fn error_is_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(LicenseError::InvalidPublicKey);
        assert_eq!(err.to_string(), "invalid public key");
    }

    // ── Validation token tests (phone-home feature) ───────────────────

    #[cfg(feature = "phone-home")]
    mod phone_home_tests {
        use super::*;
        use crate::__internal::phone_home::{
            cache_token, extract_token, load_cached_token, verify_token,
        };

        // ── Response envelope parsing tests ──────────────────────────────

        #[test]
        fn extract_token_from_valid_envelope() {
            let response = serde_json::json!({
                "meta": {
                    "responseCode": 200,
                    "limit": 20,
                    "offset": 0,
                    "message": "OK"
                },
                "data": {
                    "token": "test_token_value",
                    "expires_at": "2026-03-26T03:11:03+00:00",
                    "activations_remaining": 1234
                }
            });
            let token = extract_token(&response).unwrap();
            assert_eq!(token, "test_token_value");
        }

        #[test]
        fn extract_token_missing_data_field() {
            let response = serde_json::json!({
                "meta": { "responseCode": 200 }
            });
            let result = extract_token(&response);
            assert!(matches!(result, Err(LicenseError::InvalidValidationToken)));
        }

        #[test]
        fn extract_token_missing_token_field() {
            let response = serde_json::json!({
                "data": {
                    "expires_at": "2026-03-26T03:11:03+00:00"
                }
            });
            let result = extract_token(&response);
            assert!(matches!(result, Err(LicenseError::InvalidValidationToken)));
        }

        #[test]
        fn extract_token_rejects_old_flat_format() {
            let response = serde_json::json!({
                "token": "flat_token_value"
            });
            let result = extract_token(&response);
            assert!(matches!(result, Err(LicenseError::InvalidValidationToken)));
        }

        // ── Token verification tests ─────────────────────────────────────

        #[test]
        fn valid_token_accepted() {
            let (sk, pk) = gen_keypair();
            let nonce = "abc123";
            let license_id = "lic_test_123";
            let token_str = make_validation_token(&sk, license_id, nonce, "2099-12-31T23:59:59Z");
            let result = verify_token(&token_str, &pk, nonce, license_id);
            assert!(result.is_ok());
            let token = result.unwrap();
            assert_eq!(token.license_id, license_id);
            assert_eq!(token.nonce, nonce);
            assert_eq!(token.expires_at, "2099-12-31T23:59:59Z");
        }

        #[test]
        fn wrong_signature_rejected() {
            let (sk, _pk) = gen_keypair();
            let (_sk2, pk2) = gen_keypair();
            let token_str =
                make_validation_token(&sk, "lic_test", "nonce1", "2099-12-31T23:59:59Z");
            let result = verify_token(&token_str, &pk2, "nonce1", "lic_test");
            assert!(matches!(result, Err(LicenseError::InvalidValidationToken)));
        }

        #[test]
        fn nonce_mismatch_rejected() {
            let (sk, pk) = gen_keypair();
            let token_str =
                make_validation_token(&sk, "lic_test", "correct_nonce", "2099-12-31T23:59:59Z");
            let result = verify_token(&token_str, &pk, "wrong_nonce", "lic_test");
            assert!(matches!(
                result,
                Err(LicenseError::ValidationTokenNonceMismatch)
            ));
        }

        #[test]
        fn license_id_mismatch_rejected() {
            let (sk, pk) = gen_keypair();
            let token_str =
                make_validation_token(&sk, "lic_original", "nonce1", "2099-12-31T23:59:59Z");
            let result = verify_token(&token_str, &pk, "nonce1", "lic_different");
            assert!(matches!(
                result,
                Err(LicenseError::ValidationTokenLicenseMismatch)
            ));
        }

        #[test]
        fn expired_token_rejected() {
            let (sk, pk) = gen_keypair();
            let token_str =
                make_validation_token(&sk, "lic_test", "nonce1", "2020-01-01T00:00:00Z");
            let result = verify_token(&token_str, &pk, "nonce1", "lic_test");
            assert!(matches!(result, Err(LicenseError::ValidationTokenExpired)));
        }

        #[test]
        fn malformed_token_rejected() {
            let (_sk, pk) = gen_keypair();

            // No dot separator
            let result = verify_token("nodot", &pk, "n", "l");
            assert!(matches!(result, Err(LicenseError::InvalidValidationToken)));

            // Invalid base64
            let result = verify_token("!!!.!!!", &pk, "n", "l");
            assert!(matches!(result, Err(LicenseError::InvalidValidationToken)));

            // Valid base64 but not a valid token payload
            let result = verify_token(
                &format!("{}.{}", B64.encode(b"notjson"), B64.encode(b"notsig")),
                &pk,
                "n",
                "l",
            );
            assert!(matches!(result, Err(LicenseError::InvalidValidationToken)));
        }

        // ── Token caching tests (signed tokens) ──────────────────────

        #[test]
        fn cache_and_load_signed_token() {
            let (sk, pk) = gen_keypair();
            let dir = tempfile::tempdir().unwrap();
            let license_id = "lic_cache_test";
            let raw_token =
                make_validation_token(&sk, license_id, "nonce123", "2099-12-31T23:59:59Z");

            cache_token(dir.path(), &raw_token);
            let loaded = load_cached_token(dir.path(), &pk, license_id);

            assert!(loaded.is_some());
            let loaded = loaded.unwrap();
            assert_eq!(loaded.license_id, license_id);
            assert_eq!(loaded.expires_at, "2099-12-31T23:59:59Z");
        }

        #[test]
        fn load_missing_cached_token_returns_none() {
            let (_sk, pk) = gen_keypair();
            let dir = tempfile::tempdir().unwrap();
            let loaded = load_cached_token(dir.path(), &pk, "lic_test");
            assert!(loaded.is_none());
        }

        #[test]
        fn load_corrupt_cached_token_returns_none() {
            let (_sk, pk) = gen_keypair();
            let dir = tempfile::tempdir().unwrap();
            std::fs::write(dir.path().join(".runlicense_token"), "not valid data").unwrap();
            let loaded = load_cached_token(dir.path(), &pk, "lic_test");
            assert!(loaded.is_none());
        }

        #[test]
        fn forged_unsigned_cached_token_rejected() {
            let (_sk, pk) = gen_keypair();
            let dir = tempfile::tempdir().unwrap();
            // Attacker writes plain JSON (the old vulnerable format)
            let forged = serde_json::json!({
                "license_id": "lic_stolen",
                "nonce": "fake",
                "issued_at": "2025-01-01T00:00:00Z",
                "expires_at": "2099-12-31T23:59:59Z",
            });
            std::fs::write(dir.path().join(".runlicense_token"), forged.to_string()).unwrap();
            let loaded = load_cached_token(dir.path(), &pk, "lic_stolen");
            assert!(loaded.is_none());
        }

        #[test]
        fn cached_token_wrong_key_rejected() {
            let (sk, _pk) = gen_keypair();
            let (_sk2, pk2) = gen_keypair();
            let dir = tempfile::tempdir().unwrap();
            let raw_token =
                make_validation_token(&sk, "lic_test", "nonce1", "2099-12-31T23:59:59Z");

            cache_token(dir.path(), &raw_token);
            // Load with a different key — should fail signature check
            let loaded = load_cached_token(dir.path(), &pk2, "lic_test");
            assert!(loaded.is_none());
        }

        #[test]
        fn cached_token_wrong_license_id_rejected() {
            let (sk, pk) = gen_keypair();
            let dir = tempfile::tempdir().unwrap();
            let raw_token =
                make_validation_token(&sk, "lic_original", "nonce1", "2099-12-31T23:59:59Z");

            cache_token(dir.path(), &raw_token);
            // Load expecting a different license ID
            let loaded = load_cached_token(dir.path(), &pk, "lic_different");
            assert!(loaded.is_none());
        }

        #[test]
        fn cached_token_expired_rejected() {
            let (sk, pk) = gen_keypair();
            let dir = tempfile::tempdir().unwrap();
            let raw_token =
                make_validation_token(&sk, "lic_test", "nonce1", "2020-01-01T00:00:00Z");

            cache_token(dir.path(), &raw_token);
            let loaded = load_cached_token(dir.path(), &pk, "lic_test");
            assert!(loaded.is_none());
        }

        #[test]
        fn cache_overwrites_previous_token() {
            let (sk, pk) = gen_keypair();
            let dir = tempfile::tempdir().unwrap();

            let raw1 = make_validation_token(&sk, "lic_first", "n1", "2099-01-01T00:00:00Z");
            cache_token(dir.path(), &raw1);

            let raw2 = make_validation_token(&sk, "lic_second", "n2", "2099-06-01T00:00:00Z");
            cache_token(dir.path(), &raw2);

            let loaded = load_cached_token(dir.path(), &pk, "lic_second").unwrap();
            assert_eq!(loaded.license_id, "lic_second");

            // First token's license_id no longer matches
            let loaded_old = load_cached_token(dir.path(), &pk, "lic_first");
            assert!(loaded_old.is_none());
        }
    }

    // ── Edge case tests ───────────────────────────────────────────────

    #[test]
    fn empty_license_json_rejected() {
        let (_sk, pk) = gen_keypair();
        let result = verify_license_json_with_key("", &pk);
        assert!(matches!(result, Err(LicenseError::InvalidJson(_))));
    }

    #[test]
    fn empty_object_rejected() {
        let (_sk, pk) = gen_keypair();
        let result = verify_license_json_with_key("{}", &pk);
        assert!(matches!(result, Err(LicenseError::InvalidJson(_))));
    }

    #[test]
    fn unicode_in_payload_fields() {
        let (sk, pk) = gen_keypair();
        let payload = serde_json::json!({
            "license_id": "lic_test",
            "product_id": "prod_unicode",
            "customer_id": "cust_test",
            "status": "active",
            "expiry_date": null,
            "allowed_features": {"name": "Acme Corp"},
            "usage_limit": null,
            "token_ttl": null,
            "activation_url": null,
        })
        .to_string();
        let license = make_license(&sk, &payload);
        let result = verify_license_json_with_key(&license, &pk);
        assert!(result.is_ok());
        let p = result.unwrap();
        assert_eq!(p.license_id, "lic_test");
        assert_eq!(p.product_id, "prod_unicode");
    }

    #[test]
    fn large_features_object() {
        let (sk, pk) = gen_keypair();
        let mut features = serde_json::Map::new();
        for i in 0..100 {
            features.insert(
                format!("feature_{}", i),
                serde_json::Value::Bool(i % 2 == 0),
            );
        }
        let license =
            make_active_license_with_features(&sk, serde_json::Value::Object(features.clone()));
        let result = verify_license_json_with_key(&license, &pk);
        assert!(result.is_ok());
        let p = result.unwrap();
        let f = p.allowed_features.unwrap();
        assert_eq!(f.as_object().unwrap().len(), 100);
    }

    #[test]
    fn deterministic_signing() {
        let (sk, pk) = gen_keypair();
        let payload = make_payload_json("active", None, None, None);
        let license1 = make_license(&sk, &payload);
        let license2 = make_license(&sk, &payload);
        assert_eq!(license1, license2);

        assert!(verify_signature(&license1, &pk).is_ok());
        assert!(verify_signature(&license2, &pk).is_ok());
    }

    #[test]
    fn different_keys_produce_different_signatures() {
        let (sk1, _pk1) = gen_keypair();
        let (sk2, _pk2) = gen_keypair();
        let payload = make_payload_json("active", None, None, None);
        let license1 = make_license(&sk1, &payload);
        let license2 = make_license(&sk2, &payload);
        assert_ne!(license1, license2);
    }

    // ── Namespace validation tests ────────────────────────────────────

    #[test]
    fn namespace_path_traversal_rejected() {
        let result = discover_license_path("../../etc");
        assert!(
            matches!(result, Err(LicenseError::LicenseFileNotFound(msg)) if msg.contains("invalid namespace"))
        );
    }

    #[test]
    fn namespace_dot_component_rejected() {
        let result = discover_license_path("org/./crate");
        assert!(
            matches!(result, Err(LicenseError::LicenseFileNotFound(msg)) if msg.contains("invalid namespace"))
        );
    }

    #[test]
    fn namespace_double_dot_rejected() {
        let result = discover_license_path("org/../other");
        assert!(
            matches!(result, Err(LicenseError::LicenseFileNotFound(msg)) if msg.contains("invalid namespace"))
        );
    }

    #[test]
    fn namespace_empty_segment_rejected() {
        let result = discover_license_path("org//crate");
        assert!(
            matches!(result, Err(LicenseError::LicenseFileNotFound(msg)) if msg.contains("invalid namespace"))
        );
    }

    #[test]
    fn namespace_valid_formats_accepted() {
        // These should not error on validation (they'll fail on file-not-found instead)
        let result = discover_license_path("myorg/mycrate");
        assert!(
            matches!(result, Err(LicenseError::LicenseFileNotFound(msg)) if !msg.contains("invalid namespace"))
        );

        let result = discover_license_path("org/team/subcrate");
        assert!(
            matches!(result, Err(LicenseError::LicenseFileNotFound(msg)) if !msg.contains("invalid namespace"))
        );

        let result = discover_license_path("simple");
        assert!(
            matches!(result, Err(LicenseError::LicenseFileNotFound(msg)) if !msg.contains("invalid namespace"))
        );
    }
}
