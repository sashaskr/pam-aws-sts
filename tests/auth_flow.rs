//! Integration tests for the authenticate flow.
//!
//! These tests exercise the full authentication pipeline up to (but not including)
//! the actual STS HTTP call. They validate:
//! - Config loading from a real file
//! - Credential JSON parsing
//! - Expiration pre-check
//! - Proper error reporting for malformed inputs

use pam_aws_sts::{authenticate, AuthResult};
use std::io::Write;
use tempfile::NamedTempFile;

fn write_config(content: &str) -> NamedTempFile {
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(content.as_bytes()).unwrap();
    f.flush().unwrap();
    f
}

const VALID_CONFIG: &str = r#"
[aws]
region = "eu-central-1"
allowed_account_ids = ["111122223333"]
timeout_secs = 2
grace_period_secs = 30

[role_mapping]
"YubiKeyKMSRole" = ["pg_admin"]

[logging]
level = "debug"
facility = "auth"
"#;

#[test]
fn test_garbage_password_returns_invalid_credentials() {
    let config_file = write_config(VALID_CONFIG);
    let result = authenticate("pg_admin", "not-json-at-all", config_file.path().to_str().unwrap());
    assert!(matches!(result, AuthResult::InvalidCredentials(_)));
}

#[test]
fn test_empty_password_returns_invalid_credentials() {
    let config_file = write_config(VALID_CONFIG);
    let result = authenticate("pg_admin", "", config_file.path().to_str().unwrap());
    assert!(matches!(result, AuthResult::InvalidCredentials(_)));
}

#[test]
fn test_missing_fields_returns_invalid_credentials() {
    let config_file = write_config(VALID_CONFIG);
    let json = r#"{"AccessKeyId": "ASIA123"}"#;
    let result = authenticate("pg_admin", json, config_file.path().to_str().unwrap());
    assert!(matches!(result, AuthResult::InvalidCredentials(_)));
}

#[test]
fn test_expired_credentials_rejected_before_sts_call() {
    let config_file = write_config(VALID_CONFIG);
    let json = r#"{
        "AccessKeyId": "ASIAEXAMPLE",
        "SecretAccessKey": "secret",
        "SessionToken": "token",
        "Expiration": "2020-01-01T00:00:00Z"
    }"#;
    let result = authenticate("pg_admin", json, config_file.path().to_str().unwrap());
    assert!(matches!(result, AuthResult::InvalidCredentials(_)));
}

#[test]
fn test_missing_config_file_returns_error() {
    let json = r#"{
        "AccessKeyId": "ASIAEXAMPLE",
        "SecretAccessKey": "secret",
        "SessionToken": "token",
        "Expiration": "2099-12-31T23:59:59Z"
    }"#;
    let result = authenticate("pg_admin", json, "/nonexistent/path/config.toml");
    assert!(matches!(result, AuthResult::Error(_)));
}

#[test]
fn test_invalid_config_returns_error() {
    let config_file = write_config("not valid toml [[[");
    let json = r#"{
        "AccessKeyId": "ASIAEXAMPLE",
        "SecretAccessKey": "secret",
        "SessionToken": "token"
    }"#;
    let result = authenticate("pg_admin", json, config_file.path().to_str().unwrap());
    assert!(matches!(result, AuthResult::Error(_)));
}

#[test]
fn test_valid_creds_with_future_expiration_reaches_sts_call() {
    // With valid creds and a valid config, the flow should get past parsing and
    // expiration check, then fail at the STS HTTP call (no real endpoint).
    let config_file = write_config(VALID_CONFIG);
    let json = r#"{
        "AccessKeyId": "ASIAEXAMPLE",
        "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "SessionToken": "FwoGZXIvYXdzEBYaDH...",
        "Expiration": "2099-12-31T23:59:59Z"
    }"#;
    let result = authenticate("pg_admin", json, config_file.path().to_str().unwrap());
    // Should fail at STS call (can't reach real endpoint), not at parsing/expiration
    assert!(matches!(result, AuthResult::InvalidCredentials(_)));
    if let AuthResult::InvalidCredentials(msg) = result {
        assert!(
            msg.contains("STS validation failed"),
            "Expected STS failure, got: {}",
            msg
        );
    }
}

#[test]
fn test_config_with_mock_endpoint_reaches_sts() {
    // Point at a non-existent mock endpoint — should fail with connection error
    let config = r#"
[aws]
region = "eu-central-1"
allowed_account_ids = ["111122223333"]
sts_endpoint = "http://127.0.0.1:1"
timeout_secs = 1

[role_mapping]
"YubiKeyKMSRole" = ["pg_admin"]
"#;
    let config_file = write_config(config);
    let json = r#"{
        "AccessKeyId": "ASIATEST",
        "SecretAccessKey": "testsecret",
        "SessionToken": "testtoken",
        "Expiration": "2099-12-31T23:59:59Z"
    }"#;
    let result = authenticate("pg_admin", json, config_file.path().to_str().unwrap());
    assert!(matches!(result, AuthResult::InvalidCredentials(_)));
    if let AuthResult::InvalidCredentials(msg) = result {
        assert!(
            msg.contains("STS"),
            "Expected STS-related failure, got: {}",
            msg
        );
    }
}

#[test]
fn test_empty_role_mapping_config_rejected() {
    let config = r#"
[aws]
region = "eu-central-1"
allowed_account_ids = ["111122223333"]

[role_mapping]
"#;
    let config_file = write_config(config);
    let json = r#"{
        "AccessKeyId": "ASIA123",
        "SecretAccessKey": "secret",
        "SessionToken": "token"
    }"#;
    let result = authenticate("pg_admin", json, config_file.path().to_str().unwrap());
    assert!(matches!(result, AuthResult::Error(_)));
}
