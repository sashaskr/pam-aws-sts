use chrono::{DateTime, Utc};
use serde::Deserialize;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct StsCredentials {
    #[serde(rename = "AccessKeyId")]
    pub access_key_id: String,

    #[serde(rename = "SecretAccessKey")]
    pub secret_access_key: String,

    #[serde(rename = "SessionToken")]
    pub session_token: String,

    #[serde(rename = "Expiration")]
    #[zeroize(skip)]
    pub expiration: Option<String>,
}

impl StsCredentials {
    pub fn from_json(json: &str) -> Result<Self, String> {
        let creds: StsCredentials =
            serde_json::from_str(json).map_err(|e| format!("invalid credential JSON: {}", e))?;

        if creds.access_key_id.is_empty() {
            return Err("AccessKeyId is empty".into());
        }
        if creds.secret_access_key.is_empty() {
            return Err("SecretAccessKey is empty".into());
        }
        if creds.session_token.is_empty() {
            return Err("SessionToken is empty".into());
        }

        Ok(creds)
    }

    pub fn check_expiration(&self, grace_period_secs: u64) -> Result<(), String> {
        let expiration_str = match &self.expiration {
            Some(exp) => exp,
            None => return Ok(()),
        };

        let expiration = parse_expiration(expiration_str)?;
        let now = Utc::now();
        let remaining = expiration.signed_duration_since(now);

        if remaining.num_seconds() < 0 {
            return Err(format!("credentials expired at {}", expiration.to_rfc3339()));
        }

        if remaining.num_seconds() < grace_period_secs as i64 {
            return Err(format!(
                "credentials expire in {}s (grace period: {}s)",
                remaining.num_seconds(),
                grace_period_secs
            ));
        }

        Ok(())
    }
}

fn parse_expiration(s: &str) -> Result<DateTime<Utc>, String> {
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .or_else(|_| {
            chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%SZ")
                .map(|naive| naive.and_utc())
                .map_err(|e| format!("invalid expiration timestamp '{}': {}", s, e))
        })
        .map_err(|e| format!("invalid expiration timestamp '{}': {}", s, e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_credentials() {
        let json = r#"{
            "AccessKeyId": "ASIAEXAMPLE",
            "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "SessionToken": "FwoGZXIvYXdzEBYaDH",
            "Expiration": "2099-01-15T10:30:00Z"
        }"#;
        let creds = StsCredentials::from_json(json).unwrap();
        assert_eq!(creds.access_key_id, "ASIAEXAMPLE");
        assert_eq!(creds.secret_access_key, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
        assert_eq!(creds.session_token, "FwoGZXIvYXdzEBYaDH");
        assert_eq!(creds.expiration.as_deref(), Some("2099-01-15T10:30:00Z"));
    }

    #[test]
    fn parse_without_expiration() {
        let json = r#"{"AccessKeyId":"A","SecretAccessKey":"B","SessionToken":"C"}"#;
        let creds = StsCredentials::from_json(json).unwrap();
        assert!(creds.expiration.is_none());
    }

    #[test]
    fn parse_malformed_json() {
        assert!(StsCredentials::from_json("not json").unwrap_err().contains("invalid credential JSON"));
    }

    #[test]
    fn parse_missing_required_field() {
        let json = r#"{"SecretAccessKey":"s","SessionToken":"t"}"#;
        assert!(StsCredentials::from_json(json).is_err());
    }

    #[test]
    fn parse_empty_access_key() {
        let json = r#"{"AccessKeyId":"","SecretAccessKey":"s","SessionToken":"t"}"#;
        assert!(StsCredentials::from_json(json).unwrap_err().contains("AccessKeyId is empty"));
    }

    #[test]
    fn parse_empty_secret_key() {
        let json = r#"{"AccessKeyId":"a","SecretAccessKey":"","SessionToken":"t"}"#;
        assert!(StsCredentials::from_json(json).unwrap_err().contains("SecretAccessKey is empty"));
    }

    #[test]
    fn parse_empty_session_token() {
        let json = r#"{"AccessKeyId":"a","SecretAccessKey":"s","SessionToken":""}"#;
        assert!(StsCredentials::from_json(json).unwrap_err().contains("SessionToken is empty"));
    }

    #[test]
    fn expiration_far_future_passes() {
        let json = r#"{"AccessKeyId":"a","SecretAccessKey":"s","SessionToken":"t","Expiration":"2099-12-31T23:59:59Z"}"#;
        let creds = StsCredentials::from_json(json).unwrap();
        assert!(creds.check_expiration(30).is_ok());
    }

    #[test]
    fn expiration_already_expired() {
        let json = r#"{"AccessKeyId":"a","SecretAccessKey":"s","SessionToken":"t","Expiration":"2020-01-01T00:00:00Z"}"#;
        let creds = StsCredentials::from_json(json).unwrap();
        assert!(creds.check_expiration(30).unwrap_err().contains("expired at"));
    }

    #[test]
    fn expiration_none_skips_check() {
        let json = r#"{"AccessKeyId":"a","SecretAccessKey":"s","SessionToken":"t"}"#;
        let creds = StsCredentials::from_json(json).unwrap();
        assert!(creds.check_expiration(30).is_ok());
        assert!(creds.check_expiration(9999).is_ok());
    }

    #[test]
    fn expiration_invalid_format() {
        let json = r#"{"AccessKeyId":"a","SecretAccessKey":"s","SessionToken":"t","Expiration":"nope"}"#;
        let creds = StsCredentials::from_json(json).unwrap();
        assert!(creds.check_expiration(30).unwrap_err().contains("invalid expiration"));
    }

    #[test]
    fn expiration_rfc3339_with_offset() {
        let json = r#"{"AccessKeyId":"a","SecretAccessKey":"s","SessionToken":"t","Expiration":"2099-01-15T10:30:00+05:30"}"#;
        let creds = StsCredentials::from_json(json).unwrap();
        assert!(creds.check_expiration(30).is_ok());
    }

    #[test]
    fn garbage_password() {
        assert!(StsCredentials::from_json("hunter2").is_err());
    }

    #[test]
    fn empty_string() {
        assert!(StsCredentials::from_json("").is_err());
    }

    #[test]
    fn json_array_rejected() {
        assert!(StsCredentials::from_json("[1,2,3]").is_err());
    }

    #[test]
    fn json_null_rejected() {
        assert!(StsCredentials::from_json("null").is_err());
    }

    #[test]
    fn extra_fields_ignored() {
        let json = r#"{"AccessKeyId":"a","SecretAccessKey":"s","SessionToken":"t","Version":1,"Extra":"ok"}"#;
        assert!(StsCredentials::from_json(json).is_ok());
    }

    #[test]
    fn zero_grace_period() {
        let json = r#"{"AccessKeyId":"a","SecretAccessKey":"s","SessionToken":"t","Expiration":"2099-12-31T23:59:59Z"}"#;
        let creds = StsCredentials::from_json(json).unwrap();
        assert!(creds.check_expiration(0).is_ok());
    }
}
