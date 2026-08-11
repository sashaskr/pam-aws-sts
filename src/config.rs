use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub aws: AwsConfig,
    pub role_mapping: HashMap<String, Vec<String>>,
    #[serde(default)]
    #[allow(dead_code)]
    pub logging: LoggingConfig,
}

#[derive(Debug, Deserialize)]
pub struct AwsConfig {
    pub region: String,
    pub allowed_account_ids: Vec<String>,
    pub sts_endpoint: Option<String>,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    pub grace_period_secs: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default = "default_facility")]
    pub facility: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            facility: default_facility(),
        }
    }
}

fn default_timeout() -> u64 {
    5
}

fn default_log_level() -> String {
    "info".into()
}

fn default_facility() -> String {
    "auth".into()
}

impl Config {
    pub fn load(path: &str) -> Result<Self, String> {
        let path = Path::new(path);
        if !path.exists() {
            return Err(format!("config file not found: {}", path.display()));
        }

        let content =
            fs::read_to_string(path).map_err(|e| format!("failed to read config: {}", e))?;

        Self::from_str(&content)
    }

    pub fn from_str(content: &str) -> Result<Self, String> {
        let config: Config =
            toml::from_str(content).map_err(|e| format!("TOML parse error: {}", e))?;

        if config.aws.region.is_empty() {
            return Err("aws.region must not be empty".into());
        }
        if config.aws.allowed_account_ids.is_empty() {
            return Err("aws.allowed_account_ids must contain at least one account".into());
        }
        if config.role_mapping.is_empty() {
            return Err("role_mapping must contain at least one mapping".into());
        }

        Ok(config)
    }

    #[allow(dead_code)]
    pub fn sts_endpoint(&self) -> String {
        self.aws
            .sts_endpoint
            .clone()
            .unwrap_or_else(|| format!("https://sts.{}.amazonaws.com", self.aws.region))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_CONFIG: &str = r#"
[aws]
region = "eu-central-1"
allowed_account_ids = ["111122223333"]
timeout_secs = 5
grace_period_secs = 30

[role_mapping]
"YubiKeyKMSRole" = ["pg_admin"]

[logging]
level = "info"
facility = "auth"
"#;

    #[test]
    fn parse_valid_config() {
        let config = Config::from_str(VALID_CONFIG).unwrap();
        assert_eq!(config.aws.region, "eu-central-1");
        assert_eq!(config.aws.allowed_account_ids, vec!["111122223333"]);
        assert_eq!(config.aws.timeout_secs, 5);
        assert_eq!(config.aws.grace_period_secs, Some(30));
        assert_eq!(
            config.role_mapping.get("YubiKeyKMSRole").unwrap(),
            &vec!["pg_admin".to_string()]
        );
        assert_eq!(config.logging.level, "info");
        assert_eq!(config.logging.facility, "auth");
    }

    #[test]
    fn sts_endpoint_default() {
        let config = Config::from_str(VALID_CONFIG).unwrap();
        assert_eq!(
            config.sts_endpoint(),
            "https://sts.eu-central-1.amazonaws.com"
        );
    }

    #[test]
    fn sts_endpoint_override() {
        let toml = r#"
[aws]
region = "eu-central-1"
allowed_account_ids = ["111122223333"]
sts_endpoint = "http://localhost:4566"

[role_mapping]
"SomeRole" = ["user1"]
"#;
        let config = Config::from_str(toml).unwrap();
        assert_eq!(config.sts_endpoint(), "http://localhost:4566");
    }

    #[test]
    fn missing_region_rejected() {
        let toml = r#"
[aws]
region = ""
allowed_account_ids = ["111122223333"]

[role_mapping]
"R" = ["u"]
"#;
        assert!(Config::from_str(toml)
            .unwrap_err()
            .contains("region must not be empty"));
    }

    #[test]
    fn empty_allowed_accounts_rejected() {
        let toml = r#"
[aws]
region = "us-east-1"
allowed_account_ids = []

[role_mapping]
"R" = ["u"]
"#;
        assert!(Config::from_str(toml)
            .unwrap_err()
            .contains("allowed_account_ids"));
    }

    #[test]
    fn empty_role_mapping_rejected() {
        let toml = r#"
[aws]
region = "us-east-1"
allowed_account_ids = ["111122223333"]

[role_mapping]
"#;
        assert!(Config::from_str(toml).unwrap_err().contains("role_mapping"));
    }

    #[test]
    fn defaults_applied_when_omitted() {
        let toml = r#"
[aws]
region = "us-east-1"
allowed_account_ids = ["123456789012"]

[role_mapping]
"MyRole" = ["myuser"]
"#;
        let config = Config::from_str(toml).unwrap();
        assert_eq!(config.aws.timeout_secs, 5);
        assert_eq!(config.aws.grace_period_secs, None);
        assert_eq!(config.logging.level, "info");
        assert_eq!(config.logging.facility, "auth");
    }

    #[test]
    fn multiple_roles_and_users() {
        let toml = r#"
[aws]
region = "eu-central-1"
allowed_account_ids = ["111122223333", "444455556666"]

[role_mapping]
"AdminRole" = ["admin", "superuser"]
"ViewerRole" = ["viewer"]
"#;
        let config = Config::from_str(toml).unwrap();
        assert_eq!(config.aws.allowed_account_ids.len(), 2);
        assert_eq!(
            config.role_mapping.get("AdminRole").unwrap(),
            &vec!["admin".to_string(), "superuser".to_string()]
        );
        assert_eq!(
            config.role_mapping.get("ViewerRole").unwrap(),
            &vec!["viewer".to_string()]
        );
    }

    #[test]
    fn invalid_toml_syntax() {
        assert!(Config::from_str("not [valid toml {{").is_err());
    }

    #[test]
    fn missing_aws_section() {
        let toml = r#"
[role_mapping]
"R" = ["u"]
"#;
        assert!(Config::from_str(toml).is_err());
    }

    #[test]
    fn load_nonexistent_file() {
        assert!(Config::load("/no/such/path.toml")
            .unwrap_err()
            .contains("not found"));
    }

    #[test]
    fn load_from_real_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.toml");
        std::fs::write(&path, VALID_CONFIG).unwrap();
        let config = Config::load(path.to_str().unwrap()).unwrap();
        assert_eq!(config.aws.region, "eu-central-1");
    }
}
