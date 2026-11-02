use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub aws: AwsConfig,
    pub role_mapping: RoleMapping,
    #[serde(default)]
    pub logging: LoggingConfig,
}

/// How IAM roles map to PostgreSQL usernames.
///
/// Two shapes are accepted. The account-scoped shape is the safe one:
///
/// ```toml
/// [role_mapping."111122223333"]
/// "AdminRole" = ["dbadmin"]
/// ```
///
/// The flat shape keys on role name alone and is kept for single-account
/// configs, which are unambiguous:
///
/// ```toml
/// [role_mapping]
/// "AdminRole" = ["dbadmin"]
/// ```
///
/// A flat mapping combined with more than one allowed account is rejected at
/// load. IAM guarantees role names are unique only *within* an account, so in
/// that combination a role named `AdminRole` in any allowed account resolves
/// to the same PostgreSQL user. Whoever can create a role in the least trusted
/// allowed account would inherit the privileges of the most trusted one.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum RoleMapping {
    /// account id -> role name -> allowed PostgreSQL usernames
    PerAccount(HashMap<String, HashMap<String, Vec<String>>>),
    /// role name -> allowed PostgreSQL usernames
    Flat(HashMap<String, Vec<String>>),
}

impl RoleMapping {
    fn is_empty(&self) -> bool {
        match self {
            RoleMapping::PerAccount(m) => m.is_empty() || m.values().all(|r| r.is_empty()),
            RoleMapping::Flat(m) => m.is_empty(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct AwsConfig {
    pub region: String,
    pub allowed_account_ids: Vec<String>,
    pub sts_endpoint: Option<String>,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    pub grace_period_secs: Option<u64>,
    /// Rejects credentials that carry no `Expiration` field.
    ///
    /// `Expiration` is supplied by the client in the same payload as the
    /// credentials, so `grace_period_secs` is only enforceable when the field
    /// is present. Any client can skip that check by omitting it. Enabling
    /// this makes the grace period a real constraint. Default is off, because
    /// hand-built credential payloads legitimately omit the field.
    #[serde(default)]
    pub require_expiration: bool,
    /// Allows `sts_endpoint` to use plaintext `http://`.
    ///
    /// Intended only for a local mock such as LocalStack. The whole
    /// authentication decision is derived from the endpoint's response, so
    /// enabling this on a reachable network makes identity forgeable.
    #[serde(default)]
    pub allow_insecure_endpoint: bool,
}

#[derive(Debug, Deserialize)]
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

/// Used until the config has been read, so that a config load failure is
/// still reportable.
pub const DEFAULT_LOG_LEVEL: &str = "info";
pub const DEFAULT_LOG_FACILITY: &str = "auth";

fn default_log_level() -> String {
    DEFAULT_LOG_LEVEL.into()
}

fn default_facility() -> String {
    DEFAULT_LOG_FACILITY.into()
}

/// Largest accepted `timeout_secs`.
///
/// The STS call blocks a PostgreSQL backend, so a long timeout lets a single
/// stalled request hold a connection slot. Thirty seconds is already far
/// beyond a healthy STS round trip.
const MAX_TIMEOUT_SECS: u64 = 30;

fn validate_timeout(timeout_secs: u64) -> Result<(), String> {
    if timeout_secs == 0 {
        return Err("aws.timeout_secs must be at least 1".into());
    }
    if timeout_secs > MAX_TIMEOUT_SECS {
        return Err(format!(
            "aws.timeout_secs is {} but must not exceed {}. The STS call blocks a \
             PostgreSQL backend, so a long timeout lets stalled requests consume \
             connection slots.",
            timeout_secs, MAX_TIMEOUT_SECS
        ));
    }
    Ok(())
}

/// Refuses to read a config that an untrusted account could rewrite.
///
/// This file decides which IAM roles map to which database users, so write
/// access to it is equivalent to granting database access. The module runs
/// inside the PostgreSQL backend, under the database account, which is exactly
/// the kind of process that should not trust a group- or world-writable file.
/// `make install` sets mode 600, but nothing verified it at runtime.
#[cfg(unix)]
fn check_file_trust(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;

    let meta = fs::metadata(path)
        .map_err(|e| format!("failed to stat config {}: {}", path.display(), e))?;

    let mode = meta.mode() & 0o777;
    if mode & 0o022 != 0 {
        return Err(format!(
            "config {} is writable by group or other (mode {:04o}). It controls \
             which IAM roles may log in as which database users, so this is a \
             privilege escalation path. Fix with: chmod 600 {}",
            path.display(),
            mode,
            path.display()
        ));
    }

    // SAFETY: geteuid is always safe; it takes no arguments and cannot fail.
    let euid = unsafe { libc::geteuid() };
    if meta.uid() != 0 && meta.uid() != euid {
        return Err(format!(
            "config {} is owned by uid {}, which is neither root nor the running \
             process (uid {}). An account that owns the file can rewrite the role \
             mapping. Fix with: chown root {}",
            path.display(),
            meta.uid(),
            euid,
            path.display()
        ));
    }

    Ok(())
}

#[cfg(not(unix))]
fn check_file_trust(_path: &Path) -> Result<(), String> {
    Ok(())
}

/// Rejects an `sts_endpoint` that would carry the identity decision in plaintext.
///
/// Every authentication outcome is derived from the XML this endpoint returns.
/// Over plaintext HTTP an on-path attacker can substitute any `Account` and
/// `Arn`, which authenticates them as any mapped PostgreSQL user. HTTPS is
/// therefore a correctness requirement, not a preference, and it is enforced
/// at config load so a bad value fails once at startup rather than silently on
/// every login.
fn validate_sts_endpoint(endpoint: &str, allow_insecure: bool) -> Result<(), String> {
    if endpoint.starts_with("https://") {
        return Ok(());
    }

    if !endpoint.starts_with("http://") {
        return Err(format!(
            "aws.sts_endpoint must start with https:// (got '{}')",
            endpoint
        ));
    }

    if !allow_insecure {
        return Err(format!(
            "aws.sts_endpoint '{}' uses plaintext http://. The authentication \
             decision is derived entirely from this endpoint's response, so an \
             on-path attacker could forge any identity. Use https://, or set \
             aws.allow_insecure_endpoint = true if this is a local mock.",
            endpoint
        ));
    }

    log::warn!(
        "aws.sts_endpoint '{}' is plaintext http:// and allow_insecure_endpoint \
         is set; identity responses are forgeable. Do not use this outside testing.",
        endpoint
    );
    Ok(())
}

impl Config {
    pub fn load(path: &str) -> Result<Self, String> {
        let path = Path::new(path);
        if !path.exists() {
            return Err(format!("config file not found: {}", path.display()));
        }

        check_file_trust(path)?;

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
        if let Some(endpoint) = &config.aws.sts_endpoint {
            validate_sts_endpoint(endpoint, config.aws.allow_insecure_endpoint)?;
        }
        validate_timeout(config.aws.timeout_secs)?;
        config.validate_role_mapping()?;

        Ok(config)
    }

    /// Rejects a role mapping that cannot express the operator's intent safely.
    fn validate_role_mapping(&self) -> Result<(), String> {
        match &self.role_mapping {
            RoleMapping::Flat(_) if self.aws.allowed_account_ids.len() > 1 => Err(format!(
                "role_mapping keys on role name alone, but {} accounts are allowed. \
                 IAM role names are unique only within an account, so a role named \
                 the same thing in any allowed account would map to the same \
                 PostgreSQL user. Scope the mapping by account instead:\n\n\
                 [role_mapping.\"{}\"]\n\"MyRole\" = [\"dbadmin\"]",
                self.aws.allowed_account_ids.len(),
                self.aws.allowed_account_ids[0]
            )),
            RoleMapping::PerAccount(per_account) => {
                // A mapping for an account that is not allowed can never match.
                // Failing here is deliberate: a silently dead authorization rule
                // reads like a granted permission.
                for account in per_account.keys() {
                    if !self.aws.allowed_account_ids.contains(account) {
                        return Err(format!(
                            "role_mapping has an entry for account '{}', which is not in \
                             aws.allowed_account_ids. That mapping could never match. \
                             Add the account to allowed_account_ids or remove the mapping.",
                            account
                        ));
                    }
                }
                Ok(())
            }
            RoleMapping::Flat(_) => Ok(()),
        }
    }

    /// Returns the PostgreSQL usernames the given account and role may log in as.
    ///
    /// For a flat mapping the account is ignored, which is sound only because
    /// `validate_role_mapping` has already established that exactly one account
    /// is allowed and `validate_identity` has already matched it.
    pub fn allowed_users_for(&self, account: &str, role: &str) -> Option<&[String]> {
        match &self.role_mapping {
            RoleMapping::PerAccount(per_account) => {
                per_account.get(account)?.get(role).map(Vec::as_slice)
            }
            RoleMapping::Flat(flat) => flat.get(role).map(Vec::as_slice),
        }
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
            config
                .allowed_users_for("111122223333", "YubiKeyKMSRole")
                .unwrap(),
            ["pg_admin".to_string()]
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
    fn sts_endpoint_override_https() {
        let toml = r#"
[aws]
region = "eu-central-1"
allowed_account_ids = ["111122223333"]
sts_endpoint = "https://sts.internal.example.com"

[role_mapping]
"SomeRole" = ["user1"]
"#;
        let config = Config::from_str(toml).unwrap();
        assert_eq!(config.sts_endpoint(), "https://sts.internal.example.com");
    }

    #[test]
    fn plaintext_endpoint_rejected_by_default() {
        let toml = r#"
[aws]
region = "eu-central-1"
allowed_account_ids = ["111122223333"]
sts_endpoint = "http://localhost:4566"

[role_mapping]
"SomeRole" = ["user1"]
"#;
        let err = Config::from_str(toml).unwrap_err();
        assert!(
            err.contains("plaintext http://"),
            "unexpected error: {}",
            err
        );
        assert!(err.contains("allow_insecure_endpoint"));
    }

    #[test]
    fn plaintext_endpoint_allowed_with_explicit_opt_in() {
        let toml = r#"
[aws]
region = "eu-central-1"
allowed_account_ids = ["111122223333"]
sts_endpoint = "http://localhost:4566"
allow_insecure_endpoint = true

[role_mapping]
"SomeRole" = ["user1"]
"#;
        let config = Config::from_str(toml).unwrap();
        assert_eq!(config.sts_endpoint(), "http://localhost:4566");
    }

    #[test]
    fn non_http_scheme_rejected_even_with_opt_in() {
        for endpoint in [
            "file:///etc/passwd",
            "ftp://example.com",
            "sts.us-east-1.amazonaws.com",
            "//sts.us-east-1.amazonaws.com",
            "",
        ] {
            let toml = format!(
                r#"
[aws]
region = "us-east-1"
allowed_account_ids = ["111122223333"]
sts_endpoint = "{}"
allow_insecure_endpoint = true

[role_mapping]
"R" = ["u"]
"#,
                endpoint
            );
            let err = Config::from_str(&toml).unwrap_err();
            assert!(
                err.contains("must start with https://"),
                "endpoint {:?} should be rejected, got: {}",
                endpoint,
                err
            );
        }
    }

    #[test]
    fn opt_in_defaults_to_false() {
        let config = Config::from_str(VALID_CONFIG).unwrap();
        assert!(!config.aws.allow_insecure_endpoint);
    }

    // The default endpoint is derived from the region and is always https,
    // so omitting sts_endpoint can never produce a plaintext call.
    #[test]
    fn derived_default_endpoint_is_https() {
        let config = Config::from_str(VALID_CONFIG).unwrap();
        assert!(config.aws.sts_endpoint.is_none());
        assert!(config.sts_endpoint().starts_with("https://"));
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
allowed_account_ids = ["111122223333"]

[role_mapping]
"AdminRole" = ["admin", "superuser"]
"ViewerRole" = ["viewer"]
"#;
        let config = Config::from_str(toml).unwrap();
        assert_eq!(
            config
                .allowed_users_for("111122223333", "AdminRole")
                .unwrap(),
            ["admin".to_string(), "superuser".to_string()]
        );
        assert_eq!(
            config
                .allowed_users_for("111122223333", "ViewerRole")
                .unwrap(),
            ["viewer".to_string()]
        );
    }

    // --- role mapping shape and scoping ---

    #[test]
    fn flat_mapping_with_multiple_accounts_is_rejected() {
        let toml = r#"
[aws]
region = "eu-central-1"
allowed_account_ids = ["111122223333", "444455556666"]

[role_mapping]
"AdminRole" = ["admin"]
"#;
        let err = Config::from_str(toml).unwrap_err();
        assert!(
            err.contains("unique only within an account"),
            "unexpected error: {}",
            err
        );
        // The message should show the operator the shape to migrate to.
        assert!(err.contains("[role_mapping."));
    }

    #[test]
    fn per_account_mapping_parses() {
        let toml = r#"
[aws]
region = "eu-central-1"
allowed_account_ids = ["111122223333", "444455556666"]

[role_mapping."111122223333"]
"AdminRole" = ["dbadmin"]

[role_mapping."444455556666"]
"AdminRole" = ["readonly"]
"#;
        let config = Config::from_str(toml).unwrap();
        assert_eq!(
            config
                .allowed_users_for("111122223333", "AdminRole")
                .unwrap(),
            ["dbadmin".to_string()]
        );
        // Same role name, different account, different user. This is the whole
        // point of scoping the mapping.
        assert_eq!(
            config
                .allowed_users_for("444455556666", "AdminRole")
                .unwrap(),
            ["readonly".to_string()]
        );
    }

    #[test]
    fn per_account_lookup_misses_for_unmapped_account() {
        let toml = r#"
[aws]
region = "eu-central-1"
allowed_account_ids = ["111122223333", "444455556666"]

[role_mapping."111122223333"]
"AdminRole" = ["dbadmin"]

[role_mapping."444455556666"]
"OtherRole" = ["x"]
"#;
        let config = Config::from_str(toml).unwrap();
        assert!(config
            .allowed_users_for("444455556666", "AdminRole")
            .is_none());
        assert!(config
            .allowed_users_for("999999999999", "AdminRole")
            .is_none());
    }

    #[test]
    fn per_account_mapping_for_disallowed_account_is_rejected() {
        let toml = r#"
[aws]
region = "eu-central-1"
allowed_account_ids = ["111122223333"]

[role_mapping."999999999999"]
"AdminRole" = ["dbadmin"]
"#;
        let err = Config::from_str(toml).unwrap_err();
        assert!(
            err.contains("could never match"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn flat_mapping_with_one_account_still_accepted() {
        let config = Config::from_str(VALID_CONFIG).unwrap();
        assert!(matches!(config.role_mapping, RoleMapping::Flat(_)));
    }

    #[test]
    fn empty_per_account_mapping_rejected() {
        let toml = r#"
[aws]
region = "eu-central-1"
allowed_account_ids = ["111122223333"]

[role_mapping."111122223333"]
"#;
        assert!(Config::from_str(toml).unwrap_err().contains("role_mapping"));
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

    // --- timeout bounds ---

    #[test]
    fn zero_timeout_rejected() {
        let toml = VALID_CONFIG.replace("timeout_secs = 5", "timeout_secs = 0");
        assert!(Config::from_str(&toml).unwrap_err().contains("at least 1"));
    }

    #[test]
    fn excessive_timeout_rejected() {
        let toml = VALID_CONFIG.replace("timeout_secs = 5", "timeout_secs = 3600");
        let err = Config::from_str(&toml).unwrap_err();
        assert!(err.contains("must not exceed"), "unexpected error: {}", err);
        assert!(err.contains("blocks a PostgreSQL backend"));
    }

    #[test]
    fn boundary_timeouts_accepted() {
        for secs in [1, MAX_TIMEOUT_SECS] {
            let toml =
                VALID_CONFIG.replace("timeout_secs = 5", &format!("timeout_secs = {}", secs));
            assert!(
                Config::from_str(&toml).is_ok(),
                "timeout_secs = {} should be accepted",
                secs
            );
        }
    }

    // --- config file trust ---

    #[cfg(unix)]
    mod file_trust {
        use super::*;
        use std::os::unix::fs::PermissionsExt;

        fn write_config_with_mode(mode: u32) -> (tempfile::TempDir, std::path::PathBuf) {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("pam_aws_sts.toml");
            std::fs::write(&path, VALID_CONFIG).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            (dir, path)
        }

        #[test]
        fn mode_600_accepted() {
            let (_dir, path) = write_config_with_mode(0o600);
            assert!(Config::load(path.to_str().unwrap()).is_ok());
        }

        #[test]
        fn mode_644_accepted() {
            // World-readable is acceptable; the file holds no secrets. Only
            // write access confers privilege.
            let (_dir, path) = write_config_with_mode(0o644);
            assert!(Config::load(path.to_str().unwrap()).is_ok());
        }

        #[test]
        fn group_writable_rejected() {
            let (_dir, path) = write_config_with_mode(0o620);
            let err = Config::load(path.to_str().unwrap()).unwrap_err();
            assert!(
                err.contains("writable by group or other"),
                "unexpected error: {}",
                err
            );
            assert!(err.contains("chmod 600"), "error should say how to fix it");
        }

        #[test]
        fn world_writable_rejected() {
            let (_dir, path) = write_config_with_mode(0o602);
            assert!(Config::load(path.to_str().unwrap())
                .unwrap_err()
                .contains("writable by group or other"));
        }

        #[test]
        fn world_writable_with_sticky_like_bits_still_rejected() {
            let (_dir, path) = write_config_with_mode(0o666);
            assert!(Config::load(path.to_str().unwrap()).is_err());
        }
    }
}
