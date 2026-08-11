mod config;
mod credentials;
#[cfg(target_os = "linux")]
mod logging;
#[cfg(target_os = "linux")]
mod pam_ffi;
mod sts;
mod validation;

use config::Config;
use credentials::StsCredentials;
use sts::StsClient;
use validation::validate_identity;

#[doc(hidden)]
pub fn authenticate(username: &str, password: &str, config_path: &str) -> AuthResult {
    let config = match Config::load(config_path) {
        Ok(c) => c,
        Err(e) => {
            log::error!("config load failed '{}': {}", config_path, e);
            return AuthResult::Error("configuration load failure".into());
        }
    };

    let creds = match StsCredentials::from_json(password) {
        Ok(c) => c,
        Err(e) => {
            log::warn!("auth failed for '{}': parse error: {}", username, e);
            return AuthResult::InvalidCredentials("malformed credential JSON".into());
        }
    };

    if let Err(e) = creds.check_expiration(config.aws.grace_period_secs.unwrap_or(30)) {
        log::warn!("auth failed for '{}': {}", username, e);
        return AuthResult::InvalidCredentials(e);
    }

    let client = StsClient::new(&config.aws);
    let identity = match client.get_caller_identity(&creds) {
        Ok(id) => id,
        Err(e) => {
            log::warn!("auth failed for '{}': STS error: {}", username, e);
            return AuthResult::InvalidCredentials(format!("STS validation failed: {}", e));
        }
    };

    log::debug!(
        "identity for '{}': account={}, arn={}",
        username,
        identity.account,
        identity.arn
    );

    match validate_identity(username, &identity, &config) {
        Ok(()) => {
            log::info!("auth ok: user='{}', arn='{}'", username, identity.arn);
            AuthResult::Success
        }
        Err(e) => {
            log::warn!("auth failed for '{}': {}", username, e);
            AuthResult::InvalidCredentials(e)
        }
    }
}

#[derive(Debug)]
pub enum AuthResult {
    Success,
    InvalidCredentials(String),
    Error(String),
}
