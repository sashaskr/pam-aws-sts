// Inside an `unsafe fn`, every operation is implicitly unsafe, so individual
// raw-pointer accesses are invisible and carry no required justification. That
// is the shape of the two pointer bugs this module has already had to fix
// (CodeQL alerts on PamConv handling). Requiring an explicit block makes each
// one a deliberate, reviewable act.
#![deny(unsafe_op_in_unsafe_fn)]

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

/// Installs the syslog logger. No-op off Linux, where there is no PAM target
/// and the module is built only to run the test suite.
#[cfg(target_os = "linux")]
pub(crate) fn init_logging(level: &str, facility: &str) {
    logging::PamLogger::init(level, facility);
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn init_logging(_level: &str, _facility: &str) {}

/// Renders the client address for an audit line.
///
/// PostgreSQL sets `PAM_RHOST`, but it is absent for a local socket
/// connection, so the value is optional rather than guaranteed.
fn source_label(rhost: Option<&str>) -> &str {
    match rhost {
        Some(h) if !h.is_empty() => h,
        _ => "local",
    }
}

#[doc(hidden)]
pub fn authenticate(username: &str, password: &str, config_path: &str) -> AuthResult {
    authenticate_from(username, password, config_path, None)
}

/// As [`authenticate`], but records the client address in the audit log.
///
/// `rhost` comes from the PAM `PAM_RHOST` item and is `None` when the caller
/// did not set it.
#[doc(hidden)]
pub fn authenticate_from(
    username: &str,
    password: &str,
    config_path: &str,
    rhost: Option<&str>,
) -> AuthResult {
    let source = source_label(rhost);

    // The config is read before the logger is installed, because the logger's
    // level and facility come from it. A failure here is reported through a
    // default logger so that it is not silently swallowed.
    let config = match Config::load(config_path) {
        Ok(c) => c,
        Err(e) => {
            init_logging(config::DEFAULT_LOG_LEVEL, config::DEFAULT_LOG_FACILITY);
            log::error!("config load failed '{}': {}", config_path, e);
            return AuthResult::Error("configuration load failure".into());
        }
    };

    init_logging(&config.logging.level, &config.logging.facility);

    let creds = match StsCredentials::from_json(password) {
        Ok(c) => c,
        Err(e) => {
            log::warn!(
                "auth failed: user='{}', source='{}', reason: {}",
                username,
                source,
                e
            );
            return AuthResult::InvalidCredentials("malformed credential JSON".into());
        }
    };

    if let Err(e) =
        creds.check_expiration(config.aws.grace_period_secs, config.aws.require_expiration)
    {
        log::warn!(
            "auth failed: user='{}', source='{}', reason: {}",
            username,
            source,
            e
        );
        return AuthResult::InvalidCredentials(e);
    }

    let client = StsClient::new(&config.aws);
    let identity = match client.get_caller_identity(&creds) {
        Ok(id) => id,
        Err(e) => {
            log::warn!(
                "auth failed: user='{}', source='{}', reason: STS error: {}",
                username,
                source,
                e
            );
            return AuthResult::InvalidCredentials(format!("STS validation failed: {}", e));
        }
    };

    log::debug!(
        "identity for '{}' from '{}': account={}, arn={}",
        username,
        source,
        identity.account,
        identity.arn
    );

    match validate_identity(username, &identity, &config) {
        Ok(()) => {
            log::info!(
                "auth ok: user='{}', source='{}', account='{}', arn='{}'",
                username,
                source,
                identity.account,
                identity.arn
            );
            AuthResult::Success
        }
        Err(e) => {
            log::warn!(
                "auth failed: user='{}', source='{}', account='{}', arn='{}', reason: {}",
                username,
                source,
                identity.account,
                identity.arn,
                e
            );
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

#[cfg(test)]
mod tests {
    use super::source_label;

    #[test]
    fn source_label_uses_rhost_when_present() {
        assert_eq!(source_label(Some("10.0.0.5")), "10.0.0.5");
    }

    #[test]
    fn source_label_falls_back_when_absent() {
        assert_eq!(source_label(None), "local");
    }

    // PostgreSQL sets PAM_RHOST only for TCP connections; an empty value
    // should read the same as an absent one rather than producing source=''.
    #[test]
    fn source_label_treats_empty_as_local() {
        assert_eq!(source_label(Some("")), "local");
    }
}
