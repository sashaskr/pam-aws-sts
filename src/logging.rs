use log::LevelFilter;
use syslog::{BasicLogger, Facility, Formatter3164};
use std::sync::Once;

static INIT: Once = Once::new();

pub struct PamLogger;

impl PamLogger {
    pub fn init(level: &str, facility: &str) {
        INIT.call_once(|| {
            let level_filter = parse_level(level);
            let syslog_facility = parse_facility(facility);

            let formatter = Formatter3164 {
                facility: syslog_facility,
                hostname: None,
                process: "pam_aws_sts".into(),
                pid: std::process::id(),
            };

            match syslog::unix(formatter) {
                Ok(logger) => {
                    let _ = log::set_boxed_logger(Box::new(BasicLogger::new(logger)));
                    log::set_max_level(level_filter);
                }
                Err(e) => {
                    eprintln!("pam_aws_sts: syslog init failed: {}", e);
                    log::set_max_level(LevelFilter::Off);
                }
            }
        });
    }
}

fn parse_level(s: &str) -> LevelFilter {
    match s.to_lowercase().as_str() {
        "error" => LevelFilter::Error,
        "warn" | "warning" => LevelFilter::Warn,
        "info" => LevelFilter::Info,
        "debug" => LevelFilter::Debug,
        "trace" => LevelFilter::Trace,
        _ => LevelFilter::Info,
    }
}

fn parse_facility(s: &str) -> Facility {
    match s.to_lowercase().as_str() {
        "auth" | "authpriv" => Facility::LOG_AUTH,
        "local0" => Facility::LOG_LOCAL0,
        "local1" => Facility::LOG_LOCAL1,
        "local2" => Facility::LOG_LOCAL2,
        "local3" => Facility::LOG_LOCAL3,
        "local4" => Facility::LOG_LOCAL4,
        "local5" => Facility::LOG_LOCAL5,
        "local6" => Facility::LOG_LOCAL6,
        "local7" => Facility::LOG_LOCAL7,
        "daemon" => Facility::LOG_DAEMON,
        _ => Facility::LOG_AUTH,
    }
}
