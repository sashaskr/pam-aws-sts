use crate::config::{DEFAULT_LOG_FACILITY, DEFAULT_LOG_LEVEL};
use crate::{authenticate_from, init_logging, AuthResult};
use libc::{c_char, c_int, c_void, free};
use std::ffi::{CStr, CString};
use std::panic::{self, AssertUnwindSafe};
use std::ptr::{self, NonNull};
use std::sync::atomic::{AtomicBool, Ordering};
use zeroize::Zeroizing;

const PAM_SUCCESS: c_int = 0;
const PAM_PERM_DENIED: c_int = 6;
const PAM_AUTH_ERR: c_int = 7;
const PAM_CRED_INSUFFICIENT: c_int = 8;
const PAM_AUTHINFO_UNAVAIL: c_int = 9;
const PAM_CONV: c_int = 5;
const PAM_USER: c_int = 2;
/// Client address or hostname. PostgreSQL sets this via `pam_set_item`; which
/// of the two it contains depends on the `pam_use_hostname` HBA option.
const PAM_RHOST: c_int = 4;
const PAM_PROMPT_ECHO_OFF: c_int = 1;

/// Set when `pam_sm_authenticate` approved the current PAM transaction.
///
/// PostgreSQL forks a backend per connection and calls `pam_authenticate`
/// then `pam_acct_mgmt` within that single process (see `CheckPAMAuth` in
/// `src/backend/libpq/auth.c`), so process-local state is transaction-local
/// state in this deployment. The flag is consumed when read, so one approval
/// cannot satisfy two account checks.
///
/// This is why the state is not kept with `pam_set_data`: that would add raw
/// pointer handling and a cleanup callback to the FFI surface for no gain in
/// the single-transaction-per-process model this module targets.
static AUTHENTICATED: AtomicBool = AtomicBool::new(false);

fn mark_authenticated() {
    AUTHENTICATED.store(true, Ordering::SeqCst);
}

/// Returns whether this module authenticated the transaction, clearing the flag.
fn take_authenticated() -> bool {
    AUTHENTICATED.swap(false, Ordering::SeqCst)
}

/// Maps the account-phase decision. Separated out so it is testable without
/// touching the process-wide flag.
fn account_decision(was_authenticated: bool) -> c_int {
    if was_authenticated {
        PAM_SUCCESS
    } else {
        PAM_PERM_DENIED
    }
}

#[repr(C)]
pub struct PamHandle {
    _opaque: [u8; 0],
}

#[repr(C)]
struct PamMessage {
    msg_style: c_int,
    msg: *const c_char,
}

#[repr(C)]
struct PamResponse {
    resp: *mut c_char,
    resp_retcode: c_int,
}

#[repr(C)]
struct PamConv {
    conv: Option<
        unsafe extern "C" fn(
            num_msg: c_int,
            msg: *mut *const PamMessage,
            resp: *mut *mut PamResponse,
            appdata_ptr: *mut c_void,
        ) -> c_int,
    >,
    appdata_ptr: *mut c_void,
}

extern "C" {
    fn pam_get_item(pamh: *const PamHandle, item_type: c_int, item: *mut *const c_void) -> c_int;
}

unsafe fn get_pam_item_str(pamh: *const PamHandle, item_type: c_int) -> Result<String, c_int> {
    let mut item_ptr: *const c_void = ptr::null();
    let ret = pam_get_item(pamh, item_type, &mut item_ptr);
    if ret != PAM_SUCCESS || item_ptr.is_null() {
        return Err(PAM_AUTHINFO_UNAVAIL);
    }
    CStr::from_ptr(item_ptr as *const c_char)
        .to_str()
        .map(|s| s.to_string())
        .map_err(|_| PAM_AUTH_ERR)
}

unsafe fn get_password_via_conv(pamh: *const PamHandle) -> Result<String, c_int> {
    let mut conv_ptr: *const c_void = ptr::null();
    let ret = pam_get_item(pamh, PAM_CONV, &mut conv_ptr);
    if ret != PAM_SUCCESS || conv_ptr.is_null() {
        return Err(PAM_CRED_INSUFFICIENT);
    }

    // SAFETY: pam_get_item returned PAM_SUCCESS with a non-null pointer.
    // The PAM API guarantees this points to a valid pam_conv struct owned
    // by the PAM framework for the lifetime of this call.
    let conv_nn = NonNull::new(conv_ptr as *mut PamConv).ok_or(PAM_CRED_INSUFFICIENT)?;
    let conv_fn = (*conv_nn.as_ptr()).conv.ok_or(PAM_CRED_INSUFFICIENT)?;
    let appdata = (*conv_nn.as_ptr()).appdata_ptr;

    let prompt = CString::new("Password: ").map_err(|_| PAM_AUTH_ERR)?;
    let msg = PamMessage {
        msg_style: PAM_PROMPT_ECHO_OFF,
        msg: prompt.as_ptr(),
    };
    let msg_ptr: *const PamMessage = &msg;

    let mut resp_ptr: *mut PamResponse = ptr::null_mut();
    let ret = conv_fn(
        1,
        &msg_ptr as *const _ as *mut *const PamMessage,
        &mut resp_ptr,
        appdata,
    );

    if ret != PAM_SUCCESS || resp_ptr.is_null() {
        return Err(PAM_CRED_INSUFFICIENT);
    }

    // SAFETY: conv_fn returned PAM_SUCCESS with a non-null resp_ptr.
    // The response was allocated by the PAM conversation function; we own it.
    let resp_nn = NonNull::new(resp_ptr).ok_or(PAM_CRED_INSUFFICIENT)?;
    let resp_resp = (*resp_nn.as_ptr()).resp;
    free(resp_ptr as *mut c_void);

    if resp_resp.is_null() {
        return Err(PAM_CRED_INSUFFICIENT);
    }

    // SAFETY: resp_resp is non-null and was allocated by the PAM conversation
    // function. Ownership moves into the guard, which scrubs and frees it on
    // every exit path from here on.
    let response = ConvResponse(resp_resp);
    response.to_owned_string()
}

/// Owns the `char *` returned by a PAM conversation function.
///
/// The buffer holds the user's password. Before this guard existed, a password
/// that was not valid UTF-8 took an early return that skipped both the
/// overwrite and the `free`, leaking the allocation and leaving the secret
/// resident in the heap of a long-lived PostgreSQL backend. An attacker could
/// trigger that on demand by sending one invalid byte.
struct ConvResponse(*mut c_char);

impl ConvResponse {
    /// Copies the buffer into an owned `String`.
    ///
    /// Returns `PAM_AUTH_ERR` if the bytes are not valid UTF-8. Either way the
    /// buffer is scrubbed and freed when the guard drops.
    fn to_owned_string(&self) -> Result<String, c_int> {
        // SAFETY: self.0 is non-null and NUL-terminated per the invariant
        // documented at the construction site.
        unsafe { CStr::from_ptr(self.0) }
            .to_str()
            .map(str::to_owned)
            .map_err(|_| PAM_AUTH_ERR)
    }
}

impl Drop for ConvResponse {
    fn drop(&mut self) {
        // SAFETY: self.0 was allocated by the PAM conversation function, is
        // owned solely by this guard, and is freed exactly once here. The
        // overwrite happens before the free so the secret does not survive in
        // reusable heap memory.
        unsafe {
            let len = libc::strlen(self.0);
            ptr::write_bytes(self.0 as *mut u8, 0, len);
            free(self.0 as *mut c_void);
        }
    }
}

fn parse_config_path(argc: c_int, argv: *const *const c_char) -> String {
    let default_path = "/etc/pam_aws_sts.toml";

    if argv.is_null() || argc <= 0 {
        return default_path.to_string();
    }

    for i in 0..argc as isize {
        let arg_ptr = unsafe { *argv.offset(i) };
        if arg_ptr.is_null() {
            continue;
        }
        let arg = match unsafe { CStr::from_ptr(arg_ptr) }.to_str() {
            Ok(s) => s,
            Err(_) => continue,
        };
        if let Some(path) = arg.strip_prefix("config=") {
            return path.to_string();
        }
    }

    default_path.to_string()
}

/// Runs the body of a PAM entry point, converting a panic into a denial.
///
/// A panic that escapes an `extern "C"` function aborts the process rather
/// than unwinding into the C caller. This module is loaded into the
/// PostgreSQL *backend*, and the postmaster responds to a crashed backend by
/// terminating every other backend and entering recovery. Without this guard,
/// one panic in authentication code is a cluster-wide outage instead of a
/// single failed login.
///
/// Failing closed is the only safe choice here: a panic means an invariant we
/// relied on did not hold, so the identity decision cannot be trusted.
fn guarded(entry: &'static str, body: impl FnOnce() -> c_int) -> c_int {
    match panic::catch_unwind(AssertUnwindSafe(body)) {
        Ok(code) => code,
        Err(_) => {
            // Best effort reporting only. The logger may itself be what
            // panicked, so a failure to report must not escalate to an abort.
            let _ = panic::catch_unwind(|| {
                log::error!("{}: caught panic, denying authentication", entry);
            });
            PAM_AUTHINFO_UNAVAIL
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn pam_sm_authenticate(
    pamh: *const PamHandle,
    _flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    guarded("pam_sm_authenticate", || unsafe {
        authenticate_impl(pamh, argc, argv)
    })
}

unsafe fn authenticate_impl(
    pamh: *const PamHandle,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    let config_path = parse_config_path(argc, argv);

    // Optional. PostgreSQL sets PAM_RHOST for TCP connections but not for the
    // local socket, and another PAM application may not set it at all.
    let rhost = get_pam_item_str(pamh, PAM_RHOST).ok();

    let username = match get_pam_item_str(pamh, PAM_USER) {
        Ok(u) => u,
        Err(code) => {
            // The configured log level is not known yet, so fall back to the
            // defaults purely so this failure is not silently dropped.
            init_logging(DEFAULT_LOG_LEVEL, DEFAULT_LOG_FACILITY);
            log::error!(
                "failed to get PAM username (source='{}')",
                rhost.as_deref().unwrap_or("local")
            );
            return code;
        }
    };

    // Held in Zeroizing so the secret is scrubbed on the unwinding path as
    // well as on normal return. A plain String would be freed without being
    // overwritten if anything below panicked.
    let password = match get_password_via_conv(pamh) {
        Ok(p) => Zeroizing::new(p),
        Err(code) => {
            init_logging(DEFAULT_LOG_LEVEL, DEFAULT_LOG_FACILITY);
            log::error!(
                "failed to get password for '{}' (source='{}')",
                username,
                rhost.as_deref().unwrap_or("local")
            );
            return code;
        }
    };

    match authenticate_from(&username, password.as_str(), &config_path, rhost.as_deref()) {
        AuthResult::Success => {
            mark_authenticated();
            PAM_SUCCESS
        }
        AuthResult::InvalidCredentials(_) => PAM_AUTH_ERR,
        AuthResult::Error(_) => PAM_AUTHINFO_UNAVAIL,
    }
}

/// Account phase: confirms that this module is the one that authenticated.
///
/// PostgreSQL always calls `pam_acct_mgmt` after `pam_authenticate`, and the
/// shipped PAM service lists this module for both. Previously this returned
/// `PAM_SUCCESS` unconditionally, which made the `account required` line
/// decorative: it would approve a transaction authenticated by some other
/// module, or by nothing at all.
///
/// There is no credential available in this phase to re-verify against STS,
/// so the meaningful check is that the auth phase of this module ran and
/// succeeded for this transaction.
#[no_mangle]
pub unsafe extern "C" fn pam_sm_acct_mgmt(
    _pamh: *const PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    guarded("pam_sm_acct_mgmt", || {
        let decision = account_decision(take_authenticated());
        if decision != PAM_SUCCESS {
            log::warn!(
                "account check denied: pam_aws_sts did not authenticate this \
                 transaction. The PAM service must list \
                 'auth required pam_aws_sts.so' alongside the account entry."
            );
        }
        decision
    })
}

#[no_mangle]
pub unsafe extern "C" fn pam_sm_setcred(
    _pamh: *const PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    guarded("pam_sm_setcred", || PAM_SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_path() {
        assert_eq!(parse_config_path(0, ptr::null()), "/etc/pam_aws_sts.toml");
    }

    /// Runs `f` with the panic hook silenced, so a deliberately panicking test
    /// does not print a backtrace and look like a failure.
    fn without_panic_output<T>(f: impl FnOnce() -> T) -> T {
        let previous = panic::take_hook();
        panic::set_hook(Box::new(|_| {}));
        let out = f();
        panic::set_hook(previous);
        out
    }

    #[test]
    fn guarded_passes_through_success() {
        assert_eq!(guarded("t", || PAM_SUCCESS), PAM_SUCCESS);
    }

    #[test]
    fn guarded_passes_through_denial() {
        assert_eq!(guarded("t", || PAM_AUTH_ERR), PAM_AUTH_ERR);
    }

    #[test]
    fn guarded_converts_panic_into_denial() {
        let code = without_panic_output(|| guarded("t", || panic!("boom")));
        assert_eq!(
            code, PAM_AUTHINFO_UNAVAIL,
            "a panic must deny, never return PAM_SUCCESS"
        );
    }

    // The specific shape that used to abort the backend: slicing a str at a
    // non-char boundary deep inside the STS error path.
    #[test]
    fn guarded_contains_char_boundary_panic() {
        let code = without_panic_output(|| {
            guarded("t", || {
                let s = format!("{}\u{2014}", "x".repeat(199));
                let _ = &s[..200];
                PAM_SUCCESS
            })
        });
        assert_eq!(code, PAM_AUTHINFO_UNAVAIL);
    }

    #[test]
    fn account_phase_denies_when_auth_did_not_run() {
        assert_eq!(account_decision(false), PAM_PERM_DENIED);
    }

    #[test]
    fn account_phase_allows_after_successful_auth() {
        assert_eq!(account_decision(true), PAM_SUCCESS);
    }

    // Single test for the process-wide flag: Rust runs tests as threads in one
    // process, so exercising the static from more than one test would race.
    #[test]
    fn authenticated_flag_is_set_then_consumed() {
        assert!(!take_authenticated(), "flag should start clear");
        mark_authenticated();
        assert!(take_authenticated(), "flag should report the approval");
        assert!(
            !take_authenticated(),
            "approval must be single-use so it cannot satisfy a second account check"
        );
    }

    #[test]
    fn guarded_never_returns_success_on_panic() {
        for payload in ["str", "owned"] {
            let code = without_panic_output(|| {
                guarded("t", || {
                    if payload == "str" {
                        panic!("static str payload")
                    } else {
                        panic!("{}", String::from("owned payload"))
                    }
                })
            });
            assert_ne!(code, PAM_SUCCESS);
        }
    }
}
