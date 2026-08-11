use crate::logging::PamLogger;
use crate::{authenticate, AuthResult};
use libc::{c_char, c_int, c_void, free};
use std::ffi::{CStr, CString};
use std::ptr;
use zeroize::Zeroize;

const PAM_SUCCESS: c_int = 0;
const PAM_AUTH_ERR: c_int = 7;
const PAM_CRED_INSUFFICIENT: c_int = 8;
const PAM_AUTHINFO_UNAVAIL: c_int = 9;
const PAM_CONV: c_int = 5;
const PAM_USER: c_int = 2;
const PAM_PROMPT_ECHO_OFF: c_int = 1;

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
    fn pam_get_item(
        pamh: *const PamHandle,
        item_type: c_int,
        item: *mut *const c_void,
    ) -> c_int;
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

    let conv = &*(conv_ptr as *const PamConv);
    let conv_fn = conv.conv.ok_or(PAM_CRED_INSUFFICIENT)?;

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
        conv.appdata_ptr,
    );

    if ret != PAM_SUCCESS || resp_ptr.is_null() {
        return Err(PAM_CRED_INSUFFICIENT);
    }

    let resp = &*resp_ptr;
    if resp.resp.is_null() {
        free(resp_ptr as *mut c_void);
        return Err(PAM_CRED_INSUFFICIENT);
    }

    let password = CStr::from_ptr(resp.resp)
        .to_str()
        .map(|s| s.to_string())
        .map_err(|_| PAM_AUTH_ERR)?;

    // Zero out the C-allocated password before freeing
    let resp_len = libc::strlen(resp.resp);
    ptr::write_bytes(resp.resp as *mut u8, 0, resp_len);

    free(resp.resp as *mut c_void);
    free(resp_ptr as *mut c_void);

    Ok(password)
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

#[no_mangle]
pub unsafe extern "C" fn pam_sm_authenticate(
    pamh: *const PamHandle,
    _flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    let config_path = parse_config_path(argc, argv);
    PamLogger::init("info", "auth");

    let username = match get_pam_item_str(pamh, PAM_USER) {
        Ok(u) => u,
        Err(code) => {
            log::error!("failed to get PAM username");
            return code;
        }
    };

    let mut password = match get_password_via_conv(pamh) {
        Ok(p) => p,
        Err(code) => {
            log::error!("failed to get password for '{}'", username);
            return code;
        }
    };

    let result = authenticate(&username, &password, &config_path);

    // Zeroize the password copy in Rust memory
    password.zeroize();

    match result {
        AuthResult::Success => PAM_SUCCESS,
        AuthResult::InvalidCredentials(_) => PAM_AUTH_ERR,
        AuthResult::Error(_) => PAM_AUTHINFO_UNAVAIL,
    }
}

#[no_mangle]
pub unsafe extern "C" fn pam_sm_acct_mgmt(
    _pamh: *const PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn pam_sm_setcred(
    _pamh: *const PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_path() {
        assert_eq!(parse_config_path(0, ptr::null()), "/etc/pam_aws_sts.toml");
    }
}
