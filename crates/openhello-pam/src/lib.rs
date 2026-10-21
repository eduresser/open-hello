#![allow(non_snake_case, clippy::missing_safety_doc)]

use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

// Shared source, not a dependency: depending on the wrapper crate would export its PKCS#11 symbols from this module.
#[allow(dead_code)]
#[path = "../../openhello-pkcs11/src/config.rs"]
mod config;

use config::{Settings, PLACEHOLDER_PIN};

const PAM_SUCCESS: c_int = 0;
const PAM_IGNORE: c_int = 25;
const PAM_CONV: c_int = 5;
const PAM_AUTHTOK: c_int = 6;
const PAM_TEXT_INFO: c_int = 4;
const BUDGET: Duration = Duration::from_secs(5);
const BUS_NAME: &str = "io.openhello.Biometrics1";
const LOOKING_FOR_FACE: &CStr = c"Looking for your face...";

#[repr(C)]
struct PamMessage {
    style: c_int,
    text: *const c_char,
}

#[repr(C)]
struct PamResponse {
    text: *mut c_char,
    code: c_int,
}

type ConvFn = unsafe extern "C" fn(
    c_int,
    *mut *const PamMessage,
    *mut *mut PamResponse,
    *mut c_void,
) -> c_int;

#[repr(C)]
struct PamConv {
    conv: Option<ConvFn>,
    data: *mut c_void,
}

extern "C" {
    fn pam_get_item(pamh: *const c_void, item: c_int, value: *mut *const c_void) -> c_int;
    fn pam_set_item(pamh: *mut c_void, item: c_int, value: *const c_void) -> c_int;
}

// Success only means "placeholder set"; the stack maps it to ignore so this module can never grant access, and ignore skips pam_pkcs11, which crashes without a first password.
#[no_mangle]
pub unsafe extern "C" fn pam_sm_authenticate(
    pamh: *mut c_void,
    _flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    let args = arguments(argc, argv);
    if args.iter().any(|a| a == "clear") {
        pam_set_item(pamh, PAM_AUTHTOK, std::ptr::null());
        return PAM_IGNORE;
    }
    let started = Instant::now();
    let config = args
        .iter()
        .find_map(|a| a.strip_prefix("config=").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from(config::DEFAULT_CONFIG));
    let Ok(settings) = config::current(&config::process_env, &config) else {
        return PAM_IGNORE;
    };
    if !service_available(&settings, started) {
        return PAM_IGNORE;
    }
    tell(pamh, LOOKING_FOR_FACE);
    if let Ok(placeholder) = CString::new(PLACEHOLDER_PIN) {
        pam_set_item(pamh, PAM_AUTHTOK, placeholder.as_ptr().cast());
    }
    PAM_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn pam_sm_setcred(
    _pamh: *mut c_void,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_IGNORE
}

unsafe fn arguments(argc: c_int, argv: *const *const c_char) -> Vec<String> {
    (0..argc.max(0) as usize)
        .filter_map(|i| CStr::from_ptr(*argv.add(i)).to_str().ok())
        .map(str::to_string)
        .collect()
}

fn service_available(settings: &Settings, started: Instant) -> bool {
    let Some(socket) = settings.token_socket.as_deref() else {
        return false;
    };
    let remaining = || BUDGET.saturating_sub(started.elapsed());
    unix_socket_accepts(socket, remaining())
        && bus_name_owned(settings.bus_address.clone(), remaining())
}

fn unix_socket_accepts(path: &Path, timeout: Duration) -> bool {
    let bytes = path.as_os_str().as_bytes();
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if bytes.len() >= address.sun_path.len() {
        return false;
    }
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (slot, byte) in address.sun_path.iter_mut().zip(bytes) {
        *slot = *byte as c_char;
    }
    unsafe {
        let fd = libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        );
        if fd < 0 {
            return false;
        }
        let rc = libc::connect(
            fd,
            (&address as *const libc::sockaddr_un).cast(),
            std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
        );
        let accepted = rc == 0
            || (*libc::__errno_location() == libc::EINPROGRESS && wait_connected(fd, timeout));
        libc::close(fd);
        accepted
    }
}

unsafe fn wait_connected(fd: c_int, timeout: Duration) -> bool {
    let mut poll = libc::pollfd {
        fd,
        events: libc::POLLOUT,
        revents: 0,
    };
    if libc::poll(&mut poll, 1, timeout.as_millis() as c_int) != 1 {
        return false;
    }
    let mut error: c_int = 0;
    let mut len = std::mem::size_of::<c_int>() as libc::socklen_t;
    libc::getsockopt(
        fd,
        libc::SOL_SOCKET,
        libc::SO_ERROR,
        (&mut error as *mut c_int).cast(),
        &mut len,
    ) == 0
        && error == 0
}

fn bus_name_owned(address: Option<String>, timeout: Duration) -> bool {
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = sender.send(name_has_owner(address.as_deref()));
    });
    receiver.recv_timeout(timeout).unwrap_or(false)
}

fn name_has_owner(address: Option<&str>) -> bool {
    let connection = match address {
        Some(address) => zbus::blocking::connection::Builder::address(address)
            .and_then(|builder| builder.build()),
        None => zbus::blocking::Connection::system(),
    };
    let Ok(connection) = connection else {
        return false;
    };
    let Ok(bus) = zbus::blocking::fdo::DBusProxy::new(&connection) else {
        return false;
    };
    zbus::names::BusName::try_from(BUS_NAME)
        .ok()
        .and_then(|name| bus.name_has_owner(name).ok())
        .unwrap_or(false)
}

unsafe fn tell(pamh: *mut c_void, text: &CStr) {
    let mut conv: *const c_void = std::ptr::null();
    if pam_get_item(pamh, PAM_CONV, &mut conv) != PAM_SUCCESS || conv.is_null() {
        return;
    }
    let conv = &*(conv as *const PamConv);
    let Some(callback) = conv.conv else {
        return;
    };
    let message = PamMessage {
        style: PAM_TEXT_INFO,
        text: text.as_ptr(),
    };
    let mut messages: *const PamMessage = &message;
    let mut responses: *mut PamResponse = std::ptr::null_mut();
    callback(1, &mut messages, &mut responses, conv.data);
    if !responses.is_null() {
        libc::free((*responses).text.cast());
        libc::free(responses.cast());
    }
}
