#![allow(non_snake_case, clippy::missing_safety_doc)]

use std::ffi::{c_char, c_int, c_void, CStr};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

mod challenge;
mod debug;
mod session;

// Shared source, not a dependency: depending on the wrapper crate would export its PKCS#11 symbols from this module.
#[allow(dead_code)]
#[path = "../../openhello-pkcs11/src/config.rs"]
mod config;

use challenge::SignError;
use config::Settings;
use debug::Reason;
use session::Locality;

const PAM_SUCCESS: c_int = 0;
const PAM_AUTH_ERR: c_int = 7;
const PAM_IGNORE: c_int = 25;
const PAM_SERVICE: c_int = 1;
const PAM_TTY: c_int = 3;
const PAM_RHOST: c_int = 4;
const PAM_USER: c_int = 2;
const PAM_CONV: c_int = 5;
const PAM_TEXT_INFO: c_int = 4;
const BUDGET: Duration = Duration::from_secs(5);
const VERIFY_TIMEOUT: Duration = Duration::from_secs(4);
const BUS_NAME: &str = "io.openhello.Biometrics1";
const OBJECT_PATH: &str = "/io/openhello/Biometrics1";
const DEFAULT_AUTH_DIR: &str = "/etc/openhello/auth";
const ROOT_UID: u32 = 0;
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
}

#[no_mangle]
pub unsafe extern "C" fn pam_sm_authenticate(
    pamh: *mut c_void,
    _flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    let args = arguments(argc, argv);
    let (code, reason) = match authenticate(pamh, &args) {
        Ok(()) => (PAM_SUCCESS, Reason::Success),
        Err(Exit { code, reason }) => (code, reason),
    };
    let service = item_text(pamh, PAM_SERVICE).unwrap_or_default();
    debug::report(
        args.iter().any(|a| a == "debug"),
        &debug::syslog,
        reason,
        &service,
    );
    code
}

struct Exit {
    code: c_int,
    reason: Reason,
}

fn ignore(reason: Reason) -> Exit {
    Exit {
        code: PAM_IGNORE,
        reason,
    }
}

fn refuse(reason: Reason) -> Exit {
    Exit {
        code: PAM_AUTH_ERR,
        reason,
    }
}

unsafe fn authenticate(pamh: *mut c_void, args: &[String]) -> Result<(), Exit> {
    let started = Instant::now();
    local_session_allowed(pamh, args).map_err(ignore)?;
    let user = item_text(pamh, PAM_USER)
        .filter(|u| !u.is_empty())
        .ok_or(ignore(Reason::NoUser))?;
    let uid = uid_of(&user).ok_or(ignore(Reason::NoUser))?;
    let service = item_text(pamh, PAM_SERVICE).unwrap_or_default();
    if !openhello_auth_proto::valid_service(&service) {
        return Err(ignore(Reason::ServiceNotAllowed));
    }
    let key = registered_key(args, uid).map_err(ignore)?;
    let config = args
        .iter()
        .find_map(|a| a.strip_prefix("config=").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from(config::DEFAULT_CONFIG));
    let settings = config::current(&config::process_env, &config)
        .map_err(|_| ignore(Reason::KeydUnavailable))?;
    let socket = settings
        .token_socket
        .clone()
        .ok_or(ignore(Reason::KeydUnavailable))?;
    service_available(&settings, started).map_err(ignore)?;
    let challenge = challenge::random_challenge().ok_or(ignore(Reason::KeydUnavailable))?;
    tell(pamh, LOOKING_FOR_FACE);
    let remaining = || BUDGET.saturating_sub(started.elapsed());
    match verify_face(
        uid,
        settings.bus_address.clone(),
        remaining().min(VERIFY_TIMEOUT),
    ) {
        Some(true) => {}
        Some(false) => return Err(refuse(Reason::FaceRefused)),
        None => return Err(ignore(Reason::OpenhellodUnavailable)),
    }
    match challenge::request_signature(&socket, uid, &service, &challenge, remaining()) {
        Ok(signature)
            if challenge::signature_is_valid(&key, uid, &service, &challenge, &signature) =>
        {
            Ok(())
        }
        Ok(_) => Err(refuse(Reason::SignatureInvalid)),
        Err(SignError::Refused) => Err(refuse(Reason::FaceRefused)),
        Err(SignError::Unavailable) => Err(ignore(Reason::KeydUnavailable)),
    }
}

fn uid_of(user: &str) -> Option<u32> {
    let name = std::ffi::CString::new(user).ok()?;
    let mut buffer = vec![0u8; 4096];
    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    let mut found: *mut libc::passwd = std::ptr::null_mut();
    let rc = unsafe {
        libc::getpwnam_r(
            name.as_ptr(),
            &mut entry,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut found,
        )
    };
    (rc == 0 && !found.is_null()).then_some(entry.pw_uid)
}

// trusted_uid exists for unprivileged test runs; a privileged caller always requires root.
fn registered_key(args: &[String], uid: u32) -> Result<p256::ecdsa::VerifyingKey, Reason> {
    let dir = args
        .iter()
        .find_map(|a| a.strip_prefix("authdir=").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from(DEFAULT_AUTH_DIR));
    let (ruid, euid) = unsafe { (libc::getuid(), libc::geteuid()) };
    let owner = if config::is_privileged(ruid, euid) {
        ROOT_UID
    } else {
        args.iter()
            .find_map(|a| a.strip_prefix("trusted_uid=")?.parse().ok())
            .unwrap_or(ROOT_UID)
    };
    challenge::load_public_key(&dir, uid, owner).ok_or_else(|| {
        if dir
            .join(openhello_auth_proto::public_key_file_name(uid))
            .exists()
        {
            Reason::CredentialFileUntrusted
        } else {
            Reason::NoCredentialFile
        }
    })
}

fn verify_face(uid: u32, bus_address: Option<String>, timeout: Duration) -> Option<bool> {
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = sender.send(call_verify(uid, bus_address.as_deref()));
    });
    receiver.recv_timeout(timeout).ok().flatten()
}

fn call_verify(uid: u32, bus_address: Option<&str>) -> Option<bool> {
    let connection = connect_bus(bus_address)?;
    let proxy = zbus::blocking::Proxy::new(&connection, BUS_NAME, OBJECT_PATH, BUS_NAME).ok()?;
    proxy.call("Verify", &(uid,)).ok()
}

fn connect_bus(address: Option<&str>) -> Option<zbus::blocking::Connection> {
    match address {
        Some(address) => zbus::blocking::connection::Builder::address(address)
            .and_then(|builder| builder.build())
            .ok(),
        None => zbus::blocking::Connection::system().ok(),
    }
}

unsafe fn item_text(pamh: *mut c_void, item: c_int) -> Option<String> {
    let mut value: *const c_void = std::ptr::null();
    if pam_get_item(pamh, item, &mut value) != PAM_SUCCESS || value.is_null() {
        return None;
    }
    CStr::from_ptr(value.cast())
        .to_str()
        .ok()
        .map(str::to_string)
}

unsafe fn local_session_allowed(pamh: *mut c_void, args: &[String]) -> Result<(), Reason> {
    let probes = session::Probes {
        rhost: item_text(pamh, PAM_RHOST).is_some_and(|h| !h.is_empty()),
        tty: item_text(pamh, PAM_TTY).is_some_and(|t| !t.is_empty()),
        env: &session::process_env,
        cgroup: &session::process_cgroup,
        session: &session::process_session,
    };
    let service = item_text(pamh, PAM_SERVICE).unwrap_or_default();
    let allowlist = args
        .iter()
        .find_map(|a| a.strip_prefix("allowlist=").map(PathBuf::from));
    permitted(session::locate(&probes), &service, allowlist.as_deref())
}

// A missing or untrusted allowlist denies: the common-stack placement must never reach the camera by default.
fn permitted(locality: Locality, service: &str, allowlist: Option<&Path>) -> Result<(), Reason> {
    match locality {
        Locality::Remote => return Err(Reason::Remote),
        Locality::Unknown => return Err(Reason::NotLocal),
        Locality::Local => {}
    }
    let Some(path) = allowlist else {
        return Ok(());
    };
    let (ruid, euid) = unsafe { (libc::getuid(), libc::geteuid()) };
    let text = if config::is_privileged(ruid, euid) {
        config::read_trusted(path, 0).ok()
    } else {
        std::fs::read_to_string(path).ok()
    };
    let listed = text.is_some_and(|t| {
        t.lines()
            .map(str::trim)
            .any(|l| !l.is_empty() && !l.starts_with('#') && l == service)
    });
    listed.then_some(()).ok_or(Reason::ServiceNotAllowed)
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

fn service_available(settings: &Settings, started: Instant) -> Result<(), Reason> {
    let socket = settings
        .token_socket
        .as_deref()
        .ok_or(Reason::KeydUnavailable)?;
    let remaining = || BUDGET.saturating_sub(started.elapsed());
    if !unix_socket_accepts(socket, remaining()) {
        return Err(Reason::KeydUnavailable);
    }
    if !bus_name_owned(settings.bus_address.clone(), remaining()) {
        return Err(Reason::OpenhellodUnavailable);
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::{permitted, Locality, Reason};

    #[test]
    fn remote_or_headless_sessions_are_ignored_before_the_allowlist() {
        assert_eq!(
            permitted(Locality::Remote, "sudo", None),
            Err(Reason::Remote)
        );
        assert_eq!(
            permitted(Locality::Unknown, "sudo", None),
            Err(Reason::NotLocal)
        );
        assert_eq!(permitted(Locality::Local, "sudo", None), Ok(()));
    }

    // @covers:AC-028-pam-local-session
    #[test]
    fn a_missing_allowlist_file_denies_with_service_not_allowed() {
        let missing = std::path::Path::new("/nonexistent/openhello-allowlist");
        assert_eq!(
            permitted(Locality::Local, "sudo", Some(missing)),
            Err(Reason::ServiceNotAllowed)
        );
    }

    #[test]
    fn unknown_users_have_no_uid() {
        assert!(super::uid_of("root") == Some(0));
        assert!(super::uid_of("openhello-no-such-user").is_none());
    }
}
