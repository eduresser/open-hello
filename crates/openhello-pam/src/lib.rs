#![allow(non_snake_case, clippy::missing_safety_doc)]

use std::ffi::{c_char, c_int, c_void, CStr};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Mutex};
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
const PAM_AUTHTOK: c_int = 6;
const INTERRUPT_POLL: Duration = Duration::from_millis(50);
const HANDLED_SIGNALS: [c_int; 2] = [libc::SIGINT, libc::SIGTERM];

static INTERRUPTION: AtomicI32 = AtomicI32::new(0);

extern "C" fn note_interruption(signal: c_int) {
    let _ = INTERRUPTION.compare_exchange(0, signal, Ordering::SeqCst, Ordering::SeqCst);
}

fn interrupted() -> bool {
    INTERRUPTION.load(Ordering::SeqCst) != 0
}

struct SignalGuard {
    previous: Vec<(c_int, libc::sigaction)>,
    mask: libc::sigset_t,
    interrupt_was_blocked: bool,
    interrupt_prior: &'static str,
}

impl SignalGuard {
    fn engage() -> Self {
        INTERRUPTION.store(0, Ordering::SeqCst);
        let (mask, interrupt_was_blocked) = unsafe { unblock_handled_signals() };
        let previous: Vec<(c_int, libc::sigaction)> = HANDLED_SIGNALS
            .iter()
            .map(|&signal| unsafe {
                let mut action: libc::sigaction = std::mem::zeroed();
                action.sa_sigaction = note_interruption as extern "C" fn(c_int) as usize;
                libc::sigemptyset(&mut action.sa_mask);
                let mut old: libc::sigaction = std::mem::zeroed();
                libc::sigaction(signal, &action, &mut old);
                (signal, old)
            })
            .collect();
        let interrupt_prior = match previous.first().map(|(_, old)| old.sa_sigaction) {
            Some(libc::SIG_IGN) => "ignored",
            Some(libc::SIG_DFL) => "default",
            _ => "handler",
        };
        Self {
            previous,
            mask,
            interrupt_was_blocked,
            interrupt_prior,
        }
    }

    fn describe(&self) -> String {
        format!(
            "signals sigint-blocked={} sigint-prior={}",
            self.interrupt_was_blocked, self.interrupt_prior
        )
    }
}

unsafe fn unblock_handled_signals() -> (libc::sigset_t, bool) {
    let mut wanted: libc::sigset_t = std::mem::zeroed();
    libc::sigemptyset(&mut wanted);
    for signal in HANDLED_SIGNALS {
        libc::sigaddset(&mut wanted, signal);
    }
    let mut before: libc::sigset_t = std::mem::zeroed();
    libc::pthread_sigmask(libc::SIG_UNBLOCK, &wanted, &mut before);
    let blocked = libc::sigismember(&before, libc::SIGINT) == 1;
    (before, blocked)
}

impl Drop for SignalGuard {
    fn drop(&mut self) {
        for (signal, old) in &self.previous {
            unsafe { libc::sigaction(*signal, old, std::ptr::null_mut()) };
        }
        unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &self.mask, std::ptr::null_mut()) };
        let caught = INTERRUPTION.swap(0, Ordering::SeqCst);
        if caught != 0 {
            unsafe { libc::raise(caught) };
        }
    }
}
const DEFAULT_TOKEN_SOCKET: &str = "/run/openhello/keyd-token.sock";
const VERIFY_GRACE: Duration = Duration::from_secs(2);
const VERIFY_TIMEOUT: Duration = openhello_auth_proto::FACE_ATTEMPT_BUDGET
    .saturating_add(openhello_auth_proto::FACE_DECISION_BUDGET)
    .saturating_add(VERIFY_GRACE);
const SIGN_TIMEOUT: Duration = Duration::from_secs(3);
const BUDGET: Duration = VERIFY_TIMEOUT.saturating_add(SIGN_TIMEOUT);
const BUS_NAME: &str = "io.openhello.Biometrics1";
const OBJECT_PATH: &str = "/io/openhello/Biometrics1";
const ALREADY_DECIDED: &str = "io.openhello.Error.AlreadyDecided";
const DEFAULT_AUTH_DIR: &str = "/etc/openhello/auth";
const ROOT_UID: u32 = 0;
const DENIED_SERVICES: [&str; 13] = [
    "login",
    "su",
    "su-l",
    "sshd",
    "cron",
    "crond",
    "atd",
    "passwd",
    "chsh",
    "chfn",
    "runuser",
    "runuser-l",
    "other",
];

extern "C" {
    fn pam_get_item(pamh: *const c_void, item: c_int, value: *mut *const c_void) -> c_int;
    fn pam_get_authtok(
        pamh: *mut c_void,
        item: c_int,
        authtok: *mut *const c_char,
        prompt: *const c_char,
    ) -> c_int;
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

unsafe fn eligible(
    pamh: *mut c_void,
    args: &[String],
) -> Result<(u32, String, p256::ecdsa::VerifyingKey), Exit> {
    local_session_allowed(pamh).map_err(|reason| {
        let text = with_probes(pamh, session::describe);
        debug::report_text(args.iter().any(|a| a == "debug"), &debug::syslog, &text);
        ignore(reason)
    })?;
    let user = item_text(pamh, PAM_USER)
        .filter(|u| !u.is_empty())
        .ok_or(ignore(Reason::NoUser))?;
    let uid = uid_of(&user).ok_or(ignore(Reason::NoUser))?;
    let service = item_text(pamh, PAM_SERVICE).unwrap_or_default();
    if !openhello_auth_proto::valid_service(&service) {
        return Err(ignore(Reason::ServiceDenied));
    }
    if uid == ROOT_UID {
        return Err(ignore(Reason::NoCredentialFile));
    }
    let key = registered_key(args, uid).map_err(ignore)?;
    Ok((uid, service, key))
}

fn module_settings(args: &[String]) -> Result<Settings, ()> {
    let config = args
        .iter()
        .find_map(|a| a.strip_prefix("config=").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from(config::DEFAULT_CONFIG));
    let found = config::current(&config::process_env, &config);
    with_default_socket(found, config.exists())
}

fn with_default_socket(
    found: Result<Settings, String>,
    config_exists: bool,
) -> Result<Settings, ()> {
    let settings = match found {
        Ok(settings) => settings,
        Err(_) if !config_exists => Settings::default(),
        Err(_) => return Err(()),
    };
    let token_socket = settings
        .token_socket
        .or_else(|| Some(DEFAULT_TOKEN_SOCKET.into()));
    Ok(Settings {
        token_socket,
        ..settings
    })
}

unsafe fn authenticate(pamh: *mut c_void, args: &[String]) -> Result<(), Exit> {
    let started = Instant::now();
    let (uid, service, key) = eligible(pamh, args)?;
    if login_manager_helper(pamh) && !password_left_empty(pamh) {
        return Err(ignore(Reason::PasswordTyped));
    }
    let settings = module_settings(args).map_err(|_| ignore(Reason::KeydUnavailable))?;
    let socket = settings
        .token_socket
        .clone()
        .ok_or(ignore(Reason::KeydUnavailable))?;
    service_available(&settings, started).map_err(ignore)?;
    let _signals = SignalGuard::engage();
    debug::report_text(
        args.iter().any(|a| a == "debug"),
        &debug::syslog,
        &_signals.describe(),
    );
    let challenge = challenge::random_challenge().ok_or(ignore(Reason::KeydUnavailable))?;
    let remaining = || BUDGET.saturating_sub(started.elapsed());
    match verify_face(
        uid,
        settings.bus_address.clone(),
        remaining().saturating_sub(SIGN_TIMEOUT).min(VERIFY_TIMEOUT),
    ) {
        Some(FaceVerdict::Match) => {}
        Some(FaceVerdict::NoMatch) => return Err(refuse(Reason::FaceRefused)),
        Some(FaceVerdict::AlreadyDecided) => return Err(ignore(Reason::AlreadyDecided)),
        None if interrupted() => return Err(ignore(Reason::Interrupted)),
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

fn within<T: Send + 'static>(
    timeout: Duration,
    work: impl FnOnce() -> T + Send + 'static,
) -> Option<T> {
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = sender.send(work());
    });
    let deadline = Instant::now() + timeout;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if interrupted() || left.is_zero() {
            return None;
        }
        match receiver.recv_timeout(left.min(INTERRUPT_POLL)) {
            Ok(value) => return Some(value),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return None,
        }
    }
}

type SharedConnection = Arc<Mutex<Option<zbus::blocking::Connection>>>;

enum FaceVerdict {
    Match,
    NoMatch,
    AlreadyDecided,
}

fn verify_face(uid: u32, bus_address: Option<String>, timeout: Duration) -> Option<FaceVerdict> {
    let link = SharedConnection::default();
    let worker = link.clone();
    let verdict = within(timeout, move || {
        call_verify(uid, bus_address.as_deref(), &worker)
    })
    .flatten();
    if verdict.is_none() {
        let open = link.lock().ok().and_then(|mut held| held.take());
        if let Some(connection) = open {
            let _ = connection.close();
        }
    }
    verdict
}

fn call_verify(uid: u32, bus_address: Option<&str>, link: &SharedConnection) -> Option<FaceVerdict> {
    let connection = connect_bus(bus_address)?;
    *link.lock().ok()? = Some(connection.clone());
    let proxy = zbus::blocking::Proxy::new(&connection, BUS_NAME, OBJECT_PATH, BUS_NAME).ok()?;
    match proxy.call::<_, _, bool>("VerifyForSignIn", &(uid,)) {
        Ok(true) => Some(FaceVerdict::Match),
        Ok(false) => Some(FaceVerdict::NoMatch),
        Err(zbus::Error::MethodError(name, _, _)) if name.as_str() == ALREADY_DECIDED => Some(FaceVerdict::AlreadyDecided),
        Err(_) => None,
    }
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

unsafe fn with_probes<T>(pamh: *mut c_void, use_probes: impl FnOnce(&session::Probes) -> T) -> T {
    let probes = session::Probes {
        rhost: item_text(pamh, PAM_RHOST).is_some_and(|h| !h.is_empty()),
        tty: item_text(pamh, PAM_TTY).is_some_and(|t| !t.is_empty()),
        env: &session::process_env,
        cgroup: &session::process_cgroup,
        session: &session::process_session,
        user: &session::process_user,
        sessions: &session::process_sessions,
    };
    use_probes(&probes)
}

unsafe fn local_session_allowed(pamh: *mut c_void) -> Result<(), Reason> {
    let locality = with_probes(pamh, session::locate);
    let service = item_text(pamh, PAM_SERVICE).unwrap_or_default();
    permitted(locality, &service)
}

unsafe fn login_manager_helper(pamh: *mut c_void) -> bool {
    with_probes(pamh, |probes| session::is_login_manager_helper(probes))
}

unsafe fn password_left_empty(pamh: *mut c_void) -> bool {
    let mut token: *const c_char = std::ptr::null();
    let rc = pam_get_authtok(pamh, PAM_AUTHTOK, &mut token, std::ptr::null());
    rc == PAM_SUCCESS && !token.is_null() && *token == 0
}

fn permitted(locality: Locality, service: &str) -> Result<(), Reason> {
    match locality {
        Locality::Remote => return Err(Reason::Remote),
        Locality::Unknown => return Err(Reason::NotLocal),
        Locality::Local => {}
    }
    if DENIED_SERVICES.contains(&service) {
        return Err(Reason::ServiceDenied);
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::{
        permitted, with_default_socket, Locality, Reason, Settings, BUDGET, DEFAULT_TOKEN_SOCKET,
        DENIED_SERVICES, SIGN_TIMEOUT, VERIFY_TIMEOUT,
    };
    use openhello_auth_proto::{FACE_ATTEMPT_BUDGET, FACE_DECISION_BUDGET};

    // @spec:AC-045
    #[test]
    fn a_missing_config_file_falls_back_to_the_default_token_socket() {
        let settings = with_default_socket(Err("cannot open".into()), false).unwrap();
        assert_eq!(settings.token_socket, Some(DEFAULT_TOKEN_SOCKET.into()));
        assert_eq!(settings.bus_address, None);
    }

    // @spec:AC-045
    #[test]
    fn an_existing_but_untrusted_config_file_is_still_refused() {
        assert!(with_default_socket(Err("must be owned by root".into()), true).is_err());
    }

    // @spec:AC-045
    #[test]
    fn a_configured_socket_wins_over_the_default() {
        let configured = Settings {
            token_socket: Some("/run/other.sock".into()),
            bus_address: None,
        };
        let settings = with_default_socket(Ok(configured), true).unwrap();
        assert_eq!(settings.token_socket, Some("/run/other.sock".into()));
        let empty = with_default_socket(Ok(Settings::default()), true).unwrap();
        assert_eq!(empty.token_socket, Some(DEFAULT_TOKEN_SOCKET.into()));
    }

    #[test]
    fn remote_or_headless_sessions_are_ignored_before_the_service_is_considered() {
        for service in ["sudo", "sshd"] {
            assert_eq!(permitted(Locality::Remote, service), Err(Reason::Remote));
            assert_eq!(permitted(Locality::Unknown, service), Err(Reason::NotLocal));
        }
    }

    // @covers:AC-028-pam-local-session
    #[test]
    fn denylisted_services_are_ignored_and_every_other_local_service_acts() {
        for service in DENIED_SERVICES {
            assert_eq!(
                permitted(Locality::Local, service),
                Err(Reason::ServiceDenied),
                "{service}"
            );
        }
        for service in ["sudo", "polkit-1", "openhello-interactive", "loginx", ""] {
            assert_eq!(permitted(Locality::Local, service), Ok(()), "{service}");
        }
    }

    // @covers:AC-041-pam-budget
    #[test]
    fn the_module_waits_for_the_daemon_verdict_and_the_total_budget_covers_the_signature() {
        assert!(VERIFY_TIMEOUT > FACE_ATTEMPT_BUDGET + FACE_DECISION_BUDGET);
        assert!(BUDGET >= VERIFY_TIMEOUT + SIGN_TIMEOUT);
    }

    #[test]
    fn unknown_users_have_no_uid() {
        assert!(super::uid_of("root") == Some(0));
        assert!(super::uid_of("openhello-no-such-user").is_none());
    }
}
