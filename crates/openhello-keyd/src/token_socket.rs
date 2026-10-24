use crate::logging::{log, Level, Value};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, CertificateType, ObjectClass, ObjectHandle};
use cryptoki_sys::{CKM_ECDSA, CK_ATTRIBUTE};
use zeroize::Zeroizing;

use crate::tpm::{failure, lock, p11_failure, Guard, Token};
use crate::unlock_socket::peer_uid;
use crate::{KeydError, Protectors};

pub const OP_TOKEN_HELLO: u8 = 1;
pub const OP_TOKEN_INFO: u8 = 2;
pub const OP_TOKEN_OPEN: u8 = 3;
pub const OP_TOKEN_CLOSE: u8 = 4;
pub const OP_TOKEN_LOGIN: u8 = 5;
pub const OP_TOKEN_LOGOUT: u8 = 6;
pub const OP_TOKEN_FIND: u8 = 7;
pub const OP_TOKEN_ATTRIBUTES: u8 = 8;
pub const OP_TOKEN_SIGN_CHECK: u8 = 9;
pub const OP_TOKEN_SIGN: u8 = 10;
pub const OP_TOKEN_AUTH: u8 = 11;
pub use openhello_auth_proto::{OP_TOKEN_AUTH_RELEASE, OP_TOKEN_SEAL_SECRET};

pub const TOKEN_OK: u8 = 0;
pub const TOKEN_PIN_INCORRECT: u8 = 1;
pub const TOKEN_NO_TOKEN: u8 = 2;
pub const TOKEN_BAD_HANDLE: u8 = 3;
pub const TOKEN_BAD_REQUEST: u8 = 4;
pub const TOKEN_REFUSED: u8 = 5;
pub const TOKEN_FAILED: u8 = 6;
pub const TOKEN_BAD_MECHANISM: u8 = 7;

pub const ATTRIBUTE_INVALID: u8 = 0;
pub const ATTRIBUTE_SENSITIVE: u8 = 1;
pub const ATTRIBUTE_READ: u8 = 2;

pub const TOKEN_INFO_LEN: usize = 32 + 32 + 16 + 16 + 8;
pub const TOKEN_PLACEHOLDER_PIN: &[u8] = b"openhello-face";
pub const MAX_TOKEN_REQUEST: usize = 1024;
pub const SIGNATURE_LEN: usize = 64;

const CKA_CLASS: u64 = 0x0;
const CKA_TOKEN: u64 = 0x1;
const CKA_VALUE: u64 = 0x11;
const CKA_CERTIFICATE_TYPE: u64 = 0x80;
const CKA_ISSUER: u64 = 0x81;
const CKA_SERIAL_NUMBER: u64 = 0x82;
const CKA_SUBJECT: u64 = 0x101;
const CKA_LABEL: u64 = 0x3;
const CKA_ID: u64 = 0x102;
const CKA_SIGN: u64 = 0x108;
const CKF_LOGIN_REQUIRED: u64 = 0x4;
const CKF_USER_PIN_INITIALIZED: u64 = 0x8;
const CKF_TOKEN_INITIALIZED: u64 = 0x400;
const ROOT_UID: u32 = 0;
const MAX_PIN_LEN: usize = 64;
const MAX_SIGN_INPUT: usize = 128;
const MAX_EXPOSED: usize = 256;
const MAX_ATTRIBUTES: usize = 16;
const MAX_TEMPLATE: usize = 8;
const MAX_LOGINS: u8 = 3;
const MAX_CONNECTIONS: usize = 16;
const MAX_CONNECTIONS_PER_UID: usize = 4;
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const TOKEN_HELD_TIMEOUT: Duration = Duration::from_secs(5);
const LIFETIME: Duration = Duration::from_secs(120);
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);

const EXPOSED_CLASSES: [ObjectClass; 3] = [
    ObjectClass::CERTIFICATE,
    ObjectClass::PUBLIC_KEY,
    ObjectClass::PRIVATE_KEY,
];

const PRIVATE_KEY_READABLE: [AttributeType; 14] = [
    AttributeType::Class,
    AttributeType::Token,
    AttributeType::Private,
    AttributeType::Label,
    AttributeType::KeyType,
    AttributeType::Id,
    AttributeType::Sign,
    AttributeType::Sensitive,
    AttributeType::Extractable,
    AttributeType::AlwaysSensitive,
    AttributeType::NeverExtractable,
    AttributeType::Local,
    AttributeType::EcParams,
    AttributeType::AlwaysAuthenticate,
];

#[derive(Debug, Clone)]
pub struct TokenSocketConfig {
    pub path: PathBuf,
}

pub struct TokenSocket {
    path: PathBuf,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

#[derive(Default)]
struct Admission {
    total: usize,
    per_uid: HashMap<u32, usize>,
}

struct Permit {
    admission: Arc<Mutex<Admission>>,
    uid: u32,
}

impl Permit {
    fn acquire(admission: &Arc<Mutex<Admission>>, uid: u32) -> Option<Self> {
        let mut state = admission.lock().unwrap_or_else(PoisonError::into_inner);
        let mine = state.per_uid.get(&uid).copied().unwrap_or(0);
        if state.total >= MAX_CONNECTIONS || mine >= MAX_CONNECTIONS_PER_UID {
            return None;
        }
        state.total += 1;
        state.per_uid.insert(uid, mine + 1);
        Some(Self {
            admission: admission.clone(),
            uid,
        })
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        let mut state = self
            .admission
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        state.total -= 1;
        if let Some(mine) = state.per_uid.get_mut(&self.uid) {
            *mine -= 1;
            if *mine == 0 {
                state.per_uid.remove(&self.uid);
            }
        }
    }
}

impl TokenSocket {
    pub fn bind(protectors: Arc<Protectors>, config: TokenSocketConfig) -> Result<Self, KeydError> {
        Self::bind_as(protectors, config, None)
    }

    // Lets tests play the root peer (setuid sudo) without running as root; release builds cannot set it.
    #[cfg(debug_assertions)]
    pub fn bind_with_peer_uid(
        protectors: Arc<Protectors>,
        config: TokenSocketConfig,
        peer_uid: u32,
    ) -> Result<Self, KeydError> {
        Self::bind_as(protectors, config, Some(peer_uid))
    }

    fn bind_as(
        protectors: Arc<Protectors>,
        config: TokenSocketConfig,
        peer_override: Option<u32>,
    ) -> Result<Self, KeydError> {
        if config.path.exists() {
            std::fs::remove_file(&config.path)
                .map_err(|e| failure("replacing the token socket", &e.to_string(), &[]))?;
        }
        let listener = UnixListener::bind(&config.path)
            .map_err(|e| failure("binding the token socket", &e.to_string(), &[]))?;
        // Any local user may connect; SO_PEERCRED, not the file mode, decides whose token is addressed.
        std::fs::set_permissions(&config.path, std::fs::Permissions::from_mode(0o666))
            .map_err(|e| failure("opening the token socket to users", &e.to_string(), &[]))?;
        let stop = Arc::new(AtomicBool::new(false));
        let admission = Arc::new(Mutex::new(Admission::default()));
        let thread = {
            let stop = stop.clone();
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    let Ok(stream) = stream else { continue };
                    let Some(peer) = peer_override.or_else(|| peer_uid(&stream)) else {
                        continue;
                    };
                    let Some(permit) = Permit::acquire(&admission, peer) else {
                        log(
                            Level::Warn,
                            "token-refused",
                            &[
                                ("uid", Value::Uid(peer)),
                                ("reason", Value::Label("too many connections")),
                            ],
                        );
                        continue;
                    };
                    let protectors = protectors.clone();
                    std::thread::spawn(move || {
                        serve(&protectors, stream, peer);
                        drop(permit);
                    });
                }
            })
        };
        Ok(Self {
            path: config.path,
            stop,
            thread: Some(thread),
        })
    }

    pub fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl Drop for TokenSocket {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = UnixStream::connect(&self.path);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

struct Open {
    token: Token,
    _guard: Guard,
    logged_in: bool,
    exposed: HashMap<u64, (ObjectHandle, ObjectClass)>,
    next_handle: u64,
}

struct Connection<'a> {
    protectors: &'a Protectors,
    peer: u32,
    uid: Option<u32>,
    session_requested: bool,
    present: Option<bool>,
    logins: u8,
    auths: u8,
    open: Option<Open>,
    dead: bool,
}

type Reply = Result<Vec<u8>, u8>;

fn serve(protectors: &Protectors, mut stream: UnixStream, peer: u32) {
    let started = Instant::now();
    let _ = stream.set_write_timeout(Some(WRITE_TIMEOUT));
    let mut connection = Connection {
        protectors,
        peer,
        uid: None,
        session_requested: false,
        present: None,
        logins: 0,
        auths: 0,
        open: None,
        dead: false,
    };
    while started.elapsed() < LIFETIME && !connection.dead {
        let timeout = if connection.open.is_some() {
            TOKEN_HELD_TIMEOUT
        } else {
            IDLE_TIMEOUT
        };
        let _ = stream.set_read_timeout(Some(timeout));
        let Some((op, payload)) = read_frame(&mut stream) else {
            break;
        };
        let reply = connection.handle(op, &payload);
        let (status, body) = match reply {
            Ok(body) => (TOKEN_OK, Zeroizing::new(body)),
            Err(status) => (status, Zeroizing::new(Vec::new())),
        };
        if write_reply(&mut stream, status, &body).is_err() {
            break;
        }
    }
}

impl Connection<'_> {
    fn handle(&mut self, op: u8, payload: &Zeroizing<Vec<u8>>) -> Reply {
        if op == OP_TOKEN_HELLO {
            return self.hello(payload);
        }
        let uid = self
            .uid
            .ok_or_else(|| self.violation("request before hello"))?;
        match op {
            OP_TOKEN_INFO if payload.is_empty() => self.info(uid),
            OP_TOKEN_OPEN if payload.is_empty() => self.request_session(uid),
            OP_TOKEN_CLOSE if payload.is_empty() => self.close(),
            OP_TOKEN_LOGIN => self.login(uid, payload),
            OP_TOKEN_LOGOUT if payload.is_empty() => self.logout(),
            OP_TOKEN_FIND => self.find(uid, payload),
            OP_TOKEN_ATTRIBUTES => self.attributes(payload),
            OP_TOKEN_SIGN_CHECK => self.sign_check(payload),
            OP_TOKEN_SIGN => self.sign(uid, payload),
            OP_TOKEN_AUTH => self.auth(uid, payload),
            OP_TOKEN_AUTH_RELEASE => self.auth_release(uid, payload),
            OP_TOKEN_SEAL_SECRET => self.seal_secret(uid, payload),
            _ => Err(self.violation("unknown or malformed operation")),
        }
    }

    fn violation(&mut self, reason: &'static str) -> u8 {
        self.dead = true;
        log(
            Level::Warn,
            "token-refused",
            &[
                ("uid", Value::Uid(self.peer)),
                ("reason", Value::Label(reason)),
            ],
        );
        TOKEN_BAD_REQUEST
    }

    fn hello(&mut self, payload: &[u8]) -> Reply {
        let bytes: [u8; 4] = payload
            .try_into()
            .map_err(|_| self.violation("malformed hello"))?;
        let named = u32::from_be_bytes(bytes);
        if self.uid.is_some() {
            return Err(self.violation("second hello"));
        }
        let allowed =
            crate::validate_uid(named).is_ok() && (self.peer == ROOT_UID || named == self.peer);
        if !allowed {
            self.dead = true;
            log(
                Level::Warn,
                "token-refused",
                &[
                    ("uid", Value::Uid(self.peer)),
                    ("reason", Value::Label("uid not allowed for this peer")),
                ],
            );
            return Err(TOKEN_REFUSED);
        }
        self.uid = Some(named);
        log(Level::Debug, "token-hello", &[("uid", Value::Uid(named))]);
        Ok(Vec::new())
    }

    fn token_present(&mut self, uid: u32) -> bool {
        if self.present != Some(true) {
            self.present = Some(self.protectors.keyd().token_exists(uid).unwrap_or(false));
        }
        self.present == Some(true)
    }

    fn info(&mut self, uid: u32) -> Reply {
        if !self.token_present(uid) {
            return Err(TOKEN_NO_TOKEN);
        }
        let mut info = Vec::with_capacity(TOKEN_INFO_LEN);
        info.extend_from_slice(&padded(&crate::provision::token_label(uid), 32));
        info.extend_from_slice(&padded("open-hello", 32));
        info.extend_from_slice(&padded("TPM2 token", 16));
        info.extend_from_slice(&padded(&format!("{uid:016}"), 16));
        let flags = CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED | CKF_TOKEN_INITIALIZED;
        info.extend_from_slice(&flags.to_be_bytes());
        Ok(info)
    }

    fn request_session(&mut self, uid: u32) -> Reply {
        if self.session_requested {
            return Err(TOKEN_BAD_REQUEST);
        }
        if !self.token_present(uid) {
            return Err(TOKEN_NO_TOKEN);
        }
        self.session_requested = true;
        Ok(Vec::new())
    }

    fn close(&mut self) -> Reply {
        if !self.session_requested {
            return Err(TOKEN_BAD_REQUEST);
        }
        self.session_requested = false;
        self.open = None;
        Ok(Vec::new())
    }

    fn real_session(&mut self, uid: u32) -> Result<&mut Open, u8> {
        if !self.session_requested {
            return Err(TOKEN_BAD_REQUEST);
        }
        if self.open.is_none() {
            let guard = lock();
            guard.reset_module();
            let token = self
                .protectors
                .config
                .open_token(&guard, &crate::provision::token_label(uid))
                .map_err(|e| match e {
                    KeydError::NotProvisioned => TOKEN_NO_TOKEN,
                    _ => TOKEN_FAILED,
                })?;
            self.open = Some(Open {
                token,
                _guard: guard,
                logged_in: false,
                exposed: HashMap::new(),
                next_handle: 1,
            });
        }
        self.open.as_mut().ok_or(TOKEN_FAILED)
    }

    fn login(&mut self, uid: u32, pin: &Zeroizing<Vec<u8>>) -> Reply {
        if pin.is_empty() || pin.len() > MAX_PIN_LEN {
            return Err(TOKEN_PIN_INCORRECT);
        }
        if self.logins >= MAX_LOGINS {
            log(
                Level::Warn,
                "token-login-refused",
                &[
                    ("uid", Value::Uid(uid)),
                    (
                        "reason",
                        Value::Label("too many attempts on this connection"),
                    ),
                ],
            );
            self.dead = true;
            return Err(TOKEN_REFUSED);
        }
        self.logins += 1;
        let result = self.try_login(uid, pin);
        let (level, event) = match result {
            Ok(_) => (Level::Debug, "token-login-accepted"),
            Err(_) => (Level::Warn, "token-login-refused"),
        };
        log(level, event, &[("uid", Value::Uid(uid))]);
        result
    }

    fn try_login(&mut self, uid: u32, pin: &Zeroizing<Vec<u8>>) -> Reply {
        let protectors = self.protectors;
        let open = self.real_session(uid)?;
        if open.logged_in {
            return Err(TOKEN_BAD_REQUEST);
        }
        let secret = if pin.as_slice() == TOKEN_PLACEHOLDER_PIN {
            protectors.take_grant(uid).ok_or(TOKEN_PIN_INCORRECT)?
        } else {
            let typed = std::str::from_utf8(pin).map_err(|_| TOKEN_PIN_INCORRECT)?;
            protectors
                .unlock_with_pin(uid, typed)
                .map_err(|_| TOKEN_PIN_INCORRECT)?
        };
        open.token.login(&secret).map_err(|e| match e {
            KeydError::AuthenticationFailed => TOKEN_PIN_INCORRECT,
            _ => TOKEN_FAILED,
        })?;
        open.logged_in = true;
        Ok(Vec::new())
    }

    fn logout(&mut self) -> Reply {
        let open = self
            .open
            .as_mut()
            .filter(|o| o.logged_in)
            .ok_or(TOKEN_BAD_REQUEST)?;
        open.logged_in = false;
        open.token
            .session
            .logout()
            .map_err(|e| failed("logging out of the token", &e))?;
        Ok(Vec::new())
    }

    fn find(&mut self, uid: u32, payload: &[u8]) -> Reply {
        let Some(template) = parse_template(payload) else {
            return Err(TOKEN_BAD_REQUEST);
        };
        let open = self.real_session(uid)?;
        let handles = open
            .token
            .session
            .find_objects(&template)
            .map_err(|e| failed("searching the token", &e))?;
        let mut reply = Vec::new();
        for handle in handles {
            let Some(class) = class_of(open, handle) else {
                continue;
            };
            if !EXPOSED_CLASSES.contains(&class) {
                continue;
            }
            let exposed = open.expose(handle, class).ok_or(TOKEN_REFUSED)?;
            reply.extend_from_slice(&exposed.to_be_bytes());
        }
        Ok(reply)
    }

    fn attributes(&mut self, payload: &[u8]) -> Reply {
        if payload.len() < 9 {
            return Err(TOKEN_BAD_REQUEST);
        }
        let handle = u64::from_be_bytes(payload[..8].try_into().map_err(|_| TOKEN_BAD_REQUEST)?);
        let count = usize::from(payload[8]);
        if count == 0 || count > MAX_ATTRIBUTES || payload.len() != 9 + count * 8 {
            return Err(TOKEN_BAD_REQUEST);
        }
        let open = self.open.as_mut().ok_or(TOKEN_BAD_REQUEST)?;
        let (object, class) = *open.exposed.get(&handle).ok_or(TOKEN_BAD_HANDLE)?;
        let mut reply = Vec::new();
        for chunk in payload[9..].as_chunks::<8>().0 {
            let raw = u64::from_be_bytes(*chunk);
            let (state, value) = read_attribute(open, object, class, raw);
            let Ok(len) = u16::try_from(value.len()) else {
                return Err(TOKEN_FAILED);
            };
            reply.extend_from_slice(&raw.to_be_bytes());
            reply.push(state);
            reply.extend_from_slice(&len.to_be_bytes());
            reply.extend_from_slice(&value);
        }
        Ok(reply)
    }

    fn sign_check(&mut self, payload: &[u8]) -> Reply {
        let open = self.open.as_mut().ok_or(TOKEN_BAD_REQUEST)?;
        sign_target(open, payload)?;
        Ok(Vec::new())
    }

    fn sign(&mut self, uid: u32, payload: &[u8]) -> Reply {
        let open = self.open.as_mut().ok_or(TOKEN_BAD_REQUEST)?;
        let key = sign_target(open, payload.get(..16).unwrap_or_default())?;
        let data = &payload[16..];
        if data.is_empty() || data.len() > MAX_SIGN_INPUT {
            return Err(TOKEN_BAD_REQUEST);
        }
        let signature = open
            .token
            .session
            .sign(&Mechanism::Ecdsa, key, data)
            .map_err(|e| failed("signing with the token key", &e))?;
        log(Level::Debug, "token-signed", &[("uid", Value::Uid(uid))]);
        Ok(signature)
    }
}

impl Connection<'_> {
    fn auth(&mut self, uid: u32, payload: &[u8]) -> Reply {
        self.signed_challenge(uid, payload)
    }

    fn auth_release(&mut self, uid: u32, payload: &[u8]) -> Reply {
        let signature = self.signed_challenge(uid, payload)?;
        let secret = if self.peer == ROOT_UID {
            self.release_secret(uid)
        } else {
            None
        };
        let secret = secret.as_ref().map_or(&b""[..], |s| s.as_bytes());
        let len = u16::try_from(secret.len()).map_err(|_| TOKEN_FAILED)?;
        let mut reply = Vec::with_capacity(signature.len() + 2 + secret.len());
        reply.extend_from_slice(&signature);
        reply.extend_from_slice(&len.to_be_bytes());
        reply.extend_from_slice(secret);
        Ok(reply)
    }

    fn release_secret(&self, uid: u32) -> Option<Zeroizing<String>> {
        let secrets = self.protectors.login_secrets();
        let released = secrets.shadow_entry(uid).and_then(|entry| match entry {
            Some(entry) => secrets.release(uid, &entry),
            None => Ok(None),
        });
        match released {
            Ok(secret) => secret,
            Err(error) => {
                log(
                    Level::Warn,
                    "token-release-withheld",
                    &[
                        ("uid", Value::Uid(uid)),
                        ("reason", Value::Label(release_reason(&error))),
                    ],
                );
                None
            }
        }
    }

    fn seal_secret(&mut self, uid: u32, payload: &[u8]) -> Reply {
        let result = self.try_seal(uid, payload);
        let (level, event) = match result {
            Ok(_) => (Level::Info, "token-secret-sealed"),
            Err(_) => (Level::Warn, "token-seal-refused"),
        };
        log(level, event, &[("uid", Value::Uid(uid))]);
        result
    }

    fn try_seal(&mut self, uid: u32, payload: &[u8]) -> Reply {
        if self.peer != ROOT_UID {
            return Err(TOKEN_REFUSED);
        }
        let (named, password) =
            openhello_auth_proto::split_seal_payload(payload).ok_or(TOKEN_REFUSED)?;
        if named != uid {
            return Err(TOKEN_REFUSED);
        }
        let password = std::str::from_utf8(password).map_err(|_| TOKEN_REFUSED)?;
        let secrets = self.protectors.login_secrets();
        let entry = secrets
            .shadow_entry(uid)
            .ok()
            .flatten()
            .ok_or(TOKEN_REFUSED)?;
        secrets.seal(uid, password, &entry).map_err(|e| match e {
            KeydError::InvalidPassword | KeydError::NoShadowEntry => TOKEN_REFUSED,
            _ => TOKEN_FAILED,
        })?;
        Ok(Vec::new())
    }

    fn signed_challenge(&mut self, uid: u32, payload: &[u8]) -> Reply {
        let Some((service, challenge)) = openhello_auth_proto::parse_request(payload) else {
            return Err(self.violation("malformed auth request"));
        };
        if self.open.is_some() || self.auths >= MAX_LOGINS {
            return Err(self.violation("auth refused on this connection"));
        }
        self.auths += 1;
        let Some(secret) = self.protectors.take_grant(uid) else {
            log(
                Level::Warn,
                "token-auth-refused",
                &[
                    ("uid", Value::Uid(uid)),
                    ("reason", Value::Label("no grant")),
                ],
            );
            return Err(TOKEN_REFUSED);
        };
        let message = openhello_auth_proto::auth_message(uid, service, &challenge);
        let signature = self.sign_with_grant(uid, &secret, &message)?;
        log(
            Level::Debug,
            "token-auth-signed",
            &[("uid", Value::Uid(uid))],
        );
        Ok(signature)
    }

    fn sign_with_grant(&self, uid: u32, secret: &crate::Secret, digest: &[u8; 32]) -> Reply {
        let guard = lock();
        guard.reset_module();
        let token = self
            .protectors
            .config
            .open_token(&guard, &crate::provision::token_label(uid))
            .map_err(|e| match e {
                KeydError::NotProvisioned => TOKEN_NO_TOKEN,
                _ => TOKEN_FAILED,
            })?;
        token.login(secret).map_err(|e| match e {
            KeydError::AuthenticationFailed => TOKEN_PIN_INCORRECT,
            _ => TOKEN_FAILED,
        })?;
        let template = [
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::Sign(true),
        ];
        let keys = token
            .session
            .find_objects(&template)
            .map_err(|e| failed("locating the signing key", &e))?;
        let [key] = keys.as_slice() else {
            return Err(TOKEN_FAILED);
        };
        let signature = token
            .session
            .sign(&Mechanism::Ecdsa, *key, digest)
            .map_err(|e| failed("signing the PAM challenge", &e))?;
        if signature.len() != openhello_auth_proto::SIGNATURE_LEN {
            return Err(TOKEN_FAILED);
        }
        Ok(signature)
    }
}

impl Open {
    fn expose(&mut self, handle: ObjectHandle, class: ObjectClass) -> Option<u64> {
        if let Some((known, _)) = self
            .exposed
            .iter()
            .find(|(_, (real, _))| real.handle() == handle.handle())
        {
            return Some(*known);
        }
        if self.exposed.len() >= MAX_EXPOSED {
            return None;
        }
        let exposed = self.next_handle;
        self.next_handle += 1;
        self.exposed.insert(exposed, (handle, class));
        Some(exposed)
    }
}

fn sign_target(open: &Open, request: &[u8]) -> Result<ObjectHandle, u8> {
    let request: [u8; 16] = request.try_into().map_err(|_| TOKEN_BAD_REQUEST)?;
    let mechanism = u64::from_be_bytes(request[..8].try_into().map_err(|_| TOKEN_BAD_REQUEST)?);
    let handle = u64::from_be_bytes(request[8..].try_into().map_err(|_| TOKEN_BAD_REQUEST)?);
    if mechanism != CKM_ECDSA {
        return Err(TOKEN_BAD_MECHANISM);
    }
    match open.exposed.get(&handle) {
        Some((object, class)) if *class == ObjectClass::PRIVATE_KEY => Ok(*object),
        _ => Err(TOKEN_BAD_HANDLE),
    }
}

fn release_reason(error: &KeydError) -> &'static str {
    match error {
        KeydError::NoShadowEntry => "no shadow entry",
        KeydError::LoginSecretDamaged => "stored secret damaged",
        _ => "store failure",
    }
}

fn failed(context: &str, error: &cryptoki::error::Error) -> u8 {
    let _ = p11_failure(context, error);
    TOKEN_FAILED
}

fn class_of(open: &Open, handle: ObjectHandle) -> Option<ObjectClass> {
    open.token
        .session
        .get_attributes(handle, &[AttributeType::Class])
        .ok()?
        .into_iter()
        .find_map(|a| match a {
            Attribute::Class(class) => Some(class),
            _ => None,
        })
}

fn read_attribute(
    open: &Open,
    object: ObjectHandle,
    class: ObjectClass,
    raw: u64,
) -> (u8, Vec<u8>) {
    let Ok(kind) = AttributeType::try_from(raw) else {
        return (ATTRIBUTE_INVALID, Vec::new());
    };
    if class == ObjectClass::PRIVATE_KEY && !PRIVATE_KEY_READABLE.contains(&kind) {
        return (ATTRIBUTE_SENSITIVE, Vec::new());
    }
    match open.token.session.get_attributes(object, &[kind]) {
        Ok(found) => match found.first() {
            Some(attribute) => (ATTRIBUTE_READ, value_bytes(attribute)),
            None => (ATTRIBUTE_INVALID, Vec::new()),
        },
        Err(_) => (ATTRIBUTE_INVALID, Vec::new()),
    }
}

fn value_bytes(attribute: &Attribute) -> Vec<u8> {
    let raw = CK_ATTRIBUTE::from(attribute);
    if raw.pValue.is_null() {
        return Vec::new();
    }
    unsafe { std::slice::from_raw_parts(raw.pValue as *const u8, raw.ulValueLen as usize) }.to_vec()
}

fn parse_template(payload: &[u8]) -> Option<Vec<Attribute>> {
    let (&count, mut rest) = payload.split_first()?;
    if usize::from(count) > MAX_TEMPLATE {
        return None;
    }
    let mut template = Vec::new();
    for _ in 0..count {
        let kind = u64::from_be_bytes(rest.get(..8)?.try_into().ok()?);
        let len = usize::from(u16::from_be_bytes(rest.get(8..10)?.try_into().ok()?));
        let value = rest.get(10..10 + len)?;
        rest = &rest[10 + len..];
        template.push(match kind {
            CKA_CLASS => {
                let class = u64::from_ne_bytes(value.try_into().ok()?);
                Attribute::Class(ObjectClass::try_from(class).ok()?)
            }
            CKA_TOKEN => Attribute::Token(*value.first().filter(|_| value.len() == 1)? != 0),
            CKA_SIGN => Attribute::Sign(*value.first().filter(|_| value.len() == 1)? != 0),
            CKA_CERTIFICATE_TYPE => {
                let kind = u64::from_ne_bytes(value.try_into().ok()?);
                Attribute::CertificateType(CertificateType::try_from(kind).ok()?)
            }
            CKA_ID => Attribute::Id(value.to_vec()),
            CKA_LABEL => Attribute::Label(value.to_vec()),
            CKA_VALUE => Attribute::Value(value.to_vec()),
            CKA_ISSUER => Attribute::Issuer(value.to_vec()),
            CKA_SERIAL_NUMBER => Attribute::SerialNumber(value.to_vec()),
            CKA_SUBJECT => Attribute::Subject(value.to_vec()),
            _ => return None,
        });
    }
    let only_certificates = template.iter().any(|a| matches!(a, Attribute::Value(_)))
        && !template
            .iter()
            .any(|a| matches!(a, Attribute::Class(c) if *c == ObjectClass::CERTIFICATE));
    (rest.is_empty() && !only_certificates).then_some(template)
}

fn padded(text: &str, width: usize) -> Vec<u8> {
    let mut bytes = text.as_bytes().to_vec();
    bytes.truncate(width);
    bytes.resize(width, b' ');
    bytes
}

fn write_reply(stream: &mut UnixStream, status: u8, payload: &[u8]) -> std::io::Result<()> {
    let (status, payload) = match u16::try_from(payload.len()) {
        Ok(_) => (status, payload),
        Err(_) => (TOKEN_FAILED, &[][..]),
    };
    let mut frame = Zeroizing::new(Vec::with_capacity(3 + payload.len()));
    frame.push(status);
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(payload);
    stream.write_all(&frame)
}

fn read_frame(stream: &mut UnixStream) -> Option<(u8, Zeroizing<Vec<u8>>)> {
    let mut header = [0u8; 3];
    stream.read_exact(&mut header).ok()?;
    let len = usize::from(u16::from_be_bytes([header[1], header[2]]));
    if len > MAX_TOKEN_REQUEST {
        log(
            Level::Warn,
            "token-refused",
            &[("payload_bytes", Value::Count(len as u64))],
        );
        return None;
    }
    let mut payload = Zeroizing::new(vec![0u8; len]);
    stream.read_exact(&mut payload).ok()?;
    Some((header[0], payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(kind: u64, value: &[u8]) -> Vec<u8> {
        let mut bytes = kind.to_be_bytes().to_vec();
        bytes.extend_from_slice(&u16::try_from(value.len()).unwrap().to_be_bytes());
        bytes.extend_from_slice(value);
        bytes
    }

    fn template(entries: &[Vec<u8>]) -> Vec<u8> {
        let mut bytes = vec![u8::try_from(entries.len()).unwrap()];
        bytes.extend(entries.concat());
        bytes
    }

    // @covers:AC-027-openssl-templates
    #[test]
    fn parse_template_accepts_the_openssl_build_templates() {
        let certificate = parse_template(&template(&[
            entry(CKA_CLASS, &1u64.to_ne_bytes()),
            entry(CKA_CERTIFICATE_TYPE, &0u64.to_ne_bytes()),
        ]))
        .unwrap();
        assert!(matches!(
            certificate.as_slice(),
            [Attribute::Class(_), Attribute::CertificateType(_)]
        ));
        let key = parse_template(&template(&[
            entry(CKA_CLASS, &3u64.to_ne_bytes()),
            entry(CKA_SIGN, &[1]),
            entry(CKA_ID, &[9; 16]),
        ]))
        .unwrap();
        assert!(matches!(
            key.as_slice(),
            [Attribute::Class(_), Attribute::Sign(true), Attribute::Id(_)]
        ));
    }

    // @covers:AC-027-openssl-templates
    #[test]
    fn parse_template_still_refuses_unknown_or_malformed_attributes() {
        const CKA_MODULUS: u64 = 0x120;
        assert!(parse_template(&template(&[entry(CKA_MODULUS, &[1])])).is_none());
        assert!(parse_template(&template(&[entry(CKA_SIGN, &[1, 1])])).is_none());
        assert!(parse_template(&template(&[entry(CKA_CERTIFICATE_TYPE, &[0])])).is_none());
        assert!(parse_template(&template(&[entry(
            CKA_CERTIFICATE_TYPE,
            &99u64.to_ne_bytes()
        )]))
        .is_none());
    }
}
