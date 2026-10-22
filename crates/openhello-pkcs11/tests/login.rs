#[path = "../../openhello-keyd/tests/support/mod.rs"]
mod support;

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::Duration;

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, ObjectClass};
use cryptoki::session::UserType;
use cryptoki::types::AuthPin;
use openhello_keyd::{
    KeyInfo, Protectors, TicketSocket, TicketSocketConfig, TokenSocket, TokenSocketConfig,
    UnlockSocket, UnlockSocketConfig, OP_TICKET, OP_TICKET_KEY, OP_TOKEN_LOGIN, OP_TOKEN_OPEN,
    OP_UNLOCK_RECOVERY, STATUS_ACCEPTED,
};
use openhello_pkcs11::{PLACEHOLDER_PIN, TEST_BUS_ADDRESS_ENV, TOKEN_SOCKET_ENV};
use openhello_ticket::{Issuer, TicketKey, KEY_LEN};
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature, VerifyingKey};
use support::{looks_like_secret, relay, rig, Rig, TokenClient};

const DIGEST: [u8; 32] = [0x3c; 32];
const PIN: &str = "482916";
const PROBE_PIN_ENV: &str = "OPENHELLO_P11_PROBE_PIN";
const PROBE_MODULE_ENV: &str = "OPENHELLO_P11_MODULE";
const PROBE_NAME: &str = "wrapper_child_probe";
const BUS_NAME: &str = "io.openhello.Biometrics1";
const OBJECT_PATH: &str = "/io/openhello/Biometrics1";
const OTHER_UID: u32 = 2999;
const LEGACY_TAKE_GRANT: u8 = 1;
const LEGACY_UNLOCK_PIN: u8 = 2;

#[derive(Clone, Copy, PartialEq)]
enum Verify {
    Matches,
    NoMatch,
    MatchesButNoTicket,
}

struct VerifyState {
    ticket_socket: PathBuf,
    mode: Verify,
    calls: u32,
}

static VERIFY: Mutex<Option<VerifyState>> = Mutex::new(None);

struct FakeBiometrics;

#[zbus::interface(name = "io.openhello.Biometrics1")]
impl FakeBiometrics {
    fn verify(&self, uid: u32) -> bool {
        let mut guard = VERIFY.lock().unwrap_or_else(PoisonError::into_inner);
        let state = guard.as_mut().expect("verify state set by the test");
        state.calls += 1;
        match state.mode {
            Verify::NoMatch => false,
            Verify::MatchesButNoTicket => true,
            Verify::Matches => deliver_ticket(&state.ticket_socket, uid),
        }
    }
}

fn deliver_ticket(socket: &Path, uid: u32) -> bool {
    let mut stream = UnixStream::connect(socket).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let reply = frame_exchange(&mut stream, OP_TICKET_KEY, &[], 1 + KEY_LEN);
    assert_eq!(reply[0], STATUS_ACCEPTED);
    let key = TicketKey::from_bytes(reply[1..].try_into().unwrap());
    let ticket = Issuer::new(key).issue(uid).unwrap().encode();
    frame_exchange(&mut stream, OP_TICKET, &ticket, 1)[0] == STATUS_ACCEPTED
}

fn frame_exchange(stream: &mut UnixStream, op: u8, payload: &[u8], reply_len: usize) -> Vec<u8> {
    let mut frame = vec![op];
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(payload);
    stream.write_all(&frame).unwrap();
    let mut reply = vec![0u8; reply_len];
    stream.read_exact(&mut reply).unwrap();
    reply
}

fn serve_fake_biometrics(address: &str) {
    static STARTED: OnceLock<()> = OnceLock::new();
    STARTED.get_or_init(|| {
        let address = address.to_string();
        let (ready, wait) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            async_io::block_on(async move {
                let _connection = zbus::connection::Builder::address(address.as_str())
                    .unwrap()
                    .name(BUS_NAME)
                    .unwrap()
                    .serve_at(OBJECT_PATH, FakeBiometrics)
                    .unwrap()
                    .build()
                    .await
                    .unwrap();
                ready.send(()).unwrap();
                std::future::pending::<()>().await;
            })
        });
        wait.recv_timeout(Duration::from_secs(10))
            .expect("fake io.openhello.Biometrics1 did not start on the rig bus");
    });
}

fn uid() -> u32 {
    let uid = unsafe { libc::getuid() };
    assert!(
        uid <= 0xFFFF,
        "uid {uid} is outside the range keyd supports (0..=65535); run the tests as a regular user"
    );
    uid
}

struct Provisioned {
    key: KeyInfo,
    recovery: String,
}

fn provisioned(rig: &Rig) -> &'static Provisioned {
    static DONE: OnceLock<Provisioned> = OnceLock::new();
    DONE.get_or_init(|| {
        let protectors = Protectors::new(rig.config.clone()).unwrap();
        let recovery = protectors.provision_protectors(uid()).unwrap();
        protectors.provision_protectors(OTHER_UID).unwrap();
        protectors.set_pin(uid(), PIN).unwrap();
        Provisioned {
            key: protectors.keyd().key(uid()).unwrap(),
            recovery: recovery.reveal().to_string(),
        }
    })
}

struct Harness<'a> {
    rig: &'a Rig,
    protectors: Arc<Protectors>,
    key: &'a KeyInfo,
    unlock_path: PathBuf,
    token_path: PathBuf,
    ticket_path: PathBuf,
    _ticket: TicketSocket,
    _unlock: UnlockSocket,
    _token: TokenSocket,
    _dir: tempfile::TempDir,
}

fn harness(rig: &Rig, mode: Verify) -> Harness<'_> {
    rig.clear_lockout();
    let fixture = provisioned(rig);
    let dir = tempfile::tempdir().unwrap();
    let protectors = Arc::new(Protectors::new(rig.config.clone()).unwrap());
    let ticket_path = dir.path().join("ticket.sock");
    let unlock_path = dir.path().join("unlock.sock");
    let token_path = dir.path().join("token.sock");
    let ticket = TicketSocket::bind(
        protectors.clone(),
        TicketSocketConfig {
            path: ticket_path.clone(),
            allowed_uid: uid(),
            expected_exe: None,
        },
    )
    .unwrap();
    let unlock = UnlockSocket::bind(
        protectors.clone(),
        UnlockSocketConfig {
            path: unlock_path.clone(),
        },
    )
    .unwrap();
    let token = TokenSocket::bind(
        protectors.clone(),
        TokenSocketConfig {
            path: token_path.clone(),
        },
    )
    .unwrap();
    serve_fake_biometrics(&rig.config.env[0].1);
    *VERIFY.lock().unwrap_or_else(PoisonError::into_inner) = Some(VerifyState {
        ticket_socket: ticket_path.clone(),
        mode,
        calls: 0,
    });
    Harness {
        rig,
        protectors,
        key: &fixture.key,
        unlock_path,
        token_path,
        ticket_path,
        _ticket: ticket,
        _unlock: unlock,
        _token: token,
        _dir: dir,
    }
}

impl Harness<'_> {
    fn verify_calls(&self) -> u32 {
        VERIFY
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .unwrap()
            .calls
    }

    fn login(&self, pin: &str) -> Probe {
        self.login_on(pin, &self.token_path)
    }

    fn login_on(&self, pin: &str, socket: &Path) -> Probe {
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", PROBE_NAME, "--nocapture", "--test-threads=1"])
            .env(PROBE_PIN_ENV, pin)
            .env(PROBE_MODULE_ENV, wrapper_library())
            .env(TOKEN_SOCKET_ENV, socket)
            .env(TEST_BUS_ADDRESS_ENV, &self.rig.config.env[0].1)
            .env_remove("DBUS_SESSION_BUS_ADDRESS")
            .env_remove("TPM2_PKCS11_STORE")
            .env_remove("TPM2_PKCS11_TCTI")
            .env_remove("TPM2_PKCS11_BACKEND")
            .env_remove("TPM2TOOLS_TCTI")
            .env_remove("LD_LIBRARY_PATH")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let line = stdout
            .lines()
            .find_map(|l| l.strip_prefix("RESULT "))
            .unwrap_or_else(|| {
                panic!(
                    "the probe printed no result: {stdout}{}",
                    String::from_utf8_lossy(&output.stderr)
                )
            });
        let field = |name: &str| {
            line.split_whitespace()
                .find_map(|f| f.strip_prefix(name))
                .unwrap_or_else(|| panic!("`{name}` missing in `{line}`"))
        };
        Probe {
            login: field("login=").to_string(),
            signature: match field("sign=") {
                "none" => None,
                hex => Some(hex_to_bytes(hex)),
            },
            token_module_mapped: field("mapped=") == "1",
            private_value: field("value=").to_string(),
        }
    }

    fn signature_verifies(&self, probe: &Probe) -> bool {
        let Some(signature) = &probe.signature else {
            return false;
        };
        let verifying = VerifyingKey::from_sec1_bytes(&self.key.public_key).unwrap();
        verifying
            .verify_prehash(&DIGEST, &Signature::from_slice(signature).unwrap())
            .is_ok()
    }

    fn unlock_request(&self, op: u8, payload: &[u8]) -> Option<Vec<u8>> {
        let mut stream = UnixStream::connect(&self.unlock_path).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut frame = vec![op];
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        frame.extend_from_slice(payload);
        let _ = stream.write_all(&frame);
        let mut header = [0u8; 3];
        stream.read_exact(&mut header).ok()?;
        let mut body = vec![0u8; usize::from(u16::from_be_bytes([header[1], header[2]]))];
        stream.read_exact(&mut body).ok()?;
        (header[0] == STATUS_ACCEPTED).then_some(body)
    }
}

struct Probe {
    login: String,
    signature: Option<Vec<u8>>,
    token_module_mapped: bool,
    private_value: String,
}

fn wrapper_library() -> PathBuf {
    let wrapper = std::env::current_exe()
        .unwrap()
        .parent()
        .and_then(Path::parent)
        .unwrap()
        .join("libopenhello_pkcs11.so");
    assert!(wrapper.exists(), "{} was not built", wrapper.display());
    wrapper
}

fn hex_to_bytes(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// Runs inside a child process with no store, TCTI or bus in its environment, as the lock screen would.
#[test]
fn wrapper_child_probe() {
    let Ok(pin) = std::env::var(PROBE_PIN_ENV) else {
        return;
    };
    let module = Pkcs11::new(std::env::var(PROBE_MODULE_ENV).unwrap()).unwrap();
    module
        .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
        .unwrap();
    let slot = module.get_slots_with_token().unwrap()[0];
    let session = module.open_ro_session(slot).unwrap();
    let login = match session.login(UserType::User, Some(&AuthPin::new(pin.into()))) {
        Ok(()) => "ok".to_string(),
        Err(cryptoki::error::Error::Pkcs11(rv, _)) => format!("{rv:?}"),
        Err(other) => format!("{other:?}"),
    };
    let key = session
        .find_objects(&[Attribute::Class(ObjectClass::PRIVATE_KEY)])
        .ok()
        .and_then(|found| found.first().copied());
    let signature = key
        .and_then(|key| session.sign(&Mechanism::Ecdsa, key, &DIGEST).ok())
        .map_or("none".to_string(), |s| hex(&s));
    let private_value = key.map_or("nokey".to_string(), |key| {
        match session.get_attribute_info(key, &[AttributeType::Value]) {
            Ok(info) => format!("{:?}", info[0]),
            Err(error) => format!("{error:?}"),
        }
    });
    let mapped = std::fs::read_to_string("/proc/self/maps")
        .map(|maps| maps.contains("tpm2_pkcs11"))
        .unwrap_or(true);
    println!(
        "\nRESULT login={login} sign={signature} mapped={} value={private_value}",
        u8::from(mapped)
    );
}

fn placeholder() -> String {
    String::from_utf8(PLACEHOLDER_PIN.to_vec()).unwrap()
}

// @spec:AC-019
#[test]
fn a_ticket_from_a_verify_opens_the_session_through_the_placeholder_and_the_token_signs() {
    let rig = rig();
    let harness = harness(&rig, Verify::Matches);

    let probe = harness.login(&placeholder());
    assert_eq!(probe.login, "ok");
    assert!(harness.signature_verifies(&probe));
    assert!(
        !probe.token_module_mapped,
        "the unprivileged process never loads tpm2-pkcs11"
    );
    assert_eq!(harness.verify_calls(), 1);

    let again = harness.login(&placeholder());
    assert_eq!(again.login, "ok", "each Verify issues its own ticket");
    assert_eq!(harness.verify_calls(), 2);
}

// @spec:AC-019
#[test]
fn a_verify_that_does_not_match_leaves_the_session_closed() {
    let rig = rig();
    let harness = harness(&rig, Verify::NoMatch);
    let before = rig.lockout_counter();

    let probe = harness.login(&placeholder());
    assert_eq!(probe.login, "PinIncorrect");
    assert!(probe.signature.is_none());
    assert_eq!(harness.verify_calls(), 1);
    assert_eq!(rig.lockout_counter(), before);
}

// @spec:AC-025
#[test]
fn the_correct_pin_opens_the_session_and_a_wrong_one_counts_in_the_tpm_lockout() {
    let rig = rig();
    let harness = harness(&rig, Verify::NoMatch);
    assert_eq!(rig.lockout_counter(), 0);

    let probe = harness.login(PIN);
    assert_eq!(probe.login, "ok");
    assert!(harness.signature_verifies(&probe));
    assert_eq!(
        harness.verify_calls(),
        0,
        "a typed PIN never starts a face match"
    );
    assert_eq!(rig.lockout_counter(), 0);

    let wrong = harness.login("000000");
    assert_eq!(wrong.login, "PinIncorrect");
    assert!(wrong.signature.is_none());
    assert_eq!(rig.lockout_counter(), 1);
    rig.clear_lockout();
}

// @spec:AC-024
// @principle:P-003
#[test]
fn nothing_but_the_placeholder_with_a_grant_or_the_pin_unlocks() {
    let rig = rig();
    let harness = harness(&rig, Verify::MatchesButNoTicket);
    let before = rig.lockout_counter();

    let no_grant = harness.login(&placeholder());
    assert_eq!(no_grant.login, "PinIncorrect");
    assert!(no_grant.signature.is_none());

    let embedding: Vec<u8> = (0..512u32)
        .flat_map(|i| (i as f32 / 512.0).to_le_bytes())
        .collect();
    let template: String = (1u8..=32).map(char::from).collect();
    for material in [hex(&embedding), template, String::new()] {
        let probe = harness.login(&material);
        assert_ne!(probe.login, "ok");
        assert!(probe.signature.is_none());
    }
    assert_eq!(
        rig.lockout_counter(),
        before,
        "refused material must not reach the TPM"
    );
    assert_eq!(
        harness.verify_calls(),
        1,
        "only the placeholder asks for a face match"
    );

    assert_eq!(harness.login(PIN).login, "ok");
}

// @spec:AC-019
#[test]
fn a_grant_is_used_once_by_its_own_uid_and_the_unlock_socket_never_hands_it_out() {
    let rig = rig();
    let harness = harness(&rig, Verify::MatchesButNoTicket);
    let before = rig.lockout_counter();

    assert!(deliver_ticket(&harness.ticket_path, OTHER_UID));
    assert!(deliver_ticket(&harness.ticket_path, uid()));
    assert!(
        harness.unlock_request(LEGACY_TAKE_GRANT, &[]).is_none(),
        "the unlock socket no longer returns the secret"
    );

    let mine = harness.login(&placeholder());
    assert_eq!(mine.login, "ok", "the grant for my uid opens my token");
    let again = harness.login(&placeholder());
    assert_eq!(again.login, "PinIncorrect", "a grant is single use");
    assert!(
        harness.protectors.take_grant(OTHER_UID).is_some(),
        "the grant of another uid was never usable by mine"
    );
    assert_eq!(rig.lockout_counter(), before);
}

// @spec:AC-024
// @principle:P-003
#[test]
fn the_sockets_refuse_unknown_frames_and_large_payloads_without_the_tpm() {
    let rig = rig();
    let harness = harness(&rig, Verify::Matches);
    let before = rig.lockout_counter();

    assert!(harness.unlock_request(99, &[]).is_none());
    assert!(harness
        .unlock_request(LEGACY_TAKE_GRANT, b"extra")
        .is_none());
    assert!(harness
        .unlock_request(LEGACY_UNLOCK_PIN, &[0xff; 20])
        .is_none());
    assert!(harness
        .unlock_request(LEGACY_UNLOCK_PIN, &vec![b'7'; 4000])
        .is_none());
    assert!(harness.unlock_request(LEGACY_UNLOCK_PIN, b"12").is_none());
    assert!(harness
        .unlock_request(OP_UNLOCK_RECOVERY, b"not a code")
        .is_none());

    let mut token = TokenClient::connect(&harness.token_path, uid());
    token.ok(OP_TOKEN_OPEN, &[]);
    for refused in [vec![0xff; 20], vec![b'7'; 65], b"12".to_vec(), Vec::new()] {
        let (status, _) = token.send(OP_TOKEN_LOGIN, &refused).unwrap();
        assert_ne!(status, 0);
    }
    assert!(token.send(99, &[]).is_some_and(|(status, _)| status != 0));
    assert_eq!(rig.lockout_counter(), before);
}

// @spec:AC-025
#[test]
fn recovery_returns_a_new_code_and_never_the_secret_and_the_old_code_stops_working() {
    let rig = rig();
    let harness = harness(&rig, Verify::Matches);
    let fixture = provisioned(&rig);

    let by_pin = harness.protectors.unlock_with_pin(uid(), PIN).unwrap();
    let fresh = harness
        .unlock_request(OP_UNLOCK_RECOVERY, fixture.recovery.as_bytes())
        .unwrap();
    assert_eq!(fresh.len(), 32);
    assert_ne!(fresh, fixture.recovery.as_bytes());
    assert!(harness
        .unlock_request(OP_UNLOCK_RECOVERY, fixture.recovery.as_bytes())
        .is_none());

    let (by_recovery, newest) = harness
        .protectors
        .unlock_with_recovery(uid(), std::str::from_utf8(&fresh).unwrap())
        .unwrap();
    assert_eq!(
        by_pin.expose_for_tests(),
        by_recovery.expose_for_tests(),
        "both Protectors seal the same secret"
    );
    let _ = harness.unlock_request(OP_UNLOCK_RECOVERY, newest.reveal().as_bytes());
}

// @principle:P-004
#[test]
fn the_secret_never_crosses_a_user_socket_and_the_private_key_value_is_sensitive() {
    let rig = rig();
    let harness = harness(&rig, Verify::Matches);
    let secret = harness.protectors.unlock_with_pin(uid(), PIN).unwrap();
    let k = secret.expose_for_tests().as_bytes().to_vec();
    let relay_path = harness._dir.path().join("relay.sock");
    let recorded = relay(relay_path.clone(), harness.token_path.clone());

    let by_face = harness.login_on(&placeholder(), &relay_path);
    let by_pin = harness.login_on(PIN, &relay_path);
    assert_eq!(by_face.login, "ok");
    assert_eq!(by_pin.login, "ok");
    for probe in [&by_face, &by_pin] {
        assert!(harness.signature_verifies(probe));
        assert_eq!(probe.private_value, "Sensitive");
        assert!(!probe.token_module_mapped);
    }

    let seen = recorded.lock().unwrap();
    assert!(!seen.from_keyd.is_empty());
    assert!(!seen.from_keyd.windows(k.len()).any(|w| w == k.as_slice()));
    assert!(!looks_like_secret(&seen.from_keyd));
    assert!(
        seen.to_keyd.windows(PIN.len()).any(|w| w == PIN.as_bytes()),
        "the typed PIN is what travels towards keyd"
    );
}

// @principle:P-004
#[test]
fn the_wrapper_binary_cannot_name_or_load_the_token_module() {
    let wrapper = std::fs::read(wrapper_library()).unwrap();
    for needle in ["tpm2_pkcs11", "TPM2_PKCS11_STORE", "dlopen"] {
        assert!(
            !wrapper
                .windows(needle.len())
                .any(|w| w == needle.as_bytes()),
            "{needle} appears in the wrapper"
        );
    }
}

#[test]
fn the_wire_constants_match_between_the_wrapper_and_keyd() {
    use openhello_keyd as keyd;
    use openhello_pkcs11::proxy as wrapper;
    assert_eq!(
        [
            wrapper::OP_TOKEN_HELLO,
            wrapper::OP_TOKEN_INFO,
            wrapper::OP_TOKEN_OPEN,
            wrapper::OP_TOKEN_CLOSE,
            wrapper::OP_TOKEN_LOGIN,
            wrapper::OP_TOKEN_LOGOUT,
            wrapper::OP_TOKEN_FIND,
            wrapper::OP_TOKEN_ATTRIBUTES,
            wrapper::OP_TOKEN_SIGN_CHECK,
            wrapper::OP_TOKEN_SIGN,
            wrapper::TOKEN_OK,
            wrapper::TOKEN_PIN_INCORRECT,
            wrapper::TOKEN_NO_TOKEN,
            wrapper::TOKEN_BAD_HANDLE,
            wrapper::TOKEN_BAD_REQUEST,
            wrapper::TOKEN_REFUSED,
            wrapper::TOKEN_FAILED,
            wrapper::TOKEN_BAD_MECHANISM,
            wrapper::ATTRIBUTE_INVALID,
            wrapper::ATTRIBUTE_SENSITIVE,
            wrapper::ATTRIBUTE_READ,
        ],
        [
            keyd::OP_TOKEN_HELLO,
            keyd::OP_TOKEN_INFO,
            keyd::OP_TOKEN_OPEN,
            keyd::OP_TOKEN_CLOSE,
            keyd::OP_TOKEN_LOGIN,
            keyd::OP_TOKEN_LOGOUT,
            keyd::OP_TOKEN_FIND,
            keyd::OP_TOKEN_ATTRIBUTES,
            keyd::OP_TOKEN_SIGN_CHECK,
            keyd::OP_TOKEN_SIGN,
            keyd::TOKEN_OK,
            keyd::TOKEN_PIN_INCORRECT,
            keyd::TOKEN_NO_TOKEN,
            keyd::TOKEN_BAD_HANDLE,
            keyd::TOKEN_BAD_REQUEST,
            keyd::TOKEN_REFUSED,
            keyd::TOKEN_FAILED,
            keyd::TOKEN_BAD_MECHANISM,
            keyd::ATTRIBUTE_INVALID,
            keyd::ATTRIBUTE_SENSITIVE,
            keyd::ATTRIBUTE_READ,
        ]
    );
    assert_eq!(wrapper::TOKEN_INFO_LEN, keyd::TOKEN_INFO_LEN);
    assert_eq!(wrapper::SIGNATURE_LEN, keyd::SIGNATURE_LEN);
    assert_eq!(PLACEHOLDER_PIN, keyd::TOKEN_PLACEHOLDER_PIN);
}
