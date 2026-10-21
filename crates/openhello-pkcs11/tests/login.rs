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
use cryptoki::object::{Attribute, ObjectClass};
use cryptoki::session::UserType;
use cryptoki::types::AuthPin;
use openhello_keyd::{
    KeyInfo, Protectors, TicketSocket, TicketSocketConfig, UnlockSocket, UnlockSocketConfig,
    OP_TICKET, OP_TICKET_KEY, OP_UNLOCK_PIN, OP_UNLOCK_RECOVERY, OP_UNLOCK_TAKE_GRANT,
    RECOVERY_SEPARATOR, STATUS_ACCEPTED,
};
use openhello_pkcs11::{PLACEHOLDER_PIN, REAL_MODULE_ENV, TEST_BUS_ADDRESS_ENV, UNLOCK_SOCKET_ENV};
use openhello_ticket::{Issuer, TicketKey, KEY_LEN};
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature, VerifyingKey};
use support::{rig, Rig};

const DIGEST: [u8; 32] = [0x3c; 32];
const PIN: &str = "482916";
const PROBE_PIN_ENV: &str = "OPENHELLO_P11_PROBE_PIN";
const PROBE_MODULE_ENV: &str = "OPENHELLO_P11_MODULE";
const PROBE_NAME: &str = "wrapper_child_probe";
const BUS_NAME: &str = "io.openhello.Biometrics1";
const OBJECT_PATH: &str = "/io/openhello/Biometrics1";
const OTHER_UID: u32 = 2999;

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
    ticket_path: PathBuf,
    _ticket: TicketSocket,
    _unlock: UnlockSocket,
    _dir: tempfile::TempDir,
}

fn harness(rig: &Rig, mode: Verify) -> Harness<'_> {
    rig.clear_lockout();
    let fixture = provisioned(rig);
    let dir = tempfile::tempdir().unwrap();
    let protectors = Arc::new(Protectors::new(rig.config.clone()).unwrap());
    let ticket_path = dir.path().join("ticket.sock");
    let unlock_path = dir.path().join("unlock.sock");
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
        ticket_path,
        _ticket: ticket,
        _unlock: unlock,
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
        let wrapper = std::env::current_exe()
            .unwrap()
            .parent()
            .and_then(Path::parent)
            .unwrap()
            .join("libopenhello_pkcs11.so");
        assert!(wrapper.exists(), "{} was not built", wrapper.display());
        let config = &self.rig.config;
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", PROBE_NAME, "--nocapture", "--test-threads=1"])
            .env(PROBE_PIN_ENV, pin)
            .env(PROBE_MODULE_ENV, &wrapper)
            .env(
                REAL_MODULE_ENV,
                self.rig.prefix.join("usr/lib64/pkcs11/libtpm2_pkcs11.so"),
            )
            .env(UNLOCK_SOCKET_ENV, &self.unlock_path)
            .env(TEST_BUS_ADDRESS_ENV, &config.env[0].1)
            .env("DBUS_SESSION_BUS_ADDRESS", &config.env[0].1)
            .env("TPM2_PKCS11_STORE", &config.store_dir)
            .env("TPM2_PKCS11_BACKEND", "esysdb")
            .env("TPM2_PKCS11_TCTI", config.tcti.as_ref().unwrap())
            .env("LD_LIBRARY_PATH", self.rig.prefix.join("usr/lib64"))
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
        let (login, signature) = line.split_once(' ').unwrap();
        Probe {
            login: login.strip_prefix("login=").unwrap().to_string(),
            signature: match signature.strip_prefix("sign=").unwrap() {
                "none" => None,
                hex => Some(hex_to_bytes(hex)),
            },
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

// Runs inside a child process: the real tpm2-pkcs11 must not be initialized twice in the keyd test process.
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
    let signature = session
        .find_objects(&[Attribute::Class(ObjectClass::PRIVATE_KEY)])
        .ok()
        .and_then(|found| found.first().copied())
        .and_then(|key| session.sign(&Mechanism::Ecdsa, key, &DIGEST).ok())
        .map_or("none".to_string(), |s| hex(&s));
    println!("\nRESULT login={login} sign={signature}");
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
fn the_unlock_socket_hands_out_a_grant_once_and_only_to_its_own_uid() {
    let rig = rig();
    let harness = harness(&rig, Verify::Matches);
    let before = rig.lockout_counter();

    assert!(harness.unlock_request(OP_UNLOCK_TAKE_GRANT, &[]).is_none());
    assert!(deliver_ticket(&harness.ticket_path, OTHER_UID));
    assert!(
        harness.unlock_request(OP_UNLOCK_TAKE_GRANT, &[]).is_none(),
        "a grant for another uid is not mine"
    );
    assert!(harness.protectors.take_grant(OTHER_UID).is_some());

    assert!(deliver_ticket(&harness.ticket_path, uid()));
    let secret = harness.unlock_request(OP_UNLOCK_TAKE_GRANT, &[]).unwrap();
    assert_eq!(secret.len(), 40);
    assert!(harness.unlock_request(OP_UNLOCK_TAKE_GRANT, &[]).is_none());
    assert_eq!(rig.lockout_counter(), before);
}

// @spec:AC-024
// @principle:P-003
#[test]
fn the_unlock_socket_refuses_unknown_frames_and_large_payloads_without_the_tpm() {
    let rig = rig();
    let harness = harness(&rig, Verify::Matches);
    let before = rig.lockout_counter();

    assert!(harness.unlock_request(99, &[]).is_none());
    assert!(harness
        .unlock_request(OP_UNLOCK_TAKE_GRANT, b"extra")
        .is_none());
    assert!(harness.unlock_request(OP_UNLOCK_PIN, &[0xff; 20]).is_none());
    assert!(harness
        .unlock_request(OP_UNLOCK_PIN, &vec![b'7'; 4000])
        .is_none());
    assert!(harness.unlock_request(OP_UNLOCK_PIN, b"12").is_none());
    assert!(harness
        .unlock_request(OP_UNLOCK_RECOVERY, b"not a code")
        .is_none());
    assert_eq!(rig.lockout_counter(), before);
}

// @spec:AC-025
#[test]
fn the_unlock_socket_returns_the_secret_for_the_pin_and_for_the_recovery_code() {
    let rig = rig();
    let harness = harness(&rig, Verify::Matches);
    let fixture = provisioned(&rig);

    let by_pin = harness
        .unlock_request(OP_UNLOCK_PIN, PIN.as_bytes())
        .unwrap();
    let reply = harness
        .unlock_request(OP_UNLOCK_RECOVERY, fixture.recovery.as_bytes())
        .unwrap();
    let at = reply.iter().position(|b| *b == RECOVERY_SEPARATOR).unwrap();
    let (by_recovery, fresh) = (&reply[..at], &reply[at + 1..]);
    assert_eq!(by_pin, by_recovery, "both Protectors seal the same secret");
    assert_eq!(fresh.len(), 32);
    assert_ne!(fresh, fixture.recovery.as_bytes());
}
