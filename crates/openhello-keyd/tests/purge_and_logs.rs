mod support;

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use openhello_keyd::dbus_service::{
    Action, AuthFuture, Authorizer, Caller, Service, BUS_NAME, OBJECT_PATH,
};
use openhello_keyd::logging::{self, Level as KeydLevel};
use openhello_keyd::{
    KeydError, Protectors, TicketSocket, TicketSocketConfig, UnlockSocket, UnlockSocketConfig,
    OP_TICKET, OP_UNLOCK_PIN, OP_UNLOCK_RECOVERY, OP_UNLOCK_TAKE_GRANT, RECOVERY_SEPARATOR,
    STATUS_ACCEPTED,
};
use openhello_ticket::{Issuer, KEY_LEN};
use openhellod::backends::*;
use openhellod::core::{Biometrics, DEFAULT_TARGET_FAR};
use openhellod::keyd_client::{KeyPurge, KeydBus, KeydClient};
use openhellod::logging::{Level, LogSink, Logger};
use openhellod::ticket_client::TicketClient;
use support::{rig, Rig};

const PIN: &str = "Sntl-PIN-9d4F-7731";
const WRONG_PIN: &str = "Wrng-PIN-2b8E-4416";
const WRONG_CODE: &str = "0123456789abcdef0123456789abcdef";
const PIXELS: [u8; 8] = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
const TEMPLATE: &[u8] = b"TOP-SECRET-TEMPLATE-\xde\xad\xbe\xef\x01\x02\x03";

struct PrivateBus {
    daemon: Child,
    address: String,
}

impl PrivateBus {
    fn start() -> Self {
        let mut daemon = Command::new("dbus-daemon")
            .args(["--session", "--nofork", "--print-address=1"])
            .stdout(Stdio::piped())
            .spawn()
            .expect("dbus-daemon must be installed to run keyd tests");
        let mut address = String::new();
        BufReader::new(daemon.stdout.take().unwrap())
            .read_line(&mut address)
            .unwrap();
        Self {
            daemon,
            address: address.trim().to_string(),
        }
    }
}

impl Drop for PrivateBus {
    fn drop(&mut self) {
        let _ = self.daemon.kill();
        let _ = self.daemon.wait();
    }
}

struct AllowAll;

impl Authorizer for AllowAll {
    fn authorize<'a>(&'a self, _: Action, _: &'a Caller, _: u32) -> AuthFuture<'a> {
        Box::pin(async { Ok(()) })
    }
}

fn serve(bus: &PrivateBus, protectors: Arc<Protectors>) {
    let address = bus.address.clone();
    let service = Service::new(protectors, Arc::new(AllowAll));
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        async_io::block_on(async move {
            let _connection = zbus::connection::Builder::address(address.as_str())
                .unwrap()
                .name(BUS_NAME)
                .unwrap()
                .serve_at(OBJECT_PATH, service)
                .unwrap()
                .build()
                .await
                .unwrap();
            ready_tx.send(()).unwrap();
            std::future::pending::<()>().await;
        })
    });
    ready_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("keyd service did not start");
}

fn proxy_for(bus: &PrivateBus) -> (zbus::blocking::Connection, &'static str) {
    let conn = zbus::blocking::connection::Builder::address(bus.address.as_str())
        .unwrap()
        .build()
        .unwrap();
    (conn, "io.openhello.Keyd1")
}

fn provision(bus: &PrivateBus, uid: u32) -> zbus::Result<String> {
    let (conn, interface) = proxy_for(bus);
    zbus::blocking::Proxy::new(&conn, BUS_NAME, OBJECT_PATH, interface)
        .unwrap()
        .call("Provision", &(uid,))
}

fn set_pin(bus: &PrivateBus, uid: u32, pin: &str) -> zbus::Result<bool> {
    let (conn, interface) = proxy_for(bus);
    zbus::blocking::Proxy::new(&conn, BUS_NAME, OBJECT_PATH, interface)
        .unwrap()
        .call("SetPin", &(uid, pin))
}

type Templates = Arc<Mutex<BTreeMap<u32, Vec<u8>>>>;

struct Sensor;

impl SensorBackend for Sensor {
    fn capture(&mut self) -> Result<CapturedFrame, DaemonError> {
        Ok(CapturedFrame {
            width: 4,
            height: 2,
            pixels: PIXELS.to_vec(),
        })
    }
}

#[derive(Default)]
struct Engine {
    candidates: Vec<(u32, Vec<u8>)>,
}

impl EngineBackend for Engine {
    fn enroll_begin(&mut self, _: u64) -> Result<u64, DaemonError> {
        Ok(1)
    }

    fn enroll_submit(
        &mut self,
        _: u64,
        _: u64,
        _: &CapturedFrame,
    ) -> Result<EnrollProgress, DaemonError> {
        Ok(EnrollProgress {
            verdict: Verdict::Accepted,
            state: EnrollState::Complete,
            filled: 6,
            required: 6,
        })
    }

    fn enroll_commit(&mut self, _: u64) -> Result<Vec<u8>, DaemonError> {
        Ok(TEMPLATE.to_vec())
    }

    fn enroll_discard(&mut self, _: u64) -> Result<(), DaemonError> {
        Ok(())
    }

    fn auth_begin(
        &mut self,
        candidates: &[(u32, Vec<u8>)],
        _: f64,
        _: u32,
    ) -> Result<u64, DaemonError> {
        self.candidates = candidates.to_vec();
        Ok(1)
    }

    fn auth_submit(&mut self, _: u64, _: &CapturedFrame) -> Result<AuthProgress, DaemonError> {
        let matched = self
            .candidates
            .iter()
            .find(|(_, template)| template.as_slice() == TEMPLATE)
            .map(|(uid, _)| *uid);
        Ok(AuthProgress {
            verdict: matched.map_or(AuthVerdict::Rejected, AuthVerdict::Accepted),
            scored_frames: 1,
        })
    }

    fn auth_end(&mut self, _: u64) -> Result<(), DaemonError> {
        Ok(())
    }
}

struct Storage(Templates);

impl StorageBackend for Storage {
    fn put(&mut self, uid: u32, template: &[u8]) -> Result<(), DaemonError> {
        self.0.lock().unwrap().insert(uid, template.to_vec());
        Ok(())
    }

    fn get(&mut self, uid: u32) -> Result<Vec<u8>, DaemonError> {
        self.0
            .lock()
            .unwrap()
            .get(&uid)
            .cloned()
            .ok_or(DaemonError::NotFound)
    }

    fn list_uids(&mut self) -> Result<Vec<u32>, DaemonError> {
        Ok(self.0.lock().unwrap().keys().copied().collect())
    }

    fn purge(&mut self, uid: u32) -> Result<(), DaemonError> {
        self.0.lock().unwrap().remove(&uid);
        Ok(())
    }
}

#[derive(Default)]
struct Capture(Mutex<Vec<String>>);

impl LogSink for Capture {
    fn write_line(&self, line: &str) {
        self.0.lock().unwrap().push(line.to_string());
    }
}

struct KeydCapture(Arc<Capture>);

impl logging::LogSink for KeydCapture {
    fn write_line(&self, line: &str) {
        self.0.write_line(line);
    }
}

fn biometrics(
    templates: &Templates,
    logger: Logger,
    ticket_socket: Option<&Path>,
    keyd_bus: &PrivateBus,
) -> Biometrics {
    Biometrics::new(
        Box::new(Sensor),
        Box::new(Engine::default()),
        Box::new(Storage(templates.clone())),
        DEFAULT_TARGET_FAR,
    )
    .with_logger(logger)
    .with_ticket_client(ticket_socket.map(TicketClient::new))
    .with_keyd_client(Some(KeydClient::new(KeydBus::Address(
        keyd_bus.address.clone(),
    ))))
}

fn enroll(core: &mut Biometrics, uid: u32) {
    let handle = core.enroll_begin(uid).unwrap();
    core.enroll_capture(&handle).unwrap();
    core.enroll_commit(&handle).unwrap();
}

fn my_uid() -> u32 {
    let uid = unsafe { libc::getuid() };
    assert!(
        uid <= 0xFFFF,
        "uid {uid} is outside the range keyd supports (0..=65535); run the tests as a regular user"
    );
    uid
}

fn protectors(rig: &Rig) -> Arc<Protectors> {
    Arc::new(Protectors::new(rig.config.clone()).unwrap())
}

fn blob_count(rig: &Rig, uid: u32) -> usize {
    std::fs::read_dir(
        rig.config
            .store_dir
            .join("protectors")
            .join(uid.to_string()),
    )
    .map(|d| d.count())
    .unwrap_or(0)
}

fn unlock_request(path: &Path, op: u8, payload: &[u8]) -> Option<Vec<u8>> {
    let mut stream = UnixStream::connect(path).unwrap();
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

#[derive(Default)]
struct Recorded {
    to_keyd: Vec<u8>,
    from_keyd: Vec<u8>,
}

fn relay(listen: PathBuf, upstream: PathBuf) -> Arc<Mutex<Recorded>> {
    let recorded = Arc::new(Mutex::new(Recorded::default()));
    let listener = UnixListener::bind(&listen).unwrap();
    let seen = recorded.clone();
    std::thread::spawn(move || {
        for client in listener.incoming().flatten() {
            let Ok(server) = UnixStream::connect(&upstream) else {
                continue;
            };
            for (mut from, mut to, forward) in [
                (
                    client.try_clone().unwrap(),
                    server.try_clone().unwrap(),
                    true,
                ),
                (server, client, false),
            ] {
                let seen = seen.clone();
                std::thread::spawn(move || {
                    let mut buf = [0u8; 512];
                    while let Ok(n) = from.read(&mut buf) {
                        if n == 0 || to.write_all(&buf[..n]).is_err() {
                            break;
                        }
                        let mut log = seen.lock().unwrap();
                        let side = if forward {
                            &mut log.to_keyd
                        } else {
                            &mut log.from_keyd
                        };
                        side.extend_from_slice(&buf[..n]);
                    }
                });
            }
        }
    });
    recorded
}

fn tickets_seen(recorded: &Recorded) -> Vec<Vec<u8>> {
    let mut found = Vec::new();
    let mut rest = recorded.to_keyd.as_slice();
    while rest.len() >= 3 {
        let len = usize::from(u16::from_be_bytes([rest[1], rest[2]]));
        if rest.len() < 3 + len {
            break;
        }
        if rest[0] == OP_TICKET {
            found.push(rest[3..3 + len].to_vec());
        }
        rest = &rest[3 + len..];
    }
    found
}

fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n =
            chunk.iter().fold(0u32, |acc, b| (acc << 8) | u32::from(*b)) << (8 * (3 - chunk.len()));
        for i in 0..=chunk.len() {
            out.push(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize] as char);
        }
        out.push_str(&"=".repeat(3 - chunk.len()));
    }
    out
}

fn renderings(bytes: &[u8]) -> Vec<String> {
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    let b64 = base64(bytes);
    vec![
        hex.to_uppercase(),
        b64.trim_end_matches('=').to_string(),
        bytes
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(", "),
        format!("{bytes:?}"),
        hex,
        b64,
        String::from_utf8_lossy(bytes).into_owned(),
    ]
}

fn assert_no_leak(lines: &[String], name: &str, bytes: &[u8]) {
    for rendering in renderings(bytes) {
        assert!(
            !lines.iter().any(|l| l.contains(&rendering)),
            "a log line leaked the {name} as `{rendering}`:\n{lines:#?}"
        );
    }
}

// @spec:AC-033
#[test]
fn the_openhellod_purge_destroys_the_template_the_key_and_every_protector() {
    let rig = rig();
    rig.clear_lockout();
    let uid = 3201;
    let protectors = protectors(&rig);
    let bus = PrivateBus::start();
    serve(&bus, protectors.clone());
    let dir = tempfile::tempdir().unwrap();
    let ticket_path = dir.path().join("ticket.sock");
    let _ticket = TicketSocket::bind(
        protectors.clone(),
        TicketSocketConfig {
            path: ticket_path.clone(),
            allowed_uid: my_uid(),
            expected_exe: None,
        },
    )
    .unwrap();
    let templates = Templates::default();
    let mut core = biometrics(
        &templates,
        Logger::new(Level::Info, Arc::new(Capture::default())),
        None,
        &bus,
    );

    let code: String = provision(&bus, uid).unwrap();
    assert!(set_pin(&bus, uid, PIN).unwrap());
    enroll(&mut core, uid);
    assert_eq!(blob_count(&rig, uid), 3);
    assert!(protectors.unlock_with_pin(uid, PIN).is_ok());
    assert!(templates.lock().unwrap().contains_key(&uid));

    core.purge(uid).unwrap();

    assert_eq!(core.last_key_purge(), Some(KeyPurge::Destroyed));
    assert!(templates.lock().unwrap().is_empty());
    assert!(matches!(
        protectors.keyd().key(uid),
        Err(KeydError::NotProvisioned)
    ));
    assert_eq!(blob_count(&rig, uid), 0);
    assert!(!rig
        .config
        .store_dir
        .join("protectors")
        .join(uid.to_string())
        .exists());
    assert!(matches!(
        protectors.unlock_with_pin(uid, PIN),
        Err(KeydError::NotProvisioned)
    ));
    assert!(matches!(
        protectors.unlock_with_recovery(uid, &code),
        Err(KeydError::NotProvisioned)
    ));
    let ticket = Issuer::new(protectors.ticket_key()).issue(uid).unwrap();
    assert!(protectors
        .unlock_with_ticket(uid, &ticket.encode())
        .is_err());
}

// @spec:AC-033
#[test]
fn an_unreachable_keyd_fails_the_purge_without_hiding_the_template_result() {
    let rig = rig();
    let uid = 3202;
    let protectors = protectors(&rig);
    let bus = PrivateBus::start();
    serve(&bus, protectors.clone());
    provision(&bus, uid).unwrap();
    let dead = PrivateBus::start();
    let templates = Templates::default();
    templates.lock().unwrap().insert(uid, TEMPLATE.to_vec());
    let mut core = biometrics(
        &templates,
        Logger::new(Level::Info, Arc::new(Capture::default())),
        None,
        &dead,
    );

    assert!(core.purge(uid).is_err());
    assert_eq!(core.last_key_purge(), Some(KeyPurge::Unavailable));
    assert!(templates.lock().unwrap().is_empty());
    assert!(protectors.keyd().key(uid).is_ok());
    assert!(protectors.purge(uid).is_ok());
}

// @spec:AC-035
// @principle:P-010
#[test]
fn a_full_cycle_at_trace_verbosity_never_logs_a_pin_a_secret_a_ticket_or_a_recovery_code() {
    let rig = rig();
    rig.clear_lockout();
    let uid = my_uid();
    let capture = Arc::new(Capture::default());
    logging::configure(KeydLevel::Trace, Arc::new(KeydCapture(capture.clone())));

    let protectors = protectors(&rig);
    let bus = PrivateBus::start();
    serve(&bus, protectors.clone());
    let dir = tempfile::tempdir().unwrap();
    let keyd_ticket = dir.path().join("keyd-ticket.sock");
    let relay_path = dir.path().join("relay.sock");
    let unlock_path = dir.path().join("unlock.sock");
    let _ticket = TicketSocket::bind(
        protectors.clone(),
        TicketSocketConfig {
            path: keyd_ticket.clone(),
            allowed_uid: uid,
            expected_exe: None,
        },
    )
    .unwrap();
    let _unlock = UnlockSocket::bind(
        protectors.clone(),
        UnlockSocketConfig {
            path: unlock_path.clone(),
        },
    )
    .unwrap();
    let recorded = relay(relay_path.clone(), keyd_ticket);
    let templates = Templates::default();
    let mut core = biometrics(
        &templates,
        Logger::new(Level::Trace, capture.clone()),
        Some(&relay_path),
        &bus,
    );

    let code: String = provision(&bus, uid).unwrap();
    assert!(set_pin(&bus, uid, PIN).unwrap());
    assert!(set_pin(&bus, uid, "123").is_err());
    enroll(&mut core, uid);

    assert!(core.verify(uid).unwrap());
    let key = unlock_request(&unlock_path, OP_UNLOCK_TAKE_GRANT, &[]).expect("face grant");
    assert_eq!(key.len(), 40);

    assert_eq!(
        unlock_request(&unlock_path, OP_UNLOCK_PIN, PIN.as_bytes()).unwrap(),
        key
    );
    assert!(unlock_request(&unlock_path, OP_UNLOCK_PIN, WRONG_PIN.as_bytes()).is_none());
    assert!(unlock_request(&unlock_path, OP_UNLOCK_RECOVERY, WRONG_CODE.as_bytes()).is_none());
    let reply = unlock_request(&unlock_path, OP_UNLOCK_RECOVERY, code.as_bytes()).unwrap();
    let (recovered, fresh) =
        reply.split_at(reply.iter().position(|b| *b == RECOVERY_SEPARATOR).unwrap());
    assert_eq!(recovered, key.as_slice());
    let fresh = fresh[1..].to_vec();

    core.purge(uid).unwrap();
    assert_eq!(core.last_key_purge(), Some(KeyPurge::Destroyed));

    let (tickets, ephemeral_key) = {
        let seen = recorded.lock().unwrap();
        (tickets_seen(&seen), seen.from_keyd[1..1 + KEY_LEN].to_vec())
    };
    assert_eq!(tickets.len(), 1, "the relay must have seen the ticket");

    let lines = capture.0.lock().unwrap().clone();
    for event in [
        "openhello-keyd INFO operation-done",
        "openhello-keyd DEBUG ticket-accepted",
        "openhello-keyd DEBUG unlock-accepted",
        "openhello-keyd WARN unlock-refused",
        "openhellod INFO ticket",
        "openhellod INFO purge",
    ] {
        assert!(
            lines.iter().any(|l| l.contains(event)),
            "missing `{event}` in {lines:#?}"
        );
    }
    assert_no_leak(&lines, "PIN", PIN.as_bytes());
    assert_no_leak(&lines, "wrong PIN", WRONG_PIN.as_bytes());
    assert_no_leak(&lines, "wrong recovery code", WRONG_CODE.as_bytes());
    assert_no_leak(&lines, "recovery code", code.as_bytes());
    assert_no_leak(&lines, "fresh recovery code", &fresh);
    assert_no_leak(&lines, "Protector secret K", &key);
    assert_no_leak(&lines, "ticket", &tickets[0]);
    assert_no_leak(&lines, "ticket key", &ephemeral_key);
    assert_no_leak(&lines, "frame bytes", &PIXELS);
    assert_no_leak(&lines, "template", TEMPLATE);
}

#[test]
fn keyd_sources_log_only_through_the_redacting_logger() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    for entry in std::fs::read_dir(src).unwrap().flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name == "logging.rs" || name == "main.rs" {
            continue;
        }
        let text = std::fs::read_to_string(entry.path()).unwrap();
        for forbidden in ["eprintln!", "println!", "dbg!"] {
            assert!(
                !text.contains(forbidden),
                "{name} calls {forbidden} directly"
            );
        }
    }
}
