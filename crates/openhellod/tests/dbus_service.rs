use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use openhellod::backends::*;
use openhellod::core::{Biometrics, DEFAULT_TARGET_FAR};
use openhellod::dbus_service::{Action, AuthFuture, Authorizer, Caller, Service, BUS_NAME, OBJECT_PATH};
use openhellod::polkit::{PolkitAuthorizer, PolkitClient, PolkitFuture};

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
            .expect("dbus-daemon must be installed");
        let mut address = String::new();
        BufReader::new(daemon.stdout.take().unwrap()).read_line(&mut address).unwrap();
        Self { daemon, address: address.trim().to_string() }
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

struct Sensor;

impl SensorBackend for Sensor {
    fn capture(&mut self) -> Result<CapturedFrame, DaemonError> {
        Ok(CapturedFrame { width: 1, height: 1, pixels: vec![0] })
    }
}

struct Engine {
    begins: Arc<AtomicUsize>,
    candidates: Vec<(u32, Vec<u8>)>,
}

impl EngineBackend for Engine {
    fn enroll_begin(&mut self, _: u64) -> Result<u64, DaemonError> {
        self.begins.fetch_add(1, Ordering::SeqCst);
        Ok(1)
    }

    fn enroll_submit(&mut self, _: u64, _: u64, _: &CapturedFrame) -> Result<EnrollProgress, DaemonError> {
        Ok(EnrollProgress { verdict: Verdict::Accepted, state: EnrollState::Complete, filled: 6, required: 6 })
    }

    fn enroll_commit(&mut self, _: u64) -> Result<Vec<u8>, DaemonError> {
        Ok(b"secret-template-bytes".to_vec())
    }

    fn enroll_discard(&mut self, _: u64) -> Result<(), DaemonError> {
        Ok(())
    }

    fn auth_begin(&mut self, candidates: &[(u32, Vec<u8>)], _: f64, _: u32) -> Result<u64, DaemonError> {
        self.candidates = candidates.to_vec();
        Ok(1)
    }

    fn auth_submit(&mut self, _: u64, _: &CapturedFrame) -> Result<AuthProgress, DaemonError> {
        let matched = self.candidates.iter().find(|(_, template)| template == b"secret-template-bytes").map(|(uid, _)| *uid);
        Ok(AuthProgress { verdict: matched.map_or(AuthVerdict::Rejected, AuthVerdict::Accepted), scored_frames: 1 })
    }

    fn auth_end(&mut self, _: u64) -> Result<(), DaemonError> {
        Ok(())
    }
}

#[derive(Default)]
struct Storage(std::collections::BTreeMap<u32, Vec<u8>>);

impl StorageBackend for Storage {
    fn put(&mut self, uid: u32, template: &[u8]) -> Result<(), DaemonError> {
        self.0.insert(uid, template.to_vec());
        Ok(())
    }

    fn get(&mut self, uid: u32) -> Result<Vec<u8>, DaemonError> {
        self.0.get(&uid).cloned().ok_or(DaemonError::NotFound)
    }

    fn list_uids(&mut self) -> Result<Vec<u32>, DaemonError> {
        Ok(self.0.keys().copied().collect())
    }

    fn purge(&mut self, uid: u32) -> Result<(), DaemonError> {
        self.0.remove(&uid);
        Ok(())
    }
}

fn serve(bus: &PrivateBus, authorizer: Arc<dyn Authorizer>) -> Arc<AtomicUsize> {
    let begins = Arc::new(AtomicUsize::new(0));
    let engine = Engine { begins: begins.clone(), candidates: Vec::new() };
    let core = Biometrics::new(Box::new(Sensor), Box::new(engine), Box::new(Storage::default()), DEFAULT_TARGET_FAR);
    serve_core(bus, authorizer, core);
    begins
}

fn serve_core(bus: &PrivateBus, authorizer: Arc<dyn Authorizer>, core: Biometrics) {
    let address = bus.address.clone();
    let service = Service::new(core, authorizer);
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
    ready_rx.recv_timeout(std::time::Duration::from_secs(10)).expect("service did not start");
}

fn client(bus: &PrivateBus) -> zbus::blocking::Connection {
    zbus::blocking::connection::Builder::address(bus.address.as_str()).unwrap().build().unwrap()
}

fn proxy(conn: &zbus::blocking::Connection) -> zbus::blocking::Proxy<'_> {
    zbus::blocking::Proxy::new(conn, BUS_NAME, OBJECT_PATH, "io.openhello.Biometrics1").unwrap()
}

#[test]
fn enroll_verify_identify_and_purge_work_end_to_end_over_dbus() {
    let bus = PrivateBus::start();
    serve(&bus, Arc::new(AllowAll));
    let conn = client(&bus);
    let proxy = proxy(&conn);

    let handle: String = proxy.call("EnrollBegin", &(1000u32,)).unwrap();
    let (verdict, state, filled, required): (String, String, u32, u32) = proxy.call("EnrollCapture", &(handle.as_str(),)).unwrap();
    assert_eq!((verdict.as_str(), state.as_str(), filled, required), ("accepted", "complete", 6, 6));
    assert!(proxy.call::<_, _, bool>("EnrollCommit", &(handle.as_str(),)).unwrap());

    assert!(proxy.call::<_, _, bool>("Verify", &(1000u32,)).unwrap());
    assert!(!proxy.call::<_, _, bool>("Verify", &(1001u32,)).unwrap());
    assert_eq!(proxy.call::<_, _, (bool, u32)>("Identify", &()).unwrap(), (true, 1000));

    assert!(proxy.call::<_, _, bool>("Purge", &(1000u32,)).unwrap());
    assert_eq!(proxy.call::<_, _, (bool, u32)>("Identify", &()).unwrap(), (false, 0));
}

#[test]
fn unknown_session_handles_are_rejected_with_a_generic_error() {
    let bus = PrivateBus::start();
    serve(&bus, Arc::new(AllowAll));
    let conn = client(&bus);
    let error = proxy(&conn).call::<_, _, bool>("EnrollCommit", &("enroll-999",)).unwrap_err().to_string();
    assert!(error.contains("not valid in the current state"), "{error}");
    assert!(!error.contains("enroll-999"));
}

// @principle:P-003
#[test]
fn no_method_returns_embeddings_templates_or_byte_arrays() {
    let bus = PrivateBus::start();
    serve(&bus, Arc::new(AllowAll));
    let conn = client(&bus);
    let xml: String = conn
        .call_method(Some(BUS_NAME), OBJECT_PATH, Some("org.freedesktop.DBus.Introspectable"), "Introspect", &())
        .unwrap()
        .body()
        .deserialize()
        .unwrap();
    let our_interface = xml.split("<interface name=\"io.openhello.Biometrics1\">").nth(1).expect("interface introspected");
    let our_interface = our_interface.split("</interface>").next().unwrap();
    let out_types: Vec<&str> = our_interface
        .lines()
        .filter(|line| line.contains("direction=\"out\""))
        .filter_map(|line| line.split("type=\"").nth(1)?.split('"').next())
        .collect();
    assert!(out_types.len() >= 8, "{out_types:?}");
    assert!(out_types.iter().all(|t| matches!(*t, "s" | "b" | "u")), "{out_types:?}");

    let handle: String = proxy(&conn).call("EnrollBegin", &(1000u32,)).unwrap();
    assert!(!handle.contains("secret-template-bytes"));
}

struct ScriptedPolkit {
    authorized: bool,
    asked: std::sync::Mutex<Vec<String>>,
}

impl PolkitClient for ScriptedPolkit {
    fn is_authorized<'a>(&'a self, action_id: &'a str, _: &'a str) -> PolkitFuture<'a> {
        self.asked.lock().unwrap().push(action_id.to_string());
        let answer = self.authorized;
        Box::pin(async move { Ok(answer) })
    }
}

fn my_uid() -> u32 {
    std::fs::metadata("/proc/self").map(|m| std::os::unix::fs::MetadataExt::uid(&m)).unwrap()
}

// @spec:AC-013
// @principle:P-009
#[test]
fn a_caller_that_is_neither_the_target_user_nor_root_cannot_start_enrollment() {
    let bus = PrivateBus::start();
    let polkit = Arc::new(ScriptedPolkit { authorized: true, asked: Default::default() });
    let begins = serve(&bus, Arc::new(PolkitAuthorizer::new(polkit.clone())));
    let conn = client(&bus);
    let other_uid = my_uid() + 1;

    let error = proxy(&conn).call::<_, _, String>("EnrollBegin", &(other_uid,)).unwrap_err();
    assert!(error.to_string().contains("AuthFailed"), "{error}");
    assert_eq!(begins.load(Ordering::SeqCst), 0);
    assert!(polkit.asked.lock().unwrap().is_empty());
}

// @spec:AC-013
// @principle:P-009
#[test]
fn polkit_denial_refuses_enrollment_and_creates_no_session() {
    let bus = PrivateBus::start();
    let polkit = Arc::new(ScriptedPolkit { authorized: false, asked: Default::default() });
    let begins = serve(&bus, Arc::new(PolkitAuthorizer::new(polkit.clone())));
    let conn = client(&bus);

    let error = proxy(&conn).call::<_, _, String>("EnrollBegin", &(my_uid(),)).unwrap_err();
    assert!(error.to_string().contains("AuthFailed"), "{error}");
    assert!(error.to_string().contains("io.openhello.biometrics.enroll-begin"));
    assert_eq!(begins.load(Ordering::SeqCst), 0);
    assert_eq!(*polkit.asked.lock().unwrap(), vec!["io.openhello.biometrics.enroll-begin"]);
}

// @principle:P-009
#[test]
fn the_session_owner_is_served_when_polkit_agrees_and_every_enroll_call_is_gated() {
    let bus = PrivateBus::start();
    let polkit = Arc::new(ScriptedPolkit { authorized: true, asked: Default::default() });
    let begins = serve(&bus, Arc::new(PolkitAuthorizer::new(polkit.clone())));
    let conn = client(&bus);
    let proxy = proxy(&conn);

    let handle: String = proxy.call("EnrollBegin", &(my_uid(),)).unwrap();
    assert_eq!(begins.load(Ordering::SeqCst), 1);
    proxy.call::<_, _, (String, String, u32, u32)>("EnrollCapture", &(handle.as_str(),)).unwrap();
    proxy.call::<_, _, bool>("EnrollCommit", &(handle.as_str(),)).unwrap();
    let second: String = proxy.call("EnrollBegin", &(my_uid(),)).unwrap();
    proxy.call::<_, _, ()>("EnrollDiscard", &(second.as_str(),)).unwrap();
    proxy.call::<_, _, bool>("Purge", &(my_uid(),)).unwrap();

    assert_eq!(
        *polkit.asked.lock().unwrap(),
        vec![
            "io.openhello.biometrics.enroll-begin",
            "io.openhello.biometrics.enroll-capture",
            "io.openhello.biometrics.enroll-commit",
            "io.openhello.biometrics.enroll-begin",
            "io.openhello.biometrics.enroll-discard",
            "io.openhello.biometrics.purge",
        ]
    );
}

// @principle:P-009
#[test]
fn an_unreachable_polkit_authority_fails_closed() {
    let bus = PrivateBus::start();
    std::env::set_var("DBUS_SYSTEM_BUS_ADDRESS", "unix:path=/nonexistent/openhello-system-bus");
    let begins = serve(&bus, Arc::new(PolkitAuthorizer::new(Arc::new(openhellod::polkit::DbusPolkit))));
    let conn = client(&bus);
    let error = proxy(&conn).call::<_, _, String>("EnrollBegin", &(my_uid(),)).unwrap_err();
    assert!(error.to_string().contains("AuthFailed"), "{error}");
    assert_eq!(begins.load(Ordering::SeqCst), 0);
}

#[derive(Default)]
struct Probe {
    captures: AtomicUsize,
    auth_begins: AtomicUsize,
    auth_ends: AtomicUsize,
}

struct ProbeSensor(Arc<Probe>);

impl SensorBackend for ProbeSensor {
    fn capture(&mut self) -> Result<CapturedFrame, DaemonError> {
        std::thread::sleep(std::time::Duration::from_millis(50));
        self.0.captures.fetch_add(1, Ordering::SeqCst);
        Ok(CapturedFrame { width: 1, height: 1, pixels: vec![0] })
    }
}

struct ProbeEngine(Arc<Probe>);

impl EngineBackend for ProbeEngine {
    fn enroll_begin(&mut self, _: u64) -> Result<u64, DaemonError> {
        Ok(1)
    }

    fn enroll_submit(&mut self, _: u64, _: u64, _: &CapturedFrame) -> Result<EnrollProgress, DaemonError> {
        unreachable!()
    }

    fn enroll_commit(&mut self, _: u64) -> Result<Vec<u8>, DaemonError> {
        unreachable!()
    }

    fn enroll_discard(&mut self, _: u64) -> Result<(), DaemonError> {
        Ok(())
    }

    fn auth_begin(&mut self, _: &[(u32, Vec<u8>)], _: f64, _: u32) -> Result<u64, DaemonError> {
        self.0.auth_begins.fetch_add(1, Ordering::SeqCst);
        Ok(1)
    }

    fn auth_submit(&mut self, _: u64, _: &CapturedFrame) -> Result<AuthProgress, DaemonError> {
        Ok(AuthProgress { verdict: AuthVerdict::Continue, scored_frames: 1 })
    }

    fn auth_end(&mut self, _: u64) -> Result<(), DaemonError> {
        self.0.auth_ends.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

fn call_verify_from_a_process(bus: &PrivateBus) -> Child {
    Command::new("dbus-send")
        .args([&format!("--bus={}", bus.address), "--print-reply", &format!("--dest={BUS_NAME}"), OBJECT_PATH, "io.openhello.Biometrics1.Verify", "uint32:1000"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("dbus-send must be installed")
}

fn wait_until(what: &str, condition: impl Fn() -> bool) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(8);
    while !condition() {
        assert!(std::time::Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

// @spec:AC-040
#[test]
fn a_caller_that_disconnects_stops_the_capture_and_a_queued_call_of_a_dead_caller_never_starts() {
    let bus = PrivateBus::start();
    let probe = Arc::new(Probe::default());
    let mut storage = Storage::default();
    storage.put(1000, b"template").unwrap();
    let core = Biometrics::new(Box::new(ProbeSensor(probe.clone())), Box::new(ProbeEngine(probe.clone())), Box::new(storage), DEFAULT_TARGET_FAR);
    serve_core(&bus, Arc::new(AllowAll), core);

    let mut running = call_verify_from_a_process(&bus);
    wait_until("the first capture", || probe.captures.load(Ordering::SeqCst) >= 2);
    let mut queued = call_verify_from_a_process(&bus);
    std::thread::sleep(std::time::Duration::from_millis(500));
    queued.kill().unwrap();
    queued.wait().unwrap();
    std::thread::sleep(std::time::Duration::from_secs(1));

    running.kill().unwrap();
    running.wait().unwrap();
    wait_until("the capture session to end", || probe.auth_ends.load(Ordering::SeqCst) >= 1);
    std::thread::sleep(std::time::Duration::from_secs(1));
    let captured = probe.captures.load(Ordering::SeqCst);
    std::thread::sleep(std::time::Duration::from_millis(500));

    assert_eq!(probe.captures.load(Ordering::SeqCst), captured, "capture continued after the caller left");
    assert!(captured < 40, "{captured}");
    assert_eq!(probe.auth_begins.load(Ordering::SeqCst), 1, "the dead caller's queued call started");
    assert_eq!(probe.auth_ends.load(Ordering::SeqCst), 1);
}
