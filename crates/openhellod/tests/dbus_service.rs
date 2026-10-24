use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use openhellod::backends::*;
use openhellod::core::{Biometrics, DEFAULT_TARGET_FAR};
use openhellod::dbus_service::{Action, AuthFuture, Authorizer, Caller, Service, BUS_NAME, OBJECT_PATH};
use openhellod::polkit::{PolkitAuthorizer, PolkitClient, PolkitFuture};

mod support {
    pub mod fake_sudo;
}
use support::fake_sudo::{FakeSudo, Reads, Visudo, TUMBLEWEED_DEFAULTS};

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
    serve_service(bus, Service::new(core, authorizer));
}

fn serve_with_sudo(bus: &PrivateBus, authorizer: Arc<dyn Authorizer>, fake: &FakeSudo) {
    let engine = Engine { begins: Arc::default(), candidates: Vec::new() };
    let core = Biometrics::new(Box::new(Sensor), Box::new(engine), Box::new(Storage::default()), DEFAULT_TARGET_FAR);
    let rules = openhellod::polkit_admin::PolkitAdminStore::new(fake.dir.path().join("etc/polkit-1/rules.d"));
    serve_service(bus, Service::new(core, authorizer).with_sudo_policy(fake.store()).with_polkit_admin(rules));
}

fn serve_service(bus: &PrivateBus, service: Service) {
    let address = bus.address.clone();
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

struct FailingSensor(fn() -> DaemonError);

impl SensorBackend for FailingSensor {
    fn capture(&mut self) -> Result<CapturedFrame, DaemonError> {
        Err((self.0)())
    }
}

struct FailingStorage(fn() -> DaemonError);

impl StorageBackend for FailingStorage {
    fn put(&mut self, _: u32, _: &[u8]) -> Result<(), DaemonError> {
        Err((self.0)())
    }

    fn get(&mut self, _: u32) -> Result<Vec<u8>, DaemonError> {
        Err((self.0)())
    }

    fn list_uids(&mut self) -> Result<Vec<u32>, DaemonError> {
        Err((self.0)())
    }

    fn purge(&mut self, _: u32) -> Result<(), DaemonError> {
        Err((self.0)())
    }
}

fn verify_error_name(sensor: Box<dyn SensorBackend>, storage: Box<dyn StorageBackend>) -> (String, String) {
    let bus = PrivateBus::start();
    let engine = Engine { begins: Arc::new(AtomicUsize::new(0)), candidates: Vec::new() };
    serve_core(&bus, Arc::new(AllowAll), Biometrics::new(sensor, Box::new(engine), storage, DEFAULT_TARGET_FAR));
    let conn = client(&bus);
    let error = proxy(&conn).call::<_, _, bool>("Verify", &(1000u32,)).unwrap_err();
    match error {
        zbus::Error::MethodError(name, detail, _) => (name.to_string(), detail.unwrap_or_default()),
        other => panic!("expected a D-Bus method error, got {other}"),
    }
}

fn enrolled_storage() -> Box<dyn StorageBackend> {
    let mut storage = Storage::default();
    storage.put(1000, b"secret-template-bytes").unwrap();
    Box::new(storage)
}

// @spec:AC-069
#[test]
fn a_busy_camera_reaches_the_client_as_camera_busy_without_internal_detail() {
    let sensor = FailingSensor(|| DaemonError::CameraBusy("sensor capture: /dev/video2 held by pid 4242".into()));
    let (name, detail) = verify_error_name(Box::new(sensor), enrolled_storage());
    assert_eq!(name, "io.openhello.Error.CameraBusy");
    assert!(!detail.contains("/dev/video2") && !detail.contains("4242"), "{detail}");
}

// @spec:AC-069
#[test]
fn a_stuck_infrared_stream_reaches_the_client_as_sensor_stuck() {
    let sensor = FailingSensor(|| DaemonError::SensorStuck("sensor capture: no alternation".into()));
    let (name, detail) = verify_error_name(Box::new(sensor), enrolled_storage());
    assert_eq!(name, "io.openhello.Error.SensorStuck");
    assert!(!detail.contains("alternation"), "{detail}");
}

// @spec:AC-069
#[test]
fn a_missing_camera_reaches_the_client_as_no_camera() {
    let sensor = FailingSensor(|| DaemonError::NoCamera("sensor open: /dev/video2 does not exist".into()));
    let (name, detail) = verify_error_name(Box::new(sensor), enrolled_storage());
    assert_eq!(name, "io.openhello.Error.NoCamera");
    assert!(!detail.contains("/dev/video2"), "{detail}");
}

// @spec:AC-069
#[test]
fn an_unavailable_tpm_reaches_the_client_as_tpm_unavailable() {
    let storage = FailingStorage(|| DaemonError::TpmUnavailable("storage get: tpm2_getcap failed: no TCTI".into()));
    let (name, detail) = verify_error_name(Box::new(Sensor), Box::new(storage));
    assert_eq!(name, "io.openhello.Error.TpmUnavailable");
    assert!(!detail.contains("tpm2_getcap"), "{detail}");
}

// @spec:AC-069
#[test]
fn other_backend_failures_keep_the_generic_failed_error() {
    let sensor = FailingSensor(|| DaemonError::Backend("camera unplugged".into()));
    let (name, _) = verify_error_name(Box::new(sensor), enrolled_storage());
    assert_eq!(name, "org.freedesktop.DBus.Error.Failed");
}

const ONLY_METHOD_ALLOWED_TO_RETURN_IMAGE_DATA: &str = "EnrollFrame";

// @spec:AC-064
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
    let mut method = "";
    let mut out_types: Vec<(&str, &str)> = Vec::new();
    for line in our_interface.lines() {
        if let Some(name) = line.split("<method name=\"").nth(1).and_then(|rest| rest.split('"').next()) {
            method = name;
        }
        if line.contains("direction=\"out\"") {
            if let Some(kind) = line.split("type=\"").nth(1).and_then(|rest| rest.split('"').next()) {
                out_types.push((method, kind));
            }
        }
    }
    assert!(out_types.len() >= 8, "{out_types:?}");
    let offenders: Vec<_> = out_types
        .iter()
        .filter(|(method, _)| *method != ONLY_METHOD_ALLOWED_TO_RETURN_IMAGE_DATA)
        .filter(|(_, kind)| !matches!(*kind, "s" | "b" | "u"))
        .collect();
    assert!(offenders.is_empty(), "{offenders:?}");
    let allowed: Vec<_> = out_types.iter().filter(|(method, _)| *method == ONLY_METHOD_ALLOWED_TO_RETURN_IMAGE_DATA).map(|(_, kind)| *kind).collect();
    assert_eq!(allowed, ["h", "u", "u"]);

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

// @spec:AC-056
#[test]
fn status_reports_no_face_for_the_caller_and_refuses_other_users_without_polkit() {
    let bus = PrivateBus::start();
    let polkit = Arc::new(ScriptedPolkit { authorized: true, asked: Default::default() });
    serve(&bus, Arc::new(PolkitAuthorizer::new(polkit.clone())));
    let conn = client(&bus);
    let proxy = proxy(&conn);

    assert!(!proxy.call::<_, _, bool>("GetStatus", &(my_uid(),)).unwrap());
    let error = proxy.call::<_, _, bool>("GetStatus", &(my_uid() + 1,)).unwrap_err();
    assert!(error.to_string().contains("AuthFailed"), "{error}");
    assert!(error.to_string().contains("may not read the status"), "{error}");
    assert!(polkit.asked.lock().unwrap().is_empty());
}

// @spec:AC-057
#[test]
fn status_follows_enrollment_commit_and_purge() {
    let bus = PrivateBus::start();
    serve(&bus, Arc::new(AllowAll));
    let conn = client(&bus);
    let proxy = proxy(&conn);
    let uid = my_uid();

    assert!(!proxy.call::<_, _, bool>("GetStatus", &(uid,)).unwrap());
    let handle: String = proxy.call("EnrollBegin", &(uid,)).unwrap();
    proxy.call::<_, _, (String, String, u32, u32)>("EnrollCapture", &(handle.as_str(),)).unwrap();
    assert!(!proxy.call::<_, _, bool>("GetStatus", &(uid,)).unwrap());
    proxy.call::<_, _, bool>("EnrollCommit", &(handle.as_str(),)).unwrap();
    assert!(proxy.call::<_, _, bool>("GetStatus", &(uid,)).unwrap());
    proxy.call::<_, _, bool>("Purge", &(uid,)).unwrap();
    assert!(!proxy.call::<_, _, bool>("GetStatus", &(uid,)).unwrap());
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
    enroll_discards: AtomicUsize,
    releases: AtomicUsize,
}

struct ProbeSensor(Arc<Probe>);

impl SensorBackend for ProbeSensor {
    fn capture(&mut self) -> Result<CapturedFrame, DaemonError> {
        std::thread::sleep(std::time::Duration::from_millis(50));
        self.0.captures.fetch_add(1, Ordering::SeqCst);
        Ok(CapturedFrame { width: 1, height: 1, pixels: vec![0] })
    }

    fn release(&mut self) {
        self.0.releases.fetch_add(1, Ordering::SeqCst);
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
        self.0.enroll_discards.fetch_add(1, Ordering::SeqCst);
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

// @spec:AC-047
#[test]
fn an_enrollment_whose_owner_leaves_is_discarded_and_the_camera_is_released() {
    let bus = PrivateBus::start();
    let probe = Arc::new(Probe::default());
    let core = Biometrics::new(Box::new(ProbeSensor(probe.clone())), Box::new(ProbeEngine(probe.clone())), Box::new(Storage::default()), DEFAULT_TARGET_FAR);
    serve_core(&bus, Arc::new(AllowAll), core);

    let owner = client(&bus);
    let handle: String = proxy(&owner).call("EnrollBegin", &(my_uid(),)).unwrap();
    drop(owner);
    wait_until("the abandoned enrollment to be discarded", || probe.enroll_discards.load(Ordering::SeqCst) == 1);
    assert_eq!(probe.releases.load(Ordering::SeqCst), 1);

    let other = client(&bus);
    let error = proxy(&other).call::<_, _, (String, String, u32, u32)>("EnrollCapture", &(handle.as_str(),)).unwrap_err().to_string();
    assert!(error.contains("not valid in the current state"), "{error}");
}

// @spec:AC-047
#[test]
fn an_enrollment_that_is_committed_or_discarded_by_its_owner_is_not_discarded_again_when_it_leaves() {
    let bus = PrivateBus::start();
    let probe = Arc::new(Probe::default());
    let core = Biometrics::new(Box::new(ProbeSensor(probe.clone())), Box::new(ProbeEngine(probe.clone())), Box::new(Storage::default()), DEFAULT_TARGET_FAR);
    serve_core(&bus, Arc::new(AllowAll), core);

    let owner = client(&bus);
    let handle: String = proxy(&owner).call("EnrollBegin", &(my_uid(),)).unwrap();
    proxy(&owner).call::<_, _, ()>("EnrollDiscard", &(handle.as_str(),)).unwrap();
    drop(owner);
    std::thread::sleep(std::time::Duration::from_millis(500));
    assert_eq!(probe.enroll_discards.load(Ordering::SeqCst), 1);
    assert_eq!(probe.releases.load(Ordering::SeqCst), 1);
}

const PREVIEW_PIXELS: [u8; 6] = [10, 20, 30, 40, 50, 60];

struct PreviewSensor;

impl SensorBackend for PreviewSensor {
    fn capture(&mut self) -> Result<CapturedFrame, DaemonError> {
        Ok(CapturedFrame { width: 3, height: 2, pixels: PREVIEW_PIXELS.to_vec() })
    }
}

fn preview_core() -> Biometrics {
    let engine = Engine { begins: Arc::new(AtomicUsize::new(0)), candidates: Vec::new() };
    Biometrics::new(Box::new(PreviewSensor), Box::new(engine), Box::new(Storage::default()), DEFAULT_TARGET_FAR)
}

fn serve_preview(authorized: bool) -> (PrivateBus, Arc<ScriptedPolkit>) {
    let bus = PrivateBus::start();
    let polkit = Arc::new(ScriptedPolkit { authorized, asked: Default::default() });
    serve_core(&bus, Arc::new(PolkitAuthorizer::new(polkit.clone())), preview_core());
    (bus, polkit)
}

fn read_frame(reply: (zbus::zvariant::OwnedFd, u32, u32)) -> (std::fs::File, u32, u32) {
    (std::fs::File::from(std::os::fd::OwnedFd::from(reply.0)), reply.1, reply.2)
}

fn capture_once(proxy: &zbus::blocking::Proxy<'_>, handle: &str) {
    proxy.call::<_, _, (String, String, u32, u32)>("EnrollCapture", &(handle,)).unwrap();
}

// @spec:AC-063
#[test]
fn the_owner_receives_the_latest_frame_as_a_sealed_read_only_memory_file() {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::FileExt;

    let (bus, polkit) = serve_preview(true);
    let conn = client(&bus);
    let proxy = proxy(&conn);
    let handle: String = proxy.call("EnrollBegin", &(my_uid(),)).unwrap();
    capture_once(&proxy, &handle);

    let (file, width, height) = read_frame(proxy.call("EnrollFrame", &(handle.as_str(),)).unwrap());
    assert_eq!((width, height), (3, 2));
    let mut pixels = vec![0u8; (width * height) as usize];
    file.read_exact_at(&mut pixels, 0).unwrap();
    assert_eq!(pixels, PREVIEW_PIXELS);
    assert_eq!(file.metadata().unwrap().len(), PREVIEW_PIXELS.len() as u64);
    assert!(polkit.asked.lock().unwrap().contains(&"io.openhello.biometrics.enroll-frame".to_string()));

    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) };
    assert_ne!(flags & libc::FD_CLOEXEC, 0);
    assert!(file.write_at(&[1], 0).is_err());
    assert!(file.set_len(0).is_err());
    assert!(file.set_len(100).is_err());
    file.read_exact_at(&mut pixels, 0).unwrap();
    assert_eq!(pixels, PREVIEW_PIXELS);
}

type FrameReply = (zbus::zvariant::OwnedFd, u32, u32);

fn serve_with_captured_session(owner_uid: u32, authorized: bool) -> (PrivateBus, Arc<ScriptedPolkit>, String) {
    let bus = PrivateBus::start();
    let polkit = Arc::new(ScriptedPolkit { authorized, asked: Default::default() });
    let mut core = preview_core();
    let handle = core.enroll_begin(owner_uid).unwrap();
    core.enroll_capture(&handle).unwrap();
    serve_core(&bus, Arc::new(PolkitAuthorizer::new(polkit.clone())), core);
    (bus, polkit, handle)
}

// @spec:AC-063
#[test]
fn the_preview_refuses_unknown_handles_and_sessions_without_a_frame() {
    let (bus, _) = serve_preview(true);
    let conn = client(&bus);
    let proxy = proxy(&conn);
    let unknown = proxy.call::<_, _, FrameReply>("EnrollFrame", &("enroll-999",)).unwrap_err();
    assert!(unknown.to_string().contains("not valid in the current state"), "{unknown}");
    let handle: String = proxy.call("EnrollBegin", &(my_uid(),)).unwrap();
    let early = proxy.call::<_, _, FrameReply>("EnrollFrame", &(handle.as_str(),)).unwrap_err();
    assert!(early.to_string().contains("not valid in the current state"), "{early}");
}

// @spec:AC-063
// @principle:P-009
#[test]
fn the_preview_is_refused_to_another_user_and_without_polkit_authorization() {
    let (bus, polkit, handle) = serve_with_captured_session(my_uid() + 1, true);
    let conn = client(&bus);
    let error = proxy(&conn).call::<_, _, FrameReply>("EnrollFrame", &(handle.as_str(),)).unwrap_err();
    assert!(error.to_string().contains("AuthFailed"), "{error}");
    assert!(polkit.asked.lock().unwrap().is_empty());

    let (bus, polkit, handle) = serve_with_captured_session(my_uid(), false);
    let conn = client(&bus);
    let error = proxy(&conn).call::<_, _, FrameReply>("EnrollFrame", &(handle.as_str(),)).unwrap_err();
    assert!(error.to_string().contains("AuthFailed"), "{error}");
    assert!(error.to_string().contains("io.openhello.biometrics.enroll-frame"), "{error}");
    assert_eq!(*polkit.asked.lock().unwrap(), vec!["io.openhello.biometrics.enroll-frame"]);
}

// @spec:AC-063
#[test]
fn a_committed_or_discarded_session_no_longer_serves_its_preview() {
    let (bus, _) = serve_preview(true);
    let conn = client(&bus);
    let proxy = proxy(&conn);
    for finish in ["EnrollCommit", "EnrollDiscard"] {
        let handle: String = proxy.call("EnrollBegin", &(my_uid(),)).unwrap();
        capture_once(&proxy, &handle);
        let (kept, _, _) = read_frame(proxy.call("EnrollFrame", &(handle.as_str(),)).unwrap());
        proxy.call_method(finish, &(handle.as_str(),)).unwrap();
        let error = proxy.call::<_, _, FrameReply>("EnrollFrame", &(handle.as_str(),)).unwrap_err();
        assert!(error.to_string().contains("not valid in the current state"), "{finish}: {error}");
        drop(kept);
    }
}

struct ReadinessSensor {
    probe: fn() -> Result<(), DaemonError>,
    captures: Arc<AtomicUsize>,
}

impl SensorBackend for ReadinessSensor {
    fn capture(&mut self) -> Result<CapturedFrame, DaemonError> {
        self.captures.fetch_add(1, Ordering::SeqCst);
        Err(DaemonError::Backend("capture must not be called by the readiness check".into()))
    }

    fn probe(&mut self) -> Result<(), DaemonError> {
        (self.probe)()
    }
}

struct ReadinessStorage(fn() -> Result<(), DaemonError>);

impl StorageBackend for ReadinessStorage {
    fn put(&mut self, _: u32, _: &[u8]) -> Result<(), DaemonError> {
        Ok(())
    }

    fn get(&mut self, _: u32) -> Result<Vec<u8>, DaemonError> {
        Err(DaemonError::NotFound)
    }

    fn list_uids(&mut self) -> Result<Vec<u32>, DaemonError> {
        Ok(Vec::new())
    }

    fn purge(&mut self, _: u32) -> Result<(), DaemonError> {
        Ok(())
    }

    fn probe(&mut self) -> Result<(), DaemonError> {
        (self.0)()
    }
}

struct CountingAuthorizer(Arc<AtomicUsize>);

impl Authorizer for CountingAuthorizer {
    fn authorize<'a>(&'a self, _: Action, _: &'a Caller, _: u32) -> AuthFuture<'a> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Err("refused".to_string()) })
    }
}

struct Readiness {
    outcome: Result<(), (String, String)>,
    captures: usize,
    authorizations: usize,
}

fn check_ready(sensor_probe: fn() -> Result<(), DaemonError>, storage_probe: fn() -> Result<(), DaemonError>) -> Readiness {
    let bus = PrivateBus::start();
    let (captures, authorizations) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let sensor = ReadinessSensor { probe: sensor_probe, captures: captures.clone() };
    let engine = Engine { begins: Arc::new(AtomicUsize::new(0)), candidates: Vec::new() };
    let core = Biometrics::new(Box::new(sensor), Box::new(engine), Box::new(ReadinessStorage(storage_probe)), DEFAULT_TARGET_FAR);
    serve_core(&bus, Arc::new(CountingAuthorizer(authorizations.clone())), core);
    let conn = client(&bus);
    let outcome = match proxy(&conn).call::<_, _, ()>("CheckReady", &()) {
        Ok(()) => Ok(()),
        Err(zbus::Error::MethodError(name, detail, _)) => Err((name.to_string(), detail.unwrap_or_default())),
        Err(other) => panic!("expected a D-Bus method error, got {other}"),
    };
    Readiness { outcome, captures: captures.load(Ordering::SeqCst), authorizations: authorizations.load(Ordering::SeqCst) }
}

fn healthy() -> Result<(), DaemonError> {
    Ok(())
}

// @spec:AC-070
#[test]
fn check_ready_succeeds_with_a_healthy_camera_and_tpm_without_capturing_or_asking_polkit() {
    let readiness = check_ready(healthy, healthy);
    assert!(readiness.outcome.is_ok(), "{:?}", readiness.outcome);
    assert_eq!(readiness.captures, 0);
    assert_eq!(readiness.authorizations, 0);
}

// @spec:AC-070
// @spec:AC-069
#[test]
fn check_ready_reports_a_missing_camera_as_no_camera() {
    let readiness = check_ready(|| Err(DaemonError::NoCamera("/dev/video2 does not exist".into())), healthy);
    let (name, detail) = readiness.outcome.unwrap_err();
    assert_eq!(name, "io.openhello.Error.NoCamera");
    assert!(!detail.contains("/dev/video2"), "{detail}");
    assert_eq!(readiness.captures, 0);
}

// @spec:AC-070
// @spec:AC-069
#[test]
fn check_ready_reports_a_busy_camera_as_camera_busy() {
    let readiness = check_ready(|| Err(DaemonError::CameraBusy("VIDIOC_S_FMT: busy".into())), healthy);
    assert_eq!(readiness.outcome.unwrap_err().0, "io.openhello.Error.CameraBusy");
    assert_eq!(readiness.captures, 0);
}

// @spec:AC-070
// @spec:AC-069
#[test]
fn check_ready_reports_an_unavailable_tpm_as_tpm_unavailable() {
    let readiness = check_ready(healthy, || Err(DaemonError::TpmUnavailable("tpm2_getcap failed".into())));
    let (name, detail) = readiness.outcome.unwrap_err();
    assert_eq!(name, "io.openhello.Error.TpmUnavailable");
    assert!(!detail.contains("tpm2_getcap"), "{detail}");
    assert_eq!(readiness.captures, 0);
}

#[test]
fn the_caller_reads_whose_password_sudo_asks_only_for_its_own_uid() {
    let bus = PrivateBus::start();
    let fake = FakeSudo::new(TUMBLEWEED_DEFAULTS, Visudo::Accepts, Reads::DropIns);
    let polkit = Arc::new(ScriptedPolkit { authorized: true, asked: Default::default() });
    serve_with_sudo(&bus, Arc::new(PolkitAuthorizer::new(polkit.clone())), &fake);
    let conn = client(&bus);
    let policy: String = proxy(&conn).call("GetSudoPolicy", &(my_uid(),)).unwrap();
    assert_eq!(policy, "root-password");
    let error = proxy(&conn).call::<_, _, String>("GetSudoPolicy", &(my_uid() + 1,)).unwrap_err();
    assert!(error.to_string().contains("AuthFailed"), "{error}");
    assert!(polkit.asked.lock().unwrap().is_empty());
}

#[test]
fn switching_sudo_to_the_own_password_needs_polkit_and_purge_restores_it() {
    let bus = PrivateBus::start();
    let fake = FakeSudo::new(TUMBLEWEED_DEFAULTS, Visudo::Accepts, Reads::DropIns);
    let polkit = Arc::new(ScriptedPolkit { authorized: true, asked: Default::default() });
    serve_with_sudo(&bus, Arc::new(PolkitAuthorizer::new(polkit.clone())), &fake);
    let conn = client(&bus);
    let policy: String = proxy(&conn).call("UseOwnPasswordForSudo", &(my_uid(),)).unwrap();
    assert_eq!(policy, "own-password");
    assert!(fake.drop_in(my_uid()).exists());
    let rule = std::fs::read_to_string(polkit_rule(&fake)).unwrap();
    assert!(rule.contains("\"unix-user:0\""), "sudo asked for root before, so root stays a choice: {rule}");
    assert_eq!(*polkit.asked.lock().unwrap(), vec!["io.openhello.biometrics.sudo-own-password"]);
    assert_eq!(proxy(&conn).call::<_, _, String>("GetSudoPolicy", &(my_uid(),)).unwrap(), "own-password");

    proxy(&conn).call::<_, _, bool>("Purge", &(my_uid(),)).unwrap();
    assert!(!fake.drop_in(my_uid()).exists());
    assert!(!polkit_rule(&fake).exists());
    assert_eq!(proxy(&conn).call::<_, _, String>("GetSudoPolicy", &(my_uid(),)).unwrap(), "root-password");
}

#[test]
fn a_polkit_refusal_leaves_sudo_untouched() {
    let bus = PrivateBus::start();
    let fake = FakeSudo::new(TUMBLEWEED_DEFAULTS, Visudo::Accepts, Reads::DropIns);
    let polkit = Arc::new(ScriptedPolkit { authorized: false, asked: Default::default() });
    serve_with_sudo(&bus, Arc::new(PolkitAuthorizer::new(polkit)), &fake);
    let conn = client(&bus);
    let error = proxy(&conn).call::<_, _, String>("UseOwnPasswordForSudo", &(my_uid(),)).unwrap_err();
    assert!(error.to_string().contains("AuthFailed"), "{error}");
    assert!(fake.entries().is_empty());
}

#[test]
fn a_failed_switch_returns_a_short_message_without_paths_or_tool_output() {
    let bus = PrivateBus::start();
    let fake = FakeSudo::new(TUMBLEWEED_DEFAULTS, Visudo::Rejects, Reads::DropIns);
    serve_with_sudo(&bus, Arc::new(AllowAll), &fake);
    let conn = client(&bus);
    let error = proxy(&conn).call::<_, _, String>("UseOwnPasswordForSudo", &(my_uid(),)).unwrap_err().to_string();
    assert!(error.contains("sudo could not be changed"), "{error}");
    assert!(!error.contains("sudoers") && !error.contains("syntax error"), "{error}");
    assert!(fake.entries().is_empty());
    assert!(!polkit_rule(&fake).exists());
}

fn polkit_rule(fake: &FakeSudo) -> std::path::PathBuf {
    fake.dir.path().join(format!("etc/polkit-1/rules.d/49-openhello-uid{}.rules", my_uid()))
}

struct CountingSensor(Arc<AtomicUsize>);

impl SensorBackend for CountingSensor {
    fn capture(&mut self) -> Result<CapturedFrame, DaemonError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(CapturedFrame { width: 1, height: 1, pixels: vec![0] })
    }
}

fn enrolled_service(bus: &PrivateBus) -> (zbus::blocking::Connection, Arc<AtomicUsize>) {
    let captures = Arc::new(AtomicUsize::new(0));
    let engine = Engine { begins: Arc::default(), candidates: Vec::new() };
    let core = Biometrics::new(Box::new(CountingSensor(captures.clone())), Box::new(engine), Box::new(Storage::default()), DEFAULT_TARGET_FAR);
    serve_core(bus, Arc::new(AllowAll), core);
    let conn = client(bus);
    let handle: String = proxy(&conn).call("EnrollBegin", &(1000u32,)).unwrap();
    proxy(&conn).call::<_, _, (String, String, u32, u32)>("EnrollCapture", &(handle.as_str(),)).unwrap();
    proxy(&conn).call::<_, _, bool>("EnrollCommit", &(handle.as_str(),)).unwrap();
    captures.store(0, Ordering::SeqCst);
    (conn, captures)
}

fn sign_in_from_another_process(bus: &PrivateBus) -> String {
    let out = Command::new("dbus-send")
        .arg(format!("--bus={}", bus.address))
        .args(["--print-reply", "--dest=io.openhello.Biometrics1", "/io/openhello/Biometrics1", "io.openhello.Biometrics1.VerifyForSignIn", "uint32:1000"])
        .output()
        .expect("dbus-send must be installed");
    format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr))
}

#[test]
fn a_sign_in_process_keeps_its_match_without_the_camera_and_others_get_their_own() {
    let bus = PrivateBus::start();
    let (conn, captures) = enrolled_service(&bus);
    assert!(proxy(&conn).call::<_, _, bool>("VerifyForSignIn", &(1000u32,)).unwrap());
    let first = captures.load(Ordering::SeqCst);
    assert!(first > 0);
    assert!(proxy(&conn).call::<_, _, bool>("VerifyForSignIn", &(1000u32,)).unwrap(), "a lock screen re-asking keeps its unlock");
    let fresh = client(&bus);
    assert!(proxy(&fresh).call::<_, _, bool>("VerifyForSignIn", &(1000u32,)).unwrap());
    assert_eq!(captures.load(Ordering::SeqCst), first, "the camera stays off for the same process");
    assert!(sign_in_from_another_process(&bus).contains("boolean true"));
    assert!(captures.load(Ordering::SeqCst) > first, "another process is checked afresh");
}

#[test]
fn a_refused_face_sends_that_process_to_the_password_without_the_camera() {
    let bus = PrivateBus::start();
    let (conn, captures) = enrolled_service(&bus);
    assert!(!proxy(&conn).call::<_, _, bool>("VerifyForSignIn", &(1001u32,)).unwrap());
    let first = captures.load(Ordering::SeqCst);
    let again = proxy(&conn).call::<_, _, bool>("VerifyForSignIn", &(1001u32,)).unwrap_err().to_string();
    assert!(again.contains("io.openhello.Error.AlreadyDecided"), "{again}");
    assert_eq!(captures.load(Ordering::SeqCst), first);
}

#[test]
fn a_decision_belongs_to_the_user_it_was_made_for() {
    let bus = PrivateBus::start();
    let (conn, captures) = enrolled_service(&bus);
    assert!(!proxy(&conn).call::<_, _, bool>("VerifyForSignIn", &(1001u32,)).unwrap());
    let first = captures.load(Ordering::SeqCst);
    assert!(proxy(&conn).call::<_, _, bool>("VerifyForSignIn", &(1000u32,)).unwrap());
    assert!(captures.load(Ordering::SeqCst) > first, "a refusal for one user never answers for another");
}

#[test]
fn the_window_test_button_keeps_verifying_as_often_as_asked() {
    let bus = PrivateBus::start();
    let (conn, captures) = enrolled_service(&bus);
    for round in 1..=3 {
        assert!(proxy(&conn).call::<_, _, bool>("Verify", &(1000u32,)).unwrap());
        assert!(captures.load(Ordering::SeqCst) >= round);
    }
}

#[test]
fn the_process_start_time_is_read_past_a_command_name_with_spaces_and_parentheses() {
    let stat = "4242 (kscreenlocker (greet)) S 1 4242 4242 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 3 0 987654 1000 200 18446744073709551615";
    assert_eq!(openhellod::dbus_service::process_start_time(stat), Some(987654));
    assert_eq!(openhellod::dbus_service::process_start_time("garbage"), None);
}
