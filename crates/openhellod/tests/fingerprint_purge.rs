use std::collections::BTreeMap;
use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use openhellod::backends::*;
use openhellod::core::{Biometrics, DEFAULT_TARGET_FAR};
use openhellod::fingerprint::*;
use openhellod::keyd_client::{KeydBus, KeydClient};
use openhellod::logging::{Level, LogSink, Logger};
use zbus::object_server::SignalEmitter;
use zbus::zvariant::OwnedObjectPath;
use zbus::{interface, Connection, DBusError};

const DEVICE_PATH: &str = "/net/reactivated/Fprint/Device/0";
const OWNER_UID: u32 = 1000;
const OWNER_NAME: &str = "owner";
const INDEX: &str = "right-index-finger";
const THUMB: &str = "left-thumb";
const MARKER: &str = "PRINT-MARKER-\u{1f}\u{7f}-9f3a";
const MARKER_HEX: &str = "9f3a7c11d0e4";

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

#[derive(DBusError, Debug)]
#[zbus(prefix = "net.reactivated.Fprint.Error")]
enum FprintError {
    #[zbus(error)]
    ZBus(zbus::Error),
    NoSuchDevice(String),
    NoEnrolledPrints(String),
    PermissionDenied(String),
}

#[derive(Default)]
struct Fake {
    no_device: bool,
    delete_denied: bool,
    marker_data: bool,
    verify_script: Mutex<Vec<&'static str>>,
    enroll_script: Mutex<Vec<&'static str>>,
    enrolled: Mutex<Vec<String>>,
    claims: Mutex<Vec<String>>,
    releases: AtomicUsize,
    deletes: AtomicUsize,
    stopped: AtomicBool,
    connection: Mutex<Option<Connection>>,
}

struct Manager(Arc<Fake>);
struct Device(Arc<Fake>);

#[interface(name = "net.reactivated.Fprint.Manager")]
impl Manager {
    async fn get_default_device(&self) -> Result<OwnedObjectPath, FprintError> {
        if self.0.no_device {
            return Err(FprintError::NoSuchDevice(format!("no devices {MARKER}")));
        }
        Ok(OwnedObjectPath::try_from(DEVICE_PATH).unwrap())
    }
}

impl Device {
    fn emit_later(fake: Arc<Fake>, script: Vec<&'static str>, enroll: bool) {
        std::thread::spawn(move || {
            for status in script {
                std::thread::sleep(Duration::from_millis(20));
                if fake.stopped.load(Ordering::SeqCst) {
                    return;
                }
                let connection = fake.connection.lock().unwrap().clone().unwrap();
                async_io::block_on(async {
                    let iface = connection.object_server().interface::<_, Device>(DEVICE_PATH).await.unwrap();
                    if enroll {
                        Device::enroll_status(iface.signal_emitter(), status, false).await.unwrap();
                    } else {
                        Device::verify_status(iface.signal_emitter(), status, false).await.unwrap();
                    }
                });
            }
        });
    }
}

#[interface(name = "net.reactivated.Fprint.Device")]
impl Device {
    #[zbus(property, name = "num-enroll-stages")]
    async fn num_enroll_stages(&self) -> i32 {
        5
    }

    #[zbus(property, name = "scan-type")]
    async fn scan_type(&self) -> String {
        format!("press {MARKER}")
    }

    async fn claim(&self, username: String) {
        self.0.claims.lock().unwrap().push(username);
    }

    async fn release(&self) {
        self.0.releases.fetch_add(1, Ordering::SeqCst);
    }

    async fn list_enrolled_fingers(&self, _username: String) -> Result<Vec<String>, FprintError> {
        let mut enrolled = self.0.enrolled.lock().unwrap().clone();
        if enrolled.is_empty() {
            return Err(FprintError::NoEnrolledPrints(format!("none {MARKER}")));
        }
        if self.0.marker_data {
            enrolled.push(MARKER.to_string());
        }
        Ok(enrolled)
    }

    async fn delete_enrolled_fingers2(&self) -> Result<(), FprintError> {
        self.0.deletes.fetch_add(1, Ordering::SeqCst);
        if self.0.delete_denied {
            return Err(FprintError::PermissionDenied(format!("denied {MARKER}")));
        }
        self.0.enrolled.lock().unwrap().clear();
        Ok(())
    }

    async fn verify_start(&self, _finger: String) -> Result<(), FprintError> {
        self.0.stopped.store(false, Ordering::SeqCst);
        let script = self.0.verify_script.lock().unwrap().clone();
        Device::emit_later(self.0.clone(), script, false);
        Ok(())
    }

    async fn verify_stop(&self) {
        self.0.stopped.store(true, Ordering::SeqCst);
    }

    async fn enroll_start(&self, _finger: String) {
        self.0.stopped.store(false, Ordering::SeqCst);
        let script = self.0.enroll_script.lock().unwrap().clone();
        Device::emit_later(self.0.clone(), script, true);
    }

    async fn enroll_stop(&self) {
        self.0.stopped.store(true, Ordering::SeqCst);
    }

    #[zbus(signal)]
    async fn verify_status(emitter: &SignalEmitter<'_>, result: &str, done: bool) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn enroll_status(emitter: &SignalEmitter<'_>, result: &str, done: bool) -> zbus::Result<()>;
}

struct FakeKeyd {
    purges: Arc<AtomicUsize>,
    destroys: bool,
}

#[interface(name = "io.openhello.Keyd1")]
impl FakeKeyd {
    async fn purge(&self, _uid: u32) -> bool {
        self.purges.fetch_add(1, Ordering::SeqCst);
        self.destroys
    }
}

#[derive(Default)]
struct CaptureSink(Mutex<Vec<String>>);

impl LogSink for CaptureSink {
    fn write_line(&self, line: &str) {
        self.0.lock().unwrap().push(line.to_string());
    }
}

struct Sensor;

impl SensorBackend for Sensor {
    fn capture(&mut self) -> Result<CapturedFrame, DaemonError> {
        Ok(CapturedFrame { width: 1, height: 1, pixels: vec![0] })
    }
}

struct Engine;

impl EngineBackend for Engine {
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
        Ok(1)
    }

    fn auth_submit(&mut self, _: u64, _: &CapturedFrame) -> Result<AuthProgress, DaemonError> {
        Ok(AuthProgress { verdict: AuthVerdict::Rejected, scored_frames: 1 })
    }

    fn auth_end(&mut self, _: u64) -> Result<(), DaemonError> {
        Ok(())
    }
}

#[derive(Clone, Default)]
struct Storage {
    files: Arc<Mutex<BTreeMap<u32, Vec<u8>>>>,
    purge_fails: bool,
}

impl StorageBackend for Storage {
    fn put(&mut self, uid: u32, template: &[u8]) -> Result<(), DaemonError> {
        self.files.lock().unwrap().insert(uid, template.to_vec());
        Ok(())
    }

    fn get(&mut self, uid: u32) -> Result<Vec<u8>, DaemonError> {
        self.files.lock().unwrap().get(&uid).cloned().ok_or(DaemonError::NotFound)
    }

    fn list_uids(&mut self) -> Result<Vec<u32>, DaemonError> {
        Ok(self.files.lock().unwrap().keys().copied().collect())
    }

    fn purge(&mut self, uid: u32) -> Result<(), DaemonError> {
        if self.purge_fails {
            return Err(DaemonError::Backend("storage purge failed".into()));
        }
        self.files.lock().unwrap().remove(&uid);
        Ok(())
    }
}

struct Rig {
    _fprint: PrivateBus,
    _keyd: PrivateBus,
    _connections: Vec<Connection>,
    fake: Arc<Fake>,
    key_purges: Arc<AtomicUsize>,
    storage: Storage,
    sink: Arc<CaptureSink>,
    fprint_address: String,
    core: Biometrics,
}

fn resolver() -> Box<dyn Fn(u32) -> Option<String> + Send> {
    Box::new(|uid| (uid == OWNER_UID).then(|| OWNER_NAME.to_string()))
}

fn serve(bus: &PrivateBus, name: &str, build: impl FnOnce(zbus::connection::Builder<'static>) -> zbus::connection::Builder<'static>) -> Connection {
    let builder = zbus::connection::Builder::address(bus.address.as_str()).unwrap().name(name.to_string()).unwrap();
    async_io::block_on(async { build(builder).build().await.unwrap() })
}

fn rig(fake: Fake, key_destroys: bool, storage: Storage, with_matcher: bool) -> Rig {
    let fprint = PrivateBus::start();
    let keyd = PrivateBus::start();
    let fake = Arc::new(fake);
    let fprintd = serve(&fprint, "net.reactivated.Fprint", |builder| {
        builder
            .serve_at("/net/reactivated/Fprint/Manager", Manager(fake.clone()))
            .unwrap()
            .serve_at(DEVICE_PATH, Device(fake.clone()))
            .unwrap()
    });
    *fake.connection.lock().unwrap() = Some(fprintd.clone());
    let key_purges = Arc::new(AtomicUsize::new(0));
    let keyd_connection = serve(&keyd, "io.openhello.Keyd1", |builder| {
        builder.serve_at("/io/openhello/Keyd1", FakeKeyd { purges: key_purges.clone(), destroys: key_destroys }).unwrap()
    });
    let sink = Arc::new(CaptureSink::default());
    let logger = Logger::new(Level::Trace, sink.clone());
    let matcher = FprintdMatcher::with_user_names(FprintdBus::Address(fprint.address.clone()), logger.clone(), resolver());
    let mut core = Biometrics::new(Box::new(Sensor), Box::new(Engine), Box::new(storage.clone()), DEFAULT_TARGET_FAR)
        .with_logger(logger)
        .with_keyd_client(Some(KeydClient::new(KeydBus::Address(keyd.address.clone()))));
    if with_matcher {
        core = core.with_fingerprint(Some(Box::new(matcher)));
    }
    let fprint_address = fprint.address.clone();
    Rig { _fprint: fprint, _keyd: keyd, _connections: vec![fprintd, keyd_connection], fake, key_purges, storage, sink, fprint_address, core }
}

fn enrolled(fingers: &[&str]) -> Fake {
    Fake { enrolled: Mutex::new(fingers.iter().map(|f| f.to_string()).collect()), ..Fake::default() }
}

fn stored() -> Storage {
    let storage = Storage::default();
    storage.files.lock().unwrap().insert(OWNER_UID, b"face-template".to_vec());
    storage
}

fn purge_line(rig: &Rig) -> String {
    rig.sink.0.lock().unwrap().iter().find(|line| line.contains(" purge ")).cloned().expect("purge line logged")
}

fn assert_incomplete(result: Result<(), DaemonError>) {
    assert!(matches!(result, Err(DaemonError::Backend(_))), "{result:?}");
}

// @spec:AC-058
#[test]
fn purge_deletes_the_face_template_the_key_and_every_enrolled_finger() {
    let mut rig = rig(enrolled(&[INDEX, THUMB]), true, stored(), true);
    rig.core.purge(OWNER_UID).unwrap();
    assert!(rig.storage.files.lock().unwrap().is_empty());
    assert_eq!(rig.key_purges.load(Ordering::SeqCst), 1);
    assert!(rig.fake.enrolled.lock().unwrap().is_empty());
    assert_eq!(*rig.fake.claims.lock().unwrap(), vec![OWNER_NAME.to_string()]);
    assert_eq!(rig.fake.releases.load(Ordering::SeqCst), 1);
    let line = purge_line(&rig);
    assert!(line.contains("template=destroyed key=destroyed fingers=destroyed"), "{line}");
}

// @spec:AC-058
#[test]
fn a_refused_finger_deletion_is_incomplete_but_template_and_key_are_still_destroyed() {
    let mut rig = rig(Fake { delete_denied: true, ..enrolled(&[INDEX]) }, true, stored(), true);
    assert_incomplete(rig.core.purge(OWNER_UID));
    assert!(rig.storage.files.lock().unwrap().is_empty());
    assert_eq!(rig.key_purges.load(Ordering::SeqCst), 1);
    assert_eq!(rig.fake.deletes.load(Ordering::SeqCst), 1);
    assert_eq!(rig.fake.releases.load(Ordering::SeqCst), 1);
    assert!(purge_line(&rig).contains("key=destroyed fingers=failed"));
}

// @spec:AC-058
#[test]
fn a_failed_key_purge_is_incomplete_but_the_fingers_are_still_deleted() {
    let mut rig = rig(enrolled(&[INDEX]), false, stored(), true);
    assert_incomplete(rig.core.purge(OWNER_UID));
    assert!(rig.storage.files.lock().unwrap().is_empty());
    assert!(rig.fake.enrolled.lock().unwrap().is_empty());
    assert!(purge_line(&rig).contains("key=failed fingers=destroyed"));
}

// @spec:AC-058
#[test]
fn a_failed_template_purge_is_incomplete_but_key_and_fingers_are_still_destroyed() {
    let storage = Storage { purge_fails: true, ..stored() };
    let mut rig = rig(enrolled(&[INDEX]), true, storage, true);
    assert_incomplete(rig.core.purge(OWNER_UID));
    assert_eq!(rig.key_purges.load(Ordering::SeqCst), 1);
    assert!(rig.fake.enrolled.lock().unwrap().is_empty());
    assert!(purge_line(&rig).contains("template=failed key=destroyed fingers=destroyed"));
}

// @spec:AC-058
#[test]
fn a_user_without_enrolled_fingers_purges_successfully_without_claiming_the_reader() {
    let mut rig = rig(enrolled(&[]), true, stored(), true);
    rig.core.purge(OWNER_UID).unwrap();
    assert!(rig.fake.claims.lock().unwrap().is_empty());
    assert_eq!(rig.fake.deletes.load(Ordering::SeqCst), 0);
    assert!(purge_line(&rig).contains("fingers=none"));
}

// @spec:AC-058
#[test]
fn a_machine_without_a_reader_or_without_fprintd_purges_successfully() {
    let mut no_device = rig(Fake { no_device: true, ..enrolled(&[INDEX]) }, true, stored(), true);
    no_device.core.purge(OWNER_UID).unwrap();
    assert!(purge_line(&no_device).contains("fingers=none"));

    let mut absent = rig(enrolled(&[INDEX]), true, stored(), false);
    let empty_bus = PrivateBus::start();
    let mut matcher = FprintdMatcher::with_user_names(
        FprintdBus::Address(empty_bus.address.clone()),
        Logger::new(Level::Trace, absent.sink.clone()),
        resolver(),
    );
    assert_eq!(matcher.delete_enrolled(OWNER_UID), FingerDeletion::NothingToDelete);
    absent.core = absent.core.with_fingerprint(Some(Box::new(matcher)));
    absent.core.purge(OWNER_UID).unwrap();
    assert!(purge_line(&absent).contains("fingers=none"));
}

// @spec:AC-058
#[test]
fn without_a_fingerprint_matcher_purge_behaves_as_before() {
    let mut rig = rig(enrolled(&[INDEX]), true, stored(), false);
    rig.core.purge(OWNER_UID).unwrap();
    assert!(rig.storage.files.lock().unwrap().is_empty());
    assert_eq!(rig.key_purges.load(Ordering::SeqCst), 1);
    assert_eq!(rig.fake.enrolled.lock().unwrap().len(), 1);
    assert!(rig.fake.claims.lock().unwrap().is_empty());
    assert!(purge_line(&rig).contains("fingers=not-configured"));
}

// @spec:AC-059
// @principle:P-010
#[test]
fn fingerprint_request_enrollment_and_purge_never_log_fprintd_print_data() {
    let fake = Fake {
        marker_data: true,
        delete_denied: true,
        verify_script: Mutex::new(vec![MARKER_STATUS, "verify-retry-scan", "verify-no-match", MARKER_STATUS]),
        enroll_script: Mutex::new(vec!["enroll-stage-passed", "enroll-retry-scan", MARKER_STATUS]),
        ..enrolled(&[INDEX])
    };
    let mut rig = rig(fake, false, stored(), true);

    assert!(!rig.core.verify(OWNER_UID).unwrap());
    assert!(!rig.core.verify(4242).unwrap());

    let enroller = FprintdEnroller::with_user_names(
        FprintdBus::Address(rig.fprint_address.clone()),
        Logger::new(Level::Trace, rig.sink.clone()),
        Box::new(|uid| (uid == OWNER_UID).then(|| OWNER_NAME.to_string())),
    );
    assert_eq!(enroller.reader_status(OWNER_UID).enrolled, vec![INDEX]);
    assert!(enroller.begin(OWNER_UID, MARKER).is_err());
    assert!(enroller.begin(OWNER_UID, INDEX).is_err());
    let mut enrollment = enroller.begin(OWNER_UID, THUMB).unwrap();
    let never = || false;
    while enrollment.next_step(&never).state == FingerEnrollState::InProgress {}
    drop(enrollment);

    assert_incomplete(rig.core.purge(OWNER_UID));

    let lines = rig.sink.0.lock().unwrap();
    for event in ["fingerprint-verify", "fingerprint-reader-status", "fingerprint-enroll-begin", "fingerprint-enroll ", "purge"] {
        assert!(lines.iter().any(|line| line.contains(event)), "missing {event} in {lines:#?}");
    }
    for forbidden in [MARKER, "PRINT-MARKER", MARKER_STATUS, MARKER_HEX, "9f3a"] {
        assert!(!lines.iter().any(|line| line.contains(forbidden)), "log leaked `{forbidden}`:\n{lines:#?}");
    }
}

const MARKER_STATUS: &str = "verify-9f3a7c11d0e4-marker";
