use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use openhellod::backends::*;
use openhellod::core::{Biometrics, DEFAULT_TARGET_FAR};
use openhellod::dbus_service::{Action, AuthFuture, Authorizer, Caller, Service, BUS_NAME, OBJECT_PATH};
use openhellod::fingerprint::{FprintdBus, FprintdEnroller};
use openhellod::logging::{Level, LogSink, Logger};
use openhellod::polkit::{PolkitAuthorizer, PolkitClient, PolkitFuture};
use zbus::object_server::SignalEmitter;
use zbus::zvariant::OwnedObjectPath;
use zbus::{interface, Connection, DBusError};

const DEVICE_PATH: &str = "/net/reactivated/Fprint/Device/0";
const OWNER_NAME: &str = "owner";
const INDEX: &str = "right-index-finger";
const THUMB: &str = "left-thumb";

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
}

type Script = Vec<(u64, &'static str, bool)>;

#[derive(Default)]
struct Fake {
    no_device: bool,
    script: Mutex<Script>,
    enrolled: Mutex<Vec<String>>,
    claims: Mutex<Vec<String>>,
    enroll_starts: Mutex<Vec<String>>,
    stops: AtomicUsize,
    releases: AtomicUsize,
    stopped: std::sync::atomic::AtomicBool,
    connection: Mutex<Option<Connection>>,
}

struct Manager(Arc<Fake>);
struct Device(Arc<Fake>);

#[interface(name = "net.reactivated.Fprint.Manager")]
impl Manager {
    async fn get_default_device(&self) -> Result<OwnedObjectPath, FprintError> {
        if self.0.no_device {
            return Err(FprintError::NoSuchDevice("no devices".into()));
        }
        Ok(OwnedObjectPath::try_from(DEVICE_PATH).unwrap())
    }
}

#[interface(name = "net.reactivated.Fprint.Device")]
impl Device {
    #[zbus(property, name = "num-enroll-stages")]
    async fn num_enroll_stages(&self) -> i32 {
        5
    }

    async fn claim(&self, username: String) {
        self.0.claims.lock().unwrap().push(username);
    }

    async fn release(&self) {
        self.0.releases.fetch_add(1, Ordering::SeqCst);
    }

    async fn list_enrolled_fingers(&self, _username: String) -> Result<Vec<String>, FprintError> {
        let enrolled = self.0.enrolled.lock().unwrap().clone();
        if enrolled.is_empty() {
            return Err(FprintError::NoEnrolledPrints("none".into()));
        }
        Ok(enrolled)
    }

    async fn enroll_start(&self, finger: String) {
        self.0.enroll_starts.lock().unwrap().push(finger.clone());
        self.0.enrolled.lock().unwrap().retain(|enrolled| *enrolled != finger);
        self.0.stopped.store(false, Ordering::SeqCst);
        let fake = self.0.clone();
        let script = fake.script.lock().unwrap().clone();
        std::thread::spawn(move || {
            for (delay_ms, status, done) in script {
                std::thread::sleep(Duration::from_millis(delay_ms));
                if fake.stopped.load(Ordering::SeqCst) {
                    return;
                }
                if status == "enroll-completed" {
                    fake.enrolled.lock().unwrap().push(finger.clone());
                }
                let connection = fake.connection.lock().unwrap().clone().unwrap();
                async_io::block_on(async {
                    let iface = connection.object_server().interface::<_, Device>(DEVICE_PATH).await.unwrap();
                    Device::enroll_status(iface.signal_emitter(), status, done).await.unwrap();
                });
            }
        });
    }

    async fn enroll_stop(&self) {
        self.0.stops.fetch_add(1, Ordering::SeqCst);
        self.0.stopped.store(true, Ordering::SeqCst);
    }

    #[zbus(signal)]
    async fn enroll_status(emitter: &SignalEmitter<'_>, result: &str, done: bool) -> zbus::Result<()>;
}

#[derive(Default)]
struct CaptureSink(Mutex<Vec<String>>);

impl LogSink for CaptureSink {
    fn write_line(&self, line: &str) {
        self.0.lock().unwrap().push(line.to_string());
    }
}

struct AllowAll;

impl Authorizer for AllowAll {
    fn authorize<'a>(&'a self, _: Action, _: &'a Caller, _: u32) -> AuthFuture<'a> {
        Box::pin(async { Ok(()) })
    }
}

struct DenyAll;

impl Authorizer for DenyAll {
    fn authorize<'a>(&'a self, _: Action, _: &'a Caller, _: u32) -> AuthFuture<'a> {
        Box::pin(async { Err("denied by test".to_string()) })
    }
}

struct ScriptedPolkit {
    authorized: bool,
    asked: Mutex<Vec<String>>,
}

impl PolkitClient for ScriptedPolkit {
    fn is_authorized<'a>(&'a self, action_id: &'a str, _: &'a str) -> PolkitFuture<'a> {
        self.asked.lock().unwrap().push(action_id.to_string());
        let answer = self.authorized;
        Box::pin(async move { Ok(answer) })
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
        unreachable!()
    }

    fn auth_end(&mut self, _: u64) -> Result<(), DaemonError> {
        Ok(())
    }
}

struct Storage;

impl StorageBackend for Storage {
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
}

fn my_uid() -> u32 {
    std::fs::metadata("/proc/self").map(|m| std::os::unix::fs::MetadataExt::uid(&m)).unwrap()
}

struct Rig {
    openhello: PrivateBus,
    _fprint: PrivateBus,
    fake: Arc<Fake>,
    sink: Arc<CaptureSink>,
    _fprintd: Connection,
}

fn rig_with(fake: Fake, authorizer: Arc<dyn Authorizer>, with_enroller: bool) -> Rig {
    let fprint = PrivateBus::start();
    let fake = Arc::new(fake);
    let fprintd = async_io::block_on(async {
        zbus::connection::Builder::address(fprint.address.as_str())
            .unwrap()
            .name("net.reactivated.Fprint")
            .unwrap()
            .serve_at("/net/reactivated/Fprint/Manager", Manager(fake.clone()))
            .unwrap()
            .serve_at(DEVICE_PATH, Device(fake.clone()))
            .unwrap()
            .build()
            .await
            .unwrap()
    });
    *fake.connection.lock().unwrap() = Some(fprintd.clone());
    let sink = Arc::new(CaptureSink::default());
    let uid = my_uid();
    let enroller = FprintdEnroller::with_user_names(
        FprintdBus::Address(fprint.address.clone()),
        Logger::new(Level::Debug, sink.clone()),
        Box::new(move |asked| (asked == uid).then(|| OWNER_NAME.to_string())),
    );
    let core = Biometrics::new(Box::new(Sensor), Box::new(Engine), Box::new(Storage), DEFAULT_TARGET_FAR);
    let mut service = Service::new(core, authorizer);
    if with_enroller {
        service = service.with_finger_enroller(Arc::new(enroller));
    }
    let openhello = PrivateBus::start();
    serve(&openhello, service);
    Rig { openhello, _fprint: fprint, fake, sink, _fprintd: fprintd }
}

fn serve(bus: &PrivateBus, service: Service) {
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
    ready_rx.recv_timeout(Duration::from_secs(10)).expect("service did not start");
}

fn rig(script: Script, enrolled: &[&str]) -> Rig {
    let fake = Fake { script: Mutex::new(script), enrolled: Mutex::new(enrolled.iter().map(|f| f.to_string()).collect()), ..Fake::default() };
    rig_with(fake, Arc::new(AllowAll), true)
}

fn client(rig: &Rig) -> zbus::blocking::Connection {
    zbus::blocking::connection::Builder::address(rig.openhello.address.as_str()).unwrap().build().unwrap()
}

fn proxy(conn: &zbus::blocking::Connection) -> zbus::blocking::Proxy<'_> {
    zbus::blocking::Proxy::new(conn, BUS_NAME, OBJECT_PATH, "io.openhello.Biometrics1").unwrap()
}

type Step = (String, String, u32, u32);

fn next(proxy: &zbus::blocking::Proxy<'_>, handle: &str) -> Step {
    proxy.call("FingerEnrollNext", &(handle,)).unwrap()
}

fn step(status: &str, state: &str, passed: u32) -> Step {
    (status.to_string(), state.to_string(), passed, 5)
}

fn wait_until(what: &str, condition: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(8);
    while !condition() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn five_stages() -> Script {
    vec![
        (10, "enroll-stage-passed", false),
        (10, "enroll-stage-passed", false),
        (10, "enroll-stage-passed", false),
        (10, "enroll-stage-passed", false),
        (10, "enroll-completed", true),
    ]
}

fn enrolled(fake: &Fake) -> Vec<String> {
    let mut fingers = fake.enrolled.lock().unwrap().clone();
    fingers.sort();
    fingers
}

fn assert_stopped_and_released_once(fake: &Fake) {
    assert_eq!(fake.stops.load(Ordering::SeqCst), 1, "EnrollStop must be called exactly once");
    assert_eq!(fake.releases.load(Ordering::SeqCst), 1, "Release must be called exactly once");
}

fn assert_fprintd_never_touched(fake: &Fake) {
    assert!(fake.enroll_starts.lock().unwrap().is_empty());
    assert!(fake.claims.lock().unwrap().is_empty());
}

// @spec:AC-055
#[test]
fn five_stages_are_reported_and_the_finger_is_stored_for_the_claimed_user() {
    let rig = rig(five_stages(), &[]);
    let conn = client(&rig);
    let proxy = proxy(&conn);

    assert_eq!(proxy.call::<_, _, (bool, String)>("FingerStatus", &(my_uid(),)).unwrap(), (true, String::new()));
    let handle: String = proxy.call("FingerEnrollBegin", &(my_uid(), INDEX)).unwrap();
    let steps: Vec<Step> = (0..5).map(|_| next(&proxy, &handle)).collect();
    assert_eq!(
        steps,
        vec![
            step("stage-passed", "in-progress", 1),
            step("stage-passed", "in-progress", 2),
            step("stage-passed", "in-progress", 3),
            step("stage-passed", "in-progress", 4),
            step("completed", "complete", 5),
        ]
    );
    assert_eq!(enrolled(&rig.fake), vec![INDEX.to_string()]);
    assert_eq!(*rig.fake.claims.lock().unwrap(), vec![OWNER_NAME.to_string()]);
    assert_eq!(*rig.fake.enroll_starts.lock().unwrap(), vec![INDEX.to_string()]);
    assert_stopped_and_released_once(&rig.fake);
    assert_eq!(proxy.call::<_, _, (bool, String)>("FingerStatus", &(my_uid(),)).unwrap(), (true, INDEX.to_string()));
    assert!(proxy.call::<_, _, Step>("FingerEnrollNext", &(handle.as_str(),)).is_err());
}

// @spec:AC-055
#[test]
fn several_fingers_accumulate_one_at_a_time_and_earlier_ones_stay() {
    let rig = rig(five_stages(), &[THUMB]);
    let conn = client(&rig);
    let proxy = proxy(&conn);
    for finger in [INDEX, "left-ring-finger"] {
        let handle: String = proxy.call("FingerEnrollBegin", &(my_uid(), finger)).unwrap();
        let last = (0..5).map(|_| next(&proxy, &handle)).collect::<Vec<_>>().pop().unwrap();
        assert_eq!(last.1, "complete", "{finger}");
    }
    let mut expected = vec![THUMB.to_string(), INDEX.to_string(), "left-ring-finger".to_string()];
    expected.sort();
    assert_eq!(enrolled(&rig.fake), expected);
    let (present, listed): (bool, String) = proxy.call("FingerStatus", &(my_uid(),)).unwrap();
    assert!(present);
    let mut listed: Vec<&str> = listed.split(',').collect();
    listed.sort();
    assert_eq!(listed, expected);
    assert_eq!(rig.fake.stops.load(Ordering::SeqCst), 2);
    assert_eq!(rig.fake.releases.load(Ordering::SeqCst), 2);
}

// @spec:AC-055
#[test]
fn retry_statuses_do_not_advance_the_stages_and_failures_end_the_enrollment() {
    let rig = rig(
        vec![
            (10, "enroll-stage-passed", false),
            (10, "enroll-retry-scan", false),
            (10, "enroll-swipe-too-short", false),
            (10, "enroll-finger-not-centered", false),
            (10, "enroll-remove-and-retry", false),
            (10, "enroll-failed", true),
        ],
        &[THUMB],
    );
    let conn = client(&rig);
    let proxy = proxy(&conn);
    let handle: String = proxy.call("FingerEnrollBegin", &(my_uid(), INDEX)).unwrap();
    let steps: Vec<Step> = (0..6).map(|_| next(&proxy, &handle)).collect();
    assert_eq!(
        steps,
        vec![
            step("stage-passed", "in-progress", 1),
            step("retry-scan", "in-progress", 1),
            step("swipe-too-short", "in-progress", 1),
            step("finger-not-centered", "in-progress", 1),
            step("remove-and-retry", "in-progress", 1),
            step("failed", "failed", 1),
        ]
    );
    assert_eq!(enrolled(&rig.fake), vec![THUMB.to_string()]);
    assert_stopped_and_released_once(&rig.fake);
}

// @spec:AC-055
#[test]
fn reader_errors_end_the_enrollment_as_a_failure_never_as_a_success() {
    for (status, label) in [
        ("enroll-data-full", "data-full"),
        ("enroll-disconnected", "disconnected"),
        ("enroll-unknown-error", "unknown-error"),
        ("something-new", "unknown-error"),
    ] {
        let rig = rig(vec![(10, status, true)], &[]);
        let conn = client(&rig);
        let proxy = proxy(&conn);
        let handle: String = proxy.call("FingerEnrollBegin", &(my_uid(), INDEX)).unwrap();
        assert_eq!(next(&proxy, &handle), step(label, "failed", 0), "{status}");
        assert!(enrolled(&rig.fake).is_empty());
        assert_stopped_and_released_once(&rig.fake);
    }
}

// @spec:AC-055
#[test]
fn an_unauthorized_caller_is_refused_and_no_enrollment_reaches_the_reader() {
    let fake = Fake { script: Mutex::new(five_stages()), ..Fake::default() };
    let rig = rig_with(fake, Arc::new(DenyAll), true);
    let conn = client(&rig);
    let proxy = proxy(&conn);
    let error = proxy.call::<_, _, String>("FingerEnrollBegin", &(my_uid(), INDEX)).unwrap_err().to_string();
    assert!(error.contains("io.openhello.biometrics.finger-enroll-begin"), "{error}");
    assert!(proxy.call::<_, _, (bool, String)>("FingerStatus", &(my_uid(),)).is_err());
    assert_fprintd_never_touched(&rig.fake);
    assert_eq!(rig.fake.releases.load(Ordering::SeqCst), 0);
}

// @spec:AC-055
#[test]
fn polkit_denial_and_another_users_target_both_refuse_the_enrollment() {
    let polkit = Arc::new(ScriptedPolkit { authorized: false, asked: Mutex::new(vec![]) });
    let fake = Fake { script: Mutex::new(five_stages()), ..Fake::default() };
    let rig = rig_with(fake, Arc::new(PolkitAuthorizer::new(polkit.clone())), true);
    let conn = client(&rig);
    let proxy = proxy(&conn);
    assert!(proxy.call::<_, _, String>("FingerEnrollBegin", &(my_uid(), INDEX)).is_err());
    assert_eq!(*polkit.asked.lock().unwrap(), vec!["io.openhello.biometrics.finger-enroll-begin"]);

    let other = my_uid() + 1;
    let before = polkit.asked.lock().unwrap().len();
    assert!(proxy.call::<_, _, String>("FingerEnrollBegin", &(other, INDEX)).is_err());
    assert!(proxy.call::<_, _, (bool, String)>("FingerStatus", &(other,)).is_err());
    assert_eq!(polkit.asked.lock().unwrap().len(), before, "polkit must not be consulted for another user's data");
    assert_fprintd_never_touched(&rig.fake);
}

// @spec:AC-055
#[test]
fn each_enrollment_call_asks_polkit_for_its_own_action() {
    let polkit = Arc::new(ScriptedPolkit { authorized: true, asked: Mutex::new(vec![]) });
    let fake = Fake { script: Mutex::new(vec![(5000, "enroll-completed", true)]), ..Fake::default() };
    let rig = rig_with(fake, Arc::new(PolkitAuthorizer::new(polkit.clone())), true);
    let conn = client(&rig);
    let proxy = proxy(&conn);
    let handle: String = proxy.call("FingerEnrollBegin", &(my_uid(), INDEX)).unwrap();
    assert_eq!(*polkit.asked.lock().unwrap(), vec!["io.openhello.biometrics.finger-enroll-begin"]);
    proxy.call::<_, _, ()>("FingerEnrollDiscard", &(handle.as_str(),)).unwrap();
    assert_eq!(
        *polkit.asked.lock().unwrap(),
        vec!["io.openhello.biometrics.finger-enroll-begin", "io.openhello.biometrics.finger-enroll-discard"]
    );
    assert_stopped_and_released_once(&rig.fake);
}

// @spec:AC-056
#[test]
fn an_already_enrolled_finger_is_refused_before_the_reader_is_touched() {
    let rig = rig(five_stages(), &[THUMB, INDEX]);
    let conn = client(&rig);
    let proxy = proxy(&conn);
    let error = proxy.call::<_, _, String>("FingerEnrollBegin", &(my_uid(), THUMB)).unwrap_err().to_string();
    assert!(error.contains("already enrolled"), "{error}");
    assert!(rig.fake.enroll_starts.lock().unwrap().is_empty());
    assert!(rig.fake.claims.lock().unwrap().is_empty());
    let mut both = vec![THUMB.to_string(), INDEX.to_string()];
    both.sort();
    assert_eq!(enrolled(&rig.fake), both);
}

// @spec:AC-056
#[test]
fn an_unknown_finger_name_is_refused_before_the_reader_is_touched() {
    let rig = rig(five_stages(), &[]);
    let conn = client(&rig);
    let proxy = proxy(&conn);
    for name in ["", "any", "left-toe", "RIGHT-THUMB"] {
        let error = proxy.call::<_, _, String>("FingerEnrollBegin", &(my_uid(), name)).unwrap_err().to_string();
        assert!(error.contains("not one of the ten fingers"), "{name}: {error}");
    }
    assert_fprintd_never_touched(&rig.fake);
}

// @spec:AC-056
#[test]
fn an_owner_that_leaves_mid_enrollment_stops_the_reader_once_and_an_existing_finger_survives() {
    let rig = rig(vec![(10, "enroll-stage-passed", false)], &[THUMB]);
    let owner = client(&rig);
    let handle: String = proxy(&owner).call("FingerEnrollBegin", &(my_uid(), INDEX)).unwrap();
    assert_eq!(next(&proxy(&owner), &handle), step("stage-passed", "in-progress", 1));
    let left_at = Instant::now();
    drop(owner);
    wait_until("the abandoned enrollment to be stopped", || rig.fake.stops.load(Ordering::SeqCst) == 1 && rig.fake.releases.load(Ordering::SeqCst) == 1);
    assert!(left_at.elapsed() < Duration::from_secs(1), "took {:?}", left_at.elapsed());
    std::thread::sleep(Duration::from_millis(500));
    assert_stopped_and_released_once(&rig.fake);
    assert_eq!(enrolled(&rig.fake), vec![THUMB.to_string()]);

    let other = client(&rig);
    let error = proxy(&other).call::<_, _, Step>("FingerEnrollNext", &(handle.as_str(),)).unwrap_err().to_string();
    assert!(error.contains("not valid in the current state"), "{error}");
    assert!(rig.sink.0.lock().unwrap().iter().any(|line| line.contains("fingerprint-enroll uid=") && line.contains("outcome=cancelled")));
}

// @spec:AC-056
#[test]
fn an_owner_killed_while_the_daemon_waits_for_the_next_stage_is_stopped_within_a_second() {
    let rig = rig(vec![(60_000, "enroll-completed", true)], &[THUMB]);
    let owner = client(&rig);
    let handle: String = proxy(&owner).call("FingerEnrollBegin", &(my_uid(), INDEX)).unwrap();
    let mut waiting = Command::new("dbus-send")
        .args([
            &format!("--bus={}", rig.openhello.address),
            "--print-reply",
            &format!("--dest={BUS_NAME}"),
            OBJECT_PATH,
            "io.openhello.Biometrics1.FingerEnrollNext",
            &format!("string:{handle}"),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("dbus-send must be installed");
    std::thread::sleep(Duration::from_millis(400));
    assert_eq!(rig.fake.stops.load(Ordering::SeqCst), 0);
    drop(owner);
    let left_at = Instant::now();
    wait_until("the enrollment to be stopped", || rig.fake.stops.load(Ordering::SeqCst) == 1);
    assert!(left_at.elapsed() < Duration::from_secs(1), "took {:?}", left_at.elapsed());
    waiting.kill().unwrap();
    waiting.wait().unwrap();
    std::thread::sleep(Duration::from_millis(500));
    assert_stopped_and_released_once(&rig.fake);
    assert_eq!(enrolled(&rig.fake), vec![THUMB.to_string()]);
}

// @spec:AC-056
#[test]
fn a_discarded_or_finished_enrollment_is_not_stopped_again_when_its_owner_leaves() {
    let rig = rig(five_stages(), &[]);
    let owner = client(&rig);
    let handle: String = proxy(&owner).call("FingerEnrollBegin", &(my_uid(), INDEX)).unwrap();
    proxy(&owner).call::<_, _, ()>("FingerEnrollDiscard", &(handle.as_str(),)).unwrap();
    assert_stopped_and_released_once(&rig.fake);
    assert!(proxy(&owner).call::<_, _, ()>("FingerEnrollDiscard", &(handle.as_str(),)).is_err());
    drop(owner);
    std::thread::sleep(Duration::from_millis(500));
    assert_stopped_and_released_once(&rig.fake);

    let finishing = client(&rig);
    let handle: String = proxy(&finishing).call("FingerEnrollBegin", &(my_uid(), INDEX)).unwrap();
    for _ in 0..5 {
        next(&proxy(&finishing), &handle);
    }
    assert_eq!(rig.fake.stops.load(Ordering::SeqCst), 2);
    drop(finishing);
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(rig.fake.stops.load(Ordering::SeqCst), 2);
    assert_eq!(rig.fake.releases.load(Ordering::SeqCst), 2);
}

// @spec:AC-057
#[test]
fn a_machine_without_a_reader_reports_none_and_refuses_to_start_an_enrollment() {
    let fake = Fake { no_device: true, ..Fake::default() };
    let rig = rig_with(fake, Arc::new(AllowAll), true);
    let conn = client(&rig);
    let proxy = proxy(&conn);
    assert_eq!(proxy.call::<_, _, (bool, String)>("FingerStatus", &(my_uid(),)).unwrap(), (false, String::new()));
    let error = proxy.call::<_, _, String>("FingerEnrollBegin", &(my_uid(), INDEX)).unwrap_err().to_string();
    assert!(error.contains("no fingerprint reader was found"), "{error}");
    assert_fprintd_never_touched(&rig.fake);
}

// @spec:AC-057
#[test]
fn a_daemon_without_a_fingerprint_backend_reports_no_reader() {
    let rig = rig_with(Fake::default(), Arc::new(AllowAll), false);
    let conn = client(&rig);
    let proxy = proxy(&conn);
    assert_eq!(proxy.call::<_, _, (bool, String)>("FingerStatus", &(my_uid(),)).unwrap(), (false, String::new()));
    let error = proxy.call::<_, _, String>("FingerEnrollBegin", &(my_uid(), INDEX)).unwrap_err().to_string();
    assert!(error.contains("no fingerprint reader was found"), "{error}");
}

// @spec:AC-057
#[test]
fn an_absent_fprintd_reports_no_reader() {
    let fprint = PrivateBus::start();
    let enroller = FprintdEnroller::with_user_names(
        FprintdBus::Address(fprint.address.clone()),
        Logger::new(Level::Debug, Arc::new(CaptureSink::default())),
        Box::new(|_| Some(OWNER_NAME.to_string())),
    );
    let core = Biometrics::new(Box::new(Sensor), Box::new(Engine), Box::new(Storage), DEFAULT_TARGET_FAR);
    let service = Service::new(core, Arc::new(AllowAll)).with_finger_enroller(Arc::new(enroller));
    let openhello = PrivateBus::start();
    serve(&openhello, service);
    let conn = zbus::blocking::connection::Builder::address(openhello.address.as_str()).unwrap().build().unwrap();
    let started = Instant::now();
    assert_eq!(proxy(&conn).call::<_, _, (bool, String)>("FingerStatus", &(my_uid(),)).unwrap(), (false, String::new()));
    assert!(started.elapsed() < Duration::from_secs(4), "took {:?}", started.elapsed());
}

// @principle:P-010
#[test]
fn enrollment_logs_carry_only_uid_labels_and_counts() {
    let rig = rig(
        vec![(10, "enroll-retry-scan", false), (10, "enroll-stage-passed", false), (10, "enroll-failed", true)],
        &[],
    );
    let conn = client(&rig);
    let proxy = proxy(&conn);
    let handle: String = proxy.call("FingerEnrollBegin", &(my_uid(), INDEX)).unwrap();
    for _ in 0..3 {
        next(&proxy, &handle);
    }
    let uid = my_uid();
    let lines = rig.sink.0.lock().unwrap().clone();
    assert_eq!(
        lines,
        vec![
            format!("openhellod INFO fingerprint-enroll-begin uid={uid} outcome=started"),
            format!("openhellod INFO fingerprint-enroll uid={uid} outcome=failed stages=1 retries=1"),
        ]
    );
    assert!(lines.iter().all(|line| !line.contains(OWNER_NAME) && !line.contains(INDEX)));
}
