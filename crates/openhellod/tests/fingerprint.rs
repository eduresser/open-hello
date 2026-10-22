use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use openhellod::fingerprint::*;
use openhellod::logging::{Level, LogSink, Logger};
use zbus::object_server::SignalEmitter;
use zbus::zvariant::OwnedObjectPath;
use zbus::{interface, Connection, DBusError};

const DEVICE_PATH: &str = "/net/reactivated/Fprint/Device/0";
const OWNER_UID: u32 = 1000;
const OWNER_NAME: &str = "owner";

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
struct Behaviour {
    no_device: bool,
    claim_denied: bool,
    no_enrolled: bool,
    script: Vec<(u64, &'static str, bool)>,
}

#[derive(Default)]
struct Fake {
    behaviour: Mutex<Behaviour>,
    claims: Mutex<Vec<String>>,
    finger_args: Mutex<Vec<String>>,
    starts: AtomicUsize,
    stops: AtomicUsize,
    releases: AtomicUsize,
    stopped: AtomicBool,
    connection: Mutex<Option<Connection>>,
}

struct Manager(Arc<Fake>);
struct Device(Arc<Fake>);

#[interface(name = "net.reactivated.Fprint.Manager")]
impl Manager {
    async fn get_default_device(&self) -> Result<OwnedObjectPath, FprintError> {
        if self.0.behaviour.lock().unwrap().no_device {
            return Err(FprintError::NoSuchDevice("no devices".into()));
        }
        Ok(OwnedObjectPath::try_from(DEVICE_PATH).unwrap())
    }
}

#[interface(name = "net.reactivated.Fprint.Device")]
impl Device {
    async fn claim(&self, username: String) -> Result<(), FprintError> {
        if self.0.behaviour.lock().unwrap().claim_denied {
            return Err(FprintError::PermissionDenied("denied".into()));
        }
        self.0.claims.lock().unwrap().push(username);
        Ok(())
    }

    async fn release(&self) {
        self.0.releases.fetch_add(1, Ordering::SeqCst);
    }

    async fn verify_start(&self, finger: String) -> Result<(), FprintError> {
        self.0.finger_args.lock().unwrap().push(finger);
        if self.0.behaviour.lock().unwrap().no_enrolled {
            return Err(FprintError::NoEnrolledPrints("none".into()));
        }
        self.0.starts.fetch_add(1, Ordering::SeqCst);
        self.0.stopped.store(false, Ordering::SeqCst);
        let fake = self.0.clone();
        let script = fake.behaviour.lock().unwrap().script.clone();
        std::thread::spawn(move || {
            for (delay_ms, status, done) in script {
                std::thread::sleep(Duration::from_millis(delay_ms));
                if fake.stopped.load(Ordering::SeqCst) {
                    return;
                }
                let connection = fake.connection.lock().unwrap().clone().unwrap();
                async_io::block_on(async {
                    let iface = connection.object_server().interface::<_, Device>(DEVICE_PATH).await.unwrap();
                    Device::verify_status(iface.signal_emitter(), status, done).await.unwrap();
                });
            }
        });
        Ok(())
    }

    async fn verify_stop(&self) {
        self.0.stops.fetch_add(1, Ordering::SeqCst);
        self.0.stopped.store(true, Ordering::SeqCst);
    }

    #[zbus(signal)]
    async fn verify_status(emitter: &SignalEmitter<'_>, result: &str, done: bool) -> zbus::Result<()>;
}

struct Rig {
    _bus: PrivateBus,
    fake: Arc<Fake>,
    matcher: FprintdMatcher,
    sink: Arc<CaptureSink>,
    _connection: Connection,
}

#[derive(Default)]
struct CaptureSink(Mutex<Vec<String>>);

impl LogSink for CaptureSink {
    fn write_line(&self, line: &str) {
        self.0.lock().unwrap().push(line.to_string());
    }
}

fn matcher_for(address: &str, sink: &Arc<CaptureSink>) -> FprintdMatcher {
    FprintdMatcher::with_user_names(
        FprintdBus::Address(address.to_string()),
        Logger::new(Level::Debug, sink.clone()),
        Box::new(|uid| (uid == OWNER_UID).then(|| OWNER_NAME.to_string())),
    )
}

fn rig(behaviour: Behaviour) -> Rig {
    let bus = PrivateBus::start();
    let fake = Arc::new(Fake::default());
    *fake.behaviour.lock().unwrap() = behaviour;
    let connection = async_io::block_on(async {
        zbus::connection::Builder::address(bus.address.as_str())
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
    *fake.connection.lock().unwrap() = Some(connection.clone());
    let sink = Arc::new(CaptureSink::default());
    let matcher = matcher_for(&bus.address, &sink);
    Rig { _bus: bus, fake, matcher, sink, _connection: connection }
}

fn scripted(script: Vec<(u64, &'static str, bool)>) -> Behaviour {
    Behaviour { script, ..Behaviour::default() }
}

fn never() -> bool {
    false
}

fn assert_released_once(fake: &Fake) {
    assert_eq!(fake.releases.load(Ordering::SeqCst), 1, "Release must be called exactly once");
}

fn assert_clean_exit(fake: &Fake) {
    assert_eq!(fake.stops.load(Ordering::SeqCst), 1, "VerifyStop must be called exactly once");
    assert_released_once(fake);
}

// @spec:AC-048
#[test]
fn a_match_from_the_reader_is_reported_for_the_claimed_user() {
    let mut rig = rig(scripted(vec![(20, "verify-match", true)]));
    assert_eq!(rig.matcher.verify(OWNER_UID, &never), FingerprintResult::Match);
    assert_eq!(*rig.fake.claims.lock().unwrap(), vec![OWNER_NAME.to_string()]);
    assert_eq!(*rig.fake.finger_args.lock().unwrap(), vec!["any".to_string()]);
    assert_clean_exit(&rig.fake);
    let lines = rig.sink.0.lock().unwrap().join("\n");
    assert!(lines.contains("fingerprint-verify uid=1000 outcome=match retries=0"), "{lines}");
}

// @spec:AC-048
#[test]
fn an_unknown_uid_is_never_claimed_and_ends_the_fingerprint_side() {
    let mut rig = rig(scripted(vec![(20, "verify-match", true)]));
    assert_eq!(rig.matcher.verify(4242, &never), FingerprintResult::Unavailable(Unavailability::Unknown));
    assert!(rig.fake.claims.lock().unwrap().is_empty());
    assert_eq!(rig.fake.starts.load(Ordering::SeqCst), 0);
}

// @spec:AC-048
#[test]
fn a_retry_status_is_not_an_attempt_and_the_wait_continues_to_a_match() {
    let mut rig = rig(scripted(vec![
        (10, "verify-swipe-too-short", false),
        (10, "verify-remove-and-retry", false),
        (10, "verify-retry-scan", false),
        (10, "verify-finger-not-centered", false),
        (10, "verify-match", true),
    ]));
    assert_eq!(rig.matcher.verify(OWNER_UID, &never), FingerprintResult::Match);
    assert_clean_exit(&rig.fake);
    let lines = rig.sink.0.lock().unwrap().join("\n");
    assert!(lines.contains("outcome=match retries=4"), "{lines}");
}

// @spec:AC-049
#[test]
fn three_no_match_results_are_three_attempts_and_then_a_refusal() {
    let mut rig = rig(scripted(vec![(10, "verify-no-match", true)]));
    let decision = verify_default_attempts(&mut rig.matcher, OWNER_UID, &never);
    assert_eq!(decision, FingerprintDecision::Refused);
    assert_eq!(rig.fake.starts.load(Ordering::SeqCst), 3);
    assert_eq!(rig.fake.stops.load(Ordering::SeqCst), 3);
    assert_eq!(rig.fake.releases.load(Ordering::SeqCst), 3);
}

// @spec:AC-049
#[test]
fn one_no_match_is_reported_as_an_attempt_not_as_a_match() {
    let mut rig = rig(scripted(vec![(10, "verify-no-match", true)]));
    assert_eq!(rig.matcher.verify(OWNER_UID, &never), FingerprintResult::NoMatch);
    assert_clean_exit(&rig.fake);
}

// @spec:AC-049
#[test]
fn a_match_on_the_third_attempt_is_accepted_and_stops_the_count() {
    struct Sequence(Vec<FingerprintResult>, usize);
    impl FingerprintMatcher for Sequence {
        fn verify(&mut self, _: u32, _: openhellod::core::Cancel) -> FingerprintResult {
            self.1 += 1;
            self.0.remove(0)
        }
    }
    let mut sequence = Sequence(
        vec![FingerprintResult::NoMatch, FingerprintResult::NoMatch, FingerprintResult::Match, FingerprintResult::NoMatch],
        0,
    );
    assert_eq!(verify_default_attempts(&mut sequence, OWNER_UID, &never), FingerprintDecision::Matched);
    assert_eq!(sequence.1, 3);
}

// @spec:AC-049
#[test]
fn zero_allowed_attempts_refuse_without_touching_the_reader() {
    struct AlwaysMatch;
    impl FingerprintMatcher for AlwaysMatch {
        fn verify(&mut self, _: u32, _: openhellod::core::Cancel) -> FingerprintResult {
            FingerprintResult::Match
        }
    }
    assert_eq!(verify_with_attempts(&mut AlwaysMatch, OWNER_UID, 0, &never), FingerprintDecision::Refused);
}

// @spec:AC-049
#[test]
fn attempts_stop_at_cancellation_and_at_infrastructure_errors() {
    struct Fixed(FingerprintResult);
    impl FingerprintMatcher for Fixed {
        fn verify(&mut self, _: u32, _: openhellod::core::Cancel) -> FingerprintResult {
            self.0
        }
    }
    assert_eq!(
        verify_default_attempts(&mut Fixed(FingerprintResult::Cancelled), OWNER_UID, &never),
        FingerprintDecision::Cancelled
    );
    assert_eq!(
        verify_default_attempts(&mut Fixed(FingerprintResult::Unavailable(Unavailability::Disconnected)), OWNER_UID, &never),
        FingerprintDecision::Unavailable(Unavailability::Disconnected)
    );
}

// @spec:AC-050
#[test]
fn an_absent_fprintd_ends_the_fingerprint_side_quickly() {
    let bus = PrivateBus::start();
    let sink = Arc::new(CaptureSink::default());
    let mut matcher = matcher_for(&bus.address, &sink);
    let started = Instant::now();
    assert_eq!(matcher.verify(OWNER_UID, &never), FingerprintResult::Unavailable(Unavailability::ServiceAbsent));
    assert!(started.elapsed() < Duration::from_secs(2), "took {:?}", started.elapsed());
}

// @spec:AC-050
#[test]
fn an_unreachable_bus_ends_the_fingerprint_side_quickly() {
    let sink = Arc::new(CaptureSink::default());
    let mut matcher = matcher_for("unix:path=/nonexistent/openhello-fprint-bus", &sink);
    let started = Instant::now();
    assert_eq!(matcher.verify(OWNER_UID, &never), FingerprintResult::Unavailable(Unavailability::ServiceAbsent));
    assert!(started.elapsed() < Duration::from_secs(2));
}

// @spec:AC-050
#[test]
fn a_missing_reader_ends_the_fingerprint_side_quickly() {
    let mut rig = rig(Behaviour { no_device: true, ..Behaviour::default() });
    let started = Instant::now();
    assert_eq!(rig.matcher.verify(OWNER_UID, &never), FingerprintResult::Unavailable(Unavailability::NoDevice));
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(rig.fake.releases.load(Ordering::SeqCst), 0);
}

// @spec:AC-050
#[test]
fn a_user_without_an_enrolled_finger_ends_the_fingerprint_side_and_releases_the_reader() {
    let mut rig = rig(Behaviour { no_enrolled: true, ..Behaviour::default() });
    let started = Instant::now();
    assert_eq!(rig.matcher.verify(OWNER_UID, &never), FingerprintResult::Unavailable(Unavailability::NoEnrolledFinger));
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(rig.fake.stops.load(Ordering::SeqCst), 0);
    assert_released_once(&rig.fake);
}

// @spec:AC-050
#[test]
fn a_refused_claim_ends_the_fingerprint_side_without_starting_a_scan() {
    let mut rig = rig(Behaviour { claim_denied: true, ..Behaviour::default() });
    assert_eq!(rig.matcher.verify(OWNER_UID, &never), FingerprintResult::Unavailable(Unavailability::Unknown));
    assert_eq!(rig.fake.starts.load(Ordering::SeqCst), 0);
    assert_eq!(rig.fake.releases.load(Ordering::SeqCst), 0);
}

// @spec:AC-051
#[test]
fn reader_errors_and_disconnects_are_never_a_match() {
    for (status, expected) in [
        ("verify-disconnected", Unavailability::Disconnected),
        ("verify-unknown-error", Unavailability::Unknown),
        ("something-new", Unavailability::Unknown),
    ] {
        let mut rig = rig(scripted(vec![(10, status, true)]));
        assert_eq!(rig.matcher.verify(OWNER_UID, &never), FingerprintResult::Unavailable(expected), "{status}");
        assert_clean_exit(&rig.fake);
    }
}

// @spec:AC-051
#[test]
fn retries_alone_never_produce_a_match() {
    let mut rig = rig(scripted(vec![(10, "verify-retry-scan", false), (10, "verify-swipe-too-short", false)]));
    let polls = AtomicUsize::new(0);
    let cancel_after_a_while = || polls.fetch_add(1, Ordering::SeqCst) > 12;
    assert_eq!(rig.matcher.verify(OWNER_UID, &cancel_after_a_while), FingerprintResult::Cancelled);
    assert_clean_exit(&rig.fake);
}

// @spec:AC-051
#[test]
fn a_match_arriving_after_cancellation_is_not_reported() {
    let mut rig = rig(scripted(vec![(400, "verify-match", true)]));
    let began = Instant::now();
    let cancel_at_100ms = || began.elapsed() > Duration::from_millis(100);
    assert_eq!(rig.matcher.verify(OWNER_UID, &cancel_at_100ms), FingerprintResult::Cancelled);
    assert_clean_exit(&rig.fake);
    std::thread::sleep(Duration::from_millis(600));
    assert_clean_exit(&rig.fake);
}

// @spec:AC-051
#[test]
fn a_match_that_lands_together_with_cancellation_is_not_reported() {
    let mut rig = rig(scripted(vec![(150, "verify-match", true)]));
    let began = Instant::now();
    let cancel_at_140ms = || began.elapsed() > Duration::from_millis(140);
    assert_eq!(rig.matcher.verify(OWNER_UID, &cancel_at_140ms), FingerprintResult::Cancelled);
    assert_clean_exit(&rig.fake);
}

// @spec:AC-051
#[test]
fn cancellation_is_prompt_and_releases_the_reader() {
    let mut rig = rig(scripted(vec![]));
    let began = Instant::now();
    let cancel_at_100ms = || began.elapsed() > Duration::from_millis(100);
    assert_eq!(rig.matcher.verify(OWNER_UID, &cancel_at_100ms), FingerprintResult::Cancelled);
    assert!(began.elapsed() < Duration::from_secs(1));
    assert_clean_exit(&rig.fake);
}

// @spec:AC-051
#[test]
fn logs_carry_only_uid_outcome_and_counts() {
    let mut rig = rig(scripted(vec![(10, "verify-no-match", true)]));
    rig.matcher.verify(OWNER_UID, &never);
    let lines = rig.sink.0.lock().unwrap().clone();
    assert_eq!(lines, vec!["openhellod INFO fingerprint-verify uid=1000 outcome=no-match retries=0"]);
}
