use std::io::{BufRead, BufReader};
use std::process::{Child, Command as Process, Stdio};
use std::sync::Arc;

use openhello_cli::dbus_client::DbusClient;
use openhello_cli::{execute, Answers, Command, KeyClient, Outcome, PinPrompt, Services};
use openhellod::backends::*;
use openhellod::core::{Biometrics, DEFAULT_TARGET_FAR};
use openhellod::fingerprint::{EnrollStep, FingerEnrollError, FingerEnrollState, FingerEnroller, FingerEnrollment, ReaderStatus};
use openhellod::dbus_service::{Action, AuthFuture, Authorizer, Caller, Service, BUS_NAME, OBJECT_PATH};

struct PrivateBus {
    daemon: Child,
    address: String,
}

impl PrivateBus {
    fn start() -> Self {
        let mut daemon = Process::new("dbus-daemon")
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
    captures_needed: u32,
    seen: u32,
    candidates: Vec<(u32, Vec<u8>)>,
}

impl EngineBackend for Engine {
    fn enroll_begin(&mut self, _: u64) -> Result<u64, DaemonError> {
        self.seen = 0;
        Ok(1)
    }

    fn enroll_submit(&mut self, _: u64, _: u64, _: &CapturedFrame) -> Result<EnrollProgress, DaemonError> {
        self.seen += 1;
        let done = self.seen >= self.captures_needed;
        Ok(EnrollProgress {
            verdict: Verdict::Accepted,
            state: if done { EnrollState::Complete } else { EnrollState::InProgress },
            filled: self.seen.min(6),
            required: 6,
        })
    }

    fn enroll_commit(&mut self, _: u64) -> Result<Vec<u8>, DaemonError> {
        Ok(b"tpl".to_vec())
    }

    fn enroll_discard(&mut self, _: u64) -> Result<(), DaemonError> {
        Ok(())
    }

    fn auth_begin(&mut self, candidates: &[(u32, Vec<u8>)], _: f64, _: u32) -> Result<u64, DaemonError> {
        self.candidates = candidates.to_vec();
        Ok(1)
    }

    fn auth_submit(&mut self, _: u64, _: &CapturedFrame) -> Result<AuthProgress, DaemonError> {
        let matched = self.candidates.iter().find(|(_, template)| template.as_slice() == b"tpl").map(|(uid, _)| *uid);
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

fn serve(bus: &PrivateBus) {
    serve_with(bus, None)
}

fn serve_with(bus: &PrivateBus, enroller: Option<Arc<dyn FingerEnroller>>) {
    let address = bus.address.clone();
    let engine = Engine { captures_needed: 8, seen: 0, candidates: Vec::new() };
    let core = Biometrics::new(Box::new(Sensor), Box::new(engine), Box::new(Storage::default()), DEFAULT_TARGET_FAR);
    let mut service = Service::new(core, Arc::new(AllowAll));
    if let Some(enroller) = enroller {
        service = service.with_finger_enroller(enroller);
    }
    let (ready, wait) = std::sync::mpsc::channel();
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
            ready.send(()).unwrap();
            std::future::pending::<()>().await;
        })
    });
    wait.recv_timeout(std::time::Duration::from_secs(10)).expect("service did not start");
}

struct NoKeys;

impl KeyClient for NoKeys {
    fn provision(&mut self, _: u32) -> Result<String, String> {
        Ok("unused".into())
    }

    fn set_pin(&mut self, _: u32, _: &str) -> Result<(), String> {
        Ok(())
    }
}

struct NoPins;

impl PinPrompt for NoPins {
    fn read_secret(&mut self, _: &str) -> Result<String, String> {
        Err("no terminal".into())
    }
}

struct NoAnswers;

impl Answers for NoAnswers {
    fn ask(&mut self, _: &str) -> Result<String, String> {
        Err("no terminal".into())
    }
}

fn run_on(client: &mut DbusClient, command: Command) -> (Outcome, String) {
    let mut out = Vec::new();
    let mut services = Services { biometrics: client, keys: &mut NoKeys, pins: &mut NoPins, answers: &mut NoAnswers };
    let outcome = execute(&mut services, command, &mut out);
    (outcome, String::from_utf8(out).unwrap())
}

#[test]
fn cli_enrolls_verifies_identifies_and_purges_through_the_real_dbus_interface() {
    let bus = PrivateBus::start();
    serve(&bus);
    let mut client = DbusClient::on_address(&bus.address).unwrap();
    let mut run = |command| run_on(&mut client, command);

    let (outcome, output) = run(Command::Enroll { uid: 1000 });
    assert_eq!(outcome, Outcome::Success, "{output}");
    assert!(output.contains("enrolled uid 1000"));
    assert_eq!(run(Command::Verify { uid: 1000 }).0, Outcome::Success);
    assert_eq!(run(Command::Verify { uid: 2000 }).0, Outcome::Rejected);
    assert_eq!(run(Command::Identify).1.trim(), "identified uid 1000");
    assert_eq!(run(Command::Purge { uid: 1000 }).0, Outcome::Success);
    assert_eq!(run(Command::Identify).0, Outcome::Rejected);
}

#[test]
fn cli_reports_a_missing_daemon_as_a_failure() {
    let bus = PrivateBus::start();
    let mut client = DbusClient::on_address(&bus.address).unwrap();
    let (outcome, _) = run_on(&mut client, Command::Verify { uid: 1000 });
    assert!(matches!(outcome, Outcome::Failed(_)), "{outcome:?}");
}

#[derive(Default, Clone)]
struct Reader {
    enrolled: Arc<std::sync::Mutex<Vec<&'static str>>>,
    stopped: Arc<std::sync::atomic::AtomicUsize>,
}

struct ReaderEnrollment {
    reader: Reader,
    finger: &'static str,
    passed: u32,
}

impl FingerEnroller for Reader {
    fn reader_status(&self, _: u32) -> ReaderStatus {
        ReaderStatus { present: true, enrolled: self.enrolled.lock().unwrap().clone() }
    }

    fn begin(&self, _: u32, finger: &str) -> Result<Box<dyn FingerEnrollment>, FingerEnrollError> {
        let finger = openhellod::fingerprint::FINGERS.iter().copied().find(|name| *name == finger).ok_or(FingerEnrollError::UnknownFinger)?;
        if self.enrolled.lock().unwrap().contains(&finger) {
            return Err(FingerEnrollError::AlreadyEnrolled);
        }
        Ok(Box::new(ReaderEnrollment { reader: self.clone(), finger, passed: 0 }))
    }
}

impl FingerEnrollment for ReaderEnrollment {
    fn next_step(&mut self, _: openhellod::core::Cancel) -> EnrollStep {
        self.passed += 1;
        if self.passed < 5 {
            return EnrollStep { status: "stage-passed", state: FingerEnrollState::InProgress, passed: self.passed, total: 5 };
        }
        self.reader.enrolled.lock().unwrap().push(self.finger);
        EnrollStep { status: "completed", state: FingerEnrollState::Completed, passed: 5, total: 5 }
    }

    fn stop(&mut self) {
        self.reader.stopped.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

struct Replies(Vec<&'static str>);

impl Answers for Replies {
    fn ask(&mut self, _: &str) -> Result<String, String> {
        if self.0.is_empty() {
            return Err("no more answers".into());
        }
        Ok(self.0.remove(0).to_string())
    }
}

fn enroll_answering(client: &mut DbusClient, replies: Vec<&'static str>) -> (Outcome, String) {
    let mut out = Vec::new();
    let mut services = Services { biometrics: client, keys: &mut NoKeys, pins: &mut NoPins, answers: &mut Replies(replies) };
    let outcome = execute(&mut services, Command::Enroll { uid: 1000 }, &mut out);
    (outcome, String::from_utf8(out).unwrap())
}

// @spec:AC-055
#[test]
fn cli_enrolls_the_face_then_two_fingers_through_the_real_dbus_interface_keeping_the_first() {
    let bus = PrivateBus::start();
    let reader = Reader::default();
    serve_with(&bus, Some(Arc::new(reader.clone())));
    let mut client = DbusClient::on_address(&bus.address).unwrap();

    let (outcome, output) = enroll_answering(&mut client, vec!["", "", "y", "1", "n"]);
    assert_eq!(outcome, Outcome::Success, "{output}");
    assert!(output.contains("enrolled uid 1000") && output.contains("stage 5 of 5 done") && output.contains("enrolled the right index finger") && output.contains("enrolled the left thumb"), "{output}");
    assert_eq!(*reader.enrolled.lock().unwrap(), vec!["right-index-finger", "left-thumb"]);
    assert_eq!(reader.stopped.load(std::sync::atomic::Ordering::SeqCst), 2);

    let (outcome, output) = enroll_answering(&mut client, vec!["", "2", "n"]);
    assert_eq!(outcome, Outcome::Success, "{output}");
    assert_eq!(*reader.enrolled.lock().unwrap(), vec!["right-index-finger", "left-thumb", "left-index-finger"]);
}

// @spec:AC-057
#[test]
fn cli_without_a_reader_enrolls_the_face_and_says_so_in_one_line_through_the_real_dbus_interface() {
    let bus = PrivateBus::start();
    serve(&bus);
    let mut client = DbusClient::on_address(&bus.address).unwrap();
    let (outcome, output) = enroll_answering(&mut client, vec!["", ""]);
    assert_eq!(outcome, Outcome::Success, "{output}");
    assert!(output.contains("enrolled uid 1000"));
    assert_eq!(output.lines().filter(|line| line.contains("no fingerprint reader was found")).count(), 1, "{output}");
    assert!(!output.contains("Add a fingerprint"));
}
