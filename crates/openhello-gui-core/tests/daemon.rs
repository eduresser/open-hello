#[path = "../../openhello-keyd/tests/support/mod.rs"]
mod support;

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;

use openhello_gui_core::{ClientErrorKind, DaemonClient, EnrollClient, ManageClient, Manager, RemoveOutcome, TestOutcome};
use openhellod::backends::*;
use openhellod::core::{Biometrics, DEFAULT_TARGET_FAR};
use openhellod::dbus_service as face;
use openhello_keyd::dbus_service as keyd;
use openhello_keyd::Protectors;
use support::rig;

const PIXELS: [u8; 6] = [10, 20, 30, 40, 50, 60];

struct PrivateBus {
    daemon: Child,
    address: String,
}

impl PrivateBus {
    fn start() -> Self {
        let mut daemon = Command::new("dbus-daemon").args(["--session", "--nofork", "--print-address=1"]).stdout(Stdio::piped()).spawn().expect("dbus-daemon must be installed");
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

struct AllowFace;

impl face::Authorizer for AllowFace {
    fn authorize<'a>(&'a self, _: face::Action, _: &'a face::Caller, _: u32) -> face::AuthFuture<'a> {
        Box::pin(async { Ok(()) })
    }
}

struct AllowKeys;

impl keyd::Authorizer for AllowKeys {
    fn authorize<'a>(&'a self, _: keyd::Action, _: &'a keyd::Caller, _: u32) -> keyd::AuthFuture<'a> {
        Box::pin(async { Ok(()) })
    }
}

struct Sensor {
    busy: bool,
}

impl SensorBackend for Sensor {
    fn capture(&mut self) -> Result<CapturedFrame, DaemonError> {
        if self.busy {
            return Err(DaemonError::CameraBusy("held by another process".into()));
        }
        Ok(CapturedFrame { width: 3, height: 2, pixels: PIXELS.to_vec() })
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

    fn enroll_submit(&mut self, _: u64, _: u64, _: &CapturedFrame) -> Result<EnrollProgress, DaemonError> {
        Ok(EnrollProgress { verdict: Verdict::Accepted, state: EnrollState::Complete, filled: 6, required: 6 })
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
        let matched = self.candidates.first().map(|(uid, _)| *uid);
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

fn serve(bus: &PrivateBus, busy: bool, protectors: Arc<Protectors>) {
    let address = bus.address.clone();
    let core = Biometrics::new(Box::new(Sensor { busy }), Box::new(Engine::default()), Box::new(Storage::default()), DEFAULT_TARGET_FAR);
    let faces = face::Service::new(core, Arc::new(AllowFace));
    let keys = keyd::Service::new(protectors, Arc::new(AllowKeys));
    let (ready, wait) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        async_io::block_on(async move {
            let _connection = zbus::connection::Builder::address(address.as_str())
                .unwrap()
                .name(face::BUS_NAME)
                .unwrap()
                .name(keyd::BUS_NAME)
                .unwrap()
                .serve_at(face::OBJECT_PATH, faces)
                .unwrap()
                .serve_at(keyd::OBJECT_PATH, keys)
                .unwrap()
                .build()
                .await
                .unwrap();
            ready.send(()).unwrap();
            std::future::pending::<()>().await;
        })
    });
    wait.recv_timeout(std::time::Duration::from_secs(10)).expect("services did not start");
}

fn my_uid() -> u32 {
    unsafe { libc::getuid() }
}

// @spec:AC-058
#[test]
fn the_real_client_enrolls_over_dbus_and_reads_the_preview_and_the_combined_status() {
    let rig = rig();
    let protectors = Arc::new(Protectors::new(rig.config.clone()).unwrap());
    let bus = PrivateBus::start();
    serve(&bus, false, protectors.clone());
    let mut client = DaemonClient::on_address(&bus.address).unwrap();
    let uid = my_uid();

    let fresh = EnrollClient::status(&mut client, uid).unwrap();
    assert!(!fresh.face && !fresh.key);

    let handle = client.enroll_begin(uid).unwrap();
    let progress = client.enroll_capture(&handle).unwrap();
    assert_eq!((progress.verdict.as_str(), progress.state.as_str(), progress.filled, progress.required), ("accepted", "complete", 6, 6));
    let frame = client.enroll_frame(&handle).unwrap();
    assert_eq!((frame.width, frame.height, frame.pixels.as_slice()), (3, 2, PIXELS.as_slice()));
    client.enroll_commit(&handle).unwrap();

    let code = client.provision(uid).unwrap();
    assert_eq!(code.len(), 32);
    let ready = EnrollClient::status(&mut client, uid).unwrap();
    assert!(ready.face && ready.key);
    protectors.purge(uid).unwrap();
}

// @spec:AC-061
#[test]
fn a_busy_camera_reaches_the_real_client_as_a_typed_camera_busy_error() {
    let rig = rig();
    let bus = PrivateBus::start();
    serve(&bus, true, Arc::new(Protectors::new(rig.config.clone()).unwrap()));
    let mut client = DaemonClient::on_address(&bus.address).unwrap();
    let uid = my_uid();

    let handle = client.enroll_begin(uid).unwrap();
    let error = client.enroll_capture(&handle).unwrap_err();
    assert_eq!(error.kind, ClientErrorKind::CameraBusy);
    assert!(!error.message.contains("held by another process"), "{}", error.message);
    client.enroll_discard(&handle).unwrap();
}

// @spec:AC-066
#[test]
fn the_real_client_tests_the_face_and_removes_it_after_confirmation() {
    let rig = rig();
    let bus = PrivateBus::start();
    serve(&bus, false, Arc::new(Protectors::new(rig.config.clone()).unwrap()));
    let uid = my_uid();
    let mut enroller = DaemonClient::on_address(&bus.address).unwrap();
    let handle = enroller.enroll_begin(uid).unwrap();
    enroller.enroll_capture(&handle).unwrap();
    enroller.enroll_commit(&handle).unwrap();

    let mut manager = Manager::new(DaemonClient::on_address(&bus.address).unwrap(), uid);
    assert!(manager.status().unwrap().face);
    assert_eq!(manager.test(), TestOutcome::Recognized);
    assert_eq!(manager.remove(false), RemoveOutcome::NotConfirmed);
    assert!(manager.status().unwrap().face);
    match manager.remove(true) {
        RemoveOutcome::Removed(status) => assert!(!status.face),
        other => panic!("expected Removed, got {other:?}"),
    }
    assert_eq!(ManageClient::verify(&mut enroller, uid).unwrap(), false);
}
