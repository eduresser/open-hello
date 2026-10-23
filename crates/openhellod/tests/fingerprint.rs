use std::collections::BTreeMap;
use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};

use openhellod::backends::*;
use openhellod::core::{Biometrics, DEFAULT_TARGET_FAR};
use openhellod::fingerprint::{FprintdBus, FprintdReader};
use zbus::zvariant::OwnedObjectPath;
use zbus::{interface, Connection};

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

type Calls = Arc<Mutex<Vec<&'static str>>>;

struct Manager(Calls);
struct Device(Calls);

#[interface(name = "net.reactivated.Fprint.Manager")]
impl Manager {
    async fn get_default_device(&self) -> OwnedObjectPath {
        self.0.lock().unwrap().push("GetDefaultDevice");
        OwnedObjectPath::try_from(DEVICE_PATH).unwrap()
    }
}

#[interface(name = "net.reactivated.Fprint.Device")]
impl Device {
    async fn claim(&self, _username: String) {
        self.0.lock().unwrap().push("Claim");
    }

    async fn release(&self) {
        self.0.lock().unwrap().push("Release");
    }

    async fn list_enrolled_fingers(&self, _username: String) -> Vec<String> {
        self.0.lock().unwrap().push("ListEnrolledFingers");
        vec!["right-index-finger".to_string()]
    }

    async fn verify_start(&self, _finger: String) {
        self.0.lock().unwrap().push("VerifyStart");
    }

    async fn verify_stop(&self) {
        self.0.lock().unwrap().push("VerifyStop");
    }

    async fn enroll_start(&self, _finger: String) {
        self.0.lock().unwrap().push("EnrollStart");
    }

    async fn enroll_stop(&self) {
        self.0.lock().unwrap().push("EnrollStop");
    }

    async fn delete_enrolled_fingers2(&self) {
        self.0.lock().unwrap().push("DeleteEnrolledFingers2");
    }
}

struct Sensor;

impl SensorBackend for Sensor {
    fn capture(&mut self) -> Result<CapturedFrame, DaemonError> {
        Ok(CapturedFrame { width: 1, height: 1, pixels: vec![0] })
    }
}

struct Engine {
    verdict: AuthVerdict,
}

impl EngineBackend for Engine {
    fn enroll_begin(&mut self, _: u64) -> Result<u64, DaemonError> {
        unreachable!()
    }

    fn enroll_submit(&mut self, _: u64, _: u64, _: &CapturedFrame) -> Result<EnrollProgress, DaemonError> {
        unreachable!()
    }

    fn enroll_commit(&mut self, _: u64) -> Result<Vec<u8>, DaemonError> {
        unreachable!()
    }

    fn enroll_discard(&mut self, _: u64) -> Result<(), DaemonError> {
        unreachable!()
    }

    fn auth_begin(&mut self, _: &[(u32, Vec<u8>)], _: f64, _: u32) -> Result<u64, DaemonError> {
        Ok(1)
    }

    fn auth_submit(&mut self, _: u64, _: &CapturedFrame) -> Result<AuthProgress, DaemonError> {
        Ok(AuthProgress { verdict: self.verdict, scored_frames: 1 })
    }

    fn auth_end(&mut self, _: u64) -> Result<(), DaemonError> {
        Ok(())
    }
}

#[derive(Default)]
struct Storage(BTreeMap<u32, Vec<u8>>);

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

struct Rig {
    _bus: PrivateBus,
    _fprintd: Connection,
    calls: Calls,
    core: Biometrics,
}

fn rig(verdict: AuthVerdict) -> Rig {
    let bus = PrivateBus::start();
    let calls = Calls::default();
    let fprintd = async_io::block_on(async {
        zbus::connection::Builder::address(bus.address.as_str())
            .unwrap()
            .name("net.reactivated.Fprint")
            .unwrap()
            .serve_at("/net/reactivated/Fprint/Manager", Manager(calls.clone()))
            .unwrap()
            .serve_at(DEVICE_PATH, Device(calls.clone()))
            .unwrap()
            .build()
            .await
            .unwrap()
    });
    let reader = FprintdReader::with_user_names(
        FprintdBus::Address(bus.address.clone()),
        Box::new(|uid| (uid == OWNER_UID).then(|| OWNER_NAME.to_string())),
    );
    let storage = Storage(BTreeMap::from([(OWNER_UID, b"face-template".to_vec())]));
    let core = Biometrics::new(Box::new(Sensor), Box::new(Engine { verdict }), Box::new(storage), DEFAULT_TARGET_FAR)
        .with_fingerprint_reader(Some(Box::new(reader)));
    Rig { _bus: bus, _fprintd: fprintd, calls, core }
}

// @spec:AC-062
#[test]
fn an_accepted_face_verify_makes_no_call_to_fprintd() {
    let mut rig = rig(AuthVerdict::Accepted(OWNER_UID));
    assert!(rig.core.verify(OWNER_UID).unwrap());
    assert_eq!(*rig.calls.lock().unwrap(), Vec::<&str>::new());
}

// @spec:AC-062
#[test]
fn a_rejected_face_verify_makes_no_call_to_fprintd_and_stays_rejected() {
    let mut rig = rig(AuthVerdict::Rejected);
    assert!(!rig.core.verify(OWNER_UID).unwrap());
    assert_eq!(*rig.calls.lock().unwrap(), Vec::<&str>::new());
}
