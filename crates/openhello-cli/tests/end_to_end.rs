use std::io::{BufRead, BufReader};
use std::process::{Child, Command as Process, Stdio};
use std::sync::Arc;

use openhello_cli::dbus_client::DbusClient;
use openhello_cli::{execute, Command, Outcome};
use openhellod::backends::*;
use openhellod::core::{Biometrics, DEFAULT_TARGET_FAR};
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
    let address = bus.address.clone();
    let engine = Engine { captures_needed: 8, seen: 0, candidates: Vec::new() };
    let core = Biometrics::new(Box::new(Sensor), Box::new(engine), Box::new(Storage::default()), DEFAULT_TARGET_FAR);
    let service = Service::new(core, Arc::new(AllowAll));
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

#[test]
fn cli_enrolls_verifies_identifies_and_purges_through_the_real_dbus_interface() {
    let bus = PrivateBus::start();
    serve(&bus);
    let mut client = DbusClient::on_address(&bus.address).unwrap();
    let mut run = |command| {
        let mut out = Vec::new();
        let outcome = execute(&mut client, command, &mut out);
        (outcome, String::from_utf8(out).unwrap())
    };

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
    let outcome = execute(&mut client, Command::Verify { uid: 1000 }, &mut Vec::new());
    assert!(matches!(outcome, Outcome::Failed(_)), "{outcome:?}");
}
