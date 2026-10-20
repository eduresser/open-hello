use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;

use openhellod::backends::*;
use openhellod::core::{Biometrics, BURST_FRAMES, DEFAULT_TARGET_FAR};
use openhellod::dbus_service::{Action, AuthFuture, Authorizer, Caller, Service, BUS_NAME, OBJECT_PATH};

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

struct Engine;

impl EngineBackend for Engine {
    fn enroll_begin(&mut self, _: u64) -> Result<u64, DaemonError> {
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

    fn verify(&mut self, frames: &[CapturedFrame], template: &[u8], _: f64) -> Result<MatchDecision, DaemonError> {
        assert_eq!(frames.len(), BURST_FRAMES);
        Ok(MatchDecision { live: true, accepted: template == b"secret-template-bytes" })
    }

    fn identify(&mut self, _: &[CapturedFrame], candidates: &[(u32, Vec<u8>)], _: f64) -> Result<IdentifyDecision, DaemonError> {
        Ok(IdentifyDecision { live: true, matched_uid: candidates.first().map(|(uid, _)| *uid) })
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

fn serve(bus: &PrivateBus, authorizer: Arc<dyn Authorizer>) {
    let address = bus.address.clone();
    let core = Biometrics::new(Box::new(Sensor), Box::new(Engine), Box::new(Storage::default()), DEFAULT_TARGET_FAR);
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
