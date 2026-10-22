#[path = "../../openhello-keyd/tests/support/mod.rs"]
mod support;

use std::io::{BufRead, BufReader};
use std::process::{Child, Command as Process, Stdio};
use std::sync::Arc;

use openhello_cli::keyd_client::KeydClient;
use openhello_cli::{execute, Answers, BiometricsClient, Command, FingerProgress, FingerReader, Outcome, PinPrompt, Progress, Services};
use openhello_keyd::dbus_service::{
    Action, AuthFuture, Authorizer, Caller, Service, BUS_NAME, OBJECT_PATH,
};
use openhello_keyd::{KeydError, Protectors};
use support::rig;

const PIN: &str = "482916";

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
        BufReader::new(daemon.stdout.take().unwrap())
            .read_line(&mut address)
            .unwrap();
        Self {
            daemon,
            address: address.trim().to_string(),
        }
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

struct CompletedEnrollment;

impl BiometricsClient for CompletedEnrollment {
    fn enroll_begin(&mut self, _: u32) -> Result<String, String> {
        Ok("h1".into())
    }

    fn enroll_capture(&mut self, _: &str) -> Result<Progress, String> {
        Ok(Progress {
            verdict: "accepted".into(),
            state: "complete".into(),
            filled: 6,
            required: 6,
        })
    }

    fn enroll_commit(&mut self, _: &str) -> Result<(), String> {
        Ok(())
    }

    fn enroll_discard(&mut self, _: &str) -> Result<(), String> {
        Ok(())
    }

    fn finger_status(&mut self, _: u32) -> Result<FingerReader, String> {
        Ok(FingerReader { present: false, enrolled: Vec::new() })
    }

    fn finger_enroll_begin(&mut self, _: u32, _: &str) -> Result<String, String> {
        Err("no reader".into())
    }

    fn finger_enroll_next(&mut self, _: &str) -> Result<FingerProgress, String> {
        Err("no reader".into())
    }

    fn finger_enroll_discard(&mut self, _: &str) -> Result<(), String> {
        Ok(())
    }

    fn verify(&mut self, _: u32) -> Result<bool, String> {
        Ok(false)
    }

    fn identify(&mut self) -> Result<Option<u32>, String> {
        Ok(None)
    }

    fn purge(&mut self, _: u32) -> Result<(), String> {
        Ok(())
    }
}

struct NoAnswers;

impl Answers for NoAnswers {
    fn ask(&mut self, _: &str) -> Result<String, String> {
        Err("no terminal".into())
    }
}

struct TypedPins(Vec<&'static str>);

impl PinPrompt for TypedPins {
    fn read_secret(&mut self, _: &str) -> Result<String, String> {
        Ok(self.0.remove(0).to_string())
    }
}

fn serve(bus: &PrivateBus, protectors: Arc<Protectors>) {
    let address = bus.address.clone();
    let service = Service::new(protectors, Arc::new(AllowAll));
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
    wait.recv_timeout(std::time::Duration::from_secs(10))
        .expect("service did not start");
}

// @covers:AC-016-cli
// @covers:AC-025-cli
#[test]
fn enroll_provisions_the_real_keyd_and_set_pin_unlocks_with_the_new_pin() {
    let rig = rig();
    let protectors = Arc::new(Protectors::new(rig.config.clone()).unwrap());
    let bus = PrivateBus::start();
    serve(&bus, protectors.clone());
    let mut keys = KeydClient::on_address(&bus.address).unwrap();
    let uid = unsafe { libc::getuid() };
    let mut run = |pins: Vec<&'static str>, command| {
        let mut out = Vec::new();
        let mut biometrics = CompletedEnrollment;
        let mut typed = TypedPins(pins);
        let mut services = Services {
            biometrics: &mut biometrics,
            keys: &mut keys,
            pins: &mut typed,
            answers: &mut NoAnswers,
        };
        let outcome = execute(&mut services, command, &mut out);
        (outcome, String::from_utf8(out).unwrap())
    };

    let (outcome, output) = run(vec![], Command::Enroll { uid });
    assert_eq!(outcome, Outcome::Success, "{output}");
    let code = output.lines().last().unwrap();
    assert_eq!(code.len(), 32);
    assert_eq!(output.matches(code).count(), 1);
    assert!(protectors.unlock_with_recovery(uid, code).is_ok());

    let (mismatch, _) = run(vec![PIN, "000000"], Command::SetPin { uid });
    assert!(matches!(mismatch, Outcome::Failed(_)));
    assert!(matches!(
        protectors.unlock_with_pin(uid, PIN),
        Err(KeydError::PinNotSet)
    ));

    let (outcome, _) = run(vec![PIN, PIN], Command::SetPin { uid });
    assert_eq!(outcome, Outcome::Success);
    assert!(protectors.unlock_with_pin(uid, PIN).is_ok());

    protectors.purge(uid).unwrap();
}

#[test]
fn enroll_reports_a_provision_failure_when_the_keyd_is_not_on_the_bus() {
    let bus = PrivateBus::start();
    let mut keys = KeydClient::on_address(&bus.address).unwrap();
    let mut biometrics = CompletedEnrollment;
    let mut typed = TypedPins(vec![]);
    let mut services = Services {
        biometrics: &mut biometrics,
        keys: &mut keys,
        pins: &mut typed,
        answers: &mut NoAnswers,
    };
    let outcome = execute(
        &mut services,
        Command::Enroll { uid: 1000 },
        &mut Vec::new(),
    );
    assert!(
        matches!(outcome, Outcome::ProvisionFailed(_)),
        "{outcome:?}"
    );
    assert_eq!(outcome.exit_code(), 4);
}

// @covers:AC-016-cli
#[test]
fn provision_command_creates_the_key_for_an_enrolled_user_and_refuses_a_second_run() {
    let rig = rig();
    let protectors = Arc::new(Protectors::new(rig.config.clone()).unwrap());
    let bus = PrivateBus::start();
    serve(&bus, protectors.clone());
    let mut keys = KeydClient::on_address(&bus.address).unwrap();
    let uid = unsafe { libc::getuid() };
    let mut run = || {
        let mut out = Vec::new();
        let mut biometrics = CompletedEnrollment;
        let mut typed = TypedPins(vec![]);
        let mut services = Services {
            biometrics: &mut biometrics,
            keys: &mut keys,
            pins: &mut typed,
            answers: &mut NoAnswers,
        };
        let outcome = execute(&mut services, Command::Provision { uid }, &mut out);
        (outcome, String::from_utf8(out).unwrap())
    };

    let (outcome, output) = run();
    assert_eq!(outcome, Outcome::Success, "{output}");
    let code = output.lines().last().unwrap();
    assert_eq!(code.len(), 32);
    assert!(protectors.unlock_with_recovery(uid, code).is_ok());

    let (again, output) = run();
    assert!(matches!(again, Outcome::ProvisionFailed(_)), "{again:?}");
    assert!(!output.contains(code));

    protectors.purge(uid).unwrap();
}
