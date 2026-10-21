mod support;

use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};

use openhello_keyd::dbus_service::{
    Action, AuthFuture, Authorizer, Caller, Service, BUS_NAME, OBJECT_PATH,
};
use openhello_keyd::polkit::{PolkitAuthorizer, PolkitClient, PolkitFuture};
use openhello_keyd::{KeydError, Protectors, Secret};
use openhello_ticket::Issuer;
use support::{rig, Rig};

const PIN: &str = "482916";
const DIGEST: [u8; 32] = [0x3c; 32];

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
            .expect("dbus-daemon must be installed to run keyd tests");
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

struct ScriptedPolkit {
    asked: Mutex<Vec<String>>,
}

impl PolkitClient for ScriptedPolkit {
    fn is_authorized<'a>(&'a self, action_id: &'a str, _: &'a str) -> PolkitFuture<'a> {
        self.asked.lock().unwrap().push(action_id.to_string());
        Box::pin(async { Ok(true) })
    }
}

struct AllowAll;

impl Authorizer for AllowAll {
    fn authorize<'a>(&'a self, _: Action, _: &'a Caller, _: u32) -> AuthFuture<'a> {
        Box::pin(async { Ok(()) })
    }
}

fn serve(bus: &PrivateBus, protectors: Arc<Protectors>, authorizer: Arc<dyn Authorizer>) {
    let address = bus.address.clone();
    let service = Service::new(protectors, authorizer);
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
    ready_rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("service did not start");
}

fn client(bus: &PrivateBus) -> zbus::blocking::Connection {
    zbus::blocking::connection::Builder::address(bus.address.as_str())
        .unwrap()
        .build()
        .unwrap()
}

fn proxy(conn: &zbus::blocking::Connection) -> zbus::blocking::Proxy<'_> {
    zbus::blocking::Proxy::new(conn, BUS_NAME, OBJECT_PATH, "io.openhello.Keyd1").unwrap()
}

fn my_uid() -> u32 {
    unsafe { libc::getuid() }
}

fn protectors(rig: &Rig) -> Arc<Protectors> {
    Arc::new(Protectors::new(rig.config.clone()).unwrap())
}

fn blobs(rig: &Rig, uid: u32) -> Vec<(String, Vec<u8>)> {
    let dir = rig
        .config
        .store_dir
        .join("protectors")
        .join(uid.to_string());
    let mut found: Vec<_> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| {
            (
                e.file_name().to_string_lossy().into_owned(),
                std::fs::read(e.path()).unwrap(),
            )
        })
        .collect();
    found.sort();
    found
}

fn restore(rig: &Rig, uid: u32, copy: &[(String, Vec<u8>)]) {
    let dir = rig
        .config
        .store_dir
        .join("protectors")
        .join(uid.to_string());
    std::fs::create_dir_all(&dir).unwrap();
    for (name, bytes) in copy {
        std::fs::write(dir.join(name), bytes).unwrap();
    }
}

fn transient_handles(rig: &Rig) -> String {
    let out = rig.tpm2("tpm2_getcap", &["handles-transient"]);
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn persistent_handles(rig: &Rig) -> String {
    let out = rig.tpm2("tpm2_getcap", &["handles-persistent"]);
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn ticket_for(protectors: &Protectors, uid: u32) -> Vec<u8> {
    Issuer::new(protectors.ticket_key())
        .issue(uid)
        .unwrap()
        .encode()
        .to_vec()
}

fn assert_refused(error: zbus::Error, action: &str) {
    let text = error.to_string();
    assert!(text.contains("AuthFailed"), "{text}");
    assert!(text.contains(action), "{text}");
    assert!(text.contains("may not act"), "{text}");
}

// @spec:AC-034
#[test]
fn a_caller_that_is_not_the_target_user_cannot_provision_set_a_pin_or_purge() {
    let rig = rig();
    let protectors = protectors(&rig);
    let polkit = Arc::new(ScriptedPolkit {
        asked: Default::default(),
    });
    let bus = PrivateBus::start();
    serve(
        &bus,
        protectors.clone(),
        Arc::new(PolkitAuthorizer::new(polkit.clone())),
    );
    let conn = client(&bus);
    let proxy = proxy(&conn);

    let victim = my_uid() + 1;
    let error = proxy
        .call::<_, _, String>("Provision", &(victim,))
        .unwrap_err();
    assert_refused(error, "io.openhello.keyd.provision");
    assert!(matches!(
        protectors.keyd().key(victim),
        Err(KeydError::NotProvisioned)
    ));
    assert!(blobs(&rig, victim).is_empty());

    protectors.provision_protectors(victim).unwrap();
    let key_before = protectors.keyd().key(victim).unwrap();
    let blobs_before = blobs(&rig, victim);
    assert_eq!(blobs_before.len(), 2);

    let error = proxy
        .call::<_, _, bool>("SetPin", &(victim, PIN))
        .unwrap_err();
    assert_refused(error, "io.openhello.keyd.set-pin");
    assert!(matches!(
        protectors.unlock_with_pin(victim, PIN),
        Err(KeydError::PinNotSet)
    ));

    let error = proxy.call::<_, _, bool>("Purge", &(victim,)).unwrap_err();
    assert_refused(error, "io.openhello.keyd.purge");

    assert_eq!(protectors.keyd().key(victim).unwrap(), key_before);
    assert_eq!(blobs(&rig, victim), blobs_before);
    assert!(protectors
        .unlock_with_ticket(victim, &ticket_for(&protectors, victim))
        .is_ok());
    assert!(polkit.asked.lock().unwrap().is_empty());
    protectors.purge(victim).unwrap();
}

// @spec:AC-034
#[test]
fn the_target_user_provisions_sets_a_pin_and_purges_through_polkit() {
    let rig = rig();
    let protectors = protectors(&rig);
    let polkit = Arc::new(ScriptedPolkit {
        asked: Default::default(),
    });
    let bus = PrivateBus::start();
    serve(
        &bus,
        protectors.clone(),
        Arc::new(PolkitAuthorizer::new(polkit.clone())),
    );
    let conn = client(&bus);
    let proxy = proxy(&conn);
    let uid = my_uid();

    let code: String = proxy.call("Provision", &(uid,)).unwrap();
    assert_eq!(code.len(), 32);
    assert!(proxy.call::<_, _, bool>("SetPin", &(uid, PIN)).unwrap());
    let secret = protectors.unlock_with_pin(uid, PIN).unwrap();
    assert!(protectors.keyd().sign_digest(uid, &secret, &DIGEST).is_ok());
    assert!(protectors.unlock_with_recovery(uid, &code).is_ok());

    assert!(proxy.call::<_, _, bool>("Purge", &(uid,)).unwrap());
    assert!(matches!(
        protectors.keyd().key(uid),
        Err(KeydError::NotProvisioned)
    ));
    assert_eq!(
        *polkit.asked.lock().unwrap(),
        [
            "io.openhello.keyd.provision",
            "io.openhello.keyd.set-pin",
            "io.openhello.keyd.purge"
        ]
    );
}

#[test]
fn bad_input_is_reported_without_echoing_the_pin() {
    let rig = rig();
    let protectors = protectors(&rig);
    let bus = PrivateBus::start();
    serve(&bus, protectors.clone(), Arc::new(AllowAll));
    let conn = client(&bus);
    let proxy = proxy(&conn);
    let uid = my_uid() + 2;

    proxy.call::<_, _, String>("Provision", &(uid,)).unwrap();
    let error = proxy
        .call::<_, _, bool>("SetPin", &(uid, "123"))
        .unwrap_err()
        .to_string();
    assert!(error.contains("PIN must be"), "{error}");
    assert!(
        !error.contains("123456") && !error.contains("\"123\""),
        "{error}"
    );
    let error = proxy
        .call::<_, _, String>("Provision", &(uid,))
        .unwrap_err()
        .to_string();
    assert!(error.contains("already has a key"), "{error}");
    protectors.purge(uid).unwrap();
}

// @principle:P-008
#[test]
fn purge_destroys_the_key_and_makes_a_saved_copy_of_the_protectors_useless() {
    let rig = rig();
    let protectors = protectors(&rig);
    let uid = 3101;

    let persistent_before = persistent_handles(&rig);
    let code = protectors
        .provision_protectors(uid)
        .unwrap()
        .reveal()
        .to_string();
    protectors.set_pin(uid, PIN).unwrap();
    let saved = blobs(&rig, uid);
    assert_eq!(saved.len(), 3);
    let key_secret: Secret = protectors.unlock_with_pin(uid, PIN).unwrap();
    assert!(protectors
        .keyd()
        .sign_digest(uid, &key_secret, &DIGEST)
        .is_ok());
    assert_eq!(rig.listed_classes(&format!("openhello-{uid}")).len(), 3);
    let transient_before = transient_handles(&rig);

    protectors.purge(uid).unwrap();

    assert!(blobs(&rig, uid).is_empty());
    assert!(!Path::new(
        &rig.config
            .store_dir
            .join("protectors")
            .join(uid.to_string())
    )
    .exists());
    assert!(matches!(
        protectors.keyd().key(uid),
        Err(KeydError::NotProvisioned)
    ));
    assert!(matches!(
        protectors.keyd().sign_digest(uid, &key_secret, &DIGEST),
        Err(KeydError::NotProvisioned)
    ));
    assert!(matches!(
        protectors.unlock_with_pin(uid, PIN),
        Err(KeydError::NotProvisioned)
    ));
    assert!(matches!(
        protectors.unlock_with_recovery(uid, &code),
        Err(KeydError::NotProvisioned)
    ));
    assert!(protectors
        .unlock_with_ticket(uid, &ticket_for(&protectors, uid))
        .is_err());
    assert_eq!(transient_handles(&rig), transient_before);
    assert_eq!(persistent_handles(&rig), persistent_before);

    restore(&rig, uid, &saved);
    let revived = protectors.unlock_with_pin(uid, PIN).unwrap();
    assert!(matches!(
        protectors.keyd().key(uid),
        Err(KeydError::NotProvisioned)
    ));
    assert!(matches!(
        protectors.keyd().sign_digest(uid, &revived, &DIGEST),
        Err(KeydError::NotProvisioned)
    ));
    assert!(matches!(
        protectors.keyd().verify_protection(uid, &revived),
        Err(KeydError::NotProvisioned)
    ));
    protectors.purge(uid).unwrap();
}

#[test]
fn purge_is_idempotent_and_leaves_other_users_untouched() {
    let rig = rig();
    let protectors = protectors(&rig);
    let (gone, kept) = (3102, 3103);

    protectors.purge(gone).unwrap();
    protectors.provision_protectors(gone).unwrap();
    protectors.provision_protectors(kept).unwrap();
    let kept_key = protectors.keyd().key(kept).unwrap();
    protectors.purge(gone).unwrap();
    protectors.purge(gone).unwrap();

    assert!(matches!(
        protectors.keyd().key(gone),
        Err(KeydError::NotProvisioned)
    ));
    assert_eq!(protectors.keyd().key(kept).unwrap(), kept_key);
    assert!(protectors
        .unlock_with_ticket(kept, &ticket_for(&protectors, kept))
        .is_ok());
    protectors.purge(kept).unwrap();
}
