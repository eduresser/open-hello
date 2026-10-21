mod support;

use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use openhello_keyd::{
    Keyd, KeydError, Protectors, Secret, UnlockSocket, UnlockSocketConfig, OP_UNLOCK_FOR_UID,
    OP_UNLOCK_PIN, STATUS_ACCEPTED,
};
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature, VerifyingKey};
use support::{rig, Rig};

const SECRET: &str = "6f1d0c5a9e3b7d2480ac1f5e6b9d3a7c21e4f08b";
const PIN: &str = "482913";
const WRONG_PIN: &str = "000000";
const DIGEST: [u8; 32] = [0x3c; 32];
const SPKI_P256_PREFIX_LEN: usize = 26;

fn secret() -> Secret {
    Secret::new(SECRET).unwrap()
}

fn mapfile_lines(rig: &Rig) -> Vec<String> {
    std::fs::read_to_string(&rig.config.mapfile)
        .unwrap_or_default()
        .lines()
        .map(str::to_string)
        .collect()
}

fn lines_of(rig: &Rig, uid: u32) -> Vec<String> {
    let prefix = format!("CN=openhello-uid-{uid} ");
    let mut lines = mapfile_lines(rig);
    lines.retain(|l| l.starts_with(&prefix));
    lines
}

fn openssl(args: &[&str], stdin: &[u8]) -> Vec<u8> {
    let mut child = Command::new("openssl")
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("openssl must be installed to run the certificate tests");
    child.stdin.take().unwrap().write_all(stdin).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "openssl {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

fn pem_of(der: &[u8]) -> Vec<u8> {
    openssl(&["x509", "-inform", "DER", "-outform", "PEM"], der)
}

fn certificate_point(der: &[u8]) -> Vec<u8> {
    let spki = openssl(&["x509", "-inform", "DER", "-noout", "-pubkey"], der);
    let spki_der = openssl(&["pkey", "-pubin", "-pubout", "-outform", "DER"], &spki);
    spki_der[SPKI_P256_PREFIX_LEN..].to_vec()
}

fn verifies(point: &[u8], signature: &[u8]) -> bool {
    let key = VerifyingKey::from_sec1_bytes(point).expect("P-256 point");
    let signature = Signature::from_slice(signature).expect("raw r||s");
    key.verify_prehash(&DIGEST, &signature).is_ok()
}

// @spec:AC-016
#[test]
fn provisioning_leaves_one_key_and_one_certificate_for_that_key_and_one_mapping_line() {
    let rig = rig();
    let keyd = Keyd::new(rig.config.clone());
    let key = keyd.provision(3001, &secret()).unwrap().key;

    let mut classes = rig.listed_classes("openhello-3001");
    classes.sort();
    assert_eq!(
        classes,
        ["CKO_CERTIFICATE", "CKO_PRIVATE_KEY", "CKO_PUBLIC_KEY"]
    );
    let certificate = keyd.certificate(3001).unwrap();
    assert_eq!(certificate_point(&certificate), key.public_key);

    assert_eq!(
        lines_of(&rig, 3001),
        ["CN=openhello-uid-3001 -> user3001".to_string()]
    );
    let meta = std::fs::metadata(&rig.config.mapfile).unwrap();
    assert_eq!(meta.mode() & 0o7777, 0o644);
    assert_eq!(meta.uid(), unsafe { libc::geteuid() });

    let again = keyd.provision(3001, &secret()).unwrap();
    assert!(!again.created);
    assert_eq!(keyd.certificate(3001).unwrap(), certificate);
    assert_eq!(lines_of(&rig, 3001).len(), 1);
    assert_eq!(rig.listed_classes("openhello-3001").len(), 3);
}

#[test]
fn the_token_signature_verifies_against_the_issued_certificate() {
    let rig = rig();
    let keyd = Keyd::new(rig.config.clone());
    keyd.provision(3002, &secret()).unwrap();
    let certificate = keyd.certificate(3002).unwrap();

    let signature = keyd.sign_digest(3002, &secret(), &DIGEST).unwrap();
    assert!(verifies(&certificate_point(&certificate), &signature));

    let dir = tempfile::tempdir().unwrap();
    let pem = dir.path().join("cert.pem");
    std::fs::write(&pem, pem_of(&certificate)).unwrap();
    let pem = pem.to_str().unwrap();
    openssl(&["verify", "-CAfile", pem, pem], &[]);
    let text = String::from_utf8(openssl(&["x509", "-in", pem, "-noout", "-text"], &[])).unwrap();
    assert!(text.contains("Subject: CN=openhello-uid-3002"), "{text}");
    assert!(text.contains("ecdsa-with-SHA256"), "{text}");
}

#[test]
fn a_certificate_of_another_key_with_the_same_subject_does_not_match_the_token_key() {
    let rig = rig();
    let keyd = Keyd::new(rig.config.clone());
    let key = keyd.provision(3003, &secret()).unwrap().key;
    let issued = keyd.certificate(3003).unwrap();

    let forged_pem = openssl(
        &[
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-keyout",
            "/dev/null",
            "-subj",
            "/CN=openhello-uid-3003",
        ],
        &[],
    );
    let forged = openssl(&["x509", "-outform", "DER"], &forged_pem);
    let forged_subject = openssl(&["x509", "-noout", "-subject"], &forged_pem);
    assert!(String::from_utf8_lossy(&forged_subject).contains("openhello-uid-3003"));

    assert_ne!(forged, issued);
    assert_ne!(certificate_point(&forged), key.public_key);
    let signature = keyd.sign_digest(3003, &secret(), &DIGEST).unwrap();
    assert!(!verifies(&certificate_point(&forged), &signature));
    assert!(verifies(&certificate_point(&issued), &signature));
    assert_eq!(lines_of(&rig, 3003).len(), 1);
}

// @spec:AC-033
#[test]
fn purge_removes_the_certificate_and_only_its_own_mapping_line() {
    let rig = rig();
    let protectors = Protectors::new(rig.config.clone()).unwrap();
    protectors.provision_protectors(3004).unwrap();
    protectors.provision_protectors(3005).unwrap();
    assert!(mapfile_lines(&rig)
        .iter()
        .any(|l| l.starts_with("CN=openhello-uid-3004 ")));

    protectors.purge(3004).unwrap();

    assert!(matches!(
        protectors.keyd().certificate(3004),
        Err(KeydError::NotProvisioned)
    ));
    let lines = mapfile_lines(&rig);
    assert!(!lines.iter().any(|l| l.contains("openhello-uid-3004")));
    assert!(lines.iter().any(|l| l.contains("openhello-uid-3005")));
    assert!(protectors.keyd().certificate(3005).is_ok());
}

fn certutil(rig: &Rig, database: &Path, args: &[&str]) -> std::process::Output {
    Command::new(rig.prefix.join("usr/bin/certutil"))
        .args(["-d", &format!("sql:{}", database.display())])
        .args(args)
        .env("LD_LIBRARY_PATH", rig.prefix.join("usr/lib64"))
        .output()
        .expect("certutil from the prefix must run (mozilla-nss-tools)")
}

fn protectors_config(rig: &Rig, database: &Path) -> openhello_keyd::KeydConfig {
    let mut config = rig.config.clone();
    config.nss_dir = Some(database.to_path_buf());
    config
}

#[test]
fn provisioning_trusts_the_certificate_in_a_readable_nss_database_and_purge_removes_it() {
    let rig = rig();
    let dir = tempfile::tempdir().unwrap();
    let database = dir.path().join("nssdb");
    let protectors = Protectors::new(protectors_config(&rig, &database)).unwrap();
    protectors.provision_protectors(3008).unwrap();
    protectors.provision_protectors(3009).unwrap();

    let listing =
        |database: &Path| String::from_utf8(certutil(&rig, database, &["-L"]).stdout).unwrap();
    let line = |text: &str, uid: u32| {
        text.lines()
            .find(|l| l.starts_with(&format!("openhello-uid-{uid}")))
            .map(str::to_string)
    };
    let text = listing(&database);
    assert!(
        line(&text, 3008).is_some_and(|l| l.trim_end().ends_with("CT,C,C")),
        "{text}"
    );
    assert!(line(&text, 3009).is_some(), "{text}");

    let trusted = certutil(&rig, &database, &["-L", "-n", "openhello-uid-3008", "-a"]);
    let issued = pem_of(&protectors.keyd().certificate(3008).unwrap());
    let body = |pem: &[u8]| {
        String::from_utf8_lossy(pem)
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect::<String>()
    };
    assert_eq!(body(&trusted.stdout), body(&issued));
    assert_eq!(std::fs::metadata(&database).unwrap().mode() & 0o7777, 0o755);
    for entry in std::fs::read_dir(&database).unwrap().flatten() {
        assert_eq!(entry.metadata().unwrap().mode() & 0o7777, 0o644);
    }

    let keyd = Keyd::new(protectors_config(&rig, &database));
    keyd.provision(3010, &secret()).unwrap();
    keyd.provision(3010, &secret()).unwrap();
    let twice = listing(&database);
    let entries = twice
        .lines()
        .filter(|l| l.starts_with("openhello-uid-3010"))
        .count();
    assert_eq!(entries, 1, "{twice}");

    protectors.purge(3008).unwrap();
    let after = listing(&database);
    assert!(line(&after, 3008).is_none(), "{after}");
    assert!(line(&after, 3009).is_some(), "{after}");
    protectors.purge(3008).unwrap();
}

fn unlock(path: &Path, op: u8, payload: &[u8]) -> Option<Vec<u8>> {
    let mut stream = UnixStream::connect(path).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut frame = vec![op];
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(payload);
    let _ = stream.write_all(&frame);
    let mut header = [0u8; 3];
    stream.read_exact(&mut header).ok()?;
    let mut body = vec![0u8; usize::from(u16::from_be_bytes([header[1], header[2]]))];
    stream.read_exact(&mut body).ok()?;
    (header[0] == STATUS_ACCEPTED).then_some(body)
}

fn on_behalf_of(uid: u32, op: u8, payload: &str) -> Vec<u8> {
    let mut out = uid.to_be_bytes().to_vec();
    out.push(op);
    out.extend_from_slice(payload.as_bytes());
    out
}

#[test]
fn only_a_root_peer_may_name_the_uid_and_a_refused_request_never_reaches_the_tpm() {
    let rig = rig();
    rig.clear_lockout();
    let protectors = Arc::new(Protectors::new(rig.config.clone()).unwrap());
    protectors.provision_protectors(3006).unwrap();
    protectors.set_pin(3006, PIN).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let serve = |name: &str, peer: u32| {
        let config = UnlockSocketConfig {
            path: dir.path().join(name),
        };
        UnlockSocket::bind_with_peer_uid(protectors.clone(), config, peer).unwrap()
    };
    let user = serve("user.sock", 3007);
    let root = serve("root.sock", 0);
    let counter = rig.lockout_counter();

    let other = |pin| on_behalf_of(3006, OP_UNLOCK_PIN, pin);
    assert!(unlock(user.path(), OP_UNLOCK_FOR_UID, &other(PIN)).is_none());
    assert!(unlock(user.path(), OP_UNLOCK_FOR_UID, &other(WRONG_PIN)).is_none());
    assert!(unlock(user.path(), OP_UNLOCK_PIN, PIN.as_bytes()).is_none());
    assert_eq!(rig.lockout_counter(), counter);

    assert!(unlock(root.path(), OP_UNLOCK_FOR_UID, &other(WRONG_PIN)).is_none());
    assert!(rig.lockout_counter() > counter);
    rig.clear_lockout();

    let granted = unlock(root.path(), OP_UNLOCK_FOR_UID, &other(PIN)).expect("root names the uid");
    let granted = Secret::new(String::from_utf8(granted).unwrap()).unwrap();
    let signature = protectors
        .keyd()
        .sign_digest(3006, &granted, &DIGEST)
        .unwrap();
    let certificate = protectors.keyd().certificate(3006).unwrap();
    assert!(verifies(&certificate_point(&certificate), &signature));

    assert!(unlock(root.path(), OP_UNLOCK_PIN, PIN.as_bytes()).is_none());
    assert!(unlock(root.path(), OP_UNLOCK_FOR_UID, &[0, 0]).is_none());

    let own = serve("own.sock", 3006);
    assert!(unlock(own.path(), OP_UNLOCK_PIN, PIN.as_bytes()).is_some());
    assert!(unlock(
        own.path(),
        OP_UNLOCK_FOR_UID,
        &on_behalf_of(3006, OP_UNLOCK_PIN, PIN)
    )
    .is_some());
    rig.clear_lockout();
}
