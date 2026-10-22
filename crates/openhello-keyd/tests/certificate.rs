mod support;

use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use openhello_keyd::{
    Keyd, KeydError, Protectors, Secret, TokenSocket, TokenSocketConfig, OP_TOKEN_CLOSE,
    OP_TOKEN_HELLO, OP_TOKEN_LOGIN, OP_TOKEN_OPEN, TOKEN_BAD_REQUEST, TOKEN_NO_TOKEN, TOKEN_OK,
    TOKEN_PIN_INCORRECT, TOKEN_REFUSED,
};
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature, VerifyingKey};
use support::{rig, Rig, TokenClient, CKO_PRIVATE_KEY};

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
    let prefixes = [
        format!("CN=openhello-uid-{uid} "),
        format!("/CN=openhello-uid-{uid} "),
    ];
    let mut lines = mapfile_lines(rig);
    lines.retain(|l| prefixes.iter().any(|p| l.starts_with(p)));
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
        [
            "CN=openhello-uid-3001 -> user3001".to_string(),
            "/CN=openhello-uid-3001 -> user3001".to_string()
        ]
    );
    let meta = std::fs::metadata(&rig.config.mapfile).unwrap();
    assert_eq!(meta.mode() & 0o7777, 0o644);
    assert_eq!(meta.uid(), unsafe { libc::geteuid() });

    let again = keyd.provision(3001, &secret()).unwrap();
    assert!(!again.created);
    assert_eq!(keyd.certificate(3001).unwrap(), certificate);
    assert_eq!(
        lines_of(&rig, 3001),
        [
            "CN=openhello-uid-3001 -> user3001".to_string(),
            "/CN=openhello-uid-3001 -> user3001".to_string()
        ]
    );
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

    let oneline = String::from_utf8(openssl(
        &["x509", "-noout", "-subject", "-nameopt", "compat"],
        &pem_of(&certificate),
    ))
    .unwrap();
    let subject = oneline.trim_end().strip_prefix("subject=").unwrap();
    assert_eq!(subject, "/CN=openhello-uid-3002");
    assert_eq!(
        lines_of(&rig, 3002),
        [
            "CN=openhello-uid-3002 -> user3002".to_string(),
            format!("{subject} -> user3002")
        ]
    );
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
    assert_eq!(lines_of(&rig, 3003).len(), 2);
}

// @spec:AC-033
// @covers:AC-027-subject-map
#[test]
fn purge_removes_the_certificate_and_only_its_own_mapping_line() {
    let rig = rig();
    let protectors = Protectors::new(rig.config.clone()).unwrap();
    protectors.provision_protectors(3004).unwrap();
    protectors.provision_protectors(3005).unwrap();
    assert_eq!(
        lines_of(&rig, 3004),
        [
            "CN=openhello-uid-3004 -> user3004".to_string(),
            "/CN=openhello-uid-3004 -> user3004".to_string()
        ]
    );

    protectors.purge(3004).unwrap();

    assert!(matches!(
        protectors.keyd().certificate(3004),
        Err(KeydError::NotProvisioned)
    ));
    assert!(lines_of(&rig, 3004).is_empty());
    assert_eq!(
        lines_of(&rig, 3005),
        [
            "CN=openhello-uid-3005 -> user3005".to_string(),
            "/CN=openhello-uid-3005 -> user3005".to_string()
        ]
    );
    assert!(protectors.keyd().certificate(3005).is_ok());
}

fn hello(path: &Path, payload: &[u8]) -> Option<u8> {
    TokenClient::connect_unnamed(path)
        .send(OP_TOKEN_HELLO, payload)
        .map(|(status, _)| status)
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
        let config = TokenSocketConfig {
            path: dir.path().join(name),
        };
        TokenSocket::bind_with_peer_uid(protectors.clone(), config, peer).unwrap()
    };
    let user = serve("user.sock", 3007);
    let root = serve("root.sock", 0);
    let counter = rig.lockout_counter();

    assert_eq!(
        hello(user.path(), &3006u32.to_be_bytes()),
        Some(TOKEN_REFUSED)
    );
    let mut named_self = TokenClient::connect(user.path(), 3007);
    assert_eq!(
        named_self.send(OP_TOKEN_OPEN, &[]).unwrap().0,
        TOKEN_NO_TOKEN,
        "a user without a token never reaches another user's PIN"
    );
    assert_eq!(
        named_self.send(OP_TOKEN_LOGIN, PIN.as_bytes()).unwrap().0,
        TOKEN_BAD_REQUEST
    );
    assert_eq!(rig.lockout_counter(), counter);

    assert_eq!(hello(root.path(), &[0, 0]), Some(TOKEN_BAD_REQUEST));
    assert_eq!(
        hello(root.path(), &0x1_0000u32.to_be_bytes()),
        Some(TOKEN_REFUSED)
    );

    let mut named = TokenClient::connect(root.path(), 3006);
    named.ok(OP_TOKEN_OPEN, &[]);
    let wrong = named.send(OP_TOKEN_LOGIN, WRONG_PIN.as_bytes()).unwrap();
    assert_eq!(wrong.0, TOKEN_PIN_INCORRECT);
    assert!(rig.lockout_counter() > counter);
    rig.clear_lockout();

    named.ok(OP_TOKEN_LOGIN, PIN.as_bytes());
    let key = named.find_class(CKO_PRIVATE_KEY)[0];
    let (status, signature) = named.sign(key, &DIGEST).unwrap();
    assert_eq!(status, TOKEN_OK);
    named.ok(OP_TOKEN_CLOSE, &[]);
    drop(named);
    let certificate = protectors.keyd().certificate(3006).unwrap();
    assert!(verifies(&certificate_point(&certificate), &signature));

    let own = serve("own.sock", 3006);
    let mut mine = TokenClient::connect(own.path(), 3006);
    mine.ok(OP_TOKEN_OPEN, &[]);
    mine.ok(OP_TOKEN_LOGIN, PIN.as_bytes());
    mine.ok(OP_TOKEN_CLOSE, &[]);
    rig.clear_lockout();
}
