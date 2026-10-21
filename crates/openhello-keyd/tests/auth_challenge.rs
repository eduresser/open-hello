mod support;

use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use openhello_auth_proto::{
    auth_message, decode_public_key, request_payload, CHALLENGE_LEN, SIGNATURE_LEN,
};
use openhello_keyd::{
    Protectors, TicketSocket, TicketSocketConfig, TokenSocket, TokenSocketConfig, OP_TICKET,
    OP_TOKEN_AUTH, STATUS_ACCEPTED, TOKEN_BAD_REQUEST, TOKEN_OK, TOKEN_REFUSED,
};
use openhello_ticket::Issuer;
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature, VerifyingKey};
use support::{rig, Rig, TokenClient};

const SERVICE: &str = "sudo";
const CHALLENGE: [u8; CHALLENGE_LEN] = [0x5c; CHALLENGE_LEN];

fn uid() -> u32 {
    let uid = unsafe { libc::getuid() };
    assert!(
        uid <= 0xFFFF,
        "run the tests as a regular user (uid {uid} is outside 0..=65535)"
    );
    uid
}

fn issue_grant(protectors: &Arc<Protectors>, dir: &Path) {
    let socket = TicketSocket::bind(
        protectors.clone(),
        TicketSocketConfig {
            path: dir.join("ticket.sock"),
            allowed_uid: uid(),
            expected_exe: None,
        },
    )
    .unwrap();
    let ticket = Issuer::new(protectors.ticket_key())
        .issue(uid())
        .unwrap()
        .encode();
    let mut stream = UnixStream::connect(socket.path()).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut frame = vec![OP_TICKET];
    frame.extend_from_slice(&(ticket.len() as u16).to_be_bytes());
    frame.extend_from_slice(&ticket);
    stream.write_all(&frame).unwrap();
    let mut status = [0u8; 1];
    stream.read_exact(&mut status).unwrap();
    assert_eq!(status[0], STATUS_ACCEPTED);
}

fn verifies(rig: &Rig, uid: u32, signature: &[u8], message: &[u8; 32]) -> bool {
    let text = std::fs::read_to_string(rig.config.auth_dir.join(format!("{uid}.pub"))).unwrap();
    let point = decode_public_key(&text).expect("the .pub file holds a SEC1 point in hex");
    let key = VerifyingKey::from_sec1_bytes(&point).unwrap();
    key.verify_prehash(message, &Signature::from_slice(signature).unwrap())
        .is_ok()
}

fn auth(client: &mut TokenClient, payload: &[u8]) -> (u8, Vec<u8>) {
    client.send(OP_TOKEN_AUTH, payload).expect("keyd answers")
}

// @covers:AC-027-auth-challenge
#[test]
fn keyd_registers_a_root_owned_public_key_and_signs_the_verifiers_challenge_once_per_grant() {
    let rig = rig();
    rig.clear_lockout();
    let protectors = Arc::new(Protectors::new(rig.config.clone()).unwrap());
    protectors.provision_protectors(uid()).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let user = TokenSocket::bind(
        protectors.clone(),
        TokenSocketConfig {
            path: dir.path().join("user.sock"),
        },
    )
    .unwrap();
    let root = TokenSocket::bind_with_peer_uid(
        protectors.clone(),
        TokenSocketConfig {
            path: dir.path().join("root.sock"),
        },
        0,
    )
    .unwrap();
    let payload = request_payload(SERVICE, &CHALLENGE).unwrap();

    let file = rig.config.auth_dir.join(format!("{}.pub", uid()));
    let meta = std::fs::metadata(&file).unwrap();
    assert_eq!(meta.mode() & 0o7777, 0o644);
    assert_eq!(meta.uid(), unsafe { libc::geteuid() });
    assert_eq!(
        std::fs::metadata(&rig.config.auth_dir).unwrap().mode() & 0o7777,
        0o755
    );
    let key = protectors.keyd().key(uid()).unwrap();
    assert_eq!(
        decode_public_key(&std::fs::read_to_string(&file).unwrap()).unwrap()[..],
        key.public_key[..]
    );
    let inode = meta.ino();
    protectors
        .keyd()
        .provision(
            uid(),
            &openhello_keyd::Secret::new("0123456789abcdef0123456789abcdef").unwrap(),
        )
        .unwrap();
    assert_eq!(
        std::fs::metadata(&file).unwrap().ino(),
        inode,
        "a second provisioning keeps the same file"
    );

    let before = rig.lockout_counter();
    let mut none = TokenClient::connect(user.path(), uid());
    assert_eq!(auth(&mut none, &payload), (TOKEN_REFUSED, Vec::new()));
    assert_eq!(
        rig.lockout_counter(),
        before,
        "no grant never reaches the TPM"
    );

    issue_grant(&protectors, dir.path());
    let mut client = TokenClient::connect(user.path(), uid());
    let bad_service = [vec![0u8], vec![65u8; 66], b"\x04su\ndo".to_vec()].concat();
    for malformed in [
        &payload[..payload.len() - 1],
        &[][..],
        &bad_service[..],
        &request_payload("a", &CHALLENGE).unwrap()[..3],
    ] {
        let mut probe = TokenClient::connect(user.path(), uid());
        assert_eq!(auth(&mut probe, malformed).0, TOKEN_BAD_REQUEST);
    }
    assert!(request_payload("", &CHALLENGE).is_none());
    assert!(request_payload(&"x".repeat(65), &CHALLENGE).is_none());
    assert!(request_payload("su\ndo", &CHALLENGE).is_none());

    let (status, signature) = auth(&mut client, &payload);
    assert_eq!(status, TOKEN_OK);
    assert_eq!(signature.len(), SIGNATURE_LEN);
    assert!(verifies(
        &rig,
        uid(),
        &signature,
        &auth_message(uid(), SERVICE, &CHALLENGE)
    ));
    for forged in [
        auth_message(uid() + 1, SERVICE, &CHALLENGE),
        auth_message(uid(), "login", &CHALLENGE),
        auth_message(uid(), SERVICE, &[0x5d; CHALLENGE_LEN]),
    ] {
        assert!(!verifies(&rig, uid(), &signature, &forged));
    }

    let mut again = TokenClient::connect(user.path(), uid());
    assert_eq!(
        auth(&mut again, &payload),
        (TOKEN_REFUSED, Vec::new()),
        "one use per grant"
    );

    issue_grant(&protectors, dir.path());
    let mut named = TokenClient::connect(root.path(), uid());
    let (status, signature) = auth(&mut named, &request_payload("login", &CHALLENGE).unwrap());
    assert_eq!(status, TOKEN_OK, "a root peer signs for the uid it names");
    assert!(verifies(
        &rig,
        uid(),
        &signature,
        &auth_message(uid(), "login", &CHALLENGE)
    ));
    assert_eq!(rig.lockout_counter(), before);

    protectors.purge(uid()).unwrap();
    assert!(!file.exists(), "purge removes the registered public key");
}
