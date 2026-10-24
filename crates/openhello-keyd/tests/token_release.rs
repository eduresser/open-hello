mod support;

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use openhello_auth_proto::{
    auth_message, decode_public_key, request_payload, split_release_reply, CHALLENGE_LEN,
    SIGNATURE_LEN,
};
use openhello_keyd::logging::{self, Level, LogSink};
use openhello_keyd::{
    Protectors, TicketSocket, TicketSocketConfig, TokenSocket, TokenSocketConfig, OP_TICKET,
    OP_TOKEN_AUTH, OP_TOKEN_AUTH_RELEASE, OP_TOKEN_SEAL_SECRET, STATUS_ACCEPTED, TOKEN_OK,
    TOKEN_REFUSED,
};
use openhello_ticket::Issuer;
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature, VerifyingKey};
use support::{rig, Rig, TokenClient};

const OTHER_UID: u32 = 2998;
const SERVICE: &str = "login";
const CHALLENGE: [u8; CHALLENGE_LEN] = [0x6d; CHALLENGE_LEN];
const PASSWORD: &str = "Correct Horse 9 battery staple";

fn uid() -> u32 {
    let uid = unsafe { libc::getuid() };
    assert!(
        uid <= 0xFFFF,
        "run the tests as a regular user (uid {uid} is outside 0..=65535)"
    );
    uid
}

fn shadow_path(rig: &Rig) -> PathBuf {
    rig.config.store_dir.with_file_name("shadow")
}

fn shadow_line(salt: &str) -> String {
    format!(
        "user{}:$6$rounds=5000${salt}$SGFzaEZvclRoZVRlc3RVc2Vy:20000:0:99999:7:::\n",
        uid()
    )
}

fn provisioned(rig: &Rig) -> Arc<Protectors> {
    static DONE: OnceLock<Arc<Protectors>> = OnceLock::new();
    DONE.get_or_init(|| {
        let mut config = rig.config.clone();
        config.shadow_file = shadow_path(rig);
        let protectors = Arc::new(Protectors::new(config).unwrap());
        protectors.provision_protectors(uid()).unwrap();
        protectors.provision_protectors(OTHER_UID).unwrap();
        protectors
    })
    .clone()
}

struct Served {
    protectors: Arc<Protectors>,
    user: TokenSocket,
    root: TokenSocket,
    dir: tempfile::TempDir,
}

fn served(rig: &Rig) -> Served {
    rig.clear_lockout();
    std::fs::write(shadow_path(rig), shadow_line("saltsalt")).unwrap();
    let protectors = provisioned(rig);
    protectors.login_secrets().purge(uid()).unwrap();
    protectors.take_grant(uid());
    protectors.take_grant(OTHER_UID);
    let dir = tempfile::tempdir().unwrap();
    let bind = |name: &str| TokenSocketConfig {
        path: dir.path().join(name),
    };
    let user = TokenSocket::bind(protectors.clone(), bind("user.sock")).unwrap();
    let root = TokenSocket::bind_with_peer_uid(protectors.clone(), bind("root.sock"), 0).unwrap();
    Served {
        protectors,
        user,
        root,
        dir,
    }
}

impl Served {
    fn grant(&self, ticket_uid: u32) {
        let socket = TicketSocket::bind(
            self.protectors.clone(),
            TicketSocketConfig {
                path: self.dir.path().join("ticket.sock"),
                allowed_uid: uid(),
                expected_exe: None,
            },
        )
        .unwrap();
        let ticket = Issuer::new(self.protectors.ticket_key())
            .issue(ticket_uid)
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

    fn client(&self, root: bool) -> TokenClient {
        let socket = if root { &self.root } else { &self.user };
        TokenClient::connect(socket.path(), uid())
    }

    fn seal(&self, root: bool, named: u32, password: &[u8]) -> u8 {
        let payload = [named.to_be_bytes().to_vec(), password.to_vec()].concat();
        self.client(root)
            .send(OP_TOKEN_SEAL_SECRET, &payload)
            .expect("keyd answers")
            .0
    }

    fn release_on(&self, client: &mut TokenClient) -> (u8, Vec<u8>) {
        client
            .send(
                OP_TOKEN_AUTH_RELEASE,
                &request_payload(SERVICE, &CHALLENGE).unwrap(),
            )
            .expect("keyd answers")
    }

    fn release(&self, root: bool) -> (u8, Vec<u8>) {
        self.release_on(&mut self.client(root))
    }

    fn released_with_fresh_grant(&self) -> Vec<u8> {
        self.grant(uid());
        let (status, body) = self.release(true);
        assert_eq!(status, TOKEN_OK);
        let (_, secret) = split_release_reply(&body).unwrap();
        secret.to_vec()
    }
}

fn verifies(rig: &Rig, signature: &[u8]) -> bool {
    let text = std::fs::read_to_string(rig.config.auth_dir.join(format!("{}.pub", uid()))).unwrap();
    let key = VerifyingKey::from_sec1_bytes(&decode_public_key(&text).unwrap()).unwrap();
    key.verify_prehash(
        &auth_message(uid(), SERVICE, &CHALLENGE),
        &Signature::from_slice(signature).unwrap(),
    )
    .is_ok()
}

fn secret_dir(rig: &Rig) -> PathBuf {
    rig.config
        .store_dir
        .join("login-secrets")
        .join(uid().to_string())
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn files_contain(dir: &Path, needle: &[u8]) -> bool {
    std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .any(|entry| {
            let path = entry.path();
            if path.is_dir() {
                files_contain(&path, needle)
            } else {
                contains(&std::fs::read(&path).unwrap_or_default(), needle)
            }
        })
}

#[derive(Default)]
struct Lines(Mutex<Vec<String>>);

impl LogSink for Lines {
    fn write_line(&self, line: &str) {
        self.0.lock().unwrap().push(line.to_string());
    }
}

// @spec:AC-086
#[test]
fn the_secret_is_released_once_and_only_against_a_fresh_ticket_for_that_user() {
    let rig = rig();
    let served = served(&rig);
    assert_eq!(served.seal(true, uid(), PASSWORD.as_bytes()), TOKEN_OK);

    assert_eq!(
        served.release(true),
        (TOKEN_REFUSED, Vec::new()),
        "no ticket"
    );

    served.grant(OTHER_UID);
    assert_eq!(
        served.release(true),
        (TOKEN_REFUSED, Vec::new()),
        "a ticket for another uid"
    );
    served.protectors.take_grant(OTHER_UID);

    served.grant(uid());
    let mut client = served.client(true);
    let (status, body) = served.release_on(&mut client);
    assert_eq!(status, TOKEN_OK);
    let (signature, secret) = split_release_reply(&body).unwrap();
    assert_eq!(signature.len(), SIGNATURE_LEN);
    assert!(verifies(&rig, signature));
    assert_eq!(secret, PASSWORD.as_bytes());

    assert_eq!(
        served.release_on(&mut client),
        (TOKEN_REFUSED, Vec::new()),
        "the ticket is spent on the same connection"
    );
    assert_eq!(
        served.release(true),
        (TOKEN_REFUSED, Vec::new()),
        "the ticket is spent for new connections"
    );
    let mut plain = served.client(true);
    assert_eq!(
        plain
            .send(
                OP_TOKEN_AUTH,
                &request_payload(SERVICE, &CHALLENGE).unwrap()
            )
            .unwrap(),
        (TOKEN_REFUSED, Vec::new()),
        "nor can plain AUTH reuse it"
    );
}

// @spec:AC-087
#[test]
fn only_a_root_peer_seals_and_bad_requests_leave_the_secret_unchanged() {
    let rig = rig();
    let served = served(&rig);

    assert_eq!(
        served.seal(false, uid(), b"attacker password"),
        TOKEN_REFUSED
    );
    assert!(!secret_dir(&rig).exists(), "nothing was sealed");

    assert_eq!(served.seal(true, uid(), PASSWORD.as_bytes()), TOKEN_OK);
    let stored = std::fs::read(secret_dir(&rig).join("secret.bin")).unwrap();

    assert_eq!(
        served.seal(false, uid(), b"attacker password"),
        TOKEN_REFUSED
    );
    for (named, password) in [
        (OTHER_UID, &b"other user"[..]),
        (uid(), &b""[..]),
        (uid(), &[0xff, 0xfe][..]),
        (uid(), &b"nul\0inside"[..]),
        (uid(), &[b'x'; 513][..]),
    ] {
        assert_eq!(served.seal(true, named, password), TOKEN_REFUSED);
    }
    let mut short = served.client(true);
    assert_eq!(
        short.send(OP_TOKEN_SEAL_SECRET, &[0, 0]).unwrap().0,
        TOKEN_REFUSED
    );
    assert_eq!(
        std::fs::read(secret_dir(&rig).join("secret.bin")).unwrap(),
        stored
    );
    assert_eq!(served.released_with_fresh_grant(), PASSWORD.as_bytes());

    std::fs::write(shadow_path(&rig), "someone:$6$x$y:1::\n").unwrap();
    assert_eq!(
        served.seal(true, uid(), b"no shadow entry"),
        TOKEN_REFUSED,
        "an account outside /etc/shadow cannot be sealed"
    );
}

// @spec:AC-088
#[test]
fn the_password_never_reaches_non_root_replies_logs_or_the_store() {
    let rig = rig();
    let served = served(&rig);
    let lines = Arc::new(Lines::default());
    logging::configure(Level::Trace, lines.clone());

    let mut outsider = served.client(false);
    let payload = [uid().to_be_bytes().to_vec(), PASSWORD.as_bytes().to_vec()].concat();
    assert_eq!(
        outsider.send(OP_TOKEN_SEAL_SECRET, &payload).unwrap().0,
        TOKEN_REFUSED
    );
    assert_eq!(served.seal(true, uid(), PASSWORD.as_bytes()), TOKEN_OK);
    served.grant(uid());
    let (status, body) = served.release_on(&mut outsider);
    assert_eq!(status, TOKEN_OK);
    assert_eq!(split_release_reply(&body).unwrap().1, b"");
    assert_eq!(served.released_with_fresh_grant(), PASSWORD.as_bytes());
    assert_eq!(
        served.seal(true, OTHER_UID, PASSWORD.as_bytes()),
        TOKEN_REFUSED
    );
    std::fs::write(shadow_path(&rig), shadow_line("changed")).unwrap();
    assert_eq!(served.released_with_fresh_grant(), b"");

    logging::set_level(Level::Info);
    let logged = lines.0.lock().unwrap().join("\n");
    assert!(logged.contains("token-secret-sealed"));
    assert!(logged.contains("token-seal-refused"));
    assert!(!logged.contains(PASSWORD));
    assert!(!contains(&outsider.received, PASSWORD.as_bytes()));
    assert!(!files_contain(&rig.config.store_dir, PASSWORD.as_bytes()));
}

// @spec:AC-080
#[test]
fn a_changed_shadow_entry_withholds_and_discards_the_secret() {
    let rig = rig();
    let served = served(&rig);
    assert_eq!(served.seal(true, uid(), PASSWORD.as_bytes()), TOKEN_OK);
    assert!(secret_dir(&rig).join("secret.bin").exists());

    std::fs::write(shadow_path(&rig), shadow_line("othersalt")).unwrap();
    served.grant(uid());
    let (status, body) = served.release(true);
    assert_eq!(status, TOKEN_OK, "the face still signs in alone");
    let (signature, secret) = split_release_reply(&body).unwrap();
    assert!(verifies(&rig, signature));
    assert!(secret.is_empty());
    assert!(!secret_dir(&rig).exists(), "the stale secret is gone");

    std::fs::write(shadow_path(&rig), shadow_line("saltsalt")).unwrap();
    assert_eq!(served.released_with_fresh_grant(), b"");
}

#[test]
fn a_non_root_peer_gets_the_same_reply_shape_with_or_without_a_secret() {
    let rig = rig();
    let served = served(&rig);
    let shape = |served: &Served| {
        served.grant(uid());
        let (status, body) = served.release(false);
        assert_eq!(status, TOKEN_OK);
        assert!(verifies(&rig, &body[..SIGNATURE_LEN]));
        (body.len(), body[SIGNATURE_LEN..].to_vec())
    };

    let without = shape(&served);
    assert_eq!(served.seal(true, uid(), PASSWORD.as_bytes()), TOKEN_OK);
    let with = shape(&served);

    assert_eq!(without, (SIGNATURE_LEN + 2, vec![0, 0]));
    assert_eq!(with, without);
    assert_eq!(served.released_with_fresh_grant(), PASSWORD.as_bytes());
}
