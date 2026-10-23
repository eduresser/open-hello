mod support;

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use openhello_keyd::{
    parse_da_state, DaState, KeyInfo, Keyd, KeydError, LockoutOutcome, LockoutPolicy, Protectors,
    Secret, TicketSocket, TicketSocketConfig, OP_TICKET, OP_TICKET_KEY, STATUS_ACCEPTED,
    STATUS_REFUSED,
};
use openhello_ticket::{Issuer, TicketError, TicketKey, TICKET_LEN};
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature, VerifyingKey};
use support::{rig, Rig};

const DIGEST: [u8; 32] = [0x3c; 32];
const PIN: &str = "482916";

fn protectors(rig: &Rig) -> Arc<Protectors> {
    Arc::new(Protectors::new(rig.config.clone()).unwrap())
}

fn signs_and_verifies(keyd: &Keyd, uid: u32, secret: &Secret, key: &KeyInfo) -> bool {
    let signature = keyd.sign_digest(uid, secret, &DIGEST).unwrap();
    let verifying = VerifyingKey::from_sec1_bytes(&key.public_key).unwrap();
    verifying
        .verify_prehash(&DIGEST, &Signature::from_slice(&signature).unwrap())
        .is_ok()
}

fn ticket_for(protectors: &Protectors, uid: u32) -> Vec<u8> {
    Issuer::new(protectors.ticket_key())
        .issue(uid)
        .unwrap()
        .encode()
        .to_vec()
}

fn store_contains(dir: &Path, needle: &[u8]) -> bool {
    std::fs::read_dir(dir).unwrap().flatten().any(|entry| {
        let path = entry.path();
        if path.is_dir() {
            store_contains(&path, needle)
        } else {
            let bytes = std::fs::read(&path).unwrap_or_default();
            bytes.windows(needle.len()).any(|w| w == needle)
        }
    })
}

fn hex_to_bytes(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn current_uid() -> u32 {
    unsafe { libc::getuid() }
}

fn socket_config(rig_dir: &Path, allowed_uid: u32) -> TicketSocketConfig {
    TicketSocketConfig {
        path: rig_dir.join(format!("ticket-{allowed_uid}-{}.sock", std::process::id())),
        allowed_uid,
        expected_exe: None,
    }
}

fn request(path: &Path, op: u8, payload: &[u8], reply_len: usize) -> Vec<u8> {
    let mut stream = UnixStream::connect(path).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut frame = vec![op];
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(payload);
    let _ = stream.write_all(&frame);
    let mut reply = vec![0u8; reply_len];
    let mut read = 0;
    while read < reply_len {
        match stream.read(&mut reply[read..]) {
            Ok(0) | Err(_) => break,
            Ok(n) => read += n,
        }
    }
    reply.truncate(read);
    reply
}

fn ticket_status(path: &Path, ticket: &[u8]) -> u8 {
    request(path, OP_TICKET, ticket, 1)[0]
}

struct PolicyGuard<'a>(&'a Rig, &'a Protectors);

impl Drop for PolicyGuard<'_> {
    fn drop(&mut self) {
        let shared = LockoutPolicy {
            max_tries: 50,
            recovery_time_s: 3600,
            lockout_recovery_time_s: 3600,
        };
        let _ = self.1.apply_lockout_policy(&shared);
        let _ = self.0.tpm2("tpm2_dictionarylockout", &["--clear-lockout"]);
    }
}

// @spec:AC-019
#[test]
fn a_valid_ticket_releases_the_secret_and_the_token_signs() {
    let rig = rig();
    let protectors = protectors(&rig);
    protectors.provision_protectors(2001).unwrap();
    let key = protectors.keyd().key(2001).unwrap();

    let ticket = ticket_for(&protectors, 2001);
    let secret = protectors.unlock_with_ticket(2001, &ticket).unwrap();
    assert!(signs_and_verifies(protectors.keyd(), 2001, &secret, &key));
    assert_eq!(format!("{secret:?}"), "Secret(<redacted>)");

    assert!(matches!(
        protectors.unlock_with_ticket(2001, &ticket),
        Err(KeydError::Ticket(TicketError::Reused))
    ));
    let foreign = ticket_for(&protectors, 2999);
    assert!(matches!(
        protectors.unlock_with_ticket(2001, &foreign),
        Err(KeydError::Ticket(TicketError::UidMismatch))
    ));
    let other_key = Issuer::new(TicketKey::generate().unwrap())
        .issue(2001)
        .unwrap()
        .encode();
    assert!(matches!(
        protectors.unlock_with_ticket(2001, &other_key),
        Err(KeydError::Ticket(TicketError::InvalidMac))
    ));
}

// @spec:AC-024
// @principle:P-003
#[test]
fn templates_and_embeddings_are_refused_and_touch_nothing() {
    let rig = rig();
    rig.clear_lockout();
    let protectors = protectors(&rig);
    protectors.provision_protectors(2002).unwrap();
    protectors.set_pin(2002, PIN).unwrap();
    let before = rig.lockout_counter();

    let embedding: Vec<u8> = (0..512u32)
        .flat_map(|i| (i as f32 / 512.0).to_le_bytes())
        .collect();
    let template = [0xA5u8; TICKET_LEN];
    for material in [&embedding[..], &template[..], &[0u8; 3][..], &[][..]] {
        assert!(matches!(
            protectors.unlock_with_ticket(2002, material),
            Err(KeydError::Ticket(_))
        ));
        assert!(matches!(
            protectors.refuse_biometric_material(2002, material),
            Err(KeydError::Refused)
        ));
        assert!(matches!(
            protectors.unlock_with_pin(2002, &String::from_utf8_lossy(material)),
            Err(KeydError::AuthenticationFailed)
        ));
    }
    assert_eq!(
        rig.lockout_counter(),
        before,
        "refusal must not reach the TPM"
    );
    assert!(protectors.take_grant(2002).is_none());

    let ticket = ticket_for(&protectors, 2002);
    assert!(protectors.unlock_with_ticket(2002, &ticket).is_ok());
}

// @spec:AC-025
#[test]
fn the_correct_pin_unlocks_and_the_wrong_one_does_not() {
    let rig = rig();
    rig.clear_lockout();
    let protectors = protectors(&rig);
    assert!(matches!(
        protectors.unlock_with_pin(2003, PIN),
        Err(KeydError::NotProvisioned)
    ));
    protectors.provision_protectors(2003).unwrap();
    assert!(matches!(
        protectors.unlock_with_pin(2003, PIN),
        Err(KeydError::PinNotSet)
    ));
    assert!(matches!(
        protectors.set_pin(2003, "123"),
        Err(KeydError::InvalidPin)
    ));
    protectors.set_pin(2003, PIN).unwrap();
    let key = protectors.keyd().key(2003).unwrap();

    let secret = protectors.unlock_with_pin(2003, PIN).unwrap();
    assert!(signs_and_verifies(protectors.keyd(), 2003, &secret, &key));
    assert!(matches!(
        protectors.unlock_with_pin(2003, "000000"),
        Err(KeydError::AuthenticationFailed)
    ));
    assert!(protectors.unlock_with_pin(2003, PIN).is_ok());
    assert!(!store_contains(&rig.config.store_dir, PIN.as_bytes()));
    rig.clear_lockout();
}

// @spec:AC-026
#[test]
fn wrong_pins_reach_the_tpm_lockout_and_the_right_pin_is_refused_until_it_recovers() {
    let rig = rig();
    let protectors = protectors(&rig);
    let _restore = PolicyGuard(&rig, &protectors);
    protectors
        .apply_lockout_policy(&LockoutPolicy {
            max_tries: 3,
            recovery_time_s: 3,
            lockout_recovery_time_s: 3,
        })
        .unwrap();
    rig.clear_lockout();
    protectors.provision_protectors(2004).unwrap();
    protectors.set_pin(2004, PIN).unwrap();
    let key = protectors.keyd().key(2004).unwrap();
    assert_eq!(rig.lockout_counter(), 0);

    for attempt in 1..=3 {
        assert!(matches!(
            protectors.unlock_with_pin(2004, "000000"),
            Err(KeydError::AuthenticationFailed)
        ));
        assert_eq!(rig.lockout_counter(), attempt, "the counter is the TPM's");
    }
    let locked = protectors.unlock_with_pin(2004, PIN).unwrap_err();
    assert!(matches!(locked, KeydError::LockedOut));
    assert!(matches!(
        protectors.unlock_with_pin(2004, "111111"),
        Err(KeydError::LockedOut)
    ));

    let restarted = Protectors::new(rig.config.clone()).unwrap();
    assert!(matches!(
        restarted.unlock_with_pin(2004, PIN),
        Err(KeydError::LockedOut)
    ));

    rig.clear_lockout();
    let secret = protectors.unlock_with_pin(2004, PIN).unwrap();
    assert!(signs_and_verifies(protectors.keyd(), 2004, &secret, &key));

    for _ in 0..3 {
        let _ = protectors.unlock_with_pin(2004, "000000");
    }
    assert!(matches!(
        protectors.unlock_with_pin(2004, PIN),
        Err(KeydError::LockedOut)
    ));
    std::thread::sleep(Duration::from_secs(5));
    assert!(protectors.unlock_with_pin(2004, PIN).is_ok());
}

// @spec:AC-031
#[test]
fn the_recovery_code_is_returned_once_unlocks_and_is_never_stored_in_clear() {
    let rig = rig();
    let protectors = protectors(&rig);
    let code = protectors.provision_protectors(2005).unwrap();
    let text = code.reveal().to_string();
    let key = protectors.keyd().key(2005).unwrap();

    assert_eq!(text.len(), 32);
    assert_eq!(hex_to_bytes(&text).len(), 16);
    assert!(matches!(
        protectors.provision_protectors(2005),
        Err(KeydError::AlreadyProvisioned)
    ));
    assert_eq!(format!("{code:?}"), "RecoveryCode(<redacted>)");

    for needle in [text.as_bytes().to_vec(), hex_to_bytes(&text)] {
        assert!(
            !store_contains(&rig.config.store_dir, &needle),
            "the recovery code must not appear in the state directory"
        );
    }

    let (secret, _) = protectors.unlock_with_recovery(2005, &text).unwrap();
    assert!(signs_and_verifies(protectors.keyd(), 2005, &secret, &key));
}

// @spec:AC-032
#[test]
fn using_the_recovery_code_invalidates_it_and_issues_a_new_one() {
    let rig = rig();
    rig.clear_lockout();
    let protectors = protectors(&rig);
    let first = protectors.provision_protectors(2006).unwrap();
    let key = protectors.keyd().key(2006).unwrap();

    let (_, second) = protectors
        .unlock_with_recovery(2006, first.reveal())
        .unwrap();
    assert_ne!(first.reveal(), second.reveal());
    assert!(matches!(
        protectors.unlock_with_recovery(2006, first.reveal()),
        Err(KeydError::AuthenticationFailed)
    ));
    assert!(matches!(
        protectors.unlock_with_recovery(2006, "not a code"),
        Err(KeydError::AuthenticationFailed)
    ));

    let (secret, third) = protectors
        .unlock_with_recovery(2006, second.reveal())
        .unwrap();
    assert!(signs_and_verifies(protectors.keyd(), 2006, &secret, &key));
    assert!(matches!(
        protectors.unlock_with_recovery(2006, second.reveal()),
        Err(KeydError::AuthenticationFailed)
    ));
    assert!(!store_contains(
        &rig.config.store_dir,
        third.reveal().as_bytes()
    ));
    assert!(protectors
        .unlock_with_recovery(2006, third.reveal())
        .is_ok());
    rig.clear_lockout();
}

// @spec:AC-022
// @principle:P-003
#[test]
fn a_peer_that_is_not_authorized_gets_nothing_and_burns_no_ticket() {
    let rig = rig();
    let protectors = protectors(&rig);
    protectors.provision_protectors(2007).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let ticket = ticket_for(&protectors, 2007);

    let wrong_uid = TicketSocket::bind(
        protectors.clone(),
        socket_config(dir.path(), current_uid() + 1),
    )
    .unwrap();
    assert_eq!(
        request(wrong_uid.path(), OP_TICKET_KEY, &[], 33),
        [STATUS_REFUSED]
    );
    assert_eq!(ticket_status(wrong_uid.path(), &ticket), STATUS_REFUSED);

    let mut wrong_exe = socket_config(dir.path(), current_uid());
    wrong_exe.path = dir.path().join("exe.sock");
    wrong_exe.expected_exe = Some("/usr/bin/true".into());
    let wrong_exe = TicketSocket::bind(protectors.clone(), wrong_exe).unwrap();
    assert_eq!(
        request(wrong_exe.path(), OP_TICKET_KEY, &[], 33),
        [STATUS_REFUSED]
    );
    assert_eq!(ticket_status(wrong_exe.path(), &ticket), STATUS_REFUSED);

    assert!(protectors.take_grant(2007).is_none());
    assert!(protectors.unlock_with_ticket(2007, &ticket).is_ok());
}

// @spec:AC-019
// @spec:AC-022
// @principle:P-003
#[test]
fn the_socket_hands_out_the_ticket_key_and_accepts_only_valid_tickets() {
    let rig = rig();
    rig.clear_lockout();
    let protectors = protectors(&rig);
    protectors.provision_protectors(2008).unwrap();
    let key = protectors.keyd().key(2008).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let mut config = socket_config(dir.path(), current_uid());
    config.expected_exe = std::env::current_exe().ok();
    let socket = TicketSocket::bind(protectors.clone(), config).unwrap();
    let before = rig.lockout_counter();

    let reply = request(socket.path(), OP_TICKET_KEY, &[], 33);
    assert_eq!(reply[0], STATUS_ACCEPTED);
    assert_eq!(reply.len(), 33);
    let issuer = Issuer::new(TicketKey::from_bytes(reply[1..].try_into().unwrap()));
    let foreign = Issuer::new(TicketKey::generate().unwrap());
    let expired = Issuer::new(TicketKey::from_bytes(reply[1..].try_into().unwrap())).with_ttl_ms(0);

    let used = issuer.issue(2008).unwrap().encode();
    let refused: Vec<(&str, Vec<u8>)> = vec![
        ("wrong MAC", foreign.issue(2008).unwrap().encode().to_vec()),
        ("expired", expired.issue(2008).unwrap().encode().to_vec()),
        (
            "unprovisioned uid",
            issuer.issue(2998).unwrap().encode().to_vec(),
        ),
        ("template-sized junk", vec![0x5A; TICKET_LEN]),
        ("short", vec![1, 2, 3]),
        ("embedding", vec![0x3F; 2048]),
        ("embedding over the frame limit", vec![0x3F; 60_000]),
    ];
    for (name, bytes) in &refused {
        assert_eq!(
            ticket_status(socket.path(), bytes),
            STATUS_REFUSED,
            "{name}"
        );
        assert!(protectors.take_grant(2008).is_none(), "{name}");
    }
    assert_eq!(request(socket.path(), 9, &[], 1), [STATUS_REFUSED]);

    assert_eq!(ticket_status(socket.path(), &used), STATUS_ACCEPTED);
    assert_eq!(ticket_status(socket.path(), &used), STATUS_REFUSED, "reuse");
    let secret = protectors
        .take_grant(2008)
        .expect("accepted ticket parks K");
    assert!(signs_and_verifies(protectors.keyd(), 2008, &secret, &key));
    assert!(protectors.take_grant(2008).is_none());
    assert_eq!(rig.lockout_counter(), before);

    let path = socket.path().to_path_buf();
    drop(socket);
    assert!(!path.exists());
}

const DUAL_BOOT_GETCAP: &str = "  ownerAuthSet:              0
  endorsementAuthSet:        0
  lockoutAuthSet:            1
  inLockout:                 0
TPM2_PT_LOCKOUT_COUNTER: 0x0
TPM2_PT_MAX_AUTH_FAIL: 0x20
TPM2_PT_LOCKOUT_INTERVAL: 0x1C20
TPM2_PT_LOCKOUT_RECOVERY: 0x15180
";
const FOREIGN_LOCKOUT_AUTH: &str = "windows-owned";

// @spec:AC-026
#[test]
fn dictionary_attack_state_is_read_from_tpm2_getcap() {
    assert_eq!(
        parse_da_state(DUAL_BOOT_GETCAP),
        Some(DaState {
            lockout_auth_set: true,
            max_tries: 32,
            recovery_time_s: 7200,
            lockout_recovery_time_s: 86_400,
        })
    );
    assert_eq!(parse_da_state(&DUAL_BOOT_GETCAP.replace("lockoutAuthSet:            1", "lockoutAuthSet: 0")).map(|s| s.lockout_auth_set), Some(false));
    assert_eq!(parse_da_state(&DUAL_BOOT_GETCAP.replace("TPM2_PT_LOCKOUT_INTERVAL: 0x1C20\n", "")), None);
    assert_eq!(parse_da_state(&DUAL_BOOT_GETCAP.replace("lockoutAuthSet:            1", "lockoutAuthSet: yes")), None);
    assert_eq!(parse_da_state(""), None);
}

struct ForeignLockoutAuth<'a>(&'a Rig, &'a Protectors);

impl<'a> ForeignLockoutAuth<'a> {
    fn take(rig: &'a Rig, protectors: &'a Protectors, before: &LockoutPolicy) -> Self {
        protectors.apply_lockout_policy(before).unwrap();
        let out = rig.tpm2("tpm2_changeauth", &["-c", "lockout", FOREIGN_LOCKOUT_AUTH]);
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        ForeignLockoutAuth(rig, protectors)
    }
}

impl Drop for ForeignLockoutAuth<'_> {
    fn drop(&mut self) {
        let _ = self.0.tpm2("tpm2_changeauth", &["-c", "lockout", "-p", FOREIGN_LOCKOUT_AUTH]);
        let _ = self.1.apply_lockout_policy(&LockoutPolicy {
            max_tries: 50,
            recovery_time_s: 3600,
            lockout_recovery_time_s: 3600,
        });
        let _ = self.0.tpm2("tpm2_dictionarylockout", &["--clear-lockout"]);
    }
}

// @spec:AC-026
#[test]
fn without_a_foreign_owner_the_recommended_policy_is_applied() {
    let rig = rig();
    let protectors = protectors(&rig);
    let _restore = PolicyGuard(&rig, &protectors);
    assert_eq!(
        protectors.ensure_lockout_policy(&LockoutPolicy::RECOMMENDED).unwrap(),
        LockoutOutcome::Applied
    );
    let state = protectors.read_da_state().unwrap();
    assert!(!state.lockout_auth_set);
    assert_eq!(
        (state.max_tries, state.recovery_time_s, state.lockout_recovery_time_s),
        (10, 600, 86_400)
    );
}

// @spec:AC-026
#[test]
fn a_lockout_owned_by_another_system_is_kept_untouched_without_a_failed_attempt() {
    let rig = rig();
    let protectors = protectors(&rig);
    let windows = LockoutPolicy {
        max_tries: 32,
        recovery_time_s: 7200,
        lockout_recovery_time_s: 86_400,
    };
    let _owned = ForeignLockoutAuth::take(&rig, &protectors, &windows);
    let outcome = protectors.ensure_lockout_policy(&LockoutPolicy::RECOMMENDED).unwrap();
    assert_eq!(
        outcome,
        LockoutOutcome::KeptExisting(DaState {
            lockout_auth_set: true,
            max_tries: 32,
            recovery_time_s: 7200,
            lockout_recovery_time_s: 86_400,
        })
    );
    let probe = rig.tpm2("tpm2_dictionarylockout", &["--clear-lockout", "-p", FOREIGN_LOCKOUT_AUTH]);
    assert!(probe.status.success(), "the lockout hierarchy must not be locked: {}", String::from_utf8_lossy(&probe.stderr));
}

// @spec:AC-026
#[test]
fn a_foreign_owner_with_dictionary_attack_protection_disabled_is_refused() {
    let rig = rig();
    let protectors = protectors(&rig);
    let disabled = LockoutPolicy {
        max_tries: 32,
        recovery_time_s: 0,
        lockout_recovery_time_s: 86_400,
    };
    let _owned = ForeignLockoutAuth::take(&rig, &protectors, &disabled);
    assert!(matches!(
        protectors.ensure_lockout_policy(&LockoutPolicy::RECOMMENDED),
        Err(KeydError::Tpm)
    ));
}
