mod support;

use std::path::Path;
use std::sync::{Arc, OnceLock};

use openhello_keyd::{
    Protectors, TokenSocket, TokenSocketConfig, ATTRIBUTE_READ, ATTRIBUTE_SENSITIVE,
    OP_TOKEN_ATTRIBUTES, OP_TOKEN_CLOSE, OP_TOKEN_FIND, OP_TOKEN_HELLO, OP_TOKEN_INFO,
    OP_TOKEN_LOGIN, OP_TOKEN_OPEN, OP_TOKEN_SIGN, OP_TOKEN_SIGN_CHECK, TOKEN_BAD_HANDLE,
    TOKEN_BAD_MECHANISM, TOKEN_BAD_REQUEST, TOKEN_NO_TOKEN, TOKEN_OK, TOKEN_PIN_INCORRECT,
    TOKEN_REFUSED,
};
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature, VerifyingKey};
use support::{
    looks_like_secret, rig, Rig, TokenClient, CKM_ECDSA, CKO_CERTIFICATE, CKO_PRIVATE_KEY,
    CKO_PUBLIC_KEY,
};

const PIN: &str = "482916";
const OTHER_UID: u32 = 2998;
const NO_TOKEN_UID: u32 = 2997;
const DIGEST: [u8; 32] = [0x3c; 32];
const CKA_CLASS: u64 = 0x0;
const CKA_VALUE: u64 = 0x11;
const CKA_CERTIFICATE_TYPE: u64 = 0x80;
const CKA_KEY_TYPE: u64 = 0x100;
const CKA_ID: u64 = 0x102;
const CKA_SIGN: u64 = 0x108;
const CKC_X_509: u64 = 0;
const CKK_EC: u64 = 3;
const CKA_SENSITIVE: u64 = 0x103;
const CKA_PRIVATE_EXPONENT: u64 = 0x123;
const CKA_PRIME_1: u64 = 0x124;
const CKA_EC_POINT: u64 = 0x181;
const CKM_SHA256: u64 = 0x250;
const LEGACY_TAKE_GRANT: u8 = 1;

fn uid() -> u32 {
    let uid = unsafe { libc::getuid() };
    assert!(
        uid <= 0xFFFF,
        "uid {uid} is outside the range keyd supports (0..=65535); run the tests as a regular user"
    );
    uid
}

fn provisioned(rig: &Rig) -> &'static Arc<Protectors> {
    static DONE: OnceLock<Arc<Protectors>> = OnceLock::new();
    DONE.get_or_init(|| {
        let protectors = Arc::new(Protectors::new(rig.config.clone()).unwrap());
        protectors.provision_protectors(uid()).unwrap();
        protectors.set_pin(uid(), PIN).unwrap();
        protectors.provision_protectors(OTHER_UID).unwrap();
        protectors
    })
}

struct Served {
    protectors: Arc<Protectors>,
    socket: TokenSocket,
    root: TokenSocket,
    _dir: tempfile::TempDir,
}

fn served(rig: &Rig) -> Served {
    rig.clear_lockout();
    let protectors = provisioned(rig).clone();
    let dir = tempfile::tempdir().unwrap();
    let bind = |name: &str| TokenSocketConfig {
        path: dir.path().join(name),
    };
    let socket = TokenSocket::bind(protectors.clone(), bind("user.sock")).unwrap();
    let root = TokenSocket::bind_with_peer_uid(protectors.clone(), bind("root.sock"), 0).unwrap();
    Served {
        protectors,
        socket,
        root,
        _dir: dir,
    }
}

fn attributes(client: &mut TokenClient, handle: u64, types: &[u64]) -> Vec<(u64, u8, Vec<u8>)> {
    let mut payload = handle.to_be_bytes().to_vec();
    payload.push(types.len() as u8);
    for kind in types {
        payload.extend_from_slice(&kind.to_be_bytes());
    }
    let reply = client.ok(OP_TOKEN_ATTRIBUTES, &payload);
    let mut rest = reply.as_slice();
    let mut found = Vec::new();
    while !rest.is_empty() {
        let len = usize::from(u16::from_be_bytes([rest[9], rest[10]]));
        found.push((
            u64::from_be_bytes(rest[..8].try_into().unwrap()),
            rest[8],
            rest[11..11 + len].to_vec(),
        ));
        rest = &rest[11 + len..];
    }
    found
}

fn logged_in(path: &Path) -> TokenClient {
    let mut client = TokenClient::connect(path, uid());
    client.ok(OP_TOKEN_OPEN, &[]);
    client.ok(OP_TOKEN_LOGIN, PIN.as_bytes());
    client
}

fn sign_request(mechanism: u64, handle: u64, data: &[u8]) -> Vec<u8> {
    let mut payload = mechanism.to_be_bytes().to_vec();
    payload.extend_from_slice(&handle.to_be_bytes());
    payload.extend_from_slice(data);
    payload
}

// @principle:P-004
#[test]
fn the_private_key_value_and_every_private_read_are_refused_while_signing_works() {
    let rig = rig();
    let served = served(&rig);
    let secret = served.protectors.unlock_with_pin(uid(), PIN).unwrap();
    let k = secret.expose_for_tests().as_bytes().to_vec();
    let mut client = logged_in(served.socket.path());

    let private = client.find_class(CKO_PRIVATE_KEY);
    assert_eq!(private.len(), 1);
    let key = private[0];
    for kind in [CKA_VALUE, CKA_PRIVATE_EXPONENT, CKA_PRIME_1, CKA_EC_POINT] {
        let read = attributes(&mut client, key, &[kind]);
        assert_eq!(read[0].1, ATTRIBUTE_SENSITIVE, "{kind:#x}");
        assert!(read[0].2.is_empty());
    }
    let readable = attributes(&mut client, key, &[CKA_ID, CKA_SENSITIVE]);
    assert!(readable
        .iter()
        .all(|(_, state, _)| *state == ATTRIBUTE_READ));
    assert_eq!(readable[1].2, [1]);

    let mut template = vec![2u8];
    template.extend_from_slice(&CKA_CLASS.to_be_bytes());
    template.extend_from_slice(&8u16.to_be_bytes());
    template.extend_from_slice(&CKO_PRIVATE_KEY.to_ne_bytes());
    template.extend_from_slice(&CKA_VALUE.to_be_bytes());
    template.extend_from_slice(&32u16.to_be_bytes());
    template.extend_from_slice(&[7u8; 32]);
    let (status, _) = client.send(OP_TOKEN_FIND, &template).unwrap();
    assert_eq!(status, TOKEN_BAD_REQUEST, "no search by private value");

    let everything = client.ok(OP_TOKEN_FIND, &[0]);
    let handles: Vec<u64> = everything
        .as_chunks::<8>()
        .0
        .iter()
        .map(|c| u64::from_be_bytes(*c))
        .collect();
    assert!(handles.len() >= 3);
    for handle in handles {
        let class = attributes(&mut client, handle, &[CKA_CLASS]).remove(0).2;
        let class = u64::from_ne_bytes(class.try_into().unwrap());
        assert!([CKO_CERTIFICATE, CKO_PUBLIC_KEY, CKO_PRIVATE_KEY].contains(&class));
    }

    let certificate = client.find_class(CKO_CERTIFICATE)[0];
    let public = client.find_class(CKO_PUBLIC_KEY)[0];
    let cert_value = attributes(&mut client, certificate, &[CKA_VALUE]);
    assert_eq!(cert_value[0].1, ATTRIBUTE_READ);
    assert!(!cert_value[0].2.is_empty());
    let point = attributes(&mut client, public, &[CKA_EC_POINT]);
    assert_eq!(point[0].1, ATTRIBUTE_READ);

    let missing = client
        .send(OP_TOKEN_ATTRIBUTES, &{
            let mut p = 9999u64.to_be_bytes().to_vec();
            p.push(1);
            p.extend_from_slice(&CKA_VALUE.to_be_bytes());
            p
        })
        .unwrap();
    assert_eq!(missing.0, TOKEN_BAD_HANDLE);
    let check = |client: &mut TokenClient, mechanism, handle| {
        client
            .send(OP_TOKEN_SIGN_CHECK, &sign_request(mechanism, handle, &[]))
            .unwrap()
            .0
    };
    assert_eq!(check(&mut client, CKM_ECDSA, key), TOKEN_OK);
    assert_eq!(check(&mut client, CKM_ECDSA, certificate), TOKEN_BAD_HANDLE);
    assert_eq!(check(&mut client, CKM_ECDSA, public), TOKEN_BAD_HANDLE);
    assert_eq!(check(&mut client, CKM_SHA256, key), TOKEN_BAD_MECHANISM);

    let (status, signature) = client
        .send(OP_TOKEN_SIGN, &sign_request(CKM_ECDSA, key, &DIGEST))
        .unwrap();
    assert_eq!(status, TOKEN_OK);
    let point = attributes(&mut client, public, &[CKA_EC_POINT]).remove(0).2;
    let verifying = VerifyingKey::from_sec1_bytes(&point[2..]).unwrap();
    verifying
        .verify_prehash(&DIGEST, &Signature::from_slice(&signature).unwrap())
        .unwrap();

    for wrap_or_export in [0x20u8, 0x40, 99] {
        let mut probe = TokenClient::connect(served.socket.path(), uid());
        let reply = probe.send(wrap_or_export, &[0; 8]).unwrap();
        assert_eq!(reply.0, TOKEN_BAD_REQUEST);
        assert!(
            probe.send(OP_TOKEN_INFO, &[]).is_none(),
            "the connection is closed"
        );
    }

    client.ok(OP_TOKEN_CLOSE, &[]);
    assert!(!client.received.windows(k.len()).any(|w| w == k.as_slice()));
    assert!(!looks_like_secret(&client.received));
}

fn find_with(client: &mut TokenClient, attributes: &[(u64, &[u8])]) -> Vec<u64> {
    let mut template = vec![attributes.len() as u8];
    for (kind, value) in attributes {
        template.extend_from_slice(&kind.to_be_bytes());
        template.extend_from_slice(&(value.len() as u16).to_be_bytes());
        template.extend_from_slice(value);
    }
    client
        .ok(OP_TOKEN_FIND, &template)
        .as_chunks::<8>()
        .0
        .iter()
        .map(|c| u64::from_be_bytes(*c))
        .collect()
}

// @covers:AC-027-openssl-templates
#[test]
fn the_search_templates_of_the_openssl_build_of_pam_pkcs11_find_the_certificate_then_the_key() {
    let rig = rig();
    let served = served(&rig);
    let mut client = TokenClient::connect(served.socket.path(), uid());
    client.ok(OP_TOKEN_OPEN, &[]);

    let certificate_template = [
        (CKA_CLASS, CKO_CERTIFICATE.to_ne_bytes().to_vec()),
        (CKA_CERTIFICATE_TYPE, CKC_X_509.to_ne_bytes().to_vec()),
    ];
    let certificate_template: Vec<(u64, &[u8])> = certificate_template
        .iter()
        .map(|(k, v)| (*k, v.as_slice()))
        .collect();
    let certificates = find_with(&mut client, &certificate_template);
    assert_eq!(certificates.len(), 1);
    let id = attributes(&mut client, certificates[0], &[CKA_ID])
        .remove(0)
        .2;
    assert!(!id.is_empty());

    let class = CKO_PRIVATE_KEY.to_ne_bytes();
    let key_template: [(u64, &[u8]); 3] = [(CKA_CLASS, &class), (CKA_SIGN, &[1]), (CKA_ID, &id)];
    assert!(
        find_with(&mut client, &key_template).is_empty(),
        "no key before login"
    );

    client.ok(OP_TOKEN_LOGIN, PIN.as_bytes());
    let without_id = find_with(&mut client, &key_template[..2]);
    let keys = find_with(&mut client, &key_template);
    assert_eq!(keys.len(), 1);
    assert_eq!(without_id, keys);
    let wrong_id: [(u64, &[u8]); 3] =
        [(CKA_CLASS, &class), (CKA_SIGN, &[1]), (CKA_ID, &[0xEE; 16])];
    assert!(find_with(&mut client, &wrong_id).is_empty());

    let key_type = attributes(&mut client, keys[0], &[CKA_KEY_TYPE, CKA_ID, CKA_SIGN]);
    assert!(key_type
        .iter()
        .all(|(_, state, _)| *state == ATTRIBUTE_READ));
    assert_eq!(key_type[0].2, CKK_EC.to_ne_bytes());
    assert_eq!(key_type[1].2, id);
    assert_eq!(key_type[2].2, [1]);
    let value = attributes(&mut client, keys[0], &[CKA_VALUE]);
    assert_eq!(value[0].1, ATTRIBUTE_SENSITIVE);

    let (status, signature) = client.sign(keys[0], &DIGEST).unwrap();
    assert_eq!(status, TOKEN_OK);
    assert_eq!(signature.len(), 64);
    let public = client.find_class(CKO_PUBLIC_KEY)[0];
    let point = attributes(&mut client, public, &[CKA_EC_POINT]).remove(0).2;
    VerifyingKey::from_sec1_bytes(&point[2..])
        .unwrap()
        .verify_prehash(&DIGEST, &Signature::from_slice(&signature).unwrap())
        .unwrap();
    client.ok(OP_TOKEN_CLOSE, &[]);
}

// @principle:P-004
#[test]
fn the_secret_is_not_in_any_reply_of_a_pin_login_and_a_frame_before_hello_is_refused() {
    let rig = rig();
    let served = served(&rig);
    let k = served
        .protectors
        .unlock_with_pin(uid(), PIN)
        .unwrap()
        .expose_for_tests()
        .as_bytes()
        .to_vec();

    let mut by_pin = logged_in(served.socket.path());
    let mut transcript = by_pin.received.clone();
    by_pin.ok(OP_TOKEN_CLOSE, &[]);
    transcript.extend_from_slice(&by_pin.received);
    drop(by_pin);

    assert!(!transcript.windows(k.len()).any(|w| w == k.as_slice()));
    assert!(!looks_like_secret(&transcript));

    let mut legacy = TokenClient::connect_unnamed(served.socket.path());
    let reply = legacy.send(LEGACY_TAKE_GRANT, &[]).unwrap();
    assert_eq!(reply.0, TOKEN_BAD_REQUEST, "hello must come first");
    assert!(reply.1.is_empty());
}

// @spec:AC-024
// @principle:P-003
#[test]
fn an_embedding_or_a_template_in_place_of_a_pin_is_refused_without_touching_the_tpm() {
    let rig = rig();
    let served = served(&rig);
    let before = rig.lockout_counter();

    let embedding: Vec<u8> = (0..512u32)
        .flat_map(|i| (i as f32 / 512.0).to_le_bytes())
        .collect();
    let template: Vec<u8> = (1u8..=32).collect();
    let hex_embedding: Vec<u8> = embedding
        .iter()
        .flat_map(|b| format!("{b:02x}").into_bytes())
        .collect();

    let mut huge = TokenClient::connect(served.socket.path(), uid());
    huge.ok(OP_TOKEN_OPEN, &[]);
    assert!(huge.send(OP_TOKEN_LOGIN, &embedding).is_none());

    let mut long = TokenClient::connect(served.socket.path(), uid());
    long.ok(OP_TOKEN_OPEN, &[]);
    assert!(long.send(OP_TOKEN_LOGIN, &hex_embedding).is_none());

    let mut small = TokenClient::connect(served.socket.path(), uid());
    small.ok(OP_TOKEN_OPEN, &[]);
    for material in [&template[..], &embedding[..32], &[0xff; 20][..], b""] {
        let (status, _) = small.send(OP_TOKEN_LOGIN, material).unwrap();
        assert_ne!(status, TOKEN_OK);
    }
    assert_eq!(
        rig.lockout_counter(),
        before,
        "refused material never reaches the TPM"
    );

    let mut fresh = TokenClient::connect(served.socket.path(), uid());
    fresh.ok(OP_TOKEN_OPEN, &[]);
    let (status, _) = fresh.send(OP_TOKEN_LOGIN, b"openhello-face").unwrap();
    assert_eq!(
        status, TOKEN_PIN_INCORRECT,
        "the placeholder alone, without a grant, is refused"
    );
    assert_eq!(rig.lockout_counter(), before);
    assert!(served
        .protectors
        .refuse_biometric_material(uid(), &embedding)
        .is_err());
}

#[test]
fn a_connection_names_only_its_own_uid_unless_the_peer_is_root_and_each_user_gets_only_its_token() {
    let rig = rig();
    let served = served(&rig);

    let mut other = TokenClient::connect_unnamed(served.socket.path());
    assert_eq!(
        other
            .send(OP_TOKEN_HELLO, &OTHER_UID.to_be_bytes())
            .unwrap()
            .0,
        TOKEN_REFUSED
    );
    assert!(other.send(OP_TOKEN_INFO, &[]).is_none());

    let mut mine = TokenClient::connect(served.socket.path(), uid());
    let info = mine.ok(OP_TOKEN_INFO, &[]);
    assert_eq!(
        String::from_utf8_lossy(&info[..32]).trim_end(),
        format!("openhello-{}", uid())
    );
    assert!(mine.send(OP_TOKEN_HELLO, &uid().to_be_bytes()).unwrap().0 != TOKEN_OK);

    let mut named = TokenClient::connect(served.root.path(), OTHER_UID);
    let info = named.ok(OP_TOKEN_INFO, &[]);
    assert_eq!(
        String::from_utf8_lossy(&info[..32]).trim_end(),
        format!("openhello-{OTHER_UID}")
    );

    let mut nobody = TokenClient::connect(served.root.path(), NO_TOKEN_UID);
    assert_eq!(nobody.send(OP_TOKEN_INFO, &[]).unwrap().0, TOKEN_NO_TOKEN);
    assert_eq!(nobody.send(OP_TOKEN_OPEN, &[]).unwrap().0, TOKEN_NO_TOKEN);
}

#[test]
fn connections_are_capped_per_user_and_a_closed_connection_releases_the_token() {
    let rig = rig();
    let served = served(&rig);

    let held: Vec<TokenClient> = (0..4)
        .map(|_| TokenClient::connect(served.socket.path(), uid()))
        .collect();
    let mut excess = TokenClient::connect_unnamed(served.socket.path());
    assert!(
        excess.send(OP_TOKEN_HELLO, &uid().to_be_bytes()).is_none(),
        "a fifth connection from the same user is dropped"
    );
    drop(held);

    let first = logged_in(served.socket.path());
    drop(first);
    let second = logged_in(served.socket.path());
    drop(second);
}

#[test]
fn a_connection_gets_three_pin_attempts() {
    let rig = rig();
    let served = served(&rig);
    let before = rig.lockout_counter();

    let mut client = TokenClient::connect(served.socket.path(), uid());
    client.ok(OP_TOKEN_OPEN, &[]);
    for _ in 0..3 {
        let (status, _) = client.send(OP_TOKEN_LOGIN, b"000000").unwrap();
        assert_eq!(status, TOKEN_PIN_INCORRECT);
    }
    let (status, _) = client.send(OP_TOKEN_LOGIN, PIN.as_bytes()).unwrap();
    assert_eq!(status, TOKEN_REFUSED);
    assert!(client.send(OP_TOKEN_INFO, &[]).is_none());
    assert_eq!(rig.lockout_counter(), before + 3);
    rig.clear_lockout();
}
