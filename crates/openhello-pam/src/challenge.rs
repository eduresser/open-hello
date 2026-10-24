use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use openhello_auth_proto::{
    auth_message, decode_public_key, public_key_file_name, request_payload, split_release_reply,
    CHALLENGE_LEN, MAX_PASSWORD_LEN, MAX_RELEASE_REPLY, OP_TOKEN_AUTH_RELEASE,
    OP_TOKEN_SEAL_SECRET, SIGNATURE_LEN,
};
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature, VerifyingKey};
use zeroize::Zeroizing;

use crate::config;

const OP_HELLO: u8 = 1;
const STATUS_OK: u8 = 0;
const STATUS_PIN_INCORRECT: u8 = 1;
const STATUS_REFUSED: u8 = 5;

#[derive(Debug, PartialEq, Eq)]
pub enum SignError {
    Unavailable,
    Refused,
}

pub struct Signed {
    pub signature: [u8; SIGNATURE_LEN],
    pub secret: Zeroizing<Vec<u8>>,
}

pub fn random_challenge() -> Option<[u8; CHALLENGE_LEN]> {
    let mut challenge = [0u8; CHALLENGE_LEN];
    let mut filled = 0;
    while filled < CHALLENGE_LEN {
        let n = unsafe {
            libc::getrandom(
                challenge[filled..].as_mut_ptr().cast(),
                CHALLENGE_LEN - filled,
                0,
            )
        };
        if n < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        filled += usize::try_from(n).ok().filter(|n| *n > 0)?;
    }
    Some(challenge)
}

pub fn load_public_key(dir: &Path, uid: u32, trusted_owner: u32) -> Option<VerifyingKey> {
    let text = config::read_trusted(&dir.join(public_key_file_name(uid)), trusted_owner).ok()?;
    VerifyingKey::from_sec1_bytes(&decode_public_key(&text)?).ok()
}

pub fn signature_is_valid(
    key: &VerifyingKey,
    uid: u32,
    service: &str,
    challenge: &[u8; CHALLENGE_LEN],
    signature: &[u8],
) -> bool {
    let Ok(signature) = Signature::from_slice(signature) else {
        return false;
    };
    key.verify_prehash(&auth_message(uid, service, challenge), &signature)
        .is_ok()
}

pub fn request_signature(
    socket: &Path,
    uid: u32,
    service: &str,
    challenge: &[u8; CHALLENGE_LEN],
    timeout: Duration,
) -> Result<Signed, SignError> {
    let payload = request_payload(service, challenge).ok_or(SignError::Unavailable)?;
    let mut stream = connect_as(socket, uid, timeout).ok_or(SignError::Unavailable)?;
    let (status, body) = exchange(&mut stream, OP_TOKEN_AUTH_RELEASE, &payload)
        .map_err(|_| SignError::Unavailable)?;
    match status {
        STATUS_OK => signed(&body).ok_or(SignError::Unavailable),
        STATUS_REFUSED | STATUS_PIN_INCORRECT => Err(SignError::Refused),
        _ => Err(SignError::Unavailable),
    }
}

pub fn seal_secret(socket: &Path, uid: u32, password: &[u8], timeout: Duration) -> bool {
    if password.is_empty() || password.len() > MAX_PASSWORD_LEN {
        return false;
    }
    let mut payload = Zeroizing::new(uid.to_be_bytes().to_vec());
    payload.extend_from_slice(password);
    connect_as(socket, uid, timeout)
        .and_then(|mut stream| exchange(&mut stream, OP_TOKEN_SEAL_SECRET, &payload).ok())
        .is_some_and(|(status, _)| status == STATUS_OK)
}

fn connect_as(socket: &Path, uid: u32, timeout: Duration) -> Option<UnixStream> {
    let timeout = timeout.max(Duration::from_millis(1));
    let mut stream = UnixStream::connect(socket).ok()?;
    stream
        .set_read_timeout(Some(timeout))
        .and_then(|()| stream.set_write_timeout(Some(timeout)))
        .ok()?;
    let (status, _) = exchange(&mut stream, OP_HELLO, &uid.to_be_bytes()).ok()?;
    (status == STATUS_OK).then_some(stream)
}

fn signed(body: &[u8]) -> Option<Signed> {
    let (signature, secret) = split_release_reply(body)?;
    Some(Signed {
        signature: signature.try_into().ok()?,
        secret: Zeroizing::new(secret.to_vec()),
    })
}

fn exchange(
    stream: &mut UnixStream,
    op: u8,
    payload: &[u8],
) -> std::io::Result<(u8, Zeroizing<Vec<u8>>)> {
    let mut frame = Zeroizing::new(vec![op]);
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(payload);
    stream.write_all(&frame)?;
    let mut header = [0u8; 3];
    stream.read_exact(&mut header)?;
    let len = usize::from(u16::from_be_bytes([header[1], header[2]]));
    if len > MAX_RELEASE_REPLY {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    let mut body = Zeroizing::new(vec![0u8; len]);
    stream.read_exact(&mut body)?;
    Ok((header[0], body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use openhello_auth_proto::encode_public_key;
    use p256::ecdsa::SigningKey;
    use std::os::unix::fs::PermissionsExt;

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_slice(&[seed; 32]).unwrap()
    }

    fn sign(key: &SigningKey, uid: u32, service: &str, challenge: &[u8; 32]) -> Vec<u8> {
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        let signature: Signature = key
            .sign_prehash(&auth_message(uid, service, challenge))
            .unwrap();
        signature.to_bytes().to_vec()
    }

    #[test]
    fn a_signature_only_verifies_for_its_own_uid_service_challenge_and_key() {
        let key = signing_key(3);
        let public = *key.verifying_key();
        let signature = sign(&key, 1000, "sudo", &[5; 32]);
        assert!(signature_is_valid(
            &public, 1000, "sudo", &[5; 32], &signature
        ));
        assert!(!signature_is_valid(
            &public, 1001, "sudo", &[5; 32], &signature
        ));
        assert!(!signature_is_valid(
            &public, 1000, "login", &[5; 32], &signature
        ));
        assert!(!signature_is_valid(
            &public, 1000, "sudo", &[6; 32], &signature
        ));
        let other = *signing_key(4).verifying_key();
        assert!(!signature_is_valid(
            &other, 1000, "sudo", &[5; 32], &signature
        ));
        assert!(!signature_is_valid(
            &public,
            1000,
            "sudo",
            &[5; 32],
            &signature[..63]
        ));
    }

    #[test]
    fn the_public_key_file_loads_only_when_owned_by_the_trusted_uid_and_not_group_writable() {
        let dir = tempfile::tempdir().unwrap();
        let uid = 1234;
        let point = signing_key(3).verifying_key().to_encoded_point(false);
        let file = dir.path().join(public_key_file_name(uid));
        std::fs::write(&file, encode_public_key(point.as_bytes()).unwrap()).unwrap();
        let me = unsafe { libc::geteuid() };

        assert!(load_public_key(dir.path(), uid, me).is_some());
        assert!(load_public_key(dir.path(), uid, me + 1).is_none());
        assert!(load_public_key(dir.path(), uid + 1, me).is_none());
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(load_public_key(dir.path(), uid, me).is_none());
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::write(&file, "04zz\n").unwrap();
        assert!(load_public_key(dir.path(), uid, me).is_none());
    }

    #[test]
    fn a_release_reply_splits_into_the_signature_and_the_secret_and_rejects_bad_lengths() {
        let mut body = vec![9u8; SIGNATURE_LEN];
        body.extend_from_slice(&[0, 3]);
        body.extend_from_slice(b"pwd");
        let reply = signed(&body).unwrap();
        assert_eq!(reply.signature, [9u8; SIGNATURE_LEN]);
        assert_eq!(reply.secret.as_slice(), b"pwd");
        assert!(signed(&body[..body.len() - 1]).is_none());
        assert!(signed(&[9u8; SIGNATURE_LEN]).is_none());
        let alone = signed(&[vec![9u8; SIGNATURE_LEN], vec![0, 0]].concat()).unwrap();
        assert!(alone.secret.is_empty());
    }

    #[test]
    fn challenges_are_random_per_call() {
        assert_ne!(random_challenge(), random_challenge());
    }
}
