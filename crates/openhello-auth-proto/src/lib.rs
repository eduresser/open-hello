use sha2::{Digest, Sha256};

pub const DOMAIN: &[u8] = b"openhello-pam-v1";
pub const CHALLENGE_LEN: usize = 32;
pub const MAX_SERVICE_LEN: usize = 64;
pub const SIGNATURE_LEN: usize = 64;
pub const POINT_LEN: usize = 65;
pub const PUBLIC_KEY_FILE_SUFFIX: &str = ".pub";

pub fn valid_service(service: &str) -> bool {
    !service.is_empty()
        && service.len() <= MAX_SERVICE_LEN
        && service.chars().all(|c| !c.is_control())
}

pub fn auth_message(uid: u32, service: &str, challenge: &[u8; CHALLENGE_LEN]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(DOMAIN);
    hash.update(uid.to_be_bytes());
    hash.update([u8::try_from(service.len()).unwrap_or(u8::MAX)]);
    hash.update(service.as_bytes());
    hash.update(challenge);
    hash.finalize().into()
}

pub fn request_payload(service: &str, challenge: &[u8; CHALLENGE_LEN]) -> Option<Vec<u8>> {
    if !valid_service(service) {
        return None;
    }
    let mut payload = vec![u8::try_from(service.len()).ok()?];
    payload.extend_from_slice(service.as_bytes());
    payload.extend_from_slice(challenge);
    Some(payload)
}

pub fn parse_request(payload: &[u8]) -> Option<(&str, [u8; CHALLENGE_LEN])> {
    let (&len, rest) = payload.split_first()?;
    let len = usize::from(len);
    if rest.len() != len + CHALLENGE_LEN {
        return None;
    }
    let service = std::str::from_utf8(&rest[..len])
        .ok()
        .filter(|s| valid_service(s))?;
    Some((service, rest[len..].try_into().ok()?))
}

pub fn public_key_file_name(uid: u32) -> String {
    format!("{uid}{PUBLIC_KEY_FILE_SUFFIX}")
}

/// `<uid>.pub` holds the SEC1 uncompressed P-256 point as 130 lowercase hex digits and a newline.
pub fn encode_public_key(point: &[u8]) -> Option<String> {
    if point.len() != POINT_LEN || point[0] != 0x04 {
        return None;
    }
    let hex: String = point.iter().map(|b| format!("{b:02x}")).collect();
    Some(format!("{hex}\n"))
}

pub fn decode_public_key(text: &str) -> Option<[u8; POINT_LEN]> {
    let hex = text.strip_suffix('\n').unwrap_or(text);
    if hex.len() != POINT_LEN * 2 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut point = [0u8; POINT_LEN];
    for (byte, pair) in point.iter_mut().zip(hex.as_bytes().chunks(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    (point[0] == 0x04).then_some(point)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_binds_uid_service_and_challenge() {
        let base = auth_message(1000, "sudo", &[7; 32]);
        assert_ne!(base, auth_message(1001, "sudo", &[7; 32]));
        assert_ne!(base, auth_message(1000, "sudo2", &[7; 32]));
        assert_ne!(base, auth_message(1000, "sudo", &[8; 32]));
        assert_eq!(base, auth_message(1000, "sudo", &[7; 32]));
    }

    #[test]
    fn request_round_trips_and_rejects_malformed_input() {
        let payload = request_payload("sudo", &[9; 32]).unwrap();
        assert_eq!(parse_request(&payload), Some(("sudo", [9; 32])));
        assert!(request_payload("", &[0; 32]).is_none());
        assert!(request_payload(&"x".repeat(65), &[0; 32]).is_none());
        assert!(request_payload("su\ndo", &[0; 32]).is_none());
        assert!(parse_request(&payload[..payload.len() - 1]).is_none());
        assert!(parse_request(&[]).is_none());
        assert!(parse_request(&[0; 33]).is_none());
    }

    #[test]
    fn public_key_text_round_trips_only_uncompressed_points() {
        let mut point = [0xab; POINT_LEN];
        point[0] = 0x04;
        let text = encode_public_key(&point).unwrap();
        assert_eq!(decode_public_key(&text), Some(point));
        assert!(encode_public_key(&point[..64]).is_none());
        assert!(decode_public_key(&text.replace("04", "05")).is_none());
        assert!(decode_public_key("zz").is_none());
    }
}
