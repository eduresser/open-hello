use std::ffi::CStr;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::tpm::failure;
use crate::KeydError;

pub(crate) const DEFAULT_MAPFILE: &str = "/etc/openhello/pkcs11-subject-map";
const MAPPING_SEPARATOR: &str = " -> ";
const MAPFILE_MODE: u32 = 0o644;
const SECP256R1_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];
const ECDSA_SHA256_ALGORITHM: [u8; 12] = [
    0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
];
const OID_COMMON_NAME: [u8; 5] = [0x06, 0x03, 0x55, 0x04, 0x03];
const NOT_BEFORE: &[u8] = b"200101000000Z";
const NOT_AFTER: &[u8] = b"99991231235959Z";
const POINT_LEN: usize = 65;
const RAW_SIGNATURE_LEN: usize = 64;

pub(crate) fn subject_for(uid: u32) -> String {
    format!("CN=openhello-uid-{uid}")
}

fn subjects_for(uid: u32) -> [String; 2] {
    [subject_for(uid), format!("/{}", subject_for(uid))]
}

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    match content.len() {
        n if n < 0x80 => out.push(n as u8),
        n if n < 0x100 => out.extend([0x81, n as u8]),
        n => out.extend([0x82, (n >> 8) as u8, n as u8]),
    }
    out.extend_from_slice(content);
    out
}

fn der_integer(bytes: &[u8]) -> Vec<u8> {
    let start = bytes
        .iter()
        .position(|b| *b != 0)
        .unwrap_or(bytes.len() - 1);
    let mut value = bytes[start..].to_vec();
    if value[0] & 0x80 != 0 {
        value.insert(0, 0);
    }
    tlv(0x02, &value)
}

fn name(uid: u32) -> Vec<u8> {
    let attribute = [
        &OID_COMMON_NAME[..],
        &tlv(0x0c, subject_name(uid).as_bytes()),
    ]
    .concat();
    tlv(0x30, &tlv(0x31, &tlv(0x30, &attribute)))
}

fn subject_name(uid: u32) -> String {
    format!("openhello-uid-{uid}")
}

// pam_pkcs11/NSS rejected this self-signed certificate once basicConstraints CA:FALSE or keyUsage was added, so it has no extensions.
pub(crate) fn tbs_certificate(uid: u32, public_key: &[u8]) -> Result<Vec<u8>, KeydError> {
    if public_key.len() != POINT_LEN || public_key[0] != 0x04 {
        return Err(failure(
            "building the certificate",
            "public key is not an uncompressed P-256 point",
            &[],
        ));
    }
    let mut serial =
        Sha256::digest([subject_name(uid).as_bytes(), public_key].concat())[..16].to_vec();
    serial[0] = (serial[0] & 0x3f) | 0x40;
    let validity = tlv(
        0x30,
        &[tlv(0x17, NOT_BEFORE), tlv(0x18, NOT_AFTER)].concat(),
    );
    let spki = [&SECP256R1_SPKI_PREFIX[..], public_key].concat();
    let body = [
        &tlv(0xa0, &tlv(0x02, &[2]))[..],
        &tlv(0x02, &serial),
        &ECDSA_SHA256_ALGORITHM,
        &name(uid),
        &validity,
        &name(uid),
        &spki,
    ]
    .concat();
    Ok(tlv(0x30, &body))
}

pub(crate) fn tbs_digest(tbs: &[u8]) -> [u8; 32] {
    Sha256::digest(tbs).into()
}

pub(crate) fn assemble(tbs: &[u8], raw_signature: &[u8]) -> Result<Vec<u8>, KeydError> {
    if raw_signature.len() != RAW_SIGNATURE_LEN {
        return Err(failure(
            "building the certificate",
            "signature is not a raw P-256 r||s",
            &[],
        ));
    }
    let (r, s) = raw_signature.split_at(RAW_SIGNATURE_LEN / 2);
    let der_signature = tlv(0x30, &[der_integer(r), der_integer(s)].concat());
    let bit_string = tlv(0x03, &[&[0u8][..], &der_signature].concat());
    Ok(tlv(
        0x30,
        &[tbs, &ECDSA_SHA256_ALGORITHM, &bit_string].concat(),
    ))
}

pub(crate) fn pem(der: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::new();
    for chunk in der.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |acc, (i, b)| acc | u32::from(*b) << (16 - 8 * i));
        for i in 0..4 {
            if i <= chunk.len() {
                encoded.push(ALPHABET[(n >> (18 - 6 * i) & 0x3f) as usize] as char);
            } else {
                encoded.push('=');
            }
        }
    }
    let lines: Vec<&str> = encoded
        .as_bytes()
        .chunks(64)
        .map(|c| std::str::from_utf8(c).expect("base64 is ASCII"))
        .collect();
    format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        lines.join("\n")
    )
}

pub(crate) fn linux_user_name(uid: u32) -> Option<String> {
    let mut buffer = vec![0u8; 4096];
    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    let mut found: *mut libc::passwd = std::ptr::null_mut();
    let rc = unsafe {
        libc::getpwuid_r(
            uid,
            &mut entry,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut found,
        )
    };
    if rc != 0 || found.is_null() {
        return None;
    }
    let name = unsafe { CStr::from_ptr(entry.pw_name) };
    name.to_str().ok().map(str::to_string)
}

fn valid_user_name(user: &str) -> bool {
    !user.is_empty()
        && !user.starts_with('-')
        && user
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'$'))
}

fn subject_of(line: &str) -> Option<&str> {
    line.split_once(MAPPING_SEPARATOR)
        .map(|(subject, _)| subject)
}

fn read_lines(path: &Path) -> Result<Vec<String>, KeydError> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(text.lines().map(str::to_string).collect()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(failure("reading the mapping file", &e.to_string(), &[])),
    }
}

fn write_atomically(path: &Path, lines: &[String]) -> Result<(), KeydError> {
    let io = |e: std::io::Error| failure("writing the mapping file", &e.to_string(), &[]);
    let dir = path.parent().filter(|d| !d.as_os_str().is_empty());
    if let Some(dir) = dir {
        std::fs::create_dir_all(dir).map_err(io)?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755)).map_err(io)?;
    }
    let mut temp = path.as_os_str().to_owned();
    temp.push(format!(".tmp{}", std::process::id()));
    let temp = std::path::PathBuf::from(temp);
    let _ = std::fs::remove_file(&temp);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(MAPFILE_MODE)
        .open(&temp)
        .map_err(io)?;
    let written = (|| {
        file.set_permissions(std::fs::Permissions::from_mode(MAPFILE_MODE))?;
        for line in lines {
            writeln!(file, "{line}")?;
        }
        file.sync_all()?;
        std::fs::rename(&temp, path)
    })();
    if let Err(e) = written {
        let _ = std::fs::remove_file(&temp);
        return Err(io(e));
    }
    if let Some(dir) = dir {
        let _ = std::fs::File::open(dir).and_then(|d| d.sync_all());
    }
    Ok(())
}

pub(crate) fn upsert_mapping(path: &Path, uid: u32, user: &str) -> Result<(), KeydError> {
    if !valid_user_name(user) {
        return Err(failure(
            "recording the certificate mapping",
            "the Linux user name has characters the mapping file cannot hold",
            &[],
        ));
    }
    let subjects = subjects_for(uid);
    let wanted = subjects
        .clone()
        .map(|s| format!("{s}{MAPPING_SEPARATOR}{user}"));
    let lines = read_lines(path)?;
    let mode_ok = std::fs::metadata(path)
        .map(|m| m.permissions().mode() & 0o7777 == MAPFILE_MODE)
        .unwrap_or(false);
    let own = |l: &String| subject_of(l).is_some_and(|s| subjects.iter().any(|w| w == s));
    if mode_ok && lines.iter().filter(|l| own(l)).eq(wanted.iter()) {
        return Ok(());
    }
    let mut updated: Vec<String> = lines.into_iter().filter(|l| !own(l)).collect();
    updated.extend(wanted);
    write_atomically(path, &updated)
}

pub(crate) fn remove_mapping(path: &Path, uid: u32) -> Result<(), KeydError> {
    let subjects = subjects_for(uid);
    let lines = read_lines(path)?;
    let kept: Vec<String> = lines
        .iter()
        .filter(|l| !subject_of(l).is_some_and(|s| subjects.iter().any(|w| w == s)))
        .cloned()
        .collect();
    if kept.len() == lines.len() {
        return Ok(());
    }
    write_atomically(path, &kept)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pem_encodes_with_padding_and_wraps_lines() {
        assert_eq!(
            pem(b"hello"),
            "-----BEGIN CERTIFICATE-----\naGVsbG8=\n-----END CERTIFICATE-----\n"
        );
        assert!(pem(&[0xff; 100]).lines().nth(1).unwrap().len() == 64);
    }

    #[test]
    fn der_integers_are_minimal_and_positive() {
        assert_eq!(der_integer(&[0, 0, 0x7f]), [2, 1, 0x7f]);
        assert_eq!(der_integer(&[0x80, 1]), [2, 3, 0, 0x80, 1]);
        assert_eq!(der_integer(&[0, 0]), [2, 1, 0]);
    }

    #[test]
    // @covers:AC-027-subject-map
    fn mapping_is_idempotent_replaces_and_removes_only_its_subject() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub/map");
        upsert_mapping(&path, 1000, "ana").unwrap();
        upsert_mapping(&path, 1001, "bia").unwrap();
        upsert_mapping(&path, 1000, "ana").unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "CN=openhello-uid-1000 -> ana\n/CN=openhello-uid-1000 -> ana\n\
             CN=openhello-uid-1001 -> bia\n/CN=openhello-uid-1001 -> bia\n"
        );
        upsert_mapping(&path, 1000, "ana2").unwrap();
        remove_mapping(&path, 1001).unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "CN=openhello-uid-1000 -> ana2\n/CN=openhello-uid-1000 -> ana2\n"
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o7777,
            0o644
        );
        assert!(upsert_mapping(&path, 5, "a b\nc").is_err());
        remove_mapping(&dir.path().join("absent"), 1).unwrap();
    }
}
