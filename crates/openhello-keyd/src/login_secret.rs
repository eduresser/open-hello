use std::fs::DirBuilder;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::certificate::linux_user_name;
use crate::protector::{seal_object, unseal_object};
use crate::tpm::failure;
use crate::{validate_uid, KeydConfig, KeydError};

const LOGIN_SECRETS_DIR: &str = "login-secrets";
const KEY_FILE: &str = "key.blob";
const SECRET_FILE: &str = "secret.bin";
const SHADOW_FILE: &str = "/etc/shadow";
const MAGIC: &[u8; 4] = b"OHLS";
const VERSION: u8 = 1;
const KEY_LEN: usize = 32;
const FINGERPRINT_LEN: usize = 32;
const NONCE_LEN: usize = 24;
const HEADER_LEN: usize = MAGIC.len() + 1 + FINGERPRINT_LEN + NONCE_LEN;
const PASSWORD_MAX: usize = 512;

struct Keys {
    material: Zeroizing<Vec<u8>>,
}

impl Keys {
    fn generate() -> Result<Self, KeydError> {
        let mut material = Zeroizing::new(vec![0u8; KEY_LEN * 2]);
        getrandom::getrandom(&mut material)
            .map_err(|e| failure("gathering randomness", &e.to_string(), &[]))?;
        Ok(Self { material })
    }

    fn from_unsealed(material: Zeroizing<Vec<u8>>) -> Result<Self, KeydError> {
        if material.len() != KEY_LEN * 2 {
            return Err(failure(
                "unsealing the login secret key",
                "sealed key has an unexpected length",
                &[],
            ));
        }
        Ok(Self { material })
    }

    fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new_from_slice(&self.material[..KEY_LEN]).expect("32-byte key")
    }

    fn mac(&self, uid: u32, shadow_entry: &str) -> Hmac<Sha256> {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.material[KEY_LEN..])
            .expect("any key length");
        mac.update(&uid.to_be_bytes());
        mac.update(shadow_entry.as_bytes());
        mac
    }
}

pub struct LoginSecrets {
    config: KeydConfig,
    lock: Mutex<()>,
}

impl LoginSecrets {
    pub fn new(config: KeydConfig) -> Self {
        Self {
            config,
            lock: Mutex::new(()),
        }
    }

    pub fn seal(&self, uid: u32, password: &str, shadow_entry: &str) -> Result<(), KeydError> {
        let uid = validate_uid(uid)?;
        if password.is_empty() || password.len() > PASSWORD_MAX || password.contains('\0') {
            return Err(KeydError::InvalidPassword);
        }
        if shadow_entry.is_empty() {
            return Err(KeydError::NoShadowEntry);
        }
        let _lock = self.lock.lock().unwrap_or_else(PoisonError::into_inner);
        self.prepare_dir(uid)?;
        let dir = self.user_dir(uid);
        let keys = match read_optional(&dir.join(KEY_FILE))? {
            Some(blob) => Keys::from_unsealed(unseal_object(&self.config, &blob, None)?)?,
            None => {
                let keys = Keys::generate()?;
                let blob = seal_object(&self.config, &keys.material, None, true)?;
                write_atomically(&dir, KEY_FILE, &blob)?;
                keys
            }
        };
        let fingerprint = keys.mac(uid, shadow_entry).finalize().into_bytes();
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::getrandom(&mut nonce)
            .map_err(|e| failure("gathering randomness", &e.to_string(), &[]))?;
        let mut header = MAGIC.to_vec();
        header.push(VERSION);
        header.extend_from_slice(&fingerprint);
        header.extend_from_slice(&nonce);
        let ciphertext = keys
            .cipher()
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: password.as_bytes(),
                    aad: &associated_data(uid, &header),
                },
            )
            .map_err(|_| failure("encrypting the login secret", "AEAD failure", &[]))?;
        header.extend_from_slice(&ciphertext);
        write_atomically(&dir, SECRET_FILE, &header)
    }

    pub fn release(
        &self,
        uid: u32,
        current_shadow_entry: &str,
    ) -> Result<Option<Zeroizing<String>>, KeydError> {
        let uid = validate_uid(uid)?;
        let _lock = self.lock.lock().unwrap_or_else(PoisonError::into_inner);
        let dir = self.user_dir(uid);
        let Some(stored) = read_optional(&dir.join(SECRET_FILE))? else {
            return Ok(None);
        };
        let Some(blob) = read_optional(&dir.join(KEY_FILE))? else {
            self.destroy(uid)?;
            return Ok(None);
        };
        if stored.len() < HEADER_LEN
            || &stored[..MAGIC.len()] != MAGIC
            || stored[MAGIC.len()] != VERSION
        {
            return Err(KeydError::LoginSecretDamaged);
        }
        let keys = Keys::from_unsealed(unseal_object(&self.config, &blob, None)?)?;
        let (header, ciphertext) = stored.split_at(HEADER_LEN);
        let fingerprint = &header[MAGIC.len() + 1..MAGIC.len() + 1 + FINGERPRINT_LEN];
        if current_shadow_entry.is_empty()
            || keys
                .mac(uid, current_shadow_entry)
                .verify_slice(fingerprint)
                .is_err()
        {
            self.destroy(uid)?;
            return Ok(None);
        }
        let mut plaintext = Zeroizing::new(
            keys.cipher()
                .decrypt(
                    XNonce::from_slice(&header[HEADER_LEN - NONCE_LEN..]),
                    Payload {
                        msg: ciphertext,
                        aad: &associated_data(uid, header),
                    },
                )
                .map_err(|_| KeydError::LoginSecretDamaged)?,
        );
        match String::from_utf8(std::mem::take(&mut *plaintext)) {
            Ok(password) => Ok(Some(Zeroizing::new(password))),
            Err(error) => {
                error.into_bytes().zeroize();
                Err(KeydError::LoginSecretDamaged)
            }
        }
    }

    pub fn purge(&self, uid: u32) -> Result<(), KeydError> {
        let uid = validate_uid(uid)?;
        let _lock = self.lock.lock().unwrap_or_else(PoisonError::into_inner);
        self.destroy(uid)
    }

    pub fn shadow_entry(&self, uid: u32) -> Result<Option<Zeroizing<String>>, KeydError> {
        let uid = validate_uid(uid)?;
        let resolve = self.config.user_name.unwrap_or(linux_user_name);
        match resolve(uid) {
            Some(user) => read_shadow_entry(Path::new(SHADOW_FILE), &user),
            None => Ok(None),
        }
    }

    // The key goes first so that a crash mid-purge never leaves a decryptable secret behind (P-008).
    fn destroy(&self, uid: u32) -> Result<(), KeydError> {
        let dir = self.user_dir(uid);
        shred(&dir.join(KEY_FILE))?;
        shred(&dir.join(SECRET_FILE))?;
        match std::fs::remove_dir_all(&dir) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(failure("deleting the login secret", &e.to_string(), &[])),
        }
    }

    fn user_dir(&self, uid: u32) -> PathBuf {
        self.config
            .store_dir
            .join(LOGIN_SECRETS_DIR)
            .join(uid.to_string())
    }

    fn prepare_dir(&self, uid: u32) -> Result<(), KeydError> {
        self.config.ensure_store_dir()?;
        let dir = self.user_dir(uid);
        for path in [dir.parent().unwrap_or(&dir), &dir] {
            DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(path)
                .map_err(|e| {
                    failure("preparing the login secret directory", &e.to_string(), &[])
                })?;
        }
        Ok(())
    }
}

pub fn read_shadow_entry(
    shadow: &Path,
    user: &str,
) -> Result<Option<Zeroizing<String>>, KeydError> {
    let text =
        Zeroizing::new(std::fs::read_to_string(shadow).map_err(|_| KeydError::NoShadowEntry)?);
    Ok(text
        .lines()
        .find(|line| line.split(':').next() == Some(user))
        .map(|line| Zeroizing::new(line.to_string())))
}

fn associated_data(uid: u32, header: &[u8]) -> Vec<u8> {
    let mut aad = header.to_vec();
    aad.extend_from_slice(&uid.to_be_bytes());
    aad
}

fn read_optional(path: &Path) -> Result<Option<Vec<u8>>, KeydError> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(failure("reading the login secret", &e.to_string(), &[])),
    }
}

fn write_atomically(dir: &Path, name: &str, bytes: &[u8]) -> Result<(), KeydError> {
    let io = |e: std::io::Error| failure("writing the login secret", &e.to_string(), &[]);
    let staging = dir.join(format!("{name}.new"));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&staging)
        .map_err(io)?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(io)?;
    std::fs::rename(&staging, dir.join(name)).map_err(io)?;
    std::fs::File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(io)
}

fn shred(path: &Path) -> Result<(), KeydError> {
    let io = |e: std::io::Error| failure("shredding the login secret", &e.to_string(), &[]);
    let len = match std::fs::metadata(path) {
        Ok(meta) => meta.len() as usize,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(io(e)),
    };
    std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .and_then(|mut f| f.write_all(&vec![0u8; len]).and_then(|_| f.sync_all()))
        .map_err(io)?;
    std::fs::remove_file(path).map_err(io)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shadow_entry_is_found_by_exact_user_name() {
        let dir = tempfile::tempdir().unwrap();
        let shadow = dir.path().join("shadow");
        std::fs::write(&shadow, "alice2:$6$x:1::\nalice:$6$y:2::\n").unwrap();
        assert_eq!(
            read_shadow_entry(&shadow, "alice")
                .unwrap()
                .as_deref()
                .map(String::as_str),
            Some("alice:$6$y:2::")
        );
        assert!(read_shadow_entry(&shadow, "bob").unwrap().is_none());
        assert!(matches!(
            read_shadow_entry(&dir.path().join("missing"), "alice"),
            Err(KeydError::NoShadowEntry)
        ));
    }
}
