use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use zeroize::Zeroizing;

use crate::StorageError;

const PERSISTENT_HANDLE_BASE: u32 = 0x8108_0000;
const MAX_UID: u32 = 0xFFFF;
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;

#[derive(Debug, Clone, Default)]
pub struct TpmConfig {
    pub tcti: Option<String>,
}

pub struct TpmKeyStore {
    config: TpmConfig,
}

impl TpmKeyStore {
    pub fn new(config: TpmConfig) -> Self {
        Self { config }
    }

    pub fn exists(&self, uid: u32) -> Result<bool, StorageError> {
        let handle = persistent_handle(uid)?;
        let listing = self.run("tpm2_getcap", &["handles-persistent"], None)?;
        let wanted = format!("0x{handle:X}");
        Ok(String::from_utf8_lossy(&listing).lines().any(|line| line.trim_start_matches("- ").trim().eq_ignore_ascii_case(&wanted)))
    }

    pub fn create(&self, uid: u32) -> Result<(), StorageError> {
        let handle = persistent_handle(uid)?;
        if self.exists(uid)? {
            return Err(StorageError::Tpm(format!("a TPM key already exists for uid {uid}")));
        }
        let mut secret = Zeroizing::new([0u8; KEY_LEN]);
        getrandom::getrandom(secret.as_mut()).map_err(|e| StorageError::Tpm(format!("random source unavailable: {e}")))?;

        let dir = tempfile::tempdir().map_err(|e| StorageError::Io(e.to_string()))?;
        let path = |name: &str| dir.path().join(name).display().to_string();
        let (primary, public, private, loaded) = (path("primary.ctx"), path("key.pub"), path("key.priv"), path("key.ctx"));

        let outcome = (|| {
            self.flush();
            self.run("tpm2_createprimary", &["-C", "o", "-c", &primary], None)?;
            self.run("tpm2_create", &["-C", &primary, "-u", &public, "-r", &private, "-i-"], Some(secret.as_ref()))?;
            self.flush();
            self.run("tpm2_load", &["-C", &primary, "-u", &public, "-r", &private, "-c", &loaded], None)?;
            self.run("tpm2_evictcontrol", &["-C", "o", "-c", &loaded, &format!("0x{handle:X}")], None)?;
            Ok(())
        })();
        self.flush();
        outcome
    }

    pub fn encrypt(&self, uid: u32, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, StorageError> {
        let key = self.unseal(uid)?;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key.as_ref()));
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::getrandom(&mut nonce).map_err(|e| StorageError::Tpm(format!("random source unavailable: {e}")))?;
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad })
            .map_err(|_| StorageError::Tpm("encryption failed".into()))?;
        let mut blob = nonce.to_vec();
        blob.extend(ciphertext);
        Ok(blob)
    }

    pub fn decrypt(&self, uid: u32, aad: &[u8], blob: &[u8]) -> Result<Vec<u8>, StorageError> {
        if blob.len() < NONCE_LEN {
            return Err(StorageError::AuthenticationFailed);
        }
        let key = self.unseal(uid)?;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key.as_ref()));
        let (nonce, ciphertext) = blob.split_at(NONCE_LEN);
        cipher
            .decrypt(Nonce::from_slice(nonce), Payload { msg: ciphertext, aad })
            .map_err(|_| StorageError::AuthenticationFailed)
    }

    pub fn destroy(&self, uid: u32) -> Result<(), StorageError> {
        let handle = persistent_handle(uid)?;
        if !self.exists(uid)? {
            return Err(StorageError::NotFound);
        }
        self.run("tpm2_evictcontrol", &["-C", "o", "-c", &format!("0x{handle:X}")], None)?;
        Ok(())
    }

    fn unseal(&self, uid: u32) -> Result<Zeroizing<Vec<u8>>, StorageError> {
        let handle = persistent_handle(uid)?;
        if !self.exists(uid)? {
            return Err(StorageError::NotFound);
        }
        let secret = Zeroizing::new(self.run("tpm2_unseal", &["-c", &format!("0x{handle:X}")], None)?);
        self.flush();
        if secret.len() != KEY_LEN {
            return Err(StorageError::Tpm("sealed key has unexpected length".into()));
        }
        Ok(secret)
    }

    fn flush(&self) {
        let _ = self.run("tpm2_flushcontext", &["-t"], None);
    }

    fn run(&self, tool: &str, args: &[&str], stdin: Option<&[u8]>) -> Result<Vec<u8>, StorageError> {
        let mut command = Command::new(tool);
        command.args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
        if let Some(tcti) = &self.config.tcti {
            command.env("TPM2TOOLS_TCTI", tcti);
        }
        let mut child = command.spawn().map_err(|e| StorageError::Tpm(format!("cannot run {tool}: {e}")))?;
        if let Some(mut pipe) = child.stdin.take() {
            if let Some(data) = stdin {
                pipe.write_all(data).map_err(|e| StorageError::Tpm(format!("{tool} stdin: {e}")))?;
            }
        }
        let output = child.wait_with_output().map_err(|e| StorageError::Tpm(format!("{tool}: {e}")))?;
        if !output.status.success() {
            let detail = String::from_utf8_lossy(&output.stderr);
            let last = detail.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("no diagnostic output");
            return Err(StorageError::Tpm(format!("{tool} failed: {last}")));
        }
        Ok(output.stdout)
    }
}

fn persistent_handle(uid: u32) -> Result<u32, StorageError> {
    if uid > MAX_UID {
        return Err(StorageError::InvalidUid(uid));
    }
    Ok(PERSISTENT_HANDLE_BASE | uid)
}

pub fn ensure_private_dir(path: &Path) -> Result<(), StorageError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(path).map_err(|e| StorageError::Io(e.to_string()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).map_err(|e| StorageError::Io(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persistent_handles_are_per_uid_and_bounded() {
        assert_eq!(persistent_handle(1000).unwrap(), 0x8108_03E8);
        assert!(matches!(persistent_handle(0x1_0000), Err(StorageError::InvalidUid(_))));
    }

    #[test]
    fn missing_tpm_tools_surface_a_tpm_error() {
        let store = TpmKeyStore::new(TpmConfig { tcti: Some("device:/dev/openhello-no-tpm".into()) });
        assert!(matches!(store.exists(1000), Err(StorageError::Tpm(_))));
    }
}
