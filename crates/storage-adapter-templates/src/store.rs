use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use crate::tpm_key::{ensure_private_dir, TpmConfig, TpmKeyStore};
use crate::StorageError;

const MAGIC: &[u8; 4] = b"OHT1";
const EXTENSION: &str = "tpl";

pub struct TemplateStore {
    root: PathBuf,
    keys: TpmKeyStore,
}

impl TemplateStore {
    pub fn open(root: &Path, tpm: TpmConfig) -> Result<Self, StorageError> {
        ensure_private_dir(root)?;
        Ok(Self { root: root.to_path_buf(), keys: TpmKeyStore::new(tpm) })
    }

    pub fn template_path(&self, uid: u32) -> PathBuf {
        self.root.join(format!("{uid}.{EXTENSION}"))
    }

    pub fn put(&self, uid: u32, template: &[u8]) -> Result<(), StorageError> {
        if !self.keys.exists(uid)? {
            self.keys.create(uid)?;
        }
        let blob = self.keys.encrypt(uid, &associated_data(uid), template)?;
        let mut file_bytes = MAGIC.to_vec();
        file_bytes.extend(blob);
        self.write_atomically(uid, &file_bytes)
    }

    pub fn get(&self, uid: u32) -> Result<Vec<u8>, StorageError> {
        let bytes = fs::read(self.template_path(uid)).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => StorageError::NotFound,
            _ => StorageError::Io(e.to_string()),
        })?;
        let blob = bytes.strip_prefix(MAGIC.as_slice()).ok_or(StorageError::AuthenticationFailed)?;
        self.keys.decrypt(uid, &associated_data(uid), blob)
    }

    pub fn enrolled_uids(&self) -> Result<Vec<u32>, StorageError> {
        let mut uids: Vec<u32> = fs::read_dir(&self.root)
            .map_err(|e| StorageError::Io(e.to_string()))?
            .filter_map(Result::ok)
            .filter_map(|entry| {
                let path = entry.path();
                (path.extension()? == EXTENSION).then(|| path.file_stem()?.to_str()?.parse().ok())?
            })
            .collect();
        uids.sort_unstable();
        Ok(uids)
    }

    pub fn probe(&self) -> Result<(), StorageError> {
        self.keys.probe()
    }

    pub(crate) fn keys(&self) -> &TpmKeyStore {
        &self.keys
    }

    fn write_atomically(&self, uid: u32, bytes: &[u8]) -> Result<(), StorageError> {
        let temporary = self.root.join(format!(".{uid}.{EXTENSION}.tmp"));
        let io = |e: std::io::Error| StorageError::Io(e.to_string());
        let mut file = fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&temporary).map_err(io)?;
        file.write_all(bytes).map_err(io)?;
        file.sync_all().map_err(io)?;
        fs::rename(&temporary, self.template_path(uid)).map_err(io)
    }
}

fn associated_data(uid: u32) -> Vec<u8> {
    let mut aad = MAGIC.to_vec();
    aad.extend(uid.to_le_bytes());
    aad
}
