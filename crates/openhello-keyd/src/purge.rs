use std::io::Write;

use crate::provision::token_label;
use crate::tpm::failure;
use crate::tpm::lock;
use crate::{validate_uid, KeydError, Protectors};

impl Protectors {
    pub fn purge(&self, uid: u32) -> Result<(), KeydError> {
        let uid = validate_uid(uid)?;
        let _store = self
            .store
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.grants
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&uid);
        self.shred_protectors(uid)?;
        self.remove_token(uid)?;
        let _guard = lock();
        crate::certificate::remove_trusted(&self.config, uid)?;
        crate::certificate::remove_mapping(&self.config.mapfile, uid)
    }

    fn shred_protectors(&self, uid: u32) -> Result<(), KeydError> {
        let dir = self.user_dir(uid);
        for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            if let Ok(meta) = entry.metadata() {
                let zeros = vec![0u8; meta.len() as usize];
                let _ = std::fs::OpenOptions::new()
                    .write(true)
                    .open(entry.path())
                    .and_then(|mut f| f.write_all(&zeros).and_then(|_| f.sync_all()));
            }
        }
        match std::fs::remove_dir_all(&dir) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(failure("deleting the protectors", &e.to_string(), &[])),
        }
    }

    fn remove_token(&self, uid: u32) -> Result<(), KeydError> {
        let guard = lock();
        if !crate::tpm::store_file(&self.config.store_dir).exists() {
            return Ok(());
        }
        let label = token_label(uid);
        if self.config.inspect(&guard, &label)?.present {
            self.config
                .ptool(&guard, &["rmtoken", "--label", &label], &[])?;
        }
        guard.reset_module();
        Ok(())
    }
}
