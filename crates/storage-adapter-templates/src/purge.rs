use std::fs;

use crate::{StorageError, TemplateStore};

impl TemplateStore {
    pub fn purge(&self, uid: u32) -> Result<(), StorageError> {
        match self.keys().destroy(uid) {
            Ok(()) | Err(StorageError::NotFound) => {}
            Err(error) => return Err(error),
        }
        match fs::remove_file(self.template_path(uid)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(StorageError::Io(e.to_string())),
        }
    }
}
