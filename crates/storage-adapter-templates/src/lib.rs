mod store;
mod tpm_key;

pub use store::TemplateStore;
pub use tpm_key::{TpmConfig, TpmKeyStore};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("no template stored")]
    NotFound,
    #[error("stored template failed authentication")]
    AuthenticationFailed,
    #[error("TPM operation failed: {0}")]
    Tpm(String),
    #[error("storage I/O failed: {0}")]
    Io(String),
    #[error("uid {0} is outside the supported range (0..=65535)")]
    InvalidUid(u32),
}
