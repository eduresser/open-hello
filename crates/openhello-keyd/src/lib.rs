mod protector;
mod provision;
mod ticket_socket;
mod tpm;

pub use protector::{LockoutPolicy, Protectors, RecoveryCode};
pub use provision::{KeyAttribute, KeyInfo, Keyd, Provisioned, TpmAttributes};
pub use ticket_socket::{
    TicketSocket, TicketSocketConfig, OP_TICKET, OP_TICKET_KEY, STATUS_ACCEPTED, STATUS_REFUSED,
};
pub use tpm::KeydConfig;

use openhello_ticket::TicketError;
use thiserror::Error;
use zeroize::Zeroizing;

const MAX_UID: u32 = 0xFFFF;
const SECRET_MAX_LEN: usize = 64;

#[derive(Debug, Error)]
pub enum KeydError {
    #[error("uid {0} is outside the supported range (0..=65535)")]
    InvalidUid(u32),
    #[error("secret must be 1 to 64 ASCII letters or digits")]
    InvalidSecret,
    #[error("invalid configuration: {0}")]
    Config(String),
    #[error("no key is provisioned for this user")]
    NotProvisioned,
    #[error("the secret was not accepted")]
    AuthenticationFailed,
    #[error("PIN must be 6 to 32 printable ASCII characters")]
    InvalidPin,
    #[error("this user already has a key and protectors")]
    AlreadyProvisioned,
    #[error("no PIN is set for this user")]
    PinNotSet,
    #[error("the TPM is locked out after too many wrong attempts; try again later")]
    LockedOut,
    #[error("{0}")]
    Ticket(TicketError),
    #[error("private key material cannot be read or exported")]
    Refused,
    #[error("TPM operation failed")]
    Tpm,
}

pub struct Secret(Zeroizing<String>);

impl Secret {
    pub fn new(value: impl Into<String>) -> Result<Self, KeydError> {
        let value = Zeroizing::new(value.into());
        if value.is_empty()
            || value.len() > SECRET_MAX_LEN
            || !value.bytes().all(|b| b.is_ascii_alphanumeric())
        {
            return Err(KeydError::InvalidSecret);
        }
        Ok(Self(value))
    }

    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

pub(crate) fn validate_uid(uid: u32) -> Result<u32, KeydError> {
    if uid > MAX_UID {
        return Err(KeydError::InvalidUid(uid));
    }
    Ok(uid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_is_validated_and_never_printed() {
        assert!(matches!(Secret::new(""), Err(KeydError::InvalidSecret)));
        assert!(matches!(Secret::new("a b"), Err(KeydError::InvalidSecret)));
        assert!(matches!(
            Secret::new("x".repeat(65)),
            Err(KeydError::InvalidSecret)
        ));
        let secret = Secret::new("abc123").unwrap();
        assert_eq!(format!("{secret:?}"), "Secret(<redacted>)");
    }

    #[test]
    fn uid_range_is_enforced() {
        assert_eq!(validate_uid(1000).unwrap(), 1000);
        assert!(matches!(
            validate_uid(0x1_0000),
            Err(KeydError::InvalidUid(_))
        ));
    }
}
