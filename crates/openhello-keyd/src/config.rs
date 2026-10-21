use std::path::PathBuf;

use crate::logging::Level;
use crate::{KeydConfig, TicketSocketConfig, TokenSocketConfig, UnlockSocketConfig};

pub const DEFAULT_TICKET_SOCKET: &str = "/run/openhello/keyd-ticket.sock";
pub const DEFAULT_UNLOCK_SOCKET: &str = "/run/openhello/keyd-unlock.sock";
pub const DEFAULT_TOKEN_SOCKET: &str = "/run/openhello/keyd-token.sock";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BusKind {
    System,
    Session,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    Polkit,
    RootOnly,
}

#[derive(Debug)]
pub struct DaemonConfig {
    pub keyd: KeydConfig,
    pub ticket: TicketSocketConfig,
    pub unlock: UnlockSocketConfig,
    pub token: TokenSocketConfig,
    pub bus: BusKind,
    pub auth: AuthMode,
    pub log_level: Level,
}

impl DaemonConfig {
    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let get = |name: &str| lookup(name).filter(|v| !v.is_empty());
        let store = get("OPENHELLO_KEYD_STORE_DIR")
            .ok_or("OPENHELLO_KEYD_STORE_DIR must name the token store directory")?;
        let mut keyd = KeydConfig::new(store);
        keyd.tcti = get("OPENHELLO_KEYD_TCTI");
        if let Some(mapfile) = get("OPENHELLO_KEYD_MAPFILE") {
            keyd.mapfile = PathBuf::from(mapfile);
        }
        if let Some(dir) = get("OPENHELLO_KEYD_AUTH_DIR") {
            keyd.auth_dir = PathBuf::from(dir);
        }
        keyd.prefix = get("OPENHELLO_TPM2_PKCS11_PREFIX").map(PathBuf::from);
        keyd.module = get("OPENHELLO_TPM2_PKCS11_MODULE").map(PathBuf::from);
        keyd.nss_dir = get("OPENHELLO_KEYD_NSS_DIR").map(PathBuf::from);
        keyd.certutil = get("OPENHELLO_KEYD_CERTUTIL").map(PathBuf::from);
        let allowed_uid = match get("OPENHELLO_KEYD_TICKET_UID") {
            None => 0,
            Some(text) => text.parse().map_err(|_| {
                format!("OPENHELLO_KEYD_TICKET_UID must be a numeric uid, got `{text}`")
            })?,
        };
        let ticket = TicketSocketConfig {
            path: get("OPENHELLO_KEYD_TICKET_SOCKET")
                .unwrap_or_else(|| DEFAULT_TICKET_SOCKET.into())
                .into(),
            allowed_uid,
            expected_exe: get("OPENHELLO_KEYD_TICKET_EXE").map(PathBuf::from),
        };
        let unlock = UnlockSocketConfig {
            path: get("OPENHELLO_KEYD_UNLOCK_SOCKET")
                .unwrap_or_else(|| DEFAULT_UNLOCK_SOCKET.into())
                .into(),
        };
        let token = TokenSocketConfig {
            path: get("OPENHELLO_KEYD_TOKEN_SOCKET")
                .unwrap_or_else(|| DEFAULT_TOKEN_SOCKET.into())
                .into(),
        };
        let bus = match get("OPENHELLO_KEYD_BUS").as_deref() {
            None | Some("system") => BusKind::System,
            Some("session") => BusKind::Session,
            Some(other) => {
                return Err(format!(
                    "OPENHELLO_KEYD_BUS must be `system` or `session`, got `{other}`"
                ))
            }
        };
        let auth = match get("OPENHELLO_KEYD_AUTH").as_deref() {
            None | Some("polkit") => AuthMode::Polkit,
            Some("root-only") => AuthMode::RootOnly,
            Some(other) => {
                return Err(format!(
                    "OPENHELLO_KEYD_AUTH must be `polkit` or `root-only`, got `{other}`"
                ))
            }
        };
        let log_level = match get("OPENHELLO_KEYD_LOG_LEVEL") {
            None => Level::Info,
            Some(text) => Level::parse(&text).ok_or_else(|| {
                format!(
                    "OPENHELLO_KEYD_LOG_LEVEL must be error|warn|info|debug|trace, got `{text}`"
                )
            })?,
        };
        if ticket.path == unlock.path || ticket.path == token.path || unlock.path == token.path {
            return Err("the ticket, unlock and token sockets must use different paths".into());
        }
        Ok(Self {
            keyd,
            ticket,
            unlock,
            token,
            bus,
            auth,
            log_level,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lookup<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |name| {
            pairs
                .iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| v.to_string())
        }
    }

    #[test]
    fn defaults_are_secure_and_the_store_is_required() {
        let config =
            DaemonConfig::from_lookup(lookup(&[("OPENHELLO_KEYD_STORE_DIR", "/var/lib/k")]))
                .unwrap();
        assert_eq!(config.bus, BusKind::System);
        assert_eq!(config.auth, AuthMode::Polkit);
        assert_eq!(config.ticket.allowed_uid, 0);
        assert_eq!(config.ticket.path, PathBuf::from(DEFAULT_TICKET_SOCKET));
        assert_eq!(config.token.path, PathBuf::from(DEFAULT_TOKEN_SOCKET));
        assert!(DaemonConfig::from_lookup(lookup(&[]))
            .unwrap_err()
            .contains("OPENHELLO_KEYD_STORE_DIR"));
    }

    #[test]
    fn invalid_values_are_rejected_with_the_variable_name() {
        for (name, value) in [
            ("OPENHELLO_KEYD_BUS", "mars"),
            ("OPENHELLO_KEYD_AUTH", "none"),
            ("OPENHELLO_KEYD_TICKET_UID", "root"),
            ("OPENHELLO_KEYD_LOG_LEVEL", "loud"),
        ] {
            let error = DaemonConfig::from_lookup(lookup(&[
                ("OPENHELLO_KEYD_STORE_DIR", "/s"),
                (name, value),
            ]))
            .unwrap_err();
            assert!(error.contains(name), "{error}");
        }
        let same = DaemonConfig::from_lookup(lookup(&[
            ("OPENHELLO_KEYD_STORE_DIR", "/s"),
            ("OPENHELLO_KEYD_TICKET_SOCKET", "/run/x"),
            ("OPENHELLO_KEYD_UNLOCK_SOCKET", "/run/x"),
        ]));
        assert!(same.unwrap_err().contains("different paths"));
        let clash = DaemonConfig::from_lookup(lookup(&[
            ("OPENHELLO_KEYD_STORE_DIR", "/s"),
            ("OPENHELLO_KEYD_TOKEN_SOCKET", "/run/y"),
            ("OPENHELLO_KEYD_UNLOCK_SOCKET", "/run/y"),
        ]));
        assert!(clash.unwrap_err().contains("different paths"));
    }
}
