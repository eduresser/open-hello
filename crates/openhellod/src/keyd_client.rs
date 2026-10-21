use zbus::blocking::{connection::Builder, Connection, Proxy};

pub const BUS_ENV: &str = "OPENHELLO_KEYD_PURGE_BUS";
const KEYD_BUS_NAME: &str = "io.openhello.Keyd1";
const KEYD_OBJECT_PATH: &str = "/io/openhello/Keyd1";
const KEYD_INTERFACE: &str = "io.openhello.Keyd1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyPurge {
    Destroyed,
    Failed,
    Unavailable,
}

impl KeyPurge {
    pub fn as_str(self) -> &'static str {
        match self {
            KeyPurge::Destroyed => "destroyed",
            KeyPurge::Failed => "failed",
            KeyPurge::Unavailable => "unavailable",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeydBus {
    System,
    Session,
    Address(String),
}

pub struct KeydClient {
    bus: KeydBus,
}

impl KeydClient {
    pub fn new(bus: KeydBus) -> Self {
        Self { bus }
    }

    pub fn from_env() -> Option<Self> {
        let value = std::env::var(BUS_ENV).ok().filter(|v| !v.is_empty())?;
        Some(Self::new(match value.as_str() {
            "system" => KeydBus::System,
            "session" => KeydBus::Session,
            _ => KeydBus::Address(value),
        }))
    }

    pub fn purge(&self, uid: u32) -> KeyPurge {
        let Ok(connection) = self.connect() else {
            return KeyPurge::Unavailable;
        };
        let Ok(proxy) = Proxy::new(&connection, KEYD_BUS_NAME, KEYD_OBJECT_PATH, KEYD_INTERFACE)
        else {
            return KeyPurge::Unavailable;
        };
        match proxy.call::<_, _, bool>("Purge", &(uid,)) {
            Ok(true) => KeyPurge::Destroyed,
            Err(zbus::Error::MethodError(name, ..)) if is_missing_service(name.as_str()) => {
                KeyPurge::Unavailable
            }
            Ok(false) | Err(zbus::Error::MethodError(..) | zbus::Error::FDO(_)) => KeyPurge::Failed,
            Err(_) => KeyPurge::Unavailable,
        }
    }

    fn connect(&self) -> zbus::Result<Connection> {
        match &self.bus {
            KeydBus::System => Builder::system()?.build(),
            KeydBus::Session => Builder::session()?.build(),
            KeydBus::Address(address) => Builder::address(address.as_str())?.build(),
        }
    }
}

fn is_missing_service(error_name: &str) -> bool {
    error_name.ends_with(".ServiceUnknown") || error_name.ends_with(".NameHasNoOwner")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_variable_turns_the_key_purge_off_and_values_select_the_bus() {
        std::env::remove_var(BUS_ENV);
        assert!(KeydClient::from_env().is_none());
        std::env::set_var(BUS_ENV, "session");
        assert_eq!(KeydClient::from_env().unwrap().bus, KeydBus::Session);
        std::env::set_var(BUS_ENV, "unix:path=/run/x");
        assert_eq!(
            KeydClient::from_env().unwrap().bus,
            KeydBus::Address("unix:path=/run/x".into())
        );
        std::env::remove_var(BUS_ENV);
    }

    #[test]
    fn an_unreachable_bus_is_unavailable() {
        let client = KeydClient::new(KeydBus::Address("unix:path=/nonexistent/bus".into()));
        assert_eq!(client.purge(1000), KeyPurge::Unavailable);
    }
}
