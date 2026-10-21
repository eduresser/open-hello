use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use zbus::message::Header;
use zbus::{fdo, interface, Connection};
use zeroize::Zeroizing;

use crate::{KeydError, Protectors};

pub const BUS_NAME: &str = "io.openhello.Keyd1";
pub const OBJECT_PATH: &str = "/io/openhello/Keyd1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Provision,
    SetPin,
    Purge,
}

impl Action {
    pub fn polkit_id(self) -> &'static str {
        match self {
            Action::Provision => "io.openhello.keyd.provision",
            Action::SetPin => "io.openhello.keyd.set-pin",
            Action::Purge => "io.openhello.keyd.purge",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    pub bus_name: String,
    pub uid: u32,
}

pub type AuthFuture<'a> = Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;

pub trait Authorizer: Send + Sync {
    fn authorize<'a>(
        &'a self,
        action: Action,
        caller: &'a Caller,
        target_uid: u32,
    ) -> AuthFuture<'a>;
}

pub struct RootOnlyAuthorizer;

impl Authorizer for RootOnlyAuthorizer {
    fn authorize<'a>(&'a self, _: Action, caller: &'a Caller, _: u32) -> AuthFuture<'a> {
        Box::pin(async move {
            if caller.uid == 0 {
                Ok(())
            } else {
                Err("only root may perform this operation".to_string())
            }
        })
    }
}

pub struct Service {
    protectors: Arc<Protectors>,
    authorizer: Arc<dyn Authorizer>,
}

impl Service {
    pub fn new(protectors: Arc<Protectors>, authorizer: Arc<dyn Authorizer>) -> Self {
        Self {
            protectors,
            authorizer,
        }
    }

    async fn authorize(
        &self,
        conn: &Connection,
        header: &Header<'_>,
        action: Action,
        target_uid: u32,
    ) -> fdo::Result<()> {
        let caller = resolve_caller(conn, header).await?;
        self.authorizer
            .authorize(action, &caller, target_uid)
            .await
            .map_err(|reason| {
                eprintln!(
                    "openhello-keyd: authorization refused action={} caller_uid={} target_uid={target_uid}",
                    action.polkit_id(),
                    caller.uid
                );
                fdo::Error::AuthFailed(format!("{}: {reason}", action.polkit_id()))
            })
    }

    async fn run<T: Send + 'static>(
        &self,
        action: Action,
        uid: u32,
        operation: impl FnOnce(&Protectors) -> Result<T, KeydError> + Send + 'static,
    ) -> fdo::Result<T> {
        let protectors = self.protectors.clone();
        let outcome = blocking::unblock(move || operation(&protectors)).await;
        outcome.map_err(|error| {
            eprintln!(
                "openhello-keyd: {} failed for uid {uid}: {error}",
                action.polkit_id()
            );
            match error {
                KeydError::InvalidPin | KeydError::InvalidUid(_) | KeydError::InvalidSecret => {
                    fdo::Error::InvalidArgs(error.to_string())
                }
                _ => fdo::Error::Failed(error.to_string()),
            }
        })
    }
}

async fn resolve_caller(conn: &Connection, header: &Header<'_>) -> fdo::Result<Caller> {
    let sender = header
        .sender()
        .ok_or_else(|| fdo::Error::AuthFailed("message has no sender".into()))?;
    let dbus = fdo::DBusProxy::new(conn).await?;
    let uid = dbus.get_connection_unix_user(sender.clone().into()).await?;
    Ok(Caller {
        bus_name: sender.to_string(),
        uid,
    })
}

#[interface(name = "io.openhello.Keyd1")]
impl Service {
    async fn provision(
        &self,
        uid: u32,
        #[zbus(connection)] conn: &Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> fdo::Result<String> {
        self.authorize(conn, &header, Action::Provision, uid)
            .await?;
        let code = self
            .run(Action::Provision, uid, move |p| p.provision_protectors(uid))
            .await?;
        Ok(code.reveal().to_string())
    }

    async fn set_pin(
        &self,
        uid: u32,
        pin: String,
        #[zbus(connection)] conn: &Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> fdo::Result<bool> {
        let pin = Zeroizing::new(pin);
        self.authorize(conn, &header, Action::SetPin, uid).await?;
        self.run(Action::SetPin, uid, move |p| p.set_pin(uid, &pin))
            .await?;
        Ok(true)
    }

    async fn purge(
        &self,
        uid: u32,
        #[zbus(connection)] conn: &Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> fdo::Result<bool> {
        self.authorize(conn, &header, Action::Purge, uid).await?;
        self.run(Action::Purge, uid, move |p| p.purge(uid)).await?;
        Ok(true)
    }
}
