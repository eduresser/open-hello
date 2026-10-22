use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use futures_lite::StreamExt;

use zbus::message::Header;
use zbus::{fdo, interface, Connection};

use crate::backends::DaemonError;
use crate::core::Biometrics;
use crate::logging::{Level, Logger, Value};

pub const BUS_NAME: &str = "io.openhello.Biometrics1";
pub const OBJECT_PATH: &str = "/io/openhello/Biometrics1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    EnrollBegin,
    EnrollCapture,
    EnrollCommit,
    EnrollDiscard,
    Purge,
}

impl Action {
    pub fn polkit_id(self) -> &'static str {
        match self {
            Action::EnrollBegin => "io.openhello.biometrics.enroll-begin",
            Action::EnrollCapture => "io.openhello.biometrics.enroll-capture",
            Action::EnrollCommit => "io.openhello.biometrics.enroll-commit",
            Action::EnrollDiscard => "io.openhello.biometrics.enroll-discard",
            Action::Purge => "io.openhello.biometrics.purge",
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
    fn authorize<'a>(&'a self, action: Action, caller: &'a Caller, target_uid: u32) -> AuthFuture<'a>;
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
    core: Arc<Mutex<Biometrics>>,
    authorizer: Arc<dyn Authorizer>,
    logger: Logger,
    enrollment_owners: Arc<Mutex<HashMap<String, zbus::Task<()>>>>,
}

struct CallerWatch {
    gone: Arc<AtomicBool>,
    _task: Option<zbus::Task<()>>,
}

impl CallerWatch {
    async fn start(conn: &Connection, header: &Header<'_>) -> Self {
        let gone = Arc::new(AtomicBool::new(false));
        let task = match header.sender() {
            Some(sender) => watch_name(conn, sender.as_str(), gone.clone()).await,
            None => None,
        };
        Self { gone, _task: task }
    }

    fn flag(&self) -> Arc<AtomicBool> {
        self.gone.clone()
    }
}

async fn watch_name(conn: &Connection, name: &str, gone: Arc<AtomicBool>) -> Option<zbus::Task<()>> {
    let bus = fdo::DBusProxy::new(conn).await.ok()?;
    let mut changes = bus.receive_name_owner_changed_with_args(&[(0, name)]).await.ok()?;
    let unique = zbus::names::BusName::try_from(name.to_string()).ok()?;
    if !bus.name_has_owner(unique).await.ok()? {
        gone.store(true, Ordering::SeqCst);
        return None;
    }
    Some(conn.executor().spawn(
        async move {
            while let Some(change) = changes.next().await {
                if change.args().is_ok_and(|args| args.new_owner().is_none()) {
                    gone.store(true, Ordering::SeqCst);
                    break;
                }
            }
        },
        "openhellod-caller-watch",
    ))
}

impl Service {
    pub fn new(core: Biometrics, authorizer: Arc<dyn Authorizer>) -> Self {
        let logger = core.logger().clone();
        Self { core: Arc::new(Mutex::new(core)), authorizer, logger, enrollment_owners: Arc::default() }
    }

    async fn with_core<T: Send + 'static>(
        &self,
        operation: impl FnOnce(&mut Biometrics) -> Result<T, DaemonError> + Send + 'static,
    ) -> fdo::Result<T> {
        let core = self.core.clone();
        let outcome = blocking::unblock(move || {
            let mut guard = core.lock().map_err(|_| DaemonError::Backend("core lock poisoned".into()))?;
            operation(&mut guard)
        })
        .await;
        outcome.map_err(|error| failure(&self.logger, error))
    }

    async fn authorize(&self, conn: &Connection, header: &Header<'_>, action: Action, target_uid: u32) -> fdo::Result<()> {
        let caller = resolve_caller(conn, header).await?;
        self.authorizer
            .authorize(action, &caller, target_uid)
            .await
            .map_err(|reason| {
                self.logger.log(
                    Level::Warn,
                    "authorization-refused",
                    &[("action", Value::Label(action.polkit_id())), ("caller_uid", Value::Uid(caller.uid)), ("target_uid", Value::Uid(target_uid))],
                );
                fdo::Error::AuthFailed(format!("{}: {reason}", action.polkit_id()))
            })
    }

    async fn discard_when_owner_leaves(&self, conn: &Connection, header: &Header<'_>, handle: &str) {
        let Some(sender) = header.sender() else { return };
        let Ok(bus) = fdo::DBusProxy::new(conn).await else { return };
        let Ok(mut changes) = bus.receive_name_owner_changed_with_args(&[(0, sender.as_str())]).await else { return };
        let still_there = match zbus::names::BusName::try_from(sender.to_string()) {
            Ok(name) => bus.name_has_owner(name).await.unwrap_or(true),
            Err(_) => true,
        };
        let (core, owners, logger, key) = (self.core.clone(), self.enrollment_owners.clone(), self.logger.clone(), handle.to_string());
        let task = conn.executor().spawn(
            async move {
                let left = !still_there || loop {
                    match changes.next().await {
                        Some(change) if change.args().is_ok_and(|args| args.new_owner().is_none()) => break true,
                        Some(_) => {}
                        None => break false,
                    }
                };
                if left {
                    let session = key.clone();
                    let _ = blocking::unblock(move || match core.lock() {
                        Ok(mut core) => core.enroll_discard(&session).is_ok(),
                        Err(_) => false,
                    })
                    .await;
                    logger.log(Level::Info, "enrollment-abandoned", &[]);
                    owners.lock().map(|mut owners| owners.remove(&key)).ok();
                }
            },
            "openhellod-enrollment-owner",
        );
        if let Ok(mut owners) = self.enrollment_owners.lock() {
            owners.insert(handle.to_string(), task);
        }
    }

    fn release_enrollment_owner(&self, handle: &str) {
        if let Ok(mut owners) = self.enrollment_owners.lock() {
            owners.remove(handle);
        }
    }

    async fn session_uid(&self, handle: &str) -> fdo::Result<u32> {
        let handle = handle.to_string();
        self.with_core(move |core| core.session_uid(&handle)).await
    }
}

fn failure(logger: &Logger, error: DaemonError) -> fdo::Error {
    if !matches!(error, DaemonError::Cancelled) {
        logger.log(Level::Error, "operation-failed", &[("reason", Value::reason(&error))]);
    }
    match error {
        DaemonError::InvalidRequest(_) => fdo::Error::InvalidArgs(error.user_message().to_string()),
        _ => fdo::Error::Failed(error.user_message().to_string()),
    }
}

async fn resolve_caller(conn: &Connection, header: &Header<'_>) -> fdo::Result<Caller> {
    let sender = header.sender().ok_or_else(|| fdo::Error::AuthFailed("message has no sender".into()))?;
    let dbus = fdo::DBusProxy::new(conn).await?;
    let uid = dbus.get_connection_unix_user(sender.clone().into()).await?;
    Ok(Caller { bus_name: sender.to_string(), uid })
}

#[interface(name = "io.openhello.Biometrics1")]
impl Service {
    async fn enroll_begin(
        &self,
        uid: u32,
        #[zbus(connection)] conn: &Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> fdo::Result<String> {
        self.authorize(conn, &header, Action::EnrollBegin, uid).await?;
        let handle = self.with_core(move |core| core.enroll_begin(uid)).await?;
        self.discard_when_owner_leaves(conn, &header, &handle).await;
        Ok(handle)
    }

    async fn enroll_capture(
        &self,
        handle: String,
        #[zbus(connection)] conn: &Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> fdo::Result<(String, String, u32, u32)> {
        let uid = self.session_uid(&handle).await?;
        self.authorize(conn, &header, Action::EnrollCapture, uid).await?;
        let progress = self.with_core(move |core| core.enroll_capture(&handle)).await?;
        Ok((progress.verdict.as_str().into(), progress.state.as_str().into(), progress.filled, progress.required))
    }

    async fn enroll_commit(
        &self,
        handle: String,
        #[zbus(connection)] conn: &Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> fdo::Result<bool> {
        let uid = self.session_uid(&handle).await?;
        self.authorize(conn, &header, Action::EnrollCommit, uid).await?;
        self.release_enrollment_owner(&handle);
        self.with_core(move |core| core.enroll_commit(&handle)).await?;
        Ok(true)
    }

    async fn enroll_discard(
        &self,
        handle: String,
        #[zbus(connection)] conn: &Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> fdo::Result<()> {
        let uid = self.session_uid(&handle).await?;
        self.authorize(conn, &header, Action::EnrollDiscard, uid).await?;
        self.release_enrollment_owner(&handle);
        self.with_core(move |core| core.enroll_discard(&handle)).await
    }

    async fn verify(
        &self,
        uid: u32,
        #[zbus(connection)] conn: &Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> fdo::Result<bool> {
        let watch = CallerWatch::start(conn, &header).await;
        let gone = watch.flag();
        self.with_core(move |core| core.verify_cancellable(uid, &|| gone.load(Ordering::SeqCst))).await
    }

    async fn identify(
        &self,
        #[zbus(connection)] conn: &Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> fdo::Result<(bool, u32)> {
        let watch = CallerWatch::start(conn, &header).await;
        let gone = watch.flag();
        let matched = self.with_core(move |core| core.identify_cancellable(&|| gone.load(Ordering::SeqCst))).await?;
        Ok((matched.is_some(), matched.unwrap_or(0)))
    }

    async fn purge(
        &self,
        uid: u32,
        #[zbus(connection)] conn: &Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> fdo::Result<bool> {
        self.authorize(conn, &header, Action::Purge, uid).await?;
        self.with_core(move |core| core.purge(uid)).await?;
        Ok(true)
    }
}
