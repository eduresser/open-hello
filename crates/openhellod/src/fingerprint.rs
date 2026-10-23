use std::future::Future;
use std::time::Duration;

use async_io::Timer;
use futures_lite::{future, StreamExt};
use zbus::proxy::SignalStream;
use zbus::{Connection, DBusError, Proxy};

use crate::core::Cancel;
use crate::logging::{Level, Logger, Value};

const FPRINT_BUS_NAME: &str = "net.reactivated.Fprint";
const MANAGER_PATH: &str = "/net/reactivated/Fprint/Manager";
const MANAGER_INTERFACE: &str = "net.reactivated.Fprint.Manager";
const DEVICE_INTERFACE: &str = "net.reactivated.Fprint.Device";
const SETUP_TIMEOUT: Duration = Duration::from_secs(3);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(1);
const CANCEL_POLL: Duration = Duration::from_millis(50);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Unavailability {
    ServiceAbsent,
    NoDevice,
    NoEnrolledFinger,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FingerDeletion {
    Deleted,
    NothingToDelete,
    Failed,
}

impl FingerDeletion {
    pub fn as_str(self) -> &'static str {
        match self {
            FingerDeletion::Deleted => "destroyed",
            FingerDeletion::NothingToDelete => "none",
            FingerDeletion::Failed => "failed",
        }
    }
}

pub trait FingerprintReader: Send {
    fn delete_enrolled(&mut self, uid: u32) -> FingerDeletion;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FprintdBus {
    System,
    Address(String),
}

pub type UserNameResolver = Box<dyn Fn(u32) -> Option<String> + Send>;

pub struct FprintdReader {
    bus: FprintdBus,
    user_name: UserNameResolver,
}

impl FprintdReader {
    pub fn new(bus: FprintdBus) -> Self {
        Self::with_user_names(bus, Box::new(system_user_name))
    }

    pub fn with_user_names(bus: FprintdBus, user_name: UserNameResolver) -> Self {
        Self { bus, user_name }
    }
}

impl FingerprintReader for FprintdReader {
    fn delete_enrolled(&mut self, uid: u32) -> FingerDeletion {
        let Some(name) = (self.user_name)(uid) else { return FingerDeletion::NothingToDelete };
        async_io::block_on(run_delete(&self.bus, &name))
    }
}

fn system_user_name(uid: u32) -> Option<String> {
    let mut buffer = vec![0u8; 1024];
    loop {
        let mut passwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut found: *mut libc::passwd = std::ptr::null_mut();
        let status = unsafe { libc::getpwuid_r(uid, &mut passwd, buffer.as_mut_ptr().cast(), buffer.len(), &mut found) };
        if status == libc::ERANGE && buffer.len() < 1 << 20 {
            buffer.resize(buffer.len() * 2, 0);
            continue;
        }
        if status != 0 || found.is_null() {
            return None;
        }
        let name = unsafe { std::ffi::CStr::from_ptr(passwd.pw_name) };
        return name.to_str().ok().map(str::to_owned);
    }
}

async fn within<T>(limit: Duration, work: impl Future<Output = T>) -> Option<T> {
    future::or(async { Some(work.await) }, async {
        Timer::after(limit).await;
        None
    })
    .await
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    Manager,
    Device,
}

fn error_name(error: &zbus::Error) -> Option<String> {
    match error {
        zbus::Error::MethodError(name, ..) => Some(name.to_string()),
        zbus::Error::FDO(inner) => Some(DBusError::name(&**inner).to_string()),
        _ => None,
    }
}

fn classify(stage: Stage, error: &zbus::Error) -> Unavailability {
    match error_name(error).as_deref() {
        Some(name) if name.ends_with(".ServiceUnknown") || name.ends_with(".NameHasNoOwner") => Unavailability::ServiceAbsent,
        Some(name) if name.ends_with(".NoSuchDevice") => Unavailability::NoDevice,
        Some(name) if name.ends_with(".NoEnrolledPrints") => Unavailability::NoEnrolledFinger,
        Some(_) => Unavailability::Unknown,
        None if stage == Stage::Manager => Unavailability::ServiceAbsent,
        None => Unavailability::Unknown,
    }
}

async fn connect(bus: &FprintdBus) -> zbus::Result<Connection> {
    match bus {
        FprintdBus::System => zbus::connection::Builder::system()?.build().await,
        FprintdBus::Address(address) => zbus::connection::Builder::address(address.as_str())?.build().await,
    }
}

async fn default_device(connection: &Connection) -> Result<Proxy<'static>, Unavailability> {
    let manager = Proxy::new(connection, FPRINT_BUS_NAME, MANAGER_PATH, MANAGER_INTERFACE)
        .await
        .map_err(|error| classify(Stage::Manager, &error))?;
    let path: zbus::zvariant::OwnedObjectPath = manager
        .call("GetDefaultDevice", &())
        .await
        .map_err(|error| classify(Stage::Manager, &error))?;
    Proxy::new(connection, FPRINT_BUS_NAME, path, DEVICE_INTERFACE)
        .await
        .map_err(|error| classify(Stage::Device, &error))
}

pub const FINGERS: [&str; 10] = [
    "left-thumb",
    "left-index-finger",
    "left-middle-finger",
    "left-ring-finger",
    "left-little-finger",
    "right-thumb",
    "right-index-finger",
    "right-middle-finger",
    "right-ring-finger",
    "right-little-finger",
];
pub const DEFAULT_FINGER: &str = "right-index-finger";
const DEFAULT_ENROLL_STAGES: u32 = 5;

fn known_finger(name: &str) -> Option<&'static str> {
    FINGERS.iter().copied().find(|finger| *finger == name)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReaderStatus {
    pub present: bool,
    pub enrolled: Vec<&'static str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FingerEnrollState {
    InProgress,
    Completed,
    Failed,
}

impl FingerEnrollState {
    pub fn as_str(self) -> &'static str {
        match self {
            FingerEnrollState::InProgress => "in-progress",
            FingerEnrollState::Completed => "complete",
            FingerEnrollState::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnrollStep {
    pub status: &'static str,
    pub state: FingerEnrollState,
    pub passed: u32,
    pub total: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FingerEnrollError {
    UnknownFinger,
    AlreadyEnrolled,
    NoReader,
    Unavailable,
}

impl FingerEnrollError {
    pub fn as_str(self) -> &'static str {
        match self {
            FingerEnrollError::UnknownFinger => "unknown-finger",
            FingerEnrollError::AlreadyEnrolled => "already-enrolled",
            FingerEnrollError::NoReader => "no-reader",
            FingerEnrollError::Unavailable => "unavailable",
        }
    }

    pub fn user_message(self) -> &'static str {
        match self {
            FingerEnrollError::UnknownFinger => "that finger name is not one of the ten fingers",
            FingerEnrollError::AlreadyEnrolled => "that finger is already enrolled; choose another finger",
            FingerEnrollError::NoReader => "no fingerprint reader was found",
            FingerEnrollError::Unavailable => "the fingerprint reader could not complete the operation",
        }
    }
}

pub trait FingerEnroller: Send + Sync {
    fn reader_status(&self, uid: u32) -> ReaderStatus;
    fn begin(&self, uid: u32, finger: &str) -> Result<Box<dyn FingerEnrollment>, FingerEnrollError>;
}

pub trait FingerEnrollment: Send {
    fn next_step(&mut self, cancel: Cancel) -> EnrollStep;
    fn stop(&mut self);
}

pub type SharedUserNameResolver = Box<dyn Fn(u32) -> Option<String> + Send + Sync>;

pub struct FprintdEnroller {
    bus: FprintdBus,
    logger: Logger,
    user_name: SharedUserNameResolver,
}

impl FprintdEnroller {
    pub fn new(bus: FprintdBus, logger: Logger) -> Self {
        Self::with_user_names(bus, logger, Box::new(system_user_name))
    }

    pub fn with_user_names(bus: FprintdBus, logger: Logger, user_name: SharedUserNameResolver) -> Self {
        Self { bus, logger, user_name }
    }
}

impl FingerEnroller for FprintdEnroller {
    fn reader_status(&self, uid: u32) -> ReaderStatus {
        let status = (self.user_name)(uid)
            .map(|name| async_io::block_on(read_reader_status(&self.bus, &name)))
            .unwrap_or(ReaderStatus { present: false, enrolled: Vec::new() });
        self.logger.log(
            Level::Debug,
            "fingerprint-reader-status",
            &[("uid", Value::Uid(uid)), ("present", Value::Flag(status.present)), ("enrolled", Value::Count(status.enrolled.len() as u64))],
        );
        status
    }

    fn begin(&self, uid: u32, finger: &str) -> Result<Box<dyn FingerEnrollment>, FingerEnrollError> {
        let result = known_finger(finger).ok_or(FingerEnrollError::UnknownFinger).and_then(|finger| {
            let name = (self.user_name)(uid).ok_or(FingerEnrollError::Unavailable)?;
            async_io::block_on(start_enrollment(&self.bus, &name, finger))
        });
        let outcome = result.as_ref().err().map_or("started", |error| error.as_str());
        self.logger.log(Level::Info, "fingerprint-enroll-begin", &[("uid", Value::Uid(uid)), ("outcome", Value::Label(outcome))]);
        let (device, statuses, total) = result?;
        Ok(Box::new(FprintdEnrollment {
            device,
            statuses,
            logger: self.logger.clone(),
            uid,
            passed: 0,
            total,
            retries: 0,
            outcome: "cancelled",
            stopped: false,
        }))
    }
}

struct FprintdEnrollment {
    device: Proxy<'static>,
    statuses: SignalStream<'static>,
    logger: Logger,
    uid: u32,
    passed: u32,
    total: u32,
    retries: u64,
    outcome: &'static str,
    stopped: bool,
}

impl FprintdEnrollment {
    fn step(&self, status: &'static str, state: FingerEnrollState) -> EnrollStep {
        EnrollStep { status, state, passed: self.passed, total: self.total }
    }

    async fn wait_for_status(&mut self, cancel: Cancel<'_>) -> EnrollStep {
        loop {
            if cancel() {
                return self.step("cancelled", FingerEnrollState::Failed);
            }
            let next = future::or(async { Some(self.statuses.next().await) }, async {
                Timer::after(CANCEL_POLL).await;
                None
            })
            .await;
            let message = match next {
                None => continue,
                Some(None) => return self.step("disconnected", FingerEnrollState::Failed),
                Some(Some(message)) => message,
            };
            let Ok((status, _done)) = message.body().deserialize::<(String, bool)>() else {
                return self.step("unknown-error", FingerEnrollState::Failed);
            };
            match status.as_str() {
                "enroll-stage-passed" => {
                    self.passed = (self.passed + 1).min(self.total);
                    return self.step("stage-passed", FingerEnrollState::InProgress);
                }
                "enroll-retry-scan" => return self.retry("retry-scan"),
                "enroll-swipe-too-short" => return self.retry("swipe-too-short"),
                "enroll-finger-not-centered" => return self.retry("finger-not-centered"),
                "enroll-remove-and-retry" => return self.retry("remove-and-retry"),
                "enroll-completed" => {
                    self.passed = self.total;
                    return self.step("completed", FingerEnrollState::Completed);
                }
                "enroll-failed" => return self.step("failed", FingerEnrollState::Failed),
                "enroll-data-full" => return self.step("data-full", FingerEnrollState::Failed),
                "enroll-disconnected" => return self.step("disconnected", FingerEnrollState::Failed),
                _ => return self.step("unknown-error", FingerEnrollState::Failed),
            }
        }
    }

    fn retry(&mut self, status: &'static str) -> EnrollStep {
        self.retries += 1;
        self.step(status, FingerEnrollState::InProgress)
    }
}

impl FingerEnrollment for FprintdEnrollment {
    fn next_step(&mut self, cancel: Cancel) -> EnrollStep {
        if self.stopped {
            return self.step("cancelled", FingerEnrollState::Failed);
        }
        let step = async_io::block_on(self.wait_for_status(cancel));
        if step.state != FingerEnrollState::InProgress {
            self.outcome = step.status;
            self.stop();
        }
        step
    }

    fn stop(&mut self) {
        if self.stopped {
            return;
        }
        self.stopped = true;
        async_io::block_on(async {
            let _ = within(CLEANUP_TIMEOUT, self.device.call::<_, _, ()>("EnrollStop", &())).await;
            let _ = within(CLEANUP_TIMEOUT, self.device.call::<_, _, ()>("Release", &())).await;
        });
        self.logger.log(
            Level::Info,
            "fingerprint-enroll",
            &[
                ("uid", Value::Uid(self.uid)),
                ("outcome", Value::Label(self.outcome)),
                ("stages", Value::Count(self.passed as u64)),
                ("retries", Value::Count(self.retries)),
            ],
        );
    }
}

impl Drop for FprintdEnrollment {
    fn drop(&mut self) {
        self.stop();
    }
}

async fn list_enrolled(device: &Proxy<'_>, user_name: &str) -> Result<Vec<&'static str>, Unavailability> {
    match within(SETUP_TIMEOUT, device.call::<_, _, Vec<String>>("ListEnrolledFingers", &(user_name,))).await {
        Some(Ok(names)) => Ok(names.iter().filter_map(|name| known_finger(name)).collect()),
        Some(Err(error)) => match classify(Stage::Device, &error) {
            Unavailability::NoEnrolledFinger => Ok(Vec::new()),
            kind => Err(kind),
        },
        None => Err(Unavailability::Unknown),
    }
}

async fn read_reader_status(bus: &FprintdBus, user_name: &str) -> ReaderStatus {
    let absent = ReaderStatus { present: false, enrolled: Vec::new() };
    let Some(Ok(connection)) = within(SETUP_TIMEOUT, connect(bus)).await else { return absent };
    let Some(Ok(device)) = within(SETUP_TIMEOUT, default_device(&connection)).await else { return absent };
    let enrolled = list_enrolled(&device, user_name).await.unwrap_or_default();
    ReaderStatus { present: true, enrolled }
}

fn no_reader_or_unavailable(kind: Unavailability) -> FingerEnrollError {
    match kind {
        Unavailability::ServiceAbsent | Unavailability::NoDevice => FingerEnrollError::NoReader,
        _ => FingerEnrollError::Unavailable,
    }
}

async fn start_enrollment(
    bus: &FprintdBus,
    user_name: &str,
    finger: &'static str,
) -> Result<(Proxy<'static>, SignalStream<'static>, u32), FingerEnrollError> {
    let Some(Ok(connection)) = within(SETUP_TIMEOUT, connect(bus)).await else {
        return Err(FingerEnrollError::NoReader);
    };
    let device = match within(SETUP_TIMEOUT, default_device(&connection)).await {
        Some(Ok(device)) => device,
        Some(Err(kind)) => return Err(no_reader_or_unavailable(kind)),
        None => return Err(FingerEnrollError::NoReader),
    };
    if list_enrolled(&device, user_name).await.map_err(no_reader_or_unavailable)?.contains(&finger) {
        return Err(FingerEnrollError::AlreadyEnrolled);
    }
    match within(SETUP_TIMEOUT, device.call::<_, _, ()>("Claim", &(user_name,))).await {
        Some(Ok(())) => {}
        _ => return Err(FingerEnrollError::Unavailable),
    }
    let started = begin_claimed(&device, finger).await;
    if started.is_err() {
        let _ = within(CLEANUP_TIMEOUT, device.call::<_, _, ()>("Release", &())).await;
    }
    let (statuses, total) = started?;
    Ok((device, statuses, total))
}

async fn begin_claimed(device: &Proxy<'static>, finger: &'static str) -> Result<(SignalStream<'static>, u32), FingerEnrollError> {
    let statuses = device.receive_signal("EnrollStatus").await.map_err(|_| FingerEnrollError::Unavailable)?;
    let total = match device.get_property::<i32>("num-enroll-stages").await {
        Ok(stages) if stages > 0 => stages as u32,
        _ => DEFAULT_ENROLL_STAGES,
    };
    match within(SETUP_TIMEOUT, device.call::<_, _, ()>("EnrollStart", &(finger,))).await {
        Some(Ok(())) => Ok((statuses, total)),
        _ => Err(FingerEnrollError::Unavailable),
    }
}

async fn run_delete(bus: &FprintdBus, user_name: &str) -> FingerDeletion {
    let Some(Ok(connection)) = within(SETUP_TIMEOUT, connect(bus)).await else { return FingerDeletion::NothingToDelete };
    let device = match within(SETUP_TIMEOUT, default_device(&connection)).await {
        Some(Ok(device)) => device,
        Some(Err(Unavailability::ServiceAbsent | Unavailability::NoDevice)) => return FingerDeletion::NothingToDelete,
        Some(Err(_)) | None => return FingerDeletion::Failed,
    };
    match list_enrolled(&device, user_name).await {
        Ok(enrolled) if enrolled.is_empty() => return FingerDeletion::NothingToDelete,
        Ok(_) => {}
        Err(_) => return FingerDeletion::Failed,
    }
    match within(SETUP_TIMEOUT, device.call::<_, _, ()>("Claim", &(user_name,))).await {
        Some(Ok(())) => {}
        _ => return FingerDeletion::Failed,
    }
    let deleted = within(SETUP_TIMEOUT, device.call::<_, _, ()>("DeleteEnrolledFingers2", &())).await;
    let _ = within(CLEANUP_TIMEOUT, device.call::<_, _, ()>("Release", &())).await;
    match deleted {
        Some(Ok(())) => FingerDeletion::Deleted,
        Some(Err(error)) if classify(Stage::Device, &error) == Unavailability::NoEnrolledFinger => FingerDeletion::NothingToDelete,
        _ => FingerDeletion::Failed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_system_resolver_names_root_and_rejects_unknown_uids() {
        assert_eq!(system_user_name(0).as_deref(), Some("root"));
        assert_eq!(system_user_name(u32::MAX - 7), None);
    }
}
