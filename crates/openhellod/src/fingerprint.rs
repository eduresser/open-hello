use std::future::Future;
use std::time::Duration;

use async_io::Timer;
use futures_lite::{future, StreamExt};
use zbus::{Connection, DBusError, Proxy};

use crate::core::{Cancel, MAX_ATTEMPTS};
use crate::logging::{Level, Logger, Value};

const FPRINT_BUS_NAME: &str = "net.reactivated.Fprint";
const MANAGER_PATH: &str = "/net/reactivated/Fprint/Manager";
const MANAGER_INTERFACE: &str = "net.reactivated.Fprint.Manager";
const DEVICE_INTERFACE: &str = "net.reactivated.Fprint.Device";
const ANY_FINGER: &str = "any";
const SETUP_TIMEOUT: Duration = Duration::from_secs(3);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(1);
const CANCEL_POLL: Duration = Duration::from_millis(50);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unavailability {
    ServiceAbsent,
    NoDevice,
    NoEnrolledFinger,
    Disconnected,
    Unknown,
}

impl Unavailability {
    pub fn as_str(self) -> &'static str {
        match self {
            Unavailability::ServiceAbsent => "service-absent",
            Unavailability::NoDevice => "no-device",
            Unavailability::NoEnrolledFinger => "no-enrolled-finger",
            Unavailability::Disconnected => "disconnected",
            Unavailability::Unknown => "unknown-error",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FingerprintResult {
    Match,
    NoMatch,
    Unavailable(Unavailability),
    Cancelled,
}

impl FingerprintResult {
    pub fn as_str(self) -> &'static str {
        match self {
            FingerprintResult::Match => "match",
            FingerprintResult::NoMatch => "no-match",
            FingerprintResult::Unavailable(kind) => kind.as_str(),
            FingerprintResult::Cancelled => "cancelled",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FingerprintDecision {
    Matched,
    Refused,
    Unavailable(Unavailability),
    Cancelled,
}

pub trait FingerprintMatcher: Send {
    fn verify(&mut self, uid: u32, cancel: Cancel) -> FingerprintResult;
}

pub fn verify_with_attempts(
    matcher: &mut dyn FingerprintMatcher,
    uid: u32,
    max_attempts: u32,
    cancel: Cancel,
) -> FingerprintDecision {
    for _ in 0..max_attempts {
        match matcher.verify(uid, cancel) {
            FingerprintResult::Match => return FingerprintDecision::Matched,
            FingerprintResult::NoMatch => {}
            FingerprintResult::Unavailable(kind) => return FingerprintDecision::Unavailable(kind),
            FingerprintResult::Cancelled => return FingerprintDecision::Cancelled,
        }
    }
    FingerprintDecision::Refused
}

pub fn verify_default_attempts(matcher: &mut dyn FingerprintMatcher, uid: u32, cancel: Cancel) -> FingerprintDecision {
    verify_with_attempts(matcher, uid, MAX_ATTEMPTS, cancel)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FprintdBus {
    System,
    Address(String),
}

pub type UserNameResolver = Box<dyn Fn(u32) -> Option<String> + Send>;

pub struct FprintdMatcher {
    bus: FprintdBus,
    logger: Logger,
    user_name: UserNameResolver,
}

impl FprintdMatcher {
    pub fn new(bus: FprintdBus, logger: Logger) -> Self {
        Self::with_user_names(bus, logger, Box::new(system_user_name))
    }

    pub fn with_user_names(bus: FprintdBus, logger: Logger, user_name: UserNameResolver) -> Self {
        Self { bus, logger, user_name }
    }

    fn log_outcome(&self, uid: u32, result: FingerprintResult, retries: u64) {
        let level = match result {
            FingerprintResult::Unavailable(_) => Level::Warn,
            _ => Level::Info,
        };
        self.logger.log(
            level,
            "fingerprint-verify",
            &[("uid", Value::Uid(uid)), ("outcome", Value::Label(result.as_str())), ("retries", Value::Count(retries))],
        );
    }
}

impl FingerprintMatcher for FprintdMatcher {
    fn verify(&mut self, uid: u32, cancel: Cancel) -> FingerprintResult {
        let Some(name) = (self.user_name)(uid) else {
            let result = FingerprintResult::Unavailable(Unavailability::Unknown);
            self.log_outcome(uid, result, 0);
            return result;
        };
        let mut retries = 0;
        let result = async_io::block_on(run_verify(&self.bus, &name, cancel, &mut retries));
        self.log_outcome(uid, result, retries);
        result
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

fn classify_status(status: &str) -> Option<FingerprintResult> {
    match status {
        "verify-match" => Some(FingerprintResult::Match),
        "verify-no-match" => Some(FingerprintResult::NoMatch),
        "verify-disconnected" => Some(FingerprintResult::Unavailable(Unavailability::Disconnected)),
        "verify-retry-scan" | "verify-swipe-too-short" | "verify-finger-not-centered" | "verify-remove-and-retry" => None,
        _ => Some(FingerprintResult::Unavailable(Unavailability::Unknown)),
    }
}

async fn connect(bus: &FprintdBus) -> zbus::Result<Connection> {
    match bus {
        FprintdBus::System => zbus::connection::Builder::system()?.build().await,
        FprintdBus::Address(address) => zbus::connection::Builder::address(address.as_str())?.build().await,
    }
}

fn unavailable(kind: Unavailability) -> FingerprintResult {
    FingerprintResult::Unavailable(kind)
}

async fn run_verify(bus: &FprintdBus, user_name: &str, cancel: Cancel<'_>, retries: &mut u64) -> FingerprintResult {
    let Some(Ok(connection)) = within(SETUP_TIMEOUT, connect(bus)).await else {
        return unavailable(Unavailability::ServiceAbsent);
    };
    let device = match within(SETUP_TIMEOUT, default_device(&connection)).await {
        Some(Ok(device)) => device,
        Some(Err(kind)) => return unavailable(kind),
        None => return unavailable(Unavailability::ServiceAbsent),
    };
    match within(SETUP_TIMEOUT, device.call::<_, _, ()>("Claim", &(user_name,))).await {
        Some(Ok(())) => {}
        Some(Err(error)) => return unavailable(classify(Stage::Device, &error)),
        None => return unavailable(Unavailability::Unknown),
    }
    let result = verify_claimed(&device, cancel, retries).await;
    let _ = within(CLEANUP_TIMEOUT, device.call::<_, _, ()>("Release", &())).await;
    result
}

async fn default_device<'a>(connection: &'a Connection) -> Result<Proxy<'a>, Unavailability> {
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

async fn verify_claimed(device: &Proxy<'_>, cancel: Cancel<'_>, retries: &mut u64) -> FingerprintResult {
    let Ok(mut statuses) = device.receive_signal("VerifyStatus").await else {
        return unavailable(Unavailability::Unknown);
    };
    match within(SETUP_TIMEOUT, device.call::<_, _, ()>("VerifyStart", &(ANY_FINGER,))).await {
        Some(Ok(())) => {}
        Some(Err(error)) => return unavailable(classify(Stage::Device, &error)),
        None => return unavailable(Unavailability::Unknown),
    }
    let result = wait_for_decision(&mut statuses, cancel, retries).await;
    let _ = within(CLEANUP_TIMEOUT, device.call::<_, _, ()>("VerifyStop", &())).await;
    result
}

async fn wait_for_decision(statuses: &mut zbus::proxy::SignalStream<'_>, cancel: Cancel<'_>, retries: &mut u64) -> FingerprintResult {
    loop {
        if cancel() {
            return FingerprintResult::Cancelled;
        }
        let next = future::or(async { Some(statuses.next().await) }, async {
            Timer::after(CANCEL_POLL).await;
            None
        })
        .await;
        let message = match next {
            None => continue,
            Some(None) => return unavailable(Unavailability::Disconnected),
            Some(Some(message)) => message,
        };
        let Ok((status, _done)) = message.body().deserialize::<(String, bool)>() else {
            return unavailable(Unavailability::Unknown);
        };
        match classify_status(&status) {
            None => *retries += 1,
            Some(FingerprintResult::Match) if cancel() => return FingerprintResult::Cancelled,
            Some(result) => return result,
        }
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

    #[test]
    fn every_reader_status_maps_to_a_result_without_inventing_a_match() {
        assert_eq!(classify_status("verify-match"), Some(FingerprintResult::Match));
        assert_eq!(classify_status("verify-no-match"), Some(FingerprintResult::NoMatch));
        assert_eq!(classify_status("verify-retry-scan"), None);
        assert_eq!(classify_status(""), Some(FingerprintResult::Unavailable(Unavailability::Unknown)));
    }
}
