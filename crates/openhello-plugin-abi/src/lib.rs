use std::os::raw::{c_char, c_void};

pub const ABI_VERSION: u32 = 2;

pub const SENSOR_ENTRY_SYMBOL: &str = "openhello_sensor_interface";
pub const ENGINE_ENTRY_SYMBOL: &str = "openhello_engine_interface";
pub const STORAGE_ENTRY_SYMBOL: &str = "openhello_storage_interface";
pub const SENSOR_LAST_ERROR_SYMBOL: &str = "openhello_sensor_last_error";

pub type SensorLastError = unsafe extern "C" fn(buffer: *mut u8, capacity: usize) -> usize;

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Ok = 0,
    InvalidArgument = 1,
    DeviceUnavailable = 2,
    EmitterFailure = 3,
    NotFound = 4,
    AuthenticationFailed = 5,
    BufferTooSmall = 6,
    Internal = 7,
}

impl Status {
    pub fn is_ok(self) -> bool {
        self == Status::Ok
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FrameView {
    pub width: u32,
    pub height: u32,
    pub data: *const u8,
    pub len: usize,
    pub timestamp_us: u64,
}

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollVerdict {
    Accepted = 0,
    Blurred = 1,
    Occluded = 2,
    NoFace = 3,
    YawOutOfRange = 4,
    BucketAlreadyFilled = 5,
}

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollState {
    InProgress = 0,
    Complete = 1,
    Failed = 2,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct EnrollProgress {
    pub verdict: EnrollVerdict,
    pub state: EnrollState,
    pub filled: u32,
    pub required: u32,
}

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthState {
    Continue = 0,
    Accepted = 1,
    Rejected = 2,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct AuthProgress {
    pub state: AuthState,
    pub uid: u32,
    pub scored_frames: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TemplateRef {
    pub uid: u32,
    pub data: *const u8,
    pub len: usize,
}

pub type SensorHandle = *mut c_void;
pub type EngineHandle = *mut c_void;
pub type StorageHandle = *mut c_void;

#[repr(C)]
pub struct SensorInterface {
    pub abi_version: u32,
    pub open: unsafe extern "C" fn(device_path: *const c_char, out: *mut SensorHandle) -> Status,
    pub capture: unsafe extern "C" fn(handle: SensorHandle, out: *mut FrameView) -> Status,
    pub release_frame: unsafe extern "C" fn(handle: SensorHandle, frame: *const FrameView),
    pub close: unsafe extern "C" fn(handle: SensorHandle),
}

#[repr(C)]
pub struct EngineInterface {
    pub abi_version: u32,
    pub create: unsafe extern "C" fn(config: *const c_char, out: *mut EngineHandle) -> Status,
    pub enroll_begin: unsafe extern "C" fn(handle: EngineHandle, now_ms: u64, out_session: *mut u64) -> Status,
    pub enroll_submit: unsafe extern "C" fn(
        handle: EngineHandle,
        session: u64,
        now_ms: u64,
        frame: *const FrameView,
        out: *mut EnrollProgress,
    ) -> Status,
    pub enroll_commit: unsafe extern "C" fn(
        handle: EngineHandle,
        session: u64,
        out: *mut u8,
        out_capacity: usize,
        out_len: *mut usize,
    ) -> Status,
    pub enroll_discard: unsafe extern "C" fn(handle: EngineHandle, session: u64) -> Status,
    pub auth_begin: unsafe extern "C" fn(
        handle: EngineHandle,
        candidates: *const TemplateRef,
        candidate_count: usize,
        target_far: f64,
        max_scored_frames: u32,
        out_session: *mut u64,
    ) -> Status,
    pub auth_submit: unsafe extern "C" fn(
        handle: EngineHandle,
        session: u64,
        frame: *const FrameView,
        out: *mut AuthProgress,
    ) -> Status,
    pub auth_end: unsafe extern "C" fn(handle: EngineHandle, session: u64) -> Status,
    pub destroy: unsafe extern "C" fn(handle: EngineHandle),
}

#[repr(C)]
pub struct StorageInterface {
    pub abi_version: u32,
    pub open: unsafe extern "C" fn(root_dir: *const c_char, out: *mut StorageHandle) -> Status,
    pub put_template: unsafe extern "C" fn(
        handle: StorageHandle,
        uid: u32,
        data: *const u8,
        len: usize,
    ) -> Status,
    pub get_template: unsafe extern "C" fn(
        handle: StorageHandle,
        uid: u32,
        out: *mut u8,
        out_capacity: usize,
        out_len: *mut usize,
    ) -> Status,
    pub list_uids: unsafe extern "C" fn(
        handle: StorageHandle,
        out: *mut u32,
        out_capacity: usize,
        out_count: *mut usize,
    ) -> Status,
    pub purge: unsafe extern "C" fn(handle: StorageHandle, uid: u32) -> Status,
    pub close: unsafe extern "C" fn(handle: StorageHandle),
}

pub type SensorEntry = unsafe extern "C" fn() -> *const SensorInterface;
pub type EngineEntry = unsafe extern "C" fn() -> *const EngineInterface;
pub type StorageEntry = unsafe extern "C" fn() -> *const StorageInterface;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_symbols_are_distinct_and_prefixed() {
        let symbols = [SENSOR_ENTRY_SYMBOL, ENGINE_ENTRY_SYMBOL, STORAGE_ENTRY_SYMBOL];
        assert!(symbols.iter().all(|s| s.starts_with("openhello_")));
        assert_eq!(symbols.iter().collect::<std::collections::HashSet<_>>().len(), 3);
    }

    #[test]
    fn status_ok_is_zero() {
        assert_eq!(Status::Ok as i32, 0);
        assert!(Status::Ok.is_ok());
        assert!(!Status::Internal.is_ok());
    }
}
