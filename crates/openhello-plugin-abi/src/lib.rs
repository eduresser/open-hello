use std::os::raw::{c_char, c_void};

pub const ABI_VERSION: u32 = 1;

pub const SENSOR_ENTRY_SYMBOL: &str = "openhello_sensor_interface";
pub const ENGINE_ENTRY_SYMBOL: &str = "openhello_engine_interface";
pub const STORAGE_ENTRY_SYMBOL: &str = "openhello_storage_interface";

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

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollQualityVerdict {
    Accepted = 0,
    Blurred = 1,
    Occluded = 2,
    NoFace = 3,
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
    pub create: unsafe extern "C" fn(config_json: *const c_char, out: *mut EngineHandle) -> Status,
    pub extract_embedding: unsafe extern "C" fn(
        handle: EngineHandle,
        frame: *const FrameView,
        out: *mut f32,
        out_len: usize,
    ) -> Status,
    pub match_score: unsafe extern "C" fn(
        handle: EngineHandle,
        probe: *const f32,
        template: *const f32,
        len: usize,
        target_far: f64,
        accepted: *mut bool,
    ) -> Status,
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
