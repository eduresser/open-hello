use std::ffi::CString;
use std::path::Path;

use libloading::{Library, Symbol};
use openhello_plugin_abi::{
    AuthProgress as AbiAuthProgress, AuthState as AbiAuthState, EngineEntry, EngineHandle, EngineInterface,
    EnrollState as AbiEnrollState, EnrollVerdict, FrameView, SensorEntry, SensorHandle, SensorInterface, SensorLastError, Status, StorageEntry,
    StorageHandle, StorageInterface, TemplateRef, ABI_VERSION, ENGINE_ENTRY_SYMBOL, SENSOR_ENTRY_SYMBOL, SENSOR_LAST_ERROR_SYMBOL, STORAGE_ENTRY_SYMBOL,
};

use crate::backends::{
    AuthProgress, AuthVerdict, CapturedFrame, DaemonError, EngineBackend, EnrollProgress, EnrollState, SensorBackend,
    StorageBackend, Verdict,
};

const TEMPLATE_CAPACITY: usize = 1 << 20;

fn check(status: Status, context: &str) -> Result<(), DaemonError> {
    match status {
        Status::Ok => Ok(()),
        Status::NotFound => Err(DaemonError::NotFound),
        Status::AuthenticationFailed => Err(DaemonError::Tampered),
        Status::InvalidArgument => Err(DaemonError::InvalidRequest(format!("{context}: rejected by plugin"))),
        other => Err(DaemonError::Backend(format!("{context}: plugin status {other:?}"))),
    }
}

fn c_string(value: &str) -> Result<CString, DaemonError> {
    CString::new(value).map_err(|_| DaemonError::InvalidRequest(format!("`{value}` contains an interior NUL byte")))
}

fn load_entry<'lib, T>(library: &'lib Library, symbol: &str, path: &Path) -> Result<Symbol<'lib, T>, DaemonError> {
    unsafe { library.get(symbol.as_bytes()) }
        .map_err(|e| DaemonError::Backend(format!("{} does not export `{symbol}`: {e}", path.display())))
}

fn open_library(path: &Path) -> Result<&'static Library, DaemonError> {
    let library = unsafe { Library::new(path) }
        .map_err(|e| DaemonError::Backend(format!("cannot load plugin {}: {e}", path.display())))?;
    // Never dlclose: thread-local destructors registered by plugin code run at thread exit and would jump into unmapped pages
    Ok(Box::leak(Box::new(library)))
}

fn check_abi(version: u32, path: &Path) -> Result<(), DaemonError> {
    if version != ABI_VERSION {
        return Err(DaemonError::Backend(format!(
            "{} speaks plugin ABI {version}, daemon expects {ABI_VERSION}",
            path.display()
        )));
    }
    Ok(())
}

pub struct SensorPlugin {
    interface: &'static SensorInterface,
    handle: SensorHandle,
    last_error: Option<SensorLastError>,
}

const LAST_ERROR_CAPACITY: usize = 256;

fn last_error_reason(last_error: Option<SensorLastError>) -> Option<String> {
    let mut buffer = [0u8; LAST_ERROR_CAPACITY];
    let length = unsafe { last_error?(buffer.as_mut_ptr(), buffer.len()) }.min(LAST_ERROR_CAPACITY);
    (length > 0).then(|| String::from_utf8_lossy(&buffer[..length]).into_owned())
}

fn check_with_reason(status: Status, context: &str, last_error: Option<SensorLastError>) -> Result<(), DaemonError> {
    if status == Status::Ok {
        return Ok(());
    }
    match last_error_reason(last_error) {
        Some(reason) => check(status, &format!("{context} ({reason})")),
        None => check(status, context),
    }
}

unsafe impl Send for SensorPlugin {}

impl SensorPlugin {
    pub fn load(path: &Path, device: &str) -> Result<Self, DaemonError> {
        let library = open_library(path)?;
        let interface = {
            let entry: Symbol<SensorEntry> = load_entry(library, SENSOR_ENTRY_SYMBOL, path)?;
            unsafe { entry().as_ref() }.ok_or_else(|| DaemonError::Backend("sensor plugin returned a null interface".into()))?
        };
        let interface: &'static SensorInterface = unsafe { &*(interface as *const SensorInterface) };
        check_abi(interface.abi_version, path)?;
        let last_error: Option<SensorLastError> =
            unsafe { library.get::<SensorLastError>(SENSOR_LAST_ERROR_SYMBOL.as_bytes()) }.ok().map(|symbol| *symbol);
        let device = c_string(device)?;
        let mut handle: SensorHandle = std::ptr::null_mut();
        check_with_reason(unsafe { (interface.open)(device.as_ptr(), &mut handle) }, "sensor open", last_error)?;
        Ok(Self { interface, handle, last_error })
    }
}

impl SensorBackend for SensorPlugin {
    fn capture(&mut self) -> Result<CapturedFrame, DaemonError> {
        let mut view = FrameView { width: 0, height: 0, data: std::ptr::null(), len: 0, timestamp_us: 0 };
        check_with_reason(unsafe { (self.interface.capture)(self.handle, &mut view) }, "sensor capture", self.last_error)?;
        if view.data.is_null() {
            return Err(DaemonError::Backend("sensor returned a frame without data".into()));
        }
        let pixels = unsafe { std::slice::from_raw_parts(view.data, view.len) }.to_vec();
        unsafe { (self.interface.release_frame)(self.handle, &view) };
        Ok(CapturedFrame { width: view.width, height: view.height, pixels })
    }

    fn release(&mut self) {
        unsafe { (self.interface.release)(self.handle) };
    }
}

impl Drop for SensorPlugin {
    fn drop(&mut self) {
        unsafe { (self.interface.close)(self.handle) };
    }
}

pub struct EnginePlugin {
    interface: &'static EngineInterface,
    handle: EngineHandle,
}

unsafe impl Send for EnginePlugin {}

fn views(frames: &[CapturedFrame]) -> Vec<FrameView> {
    frames
        .iter()
        .map(|f| FrameView { width: f.width, height: f.height, data: f.pixels.as_ptr(), len: f.pixels.len(), timestamp_us: 0 })
        .collect()
}

impl EnginePlugin {
    pub fn load(path: &Path, config_json: &str) -> Result<Self, DaemonError> {
        let library = open_library(path)?;
        let interface = {
            let entry: Symbol<EngineEntry> = load_entry(library, ENGINE_ENTRY_SYMBOL, path)?;
            unsafe { entry().as_ref() }.ok_or_else(|| DaemonError::Backend("engine plugin returned a null interface".into()))?
        };
        let interface: &'static EngineInterface = unsafe { &*(interface as *const EngineInterface) };
        check_abi(interface.abi_version, path)?;
        let config = c_string(config_json)?;
        let mut handle: EngineHandle = std::ptr::null_mut();
        check(unsafe { (interface.create)(config.as_ptr(), &mut handle) }, "engine create")?;
        Ok(Self { interface, handle })
    }
}

impl EngineBackend for EnginePlugin {
    fn enroll_begin(&mut self, now_ms: u64) -> Result<u64, DaemonError> {
        let mut session = 0u64;
        check(unsafe { (self.interface.enroll_begin)(self.handle, now_ms, &mut session) }, "enroll begin")?;
        Ok(session)
    }

    fn enroll_submit(&mut self, session: u64, now_ms: u64, frame: &CapturedFrame) -> Result<EnrollProgress, DaemonError> {
        let view = views(std::slice::from_ref(frame));
        let mut out = openhello_plugin_abi::EnrollProgress {
            verdict: EnrollVerdict::NoFace,
            state: AbiEnrollState::InProgress,
            filled: 0,
            required: 0,
        };
        check(unsafe { (self.interface.enroll_submit)(self.handle, session, now_ms, view.as_ptr(), &mut out) }, "enroll submit")?;
        Ok(EnrollProgress {
            verdict: match out.verdict {
                EnrollVerdict::Accepted => Verdict::Accepted,
                EnrollVerdict::Blurred => Verdict::Blurred,
                EnrollVerdict::Occluded => Verdict::Occluded,
                EnrollVerdict::NoFace => Verdict::NoFace,
                EnrollVerdict::YawOutOfRange => Verdict::YawOutOfRange,
                EnrollVerdict::TooSoon => Verdict::TooSoon,
                EnrollVerdict::TooDark => Verdict::TooDark,
                EnrollVerdict::TooBright => Verdict::TooBright,
                EnrollVerdict::MoveLeft => Verdict::MoveLeft,
                EnrollVerdict::MoveRight => Verdict::MoveRight,
                EnrollVerdict::MoveUp => Verdict::MoveUp,
                EnrollVerdict::MoveDown => Verdict::MoveDown,
                EnrollVerdict::TooClose => Verdict::TooClose,
                EnrollVerdict::TooFar => Verdict::TooFar,
            },
            state: match out.state {
                AbiEnrollState::InProgress => EnrollState::InProgress,
                AbiEnrollState::Complete => EnrollState::Complete,
                AbiEnrollState::Failed => EnrollState::Failed,
            },
            filled: out.filled,
            required: out.required,
        })
    }

    fn enroll_commit(&mut self, session: u64) -> Result<Vec<u8>, DaemonError> {
        let mut buffer = vec![0u8; TEMPLATE_CAPACITY];
        let mut len = 0usize;
        check(
            unsafe { (self.interface.enroll_commit)(self.handle, session, buffer.as_mut_ptr(), buffer.len(), &mut len) },
            "enroll commit",
        )?;
        buffer.truncate(len);
        Ok(buffer)
    }

    fn enroll_discard(&mut self, session: u64) -> Result<(), DaemonError> {
        check(unsafe { (self.interface.enroll_discard)(self.handle, session) }, "enroll discard")
    }

    fn auth_begin(&mut self, candidates: &[(u32, Vec<u8>)], target_far: f64, max_scored_frames: u32) -> Result<u64, DaemonError> {
        let refs: Vec<TemplateRef> =
            candidates.iter().map(|(uid, data)| TemplateRef { uid: *uid, data: data.as_ptr(), len: data.len() }).collect();
        let mut session = 0u64;
        check(
            unsafe {
                (self.interface.auth_begin)(self.handle, refs.as_ptr(), refs.len(), target_far, max_scored_frames, &mut session)
            },
            "auth begin",
        )?;
        Ok(session)
    }

    fn auth_submit(&mut self, session: u64, frame: &CapturedFrame) -> Result<AuthProgress, DaemonError> {
        let view = views(std::slice::from_ref(frame));
        let mut out = AbiAuthProgress { state: AbiAuthState::Continue, uid: 0, scored_frames: 0 };
        check(unsafe { (self.interface.auth_submit)(self.handle, session, view.as_ptr(), &mut out) }, "auth submit")?;
        Ok(AuthProgress {
            verdict: match out.state {
                AbiAuthState::Continue => AuthVerdict::Continue,
                AbiAuthState::Accepted => AuthVerdict::Accepted(out.uid),
                AbiAuthState::Rejected => AuthVerdict::Rejected,
            },
            scored_frames: out.scored_frames,
        })
    }

    fn auth_end(&mut self, session: u64) -> Result<(), DaemonError> {
        check(unsafe { (self.interface.auth_end)(self.handle, session) }, "auth end")
    }
}

impl Drop for EnginePlugin {
    fn drop(&mut self) {
        unsafe { (self.interface.destroy)(self.handle) };
    }
}

pub struct StoragePlugin {
    interface: &'static StorageInterface,
    handle: StorageHandle,
}

unsafe impl Send for StoragePlugin {}

impl StoragePlugin {
    pub fn load(path: &Path, root_dir: &str) -> Result<Self, DaemonError> {
        let library = open_library(path)?;
        let interface = {
            let entry: Symbol<StorageEntry> = load_entry(library, STORAGE_ENTRY_SYMBOL, path)?;
            unsafe { entry().as_ref() }.ok_or_else(|| DaemonError::Backend("storage plugin returned a null interface".into()))?
        };
        let interface: &'static StorageInterface = unsafe { &*(interface as *const StorageInterface) };
        check_abi(interface.abi_version, path)?;
        let root = c_string(root_dir)?;
        let mut handle: StorageHandle = std::ptr::null_mut();
        check(unsafe { (interface.open)(root.as_ptr(), &mut handle) }, "storage open")?;
        Ok(Self { interface, handle })
    }
}

impl StorageBackend for StoragePlugin {
    fn put(&mut self, uid: u32, template: &[u8]) -> Result<(), DaemonError> {
        check(unsafe { (self.interface.put_template)(self.handle, uid, template.as_ptr(), template.len()) }, "storage put")
    }

    fn get(&mut self, uid: u32) -> Result<Vec<u8>, DaemonError> {
        let mut buffer = vec![0u8; TEMPLATE_CAPACITY];
        let mut len = 0usize;
        check(
            unsafe { (self.interface.get_template)(self.handle, uid, buffer.as_mut_ptr(), buffer.len(), &mut len) },
            "storage get",
        )?;
        buffer.truncate(len);
        Ok(buffer)
    }

    fn list_uids(&mut self) -> Result<Vec<u32>, DaemonError> {
        let mut uids = vec![0u32; 4096];
        let mut count = 0usize;
        check(unsafe { (self.interface.list_uids)(self.handle, uids.as_mut_ptr(), uids.len(), &mut count) }, "storage list")?;
        uids.truncate(count);
        Ok(uids)
    }

    fn purge(&mut self, uid: u32) -> Result<(), DaemonError> {
        check(unsafe { (self.interface.purge)(self.handle, uid) }, "storage purge")
    }
}

impl Drop for StoragePlugin {
    fn drop(&mut self) {
        unsafe { (self.interface.close)(self.handle) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_library_is_a_backend_error_naming_the_path() {
        let error = StoragePlugin::load(Path::new("/nonexistent/libopenhello.so"), "/tmp").err().unwrap();
        assert!(error.to_string().contains("/nonexistent/libopenhello.so"));
    }

    #[test]
    fn library_without_the_entry_symbol_is_rejected() {
        let libm = ["/usr/lib64/libm.so.6", "/lib/x86_64-linux-gnu/libm.so.6", "/usr/lib/libm.so.6"]
            .into_iter()
            .map(Path::new)
            .find(|p| p.exists())
            .expect("a libm shared object is needed for this test");
        let error = SensorPlugin::load(libm, "/dev/video0").err().unwrap();
        assert!(error.to_string().contains(SENSOR_ENTRY_SYMBOL));
    }

    #[test]
    fn interior_nul_in_arguments_is_rejected_before_crossing_the_ffi() {
        assert!(matches!(c_string("a\0b"), Err(DaemonError::InvalidRequest(_))));
    }

    #[test]
    fn plugin_statuses_map_to_domain_errors() {
        assert!(check(Status::Ok, "x").is_ok());
        assert!(matches!(check(Status::NotFound, "x"), Err(DaemonError::NotFound)));
        assert!(matches!(check(Status::AuthenticationFailed, "x"), Err(DaemonError::Tampered)));
        assert!(matches!(check(Status::EmitterFailure, "x"), Err(DaemonError::Backend(_))));
    }

    unsafe extern "C" fn fake_last_error(buffer: *mut u8, capacity: usize) -> usize {
        let message = b"camera refused the write";
        std::ptr::copy_nonoverlapping(message.as_ptr(), buffer, message.len().min(capacity));
        message.len()
    }

    #[test]
    fn sensor_failures_carry_the_reason_exported_by_the_plugin() {
        let error = check_with_reason(Status::EmitterFailure, "sensor capture", Some(fake_last_error)).unwrap_err();
        assert!(error.to_string().contains("camera refused the write"), "{error}");
        assert!(check_with_reason(Status::Ok, "x", Some(fake_last_error)).is_ok());
        assert!(check_with_reason(Status::EmitterFailure, "x", None).is_err());
    }
}
