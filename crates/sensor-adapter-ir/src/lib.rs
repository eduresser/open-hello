mod emitter_xu;
mod ioctl;
mod v4l2_capture;

use std::ffi::CStr;
use std::os::raw::c_char;

use openhello_plugin_abi::{FrameView, SensorHandle, SensorInterface, Status, ABI_VERSION};
use thiserror::Error;

pub use emitter_xu::{Emitter, EmitterControl, XuEmitter};
pub use v4l2_capture::V4l2Camera;

const EMITTER_ENV: &str = "OPENHELLO_IR_EMITTER";

#[derive(Debug, Error)]
pub enum SensorError {
    #[error("camera device error: {0}")]
    Device(String),
    #[error("IR emitter configuration invalid: {0}")]
    EmitterConfig(String),
    #[error("IR emitter activation failed: {0}")]
    EmitterActivation(String),
}

#[derive(Debug, Clone)]
pub struct Frame {
    pub width: u32,
    pub height: u32,
    pub pixels: Vec<u8>,
    pub timestamp_us: u64,
}

pub trait FrameSource {
    fn start(&mut self) -> Result<(), SensorError>;
    fn next_frame(&mut self) -> Result<Frame, SensorError>;
}

pub struct CaptureSession<E: Emitter, S: FrameSource> {
    source: S,
    _emitter: E,
}

impl<E: Emitter, S: FrameSource> CaptureSession<E, S> {
    pub fn begin(mut emitter: E, mut source: S) -> Result<Self, SensorError> {
        emitter.activate()?;
        source.start()?;
        Ok(Self { source, _emitter: emitter })
    }

    pub fn next_frame(&mut self) -> Result<Frame, SensorError> {
        self.source.next_frame()
    }
}

struct SensorState {
    session: CaptureSession<XuEmitter, V4l2Camera>,
    last: Option<Frame>,
}

fn open_state(device_path: &str) -> Result<SensorState, SensorError> {
    let spec = std::env::var(EMITTER_ENV)
        .map_err(|_| SensorError::EmitterConfig(format!("{EMITTER_ENV} is not set")))?;
    let control = EmitterControl::parse(&spec)?;
    let camera = V4l2Camera::open(device_path)?;
    let emitter = XuEmitter::new(camera.raw_fd(), control);
    let session = CaptureSession::begin(emitter, camera)?;
    Ok(SensorState { session, last: None })
}

fn status_of(error: &SensorError) -> Status {
    match error {
        SensorError::Device(_) => Status::DeviceUnavailable,
        SensorError::EmitterConfig(_) | SensorError::EmitterActivation(_) => Status::EmitterFailure,
    }
}

unsafe extern "C" fn sensor_open(device_path: *const c_char, out: *mut SensorHandle) -> Status {
    if device_path.is_null() || out.is_null() {
        return Status::InvalidArgument;
    }
    let Ok(path) = CStr::from_ptr(device_path).to_str() else {
        return Status::InvalidArgument;
    };
    match open_state(path) {
        Ok(state) => {
            *out = Box::into_raw(Box::new(state)) as SensorHandle;
            Status::Ok
        }
        Err(error) => status_of(&error),
    }
}

unsafe extern "C" fn sensor_capture(handle: SensorHandle, out: *mut FrameView) -> Status {
    if handle.is_null() || out.is_null() {
        return Status::InvalidArgument;
    }
    let state = &mut *(handle as *mut SensorState);
    match state.session.next_frame() {
        Ok(frame) => {
            let stored = state.last.insert(frame);
            *out = FrameView {
                width: stored.width,
                height: stored.height,
                data: stored.pixels.as_ptr(),
                len: stored.pixels.len(),
                timestamp_us: stored.timestamp_us,
            };
            Status::Ok
        }
        Err(error) => status_of(&error),
    }
}

unsafe extern "C" fn sensor_release_frame(_handle: SensorHandle, _frame: *const FrameView) {}

unsafe extern "C" fn sensor_close(handle: SensorHandle) {
    if !handle.is_null() {
        drop(Box::from_raw(handle as *mut SensorState));
    }
}

static SENSOR_INTERFACE: SensorInterface = SensorInterface {
    abi_version: ABI_VERSION,
    open: sensor_open,
    capture: sensor_capture,
    release_frame: sensor_release_frame,
    close: sensor_close,
};

#[no_mangle]
pub extern "C" fn openhello_sensor_interface() -> *const SensorInterface {
    &SENSOR_INTERFACE
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use super::*;

    type Log = Rc<RefCell<Vec<&'static str>>>;

    struct FakeEmitter {
        log: Log,
        fail: bool,
    }

    impl Emitter for FakeEmitter {
        fn activate(&mut self) -> Result<(), SensorError> {
            self.log.borrow_mut().push("emitter");
            if self.fail {
                Err(SensorError::EmitterActivation("XU rejected".into()))
            } else {
                Ok(())
            }
        }
    }

    struct FakeSource {
        log: Log,
    }

    impl FrameSource for FakeSource {
        fn start(&mut self) -> Result<(), SensorError> {
            self.log.borrow_mut().push("stream");
            Ok(())
        }

        fn next_frame(&mut self) -> Result<Frame, SensorError> {
            self.log.borrow_mut().push("frame");
            Ok(Frame { width: 2, height: 2, pixels: vec![0; 4], timestamp_us: 0 })
        }
    }

    // @spec:AC-011
    #[test]
    fn capture_activates_emitter_before_first_frame() {
        let log: Log = Rc::default();
        let emitter = FakeEmitter { log: log.clone(), fail: false };
        let mut session = CaptureSession::begin(emitter, FakeSource { log: log.clone() }).unwrap();
        session.next_frame().unwrap();
        assert_eq!(*log.borrow(), vec!["emitter", "stream", "frame"]);
    }

    // @spec:AC-011
    #[test]
    fn emitter_failure_is_an_explicit_error_and_no_stream_starts() {
        let log: Log = Rc::default();
        let emitter = FakeEmitter { log: log.clone(), fail: true };
        let result = CaptureSession::begin(emitter, FakeSource { log: log.clone() });
        assert!(matches!(result.err(), Some(SensorError::EmitterActivation(_))));
        assert_eq!(*log.borrow(), vec!["emitter"]);
    }

    // @spec:AC-011
    #[test]
    fn ffi_open_without_emitter_config_reports_emitter_failure() {
        std::env::remove_var(EMITTER_ENV);
        let path = std::ffi::CString::new("/dev/video2").unwrap();
        let mut handle: SensorHandle = std::ptr::null_mut();
        let status = unsafe { (openhello_sensor_interface().as_ref().unwrap().open)(path.as_ptr(), &mut handle) };
        assert_eq!(status, Status::EmitterFailure);
        assert!(handle.is_null());
    }
}
