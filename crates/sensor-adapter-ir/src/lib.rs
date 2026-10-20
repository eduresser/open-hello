mod emitter_xu;
mod illumination;
mod ioctl;
mod msxu;
mod v4l2_capture;

use std::ffi::CStr;
use std::os::raw::c_char;

use openhello_plugin_abi::{FrameView, SensorHandle, SensorInterface, Status, ABI_VERSION};
use thiserror::Error;

pub use emitter_xu::{Emitter, EmitterControl, NoEmitter, UvcXu, XuEmitter, XuTransport};
pub use illumination::LitFrameFilter;
pub use msxu::{MsxuEmitter, MsxuUnit};
pub use v4l2_capture::V4l2Camera;

use illumination::{mean_luma, MAX_CONSECUTIVE_UNLIT, MIN_LIT_MEAN, PROBE_FRAMES};

const EMITTER_ENV: &str = "OPENHELLO_IR_EMITTER";
const ALLOW_WRITE_ENV: &str = "OPENHELLO_IR_EMITTER_ALLOW_WRITE";
const AUTO_EMITTER: &str = "auto";

#[derive(Debug, Error)]
pub enum SensorError {
    #[error("camera device error: {0}")]
    Device(String),
    #[error("IR emitter configuration invalid: {0}")]
    EmitterConfig(String),
    #[error("IR emitter activation failed: {0}")]
    EmitterActivation(String),
    #[error("no IR-illuminated frames: the stream stays dark")]
    NoIllumination,
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

pub struct CaptureSession<S: FrameSource> {
    source: S,
    filter: LitFrameFilter,
}

impl<S: FrameSource> CaptureSession<S> {
    pub fn begin(emitter: &mut dyn Emitter, mut source: S) -> Result<Self, SensorError> {
        source.start()?;
        let mut filter = LitFrameFilter::default();
        if !probe_illumination(&mut source, &mut filter)? {
            emitter.activate()?;
            filter = LitFrameFilter::default();
            if !probe_illumination(&mut source, &mut filter)? {
                return Err(SensorError::NoIllumination);
            }
        }
        Ok(Self { source, filter })
    }

    pub fn next_frame(&mut self) -> Result<Frame, SensorError> {
        for _ in 0..=MAX_CONSECUTIVE_UNLIT {
            let frame = self.source.next_frame()?;
            if self.filter.admit(mean_luma(&frame.pixels)) {
                return Ok(frame);
            }
        }
        Err(SensorError::NoIllumination)
    }
}

fn probe_illumination<S: FrameSource>(source: &mut S, filter: &mut LitFrameFilter) -> Result<bool, SensorError> {
    let mut lit = false;
    for _ in 0..PROBE_FRAMES {
        let mean = mean_luma(&source.next_frame()?.pixels);
        filter.admit(mean);
        lit |= mean >= MIN_LIT_MEAN;
    }
    Ok(lit)
}

#[derive(Debug, PartialEq, Eq)]
enum EmitterPolicy {
    Auto { allow_write: bool },
    Vendor(EmitterControl),
}

impl EmitterPolicy {
    fn parse(spec: Option<&str>, allow_write: Option<&str>) -> Result<Self, SensorError> {
        match spec {
            None | Some(AUTO_EMITTER) => Ok(Self::Auto { allow_write: allow_write == Some("1") }),
            Some(vendor) => EmitterControl::parse(vendor).map(Self::Vendor),
        }
    }

    fn from_env() -> Result<Self, SensorError> {
        Self::parse(
            std::env::var(EMITTER_ENV).ok().as_deref(),
            std::env::var(ALLOW_WRITE_ENV).ok().as_deref(),
        )
    }

    fn emitter_for(self, device_path: &str, fd: std::os::fd::RawFd) -> Box<dyn Emitter> {
        match self {
            Self::Vendor(control) => Box::new(XuEmitter::new(UvcXu::new(fd), control)),
            Self::Auto { allow_write } => match msxu::locate_face_auth_unit(device_path) {
                Some(unit) => Box::new(MsxuEmitter::new(UvcXu::new(fd), unit.unit, allow_write)),
                None => Box::new(NoEmitter),
            },
        }
    }
}

struct SensorState {
    session: CaptureSession<V4l2Camera>,
    last: Option<Frame>,
}

fn open_state(device_path: &str) -> Result<SensorState, SensorError> {
    let policy = EmitterPolicy::from_env()?;
    let camera = V4l2Camera::open(device_path)?;
    let mut emitter = policy.emitter_for(device_path, camera.raw_fd());
    let session = CaptureSession::begin(emitter.as_mut(), camera)?;
    Ok(SensorState { session, last: None })
}

fn status_of(error: &SensorError) -> Status {
    match error {
        SensorError::Device(_) => Status::DeviceUnavailable,
        SensorError::EmitterConfig(_) | SensorError::EmitterActivation(_) | SensorError::NoIllumination => {
            Status::EmitterFailure
        }
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
    use std::collections::VecDeque;
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
        brightness: VecDeque<u8>,
        after_activation: u8,
        activated: bool,
    }

    impl FakeSource {
        fn new(log: &Log, brightness: &[u8]) -> Self {
            Self { log: log.clone(), brightness: brightness.iter().copied().collect(), after_activation: 0, activated: false }
        }
    }

    impl FrameSource for FakeSource {
        fn start(&mut self) -> Result<(), SensorError> {
            self.log.borrow_mut().push("stream");
            Ok(())
        }

        fn next_frame(&mut self) -> Result<Frame, SensorError> {
            if !self.activated && self.log.borrow().contains(&"emitter") {
                self.activated = true;
                self.brightness.clear();
            }
            let level = if self.activated && self.after_activation > 0 {
                self.after_activation
            } else {
                self.brightness.pop_front().unwrap_or(5)
            };
            Ok(Frame { width: 4, height: 4, pixels: vec![level; 16], timestamp_us: u64::from(level) })
        }
    }

    fn strobing(frames: usize) -> Vec<u8> {
        (0..frames).map(|i| if i % 2 == 0 { 7 } else { 66 }).collect()
    }

    // @spec:AC-011
    #[test]
    fn strobing_camera_needs_no_activation_and_only_lit_frames_are_returned() {
        let log: Log = Rc::default();
        let mut emitter = FakeEmitter { log: log.clone(), fail: false };
        let source = FakeSource::new(&log, &strobing(100));
        let mut session = CaptureSession::begin(&mut emitter, source).unwrap();
        for _ in 0..10 {
            assert_eq!(session.next_frame().unwrap().pixels[0], 66);
        }
        assert_eq!(*log.borrow(), vec!["stream"]);
    }

    // @spec:AC-011
    #[test]
    fn dark_stream_activates_the_emitter_after_the_stream_starts_and_then_returns_lit_frames() {
        let log: Log = Rc::default();
        let mut emitter = FakeEmitter { log: log.clone(), fail: false };
        let mut source = FakeSource::new(&log, &[5; 100]);
        source.after_activation = 80;
        let mut session = CaptureSession::begin(&mut emitter, source).unwrap();
        assert_eq!(session.next_frame().unwrap().pixels[0], 80);
        assert_eq!(*log.borrow(), vec!["stream", "emitter"]);
    }

    // @spec:AC-011
    #[test]
    fn emitter_failure_on_a_dark_stream_is_an_explicit_error() {
        let log: Log = Rc::default();
        let mut emitter = FakeEmitter { log: log.clone(), fail: true };
        let result = CaptureSession::begin(&mut emitter, FakeSource::new(&log, &[5; 100]));
        assert!(matches!(result.err(), Some(SensorError::EmitterActivation(_))));
    }

    // @spec:AC-011
    #[test]
    fn stream_that_stays_dark_after_activation_is_an_explicit_error() {
        let log: Log = Rc::default();
        let mut emitter = FakeEmitter { log: log.clone(), fail: false };
        let result = CaptureSession::begin(&mut emitter, FakeSource::new(&log, &[5; 100]));
        assert!(matches!(result.err(), Some(SensorError::NoIllumination)));
        assert_eq!(*log.borrow(), vec!["stream", "emitter"]);
    }

    // @spec:AC-011
    #[test]
    fn stream_that_goes_dark_mid_session_reports_no_illumination_instead_of_unlit_frames() {
        let log: Log = Rc::default();
        let mut emitter = FakeEmitter { log: log.clone(), fail: false };
        let mut brightness = vec![66; PROBE_FRAMES];
        brightness.extend(vec![5; 200]);
        let mut session = CaptureSession::begin(&mut emitter, FakeSource::new(&log, &brightness)).unwrap();
        assert!(matches!(session.next_frame().err(), Some(SensorError::NoIllumination)));
    }

    #[test]
    fn auto_policy_is_the_default_and_only_writes_when_explicitly_allowed() {
        assert_eq!(EmitterPolicy::parse(None, None).unwrap(), EmitterPolicy::Auto { allow_write: false });
        assert_eq!(EmitterPolicy::parse(Some("auto"), Some("1")).unwrap(), EmitterPolicy::Auto { allow_write: true });
        assert_eq!(EmitterPolicy::parse(Some("auto"), Some("yes")).unwrap(), EmitterPolicy::Auto { allow_write: false });
    }

    #[test]
    fn vendor_policy_parses_the_xu_spec_and_rejects_garbage() {
        let policy = EmitterPolicy::parse(Some("14:6:01030200"), None).unwrap();
        assert_eq!(policy, EmitterPolicy::Vendor(EmitterControl { unit: 14, selector: 6, payload: vec![1, 3, 2, 0] }));
        assert!(matches!(EmitterPolicy::parse(Some("garbage"), None), Err(SensorError::EmitterConfig(_))));
    }

    #[test]
    fn camera_without_a_known_emitter_control_cannot_activate() {
        assert!(NoEmitter.activate().is_err());
    }

    // @spec:AC-011
    #[test]
    fn ffi_open_with_invalid_emitter_config_reports_emitter_failure_without_touching_the_device() {
        std::env::set_var(EMITTER_ENV, "garbage");
        let path = std::ffi::CString::new("/dev/openhello-no-such-camera").unwrap();
        let mut handle: SensorHandle = std::ptr::null_mut();
        let status = unsafe { (openhello_sensor_interface().as_ref().unwrap().open)(path.as_ptr(), &mut handle) };
        std::env::remove_var(EMITTER_ENV);
        assert_eq!(status, Status::EmitterFailure);
        assert!(handle.is_null());
    }
}
