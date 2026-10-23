mod emitter_xu;
mod illumination;
mod ioctl;
mod lazy;
mod msxu;
mod v4l2_capture;

use std::ffi::CStr;
use std::os::raw::c_char;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use openhello_plugin_abi::{FrameView, SensorHandle, SensorInterface, Status, ABI_VERSION};
use thiserror::Error;

pub use emitter_xu::{Emitter, EmitterControl, NoEmitter, UvcXu, XuEmitter, XuTransport};
pub use illumination::LitFrameFilter;
pub use msxu::{MsxuEmitter, MsxuUnit};
pub use v4l2_capture::V4l2Camera;

use lazy::{LazyCapture, IDLE_RELEASE};
use illumination::{mean_luma, AlternationDetector, MAX_CONSECUTIVE_UNLIT, MAX_PROBE_FRAMES, MIN_LIT_MEAN, PROBE_LIT_FRAMES};

const EMITTER_ENV: &str = "OPENHELLO_IR_EMITTER";
const AUTO_EMITTER: &str = "auto";

#[derive(Debug, Error)]
pub enum SensorError {
    #[error("camera device error: {0}")]
    Device(String),
    #[error("camera device busy: {0}")]
    DeviceBusy(String),
    #[error("camera device missing: {0}")]
    NoDevice(String),
    #[error("IR emitter configuration invalid: {0}")]
    EmitterConfig(String),
    #[error("IR emitter activation failed: {0}")]
    EmitterActivation(String),
    #[error("no IR-illuminated frames: the stream stays dark")]
    NoIllumination,
    #[error("the camera refused the alternating-illumination write: {0}")]
    EmitterWriteRefused(String),
    #[error("the camera did not keep the alternating-illumination mode (read back mode {0})")]
    EmitterNotConfirmed(u8),
    #[error("the stream never alternates between lit and unlit frames although the emitter is controllable")]
    NoAlternation,
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
    probed: VecDeque<Frame>,
}

struct Probe {
    lit: bool,
    frames: VecDeque<Frame>,
}

impl<S: FrameSource> CaptureSession<S> {
    pub fn begin(emitter: &mut dyn Emitter, mut source: S) -> Result<Self, SensorError> {
        let controllable = emitter.controllable();
        if controllable {
            emitter.ensure()?;
        }
        source.start()?;
        let mut filter = LitFrameFilter::default();
        let mut probe = probe_illumination(&mut source, &mut filter, controllable)?;
        if controllable {
            if !probe.lit {
                return Err(SensorError::NoAlternation);
            }
            return Ok(Self { source, filter, probed: probe.frames });
        }
        if !probe.lit {
            emitter.activate()?;
            filter = LitFrameFilter::default();
            probe = probe_illumination(&mut source, &mut filter, false)?;
            if !probe.lit {
                return Err(SensorError::NoIllumination);
            }
        }
        Ok(Self { source, filter, probed: probe.frames })
    }

    pub fn next_frame(&mut self) -> Result<Frame, SensorError> {
        if let Some(frame) = self.probed.pop_front() {
            return Ok(frame);
        }
        for _ in 0..=MAX_CONSECUTIVE_UNLIT {
            let frame = self.source.next_frame()?;
            if self.filter.admit(mean_luma(&frame.pixels)) {
                return Ok(frame);
            }
        }
        Err(SensorError::NoIllumination)
    }
}

fn probe_illumination<S: FrameSource>(
    source: &mut S,
    filter: &mut LitFrameFilter,
    require_alternation: bool,
) -> Result<Probe, SensorError> {
    let mut probe = Probe { lit: false, frames: VecDeque::new() };
    let mut detector = AlternationDetector::default();
    for _ in 0..MAX_PROBE_FRAMES {
        let frame = source.next_frame()?;
        let mean = mean_luma(&frame.pixels);
        detector.observe(mean);
        probe.lit |= mean >= MIN_LIT_MEAN;
        if filter.admit(mean) {
            probe.frames.push_back(frame);
        }
        if probe.frames.len() >= PROBE_LIT_FRAMES && (!require_alternation || detector.alternating()) {
            break;
        }
    }
    if require_alternation {
        probe.lit = detector.alternating() && !probe.frames.is_empty();
    }
    Ok(probe)
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum EmitterPolicy {
    Auto,
    Vendor(EmitterControl),
}

impl EmitterPolicy {
    fn parse(spec: Option<&str>) -> Result<Self, SensorError> {
        match spec {
            None | Some(AUTO_EMITTER) => Ok(Self::Auto),
            Some(vendor) => EmitterControl::parse(vendor).map(Self::Vendor),
        }
    }

    fn from_env() -> Result<Self, SensorError> {
        Self::parse(std::env::var(EMITTER_ENV).ok().as_deref())
    }

    fn emitter_for(self, device_path: &str, fd: std::os::fd::RawFd) -> Box<dyn Emitter> {
        match self {
            Self::Vendor(control) => Box::new(XuEmitter::new(UvcXu::new(fd), control)),
            Self::Auto => match msxu::locate_face_auth_unit(device_path) {
                Some(unit) => Box::new(MsxuEmitter::new(UvcXu::new(fd), unit.unit)),
                None => Box::new(NoEmitter),
            },
        }
    }
}

struct SensorState {
    capture: LazyCapture<V4l2Camera>,
    last: Option<Frame>,
}

type SharedState = Arc<Mutex<SensorState>>;

fn open_state(device_path: &str) -> Result<SharedState, SensorError> {
    let policy = EmitterPolicy::from_env()?;
    if !std::path::Path::new(device_path).exists() {
        return Err(SensorError::NoDevice(format!("{device_path} does not exist")));
    }
    let path = device_path.to_string();
    let opener = Box::new(move || {
        let camera = V4l2Camera::open(&path)?;
        let mut emitter = policy.clone().emitter_for(&path, camera.raw_fd());
        CaptureSession::begin(emitter.as_mut(), camera)
    });
    let state = Arc::new(Mutex::new(SensorState { capture: LazyCapture::new(opener, Instant::now()), last: None }));
    spawn_idle_release(Arc::downgrade(&state));
    Ok(state)
}

fn spawn_idle_release(state: std::sync::Weak<Mutex<SensorState>>) {
    std::thread::spawn(move || {
        while let Some(shared) = state.upgrade() {
            if let Ok(mut guard) = shared.lock() {
                guard.capture.release_if_idle(Instant::now(), IDLE_RELEASE);
            }
            drop(shared);
            std::thread::sleep(Duration::from_millis(500));
        }
    });
}

fn status_of(error: &SensorError) -> Status {
    match error {
        SensorError::Device(_) => Status::DeviceUnavailable,
        SensorError::DeviceBusy(_) => Status::DeviceBusy,
        SensorError::NoDevice(_) => Status::NoDevice,
        SensorError::EmitterConfig(_) | SensorError::EmitterActivation(_) | SensorError::EmitterWriteRefused(_) => Status::EmitterFailure,
        SensorError::NoIllumination | SensorError::EmitterNotConfirmed(_) | SensorError::NoAlternation => Status::SensorStuck,
    }
}

static LAST_ERROR: Mutex<String> = Mutex::new(String::new());

fn fail(error: &SensorError) -> Status {
    if let Ok(mut last) = LAST_ERROR.lock() {
        *last = error.to_string();
    }
    status_of(error)
}

/// # Safety
/// `buffer` must be valid for `capacity` bytes. Returns the full message length; the copy is truncated to `capacity`.
#[no_mangle]
pub unsafe extern "C" fn openhello_sensor_last_error(buffer: *mut u8, capacity: usize) -> usize {
    let Ok(last) = LAST_ERROR.lock() else {
        return 0;
    };
    let bytes = last.as_bytes();
    if !buffer.is_null() {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), buffer, bytes.len().min(capacity));
    }
    bytes.len()
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
        Err(error) => fail(&error),
    }
}

unsafe extern "C" fn sensor_capture(handle: SensorHandle, out: *mut FrameView) -> Status {
    if handle.is_null() || out.is_null() {
        return Status::InvalidArgument;
    }
    let shared = &*(handle as *const SharedState);
    let Ok(mut state) = shared.lock() else {
        return Status::Internal;
    };
    match state.capture.next_frame(Instant::now()) {
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
        Err(error) => fail(&error),
    }
}

unsafe extern "C" fn sensor_release_frame(_handle: SensorHandle, _frame: *const FrameView) {}

unsafe extern "C" fn sensor_release(handle: SensorHandle) {
    if handle.is_null() {
        return;
    }
    let shared = &*(handle as *const SharedState);
    if let Ok(mut state) = shared.lock() {
        state.capture.release();
    }
}

unsafe extern "C" fn sensor_close(handle: SensorHandle) {
    if !handle.is_null() {
        drop(Box::from_raw(handle as *mut SharedState));
    }
}

static SENSOR_INTERFACE: SensorInterface = SensorInterface {
    abi_version: ABI_VERSION,
    open: sensor_open,
    capture: sensor_capture,
    release_frame: sensor_release_frame,
    release: sensor_release,
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

    #[test]
    fn lit_frames_seen_while_probing_are_delivered_first_instead_of_being_thrown_away() {
        let log: Log = Rc::default();
        let mut emitter = FakeEmitter { log: log.clone(), fail: false };
        let brightness: Vec<u8> = (60..100).collect();
        let mut session = CaptureSession::begin(&mut emitter, FakeSource::new(&log, &brightness)).unwrap();
        let first: Vec<u64> = (0..PROBE_LIT_FRAMES + 2).map(|_| session.next_frame().unwrap().timestamp_us).collect();
        assert_eq!(first, (60..60 + PROBE_LIT_FRAMES as u64 + 2).collect::<Vec<_>>());
    }

    // @spec:AC-011
    #[test]
    fn camera_that_needs_a_warm_up_before_lighting_is_waited_for_without_touching_the_emitter() {
        let log: Log = Rc::default();
        let mut emitter = FakeEmitter { log: log.clone(), fail: false };
        let mut brightness = vec![5; 40];
        brightness.extend(vec![66; 60]);
        let mut session = CaptureSession::begin(&mut emitter, FakeSource::new(&log, &brightness)).unwrap();
        assert_eq!(session.next_frame().unwrap().pixels[0], 66);
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

    struct WarmUpLevelSource;

    impl FrameSource for WarmUpLevelSource {
        fn start(&mut self) -> Result<(), SensorError> {
            Ok(())
        }

        fn next_frame(&mut self) -> Result<Frame, SensorError> {
            Ok(Frame { width: 8, height: 8, pixels: vec![25; 64], timestamp_us: 0 })
        }
    }

    // @spec:AC-011
    #[test]
    fn stream_stuck_at_the_warm_up_level_is_treated_as_unlit() {
        let log: Log = Rc::default();
        let mut emitter = FakeEmitter { log: log.clone(), fail: false };
        let result = CaptureSession::begin(&mut emitter, WarmUpLevelSource);
        assert!(matches!(result.err(), Some(SensorError::NoIllumination)));
        assert_eq!(*log.borrow(), vec!["emitter"]);
    }

    // @spec:AC-011
    #[test]
    fn stream_that_goes_dark_mid_session_reports_no_illumination_instead_of_unlit_frames() {
        let log: Log = Rc::default();
        let mut emitter = FakeEmitter { log: log.clone(), fail: false };
        let mut brightness = vec![66; PROBE_LIT_FRAMES];
        brightness.extend(vec![5; 200]);
        let mut session = CaptureSession::begin(&mut emitter, FakeSource::new(&log, &brightness)).unwrap();
        for _ in 0..PROBE_LIT_FRAMES {
            assert_eq!(session.next_frame().unwrap().pixels[0], 66);
        }
        assert!(matches!(session.next_frame().err(), Some(SensorError::NoIllumination)));
    }

    #[derive(Clone, Copy, PartialEq)]
    enum Stream {
        FollowsMode,
        Ambient,
        Flat(u8),
    }

    struct Camera {
        mode: u8,
        writes: Vec<u8>,
        streaming: bool,
        write_before_stream: bool,
        refuse_writes: bool,
        ignore_writes: bool,
        stream: Stream,
    }

    type SharedCamera = Rc<RefCell<Camera>>;

    fn camera(mode: u8, stream: Stream) -> SharedCamera {
        Rc::new(RefCell::new(Camera {
            mode,
            writes: Vec::new(),
            streaming: false,
            write_before_stream: true,
            refuse_writes: false,
            ignore_writes: false,
            stream,
        }))
    }

    struct CameraXu(SharedCamera);

    impl XuTransport for CameraXu {
        fn query(&mut self, _unit: u8, _selector: u8, request: u8, data: &mut [u8]) -> Result<(), SensorError> {
            let mut camera = self.0.borrow_mut();
            match request {
                crate::emitter_xu::UVC_GET_LEN => data.copy_from_slice(&9u16.to_le_bytes()),
                crate::emitter_xu::UVC_GET_CUR => data.copy_from_slice(&[1, 3, camera.mode, 0, 0, 0, 0, 0, 0]),
                crate::emitter_xu::UVC_GET_MAX => data.copy_from_slice(&[1, 3, 2, 0, 0, 0, 0, 0, 0]),
                _ => {
                    if camera.refuse_writes {
                        return Err(SensorError::EmitterActivation("Input/output error".into()));
                    }
                    camera.write_before_stream &= !camera.streaming;
                    camera.writes.push(data[2]);
                    if !camera.ignore_writes {
                        camera.mode = data[2];
                    }
                }
            }
            Ok(())
        }
    }

    struct CameraSource {
        camera: SharedCamera,
        tick: usize,
    }

    impl FrameSource for CameraSource {
        fn start(&mut self) -> Result<(), SensorError> {
            self.camera.borrow_mut().streaming = true;
            Ok(())
        }

        fn next_frame(&mut self) -> Result<Frame, SensorError> {
            self.tick += 1;
            let camera = self.camera.borrow();
            let level = match camera.stream {
                Stream::Flat(level) => level,
                Stream::Ambient => 31 + (self.tick % 100) as u8,
                Stream::FollowsMode if camera.mode == 2 => if self.tick.is_multiple_of(2) { 15 } else { 98 },
                Stream::FollowsMode => 90,
            };
            Ok(Frame { width: 4, height: 4, pixels: vec![level; 16], timestamp_us: self.tick as u64 })
        }
    }

    fn begin_with(camera: &SharedCamera) -> Result<CaptureSession<CameraSource>, SensorError> {
        let mut emitter = MsxuEmitter::new(CameraXu(camera.clone()), 7);
        CaptureSession::begin(&mut emitter, CameraSource { camera: camera.clone(), tick: 0 })
    }

    // @spec:AC-039
    #[test]
    fn controllable_emitter_is_forced_to_alternate_before_streaming_and_a_non_alternating_stream_fails_closed() {
        let cam = camera(1, Stream::FollowsMode);
        let mut session = begin_with(&cam).unwrap();
        assert_eq!(cam.borrow().writes, vec![2]);
        assert!(cam.borrow().write_before_stream);
        for _ in 0..20 {
            assert_eq!(session.next_frame().unwrap().pixels[0], 98);
        }

        let cam = camera(1, Stream::FollowsMode);
        cam.borrow_mut().refuse_writes = true;
        assert!(matches!(begin_with(&cam).err(), Some(SensorError::EmitterWriteRefused(_))));

        let cam = camera(1, Stream::FollowsMode);
        cam.borrow_mut().ignore_writes = true;
        assert!(matches!(begin_with(&cam).err(), Some(SensorError::EmitterNotConfirmed(1))));

        let cam = camera(2, Stream::Ambient);
        assert!(matches!(begin_with(&cam).err(), Some(SensorError::NoAlternation)));
        assert!(cam.borrow().writes.is_empty());

        let log: Log = Rc::default();
        let mut session = CaptureSession::begin(&mut NoEmitter, FakeSource::new(&log, &[60; 20])).unwrap();
        assert_eq!(session.next_frame().unwrap().pixels[0], 60);
    }

    // @covers:AC-039-no-rewrite
    #[test]
    fn camera_already_alternating_is_not_written_and_delivers_lit_frames() {
        let cam = camera(2, Stream::FollowsMode);
        let mut session = begin_with(&cam).unwrap();
        assert!(cam.borrow().writes.is_empty());
        assert_eq!(session.next_frame().unwrap().pixels[0], 98);
    }

    // @covers:AC-039-ambient
    #[test]
    fn ambient_lit_constant_stream_is_rejected_on_a_controllable_emitter() {
        let cam = camera(2, Stream::Flat(90));
        assert!(matches!(begin_with(&cam).err(), Some(SensorError::NoAlternation)));
    }

    // @covers:AC-039-warm-up
    #[test]
    fn flat_warm_up_frames_are_not_admitted_on_a_controllable_emitter() {
        let cam = camera(2, Stream::Flat(25));
        assert!(matches!(begin_with(&cam).err(), Some(SensorError::NoAlternation)));
    }

    // @covers:AC-039-unsupported
    #[test]
    fn camera_lacking_the_alternating_capability_fails_before_streaming() {
        struct NoCapability(SharedCamera);
        impl XuTransport for NoCapability {
            fn query(&mut self, unit: u8, selector: u8, request: u8, data: &mut [u8]) -> Result<(), SensorError> {
                CameraXu(self.0.clone()).query(unit, selector, request, data)?;
                if request == crate::emitter_xu::UVC_GET_CUR {
                    data[1] = 1;
                }
                Ok(())
            }
        }
        let cam = camera(1, Stream::FollowsMode);
        let mut emitter = MsxuEmitter::new(NoCapability(cam.clone()), 7);
        let result = CaptureSession::begin(&mut emitter, CameraSource { camera: cam.clone(), tick: 0 });
        assert!(matches!(result.err(), Some(SensorError::EmitterActivation(_))));
        assert!(!cam.borrow().streaming);
    }

    #[test]
    fn emitter_errors_are_reported_as_emitter_failure_with_the_reason_available() {
        let error = SensorError::EmitterWriteRefused("denied".into());
        assert_eq!(fail(&error), Status::EmitterFailure);
        let mut buffer = [0u8; 256];
        let length = unsafe { openhello_sensor_last_error(buffer.as_mut_ptr(), buffer.len()) };
        assert_eq!(std::str::from_utf8(&buffer[..length]).unwrap(), error.to_string());
    }

    #[test]
    fn stuck_stream_busy_and_missing_camera_get_their_own_statuses() {
        assert_eq!(status_of(&SensorError::NoAlternation), Status::SensorStuck);
        assert_eq!(status_of(&SensorError::EmitterNotConfirmed(1)), Status::SensorStuck);
        assert_eq!(status_of(&SensorError::NoIllumination), Status::SensorStuck);
        assert_eq!(status_of(&SensorError::DeviceBusy("x".into())), Status::DeviceBusy);
        assert_eq!(status_of(&SensorError::NoDevice("x".into())), Status::NoDevice);
        assert_eq!(status_of(&SensorError::Device("x".into())), Status::DeviceUnavailable);
    }

    #[test]
    fn auto_policy_is_the_default_and_needs_no_environment_switch() {
        assert_eq!(EmitterPolicy::parse(None).unwrap(), EmitterPolicy::Auto);
        assert_eq!(EmitterPolicy::parse(Some("auto")).unwrap(), EmitterPolicy::Auto);
    }

    #[test]
    fn vendor_policy_parses_the_xu_spec_and_rejects_garbage() {
        let policy = EmitterPolicy::parse(Some("14:6:01030200")).unwrap();
        assert_eq!(policy, EmitterPolicy::Vendor(EmitterControl { unit: 14, selector: 6, payload: vec![1, 3, 2, 0] }));
        assert!(matches!(EmitterPolicy::parse(Some("garbage")), Err(SensorError::EmitterConfig(_))));
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
