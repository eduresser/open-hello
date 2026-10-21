use std::ffi::CStr;
use std::os::raw::c_char;

use openhello_plugin_abi::{
    AuthProgress, AuthState, EngineHandle, EngineInterface, EnrollProgress, EnrollState, EnrollVerdict, FrameView, Status,
    TemplateRef, ABI_VERSION,
};
use serde::Deserialize;

use crate::engine::{AuthVerdict, Engine, Verdict};
use crate::enrollment_quality::SessionState;
use crate::matching::Template;
use crate::{EngineError, GrayImage};

#[derive(Debug, Deserialize)]
pub struct EngineConfig {
    pub models_dir: String,
    pub calibration_path: String,
}

#[cfg(feature = "ort-backend")]
pub fn build_engine(config: &EngineConfig) -> Result<Engine, EngineError> {
    use std::path::Path;

    use crate::detect::ort_backend::YunetDetector;
    use crate::embedding::ort_backend::AuraFaceEmbedder;
    use crate::enrollment_quality::EnrollmentConfig;
    use crate::far_calibration::FarCalibration;
    use crate::liveness::LivenessConfig;
    use crate::matching::Matcher;

    let models = Path::new(&config.models_dir);
    let calibration_bytes = std::fs::read(&config.calibration_path)
        .map_err(|e| EngineError::InvalidInput(format!("calibration file {}: {e}", config.calibration_path)))?;
    Ok(Engine::new(
        Box::new(YunetDetector::load(&models.join("yunet.onnx"))?),
        Box::new(AuraFaceEmbedder::load(&models.join("glintr100.onnx"))?),
        Matcher::new(FarCalibration::from_bytes(&calibration_bytes)?),
        EnrollmentConfig::default(),
        LivenessConfig::default(),
    ))
}

#[cfg(not(feature = "ort-backend"))]
pub fn build_engine(_: &EngineConfig) -> Result<Engine, EngineError> {
    Err(EngineError::Model("built without the ort-backend feature".into()))
}

fn status_of(error: &EngineError) -> Status {
    match error {
        EngineError::Model(_) => {
            eprintln!("engine-adapter-face: {error}");
            Status::Internal
        }
        EngineError::InvalidInput(_) => {
            eprintln!("engine-adapter-face: {error}");
            Status::InvalidArgument
        }
        EngineError::NoFace => Status::InvalidArgument,
    }
}

unsafe fn engine<'a>(handle: EngineHandle) -> Option<&'a Engine> {
    (handle as *const Engine).as_ref()
}

unsafe fn image(frame: &FrameView) -> Result<GrayImage, EngineError> {
    if frame.data.is_null() {
        return Err(EngineError::InvalidInput("null frame data".into()));
    }
    GrayImage::new(frame.width, frame.height, std::slice::from_raw_parts(frame.data, frame.len).to_vec())
}

unsafe extern "C" fn engine_create(config: *const c_char, out: *mut EngineHandle) -> Status {
    if config.is_null() || out.is_null() {
        return Status::InvalidArgument;
    }
    let Ok(text) = CStr::from_ptr(config).to_str() else {
        return Status::InvalidArgument;
    };
    let Ok(parsed) = serde_json::from_str::<EngineConfig>(text) else {
        return Status::InvalidArgument;
    };
    match build_engine(&parsed) {
        Ok(built) => {
            *out = Box::into_raw(Box::new(built)) as EngineHandle;
            Status::Ok
        }
        Err(error) => status_of(&error),
    }
}

unsafe extern "C" fn engine_enroll_begin(handle: EngineHandle, now_ms: u64, out_session: *mut u64) -> Status {
    let (Some(engine), false) = (engine(handle), out_session.is_null()) else {
        return Status::InvalidArgument;
    };
    *out_session = engine.enroll_begin(now_ms);
    Status::Ok
}

unsafe extern "C" fn engine_enroll_submit(
    handle: EngineHandle,
    session: u64,
    now_ms: u64,
    frame: *const FrameView,
    out: *mut EnrollProgress,
) -> Status {
    let (Some(engine), Some(frame), false) = (engine(handle), frame.as_ref(), out.is_null()) else {
        return Status::InvalidArgument;
    };
    let result = image(frame).and_then(|img| engine.enroll_submit(session, now_ms, &img));
    match result {
        Ok(progress) => {
            *out = EnrollProgress {
                verdict: match progress.verdict {
                    Verdict::Accepted => EnrollVerdict::Accepted,
                    Verdict::Blurred => EnrollVerdict::Blurred,
                    Verdict::Occluded => EnrollVerdict::Occluded,
                    Verdict::NoFace => EnrollVerdict::NoFace,
                    Verdict::YawOutOfRange => EnrollVerdict::YawOutOfRange,
                    Verdict::BucketAlreadyFilled => EnrollVerdict::BucketAlreadyFilled,
                },
                state: match progress.state {
                    SessionState::InProgress { .. } => EnrollState::InProgress,
                    SessionState::Complete => EnrollState::Complete,
                    SessionState::Failed => EnrollState::Failed,
                },
                filled: progress.filled as u32,
                required: progress.required as u32,
            };
            Status::Ok
        }
        Err(error) => status_of(&error),
    }
}

unsafe extern "C" fn engine_enroll_commit(
    handle: EngineHandle,
    session: u64,
    out: *mut u8,
    out_capacity: usize,
    out_len: *mut usize,
) -> Status {
    let (Some(engine), false, false) = (engine(handle), out.is_null(), out_len.is_null()) else {
        return Status::InvalidArgument;
    };
    match engine.enroll_commit(session) {
        Ok(template) => {
            *out_len = template.len();
            if template.len() > out_capacity {
                return Status::BufferTooSmall;
            }
            std::ptr::copy_nonoverlapping(template.as_ptr(), out, template.len());
            Status::Ok
        }
        Err(error) => status_of(&error),
    }
}

unsafe extern "C" fn engine_enroll_discard(handle: EngineHandle, session: u64) -> Status {
    let Some(engine) = engine(handle) else {
        return Status::InvalidArgument;
    };
    if engine.enroll_discard(session) {
        Status::Ok
    } else {
        Status::NotFound
    }
}

unsafe extern "C" fn engine_auth_begin(
    handle: EngineHandle,
    candidates: *const TemplateRef,
    candidate_count: usize,
    target_far: f64,
    max_scored_frames: u32,
    out_session: *mut u64,
) -> Status {
    let (Some(engine), false, false) = (engine(handle), candidates.is_null(), out_session.is_null()) else {
        return Status::InvalidArgument;
    };
    let result = std::slice::from_raw_parts(candidates, candidate_count)
        .iter()
        .map(|c| {
            if c.data.is_null() {
                return Err(EngineError::InvalidInput("null template data".into()));
            }
            Ok((c.uid, Template::from_bytes(std::slice::from_raw_parts(c.data, c.len))?))
        })
        .collect::<Result<Vec<_>, _>>()
        .and_then(|enrolled| engine.auth_begin(enrolled, target_far, max_scored_frames as usize));
    match result {
        Ok(id) => {
            *out_session = id;
            Status::Ok
        }
        Err(error) => status_of(&error),
    }
}

unsafe extern "C" fn engine_auth_submit(
    handle: EngineHandle,
    session: u64,
    frame: *const FrameView,
    out: *mut AuthProgress,
) -> Status {
    let (Some(engine), Some(frame), false) = (engine(handle), frame.as_ref(), out.is_null()) else {
        return Status::InvalidArgument;
    };
    match image(frame).and_then(|img| engine.auth_submit(session, &img)) {
        Ok(progress) => {
            let (state, uid) = match progress.verdict {
                AuthVerdict::Continue => (AuthState::Continue, 0),
                AuthVerdict::Accepted { uid } => (AuthState::Accepted, uid),
                AuthVerdict::Rejected => (AuthState::Rejected, 0),
            };
            *out = AuthProgress { state, uid, scored_frames: progress.scored_frames as u32 };
            Status::Ok
        }
        Err(error) => status_of(&error),
    }
}

unsafe extern "C" fn engine_auth_end(handle: EngineHandle, session: u64) -> Status {
    let Some(engine) = engine(handle) else {
        return Status::InvalidArgument;
    };
    if engine.auth_end(session) {
        Status::Ok
    } else {
        Status::NotFound
    }
}

unsafe extern "C" fn engine_destroy(handle: EngineHandle) {
    if !handle.is_null() {
        drop(Box::from_raw(handle as *mut Engine));
    }
}

static ENGINE_INTERFACE: EngineInterface = EngineInterface {
    abi_version: ABI_VERSION,
    create: engine_create,
    enroll_begin: engine_enroll_begin,
    enroll_submit: engine_enroll_submit,
    enroll_commit: engine_enroll_commit,
    enroll_discard: engine_enroll_discard,
    auth_begin: engine_auth_begin,
    auth_submit: engine_auth_submit,
    auth_end: engine_auth_end,
    destroy: engine_destroy,
};

#[no_mangle]
pub extern "C" fn openhello_engine_interface() -> *const EngineInterface {
    &ENGINE_INTERFACE
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;

    use super::*;

    #[test]
    fn create_rejects_malformed_config_and_missing_files() {
        let interface = unsafe { &*openhello_engine_interface() };
        let mut handle: EngineHandle = std::ptr::null_mut();
        let bad = CString::new("not json").unwrap();
        assert_eq!(unsafe { (interface.create)(bad.as_ptr(), &mut handle) }, Status::InvalidArgument);
        let missing = CString::new(r#"{"models_dir":"/nonexistent","calibration_path":"/nonexistent/cal.bin"}"#).unwrap();
        assert_eq!(unsafe { (interface.create)(missing.as_ptr(), &mut handle) }, Status::InvalidArgument);
        assert!(handle.is_null());
    }

    #[test]
    fn null_handles_are_invalid_arguments() {
        let interface = unsafe { &*openhello_engine_interface() };
        let mut session = 0u64;
        assert_eq!(unsafe { (interface.enroll_begin)(std::ptr::null_mut(), 0, &mut session) }, Status::InvalidArgument);
    }
}
