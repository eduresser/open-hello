use std::ffi::CStr;
use std::os::raw::c_char;

use openhello_plugin_abi::{
    EngineHandle, EngineInterface, EnrollProgress, EnrollState, EnrollVerdict, FrameView, IdentifyDecision, MatchDecision,
    Status, TemplateRef, ABI_VERSION,
};
use serde::Deserialize;

use crate::engine::{Engine, Verdict};
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
        EngineError::Model(_) => Status::Internal,
        EngineError::NoFace | EngineError::InvalidInput(_) => Status::InvalidArgument,
    }
}

unsafe fn engine<'a>(handle: EngineHandle) -> Option<&'a Engine> {
    (handle as *const Engine).as_ref()
}

unsafe fn images(frames: *const FrameView, count: usize) -> Result<Vec<GrayImage>, EngineError> {
    if frames.is_null() {
        return Err(EngineError::InvalidInput("null frame array".into()));
    }
    std::slice::from_raw_parts(frames, count).iter().map(|f| image(f)).collect()
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

unsafe extern "C" fn engine_verify(
    handle: EngineHandle,
    frames: *const FrameView,
    frame_count: usize,
    template: *const u8,
    template_len: usize,
    target_far: f64,
    out: *mut MatchDecision,
) -> Status {
    let (Some(engine), false, false) = (engine(handle), template.is_null(), out.is_null()) else {
        return Status::InvalidArgument;
    };
    let result = images(frames, frame_count).and_then(|imgs| {
        let template = Template::from_bytes(std::slice::from_raw_parts(template, template_len))?;
        engine.verify(&imgs, &template, target_far)
    });
    match result {
        Ok(outcome) => {
            *out = MatchDecision { live: outcome.live, accepted: outcome.accepted };
            Status::Ok
        }
        Err(error) => status_of(&error),
    }
}

unsafe extern "C" fn engine_identify(
    handle: EngineHandle,
    frames: *const FrameView,
    frame_count: usize,
    candidates: *const TemplateRef,
    candidate_count: usize,
    target_far: f64,
    out: *mut IdentifyDecision,
) -> Status {
    let (Some(engine), false, false) = (engine(handle), candidates.is_null(), out.is_null()) else {
        return Status::InvalidArgument;
    };
    let result = images(frames, frame_count).and_then(|imgs| {
        let enrolled = std::slice::from_raw_parts(candidates, candidate_count)
            .iter()
            .map(|c| {
                if c.data.is_null() {
                    return Err(EngineError::InvalidInput("null template data".into()));
                }
                Ok((c.uid, Template::from_bytes(std::slice::from_raw_parts(c.data, c.len))?))
            })
            .collect::<Result<Vec<_>, _>>()?;
        engine.identify(&imgs, &enrolled, target_far)
    });
    match result {
        Ok(outcome) => {
            *out = IdentifyDecision {
                live: outcome.live,
                found: outcome.matched_uid.is_some(),
                uid: outcome.matched_uid.unwrap_or(0),
            };
            Status::Ok
        }
        Err(error) => status_of(&error),
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
    verify: engine_verify,
    identify: engine_identify,
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
