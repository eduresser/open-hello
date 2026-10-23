use thiserror::Error;

#[derive(Debug, Error)]
pub enum DaemonError {
    #[error("no template stored")]
    NotFound,
    #[error("stored template failed authentication")]
    Tampered,
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("backend failure: {0}")]
    Backend(String),
    #[error("the caller left before the attempt finished")]
    Cancelled,
    #[error("camera busy: {0}")]
    CameraBusy(String),
    #[error("infrared stream stuck: {0}")]
    SensorStuck(String),
    #[error("no camera: {0}")]
    NoCamera(String),
    #[error("TPM unavailable: {0}")]
    TpmUnavailable(String),
}

impl DaemonError {
    pub fn user_message(&self) -> &'static str {
        match self {
            DaemonError::NotFound => "no biometric data is enrolled for this user",
            DaemonError::Tampered | DaemonError::Backend(_) => "the biometric service could not complete the operation",
            DaemonError::InvalidRequest(_) => "the request was not valid in the current state",
            DaemonError::Cancelled => "the request was cancelled",
            DaemonError::CameraBusy(_) => "the camera is in use by another program",
            DaemonError::SensorStuck(_) => "the infrared stream is stuck and the computer must be powered off completely",
            DaemonError::NoCamera(_) => "no infrared camera was found",
            DaemonError::TpmUnavailable(_) => "the TPM is unavailable",
        }
    }
}

#[derive(Debug, Clone)]
pub struct CapturedFrame {
    pub width: u32,
    pub height: u32,
    pub pixels: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Accepted,
    Blurred,
    Occluded,
    NoFace,
    YawOutOfRange,
    TooSoon,
    TooDark,
    TooBright,
    MoveLeft,
    MoveRight,
    MoveUp,
    MoveDown,
    TooClose,
    TooFar,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Accepted => "accepted",
            Verdict::Blurred => "blurred",
            Verdict::Occluded => "occluded",
            Verdict::NoFace => "no-face",
            Verdict::YawOutOfRange => "yaw-out-of-range",
            Verdict::TooSoon => "too-soon",
            Verdict::TooDark => "too-dark",
            Verdict::TooBright => "too-bright",
            Verdict::MoveLeft => "move-left",
            Verdict::MoveRight => "move-right",
            Verdict::MoveUp => "move-up",
            Verdict::MoveDown => "move-down",
            Verdict::TooClose => "too-close",
            Verdict::TooFar => "too-far",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollState {
    InProgress,
    Complete,
    Failed,
}

impl EnrollState {
    pub fn as_str(self) -> &'static str {
        match self {
            EnrollState::InProgress => "in-progress",
            EnrollState::Complete => "complete",
            EnrollState::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnrollProgress {
    pub verdict: Verdict,
    pub state: EnrollState,
    pub filled: u32,
    pub required: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthVerdict {
    Continue,
    Accepted(u32),
    Rejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthProgress {
    pub verdict: AuthVerdict,
    pub scored_frames: u32,
}

pub trait SensorBackend: Send {
    fn capture(&mut self) -> Result<CapturedFrame, DaemonError>;
    fn release(&mut self) {}
}

pub trait EngineBackend: Send {
    fn enroll_begin(&mut self, now_ms: u64) -> Result<u64, DaemonError>;
    fn enroll_submit(&mut self, session: u64, now_ms: u64, frame: &CapturedFrame) -> Result<EnrollProgress, DaemonError>;
    fn enroll_commit(&mut self, session: u64) -> Result<Vec<u8>, DaemonError>;
    fn enroll_discard(&mut self, session: u64) -> Result<(), DaemonError>;
    fn auth_begin(&mut self, candidates: &[(u32, Vec<u8>)], target_far: f64, max_scored_frames: u32) -> Result<u64, DaemonError>;
    fn auth_submit(&mut self, session: u64, frame: &CapturedFrame) -> Result<AuthProgress, DaemonError>;
    fn auth_end(&mut self, session: u64) -> Result<(), DaemonError>;
}

pub trait StorageBackend: Send {
    fn put(&mut self, uid: u32, template: &[u8]) -> Result<(), DaemonError>;
    fn get(&mut self, uid: u32) -> Result<Vec<u8>, DaemonError>;
    fn list_uids(&mut self) -> Result<Vec<u32>, DaemonError>;
    fn purge(&mut self, uid: u32) -> Result<(), DaemonError>;
}
