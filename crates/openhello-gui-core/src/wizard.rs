use std::fmt;

use crate::strings::{Language, Strings};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientErrorKind {
    CameraBusy,
    SensorStuck,
    NoCamera,
    TpmUnavailable,
    AuthDenied,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientError {
    pub kind: ClientErrorKind,
    pub message: String,
}

impl ClientError {
    pub fn new(kind: ClientErrorKind, message: impl Into<String>) -> Self {
        Self { kind, message: message.into() }
    }
}

pub type ClientResult<T> = Result<T, ClientError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Status {
    pub face: bool,
    pub key: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Progress {
    pub verdict: String,
    pub state: String,
    pub filled: u32,
    pub required: u32,
}

#[derive(Clone, PartialEq, Eq)]
pub struct Frame {
    pub width: u32,
    pub height: u32,
    pub pixels: Vec<u8>,
}

impl fmt::Debug for Frame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Frame {{ width: {}, height: {}, len: {} }}", self.width, self.height, self.pixels.len())
    }
}

pub trait EnrollClient {
    fn check_ready(&mut self) -> ClientResult<()>;
    fn status(&mut self, uid: u32) -> ClientResult<Status>;
    fn enroll_begin(&mut self, uid: u32) -> ClientResult<String>;
    fn enroll_capture(&mut self, handle: &str) -> ClientResult<Progress>;
    fn enroll_frame(&mut self, handle: &str) -> ClientResult<Frame>;
    fn enroll_commit(&mut self, handle: &str) -> ClientResult<()>;
    fn enroll_discard(&mut self, handle: &str) -> ClientResult<()>;
    fn provision(&mut self, uid: u32) -> ClientResult<String>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureCause {
    Timeout,
    CameraBusy,
    SensorStuck,
    NoCamera,
    TpmUnavailable,
    AuthDenied,
    KeyFailed,
    Other,
}

impl From<ClientErrorKind> for FailureCause {
    fn from(kind: ClientErrorKind) -> Self {
        match kind {
            ClientErrorKind::CameraBusy => FailureCause::CameraBusy,
            ClientErrorKind::SensorStuck => FailureCause::SensorStuck,
            ClientErrorKind::NoCamera => FailureCause::NoCamera,
            ClientErrorKind::TpmUnavailable => FailureCause::TpmUnavailable,
            ClientErrorKind::AuthDenied => FailureCause::AuthDenied,
            ClientErrorKind::Other => FailureCause::Other,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    Welcome,
    Identity,
    Capture,
    RecoveryCode,
    Done,
    Error(FailureCause),
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Plan {
    pub key: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Wizard {
    step: Step,
    plan: Plan,
}

impl Default for Wizard {
    fn default() -> Self {
        Self::new()
    }
}

impl Wizard {
    pub fn new() -> Self {
        Self { step: Step::Welcome, plan: Plan::default() }
    }

    pub fn step(&self) -> Step {
        self.step
    }

    pub fn plan(&self) -> Plan {
        self.plan
    }

    pub fn set_plan(&mut self, plan: Plan) {
        self.plan = plan;
    }

    pub fn set_step(&mut self, step: Step) {
        self.step = step;
    }

    pub fn fail(&mut self, cause: FailureCause) {
        self.step = Step::Error(cause);
    }

    pub fn reset(&mut self) {
        *self = Self::new();
    }

    pub fn advance(&mut self) {
        self.step = match self.step {
            Step::Welcome => Step::Identity,
            Step::Identity => Step::Capture,
            Step::Capture if self.plan.key => Step::RecoveryCode,
            Step::Capture | Step::RecoveryCode => Step::Done,
            other => other,
        };
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureUpdate {
    pub guidance: &'static str,
    pub filled: u32,
    pub required: u32,
    pub frame: Option<Frame>,
}

pub struct EnrollmentFlow<C: EnrollClient> {
    client: C,
    uid: u32,
    strings: Strings,
    wizard: Wizard,
    session: Option<String>,
    committed: bool,
    recovery_code: Option<String>,
    blocked: Option<FailureCause>,
}

impl<C: EnrollClient> EnrollmentFlow<C> {
    pub fn new(client: C, uid: u32, language: Language) -> Self {
        Self { client, uid, strings: Strings::new(language), wizard: Wizard::new(), session: None, committed: false, recovery_code: None, blocked: None }
    }

    pub fn step(&self) -> Step {
        self.wizard.step()
    }

    pub fn strings(&self) -> &Strings {
        &self.strings
    }

    pub fn recovery_code(&self) -> Option<&str> {
        self.recovery_code.as_deref()
    }

    pub fn blocked(&self) -> Option<FailureCause> {
        self.blocked
    }

    pub fn start(&mut self) {
        if self.step() != Step::Welcome {
            return;
        }
        self.blocked = self.client.check_ready().err().map(|error| error.kind.into());
        if self.blocked.is_none() {
            self.read_status();
        }
    }

    fn read_status(&mut self) {
        match self.client.status(self.uid) {
            Ok(status) => {
                self.wizard.set_plan(Plan { key: !status.key });
                self.wizard.advance();
            }
            Err(_) => self.blocked = Some(FailureCause::Other),
        }
    }

    pub fn confirm_identity(&mut self) {
        if self.step() != Step::Identity {
            return;
        }
        match self.client.enroll_begin(self.uid) {
            Ok(handle) => {
                self.session = Some(handle);
                self.wizard.advance();
            }
            Err(error) => self.wizard.fail(error.kind.into()),
        }
    }

    pub fn tick(&mut self) -> Option<CaptureUpdate> {
        if self.step() != Step::Capture {
            return None;
        }
        let handle = self.session.clone()?;
        let progress = match self.client.enroll_capture(&handle) {
            Ok(progress) => progress,
            Err(error) => {
                self.abort(error.kind.into());
                return None;
            }
        };
        let frame = self.client.enroll_frame(&handle).ok();
        match progress.state.as_str() {
            "complete" => self.finish_capture(&handle),
            "failed" => self.abort(FailureCause::Timeout),
            _ => {}
        }
        Some(self.update(progress, frame))
    }

    pub fn acknowledge_recovery_code(&mut self) {
        if self.step() == Step::RecoveryCode {
            self.recovery_code = None;
            self.wizard.advance();
        }
    }

    pub fn retry(&mut self) {
        match self.step() {
            Step::Error(FailureCause::KeyFailed) if self.committed => self.provision(Step::Capture),
            Step::Error(_) => self.restart(),
            Step::Welcome if self.blocked.is_some() => self.start(),
            _ => {}
        }
    }

    pub fn cancel(&mut self) {
        self.release_session();
        if !matches!(self.step(), Step::Done | Step::RecoveryCode) {
            self.wizard.reset();
        }
    }

    fn update(&self, progress: Progress, frame: Option<Frame>) -> CaptureUpdate {
        CaptureUpdate {
            guidance: self.strings.guidance(&progress.verdict),
            filled: progress.filled,
            required: progress.required,
            frame,
        }
    }

    fn finish_capture(&mut self, handle: &str) {
        match self.client.enroll_commit(handle) {
            Ok(()) => {
                self.session = None;
                self.committed = true;
                self.after_commit();
            }
            Err(error) => self.abort(error.kind.into()),
        }
    }

    fn after_commit(&mut self) {
        if self.wizard.plan().key {
            self.provision(Step::Capture);
        } else {
            self.wizard.advance();
        }
    }

    fn provision(&mut self, from: Step) {
        self.wizard.set_step(from);
        match self.client.provision(self.uid) {
            Ok(code) => {
                self.recovery_code = Some(code);
                self.wizard.advance();
            }
            Err(_) => self.wizard.fail(FailureCause::KeyFailed),
        }
    }

    fn restart(&mut self) {
        self.release_session();
        self.committed = false;
        self.recovery_code = None;
        self.wizard.reset();
    }

    fn abort(&mut self, cause: FailureCause) {
        self.release_session();
        self.wizard.fail(cause);
    }

    fn release_session(&mut self) {
        if let Some(handle) = self.session.take() {
            let _ = self.client.enroll_discard(&handle);
        }
    }
}

impl<C: EnrollClient> Drop for EnrollmentFlow<C> {
    fn drop(&mut self) {
        self.release_session();
    }
}
