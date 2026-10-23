use crate::manage::TestOutcome;
use crate::wizard::FailureCause;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    English,
}

impl Language {
    pub fn detect() -> Self {
        Language::English
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Text {
    WelcomeTitle,
    WelcomeBody,
    BlockedTitle,
    SetUp,
    Next,
    Cancel,
    TryAgain,
    IdentityTitle,
    IdentityBody,
    CaptureTitle,
    DoneTitle,
    DoneBody,
    GuidanceAccepted,
    GuidanceNoFace,
    GuidanceMoveLeft,
    GuidanceMoveRight,
    GuidanceMoveUp,
    GuidanceMoveDown,
    GuidanceTooClose,
    GuidanceTooFar,
    GuidanceTooDark,
    GuidanceTooBright,
    GuidanceLookForward,
    GuidanceBlurred,
    GuidanceOccluded,
    GuidanceNeutral,
    TimeoutTitle,
    TimeoutBody,
    CameraBusyTitle,
    CameraBusyBody,
    NoCameraTitle,
    NoCameraBody,
    SensorStuckTitle,
    SensorStuckBody,
    TpmTitle,
    TpmBody,
    AuthDeniedTitle,
    AuthDeniedBody,
    KeyFailedTitle,
    KeyFailedBody,
    OtherTitle,
    OtherBody,
    ManageTitle,
    ManageBody,
    TestFace,
    Testing,
    Recognized,
    NotRecognized,
    DeleteFace,
    DeleteFaceData,
    DeleteConfirmTitle,
    DeleteConfirmBody,
    SetUpAgain,
    TestFailedPrefix,
    ReasonCameraBusy,
    ReasonSensorStuck,
    ReasonNoCamera,
    ReasonTpm,
    ReasonAuthDenied,
    ReasonOther,
    SudoNotice,
    SudoUseOwn,
    SudoChanged,
    SudoFailedPrefix,
}

impl Text {
    pub const ALL: [Text; 64] = [
        Text::WelcomeTitle,
        Text::WelcomeBody,
        Text::BlockedTitle,
        Text::SetUp,
        Text::Next,
        Text::Cancel,
        Text::TryAgain,
        Text::IdentityTitle,
        Text::IdentityBody,
        Text::CaptureTitle,
        Text::DoneTitle,
        Text::DoneBody,
        Text::GuidanceAccepted,
        Text::GuidanceNoFace,
        Text::GuidanceMoveLeft,
        Text::GuidanceMoveRight,
        Text::GuidanceMoveUp,
        Text::GuidanceMoveDown,
        Text::GuidanceTooClose,
        Text::GuidanceTooFar,
        Text::GuidanceTooDark,
        Text::GuidanceTooBright,
        Text::GuidanceLookForward,
        Text::GuidanceBlurred,
        Text::GuidanceOccluded,
        Text::GuidanceNeutral,
        Text::TimeoutTitle,
        Text::TimeoutBody,
        Text::CameraBusyTitle,
        Text::CameraBusyBody,
        Text::NoCameraTitle,
        Text::NoCameraBody,
        Text::SensorStuckTitle,
        Text::SensorStuckBody,
        Text::TpmTitle,
        Text::TpmBody,
        Text::AuthDeniedTitle,
        Text::AuthDeniedBody,
        Text::KeyFailedTitle,
        Text::KeyFailedBody,
        Text::OtherTitle,
        Text::OtherBody,
        Text::ManageTitle,
        Text::ManageBody,
        Text::TestFace,
        Text::Testing,
        Text::Recognized,
        Text::NotRecognized,
        Text::DeleteFace,
        Text::DeleteFaceData,
        Text::DeleteConfirmTitle,
        Text::DeleteConfirmBody,
        Text::SetUpAgain,
        Text::TestFailedPrefix,
        Text::ReasonCameraBusy,
        Text::ReasonSensorStuck,
        Text::ReasonNoCamera,
        Text::ReasonTpm,
        Text::ReasonAuthDenied,
        Text::ReasonOther,
        Text::SudoNotice,
        Text::SudoUseOwn,
        Text::SudoChanged,
        Text::SudoFailedPrefix,
    ];

    fn english(self) -> &'static str {
        match self {
            Text::WelcomeTitle => "Welcome to Open Hello",
            Text::WelcomeBody => "Sign in with your face instead of typing your password. Setup takes a few seconds, your face data stays on this computer and your password keeps working.",
            Text::BlockedTitle => "Face recognition is not available on this computer",
            Text::SetUp => "Get started",
            Text::Next => "Next",
            Text::Cancel => "Cancel",
            Text::TryAgain => "Try again",
            Text::IdentityTitle => "Confirm it’s you",
            Text::IdentityBody => "Enter your password when the system asks for it.",
            Text::CaptureTitle => "Look at the camera",
            Text::DoneTitle => "All set",
            Text::DoneBody => "Test it now to make sure it recognizes you.",
            Text::GuidanceAccepted => "Hold still and look at the camera",
            Text::GuidanceNoFace => "No face found. Center your face in the oval",
            Text::GuidanceMoveLeft => "Move a little to your left",
            Text::GuidanceMoveRight => "Move a little to your right",
            Text::GuidanceMoveUp => "Move up a little",
            Text::GuidanceMoveDown => "Move down a little",
            Text::GuidanceTooClose => "Too close. Move back a little",
            Text::GuidanceTooFar => "Too far. Move a little closer",
            Text::GuidanceTooDark => "Not enough light on your face",
            Text::GuidanceTooBright => "Too much light. Avoid glare in front of or behind you",
            Text::GuidanceLookForward => "Face the camera straight on",
            Text::GuidanceBlurred => "Hold still. The image is blurry",
            Text::GuidanceOccluded => "Something is covering your face. Clear it from view",
            Text::GuidanceNeutral => "Look at the camera and keep your face in the oval",
            Text::TimeoutTitle => "Setup timed out",
            Text::TimeoutBody => "Not enough clear samples were collected in 30 seconds. Face the camera, keep your face centered and try again.",
            Text::CameraBusyTitle => "Camera in use",
            Text::CameraBusyBody => "Another program is using the camera. Close it and try again.",
            Text::NoCameraTitle => "Camera not found",
            Text::NoCameraBody => "No infrared camera was detected on this computer.",
            Text::SensorStuckTitle => "Infrared sensor not responding",
            Text::SensorStuckBody => "The infrared stream is stuck. Shut the computer down completely, wait a few seconds and start it again.",
            Text::TpmTitle => "Security chip unavailable",
            Text::TpmBody => "Face data is protected by the TPM, which is not responding. Check that it is enabled in the firmware.",
            Text::AuthDeniedTitle => "Authorization failed",
            Text::AuthDeniedBody => "The system password was not accepted or the prompt was dismissed.",
            Text::KeyFailedTitle => "Login key not created",
            Text::KeyFailedBody => "Your face was saved, but the login key could not be created. Try again.",
            Text::OtherTitle => "Something went wrong",
            Text::OtherBody => "Face recognition could not finish. Check the service logs and try again.",
            Text::ManageTitle => "Open Hello",
            Text::ManageBody => "Face recognition is set up for your account.",
            Text::TestFace => "Test",
            Text::Testing => "Look at the camera…",
            Text::Recognized => "It recognized you.",
            Text::NotRecognized => "Your face was not recognized. Test again or set it up again.",
            Text::DeleteFace => "Delete",
            Text::DeleteFaceData => "Delete face data",
            Text::DeleteConfirmTitle => "Delete face recognition?",
            Text::DeleteConfirmBody => "This erases your face data and your login key. You will use your password until you set it up again.",
            Text::SetUpAgain => "Set up again",
            Text::TestFailedPrefix => "The test could not run: ",
            Text::ReasonCameraBusy => "the camera is in use",
            Text::ReasonSensorStuck => "the infrared sensor is not responding",
            Text::ReasonNoCamera => "no infrared camera was found",
            Text::ReasonTpm => "the security chip is unavailable",
            Text::ReasonAuthDenied => "the system did not authorize the request",
            Text::ReasonOther => "something went wrong",
            Text::SudoNotice => "Your face works for sign-in and the lock screen. sudo on this computer asks for the root password, so it cannot use your face.",
            Text::SudoUseOwn => "Use my face for sudo",
            Text::SudoChanged => "sudo now accepts your face or your own password.",
            Text::SudoFailedPrefix => "sudo was not changed: ",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Strings {
    language: Language,
}

impl Strings {
    pub fn new(language: Language) -> Self {
        Self { language }
    }

    pub fn language(&self) -> Language {
        self.language
    }

    pub fn get(&self, text: Text) -> &'static str {
        match self.language {
            Language::English => text.english(),
        }
    }

    pub fn guidance(&self, verdict: &str) -> &'static str {
        self.get(guidance_text(verdict))
    }

    pub fn blocked_title(&self) -> &'static str {
        self.get(Text::BlockedTitle)
    }

    pub fn failure_title(&self, cause: FailureCause) -> &'static str {
        self.get(failure_texts(cause).0)
    }

    pub fn test_message(&self, outcome: &TestOutcome) -> String {
        match outcome {
            TestOutcome::Recognized => self.get(Text::Recognized).into(),
            TestOutcome::NotRecognized => self.get(Text::NotRecognized).into(),
            TestOutcome::Failed(error) => format!("{}{}.", self.get(Text::TestFailedPrefix), self.get(reason_text(error.kind.into()))),
        }
    }

    pub fn sudo_failure(&self, cause: FailureCause) -> String {
        format!("{}{}.", self.get(Text::SudoFailedPrefix), self.get(reason_text(cause)))
    }

    pub fn failure_explanation(&self, cause: FailureCause) -> &'static str {
        self.get(failure_texts(cause).1)
    }
}

fn guidance_text(verdict: &str) -> Text {
    match verdict {
        "accepted" | "too-soon" => Text::GuidanceAccepted,
        "no-face" => Text::GuidanceNoFace,
        "move-left" => Text::GuidanceMoveLeft,
        "move-right" => Text::GuidanceMoveRight,
        "move-up" => Text::GuidanceMoveUp,
        "move-down" => Text::GuidanceMoveDown,
        "too-close" => Text::GuidanceTooClose,
        "too-far" => Text::GuidanceTooFar,
        "too-dark" => Text::GuidanceTooDark,
        "too-bright" => Text::GuidanceTooBright,
        "yaw-out-of-range" => Text::GuidanceLookForward,
        "blurred" => Text::GuidanceBlurred,
        "occluded" => Text::GuidanceOccluded,
        _ => Text::GuidanceNeutral,
    }
}

fn reason_text(cause: FailureCause) -> Text {
    match cause {
        FailureCause::CameraBusy => Text::ReasonCameraBusy,
        FailureCause::SensorStuck => Text::ReasonSensorStuck,
        FailureCause::NoCamera => Text::ReasonNoCamera,
        FailureCause::TpmUnavailable => Text::ReasonTpm,
        FailureCause::AuthDenied => Text::ReasonAuthDenied,
        FailureCause::Timeout | FailureCause::KeyFailed | FailureCause::Other => Text::ReasonOther,
    }
}

fn failure_texts(cause: FailureCause) -> (Text, Text) {
    match cause {
        FailureCause::Timeout => (Text::TimeoutTitle, Text::TimeoutBody),
        FailureCause::CameraBusy => (Text::CameraBusyTitle, Text::CameraBusyBody),
        FailureCause::NoCamera => (Text::NoCameraTitle, Text::NoCameraBody),
        FailureCause::SensorStuck => (Text::SensorStuckTitle, Text::SensorStuckBody),
        FailureCause::TpmUnavailable => (Text::TpmTitle, Text::TpmBody),
        FailureCause::AuthDenied => (Text::AuthDeniedTitle, Text::AuthDeniedBody),
        FailureCause::KeyFailed => (Text::KeyFailedTitle, Text::KeyFailedBody),
        FailureCause::Other => (Text::OtherTitle, Text::OtherBody),
    }
}
