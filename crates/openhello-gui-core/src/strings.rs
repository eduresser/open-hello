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
    GetStarted,
    Next,
    Done,
    Close,
    Cancel,
    TryAgain,
    IdentityTitle,
    IdentityBody,
    PinTitle,
    PinBody,
    PinLabel,
    PinConfirmLabel,
    PinMismatch,
    PinInvalid,
    CaptureTitle,
    RecoveryTitle,
    RecoveryBody,
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
    RemoveFace,
    RemoveConfirmTitle,
    RemoveConfirmBody,
    SetUpAgain,
    CopyCode,
}

impl Text {
    fn english(self) -> &'static str {
        match self {
            Text::WelcomeTitle => "Welcome to OpenHello",
            Text::WelcomeBody => "Your device just got more personal. Start using your face to unlock your device, verify your identity, and buy things in the Store.",
            Text::GetStarted => "Get started",
            Text::Next => "Next",
            Text::Done => "Done",
            Text::Close => "Close",
            Text::Cancel => "Cancel",
            Text::TryAgain => "Try again",
            Text::IdentityTitle => "Confirm it's you",
            Text::IdentityBody => "Enter your system password when asked, to confirm that you are the owner of this account.",
            Text::PinTitle => "Create a PIN",
            Text::PinBody => "Create a PIN to use if face recognition is not available. You may never need it, but it will serve as a backup just in case. Once you set up your PIN, you will be able to sign in with your face.",
            Text::PinLabel => "PIN",
            Text::PinConfirmLabel => "Confirm PIN",
            Text::PinMismatch => "These PINs don’t match.",
            Text::PinInvalid => "The PIN must have 6 to 32 printable characters.",
            Text::CaptureTitle => "Look at the camera",
            Text::RecoveryTitle => "Recovery code",
            Text::RecoveryBody => "This recovery code is shown only once. Write it down and keep it in a safe place: it is the only way to get back in if the TPM fails.",
            Text::DoneTitle => "All set",
            Text::DoneBody => "Well done! You are ready to start using OpenHello! Use your face the next time you want to unlock your device.",
            Text::GuidanceAccepted => "Keep looking directly at your camera.",
            Text::GuidanceNoFace => "We couldn’t detect your face, please make sure there is enough light and your face is centered in the frame.",
            Text::GuidanceMoveLeft => "Move a little to your left",
            Text::GuidanceMoveRight => "Move a little to your right",
            Text::GuidanceMoveUp => "Move up a little",
            Text::GuidanceMoveDown => "Move down a little",
            Text::GuidanceTooClose => "Too close! Move a little farther away.",
            Text::GuidanceTooFar => "Too far! Move a bit closer.",
            Text::GuidanceTooDark => "Too dark! Turn on some lights or move somewhere brighter.",
            Text::GuidanceTooBright => "Too bright! Turn off some lights or go inside.",
            Text::GuidanceLookForward => "Keep looking forward, facing the camera.",
            Text::GuidanceBlurred => "Hold still: the image is not sharp enough",
            Text::GuidanceOccluded => "We’re having trouble seeing you. Try removing anything that may be blocking your face.",
            Text::GuidanceNeutral => "Stay in front of the camera and hold still.",
            Text::TimeoutTitle => "Face setup timed out",
            Text::TimeoutBody => "We could not collect enough samples in 20 seconds. Make sure there is enough light and your face is centered in the frame, then try again.",
            Text::CameraBusyTitle => "Camera in use",
            Text::CameraBusyBody => "Camera is currently in use by another app. Close the app and try again.",
            Text::NoCameraTitle => "Camera not available",
            Text::NoCameraBody => "Couldn’t turn on the camera. Make sure it’s working properly.",
            Text::SensorStuckTitle => "Infrared camera stuck",
            Text::SensorStuckBody => "The infrared stream is stuck: power the computer off completely and try again.",
            Text::TpmTitle => "TPM not available",
            Text::TpmBody => "The TPM is unavailable. Check that it is enabled in the firmware and try again.",
            Text::AuthDeniedTitle => "Identity not confirmed",
            Text::AuthDeniedBody => "The system password was not confirmed, so nothing was saved. Try again.",
            Text::KeyFailedTitle => "Login key not created",
            Text::KeyFailedBody => "Your face was saved, but the login key could not be created, so signing in with your face will not work yet. Try again to create the key.",
            Text::OtherTitle => "Something went wrong",
            Text::OtherBody => "The setup could not be completed and nothing was saved. Try again.",
            Text::ManageTitle => "Face recognition",
            Text::ManageBody => "Your face is set up. Test it, remove it or set it up again.",
            Text::TestFace => "Test",
            Text::Testing => "Look at the camera…",
            Text::Recognized => "Recognized",
            Text::NotRecognized => "Not recognized",
            Text::RemoveFace => "Remove",
            Text::RemoveConfirmTitle => "Remove your face?",
            Text::RemoveConfirmBody => "Your face and login key will be erased and the system will ask for your password. You can set them up again later.",
            Text::SetUpAgain => "Set up again",
            Text::CopyCode => "Copy",
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

    pub fn progress(&self, filled: u32, required: u32) -> String {
        match self.language {
            Language::English => format!("{filled} of {required}"),
        }
    }

    pub fn failure_title(&self, cause: FailureCause) -> &'static str {
        self.get(failure_texts(cause).0)
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
