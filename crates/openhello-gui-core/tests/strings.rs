use openhello_gui_core::{ClientError, ClientErrorKind, FailureCause, Language, Strings, Text, TestOutcome};

const VERDICTS: [&str; 14] = [
    "accepted", "too-soon", "no-face", "move-left", "move-right", "move-up", "move-down", "too-close", "too-far", "too-dark", "too-bright", "yaw-out-of-range", "blurred", "occluded",
];

const DECK: [(&str, &str); 14] = [
    ("accepted", "Hold still and look at the camera"),
    ("too-soon", "Hold still and look at the camera"),
    ("no-face", "No face found. Center your face in the oval"),
    ("move-left", "Move a little to your left"),
    ("move-right", "Move a little to your right"),
    ("move-up", "Move up a little"),
    ("move-down", "Move down a little"),
    ("too-close", "Too close. Move back a little"),
    ("too-far", "Too far. Move a little closer"),
    ("too-dark", "Not enough light on your face"),
    ("too-bright", "Too much light. Avoid glare in front of or behind you"),
    ("yaw-out-of-range", "Face the camera straight on"),
    ("blurred", "Hold still. The image is blurry"),
    ("occluded", "Something is covering your face. Clear it from view"),
];

const FORBIDDEN: [&str; 16] = [
    "Your device just got more personal", "Well done", "Making sure it", "Windows Hello", "Forget entering a password", "Too far!", "Too close!", "Too dark!", "Too bright!",
    "go through the setup again", "Sorry, something went wrong", "Keep looking directly at your camera", "Keep looking forward, facing the camera", "Move closer to the camera",
    "Move further away from the camera", "Make sure your face is centered in the frame",
];

// @spec:AC-060
#[test]
fn every_verdict_has_an_english_sentence_that_is_not_the_raw_verdict() {
    for language in [Language::English] {
        let strings = Strings::new(language);
        for verdict in VERDICTS {
            let sentence = strings.guidance(verdict);
            assert!(!sentence.trim().is_empty(), "{verdict} {language:?}");
            assert_ne!(sentence, verdict);
        }
    }
}

// @spec:AC-060
#[test]
fn every_verdict_uses_the_approved_sentence() {
    let english = Strings::new(Language::English);
    for (verdict, sentence) in DECK {
        assert_eq!(english.guidance(verdict), sentence, "{verdict}");
    }
}

// @spec:AC-060
#[test]
fn no_text_contains_a_forbidden_windows_hello_phrase() {
    let strings = Strings::new(Language::English);
    let texts = Text::ALL.iter().map(|text| strings.get(*text)).chain([strings.guidance("quantum-flux-9")]);
    for sentence in texts {
        for phrase in FORBIDDEN {
            assert!(!sentence.contains(phrase), "{phrase:?} in {sentence:?}");
        }
        assert!(!sentence.contains('!'), "{sentence:?}");
    }
}

// @spec:AC-060
#[test]
fn an_unknown_verdict_gets_a_neutral_sentence_and_never_the_raw_text() {
    for language in [Language::English] {
        let strings = Strings::new(language);
        let sentence = strings.guidance("quantum-flux-9");
        assert!(!sentence.is_empty());
        assert!(!sentence.contains("quantum"));
        assert_eq!(sentence, strings.get(Text::GuidanceNeutral));
    }
}

// @spec:AC-060
#[test]
fn the_interface_language_is_always_english() {
    assert_eq!(Language::detect(), Language::English);
}

// @spec:AC-061
#[test]
fn every_failure_cause_has_a_title_an_explanation_and_a_try_again_label() {
    let causes = [
        FailureCause::Timeout, FailureCause::CameraBusy, FailureCause::SensorStuck, FailureCause::NoCamera,
        FailureCause::TpmUnavailable, FailureCause::AuthDenied, FailureCause::KeyFailed, FailureCause::Other,
    ];
    for language in [Language::English] {
        let strings = Strings::new(language);
        for cause in causes {
            assert!(!strings.failure_title(cause).is_empty());
            assert!(strings.failure_explanation(cause).len() > 20);
            assert!(!strings.failure_explanation(cause).contains(" cm"));
        }
        assert!(!strings.get(Text::TryAgain).is_empty());
    }
}

// @spec:AC-074
#[test]
fn a_test_that_could_not_run_names_the_cause_in_plain_words() {
    let strings = Strings::new(Language::English);
    let message = |kind| strings.test_message(&TestOutcome::Failed(ClientError::new(kind, "detail")));
    assert_eq!(message(ClientErrorKind::CameraBusy), "The test could not run: the camera is in use.");
    assert_eq!(message(ClientErrorKind::SensorStuck), "The test could not run: the infrared sensor is not responding.");
    assert_eq!(message(ClientErrorKind::NoCamera), "The test could not run: no infrared camera was found.");
    assert_eq!(message(ClientErrorKind::TpmUnavailable), "The test could not run: the security chip is unavailable.");
    assert_eq!(message(ClientErrorKind::Other), "The test could not run: something went wrong.");
    assert!(!message(ClientErrorKind::CameraBusy).contains("detail"));
}

// @spec:AC-072
// @spec:AC-074
#[test]
fn recognized_and_not_recognized_have_short_sentences_and_the_final_screen_invites_a_test() {
    let strings = Strings::new(Language::English);
    assert_eq!(strings.test_message(&TestOutcome::Recognized), "It recognized you.");
    assert_eq!(strings.test_message(&TestOutcome::NotRecognized), "Your face was not recognized. Test again or set it up again.");
    assert_eq!(strings.get(Text::DoneBody), "Test it now to make sure it recognizes you.");
    assert_eq!(strings.get(Text::SetUpAgain), "Set up again");
    assert_eq!(strings.get(Text::SetUp), "Set up");
    assert_eq!(strings.get(Text::DeleteFaceData), "Delete face data");
}
