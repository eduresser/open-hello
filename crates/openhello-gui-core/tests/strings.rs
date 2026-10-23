use openhello_gui_core::{FailureCause, Language, Strings, Text};

const VERDICTS: [&str; 14] = [
    "accepted", "too-soon", "no-face", "move-left", "move-right", "move-up", "move-down", "too-close", "too-far", "too-dark", "too-bright", "yaw-out-of-range", "blurred", "occluded",
];

const WINDOWS_WORDING: [(&str, &str); 8] = [
    ("accepted", "Keep looking directly at your camera."),
    ("too-soon", "Keep looking directly at your camera."),
    ("no-face", "We couldn’t detect your face, please make sure there is enough light and your face is centered in the frame."),
    ("too-close", "Too close! Move a little farther away."),
    ("too-far", "Too far! Move a bit closer."),
    ("too-dark", "Too dark! Turn on some lights or move somewhere brighter."),
    ("too-bright", "Too bright! Turn off some lights or go inside."),
    ("yaw-out-of-range", "Keep looking forward, facing the camera."),
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
fn verdicts_with_a_windows_hello_equivalent_use_its_wording() {
    let english = Strings::new(Language::English);
    for (verdict, en) in WINDOWS_WORDING {
        assert_eq!(english.guidance(verdict), en, "{verdict}");
    }
    assert_eq!(english.guidance("blurred"), "Hold still: the image is not sharp enough");
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

// @spec:AC-060
#[test]
fn the_wizard_wording_says_openhello_and_has_no_typo() {
    let all: Vec<&str> = [Language::English]
        .into_iter()
        .flat_map(|language| {
            let strings = Strings::new(language);
            [Text::WelcomeTitle, Text::DoneBody, Text::NoCameraBody, Text::IdentityBody].map(|text| strings.get(text))
        })
        .collect();
    assert!(all.iter().all(|text| !text.contains("Windows Hello")));
    assert!(all.iter().any(|text| text.contains("OpenHello")));
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
        }
        assert!(!strings.get(Text::TryAgain).is_empty());
    }
}
