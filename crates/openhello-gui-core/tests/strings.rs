use openhello_gui_core::{FailureCause, Language, Strings, Text};

const VERDICTS: [&str; 14] = [
    "accepted", "too-soon", "no-face", "move-left", "move-right", "move-up", "move-down", "too-close", "too-far", "too-dark", "too-bright", "yaw-out-of-range", "blurred", "occluded",
];

const WINDOWS_WORDING: [(&str, &str, &str); 8] = [
    ("accepted", "Keep looking directly at your camera.", "Continue olhando diretamente para a câmera."),
    ("too-soon", "Keep looking directly at your camera.", "Continue olhando diretamente para a câmera."),
    ("no-face", "We couldn’t detect your face, please make sure there is enough light and your face is centered in the frame.", "Não conseguimos detectar o seu rosto, confira se há luz suficiente e seu rosto está centrado na moldura."),
    ("too-close", "Too close! Move a little farther away.", "Muito próximo! Afaste-se um pouco mais."),
    ("too-far", "Too far! Move a bit closer.", "Muito distante! Aproxime-se um pouco."),
    ("too-dark", "Too dark! Turn on some lights or move somewhere brighter.", "Muito escuro! Acenda algumas luzes ou vá para um lugar mais claro."),
    ("too-bright", "Too bright! Turns off some lights or go inside.", "Muito claro! Apague algumas luzes ou vá para um lugar fechado."),
    ("yaw-out-of-range", "Keep looking forward, facing the camera.", "Continue olhando para frente, de frente para a câmera."),
];

fn lookup(env: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
    move |name| env.iter().find(|(key, _)| *key == name).map(|(_, value)| value.to_string())
}

// @spec:AC-060
#[test]
fn every_verdict_has_a_sentence_in_both_languages_that_is_not_the_raw_verdict() {
    for language in [Language::English, Language::PortugueseBr] {
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
    let portuguese = Strings::new(Language::PortugueseBr);
    for (verdict, en, pt) in WINDOWS_WORDING {
        assert_eq!(english.guidance(verdict), en, "{verdict}");
        assert_eq!(portuguese.guidance(verdict), pt, "{verdict}");
    }
    assert_eq!(portuguese.guidance("occluded"), "Não estamos conseguindo ver você direito. Remova o que possa estar bloqueando sua face.");
    assert_eq!(portuguese.guidance("move-left"), "Mova-se um pouco para a esquerda");
    assert_eq!(english.guidance("blurred"), "Hold still: the image is not sharp enough");
}

// @spec:AC-060
#[test]
fn an_unknown_verdict_gets_a_neutral_sentence_and_never_the_raw_text() {
    for language in [Language::English, Language::PortugueseBr] {
        let strings = Strings::new(language);
        let sentence = strings.guidance("quantum-flux-9");
        assert!(!sentence.is_empty());
        assert!(!sentence.contains("quantum"));
        assert_eq!(sentence, strings.get(Text::GuidanceNeutral));
    }
}

// @spec:AC-060
#[test]
fn the_language_comes_from_lc_all_then_lc_messages_then_lang_with_english_as_default() {
    assert_eq!(Language::from_env(lookup(&[("LANG", "pt_BR.UTF-8")])), Language::PortugueseBr);
    assert_eq!(Language::from_env(lookup(&[("LANG", "en_US.UTF-8")])), Language::English);
    assert_eq!(Language::from_env(lookup(&[("LC_ALL", "en_US.UTF-8"), ("LANG", "pt_BR.UTF-8")])), Language::English);
    assert_eq!(Language::from_env(lookup(&[("LC_MESSAGES", "pt_PT"), ("LANG", "en_US")])), Language::PortugueseBr);
    assert_eq!(Language::from_env(lookup(&[("LC_ALL", ""), ("LANG", "pt_BR")])), Language::PortugueseBr);
    assert_eq!(Language::from_env(lookup(&[("LANG", "de_DE")])), Language::English);
    assert_eq!(Language::from_env(lookup(&[])), Language::English);
}

// @spec:AC-060
#[test]
fn the_wizard_wording_says_openhello_and_has_no_typo() {
    let all: Vec<&str> = [Language::English, Language::PortugueseBr]
        .into_iter()
        .flat_map(|language| {
            let strings = Strings::new(language);
            [Text::WelcomeTitle, Text::DoneBody, Text::NoCameraBody, Text::PinBody].map(|text| strings.get(text))
        })
        .collect();
    assert!(all.iter().all(|text| !text.contains("Windows Hello") && !text.contains("funcionado")));
    assert!(all.iter().any(|text| text.contains("OpenHello")));
}

// @spec:AC-061
#[test]
fn every_failure_cause_has_a_title_an_explanation_and_a_try_again_label_in_both_languages() {
    let causes = [
        FailureCause::Timeout, FailureCause::CameraBusy, FailureCause::SensorStuck, FailureCause::NoCamera,
        FailureCause::TpmUnavailable, FailureCause::AuthDenied, FailureCause::KeyFailed, FailureCause::Other,
    ];
    for language in [Language::English, Language::PortugueseBr] {
        let strings = Strings::new(language);
        for cause in causes {
            assert!(!strings.failure_title(cause).is_empty());
            assert!(strings.failure_explanation(cause).len() > 20);
        }
        assert!(!strings.get(Text::TryAgain).is_empty());
    }
}
