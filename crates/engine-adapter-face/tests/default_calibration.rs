use engine_adapter_face::far_calibration::{FarCalibration, Provenance, REPORTED_FARS};
use engine_adapter_face::matching::{Matcher, Template};
use engine_adapter_face::EngineError;

const EMBEDDED: &str = include_str!("../config/default_calibration.toml");

fn error_text(result: Result<FarCalibration, EngineError>) -> String {
    result.expect_err("loading must fail").to_string()
}

fn shifted_calibration() -> FarCalibration {
    let scores: Vec<f32> = (0..5_000u32)
        .map(|i| 0.85 + 0.1 * ((i.wrapping_mul(2654435761) % 10_000) as f32 / 10_000.0))
        .collect();
    FarCalibration::from_impostor_scores(&scores).unwrap()
}

fn write(dir: &tempfile::TempDir, name: &str, contents: &[u8]) -> std::path::PathBuf {
    let path = dir.path().join(name);
    std::fs::write(&path, contents).unwrap();
    path
}

fn decision_at_cosine(calibration: FarCalibration, cosine: f32) -> bool {
    let template = Template::new(vec![vec![1.0, 0.0]]).unwrap();
    Matcher::new(calibration)
        .verify(&[cosine, (1.0 - cosine * cosine).sqrt()], &template, 1e-5)
        .unwrap()
}

// @spec:AC-036
#[test]
fn engine_calibration_loads_without_a_file_and_uses_the_embedded_threshold_at_1e_5() {
    let calibration = FarCalibration::load(None).unwrap();
    assert!((calibration.score_threshold(1e-5).unwrap() - 0.7244).abs() < 5e-4);
    assert!(decision_at_cosine(calibration.clone(), 0.74));
    assert!(!decision_at_cosine(calibration, 0.70));
}

// @spec:AC-036
#[test]
fn the_daemon_default_threshold_sits_between_the_measured_infrared_impostor_and_genuine_scores() {
    let calibration = FarCalibration::load(None).unwrap();
    let threshold = calibration.score_threshold(2e-4 / 16.0 / 6.0).unwrap();
    assert!((0.75..0.80).contains(&threshold), "{threshold}");
}

// @spec:AC-037
#[test]
fn a_valid_file_overrides_the_embedded_table() {
    let dir = tempfile::tempdir().unwrap();
    let custom = shifted_calibration();
    let embedded_threshold = FarCalibration::load(None)
        .unwrap()
        .score_threshold(1e-5)
        .unwrap();
    for (name, contents) in [
        (
            "custom.toml",
            custom.to_toml(&Provenance::default()).into_bytes(),
        ),
        ("custom.bin", custom.to_bytes()),
    ] {
        let loaded = FarCalibration::load(Some(&write(&dir, name, &contents))).unwrap();
        assert_eq!(loaded, custom);
        assert!(loaded.score_threshold(1e-5).unwrap() > embedded_threshold + 0.1);
        assert!(!decision_at_cosine(loaded, 0.48));
    }
}

// @spec:AC-038
#[test]
fn truncated_wrong_marker_and_inconsistent_files_fail_explicitly_without_the_embedded_table() {
    let dir = tempfile::tempdir().unwrap();
    let valid = shifted_calibration().to_toml(&Provenance::default());
    let binary = shifted_calibration().to_bytes();
    let embedded_tail_score = "0.4720372259616852";
    let cases: Vec<(&str, Vec<u8>)> = vec![
        (
            "truncated.toml",
            valid.as_bytes()[..valid.len() / 2].to_vec(),
        ),
        ("truncated.bin", binary[..binary.len() - 5].to_vec()),
        (
            "marker.toml",
            valid
                .replace("openhello-far-calibration", "something-else")
                .into_bytes(),
        ),
        ("marker.bin", [b"XXXX".as_slice(), &binary[4..]].concat()),
        ("garbage.toml", vec![0xff, 0xfe, 0x00, 0x01]),
        (
            "inconsistent.toml",
            valid.replace("scale = ", "scale = -").into_bytes(),
        ),
        ("empty.toml", Vec::new()),
    ];
    for (name, contents) in cases {
        let message = error_text(FarCalibration::load(Some(&write(&dir, name, &contents))));
        assert!(message.contains(name), "{name}: {message}");
        assert!(!message.contains(embedded_tail_score), "{name}: {message}");
    }
    assert!(
        error_text(FarCalibration::load(Some(&dir.path().join("missing.toml"))))
            .contains("missing.toml")
    );
}

#[test]
fn toml_and_binary_round_trip_to_the_same_calibration() {
    let embedded = FarCalibration::embedded_default().unwrap();
    assert_eq!(
        FarCalibration::from_toml(&embedded.to_toml(&Provenance::default())).unwrap(),
        embedded
    );
    assert_eq!(
        FarCalibration::from_file_contents(&embedded.to_bytes()).unwrap(),
        embedded
    );
    let from_binary = FarCalibration::from_bytes(&embedded.to_bytes()).unwrap();
    assert_eq!(
        FarCalibration::from_toml(&from_binary.to_toml(&Provenance::default())).unwrap(),
        embedded
    );
}

#[test]
fn toml_with_a_wrong_sized_table_is_rejected() {
    let embedded = FarCalibration::embedded_default()
        .unwrap()
        .to_toml(&Provenance::default());
    let first_row_start = embedded.find("  [0.5,").unwrap();
    let first_row_end = first_row_start + embedded[first_row_start..].find('\n').unwrap() + 1;
    let short = format!(
        "{}{}",
        &embedded[..first_row_start],
        &embedded[first_row_end..]
    );
    assert!(error_text(FarCalibration::from_toml(&short)).contains("wrong size"));
}

#[test]
fn embedded_table_parses_and_its_thresholds_are_monotonic_and_match_the_informative_block() {
    let calibration = FarCalibration::from_toml(EMBEDDED).unwrap();
    let thresholds: Vec<f64> = REPORTED_FARS
        .iter()
        .map(|&far| calibration.score_threshold(far).unwrap())
        .collect();
    assert!(
        thresholds.windows(2).all(|pair| pair[1] > pair[0]),
        "{thresholds:?}"
    );
    let document: toml_edit::DocumentMut = EMBEDDED.parse().unwrap();
    for (far, threshold) in REPORTED_FARS.iter().zip(&thresholds) {
        let listed = document["thresholds"][format!("{far:e}").as_str()]
            .as_float()
            .unwrap();
        assert!(
            (listed - threshold).abs() < 5e-5,
            "FAR {far}: listed {listed}, computed {threshold}"
        );
    }
    assert_eq!(
        document["provenance"]["impostor_pairs"].as_integer(),
        Some(19_110)
    );
}
