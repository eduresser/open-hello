use engine_adapter_face::enrollment_quality::EnrollmentConfig;
use engine_adapter_face::far_calibration::FarCalibration;
use openhellod::core::{DEFAULT_TARGET_FAR, MAX_SCORED_FRAMES};

// @spec:AC-036
#[test]
fn the_daemon_default_target_gives_a_usable_threshold_on_the_embedded_table() {
    let embeddings = EnrollmentConfig::default().yaw_buckets as f64;
    let per_comparison = DEFAULT_TARGET_FAR / f64::from(MAX_SCORED_FRAMES) / embeddings;
    let threshold = FarCalibration::load(None).unwrap().score_threshold(per_comparison).unwrap();
    assert!((0.75..0.80).contains(&threshold), "{threshold}");
}
