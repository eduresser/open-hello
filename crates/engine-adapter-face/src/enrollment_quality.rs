use thiserror::Error;

use crate::detect::Detection;
use crate::{EngineError, GrayImage};

const YAW_DEG_PER_EYE_DISTANCE: f32 = 100.0;

#[derive(Debug, Clone)]
pub struct EnrollmentConfig {
    pub yaw_buckets: usize,
    pub yaw_range_deg: f32,
    pub blur_threshold: f32,
    pub attempt_timeout_ms: u64,
    pub max_attempts: u32,
}

impl Default for EnrollmentConfig {
    fn default() -> Self {
        Self {
            yaw_buckets: 6,
            yaw_range_deg: 45.0,
            blur_threshold: 40.0,
            attempt_timeout_ms: 60_000,
            max_attempts: 3,
        }
    }
}

pub trait OcclusionDetector {
    fn is_occluded(&self, image: &GrayImage, detection: &Detection) -> bool;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameOutcome {
    Accepted { bucket: usize },
    Blurred,
    Occluded,
    YawOutOfRange,
    BucketAlreadyFilled { bucket: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    InProgress { attempt: u32 },
    Complete,
    Failed,
}

#[derive(Debug, Error)]
pub enum EnrollmentError {
    #[error("enrollment timed out after {attempts} attempts without full yaw coverage")]
    Timeout { attempts: u32 },
    #[error("enrollment is incomplete: {filled}/{required} yaw buckets covered")]
    Incomplete { filled: usize, required: usize },
    #[error(transparent)]
    Engine(#[from] EngineError),
}

pub fn estimate_yaw_deg(landmarks: &[(f32, f32); 5]) -> f32 {
    let (right_eye, left_eye, nose) = (landmarks[0], landmarks[1], landmarks[2]);
    let eye_distance = (left_eye.0 - right_eye.0).abs().max(f32::EPSILON);
    let eye_mid_x = (left_eye.0 + right_eye.0) / 2.0;
    (nose.0 - eye_mid_x) / eye_distance * YAW_DEG_PER_EYE_DISTANCE
}

pub fn sharpness(image: &GrayImage, detection: &Detection) -> f32 {
    let x0 = (detection.x.floor().max(1.0)) as i64;
    let y0 = (detection.y.floor().max(1.0)) as i64;
    let x1 = ((detection.x + detection.width).ceil() as i64).min(image.width as i64 - 1);
    let y1 = ((detection.y + detection.height).ceil() as i64).min(image.height as i64 - 1);
    let mut responses = Vec::new();
    for y in y0..y1 {
        for x in x0..x1 {
            let laplacian = image.at(x - 1, y) + image.at(x + 1, y) + image.at(x, y - 1) + image.at(x, y + 1)
                - 4.0 * image.at(x, y);
            responses.push(laplacian);
        }
    }
    if responses.is_empty() {
        return 0.0;
    }
    let mean = responses.iter().sum::<f32>() / responses.len() as f32;
    responses.iter().map(|r| (r - mean).powi(2)).sum::<f32>() / responses.len() as f32
}

pub struct EnrollmentSession<O: OcclusionDetector> {
    config: EnrollmentConfig,
    occlusion: O,
    buckets: Vec<Option<Vec<f32>>>,
    attempt: u32,
    attempt_started_ms: u64,
    failed: bool,
}

impl<O: OcclusionDetector> EnrollmentSession<O> {
    pub fn new(config: EnrollmentConfig, occlusion: O, now_ms: u64) -> Self {
        let buckets = vec![None; config.yaw_buckets];
        Self { config, occlusion, buckets, attempt: 1, attempt_started_ms: now_ms, failed: false }
    }

    pub fn state(&self) -> SessionState {
        if self.failed {
            SessionState::Failed
        } else if self.filled() == self.config.yaw_buckets {
            SessionState::Complete
        } else {
            SessionState::InProgress { attempt: self.attempt }
        }
    }

    pub fn filled(&self) -> usize {
        self.buckets.iter().flatten().count()
    }

    pub fn tick(&mut self, now_ms: u64) -> Result<(), EnrollmentError> {
        if self.failed {
            return Err(EnrollmentError::Timeout { attempts: self.config.max_attempts });
        }
        if self.state() == SessionState::Complete {
            return Ok(());
        }
        while now_ms.saturating_sub(self.attempt_started_ms) >= self.config.attempt_timeout_ms {
            if self.attempt >= self.config.max_attempts {
                self.failed = true;
                self.buckets.iter_mut().for_each(|b| *b = None);
                return Err(EnrollmentError::Timeout { attempts: self.attempt });
            }
            self.attempt += 1;
            self.attempt_started_ms += self.config.attempt_timeout_ms;
            self.buckets.iter_mut().for_each(|b| *b = None);
        }
        Ok(())
    }

    pub fn submit(
        &mut self,
        now_ms: u64,
        image: &GrayImage,
        detection: &Detection,
        embed: impl FnOnce() -> Result<Vec<f32>, EngineError>,
    ) -> Result<FrameOutcome, EnrollmentError> {
        self.tick(now_ms)?;
        if sharpness(image, detection) < self.config.blur_threshold {
            return Ok(FrameOutcome::Blurred);
        }
        if self.occlusion.is_occluded(image, detection) {
            return Ok(FrameOutcome::Occluded);
        }
        let Some(bucket) = self.bucket_for(estimate_yaw_deg(&detection.landmarks)) else {
            return Ok(FrameOutcome::YawOutOfRange);
        };
        if self.buckets[bucket].is_some() {
            return Ok(FrameOutcome::BucketAlreadyFilled { bucket });
        }
        self.buckets[bucket] = Some(embed()?);
        Ok(FrameOutcome::Accepted { bucket })
    }

    pub fn commit(self) -> Result<Vec<Vec<f32>>, EnrollmentError> {
        if self.failed {
            return Err(EnrollmentError::Timeout { attempts: self.config.max_attempts });
        }
        let required = self.config.yaw_buckets;
        let filled = self.filled();
        if filled < required {
            return Err(EnrollmentError::Incomplete { filled, required });
        }
        Ok(self.buckets.into_iter().flatten().collect())
    }

    fn bucket_for(&self, yaw_deg: f32) -> Option<usize> {
        let range = self.config.yaw_range_deg;
        if !(-range..=range).contains(&yaw_deg) {
            return None;
        }
        let width = 2.0 * range / self.config.yaw_buckets as f32;
        Some((((yaw_deg + range) / width) as usize).min(self.config.yaw_buckets - 1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Occlusion(bool);

    impl OcclusionDetector for Occlusion {
        fn is_occluded(&self, _: &GrayImage, _: &Detection) -> bool {
            self.0
        }
    }

    fn textured_image() -> GrayImage {
        let pixels = (0..64 * 64).map(|i| if (i / 64 + i % 64) % 2 == 0 { 0 } else { 255 }).collect();
        GrayImage::new(64, 64, pixels).unwrap()
    }

    fn flat_image() -> GrayImage {
        GrayImage::new(64, 64, vec![128; 64 * 64]).unwrap()
    }

    fn face_at_yaw(yaw_deg: f32) -> Detection {
        let eye_distance = 20.0;
        let nose_x = 32.0 + yaw_deg / YAW_DEG_PER_EYE_DISTANCE * eye_distance;
        Detection {
            x: 8.0,
            y: 8.0,
            width: 48.0,
            height: 48.0,
            score: 0.99,
            landmarks: [(22.0, 24.0), (42.0, 24.0), (nose_x, 34.0), (26.0, 44.0), (38.0, 44.0)],
        }
    }

    fn session(occluded: bool) -> EnrollmentSession<Occlusion> {
        EnrollmentSession::new(EnrollmentConfig::default(), Occlusion(occluded), 0)
    }

    fn embed() -> Result<Vec<f32>, EngineError> {
        Ok(vec![1.0, 0.0])
    }

    const BUCKET_CENTERS: [f32; 6] = [-37.5, -22.5, -7.5, 7.5, 22.5, 37.5];

    // @spec:AC-001
    #[test]
    fn commit_succeeds_once_all_yaw_buckets_are_covered() {
        let mut s = session(false);
        for (i, yaw) in BUCKET_CENTERS.iter().enumerate() {
            let outcome = s.submit(1_000, &textured_image(), &face_at_yaw(*yaw), embed).unwrap();
            assert_eq!(outcome, FrameOutcome::Accepted { bucket: i });
        }
        assert_eq!(s.state(), SessionState::Complete);
        let template = s.commit().unwrap();
        assert_eq!(template.len(), 6);
    }

    // @spec:AC-001
    #[test]
    fn commit_before_full_coverage_reports_progress() {
        let mut s = session(false);
        s.submit(1_000, &textured_image(), &face_at_yaw(0.0), embed).unwrap();
        let error = s.commit().unwrap_err();
        assert!(matches!(error, EnrollmentError::Incomplete { filled: 1, required: 6 }));
    }

    // @spec:AC-001
    #[test]
    fn repeated_pose_and_out_of_range_yaw_do_not_fill_buckets() {
        let mut s = session(false);
        let image = textured_image();
        assert_eq!(s.submit(1, &image, &face_at_yaw(7.5), embed).unwrap(), FrameOutcome::Accepted { bucket: 3 });
        assert_eq!(
            s.submit(2, &image, &face_at_yaw(8.0), embed).unwrap(),
            FrameOutcome::BucketAlreadyFilled { bucket: 3 }
        );
        assert_eq!(s.submit(3, &image, &face_at_yaw(80.0), embed).unwrap(), FrameOutcome::YawOutOfRange);
        assert_eq!(s.filled(), 1);
    }

    // @spec:AC-002
    #[test]
    fn blurred_frames_are_discarded_without_embedding() {
        let mut s = session(false);
        let outcome = s
            .submit(1_000, &flat_image(), &face_at_yaw(0.0), || panic!("blurred frame must not be embedded"))
            .unwrap();
        assert_eq!(outcome, FrameOutcome::Blurred);
        assert_eq!(s.filled(), 0);
    }

    // @spec:AC-003
    #[test]
    fn occluded_frames_are_discarded_without_embedding() {
        let mut s = session(true);
        let outcome = s
            .submit(1_000, &textured_image(), &face_at_yaw(0.0), || panic!("occluded frame must not be embedded"))
            .unwrap();
        assert_eq!(outcome, FrameOutcome::Occluded);
        assert_eq!(s.filled(), 0);
    }

    // @spec:AC-004
    #[test]
    fn three_consecutive_timeouts_fail_with_explicit_error_and_no_template() {
        let mut s = session(false);
        s.submit(1_000, &textured_image(), &face_at_yaw(0.0), embed).unwrap();
        assert!(s.tick(60_000).is_ok());
        assert_eq!(s.state(), SessionState::InProgress { attempt: 2 });
        assert_eq!(s.filled(), 0);
        assert!(s.tick(120_000).is_ok());
        assert_eq!(s.state(), SessionState::InProgress { attempt: 3 });
        let error = s.tick(180_000).unwrap_err();
        assert!(matches!(error, EnrollmentError::Timeout { attempts: 3 }));
        assert_eq!(s.state(), SessionState::Failed);
        assert!(matches!(s.commit(), Err(EnrollmentError::Timeout { .. })));
    }

    // @spec:AC-004
    #[test]
    fn late_frame_after_final_timeout_is_refused() {
        let mut s = session(false);
        let result = s.submit(200_000, &textured_image(), &face_at_yaw(0.0), embed);
        assert!(matches!(result, Err(EnrollmentError::Timeout { .. })));
    }

    #[test]
    fn yaw_estimate_is_signed_and_proportional() {
        assert!(estimate_yaw_deg(&face_at_yaw(20.0).landmarks) > 19.0);
        assert!(estimate_yaw_deg(&face_at_yaw(-20.0).landmarks) < -19.0);
        assert!(estimate_yaw_deg(&face_at_yaw(0.0).landmarks).abs() < 1e-3);
    }

    #[test]
    fn sharpness_separates_texture_from_flat() {
        let face = face_at_yaw(0.0);
        assert!(sharpness(&textured_image(), &face) > EnrollmentConfig::default().blur_threshold);
        assert!(sharpness(&flat_image(), &face) < EnrollmentConfig::default().blur_threshold);
    }
}
