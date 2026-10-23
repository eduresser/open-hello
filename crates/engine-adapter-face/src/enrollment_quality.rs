use thiserror::Error;

use crate::detect::Detection;
use crate::{EngineError, GrayImage};

const YAW_DEG_PER_EYE_DISTANCE: f32 = 100.0;

#[derive(Debug, Clone)]
pub struct EnrollmentConfig {
    pub samples_required: usize,
    pub yaw_range_deg: f32,
    pub blur_threshold: f32,
    pub sample_spacing_ms: u64,
    pub timeout_ms: u64,
    pub min_face_height_ratio: f32,
    pub max_face_height_ratio: f32,
    pub max_center_offset_ratio: f32,
    pub min_face_brightness: f32,
    pub max_face_brightness: f32,
}

impl Default for EnrollmentConfig {
    fn default() -> Self {
        Self {
            samples_required: 6,
            yaw_range_deg: 20.0,
            blur_threshold: 40.0,
            sample_spacing_ms: 200,
            timeout_ms: 20_000,
            min_face_height_ratio: 0.30,
            max_face_height_ratio: 0.85,
            max_center_offset_ratio: 0.20,
            min_face_brightness: 40.0,
            max_face_brightness: 215.0,
        }
    }
}

pub trait OcclusionDetector {
    fn is_occluded(&self, image: &GrayImage, detection: &Detection) -> bool;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameOutcome {
    Accepted,
    Blurred,
    Occluded,
    YawOutOfRange,
    TooSoon,
    MoveLeft,
    MoveRight,
    MoveUp,
    MoveDown,
    TooClose,
    TooFar,
    TooDark,
    TooBright,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    InProgress,
    Complete,
    Failed,
}

#[derive(Debug, Error)]
pub enum EnrollmentError {
    #[error("enrollment timed out after {timeout_ms} ms without collecting enough frontal samples")]
    Timeout { timeout_ms: u64 },
    #[error("enrollment is incomplete: {filled}/{required} samples collected")]
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

pub fn position_guidance(image: &GrayImage, detection: &Detection, config: &EnrollmentConfig) -> Option<FrameOutcome> {
    let (width, height) = (image.width as f32, image.height as f32);
    let height_ratio = detection.height / height;
    if height_ratio < config.min_face_height_ratio {
        return Some(FrameOutcome::TooFar);
    }
    if height_ratio > config.max_face_height_ratio {
        return Some(FrameOutcome::TooClose);
    }
    let offset_x = (detection.x + detection.width / 2.0 - width / 2.0) / width;
    let offset_y = (detection.y + detection.height / 2.0 - height / 2.0) / height;
    let limit = config.max_center_offset_ratio;
    if offset_x.abs() > limit && offset_x.abs() >= offset_y.abs() {
        return Some(if offset_x < 0.0 { FrameOutcome::MoveLeft } else { FrameOutcome::MoveRight });
    }
    if offset_y.abs() > limit {
        return Some(if offset_y < 0.0 { FrameOutcome::MoveDown } else { FrameOutcome::MoveUp });
    }
    None
}

pub fn face_brightness(image: &GrayImage, detection: &Detection) -> f32 {
    let x0 = detection.x.floor().max(0.0) as i64;
    let y0 = detection.y.floor().max(0.0) as i64;
    let x1 = ((detection.x + detection.width).ceil() as i64).min(image.width as i64);
    let y1 = ((detection.y + detection.height).ceil() as i64).min(image.height as i64);
    let mut sum = 0.0;
    let mut count = 0u32;
    for y in y0..y1 {
        for x in x0..x1 {
            sum += image.at(x, y);
            count += 1;
        }
    }
    if count == 0 {
        0.0
    } else {
        sum / count as f32
    }
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
    samples: Vec<Vec<f32>>,
    started_ms: Option<u64>,
    last_accepted_ms: Option<u64>,
    failed: bool,
}

impl<O: OcclusionDetector> EnrollmentSession<O> {
    pub fn new(config: EnrollmentConfig, occlusion: O, _begin_ms: u64) -> Self {
        Self { config, occlusion, samples: Vec::new(), started_ms: None, last_accepted_ms: None, failed: false }
    }

    pub fn state(&self) -> SessionState {
        if self.failed {
            SessionState::Failed
        } else if self.samples.len() >= self.config.samples_required {
            SessionState::Complete
        } else {
            SessionState::InProgress
        }
    }

    pub fn filled(&self) -> usize {
        self.samples.len()
    }

    pub fn tick(&mut self, now_ms: u64) -> Result<(), EnrollmentError> {
        let timeout = EnrollmentError::Timeout { timeout_ms: self.config.timeout_ms };
        if self.failed {
            return Err(timeout);
        }
        if self.state() == SessionState::Complete {
            return Ok(());
        }
        let started_ms = *self.started_ms.get_or_insert(now_ms);
        if now_ms.saturating_sub(started_ms) >= self.config.timeout_ms {
            self.failed = true;
            self.samples.clear();
            return Err(timeout);
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
        if self.state() == SessionState::Complete {
            return Ok(FrameOutcome::TooSoon);
        }
        if let Some(guidance) = position_guidance(image, detection, &self.config) {
            return Ok(guidance);
        }
        let brightness = face_brightness(image, detection);
        if brightness < self.config.min_face_brightness {
            return Ok(FrameOutcome::TooDark);
        }
        if brightness > self.config.max_face_brightness {
            return Ok(FrameOutcome::TooBright);
        }
        if estimate_yaw_deg(&detection.landmarks).abs() > self.config.yaw_range_deg {
            return Ok(FrameOutcome::YawOutOfRange);
        }
        if sharpness(image, detection) < self.config.blur_threshold {
            return Ok(FrameOutcome::Blurred);
        }
        if self.occlusion.is_occluded(image, detection) {
            return Ok(FrameOutcome::Occluded);
        }
        if let Some(last) = self.last_accepted_ms {
            if now_ms.saturating_sub(last) < self.config.sample_spacing_ms {
                return Ok(FrameOutcome::TooSoon);
            }
        }
        self.samples.push(embed()?);
        self.last_accepted_ms = Some(now_ms);
        Ok(FrameOutcome::Accepted)
    }

    pub fn commit(self) -> Result<Vec<Vec<f32>>, EnrollmentError> {
        if self.failed {
            return Err(EnrollmentError::Timeout { timeout_ms: self.config.timeout_ms });
        }
        let required = self.config.samples_required;
        let filled = self.filled();
        if filled < required {
            return Err(EnrollmentError::Incomplete { filled, required });
        }
        Ok(self.samples)
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

    // @spec:AC-001
    #[test]
    fn commit_succeeds_once_enough_spaced_frontal_samples_are_collected() {
        let mut s = session(false);
        for i in 0..6u64 {
            let outcome = s.submit(1_000 + i * 250, &textured_image(), &face_at_yaw(i as f32 - 2.0), embed).unwrap();
            assert_eq!(outcome, FrameOutcome::Accepted);
        }
        assert_eq!(s.state(), SessionState::Complete);
        let template = s.commit().unwrap();
        assert_eq!(template.len(), 6);
    }

    // @spec:AC-001
    #[test]
    fn commit_before_enough_samples_reports_progress() {
        let mut s = session(false);
        s.submit(1_000, &textured_image(), &face_at_yaw(0.0), embed).unwrap();
        let error = s.commit().unwrap_err();
        assert!(matches!(error, EnrollmentError::Incomplete { filled: 1, required: 6 }));
    }

    // @spec:AC-048
    #[test]
    fn non_frontal_frames_are_discarded_without_embedding() {
        let mut s = session(false);
        let image = textured_image();
        for yaw in [25.0, -25.0, 80.0] {
            let outcome = s.submit(1_000, &image, &face_at_yaw(yaw), || panic!("non-frontal frame must not be embedded")).unwrap();
            assert_eq!(outcome, FrameOutcome::YawOutOfRange);
        }
        assert_eq!(s.submit(1_000, &image, &face_at_yaw(19.0), embed).unwrap(), FrameOutcome::Accepted);
        assert_eq!(s.filled(), 1);
    }

    // @spec:AC-049
    #[test]
    fn frames_closer_than_the_spacing_are_discarded_without_embedding() {
        let mut s = session(false);
        let image = textured_image();
        assert_eq!(s.submit(1_000, &image, &face_at_yaw(0.0), embed).unwrap(), FrameOutcome::Accepted);
        let early = s.submit(1_199, &image, &face_at_yaw(0.0), || panic!("early frame must not be embedded")).unwrap();
        assert_eq!(early, FrameOutcome::TooSoon);
        assert_eq!(s.submit(1_200, &image, &face_at_yaw(0.0), embed).unwrap(), FrameOutcome::Accepted);
        assert_eq!(s.filled(), 2);
    }

    #[test]
    fn frames_after_completion_are_not_added() {
        let mut s = session(false);
        let image = textured_image();
        for i in 0..6u64 {
            s.submit(1_000 + i * 250, &image, &face_at_yaw(0.0), embed).unwrap();
        }
        let extra = s.submit(5_000, &image, &face_at_yaw(0.0), || panic!("a full session must not embed")).unwrap();
        assert_eq!(extra, FrameOutcome::TooSoon);
        assert_eq!(s.filled(), 6);
    }

    fn face_box(x: f32, y: f32, size: f32) -> Detection {
        let (cx, cy) = (x + size / 2.0, y + size / 2.0);
        let eye = size * 0.4;
        Detection {
            x,
            y,
            width: size,
            height: size,
            score: 0.99,
            landmarks: [(cx - eye / 2.0, cy - 4.0), (cx + eye / 2.0, cy - 4.0), (cx, cy + 2.0), (cx - 6.0, cy + 8.0), (cx + 6.0, cy + 8.0)],
        }
    }

    fn guidance_for(detection: Detection) -> FrameOutcome {
        session(false).submit(1_000, &textured_image(), &detection, || panic!("a misplaced face must not be embedded")).unwrap()
    }

    // @spec:AC-050
    #[test]
    fn a_face_that_is_too_small_in_the_frame_is_too_far() {
        assert_eq!(guidance_for(face_box(24.0, 24.0, 16.0)), FrameOutcome::TooFar);
    }

    // @spec:AC-051
    #[test]
    fn a_face_that_fills_the_frame_is_too_close() {
        assert_eq!(guidance_for(face_box(4.0, 4.0, 56.0)), FrameOutcome::TooClose);
    }

    // @spec:AC-052
    #[test]
    fn a_face_off_center_is_told_which_way_to_move() {
        assert_eq!(guidance_for(face_box(0.0, 16.0, 32.0)), FrameOutcome::MoveLeft);
        assert_eq!(guidance_for(face_box(32.0, 16.0, 32.0)), FrameOutcome::MoveRight);
        assert_eq!(guidance_for(face_box(16.0, 0.0, 32.0)), FrameOutcome::MoveDown);
        assert_eq!(guidance_for(face_box(16.0, 32.0, 32.0)), FrameOutcome::MoveUp);
        let centered = session(false).submit(1_000, &textured_image(), &face_box(16.0, 16.0, 32.0), embed).unwrap();
        assert_eq!(centered, FrameOutcome::Accepted);
    }

    fn uniform_image(level: u8) -> GrayImage {
        GrayImage::new(64, 64, vec![level; 64 * 64]).unwrap()
    }

    // @spec:AC-054
    #[test]
    fn a_face_in_the_dark_is_discarded_as_too_dark() {
        let outcome = session(false)
            .submit(1_000, &uniform_image(12), &face_box(16.0, 16.0, 32.0), || panic!("a dark frame must not be embedded"))
            .unwrap();
        assert_eq!(outcome, FrameOutcome::TooDark);
    }

    // @spec:AC-055
    #[test]
    fn a_washed_out_face_is_discarded_as_too_bright() {
        let outcome = session(false)
            .submit(1_000, &uniform_image(250), &face_box(16.0, 16.0, 32.0), || panic!("a bright frame must not be embedded"))
            .unwrap();
        assert_eq!(outcome, FrameOutcome::TooBright);
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
    fn the_capture_window_elapsing_fails_with_explicit_error_and_no_template() {
        let mut s = session(false);
        s.submit(1_000, &textured_image(), &face_at_yaw(0.0), embed).unwrap();
        assert!(s.tick(20_999).is_ok());
        assert_eq!(s.state(), SessionState::InProgress);
        let error = s.tick(21_000).unwrap_err();
        assert!(matches!(error, EnrollmentError::Timeout { timeout_ms: 20_000 }));
        assert_eq!(s.state(), SessionState::Failed);
        assert_eq!(s.filled(), 0);
        assert!(matches!(s.commit(), Err(EnrollmentError::Timeout { .. })));
    }

    // @spec:AC-004
    #[test]
    fn late_frame_after_the_window_is_refused() {
        let mut s = session(false);
        s.submit(1_000, &textured_image(), &face_at_yaw(0.0), embed).unwrap();
        let result = s.submit(25_000, &textured_image(), &face_at_yaw(0.0), embed);
        assert!(matches!(result, Err(EnrollmentError::Timeout { .. })));
    }

    // @spec:AC-004
    #[test]
    fn the_window_starts_at_the_first_frame_not_at_session_creation() {
        let mut s = session(false);
        let outcome = s.submit(100_000, &textured_image(), &face_at_yaw(0.0), embed).unwrap();
        assert_eq!(outcome, FrameOutcome::Accepted);
        assert!(s.tick(119_999).is_ok());
        assert!(s.tick(120_000).is_err());
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
