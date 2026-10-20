use std::collections::HashMap;
use std::sync::Mutex;

use crate::detect::{best_face, Detection, FaceDetector};
use crate::embedding::{embed_detected, FaceEmbedder};
use crate::enrollment_quality::{
    sharpness, EnrollmentConfig, EnrollmentError, EnrollmentSession, FrameOutcome, OcclusionDetector, SessionState,
};
use crate::liveness::{assess, LivenessConfig, LivenessSample};
use crate::matching::{Matcher, Template};
use crate::{EngineError, GrayImage};

const MIN_OCCLUSION_FREE_SCORE: f32 = 0.9;

pub struct ConfidenceOcclusionDetector;

impl OcclusionDetector for ConfidenceOcclusionDetector {
    fn is_occluded(&self, _: &GrayImage, detection: &Detection) -> bool {
        let inside = |(x, y): (f32, f32)| {
            x >= detection.x && x <= detection.x + detection.width && y >= detection.y && y <= detection.y + detection.height
        };
        detection.score < MIN_OCCLUSION_FREE_SCORE || !detection.landmarks.iter().all(|p| inside(*p))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Accepted,
    Blurred,
    Occluded,
    NoFace,
    YawOutOfRange,
    BucketAlreadyFilled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnrollProgress {
    pub verdict: Verdict,
    pub state: SessionState,
    pub filled: usize,
    pub required: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MatchOutcome {
    pub live: bool,
    pub accepted: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdentifyOutcome {
    pub live: bool,
    pub matched_uid: Option<u32>,
}

pub struct Engine {
    detector: Box<dyn FaceDetector + Send + Sync>,
    embedder: Box<dyn FaceEmbedder + Send + Sync>,
    matcher: Matcher,
    enrollment: EnrollmentConfig,
    liveness: LivenessConfig,
    sessions: Mutex<HashMap<u64, EnrollmentSession<ConfidenceOcclusionDetector>>>,
    next_session: Mutex<u64>,
}

impl Engine {
    pub fn new(
        detector: Box<dyn FaceDetector + Send + Sync>,
        embedder: Box<dyn FaceEmbedder + Send + Sync>,
        matcher: Matcher,
        enrollment: EnrollmentConfig,
        liveness: LivenessConfig,
    ) -> Self {
        Self {
            detector,
            embedder,
            matcher,
            enrollment,
            liveness,
            sessions: Mutex::new(HashMap::new()),
            next_session: Mutex::new(1),
        }
    }

    pub fn enroll_begin(&self, now_ms: u64) -> u64 {
        let mut next = self.next_session.lock().unwrap();
        let id = *next;
        *next += 1;
        let session = EnrollmentSession::new(self.enrollment.clone(), ConfidenceOcclusionDetector, now_ms);
        self.sessions.lock().unwrap().insert(id, session);
        id
    }

    pub fn enroll_submit(&self, id: u64, now_ms: u64, image: &GrayImage) -> Result<EnrollProgress, EngineError> {
        let mut sessions = self.sessions.lock().unwrap();
        let session = sessions.get_mut(&id).ok_or_else(|| EngineError::InvalidInput(format!("unknown enrollment session {id}")))?;
        let required = self.enrollment.yaw_buckets;
        let progress = |verdict, session: &EnrollmentSession<_>| EnrollProgress {
            verdict,
            state: session.state(),
            filled: session.filled(),
            required,
        };
        let detection = match best_face(self.detector.detect(image)?) {
            Ok(detection) => detection,
            Err(EngineError::NoFace) => {
                session.tick(now_ms).map_err(enrollment_error)?;
                return Ok(progress(Verdict::NoFace, session));
            }
            Err(other) => return Err(other),
        };
        let outcome = session
            .submit(now_ms, image, &detection, || embed_detected(self.embedder.as_ref(), image, &detection))
            .map_err(enrollment_error)?;
        let verdict = match outcome {
            FrameOutcome::Accepted { .. } => Verdict::Accepted,
            FrameOutcome::Blurred => Verdict::Blurred,
            FrameOutcome::Occluded => Verdict::Occluded,
            FrameOutcome::YawOutOfRange => Verdict::YawOutOfRange,
            FrameOutcome::BucketAlreadyFilled { .. } => Verdict::BucketAlreadyFilled,
        };
        Ok(progress(verdict, session))
    }

    pub fn enroll_commit(&self, id: u64) -> Result<Vec<u8>, EngineError> {
        let session = self
            .sessions
            .lock()
            .unwrap()
            .remove(&id)
            .ok_or_else(|| EngineError::InvalidInput(format!("unknown enrollment session {id}")))?;
        let embeddings = session.commit().map_err(enrollment_error)?;
        Ok(Template::new(embeddings)?.to_bytes())
    }

    pub fn enroll_discard(&self, id: u64) -> bool {
        self.sessions.lock().unwrap().remove(&id).is_some()
    }

    pub fn verify(&self, frames: &[GrayImage], template: &Template, target_far: f64) -> Result<MatchOutcome, EngineError> {
        let (live, probe) = self.probe(frames)?;
        if !live {
            return Ok(MatchOutcome { live, accepted: false });
        }
        Ok(MatchOutcome { live, accepted: self.matcher.verify(&probe, template, target_far)? })
    }

    pub fn identify(
        &self,
        frames: &[GrayImage],
        enrolled: &[(u32, Template)],
        target_far: f64,
    ) -> Result<IdentifyOutcome, EngineError> {
        let (live, probe) = self.probe(frames)?;
        if !live {
            return Ok(IdentifyOutcome { live, matched_uid: None });
        }
        let matched = self.matcher.identify(&probe, enrolled, target_far)?;
        Ok(IdentifyOutcome { live, matched_uid: matched.map(|m| m.uid) })
    }

    fn probe(&self, frames: &[GrayImage]) -> Result<(bool, Vec<f32>), EngineError> {
        let mut observed = Vec::new();
        for image in frames {
            if let Ok(detection) = best_face(self.detector.detect(image)?) {
                observed.push((image, detection));
            }
        }
        let samples: Vec<LivenessSample> = observed.iter().map(|(i, d)| LivenessSample::observe(i, d)).collect();
        if samples.len() < self.liveness.min_frames {
            return Err(EngineError::NoFace);
        }
        let live = assess(&samples, &self.liveness)?.live;
        let (image, detection) = observed
            .iter()
            .max_by(|a, b| sharpness(a.0, &a.1).total_cmp(&sharpness(b.0, &b.1)))
            .expect("samples is non-empty");
        Ok((live, embed_detected(self.embedder.as_ref(), image, detection)?))
    }
}

fn enrollment_error(error: EnrollmentError) -> EngineError {
    match error {
        EnrollmentError::Engine(inner) => inner,
        other => EngineError::InvalidInput(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::embedding::l2_normalize;
    use crate::far_calibration::FarCalibration;

    struct ScriptedDetector {
        calls: AtomicUsize,
        script: Vec<Vec<Detection>>,
    }

    impl FaceDetector for ScriptedDetector {
        fn detect(&self, _: &GrayImage) -> Result<Vec<Detection>, EngineError> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.script[call % self.script.len()].clone())
        }
    }

    struct BrightnessEmbedder;

    impl FaceEmbedder for BrightnessEmbedder {
        fn embed(&self, aligned: &GrayImage) -> Result<Vec<f32>, EngineError> {
            let mean = aligned.pixels.iter().map(|&p| p as f32).sum::<f32>() / aligned.pixels.len() as f32;
            l2_normalize(vec![mean + 1.0, 255.0 - mean + 1.0])
        }
    }

    fn textured() -> GrayImage {
        let pixels = (0..128 * 128).map(|i| if (i / 128 + i % 128) % 2 == 0 { 20 } else { 230 }).collect();
        GrayImage::new(128, 128, pixels).unwrap()
    }

    fn face(yaw_offset: f32, jitter: f32) -> Detection {
        let nose_x = 64.0 + yaw_offset;
        Detection {
            x: 24.0,
            y: 24.0,
            width: 80.0,
            height: 80.0,
            score: 0.99,
            landmarks: [
                (50.0 + jitter, 52.0),
                (78.0, 52.0 - jitter),
                (nose_x, 68.0 + jitter),
                (54.0 - jitter, 86.0),
                (74.0, 86.0 + jitter),
            ],
        }
    }

    fn calibration() -> FarCalibration {
        let scores: Vec<f32> = (0..2000).map(|i| ((i as f32 * 0.7919).sin()) * 0.05).collect();
        FarCalibration::from_impostor_scores(&scores).unwrap()
    }

    fn engine(script: Vec<Vec<Detection>>) -> Engine {
        Engine::new(
            Box::new(ScriptedDetector { calls: AtomicUsize::new(0), script }),
            Box::new(BrightnessEmbedder),
            Matcher::new(calibration()),
            EnrollmentConfig::default(),
            LivenessConfig::default(),
        )
    }

    #[test]
    fn enrollment_flows_through_detector_gate_and_commits_a_template() {
        let yaws: Vec<f32> = [-37.5, -22.5, -7.5, 7.5, 22.5, 37.5].iter().map(|deg| deg * 0.28).collect();
        let engine = engine(yaws.iter().map(|y| vec![face(*y, 0.0)]).collect());
        let session = engine.enroll_begin(0);
        let mut last = None;
        for step in 0..6u64 {
            last = Some(engine.enroll_submit(session, step * 100, &textured()).unwrap());
        }
        let last = last.unwrap();
        assert_eq!(last.verdict, Verdict::Accepted);
        assert_eq!(last.state, SessionState::Complete);
        let template = Template::from_bytes(&engine.enroll_commit(session).unwrap()).unwrap();
        assert_eq!(template.to_bytes().len(), 8 + 6 * 2 * 4);
    }

    #[test]
    fn frames_without_a_face_report_no_face_and_unknown_sessions_error() {
        let engine = engine(vec![vec![]]);
        let session = engine.enroll_begin(0);
        assert_eq!(engine.enroll_submit(session, 10, &textured()).unwrap().verdict, Verdict::NoFace);
        assert!(engine.enroll_submit(999, 10, &textured()).is_err());
        assert!(engine.enroll_commit(999).is_err());
        assert!(engine.enroll_discard(session));
        assert!(!engine.enroll_discard(session));
    }

    #[test]
    fn photo_like_burst_is_not_live_and_never_accepted() {
        let still = vec![face(0.0, 0.0)];
        let engine = engine(vec![still]);
        let template = Template::new(vec![vec![0.7, 0.7]]).unwrap();
        let frames = vec![textured(); 10];
        let outcome = engine.verify(&frames, &template, 1e-5).unwrap();
        assert_eq!(outcome, MatchOutcome { live: false, accepted: false });
        assert_eq!(engine.identify(&frames, &[(1000, template)], 1e-5).unwrap(), IdentifyOutcome { live: false, matched_uid: None });
    }

    #[test]
    fn short_burst_without_enough_faces_is_an_error() {
        let engine = engine(vec![vec![face(0.0, 0.0)]]);
        let template = Template::new(vec![vec![0.7, 0.7]]).unwrap();
        assert!(matches!(engine.verify(&vec![textured(); 2], &template, 1e-5), Err(EngineError::NoFace)));
    }

    #[test]
    fn occlusion_heuristic_flags_low_confidence_and_stray_landmarks() {
        let image = textured();
        assert!(!ConfidenceOcclusionDetector.is_occluded(&image, &face(0.0, 0.0)));
        let mut weak = face(0.0, 0.0);
        weak.score = 0.5;
        assert!(ConfidenceOcclusionDetector.is_occluded(&image, &weak));
        let mut stray = face(0.0, 0.0);
        stray.landmarks[2] = (500.0, 500.0);
        assert!(ConfidenceOcclusionDetector.is_occluded(&image, &stray));
    }
}
