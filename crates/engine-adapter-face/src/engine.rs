use std::collections::HashMap;
use std::sync::Mutex;

use crate::detect::{best_face, Detection, FaceDetector};
use crate::embedding::{embed_detected, FaceEmbedder};
use crate::enrollment_quality::{
    EnrollmentConfig, EnrollmentError, EnrollmentSession, FrameOutcome, OcclusionDetector, SessionState,
};
use crate::matching::{Matcher, Template};
use crate::{EngineError, GrayImage};

const MIN_OCCLUSION_FREE_SCORE: f32 = 0.9;
const SCORE_LOG_ENV: &str = "OPENHELLO_SCORE_LOG";

fn score_log_enabled() -> bool {
    std::env::var(SCORE_LOG_ENV).is_ok_and(|value| value == "1")
}

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
pub enum AuthVerdict {
    Continue,
    Accepted { uid: u32 },
    Rejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthProgress {
    pub verdict: AuthVerdict,
    pub scored_frames: usize,
}

struct AuthSession {
    candidates: Vec<(u32, Template)>,
    far_per_frame: f64,
    max_scored_frames: usize,
    scored_frames: usize,
}

pub struct Engine {
    detector: Box<dyn FaceDetector + Send + Sync>,
    embedder: Box<dyn FaceEmbedder + Send + Sync>,
    matcher: Matcher,
    enrollment: EnrollmentConfig,
    sessions: Mutex<HashMap<u64, EnrollmentSession<ConfidenceOcclusionDetector>>>,
    auth_sessions: Mutex<HashMap<u64, AuthSession>>,
    next_session: Mutex<u64>,
}

impl Engine {
    pub fn new(
        detector: Box<dyn FaceDetector + Send + Sync>,
        embedder: Box<dyn FaceEmbedder + Send + Sync>,
        matcher: Matcher,
        enrollment: EnrollmentConfig,
    ) -> Self {
        Self {
            detector,
            embedder,
            matcher,
            enrollment,
            sessions: Mutex::new(HashMap::new()),
            auth_sessions: Mutex::new(HashMap::new()),
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

    pub fn auth_begin(
        &self,
        candidates: Vec<(u32, Template)>,
        target_far: f64,
        max_scored_frames: usize,
    ) -> Result<u64, EngineError> {
        if candidates.is_empty() || max_scored_frames == 0 || !(target_far > 0.0 && target_far < 1.0) {
            return Err(EngineError::InvalidInput(format!(
                "authentication needs candidates, a frame budget and a target FAR in (0, 1); got {} candidates, {max_scored_frames} frames, FAR {target_far}",
                candidates.len()
            )));
        }
        let mut next = self.next_session.lock().unwrap();
        let id = *next;
        *next += 1;
        self.auth_sessions.lock().unwrap().insert(
            id,
            AuthSession {
                candidates,
                far_per_frame: target_far / max_scored_frames as f64,
                max_scored_frames,
                scored_frames: 0,
            },
        );
        Ok(id)
    }

    pub fn auth_submit(&self, id: u64, image: &GrayImage) -> Result<AuthProgress, EngineError> {
        let mut sessions = self.auth_sessions.lock().unwrap();
        let session = sessions
            .get_mut(&id)
            .ok_or_else(|| EngineError::InvalidInput(format!("unknown authentication session {id}")))?;
        let detection = match best_face(self.detector.detect(image)?) {
            Ok(detection) => detection,
            Err(EngineError::NoFace) => {
                if score_log_enabled() {
                    eprintln!("openhello-score no-face scored_frames={}", session.scored_frames);
                }
                return Ok(AuthProgress { verdict: AuthVerdict::Continue, scored_frames: session.scored_frames });
            }
            Err(other) => return Err(other),
        };
        session.scored_frames += 1;
        let probe = embed_detected(self.embedder.as_ref(), image, &detection)?;
        let scored = self.matcher.identify_scored(&probe, &session.candidates, session.far_per_frame)?;
        if score_log_enabled() {
            eprintln!(
                "openhello-score frame={} face={}x{} detector={:.2} score={:.4} threshold={:.4} accepted={}",
                session.scored_frames,
                detection.width as u32,
                detection.height as u32,
                detection.score,
                scored.best_score,
                scored.threshold,
                scored.found.is_some()
            );
        }
        let verdict = match scored.found {
            Some(found) => AuthVerdict::Accepted { uid: found.uid },
            None if session.scored_frames >= session.max_scored_frames => AuthVerdict::Rejected,
            None => AuthVerdict::Continue,
        };
        Ok(AuthProgress { verdict, scored_frames: session.scored_frames })
    }

    pub fn auth_end(&self, id: u64) -> bool {
        self.auth_sessions.lock().unwrap().remove(&id).is_some()
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

    struct FixedEmbedder(Vec<f32>);

    impl FaceEmbedder for FixedEmbedder {
        fn embed(&self, _: &GrayImage) -> Result<Vec<f32>, EngineError> {
            Ok(self.0.clone())
        }
    }

    fn engine(script: Vec<Vec<Detection>>) -> Engine {
        engine_with(script, Box::new(BrightnessEmbedder))
    }

    fn engine_with(script: Vec<Vec<Detection>>, embedder: Box<dyn FaceEmbedder + Send + Sync>) -> Engine {
        Engine::new(
            Box::new(ScriptedDetector { calls: AtomicUsize::new(0), script }),
            embedder,
            Matcher::new(calibration()),
            EnrollmentConfig::default(),
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

    fn steady_face_script() -> Vec<Vec<Detection>> {
        vec![vec![face(0.0, 0.0)]]
    }

    fn probe_of(image: &GrayImage, detection: &Detection) -> Vec<f32> {
        embed_detected(&BrightnessEmbedder, image, detection).unwrap()
    }

    fn template_with_cosine(probe: &[f32], cosine: f32) -> Template {
        let orthogonal = [-probe[1], probe[0]];
        let sine = (1.0 - cosine * cosine).sqrt();
        Template::new(vec![vec![cosine * probe[0] + sine * orthogonal[0], cosine * probe[1] + sine * orthogonal[1]]]).unwrap()
    }

    fn run_until_decided(engine: &Engine, session: u64, frames: usize) -> AuthProgress {
        let mut last = engine.auth_submit(session, &textured()).unwrap();
        for _ in 1..frames {
            if last.verdict != AuthVerdict::Continue {
                break;
            }
            last = engine.auth_submit(session, &textured()).unwrap();
        }
        last
    }

    // @spec:AC-005
    // @spec:AC-007
    #[test]
    fn matching_face_is_accepted_on_the_first_scored_frame() {
        let engine = engine(steady_face_script());
        let template = Template::new(vec![probe_of(&textured(), &face(0.0, 0.0))]).unwrap();
        let session = engine.auth_begin(vec![(1000, template)], 1e-5, 16).unwrap();
        let progress = run_until_decided(&engine, session, 16);
        assert_eq!(progress.verdict, AuthVerdict::Accepted { uid: 1000 });
        assert_eq!(progress.scored_frames, 1);
        assert!(engine.auth_end(session));
    }

    // @spec:AC-007
    #[test]
    fn identification_picks_the_matching_account_among_several() {
        let engine = engine(steady_face_script());
        let probe = probe_of(&textured(), &face(0.0, 0.0));
        let stranger = Template::new(vec![vec![-probe[1], probe[0]]]).unwrap();
        let owner = Template::new(vec![probe]).unwrap();
        let session = engine.auth_begin(vec![(1000, stranger), (1001, owner)], 1e-5, 16).unwrap();
        assert_eq!(run_until_decided(&engine, session, 16).verdict, AuthVerdict::Accepted { uid: 1001 });
    }

    // @spec:AC-006
    // @spec:AC-008
    #[test]
    fn non_matching_face_is_rejected_when_the_frame_budget_runs_out() {
        let engine = engine(steady_face_script());
        let probe = probe_of(&textured(), &face(0.0, 0.0));
        let stranger = Template::new(vec![vec![-probe[1], probe[0]]]).unwrap();
        let session = engine.auth_begin(vec![(1000, stranger)], 1e-5, 12).unwrap();
        let progress = run_until_decided(&engine, session, 30);
        assert_eq!(progress.verdict, AuthVerdict::Rejected);
        assert_eq!(progress.scored_frames, 12);
    }

    // @spec:AC-005
    #[test]
    fn target_far_is_split_across_the_frame_budget() {
                let probe = vec![1.0, 0.0];
        let calibration = calibration();
        let small_budget = calibration.score_threshold(1e-5).unwrap();
        let large_budget = calibration.score_threshold(1e-5 / 2.0).unwrap();
        assert!(large_budget > small_budget);
        let template = template_with_cosine(&probe, ((small_budget + large_budget) / 2.0) as f32);

        let small = engine_with(steady_face_script(), Box::new(FixedEmbedder(probe.clone())));
        let session = small.auth_begin(vec![(1000, template.clone())], 1e-5, 1).unwrap();
        assert_eq!(run_until_decided(&small, session, 40).verdict, AuthVerdict::Accepted { uid: 1000 });

        let large = engine_with(steady_face_script(), Box::new(FixedEmbedder(probe)));
        let session = large.auth_begin(vec![(1000, template)], 1e-5, 2).unwrap();
        assert_eq!(run_until_decided(&large, session, 40).verdict, AuthVerdict::Rejected);
    }

    #[test]
    fn frames_without_a_face_do_not_consume_the_frame_budget() {
        let engine = engine(vec![vec![]]);
        let template = Template::new(vec![vec![0.7, 0.7]]).unwrap();
        let session = engine.auth_begin(vec![(1000, template)], 1e-5, 3).unwrap();
        for _ in 0..10 {
            let progress = engine.auth_submit(session, &textured()).unwrap();
            assert_eq!(progress, AuthProgress { verdict: AuthVerdict::Continue, scored_frames: 0 });
        }
    }

    #[test]
    fn invalid_authentication_arguments_and_unknown_sessions_are_errors() {
        let engine = engine(vec![vec![]]);
        let template = Template::new(vec![vec![0.7, 0.7]]).unwrap();
        assert!(engine.auth_begin(vec![], 1e-5, 8).is_err());
        assert!(engine.auth_begin(vec![(1, template.clone())], 1e-5, 0).is_err());
        assert!(engine.auth_begin(vec![(1, template.clone())], 0.0, 8).is_err());
        assert!(engine.auth_begin(vec![(1, template)], 1.0, 8).is_err());
        assert!(engine.auth_submit(999, &textured()).is_err());
        assert!(!engine.auth_end(999));
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
