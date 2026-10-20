use crate::detect::Detection;
use crate::embedding::estimate_similarity;
use crate::EngineError;

#[derive(Debug, Clone)]
pub struct LivenessConfig {
    pub min_frames: usize,
    pub min_nonrigid_motion: f32,
}

// Measured on the target IR camera over 10-frame bursts: a held photo scored 0.004-0.020, a live face
// 0.005-0.059. Focus variation did not separate them (0.011-0.28 vs 0.009-0.25), so it is not used.
impl Default for LivenessConfig {
    fn default() -> Self {
        Self { min_frames: 8, min_nonrigid_motion: 0.012 }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct LivenessSample {
    pub landmarks: [(f32, f32); 5],
}

impl LivenessSample {
    pub fn observe(detection: &Detection) -> Self {
        Self { landmarks: detection.landmarks }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LivenessReport {
    pub nonrigid_motion: f32,
    pub live: bool,
}

pub fn assess(samples: &[LivenessSample], config: &LivenessConfig) -> Result<LivenessReport, EngineError> {
    if samples.len() < config.min_frames {
        return Err(EngineError::InvalidInput(format!(
            "liveness needs at least {} frames, got {}",
            config.min_frames,
            samples.len()
        )));
    }
    let nonrigid_motion = nonrigid_motion(samples);
    Ok(LivenessReport { nonrigid_motion, live: nonrigid_motion >= config.min_nonrigid_motion })
}

fn nonrigid_motion(samples: &[LivenessSample]) -> f32 {
    let mut total = 0.0;
    for pair in samples.windows(2) {
        let (before, after) = (&pair[0].landmarks, &pair[1].landmarks);
        let rigid = estimate_similarity(before, after);
        let eye_distance = (before[1].0 - before[0].0).hypot(before[1].1 - before[0].1).max(f32::EPSILON);
        let residual: f32 = before
            .iter()
            .zip(after)
            .map(|(b, a)| {
                let predicted = rigid.apply(*b);
                (predicted.0 - a.0).hypot(predicted.1 - a.1)
            })
            .sum::<f32>()
            / before.len() as f32;
        total += residual / eye_distance;
    }
    total / (samples.len() - 1) as f32
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: [(f32, f32); 5] = [(80.0, 90.0), (120.0, 90.0), (100.0, 110.0), (85.0, 130.0), (115.0, 130.0)];

    struct Rng(u64);

    impl Rng {
        fn centered(&mut self, amplitude: f32) -> f32 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            (((self.0 >> 11) as f64 / (1u64 << 53) as f64) as f32 * 2.0 - 1.0) * amplitude
        }
    }

    fn rigid_photo_burst(frames: usize, rng: &mut Rng) -> Vec<LivenessSample> {
        (0..frames)
            .map(|_| {
                let (angle, dx, dy) = (rng.centered(0.05), rng.centered(6.0), rng.centered(6.0));
                let (sin, cos) = angle.sin_cos();
                let landmarks = BASE.map(|(x, y)| (cos * x - sin * y + dx, sin * x + cos * y + dy));
                LivenessSample { landmarks }
            })
            .collect()
    }

    fn live_burst(frames: usize, rng: &mut Rng) -> Vec<LivenessSample> {
        (0..frames)
            .map(|_| {
                let landmarks = BASE.map(|(x, y)| (x + rng.centered(1.5), y + rng.centered(1.5)));
                LivenessSample { landmarks }
            })
            .collect()
    }

    fn still_burst(frames: usize) -> Vec<LivenessSample> {
        vec![LivenessSample { landmarks: BASE }; frames]
    }

    // @spec:AC-012
    #[test]
    fn photo_moving_rigidly_is_rejected() {
        let report = assess(&rigid_photo_burst(12, &mut Rng(5)), &LivenessConfig::default()).unwrap();
        assert!(!report.live, "{report:?}");
        assert!(report.nonrigid_motion < 0.005);
    }

    // @spec:AC-012
    #[test]
    fn perfectly_still_replay_is_rejected() {
        let report = assess(&still_burst(12), &LivenessConfig::default()).unwrap();
        assert!(!report.live);
        assert_eq!(report.nonrigid_motion, 0.0);
    }

    // @spec:AC-012
    #[test]
    fn live_face_with_natural_variation_is_accepted() {
        let report = assess(&live_burst(12, &mut Rng(9)), &LivenessConfig::default()).unwrap();
        assert!(report.live, "{report:?}");
    }

    // @spec:AC-012
    #[test]
    fn detector_jitter_of_a_held_photo_stays_below_the_threshold_and_real_motion_above_it() {
        let config = LivenessConfig::default();
        let burst = |amplitude: f32, seed: u64| {
            let mut rng = Rng(seed);
            (0..10)
                .map(|_| LivenessSample { landmarks: BASE.map(|(x, y)| (x + rng.centered(amplitude), y + rng.centered(amplitude))) })
                .collect::<Vec<_>>()
        };
        assert!(!assess(&burst(0.3, 11), &config).unwrap().live);
        assert!(assess(&burst(1.5, 12), &config).unwrap().live);
    }

    #[test]
    fn short_burst_is_an_error() {
        assert!(assess(&still_burst(3), &LivenessConfig::default()).is_err());
    }
}
