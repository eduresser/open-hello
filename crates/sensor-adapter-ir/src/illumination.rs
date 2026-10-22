use std::collections::VecDeque;

// 2b7e:c757 shows flat frames at ~25 while warming up, lit frames at ~48 and unlit ones at ~2.
pub const MIN_LIT_MEAN: f64 = 30.0;
pub const PROBE_LIT_FRAMES: usize = 4;
// 2b7e:c757 needs about 35 frames after the stream starts before the lit frames reach full exposure.
pub const MAX_PROBE_FRAMES: usize = 90;
pub const MAX_CONSECUTIVE_UNLIT: usize = 60;
const WINDOW: usize = 8;
const UNLIT_RATIO: f64 = 0.5;
const MIN_SWINGS: usize = 3;
const SAMPLE_STEP: usize = 7;

pub fn mean_luma(pixels: &[u8]) -> f64 {
    let (sum, count) = pixels
        .iter()
        .step_by(SAMPLE_STEP)
        .fold((0u64, 0u64), |(sum, count), &p| (sum + u64::from(p), count + 1));
    if count == 0 {
        0.0
    } else {
        sum as f64 / count as f64
    }
}

#[derive(Default)]
pub struct LitFrameFilter {
    recent: VecDeque<f64>,
}

impl LitFrameFilter {
    pub fn admit(&mut self, mean: f64) -> bool {
        self.recent.push_back(mean);
        if self.recent.len() > WINDOW {
            self.recent.pop_front();
        }
        let brightest = self.recent.iter().cloned().fold(0.0, f64::max);
        mean >= MIN_LIT_MEAN && mean >= UNLIT_RATIO * brightest
    }
}

#[derive(Default)]
pub struct AlternationDetector {
    previous: Option<f64>,
    swings: usize,
}

impl AlternationDetector {
    pub fn observe(&mut self, mean: f64) {
        if let Some(previous) = self.previous {
            let (low, high) = (previous.min(mean), previous.max(mean));
            if high >= MIN_LIT_MEAN && low <= UNLIT_RATIO * high {
                self.swings += 1;
            }
        }
        self.previous = Some(mean);
    }

    pub fn alternating(&self) -> bool {
        self.swings >= MIN_SWINGS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mean_of_uniform_frame_and_empty_frame() {
        assert_eq!(mean_luma(&[100; 640]), 100.0);
        assert_eq!(mean_luma(&[]), 0.0);
    }

    #[test]
    fn strobing_stream_keeps_lit_frames_and_drops_unlit_ones() {
        let mut filter = LitFrameFilter::default();
        let admitted: Vec<bool> = [49.0, 7.0, 66.0, 7.0, 66.0, 7.0, 73.0].iter().map(|&m| filter.admit(m)).collect();
        assert_eq!(admitted, vec![true, false, true, false, true, false, true]);
    }

    #[test]
    fn steady_lit_stream_is_fully_admitted_even_when_exposure_drifts() {
        let mut filter = LitFrameFilter::default();
        assert!([60.0, 58.0, 55.0, 52.0, 50.0, 47.0].iter().all(|&m| filter.admit(m)));
    }

    #[test]
    fn dark_stream_and_warm_up_level_frames_are_never_admitted() {
        let mut filter = LitFrameFilter::default();
        assert!([1.0, 6.0, 7.0, 25.0, 27.0, 29.9].iter().all(|&m| !filter.admit(m)));
    }

    fn alternates(means: &[f64]) -> bool {
        let mut detector = AlternationDetector::default();
        means.iter().for_each(|&m| detector.observe(m));
        detector.alternating()
    }

    // @covers:AC-039-alternation
    #[test]
    fn strobing_means_alternate_but_flat_ambient_ramping_and_stepped_streams_do_not() {
        assert!(alternates(&[100.0, 15.0, 98.0, 15.0, 97.0, 15.0]));
        assert!(!alternates(&[25.0; 40]));
        assert!(!alternates(&[90.0; 40]));
        let ramp: Vec<f64> = (31..148).map(f64::from).collect();
        assert!(!alternates(&ramp));
        let mut stepped = vec![5.0; 20];
        stepped.extend(vec![66.0; 20]);
        assert!(!alternates(&stepped));
    }
}
