use std::collections::VecDeque;

pub const MIN_LIT_MEAN: f64 = 20.0;
pub const PROBE_FRAMES: usize = 8;
pub const MAX_CONSECUTIVE_UNLIT: usize = 60;
const WINDOW: usize = 8;
const UNLIT_RATIO: f64 = 0.5;
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
    fn dark_stream_is_never_admitted() {
        let mut filter = LitFrameFilter::default();
        assert!([1.0, 6.0, 7.0, 19.9].iter().all(|&m| !filter.admit(m)));
    }
}
