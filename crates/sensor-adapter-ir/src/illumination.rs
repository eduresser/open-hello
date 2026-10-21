use std::collections::VecDeque;

pub const MIN_LIT_MEAN: f64 = 20.0;
// Real lit frames spread well past this; a camera stuck at a flat gray level (seen on 2b7e:c757 with brightness 25 and
// std dev ~0.5) passes the mean test but carries no image.
pub const MIN_LIT_STD_DEV: f64 = 3.0;
pub const PROBE_LIT_FRAMES: usize = 4;
// 2b7e:c757 needs about 35 frames after the stream starts before the lit frames reach full exposure.
pub const MAX_PROBE_FRAMES: usize = 90;
pub const MAX_CONSECUTIVE_UNLIT: usize = 60;
const WINDOW: usize = 8;
const UNLIT_RATIO: f64 = 0.5;
const SAMPLE_STEP: usize = 7;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FrameStats {
    pub mean: f64,
    pub std_dev: f64,
}

impl FrameStats {
    pub fn of(pixels: &[u8]) -> Self {
        let (sum, sum_squares, count) = pixels.iter().step_by(SAMPLE_STEP).fold((0u64, 0u64, 0u64), |(sum, squares, count), &p| {
            (sum + u64::from(p), squares + u64::from(p) * u64::from(p), count + 1)
        });
        if count == 0 {
            return Self { mean: 0.0, std_dev: 0.0 };
        }
        let mean = sum as f64 / count as f64;
        let variance = (sum_squares as f64 / count as f64 - mean * mean).max(0.0);
        Self { mean, std_dev: variance.sqrt() }
    }

    pub fn is_illuminated(&self) -> bool {
        self.mean >= MIN_LIT_MEAN && self.std_dev >= MIN_LIT_STD_DEV
    }
}

#[derive(Default)]
pub struct LitFrameFilter {
    recent: VecDeque<f64>,
}

impl LitFrameFilter {
    pub fn admit(&mut self, stats: FrameStats) -> bool {
        let mean = stats.mean;
        self.recent.push_back(mean);
        if self.recent.len() > WINDOW {
            self.recent.pop_front();
        }
        let brightest = self.recent.iter().cloned().fold(0.0, f64::max);
        stats.is_illuminated() && mean >= UNLIT_RATIO * brightest
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn textured(mean: f64) -> FrameStats {
        FrameStats { mean, std_dev: 20.0 }
    }

    #[test]
    fn stats_of_uniform_frame_and_empty_frame() {
        assert_eq!(FrameStats::of(&[100; 640]), FrameStats { mean: 100.0, std_dev: 0.0 });
        assert_eq!(FrameStats::of(&[]), FrameStats { mean: 0.0, std_dev: 0.0 });
    }

    #[test]
    fn std_dev_measures_the_spread_of_the_pixels() {
        let pixels: Vec<u8> = (0..640).map(|i| if i % 2 == 0 { 40 } else { 80 }).collect();
        let stats = FrameStats::of(&pixels);
        assert!((stats.mean - 60.0).abs() < 1.0, "{stats:?}");
        assert!((stats.std_dev - 20.0).abs() < 1.0, "{stats:?}");
    }

    #[test]
    fn strobing_stream_keeps_lit_frames_and_drops_unlit_ones() {
        let mut filter = LitFrameFilter::default();
        let admitted: Vec<bool> = [49.0, 7.0, 66.0, 7.0, 66.0, 7.0, 73.0].iter().map(|&m| filter.admit(textured(m))).collect();
        assert_eq!(admitted, vec![true, false, true, false, true, false, true]);
    }

    #[test]
    fn steady_lit_stream_is_fully_admitted_even_when_exposure_drifts() {
        let mut filter = LitFrameFilter::default();
        assert!([60.0, 58.0, 55.0, 52.0, 50.0, 47.0].iter().all(|&m| filter.admit(textured(m))));
    }

    #[test]
    fn dark_stream_is_never_admitted() {
        let mut filter = LitFrameFilter::default();
        assert!([1.0, 6.0, 7.0, 19.9].iter().all(|&m| !filter.admit(textured(m))));
    }

    #[test]
    fn flat_gray_frames_are_not_admitted_even_when_bright_enough() {
        let mut filter = LitFrameFilter::default();
        let flat = FrameStats { mean: 25.0, std_dev: 0.5 };
        assert!(!flat.is_illuminated());
        assert!((0..10).all(|_| !filter.admit(flat)));
        assert!(filter.admit(textured(60.0)));
    }
}
