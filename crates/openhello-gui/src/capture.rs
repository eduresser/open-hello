use openhello_gui_core::{CaptureUpdate, Frame, Strings};
use slint::{Rgb8Pixel, SharedPixelBuffer};

pub struct CaptureView {
    pub guidance: &'static str,
    pub accepted: bool,
    pub progress_text: String,
    pub progress: f32,
    pub frame: Option<SharedPixelBuffer<Rgb8Pixel>>,
}

impl CaptureView {
    pub fn new(update: CaptureUpdate, strings: &Strings) -> Self {
        Self {
            guidance: update.guidance,
            accepted: update.guidance == strings.guidance("accepted"),
            progress_text: update.progress_text,
            progress: progress_fraction(update.filled, update.required),
            frame: update.frame.as_ref().and_then(to_buffer),
        }
    }
}

pub fn progress_fraction(filled: u32, required: u32) -> f32 {
    if required == 0 {
        return 0.0;
    }
    (filled as f32 / required as f32).clamp(0.0, 1.0)
}

pub fn to_buffer(frame: &Frame) -> Option<SharedPixelBuffer<Rgb8Pixel>> {
    let expected = (frame.width as usize).checked_mul(frame.height as usize)?;
    if expected == 0 || frame.pixels.len() != expected {
        return None;
    }
    let mut buffer = SharedPixelBuffer::<Rgb8Pixel>::new(frame.width, frame.height);
    for (target, gray) in buffer.make_mut_slice().iter_mut().zip(&frame.pixels) {
        *target = Rgb8Pixel { r: *gray, g: *gray, b: *gray };
    }
    Some(buffer)
}

#[cfg(test)]
mod tests {
    use openhello_gui_core::Language;

    use super::*;

    fn update(verdict: &str, filled: u32, frame: Option<Frame>) -> CaptureUpdate {
        let strings = Strings::new(Language::English);
        CaptureUpdate { guidance: strings.guidance(verdict), progress_text: strings.progress(filled, 6), filled, required: 6, frame }
    }

    // @spec:AC-059
    #[test]
    fn a_gray_frame_becomes_an_rgb_buffer_with_the_same_size_and_levels() {
        let frame = Frame { width: 3, height: 2, pixels: vec![0, 10, 20, 30, 40, 255] };
        let buffer = to_buffer(&frame).expect("a well-formed frame converts");
        assert_eq!((buffer.width(), buffer.height()), (3, 2));
        let levels: Vec<u8> = buffer.as_slice().iter().map(|pixel| pixel.g).collect();
        assert_eq!(levels, vec![0, 10, 20, 30, 40, 255]);
        assert!(buffer.as_slice().iter().all(|pixel| pixel.r == pixel.g && pixel.g == pixel.b));
    }

    // @spec:AC-059
    #[test]
    fn a_frame_whose_pixel_count_does_not_match_its_size_is_dropped() {
        assert!(to_buffer(&Frame { width: 4, height: 4, pixels: vec![0; 15] }).is_none());
        assert!(to_buffer(&Frame { width: 0, height: 0, pixels: Vec::new() }).is_none());
    }

    // @spec:AC-059
    #[test]
    fn progress_is_filled_over_required_and_clamped() {
        assert_eq!(progress_fraction(0, 6), 0.0);
        assert_eq!(progress_fraction(3, 6), 0.5);
        assert_eq!(progress_fraction(6, 6), 1.0);
        assert_eq!(progress_fraction(9, 6), 1.0);
        assert_eq!(progress_fraction(2, 0), 0.0);
    }

    // @spec:AC-059
    #[test]
    fn the_view_carries_the_sentence_the_n_of_6_text_and_the_accepted_state() {
        let strings = Strings::new(Language::English);
        let accepted = CaptureView::new(update("accepted", 2, None), &strings);
        assert_eq!(accepted.guidance, "Hold still and look at the camera");
        assert_eq!(accepted.progress_text, "2 of 6");
        assert!(accepted.accepted && accepted.frame.is_none());
        let moving = CaptureView::new(update("move-left", 2, Some(Frame { width: 2, height: 1, pixels: vec![1, 2] })), &strings);
        assert_eq!(moving.guidance, "Move a little to your left");
        assert!(!moving.accepted && moving.frame.is_some());
    }
}
