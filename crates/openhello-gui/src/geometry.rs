use std::f64::consts::PI;

const OVAL_HEIGHT_SHARE: f64 = 0.55;
const OVAL_ASPECT: f64 = 0.78;
const OVAL_MAX_WIDTH_SHARE: f64 = 0.9;
const RING_MARGIN: f64 = 1.07;
const SEGMENT_GAP: f64 = 0.12;
const MAX_SEGMENTS: u32 = 24;
const EASE_RATE: f64 = 10.0;
const EASE_SNAP: f64 = 0.001;
const PREVIEW_WIDTH: i32 = 480;
const PREVIEW_MIN_HEIGHT: i32 = 240;
const PREVIEW_MAX_HEIGHT: i32 = 600;
const PREVIEW_FALLBACK_HEIGHT: i32 = 360;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Oval {
    pub cx: f64,
    pub cy: f64,
    pub rx: f64,
    pub ry: f64,
}

impl Oval {
    pub fn grown(self, factor: f64) -> Oval {
        Oval { rx: self.rx * factor, ry: self.ry * factor, ..self }
    }
}

pub fn guide_oval(width: f64, height: f64) -> Oval {
    let ry = height * OVAL_HEIGHT_SHARE / 2.0;
    let rx = (ry * OVAL_ASPECT).min(width * OVAL_MAX_WIDTH_SHARE / 2.0);
    Oval { cx: width / 2.0, cy: height / 2.0, rx, ry }
}

pub fn ring_oval(width: f64, height: f64) -> Oval {
    guide_oval(width, height).grown(RING_MARGIN)
}

pub fn fraction(filled: u32, required: u32) -> f64 {
    if required == 0 {
        return 0.0;
    }
    (f64::from(filled) / f64::from(required)).clamp(0.0, 1.0)
}

pub fn segments(required: u32) -> Vec<(f64, f64)> {
    let count = required.min(MAX_SEGMENTS);
    if count == 0 {
        return Vec::new();
    }
    let span = 2.0 * PI / f64::from(count);
    let gap = span * SEGMENT_GAP;
    (0..count)
        .map(|index| {
            let start = -PI / 2.0 + span * f64::from(index);
            (start + gap / 2.0, start + span - gap / 2.0)
        })
        .collect()
}

pub fn segment_fill(progress: f64, required: u32, index: u32) -> f64 {
    (progress.clamp(0.0, 1.0) * f64::from(required.min(MAX_SEGMENTS)) - f64::from(index)).clamp(0.0, 1.0)
}

pub fn ease_toward(current: f64, target: f64, seconds: f64) -> f64 {
    if (target - current).abs() < EASE_SNAP {
        return target;
    }
    current + (target - current) * (1.0 - (-seconds.max(0.0) * EASE_RATE).exp())
}

pub fn mirrored_rgba(width: u32, height: u32, gray: &[u8]) -> Option<Vec<u8>> {
    let (columns, rows) = (width as usize, height as usize);
    if columns == 0 || rows == 0 || gray.len() != columns.checked_mul(rows)? {
        return None;
    }
    let mut rgba = Vec::with_capacity(gray.len() * 4);
    for row in gray.chunks_exact(columns) {
        rgba.extend(row.iter().rev().flat_map(|&value| [value, value, value, u8::MAX]));
    }
    Some(rgba)
}

pub fn preview_size(frame_width: u32, frame_height: u32) -> (i32, i32) {
    if frame_width == 0 || frame_height == 0 {
        return (PREVIEW_WIDTH, PREVIEW_FALLBACK_HEIGHT);
    }
    let height = f64::from(PREVIEW_WIDTH) * f64::from(frame_height) / f64::from(frame_width);
    (PREVIEW_WIDTH, (height.round() as i32).clamp(PREVIEW_MIN_HEIGHT, PREVIEW_MAX_HEIGHT))
}

#[cfg(test)]
mod tests {
    use super::*;

    // @spec:AC-059
    #[test]
    fn the_guide_oval_is_centered_and_takes_about_55_percent_of_the_height() {
        let oval = guide_oval(480.0, 360.0);
        assert_eq!((oval.cx, oval.cy), (240.0, 180.0));
        assert!((oval.ry * 2.0 / 360.0 - 0.55).abs() < 1e-9);
        assert!(oval.rx < oval.ry);
    }

    // @spec:AC-059
    #[test]
    fn the_guide_oval_never_overflows_a_narrow_window() {
        let oval = guide_oval(100.0, 600.0);
        assert!(oval.rx * 2.0 <= 100.0);
    }

    // @spec:AC-059
    #[test]
    fn the_progress_ring_sits_just_outside_the_guide() {
        let (guide, ring) = (guide_oval(480.0, 360.0), ring_oval(480.0, 360.0));
        assert!(ring.rx > guide.rx && ring.ry > guide.ry);
        assert_eq!((ring.cx, ring.cy), (guide.cx, guide.cy));
    }

    // @spec:AC-059
    #[test]
    fn progress_is_filled_over_required_and_clamped() {
        assert_eq!(fraction(0, 6), 0.0);
        assert_eq!(fraction(3, 6), 0.5);
        assert_eq!(fraction(9, 6), 1.0);
        assert_eq!(fraction(2, 0), 0.0);
    }

    // @spec:AC-059
    #[test]
    fn six_required_samples_make_six_separate_arcs_that_start_at_the_top() {
        let arcs = segments(6);
        assert_eq!(arcs.len(), 6);
        assert!(arcs[0].0 > -PI / 2.0 && arcs[0].0 < -PI / 2.0 + 0.2);
        assert!(arcs.windows(2).all(|pair| pair[0].1 < pair[1].0));
        assert!(arcs[5].1 < 3.0 * PI / 2.0);
        assert!(segments(0).is_empty());
    }

    // @spec:AC-059
    #[test]
    fn each_arc_fills_only_after_the_previous_ones() {
        let fills: Vec<f64> = (0..6).map(|index| segment_fill(0.5, 6, index)).collect();
        assert_eq!(fills, vec![1.0, 1.0, 1.0, 0.0, 0.0, 0.0]);
        assert_eq!(segment_fill(0.25, 6, 1), 0.5);
        assert_eq!(segment_fill(1.0, 6, 5), 1.0);
    }

    // @spec:AC-059
    #[test]
    fn the_ring_animation_approaches_the_target_without_overshooting_and_then_snaps() {
        let step = ease_toward(0.0, 1.0, 0.016);
        assert!(step > 0.0 && step < 1.0);
        assert!(ease_toward(step, 1.0, 0.016) > step);
        assert_eq!(ease_toward(0.9995, 1.0, 0.016), 1.0);
        assert_eq!(ease_toward(0.3, 0.3, 0.016), 0.3);
        assert!(ease_toward(1.0, 0.0, 10.0) < 0.001);
    }

    // @spec:AC-059
    #[test]
    fn the_preview_is_mirrored_horizontally_and_expanded_to_opaque_rgba() {
        let rgba = mirrored_rgba(3, 2, &[1, 2, 3, 4, 5, 6]).expect("valid frame");
        let channel = |offset: usize| -> Vec<u8> { rgba.iter().skip(offset).step_by(4).copied().collect() };
        assert_eq!(channel(0), vec![3, 2, 1, 6, 5, 4]);
        assert_eq!(channel(1), channel(0));
        assert_eq!(channel(2), channel(0));
        assert_eq!(channel(3), vec![255; 6]);
    }

    // @spec:AC-059
    #[test]
    fn a_frame_whose_length_does_not_match_its_size_is_refused() {
        assert!(mirrored_rgba(3, 2, &[0; 5]).is_none());
        assert!(mirrored_rgba(0, 2, &[]).is_none());
        assert!(mirrored_rgba(2, 0, &[]).is_none());
    }

    // @spec:AC-059
    #[test]
    fn the_preview_keeps_the_frame_aspect_within_sane_bounds() {
        assert_eq!(preview_size(640, 360), (480, 270));
        assert_eq!(preview_size(640, 480), (480, 360));
        assert_eq!(preview_size(100, 1000).1, 600);
        assert_eq!(preview_size(1000, 10).1, 240);
        assert_eq!(preview_size(0, 0), (480, 360));
    }
}
