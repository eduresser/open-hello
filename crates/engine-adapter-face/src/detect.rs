use crate::{EngineError, GrayImage};

const STRIDES: [u32; 3] = [8, 16, 32];
const SCORE_THRESHOLD: f32 = 0.6;
const NMS_IOU_THRESHOLD: f32 = 0.3;

#[derive(Debug, Clone, PartialEq)]
pub struct Detection {
    pub x: f32,
    pub y: f32,
    pub width: f32,
    pub height: f32,
    pub score: f32,
    pub landmarks: [(f32, f32); 5],
}

impl Detection {
    fn iou(&self, other: &Detection) -> f32 {
        let left = self.x.max(other.x);
        let top = self.y.max(other.y);
        let right = (self.x + self.width).min(other.x + other.width);
        let bottom = (self.y + self.height).min(other.y + other.height);
        let intersection = (right - left).max(0.0) * (bottom - top).max(0.0);
        let union = self.width * self.height + other.width * other.height - intersection;
        if union <= 0.0 {
            0.0
        } else {
            intersection / union
        }
    }
}

pub struct StrideOutput<'a> {
    pub cls: &'a [f32],
    pub obj: &'a [f32],
    pub bbox: &'a [f32],
    pub kps: &'a [f32],
}

pub trait FaceDetector {
    fn detect(&self, image: &GrayImage) -> Result<Vec<Detection>, EngineError>;
}

pub const DETECTOR_INPUT_SIZE: u32 = 640;

pub fn letterbox_scale(image: &GrayImage) -> f32 {
    (DETECTOR_INPUT_SIZE as f32 / image.width as f32).min(DETECTOR_INPUT_SIZE as f32 / image.height as f32)
}

pub fn letterbox(image: &GrayImage) -> Vec<f32> {
    let scale = letterbox_scale(image);
    let side = DETECTOR_INPUT_SIZE as usize;
    let (fit_w, fit_h) = ((image.width as f32 * scale) as usize, (image.height as f32 * scale) as usize);
    let mut resized = GrayImage { width: DETECTOR_INPUT_SIZE, height: DETECTOR_INPUT_SIZE, pixels: vec![0; side * side] };
    for y in 0..fit_h.min(side) {
        for x in 0..fit_w.min(side) {
            let value = image.sample((x as f32 + 0.5) / scale - 0.5, (y as f32 + 0.5) / scale - 0.5);
            resized.pixels[y * side + x] = value.round().clamp(0.0, 255.0) as u8;
        }
    }
    to_chw_bgr(&resized, DETECTOR_INPUT_SIZE, DETECTOR_INPUT_SIZE)
}

pub fn unscale(detections: Vec<Detection>, scale: f32) -> Vec<Detection> {
    detections
        .into_iter()
        .map(|d| Detection {
            x: d.x / scale,
            y: d.y / scale,
            width: d.width / scale,
            height: d.height / scale,
            score: d.score,
            landmarks: d.landmarks.map(|(x, y)| (x / scale, y / scale)),
        })
        .collect()
}

pub fn decode_yunet(
    outputs: &[StrideOutput; 3],
    input_width: u32,
    input_height: u32,
) -> Result<Vec<Detection>, EngineError> {
    let mut candidates = Vec::new();
    for (stride, out) in STRIDES.iter().zip(outputs) {
        let cols = input_width / stride;
        let rows = input_height / stride;
        let cells = (cols * rows) as usize;
        if out.cls.len() != cells || out.obj.len() != cells || out.bbox.len() != cells * 4 || out.kps.len() != cells * 10 {
            return Err(EngineError::Model(format!("YuNet stride {stride} output shape mismatch for {cells} cells")));
        }
        let stride = *stride as f32;
        for idx in 0..cells {
            let score = (out.cls[idx].clamp(0.0, 1.0) * out.obj[idx].clamp(0.0, 1.0)).sqrt();
            if score < SCORE_THRESHOLD {
                continue;
            }
            let (row, col) = ((idx / cols as usize) as f32, (idx % cols as usize) as f32);
            let b = &out.bbox[idx * 4..idx * 4 + 4];
            let (cx, cy) = ((col + b[0]) * stride, (row + b[1]) * stride);
            let (w, h) = (b[2].exp() * stride, b[3].exp() * stride);
            let mut landmarks = [(0.0, 0.0); 5];
            for (n, point) in landmarks.iter_mut().enumerate() {
                let k = &out.kps[idx * 10 + n * 2..idx * 10 + n * 2 + 2];
                *point = ((k[0] + col) * stride, (k[1] + row) * stride);
            }
            candidates.push(Detection { x: cx - w / 2.0, y: cy - h / 2.0, width: w, height: h, score, landmarks });
        }
    }
    Ok(non_max_suppression(candidates))
}

fn non_max_suppression(mut candidates: Vec<Detection>) -> Vec<Detection> {
    candidates.sort_by(|a, b| b.score.total_cmp(&a.score));
    let mut kept: Vec<Detection> = Vec::new();
    for candidate in candidates {
        if kept.iter().all(|k| k.iou(&candidate) < NMS_IOU_THRESHOLD) {
            kept.push(candidate);
        }
    }
    kept
}

pub fn best_face(detections: Vec<Detection>) -> Result<Detection, EngineError> {
    detections
        .into_iter()
        .max_by(|a, b| a.score.total_cmp(&b.score))
        .ok_or(EngineError::NoFace)
}

pub fn to_chw_bgr(image: &GrayImage, width: u32, height: u32) -> Vec<f32> {
    let plane = (width * height) as usize;
    let mut out = vec![0.0; plane * 3];
    for y in 0..height as usize {
        for x in 0..width as usize {
            let v = if (x as u32) < image.width && (y as u32) < image.height {
                image.pixels[y * image.width as usize + x] as f32
            } else {
                0.0
            };
            for channel in 0..3 {
                out[channel * plane + y * width as usize + x] = v;
            }
        }
    }
    out
}

#[cfg(feature = "ort-backend")]
pub mod ort_backend {
    use std::path::Path;
    use std::sync::Mutex;

    use ort::session::Session;
    use ort::value::Tensor;

    use crate::ort_environment;

    use super::*;

    pub struct YunetDetector {
        session: Mutex<Session>,
    }

    impl YunetDetector {
        pub fn load(model_path: &Path) -> Result<Self, EngineError> {
            let session = ort_environment().and_then(|env| Session::builder(env).map_err(|e| EngineError::Model(e.to_string())))
                .and_then(|mut b| b.commit_from_file(model_path).map_err(|e| EngineError::Model(e.to_string())))
                .map_err(|e| EngineError::Model(format!("load {}: {e}", model_path.display())))?;
            Ok(Self { session: Mutex::new(session) })
        }
    }

    impl FaceDetector for YunetDetector {
        fn detect(&self, image: &GrayImage) -> Result<Vec<Detection>, EngineError> {
            let side = DETECTOR_INPUT_SIZE as usize;
            let input = Tensor::from_array(([1usize, 3, side, side], letterbox(image)))
                .map_err(|e| EngineError::Model(e.to_string()))?;
            let mut session = self.session.lock().map_err(|_| EngineError::Model("session lock poisoned".into()))?;
            let outputs = session
                .run(ort::inputs!["input" => input])
                .map_err(|e| EngineError::Model(e.to_string()))?;
            let fetch = |name: String| -> Result<Vec<f32>, EngineError> {
                let (_, data) = outputs[name.as_str()]
                    .try_extract_tensor::<f32>()
                    .map_err(|e| EngineError::Model(format!("{name}: {e}")))?;
                Ok(data.to_vec())
            };
            let mut buffers = Vec::new();
            for stride in STRIDES {
                buffers.push([
                    fetch(format!("cls_{stride}"))?,
                    fetch(format!("obj_{stride}"))?,
                    fetch(format!("bbox_{stride}"))?,
                    fetch(format!("kps_{stride}"))?,
                ]);
            }
            let view = |i: usize| StrideOutput {
                cls: &buffers[i][0],
                obj: &buffers[i][1],
                bbox: &buffers[i][2],
                kps: &buffers[i][3],
            };
            let found = decode_yunet(&[view(0), view(1), view(2)], DETECTOR_INPUT_SIZE, DETECTOR_INPUT_SIZE)?;
            Ok(unscale(found, letterbox_scale(image)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Planes {
        cls: Vec<f32>,
        obj: Vec<f32>,
        bbox: Vec<f32>,
        kps: Vec<f32>,
    }

    fn planes(cells: usize) -> Planes {
        Planes { cls: vec![0.0; cells], obj: vec![0.0; cells], bbox: vec![0.0; cells * 4], kps: vec![0.0; cells * 10] }
    }

    fn view(p: &Planes) -> StrideOutput<'_> {
        StrideOutput { cls: &p.cls, obj: &p.obj, bbox: &p.bbox, kps: &p.kps }
    }

    #[test]
    fn decodes_a_single_cell_into_box_and_landmarks() {
        let (w, h) = (64, 64);
        let mut s8 = planes(64);
        let (s16, s32) = (planes(16), planes(4));
        let idx = 2 * 8 + 3;
        s8.cls[idx] = 0.81;
        s8.obj[idx] = 1.0;
        s8.bbox[idx * 4..idx * 4 + 4].copy_from_slice(&[0.5, 0.5, 1.0, 1.0]);
        s8.kps[idx * 10..idx * 10 + 2].copy_from_slice(&[0.25, 0.75]);
        let found = decode_yunet(&[view(&s8), view(&s16), view(&s32)], w, h).unwrap();
        assert_eq!(found.len(), 1);
        let d = &found[0];
        assert!((d.score - 0.9).abs() < 1e-5);
        let size = std::f32::consts::E * 8.0;
        assert!((d.width - size).abs() < 1e-3);
        assert!((d.x + d.width / 2.0 - 28.0).abs() < 1e-3);
        assert!((d.y + d.height / 2.0 - 20.0).abs() < 1e-3);
        assert_eq!(d.landmarks[0], ((0.25 + 3.0) * 8.0, (0.75 + 2.0) * 8.0));
    }

    #[test]
    fn rejects_low_confidence_cells() {
        let mut s8 = planes(64);
        s8.cls[0] = 0.5;
        s8.obj[0] = 0.5;
        let found = decode_yunet(&[view(&s8), view(&planes(16)), view(&planes(4))], 64, 64).unwrap();
        assert!(found.is_empty());
    }

    #[test]
    fn nms_keeps_best_of_overlapping_boxes() {
        let mut s8 = planes(64);
        for (idx, score) in [(10usize, 0.95_f32), (11, 0.8)] {
            s8.cls[idx] = score;
            s8.obj[idx] = score;
            s8.bbox[idx * 4 + 2] = 2.0;
            s8.bbox[idx * 4 + 3] = 2.0;
        }
        let found = decode_yunet(&[view(&s8), view(&planes(16)), view(&planes(4))], 64, 64).unwrap();
        assert_eq!(found.len(), 1);
        assert!((found[0].score - 0.95).abs() < 1e-6);
    }

    #[test]
    fn shape_mismatch_is_a_model_error() {
        let result = decode_yunet(&[view(&planes(3)), view(&planes(16)), view(&planes(4))], 64, 64);
        assert!(matches!(result, Err(EngineError::Model(_))));
    }

    #[test]
    fn best_face_errors_when_empty() {
        assert!(matches!(best_face(vec![]), Err(EngineError::NoFace)));
    }

    #[test]
    fn grayscale_is_replicated_across_three_channels_with_padding() {
        let image = GrayImage::new(2, 1, vec![10, 20]).unwrap();
        let chw = to_chw_bgr(&image, 3, 2);
        assert_eq!(chw.len(), 18);
        assert_eq!(&chw[0..3], &[10.0, 20.0, 0.0]);
        assert_eq!(&chw[6..9], &chw[12..15]);
    }

    #[test]
    fn letterbox_fits_the_long_side_and_unscale_restores_coordinates() {
        let wide = GrayImage::new(1280, 320, vec![200; 1280 * 320]).unwrap();
        assert_eq!(letterbox_scale(&wide), 0.5);
        let input = letterbox(&wide);
        let side = DETECTOR_INPUT_SIZE as usize;
        assert_eq!(input.len(), 3 * side * side);
        assert_eq!(input[10 * side + 10], 200.0);
        assert_eq!(input[300 * side + 10], 0.0);

        let found = Detection { x: 100.0, y: 50.0, width: 40.0, height: 60.0, score: 0.9, landmarks: [(110.0, 60.0); 5] };
        let restored = unscale(vec![found], 0.5);
        assert_eq!((restored[0].x, restored[0].width, restored[0].landmarks[0]), (200.0, 80.0, (220.0, 120.0)));
    }
}
