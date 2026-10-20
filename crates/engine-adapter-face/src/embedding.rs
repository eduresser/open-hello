use crate::detect::Detection;
use crate::{EngineError, GrayImage};

pub const ALIGNED_SIZE: u32 = 112;
pub const EMBEDDING_DIM: usize = 512;

const ARCFACE_TEMPLATE: [(f32, f32); 5] = [
    (38.2946, 51.6963),
    (73.5318, 51.5014),
    (56.0252, 71.7366),
    (41.5493, 92.3655),
    (70.7299, 92.2041),
];

pub trait FaceEmbedder {
    fn embed(&self, aligned: &GrayImage) -> Result<Vec<f32>, EngineError>;
}

#[derive(Debug, Clone, Copy)]
struct Similarity {
    scale_cos: f32,
    scale_sin: f32,
    tx: f32,
    ty: f32,
}

impl Similarity {
    fn apply(&self, (x, y): (f32, f32)) -> (f32, f32) {
        (self.scale_cos * x - self.scale_sin * y + self.tx, self.scale_sin * x + self.scale_cos * y + self.ty)
    }

    fn inverse(&self) -> Similarity {
        let det = self.scale_cos * self.scale_cos + self.scale_sin * self.scale_sin;
        let (a, b) = (self.scale_cos / det, -self.scale_sin / det);
        Similarity {
            scale_cos: a,
            scale_sin: b,
            tx: -(a * self.tx - b * self.ty),
            ty: -(b * self.tx + a * self.ty),
        }
    }
}

fn estimate_similarity(from: &[(f32, f32); 5], to: &[(f32, f32); 5]) -> Similarity {
    let n = from.len() as f32;
    let centroid = |pts: &[(f32, f32); 5]| (pts.iter().map(|p| p.0).sum::<f32>() / n, pts.iter().map(|p| p.1).sum::<f32>() / n);
    let (fc, tc) = (centroid(from), centroid(to));
    let (mut num_cos, mut num_sin, mut denom) = (0.0, 0.0, 0.0);
    for (f, t) in from.iter().zip(to) {
        let (fx, fy) = (f.0 - fc.0, f.1 - fc.1);
        let (tx, ty) = (t.0 - tc.0, t.1 - tc.1);
        num_cos += fx * tx + fy * ty;
        num_sin += fx * ty - fy * tx;
        denom += fx * fx + fy * fy;
    }
    let (a, b) = (num_cos / denom, num_sin / denom);
    Similarity { scale_cos: a, scale_sin: b, tx: tc.0 - (a * fc.0 - b * fc.1), ty: tc.1 - (b * fc.0 + a * fc.1) }
}

pub fn align_face(image: &GrayImage, detection: &Detection) -> Result<GrayImage, EngineError> {
    let forward = estimate_similarity(&detection.landmarks, &ARCFACE_TEMPLATE);
    if !forward.scale_cos.is_finite() || !forward.scale_sin.is_finite() {
        return Err(EngineError::InvalidInput("degenerate landmarks".into()));
    }
    let inverse = forward.inverse();
    let mut pixels = Vec::with_capacity((ALIGNED_SIZE * ALIGNED_SIZE) as usize);
    for y in 0..ALIGNED_SIZE {
        for x in 0..ALIGNED_SIZE {
            let (sx, sy) = inverse.apply((x as f32, y as f32));
            pixels.push(image.sample(sx, sy).round().clamp(0.0, 255.0) as u8);
        }
    }
    GrayImage::new(ALIGNED_SIZE, ALIGNED_SIZE, pixels)
}

pub fn to_model_input(aligned: &GrayImage) -> Vec<f32> {
    let plane = aligned.pixels.len();
    let mut out = Vec::with_capacity(plane * 3);
    for _ in 0..3 {
        out.extend(aligned.pixels.iter().map(|&p| (p as f32 - 127.5) / 127.5));
    }
    out
}

pub fn l2_normalize(mut embedding: Vec<f32>) -> Result<Vec<f32>, EngineError> {
    let norm = embedding.iter().map(|v| v * v).sum::<f32>().sqrt();
    if !norm.is_finite() || norm < 1e-12 {
        return Err(EngineError::Model("embedding has zero norm".into()));
    }
    embedding.iter_mut().for_each(|v| *v /= norm);
    Ok(embedding)
}

pub fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    a.iter().zip(b).map(|(x, y)| x * y).sum()
}

pub fn embed_detected(
    embedder: &dyn FaceEmbedder,
    image: &GrayImage,
    detection: &Detection,
) -> Result<Vec<f32>, EngineError> {
    let aligned = align_face(image, detection)?;
    l2_normalize(embedder.embed(&aligned)?)
}

#[cfg(feature = "ort-backend")]
pub mod ort_backend {
    use std::path::Path;
    use std::sync::Mutex;

    use ort::session::Session;
    use ort::value::Tensor;

    use crate::ort_environment;

    use super::*;

    pub struct AuraFaceEmbedder {
        session: Mutex<Session>,
    }

    impl AuraFaceEmbedder {
        pub fn load(model_path: &Path) -> Result<Self, EngineError> {
            let session = ort_environment().and_then(|env| Session::builder(env).map_err(|e| EngineError::Model(e.to_string())))
                .and_then(|mut b| b.commit_from_file(model_path).map_err(|e| EngineError::Model(e.to_string())))
                .map_err(|e| EngineError::Model(format!("load {}: {e}", model_path.display())))?;
            Ok(Self { session: Mutex::new(session) })
        }
    }

    impl FaceEmbedder for AuraFaceEmbedder {
        fn embed(&self, aligned: &GrayImage) -> Result<Vec<f32>, EngineError> {
            let side = ALIGNED_SIZE as usize;
            let input = Tensor::from_array(([1usize, 3, side, side], to_model_input(aligned)))
                .map_err(|e| EngineError::Model(e.to_string()))?;
            let mut session = self.session.lock().map_err(|_| EngineError::Model("session lock poisoned".into()))?;
            let outputs = session.run(ort::inputs![input]).map_err(|e| EngineError::Model(e.to_string()))?;
            let (_, data) = outputs[0]
                .try_extract_tensor::<f32>()
                .map_err(|e| EngineError::Model(e.to_string()))?;
            if data.len() != EMBEDDING_DIM {
                return Err(EngineError::Model(format!("expected {EMBEDDING_DIM}-d embedding, got {}", data.len())));
            }
            Ok(data.to_vec())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detection_with(landmarks: [(f32, f32); 5]) -> Detection {
        Detection { x: 0.0, y: 0.0, width: 10.0, height: 10.0, score: 1.0, landmarks }
    }

    #[test]
    fn similarity_maps_landmarks_onto_template() {
        let shifted = ARCFACE_TEMPLATE.map(|(x, y)| (x * 2.0 + 30.0, y * 2.0 + 10.0));
        let sim = estimate_similarity(&shifted, &ARCFACE_TEMPLATE);
        for (src, dst) in shifted.iter().zip(&ARCFACE_TEMPLATE) {
            let mapped = sim.apply(*src);
            assert!((mapped.0 - dst.0).abs() < 1e-3 && (mapped.1 - dst.1).abs() < 1e-3);
        }
    }

    #[test]
    fn inverse_round_trips_a_point() {
        let sim = Similarity { scale_cos: 0.8, scale_sin: 0.3, tx: 5.0, ty: -7.0 };
        let back = sim.inverse().apply(sim.apply((12.0, 34.0)));
        assert!((back.0 - 12.0).abs() < 1e-3 && (back.1 - 34.0).abs() < 1e-3);
    }

    #[test]
    fn aligning_a_template_shaped_face_reproduces_the_source_pixels() {
        let (w, h) = (112u32, 112u32);
        let pixels: Vec<u8> = (0..w * h).map(|i| ((i % w) * 2) as u8).collect();
        let image = GrayImage::new(w, h, pixels.clone()).unwrap();
        let aligned = align_face(&image, &detection_with(ARCFACE_TEMPLATE)).unwrap();
        let diff = aligned.pixels.iter().zip(&pixels).map(|(a, b)| a.abs_diff(*b) as u32).max().unwrap();
        assert!(diff <= 1);
    }

    #[test]
    fn degenerate_landmarks_are_rejected() {
        let image = GrayImage::new(4, 4, vec![0; 16]).unwrap();
        let result = align_face(&image, &detection_with([(1.0, 1.0); 5]));
        assert!(matches!(result, Err(EngineError::InvalidInput(_))));
    }

    #[test]
    fn model_input_is_normalised_and_triplicated() {
        let aligned = GrayImage::new(2, 1, vec![0, 255]).unwrap();
        let input = to_model_input(&aligned);
        assert_eq!(input.len(), 6);
        assert_eq!(input[0], -1.0);
        assert_eq!(input[1], 1.0);
        assert_eq!(input[0..2], input[4..6]);
    }

    #[test]
    fn l2_normalize_yields_unit_vector_and_rejects_zero() {
        let unit = l2_normalize(vec![3.0, 4.0]).unwrap();
        assert!((unit[0] - 0.6).abs() < 1e-6 && (unit[1] - 0.8).abs() < 1e-6);
        assert!(l2_normalize(vec![0.0, 0.0]).is_err());
    }

    #[test]
    fn cosine_of_identical_unit_vectors_is_one() {
        let v = l2_normalize(vec![1.0, 2.0, 3.0]).unwrap();
        assert!((cosine_similarity(&v, &v) - 1.0).abs() < 1e-6);
    }
}
