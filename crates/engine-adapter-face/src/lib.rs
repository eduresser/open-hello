pub mod detect;
pub mod embedding;
pub mod engine;
pub mod enrollment_quality;
pub mod far_calibration;
pub mod liveness;
pub mod ffi;
pub mod matching;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum EngineError {
    #[error("model error: {0}")]
    Model(String),
    #[error("no face detected in frame")]
    NoFace,
    #[error("invalid input: {0}")]
    InvalidInput(String),
}

#[derive(Debug, Clone)]
pub struct GrayImage {
    pub width: u32,
    pub height: u32,
    pub pixels: Vec<u8>,
}

impl GrayImage {
    pub fn new(width: u32, height: u32, pixels: Vec<u8>) -> Result<Self, EngineError> {
        if pixels.len() != (width as usize) * (height as usize) {
            return Err(EngineError::InvalidInput(format!(
                "{width}x{height} image needs {} bytes, got {}",
                width as usize * height as usize,
                pixels.len()
            )));
        }
        Ok(Self { width, height, pixels })
    }

    pub fn at(&self, x: i64, y: i64) -> f32 {
        let x = x.clamp(0, self.width as i64 - 1) as usize;
        let y = y.clamp(0, self.height as i64 - 1) as usize;
        self.pixels[y * self.width as usize + x] as f32
    }

    pub fn sample(&self, x: f32, y: f32) -> f32 {
        let (x0, y0) = (x.floor(), y.floor());
        let (fx, fy) = (x - x0, y - y0);
        let (x0, y0) = (x0 as i64, y0 as i64);
        let top = self.at(x0, y0) * (1.0 - fx) + self.at(x0 + 1, y0) * fx;
        let bottom = self.at(x0, y0 + 1) * (1.0 - fx) + self.at(x0 + 1, y0 + 1) * fx;
        top * (1.0 - fy) + bottom * fy
    }
}

#[cfg(feature = "ort-backend")]
pub(crate) fn ort_environment() -> Result<&'static ort::environment::Environment, EngineError> {
    use std::sync::OnceLock;

    static ENVIRONMENT: OnceLock<Result<ort::environment::Environment, String>> = OnceLock::new();
    ENVIRONMENT
        .get_or_init(|| {
            ort::environment::init()
                .with_name("openhello")
                .build()
                .map_err(|e| e.to_string())
        })
        .as_ref()
        .map_err(|e| EngineError::Model(format!("onnxruntime init: {e}")))
}
