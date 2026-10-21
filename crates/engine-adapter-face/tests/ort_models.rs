use std::path::PathBuf;

use engine_adapter_face::detect::ort_backend::YunetDetector;
use engine_adapter_face::detect::FaceDetector;
use engine_adapter_face::embedding::ort_backend::AuraFaceEmbedder;
use engine_adapter_face::embedding::{FaceEmbedder, EMBEDDING_DIM};
use engine_adapter_face::GrayImage;

fn models_dir() -> PathBuf {
    PathBuf::from(std::env::var("OPENHELLO_MODELS_DIR").expect("set OPENHELLO_MODELS_DIR and ORT_DYLIB_PATH to run this test"))
}

#[test]
#[ignore = "needs the downloaded models and libonnxruntime (see scripts/install.sh)"]
fn real_models_load_and_produce_correctly_shaped_outputs() {
    let detector = YunetDetector::load(&models_dir().join("yunet.onnx")).unwrap();
    let blank = GrayImage::new(320, 240, vec![90; 320 * 240]).unwrap();
    assert!(detector.detect(&blank).unwrap().is_empty());

    let embedder = AuraFaceEmbedder::load(&models_dir().join("glintr100.onnx")).unwrap();
    let pixels = (0..112 * 112).map(|i| ((i * 7) % 251) as u8).collect();
    let embedding = embedder.embed(&GrayImage::new(112, 112, pixels).unwrap()).unwrap();
    assert_eq!(embedding.len(), EMBEDDING_DIM);
    assert!(embedding.iter().all(|v| v.is_finite()));
}
