use std::path::{Path, PathBuf};

use crate::detect::{best_face, FaceDetector};
use crate::embedding::{cosine_similarity, embed_detected, FaceEmbedder};
use crate::far_calibration::FarCalibration;
use crate::{EngineError, GrayImage};

const IMAGE_EXTENSIONS: [&str; 4] = ["jpg", "jpeg", "png", "pgm"];

pub fn identity_directories(root: &Path) -> Result<Vec<PathBuf>, EngineError> {
    let mut directories: Vec<PathBuf> = std::fs::read_dir(root)
        .map_err(|e| EngineError::InvalidInput(format!("{}: {e}", root.display())))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect();
    directories.sort();
    Ok(directories)
}

pub fn first_image(directory: &Path) -> Option<PathBuf> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(directory)
        .ok()?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|e| e.to_str()).is_some_and(|e| IMAGE_EXTENSIONS.contains(&e.to_lowercase().as_str())))
        .collect();
    files.sort();
    files.into_iter().next()
}

pub fn impostor_scores(embeddings: &[Vec<f32>]) -> Vec<f32> {
    let mut scores = Vec::with_capacity(embeddings.len() * embeddings.len().saturating_sub(1) / 2);
    for (i, a) in embeddings.iter().enumerate() {
        for b in &embeddings[i + 1..] {
            scores.push(cosine_similarity(a, b));
        }
    }
    scores
}

pub fn calibrate_from_identities(
    detector: &dyn FaceDetector,
    embedder: &dyn FaceEmbedder,
    images: impl Iterator<Item = GrayImage>,
) -> Result<(FarCalibration, usize), EngineError> {
    let mut embeddings = Vec::new();
    for image in images {
        if let Ok(face) = best_face(detector.detect(&image)?) {
            embeddings.push(embed_detected(embedder, &image, &face)?);
        }
    }
    let used = embeddings.len();
    Ok((FarCalibration::from_impostor_scores(&impostor_scores(&embeddings))?, used))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::Detection;

    struct CenteredFace;

    impl FaceDetector for CenteredFace {
        fn detect(&self, image: &GrayImage) -> Result<Vec<Detection>, EngineError> {
            if image.pixels[0] == 255 {
                return Ok(vec![]);
            }
            Ok(vec![Detection {
                x: 0.0,
                y: 0.0,
                width: 112.0,
                height: 112.0,
                score: 0.99,
                landmarks: [(38.3, 51.7), (73.5, 51.5), (56.0, 71.7), (41.5, 92.4), (70.7, 92.2)],
            }])
        }
    }

    struct SeedEmbedder;

    impl FaceEmbedder for SeedEmbedder {
        fn embed(&self, aligned: &GrayImage) -> Result<Vec<f32>, EngineError> {
            let seed = aligned.pixels[0] as u32;
            Ok((0..64u32).map(|i| ((seed.wrapping_mul(2654435761).wrapping_add(i * 40503)) % 1000) as f32 - 500.0).collect())
        }
    }

    fn image(seed: u8) -> GrayImage {
        GrayImage::new(112, 112, vec![seed; 112 * 112]).unwrap()
    }

    #[test]
    fn pairs_each_identity_once() {
        let scores = impostor_scores(&[vec![1.0, 0.0], vec![0.0, 1.0], vec![1.0, 0.0]]);
        assert_eq!(scores, vec![0.0, 1.0, 0.0]);
    }

    #[test]
    fn calibration_skips_faceless_images_and_reports_how_many_were_used() {
        let mut images: Vec<GrayImage> = (0..60u8).map(image).collect();
        images.push(image(255));
        let (_, used) = calibrate_from_identities(&CenteredFace, &SeedEmbedder, images.into_iter()).unwrap();
        assert_eq!(used, 60);
    }

    #[test]
    fn too_few_identities_cannot_calibrate() {
        let result = calibrate_from_identities(&CenteredFace, &SeedEmbedder, (0..5u8).map(image));
        assert!(result.is_err());
    }

    #[test]
    fn directory_helpers_pick_sorted_identities_and_first_image() {
        let root = tempfile::tempdir().unwrap();
        for name in ["zed", "amy"] {
            std::fs::create_dir(root.path().join(name)).unwrap();
        }
        std::fs::write(root.path().join("amy/b.JPG"), b"x").unwrap();
        std::fs::write(root.path().join("amy/a.png"), b"x").unwrap();
        std::fs::write(root.path().join("amy/notes.txt"), b"x").unwrap();
        let dirs = identity_directories(root.path()).unwrap();
        assert_eq!(dirs.iter().map(|d| d.file_name().unwrap().to_str().unwrap()).collect::<Vec<_>>(), vec!["amy", "zed"]);
        assert_eq!(first_image(&dirs[0]).unwrap().file_name().unwrap(), "a.png");
        assert!(first_image(&dirs[1]).is_none());
    }
}
