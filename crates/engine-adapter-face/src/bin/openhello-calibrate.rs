use std::path::PathBuf;
use std::process::ExitCode;

use engine_adapter_face::calibrate::{calibrate_from_identities, first_image, identity_directories};
use engine_adapter_face::detect::ort_backend::YunetDetector;
use engine_adapter_face::embedding::ort_backend::AuraFaceEmbedder;
use engine_adapter_face::GrayImage;

const USAGE: &str = "usage: openhello-calibrate --models-dir DIR --images-dir DIR --out FILE [--max-identities 600]
images-dir holds one sub-directory per person, each with at least one face photo (jpg/png)";

fn parse(args: impl Iterator<Item = String>) -> Result<(PathBuf, PathBuf, PathBuf, usize), String> {
    let mut values = std::collections::HashMap::new();
    let mut args = args;
    while let Some(flag) = args.next() {
        let name = flag.strip_prefix("--").ok_or_else(|| format!("unexpected argument `{flag}`"))?.to_string();
        values.insert(name, args.next().ok_or_else(|| format!("--{flag} needs a value"))?);
    }
    let mut take = |name: &str| values.remove(name).ok_or_else(|| format!("--{name} is required"));
    let (models, images, out) = (take("models-dir")?, take("images-dir")?, take("out")?);
    let max = match values.remove("max-identities") {
        None => 600,
        Some(text) => text.parse().map_err(|_| format!("--max-identities must be a positive integer, got `{text}`"))?,
    };
    Ok((models.into(), images.into(), out.into(), max))
}

fn run() -> Result<(), String> {
    let (models, images_dir, out, max) = parse(std::env::args().skip(1))?;
    let detector = YunetDetector::load(&models.join("yunet.onnx")).map_err(|e| e.to_string())?;
    let embedder = AuraFaceEmbedder::load(&models.join("glintr100.onnx")).map_err(|e| e.to_string())?;
    let directories = identity_directories(&images_dir).map_err(|e| e.to_string())?;
    let photos = directories.iter().filter_map(|d| first_image(d)).take(max).filter_map(|path| {
        let gray = image::open(&path).ok()?.to_luma8();
        GrayImage::new(gray.width(), gray.height(), gray.into_raw()).ok()
    });
    let (calibration, used) = calibrate_from_identities(&detector, &embedder, photos).map_err(|e| e.to_string())?;
    std::fs::write(&out, calibration.to_bytes()).map_err(|e| format!("cannot write {}: {e}", out.display()))?;
    println!("calibrated from {used} identities -> {}", out.display());
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(problem) => {
            eprintln!("openhello-calibrate: {problem}\n{USAGE}");
            ExitCode::FAILURE
        }
    }
}
