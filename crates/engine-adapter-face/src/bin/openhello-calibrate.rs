use std::path::{Path, PathBuf};
use std::process::ExitCode;

use engine_adapter_face::calibrate::{calibrate_from_identities, first_image, identity_directories};
use engine_adapter_face::detect::ort_backend::YunetDetector;
use engine_adapter_face::embedding::ort_backend::AuraFaceEmbedder;
use engine_adapter_face::far_calibration::Provenance;
use engine_adapter_face::GrayImage;
use sha2::{Digest, Sha256};

const USAGE: &str = "usage: openhello-calibrate --models-dir DIR --images-dir DIR --out FILE [--format toml|bin] [--max-identities 600]
       [--dataset NAME] [--license-note TEXT] [--date YYYY-MM-DD]
images-dir holds one sub-directory per person, each with at least one face photo (jpg/png)";

struct Options {
    models: PathBuf,
    images: PathBuf,
    out: PathBuf,
    max: usize,
    binary: bool,
    provenance: Provenance,
}

fn parse(args: impl Iterator<Item = String>) -> Result<Options, String> {
    let mut values = std::collections::HashMap::new();
    let mut args = args;
    while let Some(flag) = args.next() {
        let name = flag.strip_prefix("--").ok_or_else(|| format!("unexpected argument `{flag}`"))?.to_string();
        values.insert(name, args.next().ok_or_else(|| format!("{flag} needs a value"))?);
    }
    let mut take = |name: &str| values.remove(name).ok_or_else(|| format!("--{name} is required"));
    let (models, images, out) = (take("models-dir")?, take("images-dir")?, take("out")?);
    let max = match values.remove("max-identities") {
        None => 600,
        Some(text) => text.parse().map_err(|_| format!("--max-identities must be a positive integer, got `{text}`"))?,
    };
    let binary = match values.remove("format").as_deref() {
        None | Some("toml") => false,
        Some("bin") => true,
        Some(other) => return Err(format!("--format must be toml or bin, got `{other}`")),
    };
    let provenance = Provenance {
        dataset: values.remove("dataset").unwrap_or_default(),
        license_note: values.remove("license-note").unwrap_or_default(),
        date: values.remove("date").unwrap_or_default(),
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        ..Provenance::default()
    };
    if let Some(unknown) = values.keys().next() {
        return Err(format!("unknown option --{unknown}"));
    }
    Ok(Options { models: models.into(), images: images.into(), out: out.into(), max, binary, provenance })
}

fn sha256_of(path: &Path) -> Result<String, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    Ok(Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect())
}

fn run() -> Result<(), String> {
    let Options { models, images, out, max, binary, mut provenance } = parse(std::env::args().skip(1))?;
    let (detector_path, embedding_path) = (models.join("yunet.onnx"), models.join("glintr100.onnx"));
    let detector = YunetDetector::load(&detector_path).map_err(|e| e.to_string())?;
    let embedder = AuraFaceEmbedder::load(&embedding_path).map_err(|e| e.to_string())?;
    let directories = identity_directories(&images).map_err(|e| e.to_string())?;
    let photos = directories.iter().filter_map(|d| first_image(d)).take(max).filter_map(|path| {
        let gray = image::open(&path).ok()?.to_luma8();
        GrayImage::new(gray.width(), gray.height(), gray.into_raw()).ok()
    });
    let (calibration, used) = calibrate_from_identities(&detector, &embedder, photos).map_err(|e| e.to_string())?;
    provenance.detector_sha256 = sha256_of(&detector_path)?;
    provenance.embedding_sha256 = sha256_of(&embedding_path)?;
    provenance.impostor_pairs = (used * used.saturating_sub(1) / 2) as u64;
    let contents = if binary { calibration.to_bytes() } else { calibration.to_toml(&provenance).into_bytes() };
    std::fs::write(&out, contents).map_err(|e| format!("cannot write {}: {e}", out.display()))?;
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
