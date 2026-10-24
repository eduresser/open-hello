use std::fmt::Write as _;
use std::path::Path;

use toml_edit::{DocumentMut, Item};

use crate::EngineError;

pub const DEFAULT_TARGET_FAR: f64 = 1e-5;
const MIN_IMPOSTOR_SAMPLES: usize = 1_000;
const MIN_TAIL_SAMPLES: usize = 50;
const TAIL_FRACTION: f64 = 0.02;
const BODY_LEVELS: usize = 64;
const BODY_TOP_FAR: f64 = 0.5;
// Impostor cosine tails are heavier than Gaussian; an exponential floor keeps extrapolation from understating FAR.
const MAX_SHAPE: f64 = 0.5;
const FORMAT_MAGIC: &[u8; 4] = b"OHC2";
const TOML_FORMAT: &str = "openhello-far-calibration";
const TOML_VERSION: i64 = 1;
const EMBEDDED_TOML: &str = include_str!("../config/default_calibration.toml");
pub const REPORTED_FARS: [f64; 8] = [1e-1, 1e-2, 1e-3, 1e-4, 1e-5, 1e-6, 1e-7, 1e-8];
const SERIALIZED_LEN: usize = 4 + 8 + 4 * 8 + 4 + BODY_LEVELS * 16;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Provenance {
    pub dataset: String,
    pub license_note: String,
    pub date: String,
    pub detector_sha256: String,
    pub embedding_sha256: String,
    pub impostor_pairs: u64,
    pub tool_version: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FarCalibration {
    samples: u64,
    body: Vec<(f64, f64)>,
    tail_far: f64,
    tail_score: f64,
    shape: f64,
    scale: f64,
}

impl FarCalibration {
    pub fn from_impostor_scores(scores: &[f32]) -> Result<Self, EngineError> {
        if scores.len() < MIN_IMPOSTOR_SAMPLES || scores.iter().any(|s| !s.is_finite()) {
            return Err(EngineError::InvalidInput(format!(
                "calibration needs at least {MIN_IMPOSTOR_SAMPLES} finite impostor scores, got {}",
                scores.len()
            )));
        }
        let mut sorted: Vec<f64> = scores.iter().map(|&s| f64::from(s)).collect();
        sorted.sort_by(f64::total_cmp);
        let n = sorted.len();
        let tail_count = ((n as f64 * TAIL_FRACTION).ceil() as usize).max(MIN_TAIL_SAMPLES);
        let tail_far = tail_count as f64 / n as f64;
        let tail_score = sorted[n - tail_count - 1];
        let (shape, scale) = fit_tail(&sorted[n - tail_count..], tail_score)?;
        let body = (0..BODY_LEVELS)
            .map(|i| {
                let far = BODY_TOP_FAR * (tail_far / BODY_TOP_FAR).powf(i as f64 / (BODY_LEVELS - 1) as f64);
                let index = (((1.0 - far) * n as f64) as usize).min(n - 1);
                (far, if i == BODY_LEVELS - 1 { tail_score } else { sorted[index].min(tail_score) })
            })
            .collect();
        Ok(Self { samples: n as u64, body, tail_far, tail_score, shape, scale })
    }

    pub fn score_threshold(&self, target_far: f64) -> Result<f64, EngineError> {
        if !(target_far > 0.0 && target_far < 1.0) {
            return Err(EngineError::InvalidInput(format!("target FAR must be in (0, 1), got {target_far}")));
        }
        if target_far < self.tail_far {
            let ratio = target_far / self.tail_far;
            return Ok(self.tail_score + self.scale * excess_per_scale(ratio, self.shape));
        }
        Ok(self.body_score(target_far))
    }

    pub fn far_at(&self, score: f64) -> f64 {
        if score > self.tail_score {
            let z = (score - self.tail_score) / self.scale;
            return self.tail_far * survival_ratio(z, self.shape);
        }
        self.body_far(score)
    }

    fn body_score(&self, far: f64) -> f64 {
        let (high_far, high_score) = self.body[0];
        if far >= high_far {
            return high_score;
        }
        let upper = self.body.partition_point(|&(f, _)| f > far).min(self.body.len() - 1);
        let ((far_a, score_a), (far_b, score_b)) = (self.body[upper - 1], self.body[upper]);
        let weight = (far_a.ln() - far.ln()) / (far_a.ln() - far_b.ln());
        score_a + weight * (score_b - score_a)
    }

    fn body_far(&self, score: f64) -> f64 {
        let (top_far, bottom_score) = (self.body[0].0, self.body[0].1);
        if score <= bottom_score {
            return top_far;
        }
        let upper = self.body.partition_point(|&(_, s)| s < score).min(self.body.len() - 1);
        let ((far_a, score_a), (far_b, score_b)) = (self.body[upper - 1], self.body[upper]);
        if score_b <= score_a {
            return far_b;
        }
        let weight = (score - score_a) / (score_b - score_a);
        (far_a.ln() + weight * (far_b.ln() - far_a.ln())).exp()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(SERIALIZED_LEN);
        out.extend(FORMAT_MAGIC);
        out.extend(self.samples.to_le_bytes());
        for value in [self.tail_far, self.tail_score, self.shape, self.scale] {
            out.extend(value.to_le_bytes());
        }
        out.extend((self.body.len() as u32).to_le_bytes());
        for (far, score) in &self.body {
            out.extend(far.to_le_bytes());
            out.extend(score.to_le_bytes());
        }
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EngineError> {
        if bytes.len() != SERIALIZED_LEN || &bytes[..4] != FORMAT_MAGIC {
            return Err(EngineError::InvalidInput(
                "calibration file has an unsupported format; regenerate it with openhello-calibrate".into(),
            ));
        }
        let number = |offset: usize| f64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
        let samples = u64::from_le_bytes(bytes[4..12].try_into().unwrap());
        let (tail_far, tail_score, shape, scale) = (number(12), number(20), number(28), number(36));
        let levels = u32::from_le_bytes(bytes[44..48].try_into().unwrap()) as usize;
        if levels != BODY_LEVELS {
            return Err(EngineError::InvalidInput("calibration body table has the wrong size".into()));
        }
        let body: Vec<(f64, f64)> = (0..levels).map(|i| (number(48 + i * 16), number(56 + i * 16))).collect();
        Self::validated(samples, body, tail_far, tail_score, shape, scale)
    }

    fn validated(samples: u64, body: Vec<(f64, f64)>, tail_far: f64, tail_score: f64, shape: f64, scale: f64) -> Result<Self, EngineError> {
        let valid = body.len() == BODY_LEVELS
            && [tail_far, tail_score, shape, scale].iter().all(|v| v.is_finite())
            && tail_far > 0.0
            && tail_far < BODY_TOP_FAR
            && scale > 0.0
            && (0.0..=MAX_SHAPE).contains(&shape)
            && body.iter().all(|(f, s)| f.is_finite() && s.is_finite() && *f > 0.0 && *f <= 1.0)
            && body.windows(2).all(|w| w[0].0 > w[1].0 && w[0].1 <= w[1].1)
            && body.last().is_some_and(|&(f, s)| f == tail_far && s == tail_score);
        if !valid {
            return Err(EngineError::InvalidInput("calibration contains inconsistent values".into()));
        }
        Ok(Self { samples, body, tail_far, tail_score, shape, scale })
    }

    pub fn to_toml(&self, provenance: &Provenance) -> String {
        let quote = |text: &str| toml_edit::Value::from(text).to_string();
        let mut out = String::new();
        let _ = writeln!(out, "format = {}\nversion = {TOML_VERSION}\nsamples = {}", quote(TOML_FORMAT), self.samples);
        let _ = writeln!(out, "tail_far = {:?}\ntail_score = {:?}\nshape = {:?}\nscale = {:?}", self.tail_far, self.tail_score, self.shape, self.scale);
        out.push_str("body = [\n");
        for (far, score) in &self.body {
            let _ = writeln!(out, "  [{far:?}, {score:?}],");
        }
        out.push_str("]\n\n[provenance]\n");
        let _ = writeln!(out, "dataset = {}\nlicense_note = {}\ndate = {}", quote(&provenance.dataset), quote(&provenance.license_note), quote(&provenance.date));
        let _ = writeln!(out, "impostor_pairs = {}\ntool_version = {}", provenance.impostor_pairs, quote(&provenance.tool_version));
        let _ = writeln!(
            out,
            "\n[provenance.models_sha256]\ndetector = {}\nembedding = {}\n\n[thresholds]",
            quote(&provenance.detector_sha256),
            quote(&provenance.embedding_sha256)
        );
        for far in REPORTED_FARS {
            let _ = writeln!(out, "\"{far:e}\" = {:.4}", self.score_threshold(far).unwrap_or(f64::NAN));
        }
        out
    }

    pub fn from_toml(text: &str) -> Result<Self, EngineError> {
        let bad = |what: &str| EngineError::InvalidInput(format!("calibration file is not valid: {what}"));
        let doc: DocumentMut = text.parse().map_err(|_| bad("not readable as TOML"))?;
        if doc.get("format").and_then(Item::as_str) != Some(TOML_FORMAT) || doc.get("version").and_then(Item::as_integer) != Some(TOML_VERSION) {
            return Err(bad("unsupported format marker or version; regenerate it with openhello-calibrate"));
        }
        let float = |key: &str| doc.get(key).and_then(Item::as_float).ok_or_else(|| bad(&format!("`{key}` is missing or not a number")));
        let samples = doc
            .get("samples")
            .and_then(Item::as_integer)
            .and_then(|n| u64::try_from(n).ok())
            .ok_or_else(|| bad("`samples` is missing or not a positive integer"))?;
        let rows = doc.get("body").and_then(Item::as_array).ok_or_else(|| bad("`body` table is missing"))?;
        let body = rows
            .iter()
            .map(|row| {
                let pair = row.as_array().filter(|pair| pair.len() == 2)?;
                Some((pair.get(0)?.as_float()?, pair.get(1)?.as_float()?))
            })
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| bad("`body` rows must be [far, score] numbers"))?;
        if body.len() != BODY_LEVELS {
            return Err(EngineError::InvalidInput("calibration body table has the wrong size".into()));
        }
        Self::validated(samples, body, float("tail_far")?, float("tail_score")?, float("shape")?, float("scale")?)
    }

    pub fn from_file_contents(bytes: &[u8]) -> Result<Self, EngineError> {
        if bytes.starts_with(FORMAT_MAGIC) {
            return Self::from_bytes(bytes);
        }
        let text = std::str::from_utf8(bytes)
            .map_err(|_| EngineError::InvalidInput("calibration file has an unsupported format; regenerate it with openhello-calibrate".into()))?;
        Self::from_toml(text)
    }

    pub fn embedded_default() -> Result<Self, EngineError> {
        Self::from_toml(EMBEDDED_TOML)
    }

    pub fn load(path: Option<&Path>) -> Result<Self, EngineError> {
        let Some(path) = path else {
            return Self::embedded_default();
        };
        let bytes = std::fs::read(path).map_err(|e| EngineError::InvalidInput(format!("calibration file {}: {e}", path.display())))?;
        Self::from_file_contents(&bytes).map_err(|e| match e {
            EngineError::InvalidInput(reason) => EngineError::InvalidInput(format!("calibration file {}: {reason}", path.display())),
            other => other,
        })
    }
}

fn fit_tail(top_scores: &[f64], threshold: f64) -> Result<(f64, f64), EngineError> {
    let count = top_scores.len() as f64;
    let excesses: Vec<f64> = top_scores.iter().map(|s| s - threshold).collect();
    let mean = excesses.iter().sum::<f64>() / count;
    if !(mean.is_finite() && mean > 0.0) {
        return Err(EngineError::InvalidInput("impostor scores have no variance".into()));
    }
    let weighted = excesses
        .iter()
        .enumerate()
        .map(|(i, e)| e * (1.0 - (i as f64 + 0.65) / count))
        .sum::<f64>()
        / count;
    let spread = mean - 2.0 * weighted;
    let shape = if spread > 0.0 { (2.0 - mean / spread).clamp(0.0, MAX_SHAPE) } else { 0.0 };
    Ok((shape, mean * (1.0 - shape)))
}

fn excess_per_scale(far_ratio: f64, shape: f64) -> f64 {
    if shape < 1e-9 {
        -far_ratio.ln()
    } else {
        (far_ratio.powf(-shape) - 1.0) / shape
    }
}

fn survival_ratio(z: f64, shape: f64) -> f64 {
    if shape < 1e-9 {
        (-z).exp()
    } else {
        (1.0 + shape * z).powf(-1.0 / shape)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Rng(u64);

    impl Rng {
        fn uniform(&mut self) -> f64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            ((self.0 >> 11) as f64 / (1u64 << 53) as f64).max(1e-12)
        }

        fn normal(&mut self) -> f64 {
            let (u1, u2) = (self.uniform(), self.uniform());
            (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos()
        }

        fn student_t5(&mut self, mean: f64, scale: f64) -> f32 {
            let chi_square: f64 = (0..5).map(|_| self.normal().powi(2)).sum();
            (mean + scale * self.normal() / (chi_square / 5.0).sqrt()) as f32
        }
    }

    fn heavy_tailed_scores(rng: &mut Rng, n: usize) -> Vec<f32> {
        (0..n).map(|_| rng.student_t5(0.05, 0.04)).collect()
    }

    fn calibration_from(n: usize, seed: u64) -> FarCalibration {
        FarCalibration::from_impostor_scores(&heavy_tailed_scores(&mut Rng(seed), n)).unwrap()
    }

    #[test]
    fn measured_far_on_unseen_heavy_tailed_scores_stays_near_the_target() {
        let calibration = calibration_from(200_000, 0x9E3779B97F4A7C15);
        let unseen = heavy_tailed_scores(&mut Rng(0xD1B54A32D192ED03), 2_000_000);
        for far in [1e-2, 1e-3, 1e-4, 1e-5] {
            let threshold = calibration.score_threshold(far).unwrap();
            let measured = unseen.iter().filter(|&&s| f64::from(s) >= threshold).count() as f64 / unseen.len() as f64;
            assert!(measured < far * 2.0 && measured > far / 3.0, "target {far} measured {measured}");
        }
    }

    #[test]
    fn far_at_inverts_score_threshold_in_body_and_tail() {
        let calibration = calibration_from(20_000, 5);
        for far in [0.4, 0.1, 1e-2, 1e-3, 1e-5, 1e-7] {
            let back = calibration.far_at(calibration.score_threshold(far).unwrap());
            assert!((back / far - 1.0).abs() < 1e-6, "far {far} round-tripped to {back}");
        }
    }

    #[test]
    fn stricter_far_never_lowers_the_threshold() {
        let calibration = calibration_from(5_000, 9);
        let thresholds: Vec<f64> = (1..=12).map(|exp| calibration.score_threshold(10f64.powi(-exp)).unwrap()).collect();
        assert!(thresholds.windows(2).all(|pair| pair[1] > pair[0]), "{thresholds:?}");
    }

    #[test]
    fn rejects_too_few_samples_invalid_far_and_degenerate_scores() {
        assert!(FarCalibration::from_impostor_scores(&[0.1; 10]).is_err());
        assert!(FarCalibration::from_impostor_scores(&[0.3; 2_000]).is_err());
        let mut with_nan = heavy_tailed_scores(&mut Rng(3), 2_000);
        with_nan[7] = f32::NAN;
        assert!(FarCalibration::from_impostor_scores(&with_nan).is_err());
        let calibration = calibration_from(2_000, 3);
        assert!(calibration.score_threshold(0.0).is_err());
        assert!(calibration.score_threshold(1.0).is_err());
    }

    #[test]
    fn serialization_round_trips_and_rejects_garbage_and_legacy_files() {
        let calibration = calibration_from(2_000, 11);
        let bytes = calibration.to_bytes();
        assert_eq!(FarCalibration::from_bytes(&bytes).unwrap(), calibration);
        assert!(FarCalibration::from_bytes(&bytes[..bytes.len() - 1]).is_err());
        assert!(FarCalibration::from_bytes(&[0; 24]).is_err());
        let mut corrupted = bytes.clone();
        corrupted[36..44].copy_from_slice(&f64::NAN.to_le_bytes());
        assert!(FarCalibration::from_bytes(&corrupted).is_err());
        let mut swapped = bytes;
        swapped[12..20].copy_from_slice(&0.9f64.to_le_bytes());
        assert!(FarCalibration::from_bytes(&swapped).is_err());
    }

    const GOLDEN_FARS: [f64; 7] = [0.3, 0.05, 1e-2, 1e-3, 1e-4, 1e-6, 1e-8];
    const GOLDEN_SCORES: [f64; 5] = [0.0, 0.1, 0.2, 0.3, 0.45];

    fn golden_calibration() -> FarCalibration {
        calibration_from(5_000, 21)
    }

    #[test]
    #[ignore = "regenerates tests/fixtures/calibration_golden.json"]
    fn regenerate_golden_calibration() {
        let calibration = golden_calibration();
        let hex: String = calibration.to_bytes().iter().map(|b| format!("{b:02x}")).collect();
        let thresholds: Vec<f64> = GOLDEN_FARS.iter().map(|&far| calibration.score_threshold(far).unwrap()).collect();
        let fars: Vec<f64> = GOLDEN_SCORES.iter().map(|&score| calibration.far_at(score)).collect();
        let json = serde_json::json!({
            "calibration_hex": hex,
            "target_fars": GOLDEN_FARS,
            "thresholds": thresholds,
            "scores": GOLDEN_SCORES,
            "far_at_scores": fars,
        });
        std::fs::write(
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/calibration_golden.json"),
            serde_json::to_string_pretty(&json).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn thresholds_match_the_golden_file() {
        let golden: serde_json::Value = serde_json::from_str(include_str!("../tests/fixtures/calibration_golden.json")).unwrap();
        let hex = golden["calibration_hex"].as_str().unwrap();
        let bytes: Vec<u8> = (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect();
        let calibration = FarCalibration::from_bytes(&bytes).unwrap();
        for (far, expected) in golden["target_fars"].as_array().unwrap().iter().zip(golden["thresholds"].as_array().unwrap()) {
            let (far, expected) = (far.as_f64().unwrap(), expected.as_f64().unwrap());
            assert!((calibration.score_threshold(far).unwrap() - expected).abs() < 1e-9, "threshold at {far}");
        }
        for (score, expected) in golden["scores"].as_array().unwrap().iter().zip(golden["far_at_scores"].as_array().unwrap()) {
            let (score, expected) = (score.as_f64().unwrap(), expected.as_f64().unwrap());
            assert!((calibration.far_at(score) / expected - 1.0).abs() < 1e-9, "far at {score}");
        }
    }
}
