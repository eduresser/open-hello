use crate::EngineError;

pub const DEFAULT_TARGET_FAR: f64 = 1e-5;
const MIN_IMPOSTOR_SAMPLES: usize = 1_000;

#[derive(Debug, Clone, PartialEq)]
pub struct FarCalibration {
    mean: f64,
    std_dev: f64,
    samples: u64,
}

impl FarCalibration {
    pub fn from_impostor_scores(scores: &[f32]) -> Result<Self, EngineError> {
        if scores.len() < MIN_IMPOSTOR_SAMPLES {
            return Err(EngineError::InvalidInput(format!(
                "calibration needs at least {MIN_IMPOSTOR_SAMPLES} impostor scores, got {}",
                scores.len()
            )));
        }
        let n = scores.len() as f64;
        let mean = scores.iter().map(|&s| s as f64).sum::<f64>() / n;
        let variance = scores.iter().map(|&s| (s as f64 - mean).powi(2)).sum::<f64>() / (n - 1.0);
        if !variance.is_finite() || variance <= 0.0 {
            return Err(EngineError::InvalidInput("impostor scores have no variance".into()));
        }
        Ok(Self { mean, std_dev: variance.sqrt(), samples: scores.len() as u64 })
    }

    pub fn score_threshold(&self, target_far: f64) -> Result<f64, EngineError> {
        if !(target_far > 0.0 && target_far < 1.0) {
            return Err(EngineError::InvalidInput(format!("target FAR must be in (0, 1), got {target_far}")));
        }
        Ok(self.mean + self.std_dev * inverse_normal_cdf(1.0 - target_far))
    }

    pub fn far_at(&self, score: f64) -> f64 {
        0.5 * erfc((score - self.mean) / (self.std_dev * std::f64::consts::SQRT_2))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(24);
        out.extend(self.mean.to_le_bytes());
        out.extend(self.std_dev.to_le_bytes());
        out.extend(self.samples.to_le_bytes());
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EngineError> {
        let invalid = || EngineError::InvalidInput("calibration file must be 24 bytes".into());
        let field = |range: std::ops::Range<usize>| -> Result<[u8; 8], EngineError> {
            bytes.get(range).and_then(|s| s.try_into().ok()).ok_or_else(invalid)
        };
        if bytes.len() != 24 {
            return Err(invalid());
        }
        let calibration = Self {
            mean: f64::from_le_bytes(field(0..8)?),
            std_dev: f64::from_le_bytes(field(8..16)?),
            samples: u64::from_le_bytes(field(16..24)?),
        };
        if !calibration.mean.is_finite() || !(calibration.std_dev.is_finite() && calibration.std_dev > 0.0) {
            return Err(EngineError::InvalidInput("calibration contains non-finite values".into()));
        }
        Ok(calibration)
    }
}

fn inverse_normal_cdf(p: f64) -> f64 {
    const A: [f64; 6] = [-3.969683028665376e1, 2.209460984245205e2, -2.759285104469687e2, 1.383577518672690e2, -3.066479806614716e1, 2.506628277459239];
    const B: [f64; 5] = [-5.447609879822406e1, 1.615858368580409e2, -1.556989798598866e2, 6.680131188771972e1, -1.328068155288572e1];
    const C: [f64; 6] = [-7.784894002430293e-3, -3.223964580411365e-1, -2.400758277161838, -2.549732539343734, 4.374664141464968, 2.938163982698783];
    const D: [f64; 4] = [7.784695709041462e-3, 3.224671290700398e-1, 2.445134137142996, 3.754408661907416];
    const LOW: f64 = 0.02425;
    if p < LOW {
        let q = (-2.0 * p.ln()).sqrt();
        (((((C[0] * q + C[1]) * q + C[2]) * q + C[3]) * q + C[4]) * q + C[5])
            / ((((D[0] * q + D[1]) * q + D[2]) * q + D[3]) * q + 1.0)
    } else if p <= 1.0 - LOW {
        let q = p - 0.5;
        let r = q * q;
        (((((A[0] * r + A[1]) * r + A[2]) * r + A[3]) * r + A[4]) * r + A[5]) * q
            / (((((B[0] * r + B[1]) * r + B[2]) * r + B[3]) * r + B[4]) * r + 1.0)
    } else {
        -inverse_normal_cdf(1.0 - p)
    }
}

fn erfc(x: f64) -> f64 {
    let z = x.abs();
    let t = 1.0 / (1.0 + 0.5 * z);
    let poly = -z * z - 1.26551223
        + t * (1.00002368
            + t * (0.37409196
                + t * (0.09678418 + t * (-0.18628806 + t * (0.27886807 + t * (-1.13520398 + t * (1.48851587 + t * (-0.82215223 + t * 0.17087277))))))));
    let value = t * poly.exp();
    if x >= 0.0 {
        value
    } else {
        2.0 - value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gaussian_scores(n: usize, mean: f32, std: f32) -> Vec<f32> {
        let mut state = 0x9E3779B97F4A7C15u64;
        let mut uniform = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 11) as f64 / (1u64 << 53) as f64
        };
        (0..n)
            .map(|_| {
                let (u1, u2) = (uniform().max(1e-12), uniform());
                let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
                mean + std * z as f32
            })
            .collect()
    }

    #[test]
    fn inverse_cdf_matches_known_quantiles() {
        assert!(inverse_normal_cdf(0.5).abs() < 1e-9);
        assert!((inverse_normal_cdf(1.0 - 1e-5) - 4.264890794).abs() < 1e-3);
        assert!((inverse_normal_cdf(0.975) - 1.959964).abs() < 1e-4);
    }

    #[test]
    fn far_at_threshold_round_trips_the_target() {
        let calibration = FarCalibration::from_impostor_scores(&gaussian_scores(5_000, 0.02, 0.045)).unwrap();
        for far in [1e-2, 1e-3, 1e-5] {
            let threshold = calibration.score_threshold(far).unwrap();
            let back = calibration.far_at(threshold);
            assert!((back / far - 1.0).abs() < 0.05, "far {far} round-tripped to {back}");
        }
    }

    #[test]
    fn stricter_far_demands_higher_score() {
        let calibration = FarCalibration::from_impostor_scores(&gaussian_scores(5_000, 0.0, 0.05)).unwrap();
        assert!(calibration.score_threshold(1e-6).unwrap() > calibration.score_threshold(1e-3).unwrap());
    }

    #[test]
    fn rejects_too_few_samples_and_invalid_far() {
        assert!(FarCalibration::from_impostor_scores(&[0.1; 10]).is_err());
        let calibration = FarCalibration::from_impostor_scores(&gaussian_scores(2_000, 0.0, 0.05)).unwrap();
        assert!(calibration.score_threshold(0.0).is_err());
        assert!(calibration.score_threshold(1.0).is_err());
        assert!(FarCalibration::from_impostor_scores(&[0.3; 2_000]).is_err());
    }

    #[test]
    fn serialization_round_trips_and_rejects_garbage() {
        let calibration = FarCalibration::from_impostor_scores(&gaussian_scores(2_000, 0.01, 0.04)).unwrap();
        assert_eq!(FarCalibration::from_bytes(&calibration.to_bytes()).unwrap(), calibration);
        assert!(FarCalibration::from_bytes(&[0; 5]).is_err());
        assert!(FarCalibration::from_bytes(&[0; 24]).is_err());
    }
}
