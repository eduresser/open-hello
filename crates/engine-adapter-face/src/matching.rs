use crate::embedding::cosine_similarity;
use crate::far_calibration::FarCalibration;
use crate::EngineError;

#[derive(Debug, Clone, PartialEq)]
pub struct Template {
    embeddings: Vec<Vec<f32>>,
}

impl Template {
    pub fn new(embeddings: Vec<Vec<f32>>) -> Result<Self, EngineError> {
        let dim = embeddings.first().map(Vec::len).unwrap_or(0);
        if dim == 0 || embeddings.iter().any(|e| e.len() != dim) {
            return Err(EngineError::InvalidInput("template needs equally sized, non-empty embeddings".into()));
        }
        Ok(Self { embeddings })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend((self.embeddings.len() as u32).to_le_bytes());
        out.extend((self.embeddings[0].len() as u32).to_le_bytes());
        for value in self.embeddings.iter().flatten() {
            out.extend(value.to_le_bytes());
        }
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EngineError> {
        let invalid = || EngineError::InvalidInput("malformed template bytes".into());
        let header = bytes.get(..8).ok_or_else(invalid)?;
        let count = u32::from_le_bytes(header[..4].try_into().unwrap()) as usize;
        let dim = u32::from_le_bytes(header[4..].try_into().unwrap()) as usize;
        let body = &bytes[8..];
        if count == 0 || dim == 0 || body.len() != count.checked_mul(dim).and_then(|n| n.checked_mul(4)).ok_or_else(invalid)? {
            return Err(invalid());
        }
        let values: Vec<f32> = body.chunks_exact(4).map(|c| f32::from_le_bytes(c.try_into().unwrap())).collect();
        Self::new(values.chunks(dim).map(<[f32]>::to_vec).collect())
    }

    pub fn len(&self) -> usize {
        self.embeddings.len()
    }

    pub fn is_empty(&self) -> bool {
        self.embeddings.is_empty()
    }

    fn best_score(&self, probe: &[f32]) -> f32 {
        self.embeddings
            .iter()
            .map(|e| cosine_similarity(probe, e))
            .fold(f32::NEG_INFINITY, f32::max)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct IdentifyMatch {
    pub uid: u32,
    pub achieved_far: f64,
}

pub struct Matcher {
    calibration: FarCalibration,
}

impl Matcher {
    pub fn new(calibration: FarCalibration) -> Self {
        Self { calibration }
    }

    pub fn verify(&self, probe: &[f32], template: &Template, target_far: f64) -> Result<bool, EngineError> {
        check_dimension(probe, template)?;
        let threshold = self.calibration.score_threshold(target_far / template.len() as f64)?;
        Ok(f64::from(template.best_score(probe)) >= threshold)
    }

    pub fn identify(
        &self,
        probe: &[f32],
        enrolled: &[(u32, Template)],
        target_far: f64,
    ) -> Result<Option<IdentifyMatch>, EngineError> {
        if enrolled.is_empty() {
            return Ok(None);
        }
        let comparisons: usize = enrolled.iter().map(|(_, template)| template.len()).sum();
        let per_comparison_far = target_far / comparisons as f64;
        let threshold = self.calibration.score_threshold(per_comparison_far)?;
        let mut best: Option<(u32, f32)> = None;
        for (uid, template) in enrolled {
            check_dimension(probe, template)?;
            let score = template.best_score(probe);
            if best.is_none_or(|(_, s)| score > s) {
                best = Some((*uid, score));
            }
        }
        Ok(best.and_then(|(uid, score)| {
            (f64::from(score) >= threshold).then(|| IdentifyMatch {
                uid,
                achieved_far: self.calibration.far_at(f64::from(score)) * comparisons as f64,
            })
        }))
    }
}

fn check_dimension(probe: &[f32], template: &Template) -> Result<(), EngineError> {
    if probe.len() != template.embeddings[0].len() {
        return Err(EngineError::InvalidInput(format!(
            "probe has {} dimensions, template has {}",
            probe.len(),
            template.embeddings[0].len()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::embedding::l2_normalize;
    use crate::far_calibration::DEFAULT_TARGET_FAR;

    const DIM: usize = 512;

    struct Rng(u64);

    impl Rng {
        fn next_unit(&mut self) -> f32 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            ((self.0 >> 11) as f64 / (1u64 << 53) as f64) as f32 * 2.0 - 1.0
        }

        fn identity(&mut self) -> Vec<f32> {
            l2_normalize((0..DIM).map(|_| self.next_unit()).collect()).unwrap()
        }

        fn capture_of(&mut self, identity: &[f32], noise: f32) -> Vec<f32> {
            l2_normalize(identity.iter().map(|v| v + noise * self.next_unit()).collect()).unwrap()
        }
    }

    fn calibrated_matcher(rng: &mut Rng) -> Matcher {
        let people: Vec<Vec<f32>> = (0..120).map(|_| rng.identity()).collect();
        let mut scores = Vec::new();
        for i in 0..people.len() {
            for j in i + 1..people.len() {
                scores.push(cosine_similarity(&people[i], &people[j]));
            }
        }
        Matcher::new(FarCalibration::from_impostor_scores(&scores).unwrap())
    }

    fn enroll(rng: &mut Rng, identity: &[f32]) -> Template {
        Template::new((0..6).map(|_| rng.capture_of(identity, 0.02)).collect()).unwrap()
    }

    // @spec:AC-005
    // @principle:P-007
    #[test]
    fn same_person_is_accepted_at_default_far() {
        let mut rng = Rng(7);
        let matcher = calibrated_matcher(&mut rng);
        let me = rng.identity();
        let template = enroll(&mut rng, &me);
        let probe = rng.capture_of(&me, 0.03);
        assert!(matcher.verify(&probe, &template, DEFAULT_TARGET_FAR).unwrap());
    }

    // @spec:AC-006
    #[test]
    fn different_person_is_rejected() {
        let mut rng = Rng(11);
        let matcher = calibrated_matcher(&mut rng);
        let me = rng.identity();
        let template = enroll(&mut rng, &me);
        for _ in 0..50 {
            let stranger = rng.identity();
            assert!(!matcher.verify(&stranger, &template, DEFAULT_TARGET_FAR).unwrap());
        }
    }

    // @spec:AC-007
    #[test]
    fn identify_returns_the_right_account_among_several() {
        let mut rng = Rng(13);
        let matcher = calibrated_matcher(&mut rng);
        let people: Vec<Vec<f32>> = (0..3).map(|_| rng.identity()).collect();
        let enrolled: Vec<(u32, Template)> =
            people.iter().enumerate().map(|(i, p)| (1000 + i as u32, enroll(&mut rng, p))).collect();
        for (i, person) in people.iter().enumerate() {
            let probe = rng.capture_of(person, 0.03);
            let found = matcher.identify(&probe, &enrolled, DEFAULT_TARGET_FAR).unwrap().unwrap();
            assert_eq!(found.uid, 1000 + i as u32);
        }
    }

    // @spec:AC-008
    #[test]
    fn identify_rejects_an_unenrolled_face() {
        let mut rng = Rng(17);
        let matcher = calibrated_matcher(&mut rng);
        let enrolled: Vec<(u32, Template)> = (0..3)
            .map(|i| {
                let person = rng.identity();
                (1000 + i, enroll(&mut rng, &person))
            })
            .collect();
        for _ in 0..50 {
            let stranger = rng.identity();
            assert_eq!(matcher.identify(&stranger, &enrolled, DEFAULT_TARGET_FAR).unwrap(), None);
        }
        assert_eq!(matcher.identify(&rng.identity(), &[], DEFAULT_TARGET_FAR).unwrap(), None);
    }

    // @principle:P-007
    #[test]
    fn decision_depends_on_the_requested_far_not_a_fixed_cutoff() {
        let mut rng = Rng(19);
        let matcher = calibrated_matcher(&mut rng);
        let me = rng.identity();
        let template = enroll(&mut rng, &me);
        let noisy_probe = rng.capture_of(&me, 0.35);
        let lenient = matcher.verify(&noisy_probe, &template, 1e-2).unwrap();
        let strict = matcher.verify(&noisy_probe, &template, 1e-12).unwrap();
        assert!(lenient && !strict);
        assert!(matcher.verify(&noisy_probe, &template, 0.0).is_err());
    }

    #[test]
    fn target_far_is_split_across_every_embedding_in_the_template() {
        let mut rng = Rng(29);
        let matcher = calibrated_matcher(&mut rng);
        let far = 1e-3;
        let (single_cut, sixfold_cut) = (
            matcher.calibration.score_threshold(far).unwrap(),
            matcher.calibration.score_threshold(far / 6.0).unwrap(),
        );
        let score = ((single_cut + sixfold_cut) / 2.0) as f32;
        let anchor = rng.identity();
        let mut orthogonal = rng.identity();
        let overlap = cosine_similarity(&orthogonal, &anchor);
        orthogonal.iter_mut().zip(&anchor).for_each(|(o, a)| *o -= overlap * a);
        let orthogonal = l2_normalize(orthogonal).unwrap();
        let probe: Vec<f32> = anchor.iter().zip(&orthogonal).map(|(a, o)| score * a + (1.0 - score * score).sqrt() * o).collect();
        let single = Template::new(vec![anchor.clone()]).unwrap();
        let sixfold = Template::new(std::iter::once(anchor).chain((0..5).map(|_| rng.identity())).collect()).unwrap();
        assert!(matcher.verify(&probe, &single, far).unwrap());
        assert!(!matcher.verify(&probe, &sixfold, far).unwrap());
    }

    #[test]
    fn dimension_mismatch_is_an_error() {
        let mut rng = Rng(23);
        let matcher = calibrated_matcher(&mut rng);
        let template = Template::new(vec![vec![1.0, 0.0]]).unwrap();
        assert!(matcher.verify(&rng.identity(), &template, DEFAULT_TARGET_FAR).is_err());
    }

    #[test]
    fn template_serialization_round_trips_and_rejects_truncation() {
        let template = Template::new(vec![vec![0.5, -0.5], vec![0.25, 0.75]]).unwrap();
        let bytes = template.to_bytes();
        assert_eq!(Template::from_bytes(&bytes).unwrap(), template);
        assert!(Template::from_bytes(&bytes[..bytes.len() - 1]).is_err());
        assert!(Template::from_bytes(&[]).is_err());
        assert!(Template::new(vec![]).is_err());
    }
}
