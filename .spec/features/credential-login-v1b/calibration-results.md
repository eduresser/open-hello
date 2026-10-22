# Calibration results

Source of the embedded default table `crates/engine-adapter-face/config/default_calibration.toml` (T-026, AC-036 to AC-038). The table was generated from LFW (visible light) until 2026-10-22 and is now generated from the CBSR NIR dataset; the LFW run is kept below as history.

## Execution

| Item | Value |
|---|---|
| Date | 2026-10-21 |
| Host | KDE neon VM, 4 CPUs |
| Tool | `openhello-calibrate` (binary `OHC2` output, converted to TOML by the project code without recomputation) |
| Duration | 3 min 44 s |
| Detector | YuNet 2023mar, sha256 `8f2383e4dd3cfbb4553ea8718107fc0423210dc964f9f4280604804ed2552fa4` (as in `scripts/install.sh`) |
| Embedding | AuraFace glintr100, sha256 `a7933ea5330113b01c9b60351d8f4c33003f145d8470ac5f0e52ee2effe25c60` |
| Dataset | LFW (`lfw.tgz`, figshare file 5976018), 5749 identities; first 600 in alphabetical directory order, one photo each |
| Identities used | 600 |
| Impostor pairs | 179700 (600 x 599 / 2) |
| Source file | 1072 bytes, sha256 `c86fa30983d409531cc12a6bb3930a6fcc2e16371e661c5ccb8a13232d32f875` |
| Tail | top 2% of scores (tail_far 0.02), shape 0.0 (exponential), scale 0.0339, tail_score 0.2052 |

## Thresholds by FAR

| FAR | Cosine threshold | Origin |
|---|---|---|
| 1e-1 | 0.1444 | empirical body table |
| 1e-2 | 0.2287 | tail extrapolation (below tail_far 0.02) |
| 1e-3 | 0.3068 | tail extrapolation |
| 1e-4 | 0.3850 | tail extrapolation |
| 1e-5 | 0.4632 | tail extrapolation, default target |
| 1e-6 | 0.5413 | tail extrapolation |
| 1e-7 | 0.6195 | tail extrapolation |
| 1e-8 | 0.6976 | tail extrapolation |

## Caveats

- Empirical resolution is about 5.6e-6 (1 / 179700). Thresholds at 1e-5 and below come from the fitted tail, not from observed impostor pairs, and cannot be confirmed with this dataset.
- The tail is exponential (shape 0.0): the fit found no heavier tail, so the extrapolation may understate FAR at the strictest levels.
- ASM-013: LFW is visible-light, uncontrolled photography. The product camera is infrared. Impostor score distributions on infrared captures can differ, so this table is a starting point and must be regenerated from infrared captures (`openhello-calibrate --dataset ... --license-note ... --date ...`) when such a set exists.
- No LFW image is versioned. Only derived statistics and the provenance block are stored.

## Infrared measurement on the product camera (2026-10-22, ASM-013)

One enrolled user, one impostor (not enrolled), Sunplus IR camera on the KDE neon VM, about 50 cm, diffuse light. Scores are per scored frame (cosine against the best of 6 template embeddings), logged with `OPENHELLO_SCORE_LOG=1`.

| Group | Frames | Median | Min | Max | Share at or above 0.62 | Share at or above 0.75 |
|---|---|---|---|---|---|---|
| Impostor | 231 (6 requests) | 0.388 | 0.200 | 0.728 | 5.2% | 0% |
| Genuine | 394 (10 requests) | 0.801 | 0.719 | 0.834 | 100% | 97.7% |

- The LFW table gives about 0.62 for the default target (1e-5 split across 16 frames and 6 embeddings, about 1e-7 per comparison). On infrared, 5.2% of the impostor's frames reach it: the real per-frame false accept is about five orders of magnitude above the design value, and an impostor passed in a real test. ASM-013 is refuted for the default table.
- Target 1e-8 gave a threshold of 0.8526, above every genuine frame measured here (max 0.834): all 10 genuine requests were refused.
- Needed before trusting the face alone (and before locking passwords): a calibration table from infrared captures of many identities (`openhello-calibrate`).

## Current default: CBSR NIR Face Dataset (2026-10-22)

| Item | Value |
|---|---|
| Dataset | Kaggle `gpreda/cbsr-nir-face-dataset` (origin CASIA CBSR): 3940 near-infrared images of 197 people, 480x640, 8 bit; the uploader states MIT, the original CBSR terms are unconfirmed; only derived statistics are kept |
| Used | 196 identities (identity 0101 is the same person as 0019: 384 impostor image pairs scored 0.7 to 0.9, all from that pair), one photo each, glasses avoided: 19110 impostor pairs |
| Models | same YuNet and AuraFace hashes as the LFW run |
| Tail | top 2% at 0.472, scale 0.0332 |

| FAR per comparison | LFW table | CBSR NIR table |
|---|---|---|
| 1e-2 | 0.229 | 0.495 |
| 1e-4 | 0.385 | 0.648 |
| 1e-5 | 0.463 | 0.724 |
| 1e-6 | 0.541 | 0.801 |
| 1e-7 | 0.620 | 0.877 |

Check over all 3940 images (7,644,000 impostor image pairs, 37,430 genuine pairs; correlated, 196 identities): the impostor maximum is 0.682, the 99.99th percentile 0.620, and 0 pairs reach 0.70; genuine pairs reach 0.70 in 90% and 0.77 in 80% of cases.

- The product camera behaves worse than this dataset for the genuine user (median 0.80, minimum 0.72, against a dataset median of 0.89), and the one impostor tested reached 0.73, above the dataset's maximum (a relative or look-alike is possible; one person only).
- The design target of 1e-5 per request (split over 16 frames and 6 embeddings, about 1e-7 per comparison) now means a threshold of 0.877, above every genuine frame measured on the product camera: it would refuse the owner. The default target was therefore changed to `2e-4` (threshold about 0.776, about 2e-6 per comparison on the extrapolated tail, at most about 2e-4 per attempt by the union bound). It is a working value, not a proven false accept rate: 196 identities support claims only down to about 1e-4 per comparison.
- To reach 1e-5 the genuine scores of the product camera must rise (re-enrol in good light and focus, at 40 to 60 cm) or the capture and embedding must improve; measure again with `OPENHELLO_SCORE_LOG=1`.
