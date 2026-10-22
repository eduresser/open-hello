# Calibration results

Source of the embedded default table `crates/engine-adapter-face/config/default_calibration.toml` (T-026, AC-036 to AC-038).

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
