# Accuracy evaluation

Measures, outside the application, how often recognition accepts the right person and rejects others. The application stays entirely in Rust; this folder only reads what it produces (`openhello-calibrate`) and runs the same ONNX models.

## Scope

- Runs YuNet and AuraFace in Python with the same preprocessing as the Rust engine (640 letterbox, 5-point ArcFace alignment, grayscale replicated to 3 channels).
- Reads the calibration file produced by Rust and applies the production thresholds: the target FAR is divided by the number of embeddings in the template (verify) or in all templates (identify).
- Does not calibrate anything itself. `openhello-calibrate` does.

## Environment

```bash
cd evaluation
uv sync
uv run pytest
```

## LFW workflow

Datasets stay outside the repository (`data/` is in `.gitignore`).

```bash
uv run python -m openhello_eval prepare --parquet lfw.parquet --out data/people
uv run python -m openhello_eval embed --models-dir MODELS --images-dir data/people --out data/embeddings.npz
uv run python -m openhello_eval strangers --images-dir data/people --out data/strangers
openhello-calibrate --models-dir MODELS --images-dir data/strangers --out data/calibration.bin
uv run python -m openhello_eval parity --images-dir data/people --embeddings data/embeddings.npz --calibration data/calibration.bin
uv run python -m openhello_eval report --images-dir data/people --embeddings data/embeddings.npz --calibration data/calibration.bin
```

`MODELS` is the folder holding `yunet.onnx` and `glintr100.onnx`. The Python ONNX Runtime comes from `uv`; `openhello-calibrate` needs `ORT_DYLIB_PATH`.

## Identity split

- At least `enroll-shots + 2` photos: enrolled. The first `enroll-shots` photos form the template and the rest are probes.
- Fewer photos: strangers. The first photo of each one calibrates the FAR and serves as the unenrolled face in identification.

## Parity with Rust

- `parity` compares the quantiles in the calibration table written by Rust with the quantiles Python computes from its own embeddings. A difference above 0.02, or a different number of pairs, fails the command.
- `tests/test_calibration.py` checks the threshold computation against `crates/engine-adapter-face/tests/fixtures/calibration_golden.json`, the same file the Rust test checks.
- Regenerate the golden file: `cargo test -p engine-adapter-face --lib regenerate_golden -- --ignored`.

## Notebook

`notebooks/evaluation.ipynb` uses the same functions and plots score distributions, measured FAR against target, and the ROC curve. Commit it without outputs. Rebuild it with `uv run python notebooks/build_notebook.py`.

```bash
OPENHELLO_EVAL_DATA=data uv run jupyter lab
```

## Limits

- LFW is visible light. This measures the pipeline, not infrared performance (ASM-001).
- LFW has a few label errors, which slightly inflate the impostor count.
