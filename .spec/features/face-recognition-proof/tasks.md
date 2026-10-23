# Tasks: Face recognition proof

> feature: face-recognition-proof

## T-001 — Workspace scaffolding + plugin ABI contract [done]

- Refs: US-001, US-002, US-003
- Files: Cargo.toml, crates/openhello-plugin-abi/Cargo.toml, crates/openhello-plugin-abi/src/lib.rs
- Model: claude-sonnet-5
- Effort: low
- Notes: `#[repr(C)]` vtable structs (`SensorInterface`/`EngineInterface`/`StorageInterface`) and the three
  entry-point symbol names, mirroring WinBio's `WbioQuery<Layer>Interface`. Everything else depends on this.

## T-002 — Sensor Adapter: IR capture + emitter activation [done]

- Refs: AC-011, ASM-004
- Files: crates/sensor-adapter-ir/Cargo.toml, crates/sensor-adapter-ir/src/lib.rs, crates/sensor-adapter-ir/src/v4l2_capture.rs, crates/sensor-adapter-ir/src/emitter_xu.rs, crates/sensor-adapter-ir/src/msxu.rs, crates/sensor-adapter-ir/src/illumination.rs
- Model: claude-sonnet-5
- Effort: high
- Notes: depends on T-001 (ABI). Illumination is probed from frame brightness; the Microsoft face-auth XU or a
  configured vendor XU is used only when the stream is dark (ASM-004, confirmed on `2b7e:c757`).

## T-003 — Engine Adapter: detection + embedding (YuNet + AuraFace via ort) [done]

- Refs: US-002, US-003
- Files: crates/engine-adapter-face/Cargo.toml, crates/engine-adapter-face/src/lib.rs, crates/engine-adapter-face/src/detect.rs, crates/engine-adapter-face/src/embedding.rs
- Model: claude-sonnet-5
- Effort: high
- Notes: depends on T-001. Implements ASM-001 (AuraFace `glintr100` zero-shot on grayscale-as-RGB IR); the
  ~2-week SFace-fallback evaluation happens here before this task can be marked done.

## T-004 — Engine Adapter: enrollment quality gate [done]

- Refs: AC-001, AC-002, AC-003, AC-004, ASM-002
- Files: crates/engine-adapter-face/src/enrollment_quality.rs
- Model: claude-sonnet-5
- Effort: medium
- Notes: depends on T-003. Blur threshold and occlusion rejection; its yaw-bucket coverage and 60s/3-attempt
  timeout were replaced by T-057.

## T-005 — Engine Adapter: FAR-calibrated Verify/Identify matching [done]

- Refs: AC-005, AC-006, AC-007, AC-008, P-007
- Files: crates/engine-adapter-face/src/matching.rs, crates/engine-adapter-face/src/far_calibration.rs
- Model: claude-sonnet-5
- Effort: high
- Notes: depends on T-003. Public API takes a target FAR (default `1e-5`), never a raw distance cutoff.
  Calibration curve built offline from local, non-redistributed NIR dataset scores (see design.md).

## T-007 — Storage Adapter: TPM-sealed AEAD template store [done]

- Refs: AC-009, AC-010, P-004, P-006
- Files: crates/storage-adapter-templates/Cargo.toml, crates/storage-adapter-templates/src/lib.rs, crates/storage-adapter-templates/src/store.rs, crates/storage-adapter-templates/src/tpm_key.rs
- Model: claude-sonnet-5
- Effort: high
- Notes: depends on T-001. TPM key is dedicated to this store (scoped separately from the future
  `openhello-keyd` user credential key, per design.md). `tpm_key.rs`'s public API never returns plaintext
  key bytes (P-004).

## T-008 — Storage Adapter: purge (crypto-shred) [done]

- Refs: AC-014, P-008
- Files: crates/storage-adapter-templates/src/purge.rs
- Model: claude-sonnet-5
- Effort: medium
- Notes: depends on T-007. Deletes the TPM key object, then unlinks the encrypted file.

## T-009 — openhellod: D-Bus service, plugin loading, dispatch [done]

- Refs: US-001, US-002, US-003, US-008, P-003
- Files: crates/openhellod/Cargo.toml, crates/openhellod/src/main.rs, crates/openhellod/src/dbus_service.rs, crates/openhellod/src/plugin_loader.rs
- Model: claude-sonnet-5
- Effort: high
- Notes: depends on T-001, T-002, T-003, T-007 (loads their `.so` outputs via `dlopen`). D-Bus reply shapes
  never carry raw embeddings/templates (P-003) — only booleans, UIDs, and opaque session handles.

## T-010 — openhellod: polkit authorization on sensitive calls [done]

- Refs: AC-013, P-009
- Files: crates/openhellod/src/polkit.rs, crates/openhellod/io.openhello.Biometrics1.policy
- Model: claude-sonnet-5
- Effort: medium
- Notes: depends on T-009. Covers `EnrollBegin`/`EnrollCapture`/`EnrollCommit`/`EnrollDiscard`.

## T-011 — openhellod: logging redaction [done]

- Refs: AC-015, P-010
- Files: crates/openhellod/src/logging.rs
- Model: claude-sonnet-5
- Effort: low
- Notes: depends on T-009. Structured logging layer that statically excludes frame/embedding/template fields.

## T-012 — openhello-cli: v1a test harness [done]

- Refs: US-001, US-002, US-003, US-008
- Files: crates/openhello-cli/Cargo.toml, crates/openhello-cli/src/main.rs
- Model: claude-sonnet-5
- Effort: medium
- Notes: depends on T-009, T-010. Enroll/Verify/Identify/Purge over D-Bus — the v1a stand-in for PAM/login.

## T-013 — swtpm + recorded-frame fixture test infrastructure [done]

- Refs: AC-001, AC-005, AC-007, AC-009
- Files: tests/fixtures/README.md, tests/support/swtpm_harness.rs, tests/support/frame_fixtures.rs
- Model: claude-sonnet-5
- Effort: medium
- Notes: depends on T-001. Recorded IR-frame fixtures come from the developer's own camera only; any public
  NIR dataset used for calibration stays local and out of the repo (licensing, see architecture grilling).

## T-057 — Frontal-sample enrollment replaces the 6-pose protocol [done]

- Refs: AC-001, AC-002, AC-003, AC-004, AC-048, AC-049, ASM-002, ASM-017
- Files: crates/engine-adapter-face/src/engine.rs, crates/engine-adapter-face/src/ffi.rs, crates/openhello-plugin-abi/src/lib.rs, crates/openhellod/src/backends.rs, crates/openhellod/src/plugin_loader.rs, crates/openhellod/tests/default_target_far.rs
- Model: claude-sonnet-5
- Effort: medium
- Notes: depends on T-004. 6 spaced near-frontal samples, one 20 s window, no head movement. The template keeps 6
  embeddings so the FAR split and the CBSR NIR calibration are unchanged. `BucketAlreadyFilled` became
  `TooSoon`; the D-Bus verdict string `pose-already-captured` became `too-soon`.

## T-058 — Enrollment guidance: distance, centering and plain-language CLI messages [done]

- Refs: AC-050, AC-051, AC-052, AC-053, ASM-018
- Files: crates/engine-adapter-face/src/enrollment_quality.rs, crates/openhello-cli/src/lib.rs
- Model: claude-sonnet-5
- Effort: medium
- Notes: depends on T-057. Adds the verdicts `move-left|right|up|down`, `too-close`, `too-far` end to end (plugin ABI
  version 4, daemon D-Bus strings, CLI sentences). The same verdicts feed the future enrollment GUI.

## T-059 — Enrollment guidance: face brightness [done]

- Refs: AC-054, AC-055, ASM-019
- Files: crates/engine-adapter-face/src/enrollment_quality.rs
- Model: claude-sonnet-5
- Effort: low
- Notes: depends on T-058. Adds `too-dark` and `too-bright` (plugin ABI version 5) from the mean luma of the face box.
