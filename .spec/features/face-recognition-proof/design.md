# Design: Face recognition proof

> feature: face-recognition-proof

## Workspace layout (Rust)

```
Cargo.toml                         # workspace
crates/
  openhello-plugin-abi/            # shared C-ABI contract (no logic)
  openhellod/                      # binary: daemon, D-Bus service, plugin loader, dispatch
  sensor-adapter-ir/                # cdylib: V4L2 IR capture + emitter activation
  engine-adapter-face/              # cdylib: AuraFace embedding, FAR calibration, liveness
  storage-adapter-templates/        # cdylib: AEAD template store, TPM-sealed storage key
  openhello-cli/                    # binary: v1a test harness (Enroll/Verify/Identify/Purge)
```

## Components

- **`openhello-plugin-abi`** — `#[repr(C)]` vtable structs (`SensorInterface`, `EngineInterface`,
  `StorageInterface`) and the three entry-point symbol names
  (`openhello_sensor_interface`/`_engine_interface`/`_storage_interface`), mirroring WinBio's
  `WbioQuery<Layer>Interface` contract from the Windows RE. No behavior lives here — only the contract both
  `openhellod` and every adapter crate compile against.
- **`openhellod`** — loads the three adapter `.so` files via `dlopen`/`dlsym`, owns the D-Bus service
  `io.openhello.Biometrics1` (`zbus`), session/focus arbitration, and the `EnrollBegin/Capture/Commit/Discard`,
  `Verify`, `Identify` dispatch. Enforces polkit authorization (AC-013/P-009) before creating an enrollment
  session. Never holds key material — only calls into Storage Adapter for encrypted reads/writes and into
  Engine Adapter for match decisions.
- **`sensor-adapter-ir`** — opens the IR V4L2 node, issues the UVC Extension Unit control to activate the
  illuminator before the first frame (AC-011), exposes a frame stream to the daemon.
- **`engine-adapter-face`** — YuNet detection + AuraFace (`glintr100`) embedding via `ort` (ONNX Runtime),
  pose-bucket/blur/occlusion quality gating for enrollment (AC-001–AC-004), FAR-calibrated match decision
  (AC-005/AC-006/P-007), 1:N identify (AC-007/AC-008), and the micro-motion + focus-variance liveness
  heuristic (AC-012).
- **`storage-adapter-templates`** — per-UID template file store under AEAD (AC-009/AC-010/P-006). The
  encryption key is sealed by a dedicated TPM2 object created directly via `tpm2-tools`/`tss-esapi`, scoped
  only to this store — **not** the user credential key that `openhello-keyd` will own in v1b. Purge
  (AC-014/P-008) deletes this TPM key object, then unlinks the encrypted file.
- **`openhello-cli`** — the v1a test harness: invokes `EnrollBegin/Capture/Commit`, `Verify`, `Identify`,
  `Purge` over D-Bus, for manual and automated (swtpm + recorded-frame) testing. Stands in for the PAM/login
  integration that v1b will build.

## v1a simplification, explicitly scoped

`Verify`/`Identify` need to know which account's template(s) to check. In the eventual login flow (v1b),
the D-Bus caller's identity comes from the greeter/PAM session. In v1a there is no login integration yet, so
`openhello-cli` passes the target UID explicitly (or omits it for `Identify`, which checks all enrolled
UIDs). This is a test-harness simplification, not a security boundary — it does not need to be revisited
until v1b designs the real caller-identity story for the login path.

## Testing approach

- **TPM**: tests run against `swtpm` (software TPM), never the host's physical TPM.
- **Camera**: tests run against recorded IR-frame fixtures captured from the developer's own camera (see
  `tests/fixtures/`), never a live camera and never a third-party dataset (licensing — see architecture
  grilling). Public NIR datasets are used only for offline, local, non-redistributed accuracy/FAR
  calibration experiments, never committed to the repo.
- **Multi-account `Identify` (AC-007)**: exercised with multiple synthetic UIDs enrolled from distinct
  fixture identities (dataset-derived, used locally) plus, where available, a second real enrolled person.
