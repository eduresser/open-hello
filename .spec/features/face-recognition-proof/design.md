# Design: Face recognition proof

> feature: face-recognition-proof

## Workspace layout (Rust)

```
Cargo.toml                         # workspace
crates/
  openhello-plugin-abi/            # shared C-ABI contract (no logic)
  openhellod/                      # binary: daemon, D-Bus service, plugin loader, dispatch
  sensor-adapter-ir/                # cdylib: V4L2 IR capture + emitter activation
  engine-adapter-face/              # cdylib: AuraFace embedding, FAR calibration
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
- **`sensor-adapter-ir`** — opens the IR V4L2 node and returns only IR-illuminated frames (AC-011, AC-039). For a
  camera that exposes the Microsoft face-auth XU (GUID `0f3f95dc-2632-4c4e-92c9-a04782f43bc8`, selector 6, found by
  GUID in the USB descriptors) it reads the control before every capture, writes alternating-illumination mode 2
  when the current mode is not 2, confirms it by read-back, and admits frames only from a stream that alternates
  lit/unlit (unlit frames dropped); a refused write, an unconfirmed write or a stream that never alternates is an
  explicit error. Cameras with no controllable emitter keep the brightness probe (a vendor XU from
  `OPENHELLO_IR_EMITTER=unit:selector:hex` is activated when the stream is dark, else an explicit error). The
  failure reason is exported through the optional `openhello_sensor_last_error` symbol and logged by the daemon.
  MIPI/IPU6 cameras are out of scope.
- **`engine-adapter-face`** — YuNet detection + AuraFace (`glintr100`) embedding via `ort` (ONNX Runtime),
  frontal-sample/blur/occlusion quality gating for enrollment (AC-001–AC-004, AC-048, AC-049), FAR-calibrated match decision
  (AC-005/AC-006/P-007), and 1:N identify (AC-007/AC-008). It has no anti-spoofing in v1a (ASM-005).
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

## Authentication flow (Verify / Identify)

`openhellod` runs one engine authentication session per request and feeds it one frame at a time, stopping at
the first decision instead of capturing a fixed burst:

- The engine detects the face in each lit frame, embeds it and matches it against the candidates (one
  template for Verify, all enrolled templates for Identify).
- The target FAR (default `1e-5`) is divided by the frame budget (16 scored frames) and, inside the matcher,
  by the number of enrolled embeddings, so accepting on the first passing frame does not raise the overall
  false-accept rate. This keeps the "reject the right person rather than accept the wrong one" stance.
- The session ends as Accepted at the first matching frame, as Rejected when the frame budget is spent,
  and the daemon gives up after 48 captured frames. Frames with no detected face do not consume the budget.
- The Sensor Adapter returns lit frames only and hands over the lit frames it saw while probing the stream, so
  the first decision does not wait for a fresh burst. It opens the camera on demand and releases it after 3 s
  without a capture request.
- Windows Hello (see `docs/windows-hello-arquitetura.md`) also scores frame by frame and stops at the first
  frame that passes; its anti-spoofing works on IR appearance. v1a has none (ASM-005): the planned step is an
  appearance classifier trained on own captures, which needs the Sensor Adapter to hand over the unlit frame.

## Testing approach

Live check on the target hardware (VM with the camera passed through, 2026-10-20): two people enrolled under
different UIDs; each verified and identified as themselves 10/10 and was rejected against the other's template
10/10 (AC-005 to AC-008). Decisions take ~0.2 s with a warm camera and ~1 s on a cold start.

- **TPM**: tests run against `swtpm` (software TPM), never the host's physical TPM.
- **Camera**: tests run against recorded IR-frame fixtures captured from the developer's own camera (see
  `tests/fixtures/`), never a live camera and never a third-party dataset (licensing — see architecture
  grilling). Public NIR datasets are used only for offline, local, non-redistributed accuracy/FAR
  calibration experiments, never committed to the repo.
- **Multi-account `Identify` (AC-007)**: exercised with multiple synthetic UIDs enrolled from distinct
  fixture identities (dataset-derived, used locally) plus, where available, a second real enrolled person.
