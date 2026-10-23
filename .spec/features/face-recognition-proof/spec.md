# Spec: Face recognition proof

> feature: face-recognition-proof
> status: draft

## Context

Before building the TPM/PKCS#11 credential layer (`openhello-keyd`) and wiring it into login, open-hello
needs standalone proof that `openhellod` can reliably enroll and recognize a face through this laptop's IR
camera. This is roadmap phase v1a: capture, matching, and encrypted storage, driven by a CLI/D-Bus client,
with no PAM/login integration yet.

## Stories

### US-001 — Quality-gated face enrollment

As a laptop owner, I want to enroll my face by looking at the IR camera for a few seconds, with automatic
quality checks, so that only usable, near-frontal samples become my stored biometric template and enrollment
never asks me to move my head.

#### AC-001 — Enrollment succeeds once enough frontal samples are collected

- **Given** an enrollment session is in progress for a user with no existing template
- **When** the user presents frames that supply 6 near-frontal samples, spaced apart in time, with acceptable
  sharpness and no detected occlusion
- **Then** `EnrollCommit` succeeds and a template of those 6 embeddings is persisted for that user

#### AC-002 — Blurred frames are discarded during capture

- **Given** an enrollment session is capturing frames
- **When** a captured frame's sharpness score falls below the configured blur threshold
- **Then** the frame is discarded and does not count as a sample

#### AC-003 — Occluded frames are discarded during capture

- **Given** an enrollment session is capturing frames
- **When** a captured frame is flagged by the occlusion detector (face/mouth/nose)
- **Then** the frame is discarded and does not count as a sample

#### AC-004 — Enrollment fails after the capture window elapses

- **Given** an enrollment session has not collected 6 samples
- **When** 20 seconds elapse since the first captured frame of the session (time spent before capture starts, such as choosing a PIN, does not count)
- **Then** the enrollment session fails with an explicit timeout error and no template is persisted

#### AC-048 — Non-frontal frames are discarded during capture

- **Given** an enrollment session is capturing frames
- **When** a captured frame's estimated yaw is more than 20 degrees away from frontal
- **Then** the frame is discarded and does not count as a sample

#### AC-049 — Samples come from distinct moments

- **Given** an enrollment session has just accepted a sample
- **When** another valid frame arrives less than 200 ms later
- **Then** the frame is discarded as too soon and does not count as a sample

#### AC-050 — A face too far from the camera is discarded with guidance

- **Given** an enrollment session is capturing frames
- **When** the detected face is shorter than 42% of the frame height
- **Then** the frame is discarded and the verdict tells the client the face is too far

#### AC-051 — A face too close to the camera is discarded with guidance

- **Given** an enrollment session is capturing frames
- **When** the detected face is taller than 68% of the frame height
- **Then** the frame is discarded and the verdict tells the client the face is too close

#### AC-052 — An off-center face is discarded with a direction

- **Given** an enrollment session is capturing frames
- **When** the center of the detected face is more than 10% of the frame size away from the frame center
- **Then** the frame is discarded and the verdict tells the client to move left, right, up or down, along the
  larger offset

#### AC-054 — A face in the dark is discarded with guidance

- **Given** an enrollment session is capturing frames
- **When** the average brightness inside the detected face is below 40 (of 255)
- **Then** the frame is discarded and the verdict tells the client the image is too dark

#### AC-055 — A washed-out face is discarded with guidance

- **Given** an enrollment session is capturing frames
- **When** the average brightness inside the detected face is above 215 (of 255)
- **Then** the frame is discarded and the verdict tells the client the image is too bright

#### AC-053 — The CLI tells the user what to do

- **Given** `openhello-cli enroll` is capturing frames
- **When** the daemon reports a guidance verdict (face not detected, move left/right/up/down, too close, too far,
  too dark, too bright, keep looking forward, blurred, occluded)
- **Then** the CLI prints a plain sentence for it, and does not repeat an identical line

### US-002 — Verify a single claimed identity

As a user with an enrolled face, I want the system to confirm it is really me, so that I can authorize a
sensitive action without typing a password.

#### AC-005 — A matching face is accepted at the target false-accept rate

- **Given** a user has an enrolled face template
- **When** that same user's face is presented for `Verify`
- **Then** the match is accepted because the calibrated match score meets the configured target false-accept
  rate (default `1e-5`)

#### AC-006 — A non-matching face is rejected

- **Given** a user has an enrolled face template
- **When** a different face (enrolled under another account, or never enrolled) is presented for `Verify`
  against that user's identity
- **Then** the match is rejected

### US-003 — Identify among multiple enrolled accounts

As a user on a shared laptop, I want the system to recognize which of several enrolled accounts is looking
at the camera, so that I don't have to select my username before authenticating.

#### AC-007 — Identify resolves to the correct account among several enrolled users

- **Given** at least two different Linux accounts have enrolled face templates
- **When** one of those users' faces is presented for `Identify`
- **Then** `Identify` returns that user's account identifier and no other

#### AC-008 — Identify rejects an unenrolled face

- **Given** at least one account has an enrolled face template
- **When** a face with no enrolled template is presented for `Identify`
- **Then** `Identify` returns no match

### US-004 — Encrypted, tamper-evident template storage

As the system, I want enrolled templates stored under authenticated encryption with a TPM-sealed key, so
that template data stays confidential and any tampering is detected rather than silently accepted.

#### AC-009 — Template files are stored as authenticated ciphertext

- **Given** a template has been enrolled
- **When** the on-disk template file is inspected directly
- **Then** its content is ciphertext carrying an authentication tag, never a raw embedding

#### AC-010 — Tampered ciphertext is rejected, not silently decrypted

- **Given** an encrypted template file exists
- **When** any byte of the stored ciphertext or its authentication tag is modified
- **Then** decryption fails and the template is treated as unavailable for matching

### US-005 — IR capture with the emitter active

As the system, I want the Sensor Adapter to return only IR-illuminated frames, whatever the camera model, so
that matching runs against a trustworthy IR signal instead of one lit only by ambient light.

#### AC-011 — Capture returns only illuminated frames

- **Given** the IR camera node is available
- **When** a capture session begins
- **Then** every frame returned is IR-illuminated: a camera that already illuminates (steadily or by
  alternating lit/unlit frames) is left untouched and its unlit frames are dropped; a camera whose stream is
  dark gets its emitter control activated (Microsoft face-auth control, or a configured vendor control) and
  verified; if illumination cannot be established, an explicit error is surfaced rather than unlit frames

### US-007 — Authorization on sensitive biometric operations

As the device owner, I want enrollment and deletion of biometric identities restricted to the authorized
session owner or root, so that another local process cannot plant its own face as a valid identity.

#### AC-013 — An unauthorized caller cannot start enrollment

- **Given** a D-Bus caller is neither the active session's own user nor root
- **When** that caller invokes `EnrollBegin` on `io.openhello.Biometrics1`
- **Then** the call is refused with a polkit authorization error and no enrollment session is created

### US-008 — Explicit, irreversible data purge

As a user, I want to permanently delete my biometric data on demand, so that I can be confident no usable
copy remains if I stop using the system.

#### AC-014 — Purge destroys the TPM key protecting a user's templates

- **Given** a user has enrolled templates protected by a TPM-sealed storage key
- **When** that user's data is purged
- **Then** the TPM key object is deleted and the encrypted template file is removed, leaving any prior
  ciphertext permanently undecryptable (crypto-shredding)

### US-009 — No raw biometric data in logs

As a privacy-conscious user, I want assurance that frames, embeddings, and templates are never written to
logs, so that debugging or crash output cannot leak my biometric data.

#### AC-015 — Debug/error logging never contains raw frame or template bytes

- **Given** logging is enabled at the most verbose configured level
- **When** a full enrollment and verify cycle runs
- **Then** no log line contains raw frame pixel data, embedding vectors, or decrypted template bytes

## Out of scope

- `openhello-keyd`, TPM-sealed asymmetric key creation, the PKCS#11 token, and the Protector/`authValue`
  mechanism (roadmap v1b).
- PAM/`pam_pkcs11` login integration and the `C_Login` PIN/biometric shim (roadmap v1b).
- The one-shot consent API (`io.openhello.ConsentVerifier1`) (roadmap v3).
- Fingerprint Sensor/Engine Adapter via `fprintd` (roadmap v3, no hardware available to validate today).
- TPM key backup/recovery code generation and verification (roadmap v1b, lives in `openhello-keyd`).
- Anti-spoofing of any kind (printed photos, screens, masks). Accepted risk in v1a, see ASM-005; the planned
  mitigation is an appearance classifier on the lit/unlit IR pair, trained on captures from the target camera.
- Greeter UX (roadmap v2).

## Assumptions

| ID | Assumption | Status | Resolution |
|---|---|---|---|
| ASM-001 | AuraFace (`glintr100`, IResNet100+ArcFace) run zero-shot on grayscale-as-3-channel IR input reaches acceptable accuracy on this camera without fine-tuning, within the ~2-week evaluation budget; SFace is the fallback before a Howdy-style approach. | open | Partial evidence on `2b7e:c757` (2026-10-20, two enrolled people, 60 attempts, frame-by-frame decision at target FAR 1e-5): each person verified 10/10 and identified 10/10 as themselves, and the other person's template was rejected 10/10 in both directions. Two people on one camera do not measure FAR or accuracy; kept open until more people are tested. |
| ASM-002 | The enrollment protocol values (6 samples, 20 s window, 200 ms spacing, 20 degree yaw limit, blur threshold) are adjustable defaults, not final UX-tuned numbers. | confirmed | Supersedes the earlier 6-yaw-bucket, 60 s x 3 attempts protocol, which on this camera often stalled at 4-5 buckets. Evidence for frontal-only enrollment: reverse engineering of the Windows Hello enrollment UI (`BioEnrollmentUI.dll`, `WinBioDataModel.dll`) shows no head-turn text, symbol or animation, and every directional reject hint is shown as the generic "face not detected" message; Microsoft documents a +-15 degree yaw requirement for recognition. Product owner decision: prefer a false reject over a false accept. |
| ASM-003 | `Identify`/`Verify` match results are keyed by Linux UID, matching the Storage Adapter's per-UID template layout already decided in the architecture docs. | open | — |
| ASM-004 | Illumination of the IR emitter can be established generically, without a per-model payload. | confirmed | The Microsoft XU `{0f3f95dc-2632-4c4e-92c9-a04782f43bc8}` (selector 6, face-auth) has the mode in byte 2: on `2b7e:c757` the camera comes up in mode 1 (emitter off, ambient frames of luma 31-148) after every power-up or reset, while default and maximum are mode 2 (alternating lit/unlit, luma ~53 vs ~7, IR dot blinking). Owner rule (2026-10-21, as Windows Hello): a controllable emitter is on whenever the camera is in use and capture fails closed otherwise. The Sensor Adapter therefore reads the control by GUID before every capture, writes mode 2 with read-back confirmation when the current mode is not 2 (no environment switch; `OPENHELLO_IR_EMITTER_ALLOW_WRITE` is obsolete and ignored), and admits frames only from a stream that alternates lit/unlit; cameras without a controllable emitter keep the brightness rule, and a vendor XU from `OPENHELLO_IR_EMITTER` is still honoured. Write with read-back verified by hand on hardware via `UVCIOC_CTRL_QUERY`; some cameras are reported to hang on writes. |
| ASM-005 | A printed photo of an enrolled user can be accepted by `Verify`/`Identify` in v1a. | confirmed | Accepted by the product owner. The micro-motion gate was removed after measurement on `2b7e:c757`: it rejected 39% of 10-frame windows of a still real face and only 15% of a propped small photo, because landmark jitter normalized by eye distance grows for small faces. Screens are already blank in IR. Laser prints are a known weakness of NIR systems (Idiap, 97-100% success). |
| ASM-017 | The numeric defaults (20 degree yaw limit from the five-landmark heuristic, 200 ms spacing, 20 s window) let a still owner reach 6 samples without stalling, while the verify threshold stays at the existing CBSR NIR calibration (target FAR 2e-4). | open | Chosen from the +-15 degree Windows requirement plus margin for landmark jitter; measure on `2b7e:c757` with `OPENHELLO_SCORE_LOG=1` before treating as final. |
| ASM-018 | The enrollment-only fit limits (face height 42%-68% of the frame, center within 10%) match the guide oval of the window (about 55% of the preview height) and fit the owner at 40-60 cm; the raw IR frame is not mirrored. | open | The first limits (30%-85%, 20%) let a barely fitted face pass in the VM test (2026-10-23), so they were tightened. Authentication is not affected: only enrollment applies them. They can be tuned without rebuilding with `OPENHELLO_ENROLL_MIN_FACE`, `OPENHELLO_ENROLL_MAX_FACE` and `OPENHELLO_ENROLL_MAX_OFFSET`. |
| ASM-019 | The face-brightness limits (40 and 215 of 255) separate a usable IR face from an unlit or saturated one on this camera. | open | Initial values; measure the owner's face mean with the emitter on at 40-60 cm and in a bright room, then adjust. |

## Open questions

| ID | Question | Status | Answer |
|---|---|---|---|
| Q-001 | Which liveness heuristic should AC-012 implement? | dropped | No heuristic in v1a. Micro-motion was measured on the target camera and removed (ASM-005); an IR-appearance classifier needs own spoof captures and a sensor change to deliver the unlit frame. |
