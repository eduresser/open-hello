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

As a laptop owner, I want to enroll my face through the IR camera with automatic quality and pose checks,
so that only usable, well-covered samples become my stored biometric template.

#### AC-001 — Enrollment succeeds once all yaw buckets are covered

- **Given** an enrollment session is in progress for a user with no existing template
- **When** the user presents frames that fill all 6 configured yaw buckets with acceptable sharpness and no
  detected occlusion
- **Then** `EnrollCommit` succeeds and a template is persisted for that user

#### AC-002 — Blurred frames are discarded during capture

- **Given** an enrollment session is capturing frames
- **When** a captured frame's sharpness score falls below the configured blur threshold
- **Then** the frame is discarded and does not count toward any yaw bucket

#### AC-003 — Occluded frames are discarded during capture

- **Given** an enrollment session is capturing frames
- **When** a captured frame is flagged by the occlusion detector (face/mouth/nose)
- **Then** the frame is discarded and does not count toward any yaw bucket

#### AC-004 — Enrollment fails after 3 timed-out attempts

- **Given** an enrollment session has not achieved full yaw-bucket coverage
- **When** 60 seconds elapse without completing coverage, for 3 attempts in a row
- **Then** the enrollment session fails with an explicit timeout error and no template is persisted

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
that matching and liveness run against a trustworthy IR signal instead of one lit only by ambient light.

#### AC-011 — Capture returns only illuminated frames

- **Given** the IR camera node is available
- **When** a capture session begins
- **Then** every frame returned is IR-illuminated: a camera that already illuminates (steadily or by
  alternating lit/unlit frames) is left untouched and its unlit frames are dropped; a camera whose stream is
  dark gets its emitter control activated (Microsoft face-auth control, or a configured vendor control) and
  verified; if illumination cannot be established, an explicit error is surfaced rather than unlit frames

### US-006 — Basic liveness heuristic against flat-photo spoofing

As the system, I want a lightweight liveness check based on micro-motion and focus variance across a short
frame burst, so that a printed photo or a phone/monitor replay is rejected — a documented, intentionally
weaker substitute for Windows' hardware-isolated "Enhanced Sign-in Security".

#### AC-012 — A flat printed/screen photo fails the liveness check

- **Given** liveness checking is enabled
- **When** a flat photo (printed or shown on a screen) is presented instead of a live face, across a short
  capture burst
- **Then** the liveness heuristic detects the lack of natural micro-motion/focus variance and rejects it,
  independent of the embedding match score

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
- Greeter (GDM/SDDM) UX and anti-spoof hardening beyond the v1a heuristic (roadmap v2).

## Assumptions

| ID | Assumption | Status | Resolution |
|---|---|---|---|
| ASM-001 | AuraFace (`glintr100`, IResNet100+ArcFace) run zero-shot on grayscale-as-3-channel IR input reaches acceptable accuracy on this camera without fine-tuning, within the ~2-week evaluation budget; SFace is the fallback before a Howdy-style approach. | open | — |
| ASM-002 | The provisional enrollment protocol values (6 yaw buckets, 60s timeout, 3 attempts) are adjustable defaults, not final UX-tuned numbers. | confirmed | Accepted as provisional in the architecture grilling session; revisit after real usage data from this feature. |
| ASM-003 | `Identify`/`Verify` match results are keyed by Linux UID, matching the Storage Adapter's per-UID template layout already decided in the architecture docs. | open | — |
| ASM-004 | Illumination of the IR emitter can be established generically, without a per-model payload. | confirmed | This camera (`2b7e:c757`) alternates lit/unlit frames by default (measured mean luma ~7 vs ~60); the Microsoft XU `{0f3f95dc-2632-4c4e-92c9-a04782f43bc8}` (selector 6, face-auth) reports mode 2 as current/default/maximum. The Sensor Adapter reads that control by GUID, writes it only when the stream is dark and `OPENHELLO_IR_EMITTER_ALLOW_WRITE=1`, and falls back to a vendor XU from `OPENHELLO_IR_EMITTER`. Vendor GUID `63610682-…` is not needed. Write path untested on hardware; some cameras are reported to hang on writes. |

## Open questions

| ID | Question | Status | Answer |
|---|---|---|---|
| Q-001 | Which liveness heuristic should AC-012 implement? | answered | Micro-motion + focus-variance across a short frame burst (confirmed by product owner; reflectance-falloff and moiré-detection deferred to v2 hardening). |
