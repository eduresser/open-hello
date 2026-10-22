# Constitution — v1.1.0

<!--
  The project's non-negotiable principles. They are not style: they are constraints.
  P-xxx = principle (trace code, like US/AC/T).
  Levels: [MUST] required · [SHOULD] strong · [MAY] allowed/explicit.
  Every [MUST] needs an executable check — otherwise the audit reports
  "principle without check" (PRINCIPLE_WITHOUT_CHECK). Formats:
    - check(gate): satisfied by the audit itself (only for "meta" principles)
    - check(test): @principle:P-xxx
    - check(forbidden): `regex` in `glob`
    - check(required): `regex` in `glob`
-->

## P-001 [MUST] Every requirement has executable proof

No feature is declared done without the audit in CI mode coming out clean (exit 0).
This principle is checked by the audit mechanism itself (AC_WITHOUT_TEST,
AC_WITHOUT_PROOF, TASK_DONE_WITHOUT_PROOF) — it needs no extra test from you.

- check(gate): intrinsic to the audit

## P-002 [SHOULD] Secrets never in code

Keys and passwords come from environment variables or TPM/PKCS#11 storage, never hard-coded.

- check(forbidden): `(api[_-]?key|password)\s*[:=]\s*['"][^'"]{8,}` in `crates/**/*.rs`

## P-003 [MUST] Biometric data is never the authentication secret

A face/fingerprint template only authorizes use of an existing TPM-sealed asymmetric key. It
never becomes, by itself, a credential accepted anywhere outside the local matching daemon.

- check(test): @principle:P-003

## P-004 [MUST] Private key material never leaves the TPM in plaintext

`openhello-keyd` only performs TPM-wrapped operations. No code path exports, logs, or returns
raw private key bytes; the PKCS#11 token surface exposes signing/decryption operations only.

- check(test): @principle:P-004

## P-006 [MUST] Template storage uses authenticated encryption with a TPM-sealed key

The template database is encrypted with a real AEAD primitive (confidentiality + integrity in the
same primitive). Any ciphertext tampering is detected, never silently accepted.

Scope: the face template database that open-hello owns. Fingerprint templates are kept by `fprintd`
in its own storage and are outside this principle (owner decision 2026-10-22, `fingerprint-login-v3` ASM-019).

- check(test): @principle:P-006

## P-007 [MUST] Matching is calibrated against a target false-accept rate, never an arbitrary distance cutoff

The public match/verify API is parameterized by a target FAR (default `1e-5`), with an internal
calibration layer converting the model's raw score into that unit. No uncalibrated "distance >
magic number" check ships as the decision boundary.

Scope: the face engine. The fingerprint false-accept rate is decided inside `libfprint`, which does not
expose it, so fingerprint matching is outside this principle (owner decision 2026-10-22,
`fingerprint-login-v3` ASM-019).

- check(test): @principle:P-007

## P-008 [MUST] Purge destroys usability of biometric data via key destruction, not just file deletion

Purging a user's data destroys the TPM key protecting their template store (crypto-shredding) and
removes the encrypted file. A purge that only deletes the file while the TPM key survives does not
satisfy this principle.

- check(test): @principle:P-008

## P-009 [MUST] Sensitive biometric D-Bus operations require authorization

`EnrollBegin`, `EnrollCapture`, `EnrollCommit`, and `EnrollDiscard` on `io.openhello.Biometrics1`
require polkit authorization tied to the calling session's own user (or root). No unauthenticated
local process may enroll a new biometric identity.

- check(test): @principle:P-009

## P-010 [MUST] No raw biometric data in logs or telemetry

Frame buffers, embeddings, and templates are never written to logs, journal output, or crash
diagnostics, in any build configuration.

- check(test): @principle:P-010
