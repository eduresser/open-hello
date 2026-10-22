# Spec: Fingerprint login v3

> feature: fingerprint-login-v3
> status: draft

<!--
  How to read this file (the format is checked by `onp-spec audit`):
  - US-xxx = user story · AC-xxx = acceptance criterion
    ASM-xxx = assumption · Q-xxx = open question
    They are trace codes: they tie the specification to the tasks and the tests.
  - Every user story needs at least one acceptance criterion.
  - Every acceptance criterion needs a complete Given/When/Then.
  - The codes are unique across the whole project (never reuse a number).
  - Assumptions and Open questions are REQUIRED: if there are none,
    write "None." — but be suspicious: almost every feature hides one.
-->

## Context

Users with a fingerprint reader can authenticate (`sudo`, polkit, lock screen) with a finger, through the same ticket, TPM-key signature and PAM module that the face already uses. The reader is driven by `fprintd` (libfprint) over D-Bus, as `arquitetura-linux.md` prescribes ("Sensor + Engine Adapter — impressão digital"), and the owner decided (2026-10-22): integrate through `fprintd`, run face and finger in parallel with the first match winning, and enroll through `openhello-cli`. The first plan used one command for face and finger; on 2026-10-22 the owner saw `enroll` start the camera and count poses before any finger step and asked for one command for each: `enroll face` and `enroll finger` become two subcommands (a bare `enroll` stays an alias of `enroll face`).

## Stories

### US-019 — Authenticate with a finger

As a user with an enrolled finger, I want a matching finger to authenticate me where the face does, so that I can use the reader instead of typing the password.

#### AC-048 — A matching finger passes a PAM authentication without a password

- **Given** a user with an enrolled finger, a provisioned TPM key and `pam_openhello` in the stack
- **When** the user touches the reader with that finger during `sudo`
- **Then** the authentication succeeds without a password prompt (`openhellod` `Verify` returns accepted, a ticket is delivered to `openhello-keyd`, and the challenge is signed by the TPM key)

#### AC-049 — A different finger is never accepted and falls through to the password

- **Given** a user with an enrolled finger
- **When** the reader reports no match three times for a request
- **Then** the request is refused at once, no ticket is delivered and the password prompt appears

#### AC-050 — A missing fprintd, reader or enrolled finger falls through

- **Given** `fprintd` is absent, no reader is present, or the user has no enrolled finger
- **When** a request is made
- **Then** the fingerprint side ends without an error shown to the user and the face (or the password) still works, within the existing 5 s detection of a missing service

#### AC-051 — A fingerprint match is the only thing that produces a ticket

- **Given** a request where the reader reports an error, a disconnect, a retry or no match
- **When** the request ends
- **Then** no ticket is delivered to `openhello-keyd` and the fingerprint is never accepted as a credential by itself (P-003)

### US-020 — Face and finger at the same time

As a user, I want the camera and the reader to listen together and the first match to win, so that I do not have to choose a method.

#### AC-052 — The first modality to match wins and the other is stopped

- **Given** a user with an enrolled face and finger
- **When** one modality matches while the other is still waiting
- **Then** the request is accepted once, a single ticket is delivered, and the other modality is cancelled (the camera and the IR emitter are released, or the reader device is released)

#### AC-053 — One time budget and three no-match results per request cover both modalities

- **Given** a request with face and finger active
- **When** neither matches
- **Then** the request ends after the existing 10 s waiting budget, and the fingerprint side stops after three no-match results, falling through to the password

#### AC-054 — A caller that leaves cancels the reader as well

- **Given** an authentication request waiting for a finger
- **When** the caller disappears from the bus or is interrupted (Ctrl+C in `sudo`)
- **Then** the reader is released within a second, and a match that arrives afterwards delivers no ticket (same rule as AC-040)

### US-021 — Enroll a finger with its own command

As a user, I want a command that registers only my finger and leaves the camera alone, so that I can add a finger without redoing the face.

#### AC-055 — Enrolling a finger goes through openhellod and polkit

- **Given** a user at an active session with a reader and a face enrollment flow already available
- **When** they run `openhello-cli enroll finger` and choose a finger (any of the ten, one at a time)
- **Then** the five reader stages are shown as progress, the finger is stored by `fprintd` for that user, other enrolled fingers stay, and the TPM key exists afterwards (P-009 applies: an unauthorized caller is refused)

#### AC-056 — An enrollment whose owner leaves is discarded

- **Given** a finger enrollment in progress
- **When** the CLI is interrupted or the caller leaves the bus
- **Then** the reader is released and an already enrolled finger of that user is left intact

#### AC-057 — The CLI reports when there is no reader

- **Given** a machine with no fingerprint reader
- **When** the user runs `openhello-cli enroll finger`
- **Then** one plain line says no fingerprint reader was found and nothing is enrolled or changed

#### AC-060 — The face command never touches the reader and the finger command never touches the camera

- **Given** a user with a camera and a reader
- **When** they run `openhello-cli enroll face`, or `openhello-cli enroll finger`
- **Then** `enroll face` starts only the face enrollment and offers no finger step, and `enroll finger` starts no camera or face enrollment, and a user with no face enrolled still gets the TPM key provisioned after the first finger

### US-022 — Purge and logs

As a user, I want purge and logs to treat fingerprints with the same care as the face, so that nothing biometric is left behind or leaked.

#### AC-058 — Purge removes the enrolled fingers and the key

- **Given** a user with an enrolled finger and a TPM key
- **When** `openhellod` `Purge` runs for that user
- **Then** every enrolled finger is deleted in `fprintd` (`DeleteEnrolledFingers`), the TPM key and Protectors are destroyed (P-008), and a failure of either step is reported as incomplete

#### AC-059 — Logs never contain fingerprint data

- **Given** any build and any outcome of a fingerprint request or enrollment
- **When** the logs and journal output are read
- **Then** they carry only counts, labels and the uid (outcome, attempts), never scan data, template data or `fprintd` print contents (P-010)

## Out of scope

- A fingerprint engine of our own, or talking to `libfprint` directly (owner decision, 2026-10-22).
- Sealing fingerprint templates in our TPM-sealed store: `fprintd` keeps them in `/var/lib/fprint` (see ASM-019).
- A persistent failure counter across requests (same deferral as `credential-login-v1b` ASM-016).
- Selecting a specific finger at authentication time; `VerifyStart("any")` is used.
- Presence or liveness checks of the finger beyond what the sensor driver does.
- Phone sensors as a reader; they cannot be exposed to Linux.

## Assumptions

<!-- What we are ASSUMING without confirmation. Status: open | confirmed | invalidated -->

| ID | Assumption | Status | Resolution |
|---|---|---|---|
| ASM-017 | `fprintd` 1.94 keeps the D-Bus API that the shim uses (`Manager.GetDefaultDevice`, `Device.Claim`/`Release`, `VerifyStart`/`VerifyStop`, `VerifyStatus`, `EnrollStart`/`EnrollStatus`, `DeleteEnrolledFingers`). | open | Seen working from `fprintd-enroll` and `fprintd-verify` on the VM (2026-10-22); other `fprintd` versions on other distributions are not tested. |
| ASM-018 | `openhellod` runs as root, so it may `Claim` the reader for any user and pass the user name, which is what polkit allows for root. | open | The unit has no `User=` line today. To confirm on the VM when the shim claims a device for uid 1000. |
| ASM-019 | Two constitution principles do not reach fingerprints and need an explicit exception: P-006 (templates live in `fprintd`'s storage, not in our TPM-sealed AEAD store) and P-007 (the false-accept rate is decided inside `libfprint`, not by our calibration). | confirmed | Owner approved on 2026-10-22; the exceptions are written into `.spec/constitution.md` by T-061. P-003 still holds (AC-051). |
| ASM-020 | The libfprint virtual device on the VM proves the D-Bus and PAM protocol (enroll, match, no-match), not the behaviour of a real sensor (quality retries, finger-off timing, driver quirks). | confirmed | Validated 2026-10-22: `enroll-completed`, `verify-match` with the enrolled finger, `verify-no-match` with another (`virtual-fingerprint-reader-vm` memory). A real USB reader is optional later evidence. |
| ASM-021 | Face and finger can be armed in one `Verify` call without contention, because they use different hardware (the IR camera and the reader) and one polkit/D-Bus identity. | open | Not proven; the concurrency in `openhellod` (a single core lock today) must allow the finger wait while the camera loop runs. |

## Open questions

<!-- What we still do not know. Status: open | answered -->

| ID | Question | Status | Answer |
|---|---|---|---|
| Q-004 | Should `openhello-cli enroll` accept more than one finger per user, or only one? | answered | Several, as Windows Hello does (owner asked to follow Windows). REA 2026-10-22 on build 10.0.26100, confidence medium-high: `wbiosrvc.dll` `EnumEnrollmentsExecute` carries `subFactorCount`, `winbio.dll.mui` has sub-factor enrollment errors ("identity and sub-factor are already enrolled") and `BioCredProv.dll` has `subFactorCount`. No explicit maximum was found in the binaries, so the limit is `fprintd`'s (one print per finger). |
| Q-005 | If `fprintd` reports `verify-unknown-error` or `verify-disconnected` mid-request, should the request keep waiting for the face, or end and fall through to the password? | answered | Keep waiting for the face; only the fingerprint side ends. Windows basis (REA 2026-10-22, confidence medium-high): `BioCredProv.dll` maps the fingerprint state to `BioDeviceNotAttached`, `BiometricUnitMissing`, `NoFPEnrollments`, `FailedToStartCapture` and `FatalSensorError`, and its errors are logged through WIL without a fail-fast; `facecredentialprovider.dll` disables only its own listener (`BioListenerDisabledDueTo...`) and can re-enable it. Providers are separate COM objects, so the PIN, password and face stay available. Not proven in code: that `GetCredentialState` hides the tile on `FatalSensorError`. A fingerprint infrastructure error is not one of the three attempts (as AC-043). |
