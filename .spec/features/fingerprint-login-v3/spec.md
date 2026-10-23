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

Users with a fingerprint reader manage their fingers with open-hello (`openhello-cli enroll finger`, status, purge) while the login itself stays with the system's own `fprintd` and `pam_fprintd`. Owner decision (2026-10-22): the native mechanism already unlocks `sudo`, polkit, the lock screen and the greeter with the same practical effect, and two owners of one reader conflict (seen on the KDE lock screen, where `pam_fprintd` takes the reader first), so open-hello is a manager for `fprintd` and does not authenticate fingers itself. The face keeps the TPM key, the ticket and the PAM module. Earlier in the feature a finger authentication path inside `openhellod` was built and verified on the VM (`sudo`, polkit); it is removed by T-063 and the stories that described it (US-019, US-020, AC-048 to AC-054) are retired.

## Stories

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

### US-023 — The finger is used by the system's own login

As a user, I want open-hello to stay out of the way of the system's fingerprint login and to tell me whether it is on, so that my enrolled finger works where the system supports it and open-hello never competes for the reader.

#### AC-061 — Enrolling a finger says whether the system's fingerprint login is on

- **Given** a user who has just enrolled a finger with `openhello-cli enroll finger`
- **When** the command ends
- **Then** one plain line says whether the system's PAM configuration uses the fingerprint reader for login (the module `pam_fprintd` appears in a PAM service file) and, when it does not, that enabling it is done with the system's own tools, and the command never edits the PAM configuration for the finger

#### AC-062 — An authentication request never takes the fingerprint reader

- **Given** a machine with a fingerprint reader and an enrolled finger
- **When** an authentication request runs through `pam_openhello` and `openhellod` `Verify`
- **Then** `openhellod` makes no `Claim`, `VerifyStart` or any other verification call to `fprintd`, so the system's own fingerprint login keeps the reader (the face decides alone)

## Out of scope

- Authenticating a finger inside open-hello: no ticket, no TPM signature and no parallel run with the face for the finger (owner decision, 2026-10-22; the system's `pam_fprintd` does it).
- A fingerprint engine of our own, or talking to `libfprint` directly (owner decision, 2026-10-22).
- Enabling or editing the system's PAM configuration for the fingerprint.
- Sealing fingerprint templates in our TPM-sealed store: `fprintd` keeps them in `/var/lib/fprint` (see ASM-019).
- Phone sensors as a reader; they cannot be exposed to Linux.
- A password prompt that stays available while face and finger listen in parallel, and a fingerprint wait with no time limit. Owner target (2026-10-22), deferred: it needs a mechanism inside `pam_openhello` that works in every PAM application, because the owner ruled out per-desktop code (no `kde-fingerprint`, `gdm-fingerprint` or other per-environment PAM services). Until a spike proves such a mechanism, face and finger each wait at most 10 s (ASM-022).

## Assumptions

<!-- What we are ASSUMING without confirmation. Status: open | confirmed | invalidated -->

| ID | Assumption | Status | Resolution |
|---|---|---|---|
| ASM-017 | `fprintd` 1.94 keeps the D-Bus API that the manager uses (`Manager.GetDefaultDevice`, `Device.Claim`/`Release`, `EnrollStart`/`EnrollStatus`/`EnrollStop`, `ListEnrolledFingers`, `DeleteEnrolledFingers2`). | open | Seen working from `fprintd-enroll` and `fprintd-verify` on the VM (2026-10-22); other `fprintd` versions on other distributions are not tested. |
| ASM-018 | `openhellod` runs as root, so it may `Claim` the reader to enroll or delete for any user and pass the user name, which is what polkit allows for root. | open | The unit has no `User=` line today. To confirm on the VM when the shim claims a device for uid 1000. |
| ASM-019 | Three constitution principles do not reach fingerprints and need an explicit exception: P-003 (the finger is accepted by the system's `pam_fprintd` as a yes or no answer, not as the authorization of a TPM key), P-006 (templates live in `fprintd`'s storage, not in our TPM-sealed AEAD store) and P-007 (the false-accept rate is decided inside `libfprint`, not by our calibration). | confirmed | Owner approved P-006 and P-007 on 2026-10-22 and P-003 the same day when the finger became the system's job; the exceptions are written into `.spec/constitution.md`. |
| ASM-020 | The libfprint virtual device on the VM proves the D-Bus and PAM protocol (enroll, match, no-match), not the behaviour of a real sensor (quality retries, finger-off timing, driver quirks). | confirmed | Validated 2026-10-22: `enroll-completed`, `verify-match` with the enrolled finger, `verify-no-match` with another (`virtual-fingerprint-reader-vm` memory). A real USB reader is optional later evidence. |
| ASM-021 | Face and finger can be armed in one `Verify` call without contention. | invalidated | Retired 2026-10-22: the finger no longer takes part in `Verify` (AC-062). |

| ASM-022 | The face waits at most 10 s per request on every surface, because PAM is serial and the module blocks the password prompt while it waits; the timing of the finger belongs to the system's `pam_fprintd`. | confirmed | Owner decision 2026-10-22: the parallel target (password always available, finger without limit) is wanted, but only through a universal mechanism in `pam_openhello`; per-desktop PAM services are refused. The research found (confidence medium, several primary sources were blocked) that sudo and polkit run one serial PAM conversation, that a `grosshack`-style thread plus password prompt inside the module is the only universal route, and that it is unproven (risks: terminal echo not restored, `pam_faillock` counting). The lock screen and GDM have native parallel services, but using them is per-desktop code. Next step is a separate feature starting with a spike on the VM. See the memory `parallel-password-and-biometrics-target`. |
| ASM-023 | The system's own `pam_fprintd` unlocks `sudo`, polkit, the lock screen and the greeter with the same practical effect as an open-hello finger path, without the TPM key. | confirmed | Owner reasoning 2026-10-22, supported by the research of that day (confidence medium): `pam_fprintd` returns a yes or no to PAM, which is all these surfaces need; the keyring still asks for the password, as with the face. Seen on the VM: the KDE lock screen runs `kde-fingerprint` with `pam_fprintd` and takes the reader before `openhellod` can (log of 2026-10-22 21:07:56). Loss accepted: the finger is not tied to the TPM key. |

## Open questions

<!-- What we still do not know. Status: open | answered -->

| ID | Question | Status | Answer |
|---|---|---|---|
| Q-004 | Should `openhello-cli enroll` accept more than one finger per user, or only one? | answered | Several, as Windows Hello does (owner asked to follow Windows). REA 2026-10-22 on build 10.0.26100, confidence medium-high: `wbiosrvc.dll` `EnumEnrollmentsExecute` carries `subFactorCount`, `winbio.dll.mui` has sub-factor enrollment errors ("identity and sub-factor are already enrolled") and `BioCredProv.dll` has `subFactorCount`. No explicit maximum was found in the binaries, so the limit is `fprintd`'s (one print per finger). |
| Q-005 | If `fprintd` reports `verify-unknown-error` or `verify-disconnected` mid-request, should the request keep waiting for the face, or end and fall through to the password? | answered | Moot since 2026-10-22, when the finger left `Verify` (AC-062). Earlier answer: keep waiting for the face; only the fingerprint side ends. Windows basis (REA 2026-10-22, confidence medium-high): `BioCredProv.dll` maps the fingerprint state to `BioDeviceNotAttached`, `BiometricUnitMissing`, `NoFPEnrollments`, `FailedToStartCapture` and `FatalSensorError`, and its errors are logged through WIL without a fail-fast; `facecredentialprovider.dll` disables only its own listener (`BioListenerDisabledDueTo...`) and can re-enable it. Providers are separate COM objects, so the PIN, password and face stay available. Not proven in code: that `GetCredentialState` hides the tile on `FatalSensorError`. A fingerprint infrastructure error is not one of the three attempts (as AC-043). |
