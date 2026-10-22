# Spec: Credential login v1b

> feature: credential-login-v1b
> status: draft

## Context

`openhellod` already enrolls and recognizes a face (feature `face-recognition-proof`). Today a successful
`Verify` is only a boolean. v1b turns it into authorization to use a per-user, TPM-sealed ECDSA P-256 key,
exposed as a PKCS#11 token, so that `sudo` and the lock screen can accept a face (or a PIN fallback) through the
existing `pam_pkcs11` stack. Scope is `sudo` and the lock screen; graphical login through a display-manager greeter is roadmap v2.

## Stories

### US-010 — Per-user TPM key provisioned after enrollment

As a laptop owner, I want a signing key created for me inside the TPM when I enroll my face, so that my face
can authorize a real cryptographic key instead of being a password-like secret.

#### AC-016 — Enrollment provisions a non-exportable P-256 key in the TPM

- **Given** a user with a committed face enrollment and no TPM key yet
- **When** `openhello-keyd` provisions the user's credential
- **Then** a TPM-resident ECDSA P-256 signing key exists for that user, created with `fixedtpm`, `fixedparent`
  and `sensitivedataorigin`, and the token lists exactly one key for that user

#### AC-017 — Provisioning twice never replaces an existing key

- **Given** a user who already has a provisioned key
- **When** provisioning is requested again
- **Then** the call reports the existing key and the key handle and public key are unchanged

#### AC-018 — Private key bytes are never exposed

- **Given** a provisioned key
- **When** any caller asks the `openhello-keyd` API or the PKCS#11 token to export or read the private key
  (including `CKA_VALUE`)
- **Then** the request is refused, the key reports as non-extractable and sensitive, and signing remains the
  only private-key operation offered

### US-011 — Face match authorizes key use through a short-lived ticket

As a laptop owner, I want the key to unlock only after a fresh, successful face match, so that nothing else on
the machine can use my key by claiming I was recognized.

#### AC-019 — A fresh ticket from a successful Verify unlocks the key

- **Given** a provisioned user and a successful `Verify` that produced a ticket
- **When** the PKCS#11 session logs in using that ticket
- **Then** login succeeds and the session can sign a challenge that verifies against the user's public key

#### AC-020 — An expired ticket is refused

- **Given** a ticket older than its time-to-live (default 5 seconds)
- **When** it is presented to `openhello-keyd`
- **Then** login is refused with an explicit expired-ticket error and the key stays locked

#### AC-021 — A ticket cannot be used twice

- **Given** a ticket that already unlocked a session
- **When** the same ticket is presented again
- **Then** the second use is refused and no second session is unlocked

#### AC-022 — Forged or foreign tickets are refused

- **Given** a ticket with a wrong signature, a ticket issued for another UID, or a ticket presented by a
  process that is not `openhellod`
- **When** it is presented to `openhello-keyd`
- **Then** it is refused and the key stays locked

#### AC-023 — A failed Verify produces no ticket

- **Given** a user whose face does not match (or a camera that returns no face)
- **When** `Verify` runs
- **Then** no ticket is issued and the key cannot be unlocked by biometrics

#### AC-024 — A template alone is never accepted as a credential

- **Given** a stored face template or a raw embedding for a user
- **When** it is presented to `openhello-keyd` or to the PKCS#11 token in place of a ticket or PIN
- **Then** it is refused, because biometric data only authorizes use of the TPM key through a ticket

### US-012 — PIN fallback with hardware-backed throttling

As a laptop owner, I want to unlock the same key with a PIN when the camera fails, and I want repeated wrong
guesses to be blocked by the TPM itself, so that a compromised process cannot reset the counter.

#### AC-025 — The correct PIN unlocks the key

- **Given** a provisioned user with a PIN set
- **When** the user logs in to the token with that PIN
- **Then** login succeeds and signing works

#### AC-026 — Repeated wrong PINs trigger the TPM lockout

- **Given** a provisioned user with a PIN set
- **When** wrong PINs are presented until the TPM dictionary-attack limit is reached
- **Then** further attempts, including the correct PIN, are refused with a lockout error until the TPM lockout
  recovers, and the counter is the TPM's, not a software counter

### US-013 — Face or PIN authenticates `sudo` and the lock screen

As a laptop owner on any Linux distribution and desktop, I want `sudo` and the lock screen to accept my face, so that I stop typing my password.

#### AC-027 — A matching face authenticates `sudo`

- **Given** an enrolled and provisioned user and a `sudo` PAM stack with the open-hello module
- **When** the user runs `sudo` and looks at the camera
- **Then** authentication succeeds without a password, by verifying a challenge signed with the TPM key

#### AC-028 — A matching face passes a lock screen's PAM authentication without a password

- **Given** an enrolled and provisioned user on a locked graphical session whose screen locker authenticates through PAM, with the open-hello module enabled once in the common PAM auth stack
- **When** the user looks at the camera
- **Then** the locker's own PAM service authenticates the face with no password, as the unprivileged user and through the same path as `sudo`, with no desktop-specific code, data or message in open-hello; the module acts for every local service except a compiled denylist of non-desktop services (`login`, `su`, `su-l`, `sshd`, `cron`, `crond`, `atd`, `passwd`, `chsh`, `chfn`, `runuser`, `runuser-l`, `other`) and stays silent for remote or headless sessions, root, and users without a registered credential; a miss, or an unavailable daemon, falls through to the password; completing the unlock afterwards is the locker's own behaviour

#### AC-029 — A different face is never accepted and falls through to the password

- **Given** an enrolled user's account and another person at the camera
- **When** authentication runs
- **Then** the open-hello module does not grant access and the stack continues to the next module (password
  prompt)

#### AC-030 — A missing daemon or camera falls through quickly

- **Given** `openhellod`, `openhello-keyd` or the camera is unavailable
- **When** authentication runs
- **Then** the open-hello module returns "ignore" within 5 seconds and the password prompt appears; a daemon that answers the call but stays silent is bounded by the attempt budget instead (AC-041)

### US-014 — Recovery code

As a laptop owner, I want a one-time recovery code, so that I can regain use of my key if the face and PIN
both stop working.

#### AC-031 — A recovery code is shown once at provisioning and unlocks the key

- **Given** a freshly provisioned user
- **When** provisioning completes
- **Then** a recovery code is returned exactly once, is never stored in plaintext, and logging in with it
  unlocks the key

#### AC-032 — Using the recovery code invalidates it

- **Given** a recovery code that has just unlocked the key
- **When** the same code is presented again
- **Then** it is refused and a new code is issued to the caller

### US-015 — Purge, authorization and logs for key operations

As a user, I want key creation, PIN changes and deletion restricted to me or root, and I want my secrets kept
out of logs, so that another process cannot plant, change or leak my credential.

#### AC-033 — Purge destroys the key and every Protector

- **Given** a provisioned user with PIN and recovery code
- **When** that user's data is purged
- **Then** the token no longer lists the key, every Protector secret is deleted, and nothing can unlock the key (Windows Hello likewise has no persistent TPM handle to evict)

#### AC-034 — An unauthorized caller cannot provision, set a PIN or purge

- **Given** a D-Bus caller that is neither the target user nor root
- **When** it asks `openhello-keyd` to provision, set a PIN or purge another user's key
- **Then** the call is refused with an authorization error and nothing changes

#### AC-035 — Logs never contain PINs, Protector secrets, tickets or recovery codes

- **Given** logging at the most verbose level
- **When** a full provision, face unlock, PIN unlock, recovery and purge cycle runs
- **Then** no log line contains a PIN, a Protector secret, a ticket value or a recovery code

### US-016 — FAR calibration shipped with the application

As a person installing open-hello, I want the false-accept calibration to ship inside the application, so that I need no photo dataset to install it and every machine decides with the same measured thresholds.

#### AC-036 — The engine starts without any calibration file

- **Given** a configuration with no calibration file path and no file at the default location
- **When** the face engine is loaded
- **Then** it loads, using the calibration table embedded in the binary, and a `Verify` at the default target false-accept rate (1e-5) uses the embedded table's threshold

#### AC-037 — A calibration file overrides the embedded table

- **Given** a valid calibration file at the configured path whose thresholds differ from the embedded table
- **When** the face engine is loaded and matches a face
- **Then** the decision threshold comes from the file, not from the embedded table

#### AC-038 — A broken calibration file is an explicit error, never a silent fallback

- **Given** a configured calibration file that is truncated, has the wrong format marker or holds inconsistent values
- **When** the face engine is loaded
- **Then** loading fails with an explicit calibration error and the embedded table is not used

#### AC-039 — The IR emitter is switched on before every capture and capture fails closed without illumination

- **Given** a camera that exposes the Microsoft face-auth control, or one with no controllable emitter
- **When** the sensor adapter begins a capture
- **Then** for the Microsoft control it reads the control before every capture, writes the alternating-illumination mode and confirms it by read-back when the current mode is not alternating (no environment switch), and admits frames only from a stream that alternates lit/unlit; for a camera with no controllable emitter the existing brightness rule applies unchanged; a refused write, an unconfirmed write or a stream that never alternates fails the capture with a distinct error and no frame is returned

### US-017 — Cancelable capture and time budget

As a laptop owner, I want the camera and the IR emitter to stop as soon as the screen or command that asked for my face is gone, and I want a request to look for my face for a bounded, known time, so that the emitter never blinks after I unlock with the password.

#### AC-040 — A caller that leaves cancels its capture

- **Given** a `Verify` or `Identify` call in progress or queued behind another call, and a D-Bus caller whose unique name then disappears from the bus
- **When** the daemon next checks the caller (before every frame, and before it starts a queued call)
- **Then** a running capture stops without another frame, a queued call of a departed caller never starts, the engine session is always ended, and no ticket is delivered

#### AC-041 — One 10-second clock bounds the request and the module waits for it

- **Given** a request whose attempts find no face, or a daemon that stays silent
- **When** the request runs
- **Then** the daemon stops starting frames and attempts after 10 seconds of wall clock for the whole request (one budget shared by every attempt, measured on an injectable clock), and `pam_openhello` waits for the daemon's verdict for longer than that budget and falls through to the password within its own total budget (verdict wait plus signature), never sooner than the daemon and never beyond its budget

#### AC-044 — The camera is released when the request is decided

- **Given** a `Verify` or `Identify` request that ends by acceptance, refusal, camera error or caller departure
- **When** the request ends
- **Then** the daemon closes the camera stream (and with it the IR emitter) at once, without waiting for the idle period, and a later request reopens it

#### AC-045 — A clean install needs no PAM configuration file

- **Given** a system where `/etc/openhello/pkcs11.conf` does not exist (a fresh install, which never creates it)
- **When** `pam_openhello` runs, including under setuid `sudo`
- **Then** it uses the default key-daemon socket `/run/openhello/keyd-token.sock`; a configured socket still wins, and a config file that exists but is not owned by root or is writable by others is still refused

### US-018 — Recognition attempts per authentication request

As a laptop owner, I want each authentication request to give my face a few chances before falling back to the password, so that one bad frame does not cost me a password typing, while a stranger cannot keep trying.

#### AC-042 — A request makes up to three attempts and stops at the first acceptance

- **Given** an enrolled user and a request (`Verify`, or `Identify`)
- **When** the engine accepts the face on the first, second or third attempt, or rejects three attempts in a row
- **Then** acceptance on any attempt ends the request as a success after that attempt, three rejections end it as a refusal at once (the module falls through to the password), every attempt uses a new engine session that is always ended, an attempt is one engine rejection or the per-attempt frame limit reached without a decision, and a refusal delivers no ticket

#### AC-043 — Infrastructure errors and cancellation are not attempts

- **Given** a request in progress
- **When** the camera or the engine fails, or the caller leaves between or during attempts
- **Then** the request ends with an error (the module ignores it and falls through), no further attempt starts, the open engine session is ended, and the failure is not reported as a rejection

## Out of scope

- Graphical login through a display-manager greeter and its UX (roadmap v2).
- Anti-spoofing improvements; the printed-photo risk stays accepted (see `face-recognition-proof` ASM-005).
- SSH agent and LUKS use of the same token (follow-up, the token is built to allow it).
- `io.openhello.ConsentVerifier1` (roadmap v3) and fingerprint support.
- TEE-based isolation of `openhello-keyd`; a root-only daemon with systemd sandboxing is the v1b boundary.
- Migrating a key to another machine or TPM.

## Assumptions

| ID | Assumption | Status | Resolution |
|---|---|---|---|
| ASM-006 | `pam_pkcs11` verifies ECDSA P-256 signatures from the `tpm2-pkcs11` token on this system; RSA-2048 is the fallback. | confirmed | Proved on swtpm (spike.md, 2026-10-21): `tpm2-pkcs11` creates a P-256 token key and `pam_pkcs11` 0.6.13 authenticates with it (`signature` and `ca,signature`); a certificate for another key is rejected. No RSA-2048 fallback needed. Not yet tried on the physical TPM. |
| ASM-007 | A wrapper PKCS#11 module can forward every call to `tpm2-pkcs11` and replace only `C_Login`, so the PIN is supplied by `openhello-keyd` after a ticket check. | confirmed | Proved on swtpm with a ~45-line C wrapper that exports only `C_GetFunctionList` and `C_Login` (spike.md). Caveat: `pam_pkcs11` asks the PAM conversation for a PIN before `C_Login` and rejects an empty one, so the PAM side answers a non-empty placeholder; `CKF_PROTECTED_AUTHENTICATION_PATH` does not work. A 40-char hex PIN (20 random bytes) works as the Protector secret. |
| ASM-008 | The biometric Protector secret (20 random bytes) is held by `openhello-keyd`, sealed in the TPM without an auth value and released only against a valid ticket. TPM lockout therefore throttles the PIN path only; the biometric path is bounded by the match FAR and the ticket lifetime. | open | Honest weaker point versus a PIN: a root-level compromise of `openhello-keyd` can unlock the key. Documented, not mitigated in v1b. |
| ASM-009 | Ticket lifetime of 5 seconds, single use, is a provisional default. | open | Adjustable, like `face-recognition-proof` ASM-002; revisit after real `sudo` and lock-screen use. |
| ASM-010 | `swtpm` supports ECC P-256 and the dictionary-attack lockout well enough to run the key and lockout tests in CI. | confirmed | Proved (spike.md): swtpm has P-256 and the dictionary-attack lockout; three wrong auths give `inLockout=1`, the right password is refused (0x921), `--clear-lockout` recovers. Needs a recovery time above zero and `tpm2-abrmd`. The lockout counter is global to the TPM, not per key: tests and T-017 must set `max-tries` and `recovery-time`. |
| ASM-011 | A PAM-based screen locker can run the open-hello PAM module non-interactively through the common auth stack, on any distro and desktop with an IR camera. | confirmed | One line in the common stack (`auth sufficient pam_openhello.so`), no per-locker service or code. Live evidence on one VM (2026-10-21, `lockscreen.md`): the locker's own PAM service authenticated the face without a password. Other lockers are unverified; the module ignores services in the compiled denylist (T-044). |
| ASM-012 | Purge destroys the user's key the way P-008 intends. | confirmed | Accepted by parity with Windows Hello, where NGC containers are logical and no persistent TPM handle exists either (MS-HOW, `windows-hello-alignment.md`). `tpm2-pkcs11` keeps the key as a wrapped blob in its store under a deterministic primary; Purge removes the token and every Protector, so nobody can unlock it. An attacker holding a copy of the store, the sealed Protector blobs and the same TPM could still sign (T-020 test); closing that would need a persistent TPM object per user and goes beyond Windows. AC-033 is worded accordingly. |
| ASM-013 | The embedded calibration table, measured on visible-light photos (LFW) through the real detector and embedding model, is an acceptable provisional default for the infrared camera. | open | Not proven: infrared impostor scores may differ and the 2-person live test (ASM-001) does not measure FAR. Replace the table with one measured on infrared captures from the target camera once enough people are available; the table is one 1,072-byte file plus the golden test, so swapping it is cheap. |
| ASM-014 | `pam_openhello` can ask keyd to sign a random challenge and verify the ECDSA P-256 signature itself against a root-owned public key, so the PAM path needs no `pam_pkcs11`, NSS database or certificate mapping (owner decision, 2026-10-21). | confirmed | Three failures on the first Ubuntu run came from `pam_pkcs11` build differences (search templates, NSS trust, subject format), and Arch has no official package. The PKCS#11 token and certificate stay for SSH and LUKS. ASM-006 and ASM-007 describe the earlier `pam_pkcs11` path and remain true for it, but the PAM stacks stop depending on it. Windows basis (`windows-hello-alignment.md`): the Entra/Cloud AP and AD key-trust flows sign a nonce and verify it against a registered public key without a PKI (MS-AUTH, confirmed); local-account Hello uses no asymmetric key (MS-OVR, confirmed), so this is an adaptation of the Entra pattern, not a copy of the local case. Verification runs inside the PAM process: equivalent to Windows under `sudo` (root), weaker on user-level lock screens where Windows verifies outside the UI process. Accepted for v1b; moving the check to a root helper or keyd is a later improvement. Live evidence (2026-10-21, KDE neon VM, Ubuntu noble, real vTPM): `sudo true` authenticated by face through `pam_openhello` alone (Verify accepted, ticket delivered, TPM signature of the PAM challenge verified against `/etc/openhello/auth/1000.pub`), no password prompt, exit 0; a single run reported by the owner, so it is evidence of the path, not a success rate or a timing. Not yet measured on the physical TPM or with a second person. |
| ASM-015 | A request may look for a face for at most 10 seconds in total, shared by up to three attempts. | open | Owner decision (2026-10-21, from watching real use: "tenta identificar por uns 10 segundos"), not proven Windows parity. Windows evidence is indirect: `facecredentialprovider.dll` carries timeout telemetry names (`BioListenerDisabledDueToCredProvTimeout`, `CameraStartupTimeout`) and the policy `HKLM\SOFTWARE\Policies\Microsoft\Biometrics\Credential Provider\SwitchTimeoutInSeconds` (default not found), confidence medium. The number is one constant (`FACE_ATTEMPT_BUDGET`). |
| ASM-016 | Three attempts per request is the policy; the Windows counter that persists across events and blocks the face until another login method (`mismatchCount`, N=3, per SID) is not implemented. | open | Owner decision (2026-10-21). Windows evidence (REA, `facecredentialprovider.dll`, confidence high): N=3 consecutive failures fixed in code, a per-user `REG_DWORD mismatchCount` that survives lock cycles, block until a login with another method; the reset point was not proven (probably a successful logon). Persistent lockout is deferred, see `design.md`. |

## Open questions

| ID | Question | Status | Answer |
|---|---|---|---|
| Q-002 | Is the fallback PIN a separate open-hello PIN, or should the PAM stack fall through to the normal Linux password? | answered | Windows Hello: PIN and biometrics are two Protectors on the same key container, and the PIN is not the account password (`windows-hello-arquitetura.md`, "PIN como fallback"). Linux equivalent (`arquitetura-linux.md`, "Protector"): a separate open-hello PIN Protector, presented through `C_Login`; the Linux password stays outside the token, as the next PAM module (AC-029, AC-030). |
| Q-003 | What does the user see while the camera is looking (a `sudo` prompt line, a lock-screen hint)? | answered | Windows Hello: the Credential Provider and a shared UI library show the biometric state. Linux equivalent: the greeter UX is roadmap v2, so owner decision (2026-10-21): v1b shows no text. The blinking IR emitter is the indicator, and any text would depend on how each interface renders PAM messages. |
