# Tasks: Fingerprint login v3

> feature: fingerprint-login-v3

## T-057 — fprintd client and fingerprint backend in openhellod [done]
- Refs: US-021, AC-055, AC-056
- Files: crates/openhellod/src/fingerprint.rs, crates/openhellod/src/lib.rs, crates/openhellod/Cargo.toml
- Notes: D-Bus client for `net.reactivated.Fprint` (GetDefaultDevice, Claim, VerifyStart "any", VerifyStatus, VerifyStop, Release). Result type separates match, no-match and infrastructure error (unavailable, no enrolled finger, disconnected). Trait so tests use a fake `fprintd` on a private bus. Follow the minimal-comments skill.

## T-058 — Face and finger in one request, first match wins [done]

- Superseded on 2026-10-22: the finger no longer authenticates inside openhellod; T-063 removes this path and proves AC-062.
- Refs: US-023, AC-062
- Files: crates/openhellod/src/core.rs, crates/openhellod/src/backends.rs, crates/openhellod/src/main.rs
- Notes: depends on T-057. Shared 10 s budget, three no-match results for the finger, cancellation releases the reader and the camera, an infrastructure error ends only the finger side (Q-005). Must not hold the core lock while waiting for a finger (ASM-021). Follow the minimal-comments skill.

## T-059 — Finger enrollment through openhellod and the CLI [done]
- Refs: US-021, AC-055, AC-056, AC-057
- Files: crates/openhellod/src/dbus_service.rs, crates/openhello-cli/src/lib.rs, crates/openhello-cli/src/dbus_client.rs, crates/openhello-cli/src/terminal.rs
- Notes: depends on T-057. Enroll methods stay under polkit (P-009). Choosing a finger, several fingers (Q-004), "no reader" line. Follow the minimal-comments skill.

## T-060 — Purge of fingers and fingerprint-safe logs [done]
- Refs: US-022, AC-058, AC-059
- Files: crates/openhellod/src/core.rs, crates/openhellod/src/logging.rs
- Notes: depends on T-058 (same file). `DeleteEnrolledFingers` in purge; a failure reports "incomplete" as for the key. Follow the minimal-comments skill.

## T-061 — Constitution exceptions, packaging and VM evidence [done]
- Refs: US-021, AC-055
- Files: .spec/constitution.md, packaging/openhellod.service, scripts/install.sh
- Notes: the exceptions to P-006 and P-007 are already written (ASM-019). Remaining: unit ordering after `fprintd`, installer capability check for `fprintd`, and the end-to-end run on the VM with the virtual reader (`virtual-fingerprint-reader-vm` memory), recorded as evidence. Follow the minimal-comments skill.

## T-062 — Enroll face and enroll finger subcommands [done]
- Refs: US-021, AC-055, AC-057, AC-060
- Files: crates/openhello-cli/src/lib.rs, crates/openhello-cli/src/main.rs, crates/openhello-cli/tests/end_to_end.rs, crates/openhello-cli/tests/provisioning_flow.rs
- Notes: owner request 2026-10-22 after seeing `enroll` open the camera before any finger step. `enroll face` is the face only (a bare `enroll` is its alias); `enroll finger` runs the finger step alone and provisions the TPM key if the user has none. Follow the minimal-comments skill.

## T-063 — Remove the fingerprint authentication path from openhellod [pending]

- Refs: US-023, AC-062, AC-055, AC-056, AC-058, AC-059
- Files: crates/openhellod/src/core.rs, crates/openhellod/src/fingerprint.rs, crates/openhellod/src/main.rs, crates/openhellod/tests/fingerprint.rs, crates/openhellod/tests/fingerprint_enroll.rs, crates/openhellod/tests/fingerprint_purge.rs
- Notes: owner decision 2026-10-22: open-hello manages fingers (enroll, status, purge) and the system's `pam_fprintd` authenticates them. Remove the finger verification in `Verify` (T-058 concurrency, `verify_with_attempts`, `FingerprintResult` verify variants, the verify wait) and its tests; keep enrollment, status, list and delete, and their tests. `Verify` must never call Claim or VerifyStart (AC-062). Face-only behaviour of `Verify` must stay exactly as before T-058. Follow the minimal-comments skill.

## T-064 — Report whether the system's fingerprint login is on [pending]

- Refs: US-023, AC-061
- Files: crates/openhello-cli/src/lib.rs, crates/openhello-cli/tests/end_to_end.rs, scripts/install.sh
- Notes: depends on T-063. After `enroll finger` print one plain line saying whether `pam_fprintd` appears in a PAM service file under the PAM directories (search `/etc/pam.d` and the vendor directory such as `/usr/lib/pam.d` or `/usr/share/pam.d`, no desktop or distribution names) and, when it does not, that the system's own tools enable it. Never edit the PAM configuration for the finger. The installer line about fprintd reports the same finding. Follow the minimal-comments skill.
