# Tasks: Fingerprint login v3

> feature: fingerprint-login-v3

## T-057 — fprintd client and fingerprint backend in openhellod [done]
- Refs: US-019, AC-048, AC-049, AC-050, AC-051
- Files: crates/openhellod/src/fingerprint.rs, crates/openhellod/src/lib.rs, crates/openhellod/Cargo.toml
- Notes: D-Bus client for `net.reactivated.Fprint` (GetDefaultDevice, Claim, VerifyStart "any", VerifyStatus, VerifyStop, Release). Result type separates match, no-match and infrastructure error (unavailable, no enrolled finger, disconnected). Trait so tests use a fake `fprintd` on a private bus. Follow the minimal-comments skill.

## T-058 — Face and finger in one request, first match wins [done]
- Refs: US-020, AC-052, AC-053, AC-054
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

## T-061 — Constitution exceptions, packaging and VM evidence [pending]

- Refs: US-019, AC-048
- Files: .spec/constitution.md, packaging/openhellod.service, scripts/install.sh
- Notes: the exceptions to P-006 and P-007 are already written (ASM-019). Remaining: unit ordering after `fprintd`, installer capability check for `fprintd`, and the end-to-end run on the VM with the virtual reader (`virtual-fingerprint-reader-vm` memory), recorded as evidence. Follow the minimal-comments skill.

## T-062 — Enroll face and enroll finger subcommands [done]
- Refs: US-021, AC-055, AC-057, AC-060
- Files: crates/openhello-cli/src/lib.rs, crates/openhello-cli/src/main.rs, crates/openhello-cli/tests/end_to_end.rs, crates/openhello-cli/tests/provisioning_flow.rs
- Notes: owner request 2026-10-22 after seeing `enroll` open the camera before any finger step. `enroll face` is the face only (a bare `enroll` is its alias); `enroll finger` runs the finger step alone and provisions the TPM key if the user has none. Follow the minimal-comments skill.
