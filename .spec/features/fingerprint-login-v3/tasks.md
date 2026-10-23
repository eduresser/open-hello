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

## T-063 — Remove the fingerprint authentication path from openhellod [done]
- Refs: US-023, AC-062, AC-055, AC-056, AC-058, AC-059
- Files: crates/openhellod/src/core.rs, crates/openhellod/src/fingerprint.rs, crates/openhellod/src/main.rs, crates/openhellod/tests/fingerprint.rs, crates/openhellod/tests/fingerprint_enroll.rs, crates/openhellod/tests/fingerprint_purge.rs
- Notes: owner decision 2026-10-22: open-hello manages fingers (enroll, status, purge) and the system's `pam_fprintd` authenticates them. A paused attempt is in `git stash list` ("T-063 WIP"): `git stash pop` restores it (removal in core.rs, verify half gone from fingerprint.rs with `FingerprintReader`/`FprintdReader` renames, main.rs wiring, the AC-062 tests); review it, finish it, run the tests. `Verify` must never call Claim or VerifyStart (AC-062). Face-only behaviour of `Verify` must stay exactly as before T-058. Follow the minimal-comments skill.

## T-064 — pam enable, disable and status handle the system's fingerprint line [done]
- Refs: US-023, AC-061, AC-072, AC-074
- Files: crates/openhello-cli/src/pam_enable.rs, crates/openhello-cli/tests/pam_enable.rs, crates/openhello-cli/src/lib.rs, scripts/install.sh
- Notes: reuse the existing common-stack discovery, backup, atomic write and undo in `pam_enable.rs` (the `enable_common` path). Insert `auth sufficient pam_fprintd.so max-tries=3 timeout=10` right after our line, only when the module file `pam_fprintd.so` exists in the PAM module directory the CLI already discovers and no `pam_fprintd` line reaches the common stack. Mark the line it adds so `disable` removes only that one. Add `--no-fingerprint`. Extend `status`. The installer's fprintd line reports what `pam enable` did. No desktop or distribution names in the code. Follow the minimal-comments skill.

## T-065 — Report whether the system's fingerprint login is on after enrolling a finger [pending]

- Refs: US-023, AC-073
- Files: crates/openhello-cli/src/lib.rs, crates/openhello-cli/tests/end_to_end.rs
- Notes: depends on T-064 (reuse its detection of a `pam_fprintd` line in the common stack). After `enroll finger` print one plain line; never edit PAM from this command. Follow the minimal-comments skill.

## T-066 — Remove distribution and desktop names from production code [pending]

- Refs: US-023, AC-075
- Files: crates/openhello-cli/src/pam_enable.rs, crates/openhello-cli/tests/pam_enable.rs, crates/openhello-cli/tests/pam_sudo.rs, scripts/install.sh, packaging/openhello-keyd.service
- Notes: owner rule 2026-10-22: production code must be as general as possible, with no name of a distribution, desktop, package manager or PAM stack file. Replace the fixed `COMMON_STACKS` list (used only by `validate_service` to refuse editing a shared stack) with a structural test: a service file is a shared stack when another service file includes it (`@include`, `include`, `substack`). Remove the distribution names from comments in `scripts/install.sh` and `packaging/openhello-keyd.service`. In the tests rename `DEBIAN_COMMON_AUTH` and similar fixtures to neutral names, and add the AC-075 tests with arbitrary stack file names (the `sudo` service including a file such as `base-auth`, another service including `extra-auth`). `scripts/pam-survey.sh` and `scripts/spike-pkcs11.sh` are development tools, leave their content. Follow the minimal-comments skill.

