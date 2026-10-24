# Tasks: Login secret release

> feature: login-secret-release

## T-079 — Spike: released token on real distribution PAM stacks [done]
- Refs: US-028, AC-090
- Files: crates/openhello-cli/tests/pam_release_stacks.rs, tests/fixtures/pam-stacks/README.md
- Notes: copy the unmodified login-manager and common auth files of openSUSE Tumbleweed, Fedora, Debian/Ubuntu and Arch into fixtures; run them under pam_wrapper with OpenHello enabled as the package does, a fake keyd that releases a known password, a password-check stub with each distro's options, and a keyring stub. Settles ASM-025 and ASM-026; any stack that prompts goes to the owner (Q-006) before T-082.
- Effort: high

## T-080 — keyd: TPM-protected login secret store [done]
- Refs: US-026, AC-082, AC-083, AC-088, AC-089
- Files: crates/openhello-keyd/src/login_secret.rs, crates/openhello-keyd/src/lib.rs, crates/openhello-keyd/src/purge.rs, crates/openhello-keyd/tests/login_secret.rs
- Notes: envelope encryption under a TPM-sealed key (ASM-027); atomic replace; purge destroys the key first; store a fingerprint (keyed hash) of the user's /etc/shadow entry with the secret and refuse/discard on mismatch (AC-080).
- Effort: high

## T-081 — keyd: seal and release operations on the token socket [done]
- Refs: US-027, AC-080, AC-086, AC-087, AC-088
- Files: crates/openhello-keyd/src/token_socket.rs, crates/openhello-auth-proto/src/lib.rs, crates/openhello-keyd/tests/token_release.rs
- Notes: AUTH_RELEASE consumes the face ticket once; SEAL and the secret part of AUTH_RELEASE need a uid-0 peer.
- Effort: high

## T-082 — PAM: release the sealed password after a face match [done]
- Refs: US-025, AC-078, AC-079, AC-080, AC-081, AC-085
- Files: crates/openhello-pam/src/lib.rs, crates/openhello-pam/src/challenge.rs, crates/openhello-pam/src/debug.rs, crates/openhello-cli/tests/pam_sudo.rs
- Notes: depends on T-079 (go/no-go), T-081.
- Effort: high

## T-083 — PAM: capture line after the password check seals the verified password [done]
- Refs: US-026, AC-082, AC-083, AC-084
- Files: crates/openhello-pam/src/lib.rs, crates/openhello-pam/src/challenge.rs, crates/openhello-cli/src/pam_enable.rs, crates/openhello-cli/tests/pam_enable.rs, crates/openhello-cli/tests/pam_sudo.rs, crates/openhello-cli/tests/pam_release_stacks.rs, packaging/package/postinstall.sh, crates/openhello-cli/tests/packaging.rs
- Notes: first prove ASM-029 on the T-079 container stacks; `pam enable`/`disable`/`status` place and remove the capture line (`auth optional pam_openhello.so capture`) after the password check; the capture line stashes the token and seals it in setcred only when the whole authentication succeeded and OpenHello did not release it itself; package upgrades add the capture line wherever OpenHello's first line is present (never re-enable after a `pam disable`). Depends on T-081; runs after T-082 (shared files).
- Effort: medium

## T-084 — keyd: login secret key lives in a persistent TPM handle [done]
- Refs: US-027, AC-089
- Files: crates/openhello-keyd/src/login_secret.rs, crates/openhello-keyd/src/protector.rs, crates/openhello-keyd/tests/login_secret.rs
- Notes: owner decision 2026-10-24: real crypto-shred like the template key (persistent handle via evictcontrol), purge evicts it; a backup of key files must not release the secret afterwards. Reuse how storage-adapter-templates handles its persistent handle; existing sealed secrets migrate or are dropped (the next typed password reseals).
- Effort: high

## T-085 — PAM: seal on a successful pam_end so polkit prompts teach the password [done]
- Refs: US-026, AC-082, AC-091
- Files: crates/openhello-pam/src/lib.rs, crates/openhello-cli/tests/pam_sudo.rs
- Notes: the capture stash's pam_set_data cleanup seals when pam_end reports PAM_SUCCESS (not PAM_DATA_REPLACE); polkit-agent-helper-1 only calls authenticate, acct_mgmt and pam_end. Keep the setcred path or replace it, but seal at most once per transaction.
- Effort: medium

## T-086 — Learn the password at enrollment for users without a face yet [pending]

- Refs: US-026, AC-091, AC-092
- Files: crates/openhello-pam/src/lib.rs, crates/openhello-keyd/src/token_socket.rs, crates/openhello-keyd/src/login_secret.rs, crates/openhello-keyd/src/dbus_service.rs, crates/openhello-keyd/src/provision.rs, crates/openhello-keyd/tests/token_release.rs, crates/openhello-cli/tests/pam_sudo.rs
- Notes: owner bug report 2026-10-24: after purge + re-enroll the polkit password was ignored because `capture` used the face-login eligibility (requires `<uid>.pub`). Capture must only require a local session, an allowed service and a non-root user. keyd seals at once when the user is provisioned; otherwise it keeps the password in memory (Zeroizing, 15 min TTL, one per uid, newest wins) and seals it when Provision for that uid succeeds. AC-091's test must run in the real order: no credential, polkit-like prompt, then provision, then face sign-in.
- Effort: high
