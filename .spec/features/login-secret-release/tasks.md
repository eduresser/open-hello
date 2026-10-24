# Tasks: Login secret release

> feature: login-secret-release

## T-079 — Spike: released token on real distribution PAM stacks [pending]

- Refs: US-028, AC-090
- Files: crates/openhello-cli/tests/pam_release_stacks.rs, tests/fixtures/pam-stacks/README.md
- Notes: copy the unmodified login-manager and common auth files of openSUSE Tumbleweed, Fedora, Debian/Ubuntu and Arch into fixtures; run them under pam_wrapper with OpenHello enabled as the package does, a fake keyd that releases a known password, a password-check stub with each distro's options, and a keyring stub. Settles ASM-025 and ASM-026; any stack that prompts goes to the owner (Q-006) before T-082.
- Effort: high

## T-080 — keyd: TPM-protected login secret store [pending]

- Refs: US-026, AC-082, AC-083, AC-088, AC-089
- Files: crates/openhello-keyd/src/login_secret.rs, crates/openhello-keyd/src/lib.rs, crates/openhello-keyd/src/purge.rs, crates/openhello-keyd/tests/login_secret.rs
- Notes: envelope encryption under a TPM-sealed key (ASM-027); atomic replace; purge destroys the key first; store a fingerprint (keyed hash) of the user's /etc/shadow entry with the secret and refuse/discard on mismatch (AC-080).
- Effort: high

## T-081 — keyd: seal and release operations on the token socket [pending]

- Refs: US-027, AC-080, AC-086, AC-087, AC-088
- Files: crates/openhello-keyd/src/token_socket.rs, crates/openhello-auth-proto/src/lib.rs, crates/openhello-keyd/tests/token_release.rs
- Notes: AUTH_RELEASE consumes the face ticket once; SEAL and the secret part of AUTH_RELEASE need a uid-0 peer.
- Effort: high

## T-082 — PAM: release the sealed password after a face match [pending]

- Refs: US-025, AC-078, AC-079, AC-080, AC-081, AC-085
- Files: crates/openhello-pam/src/lib.rs, crates/openhello-pam/src/challenge.rs, crates/openhello-cli/tests/pam_release.rs
- Notes: depends on T-079 (go/no-go), T-081.
- Effort: high

## T-083 — PAM: capture line after the password check seals the verified password [pending]

- Refs: US-026, AC-082, AC-083, AC-084
- Files: crates/openhello-pam/src/lib.rs, crates/openhello-pam/src/challenge.rs, crates/openhello-cli/src/pam_enable.rs, crates/openhello-cli/tests/pam_enable.rs, crates/openhello-cli/tests/pam_release.rs, crates/openhello-cli/tests/pam_release_stacks.rs
- Notes: first prove ASM-029 on the T-079 container stacks; `pam enable`/`disable`/`status` place and remove the capture line (`auth optional pam_openhello.so capture`) after the password check; the capture line stashes the token and seals it in setcred only when the whole authentication succeeded and OpenHello did not release it itself. Depends on T-081; runs after T-082 (shared files).
- Effort: medium
