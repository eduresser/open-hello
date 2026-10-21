# Tasks: Credential login v1b

> feature: credential-login-v1b

## T-014 — Spike: tpm2-pkcs11 + pam_pkcs11 + C_Login override on swtpm [done]
- Refs: AC-019, AC-027
- Files: scripts/spike-pkcs11.sh, .spec/features/credential-login-v1b/spike.md
- Model: claude-sonnet-5
- Effort: high
- Notes: spike finished 2026-10-21 (ASM-006, ASM-007, ASM-010 proved, see spike.md); stays in-progress until AC-019 and AC-027 have proof in T-019 and T-022. First task, blocked the rest. Installs/builds `tpm2-pkcs11`, `pam_pkcs11`, `pamtester` on a test
  prefix; proves ASM-006 (P-256 verified by `pam_pkcs11`), ASM-007 (a wrapper replacing only `C_Login`) and
  ASM-010 (swtpm ECC + dictionary-attack lockout). Writes the result into `spike.md` and updates the assumptions.

## T-015 — Ticket library (HMAC, TTL, single use) [done]
- Refs: AC-020, AC-021, AC-022
- Files: crates/openhello-ticket/Cargo.toml, crates/openhello-ticket/src/lib.rs
- Model: claude-sonnet-5
- Effort: medium
- Notes: pure library, no I/O. Independent of the spike.

## T-016 — openhello-keyd: workspace crate and TPM key provisioning [done]
- Refs: AC-016, AC-017, AC-018
- Files: Cargo.toml, crates/openhello-keyd/Cargo.toml, crates/openhello-keyd/src/lib.rs, crates/openhello-keyd/src/tpm.rs, crates/openhello-keyd/src/provision.rs
- Model: claude-sonnet-5
- Effort: high
- Notes: depends on T-014. Idempotent provisioning; non-extractable key; no private bytes in any output (P-004).

## T-017 — openhello-keyd: Protectors (biometric, PIN, recovery) and lockout [done]
- Refs: AC-019, AC-024, AC-025, AC-026, AC-031, AC-032
- Files: crates/openhello-keyd/src/protector.rs, crates/openhello-keyd/src/ticket_socket.rs, crates/openhello-keyd/tests/protectors.rs
- Model: claude-sonnet-5
- Effort: xhigh
- Notes: depends on T-015, T-016. PIN uses the TPM dictionary-attack lockout; the ticket socket checks
  `SO_PEERCRED`. Biometrics only authorize the key, never replace it (P-003).

## T-018 — openhellod: issue a ticket after a successful Verify [done]
- Refs: AC-023, AC-019
- Files: crates/openhellod/src/ticket_client.rs, crates/openhellod/src/core.rs, crates/openhellod/Cargo.toml
- Model: claude-sonnet-5
- Effort: medium
- Notes: depends on T-015. No match, no ticket.

## T-019 — openhello-pkcs11: wrapper module overriding C_Login [done]
- Refs: AC-019, AC-024, AC-025
- Files: Cargo.toml, crates/openhello-pkcs11/Cargo.toml, crates/openhello-pkcs11/src/lib.rs, crates/openhello-pkcs11/tests/login.rs, crates/openhello-keyd/src/unlock_socket.rs, crates/openhello-keyd/src/lib.rs
- Model: claude-sonnet-5
- Effort: xhigh
- Notes: depends on T-014, T-017, T-018. Forwards all other calls to `tpm2-pkcs11`; refuses templates and embeddings. `C_Login` with the fixed placeholder runs the face flow (openhellod `Verify` -> ticket -> keyd grant); any other PIN runs the PIN Protector. The wrapper never holds the Protector longer than the `C_Login` call. keyd gains an unlock socket where the peer uid must equal the target uid (the user's own process), separate from the root-only ticket socket.

## T-020 — openhello-keyd: D-Bus service, polkit and systemd sandbox [done]
- Refs: AC-034
- Files: crates/openhello-keyd/src/main.rs, crates/openhello-keyd/src/dbus_service.rs, crates/openhello-keyd/src/polkit.rs, crates/openhello-keyd/src/purge.rs, crates/openhello-keyd/tests/dbus_service.rs, packaging/io.openhello.Keyd1.conf, packaging/openhello-keyd.service
- Model: claude-sonnet-5
- Effort: high
- Notes: depends on T-016, T-017. Same authorization pattern as `openhellod` (T-010). Methods Provision, SetPin and Purge; the keyd purge itself (evict the TPM key, delete Protectors, remove the token) lives in `purge.rs` so that AC-034 can be tested against a real Purge.

## T-021 — Purge integration and log redaction [done]
- Refs: AC-033, AC-035
- Files: crates/openhello-keyd/src/logging.rs, crates/openhello-keyd/tests/purge_and_logs.rs, crates/openhellod/src/dbus_service.rs, crates/openhellod/src/core.rs
- Model: claude-sonnet-5
- Effort: medium
- Notes: depends on T-020. `openhellod` Purge calls the keyd purge from T-020 (extends P-008); this task proves AC-033 end to end and adds log redaction for PINs, Protector secrets, tickets and recovery codes (AC-035).

## T-024 — keyd: token certificate, root-owned mapping and root-delegated unlock [done]
- Refs: AC-016
- Files: crates/openhello-keyd/src/certificate.rs, crates/openhello-keyd/src/provision.rs, crates/openhello-keyd/src/unlock_socket.rs, crates/openhello-keyd/src/lib.rs, crates/openhello-keyd/src/purge.rs, crates/openhello-keyd/tests/certificate.rs
- Model: claude-sonnet-5
- Effort: high
- Notes: depends on T-020, T-021; must run before T-022. `pam_pkcs11` needs a certificate on the token, and its default mapper reads `~/.eid/authorized_certificates`, a file the user controls, so any user could authorize their own software key and pass `sudo`. Provision issues a self-signed certificate for the TPM key and records its digest in a root-owned mapping file; Purge removes both. Under setuid `sudo` the peer of the unlock socket is root, so a root peer may name the target uid (Windows Hello: the privileged logon component asks the key service on behalf of the user); a non-root peer still only acts for its own uid. Partial evidence for AC-027 and AC-029 (signature checks against the certificate) is covered by unlabeled tests; those criteria are proven in T-022.

## T-022 — PAM stack, installer and sudo end-to-end [done]
- Refs: AC-027, AC-029, AC-030
- Files: Cargo.toml, packaging/pam/sudo-openhello, packaging/pam/pam_pkcs11.conf, packaging/pam/pkcs11.conf, packaging/openhello-keyd.service, scripts/install.sh, crates/openhello-pam/Cargo.toml, crates/openhello-pam/src/lib.rs, crates/openhello-cli/Cargo.toml, crates/openhello-cli/tests/pam_sudo.rs, crates/openhello-keyd/src/certificate.rs, crates/openhello-keyd/src/config.rs, crates/openhello-keyd/src/provision.rs, crates/openhello-keyd/src/purge.rs, crates/openhello-keyd/src/tpm.rs, crates/openhello-keyd/tests/certificate.rs, crates/openhello-pkcs11/src/lib.rs, crates/openhello-pkcs11/src/config.rs, crates/openhello-pkcs11/tests/privileged_config.rs
- Model: claude-sonnet-5
- Effort: high
- Notes: depends on T-019, T-020, T-024. Tested with a `pam_wrapper` client (pamtester is not packaged) against a private service file. Fixes the wrapper and module paths in root-owned config instead of the caller's environment, supplies the `C_Login` placeholder to `pam_pkcs11`, and uses the root-owned certificate mapping from T-024. `pam_pkcs11` only accepts the self-signed certificate if it is imported as a trusted CA in a root-owned NSS database (`certutil -A -t "CT,C,C"`; the certificate must carry no extensions): Provision imports it there and Purge removes it.
  `pam_openhello` (new crate) shows "Looking for your face..." and sets the `C_Login` placeholder as the first password; `pam_pkcs11` crashes without a first password, so the stack maps its answer with `[success=ignore ignore=2 default=ignore]` (ignore skips `pam_pkcs11`) and a trailing `pam_openhello.so clear` drops the placeholder before the password module. The PIN is an opt-in second `pam_pkcs11` line (no `use_first_pass`) because a password typed by habit would count against the TPM-wide lockout. The wrapper also exposes only the caller's own token to `pam_pkcs11`, pins the token store from the root-owned config when privileged, and caps `Verify` at 4 s so a silent camera falls through within 5 s.

## T-025 — Token proxy: the wrapper forwards PKCS#11 calls to keyd [pending]

- Refs: AC-019, AC-025, AC-027
- Files: crates/openhello-keyd/src/token_socket.rs, crates/openhello-keyd/src/unlock_socket.rs, crates/openhello-keyd/src/lib.rs, crates/openhello-keyd/src/main.rs, crates/openhello-keyd/tests/token_proxy.rs, crates/openhello-pkcs11/src/proxy.rs, crates/openhello-pkcs11/src/lib.rs, crates/openhello-pkcs11/src/config.rs, crates/openhello-pkcs11/tests/login.rs, packaging/openhello-keyd.service
- Model: claude-sonnet-5
- Effort: xhigh
- Notes: depends on T-022; must run before T-023. The lock screen runs as the user and cannot open the root-owned token (the `sudo` path works only because it is root). Decision (owner, 2026-10-21): the wrapper in the user's process becomes a thin proxy; keyd (root) owns the real PKCS#11 session and signs, as in Windows Hello where the key never leaves the service. The Protector secret K stops crossing the socket: the world-accessible unlock socket no longer returns K. AC-019, AC-025 and AC-027 must keep passing through the proxy.

## T-023 — KDE lock screen verification [pending]

- Refs: AC-028
- Files: packaging/pam/kde-openhello, .spec/features/credential-login-v1b/lockscreen.md
- Model: claude-sonnet-5
- Effort: medium
- Notes: depends on T-025. Manual check on the Plasma session (ASM-011), recorded as evidence; an unprivileged PAM test through the `kde` service file covers the same path in CI.
