# Tasks: Credential login v1b

> feature: credential-login-v1b

## T-014 — Spike: tpm2-pkcs11 + pam_pkcs11 + C_Login override on swtpm [in-progress]
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

## T-017 — openhello-keyd: Protectors (biometric, PIN, recovery) and lockout [pending]

- Refs: AC-019, AC-024, AC-025, AC-026, AC-031, AC-032
- Files: crates/openhello-keyd/src/protector.rs, crates/openhello-keyd/src/ticket_socket.rs, crates/openhello-keyd/tests/protectors.rs
- Model: claude-sonnet-5
- Effort: xhigh
- Notes: depends on T-015, T-016. PIN uses the TPM dictionary-attack lockout; the ticket socket checks
  `SO_PEERCRED`. Biometrics only authorize the key, never replace it (P-003).

## T-018 — openhellod: issue a ticket after a successful Verify [pending]

- Refs: AC-023, AC-019
- Files: crates/openhellod/src/ticket_client.rs, crates/openhellod/src/core.rs, crates/openhellod/Cargo.toml
- Model: claude-sonnet-5
- Effort: medium
- Notes: depends on T-015. No match, no ticket.

## T-019 — openhello-pkcs11: wrapper module overriding C_Login [pending]

- Refs: AC-019, AC-024, AC-025
- Files: crates/openhello-pkcs11/Cargo.toml, crates/openhello-pkcs11/src/lib.rs, crates/openhello-pkcs11/tests/login.rs
- Model: claude-sonnet-5
- Effort: xhigh
- Notes: depends on T-014, T-017. Forwards all other calls to `tpm2-pkcs11`; refuses templates and embeddings.

## T-020 — openhello-keyd: D-Bus service, polkit and systemd sandbox [pending]

- Refs: AC-034
- Files: crates/openhello-keyd/src/main.rs, crates/openhello-keyd/src/dbus_service.rs, crates/openhello-keyd/src/polkit.rs, packaging/io.openhello.Keyd1.conf, packaging/openhello-keyd.service
- Model: claude-sonnet-5
- Effort: high
- Notes: depends on T-016, T-017. Same authorization pattern as `openhellod` (T-010).

## T-021 — Purge integration and log redaction [pending]

- Refs: AC-033, AC-035
- Files: crates/openhello-keyd/src/purge.rs, crates/openhello-keyd/src/logging.rs, crates/openhellod/src/dbus_service.rs
- Model: claude-sonnet-5
- Effort: medium
- Notes: depends on T-020. `openhellod` Purge calls the keyd purge (extends P-008).

## T-022 — PAM stack, installer and sudo end-to-end [pending]

- Refs: AC-027, AC-029, AC-030
- Files: packaging/pam/sudo-openhello, packaging/pam/pam_pkcs11.conf, scripts/install.sh, crates/openhello-cli/tests/pam_sudo.rs
- Model: claude-sonnet-5
- Effort: high
- Notes: depends on T-019, T-020. Tested with `pamtester` against a private service file.

## T-023 — KDE lock screen verification [pending]

- Refs: AC-028
- Files: packaging/pam/kde-openhello, .spec/features/credential-login-v1b/lockscreen.md
- Model: claude-sonnet-5
- Effort: medium
- Notes: depends on T-022. Manual check on the Plasma session (ASM-011), recorded as evidence.
