# Design: Credential login v1b

> feature: credential-login-v1b

Follows `docs/arquitetura-linux.md` ("openhello-keyd", "Protector", "Integração com login") and the Windows
Hello findings in `docs/windows-hello-arquitetura.md` (NGC container, Protectors, Credential Provider).

## Workspace additions

```
crates/
  openhello-ticket/      # lib: ticket format (HMAC-SHA256), TTL, single-use ledger; no I/O
  openhello-keyd/        # binary: root-only key daemon, D-Bus io.openhello.Keyd1, TPM key + Protectors
  openhello-pkcs11/      # cdylib: PKCS#11 wrapper over tpm2-pkcs11 that overrides only C_Login
packaging/
  io.openhello.Keyd1.conf, openhello-keyd.service, pam/ (sudo + kde stack snippets)
```

## Components

- **`openhello-ticket`** — a ticket is `{uid, nonce, expiry}` plus an HMAC-SHA256 over them with an ephemeral key.
  The verifier rejects a bad MAC, a foreign UID, an expired ticket (default TTL 5 s, ASM-009) and a repeated
  nonce (AC-020/021/022). No I/O, so it is tested directly.
- **`openhello-keyd`** — the only process that talks to the TPM for user keys (P-004). Responsibilities:
  1. Provision a per-user ECDSA P-256 key (`fixedtpm|fixedparent|sensitivedataorigin`, never exportable) and
     register it in the `tpm2-pkcs11` token (AC-016/017/018).
  2. Hold Protectors, as in the Windows NGC container (PIN and biometrics are two Protectors on one key):
     a 20-byte secret per Protector. The PIN Protector is guarded by the TPM dictionary-attack lockout
     (AC-025/026). The biometric Protector is released only for a valid ticket (AC-019, ASM-008). The recovery
     Protector mirrors `ngcrecovery.dll`: a separate secret, shown once, rotated on use (AC-031/032).
  3. Accept tickets only on a Unix socket, checking the peer with `SO_PEERCRED` (root, the `openhellod` binary)
     (AC-022).
  4. Authorize provision/PIN/purge calls through D-Bus sender identity plus polkit, the same pattern as
     `openhellod` (AC-034). Redact secrets from logs (AC-035).
- **`openhellod` change** — after a successful `Verify`/`Identify`, ask `openhello-ticket` for a ticket and send
  it to `openhello-keyd` for the matched UID. No match, no ticket (AC-023). It still never sees key material.
- **`openhello-pkcs11`** — implements the PKCS#11 entry points by forwarding every call to `tpm2-pkcs11`, except
  `C_Login`: it asks `openhello-keyd` for the Protector (biometric, PIN or recovery) and passes it to
  `tpm2-pkcs11` as the user PIN. This is the "PIN swap" shim from the architecture doc (ASM-007). Raw
  templates or embeddings are never accepted here (AC-024).
- **PAM** — `pam_pkcs11` configured against `openhello-pkcs11` for the `sudo` and KDE lock-screen services,
  marked `sufficient` and placed before `pam_unix`, so any failure, timeout or missing daemon falls through
  to the Linux password (AC-029/030). A PAM text line shows "Looking for your face..." (Q-003).

## Flows

- **Unlock**: PAM → `pam_pkcs11` → `C_Login` in `openhello-pkcs11` → `openhellod` `Verify` → ticket →
  `openhello-keyd` validates → Protector → `tpm2-pkcs11` login → challenge signed by the TPM key → PAM success.
- **PIN fallback**: same path, `C_Login` receives the PIN instead of a ticket.
- **Purge**: `openhellod` Purge also calls `openhello-keyd` purge: evict the TPM key, delete Protectors, remove
  the token objects (AC-033, extends P-008).

## Order of work and risk

Roughly two assumptions decide the whole design (ASM-006, ASM-007) and neither tool is installed yet, so the
first task is a spike on `swtpm` that proves `tpm2-pkcs11` + `pam_pkcs11` + a `C_Login` override work with
P-256. If it fails, fall back to RSA-2048, or to the own-PAM-module option the owner declined, and revise this
design before any other task.

## Testing approach

- **TPM**: `swtpm`, never the physical TPM (same rule as `face-recognition-proof`).
- **Faces**: `openhellod` is replaced by a test ticket issuer; live face checks reuse the recorded-frame fixtures.
- **PAM**: run `pamtester` against a private PAM service file in a temp dir, not the system `sudo` stack.
- **Lock screen (AC-028)**: manual on the Plasma session, recorded as partial evidence like ASM-001 until a
  scripted check exists.
