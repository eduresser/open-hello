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
  4. Serve token sessions on a world-accessible Unix socket (T-025). Each connection is bound to the uid the
     kernel reports (a root peer may name the target uid, as under `sudo`). keyd holds the real `tpm2-pkcs11`
     session, logs in with the Protector internally (placeholder PIN: the single-use grant from the ticket;
     any other PIN: the PIN Protector), and exposes only the certificate, the public key and an opaque
     private-key handle that signs with ECDSA. `CKA_VALUE` and every other private-key attribute are refused,
     and K never crosses a user socket (P-004).
  5. Authorize provision/PIN/purge calls through D-Bus sender identity plus polkit, the same pattern as
     `openhellod` (AC-034). Redact secrets from logs (AC-035).
- **`openhellod` change** — after a successful `Verify`/`Identify`, ask `openhello-ticket` for a ticket and send
  it to `openhello-keyd` for the matched UID. No match, no ticket (AC-023). It still never sees key material.
- **`openhello-pkcs11`** — a thin PKCS#11 proxy (T-025). It never loads `tpm2-pkcs11`: it forwards the calls
  `pam_pkcs11` makes (slot and token info, sessions, login, find, attributes, sign) to the keyd token socket and
  answers `CKR_FUNCTION_NOT_SUPPORTED` to the rest. For the placeholder PIN it still calls `Verify` on
  `openhellod` over D-Bus as the user (`openhellod` already delivers the ticket to keyd), then sends the
  placeholder to keyd, which finishes the login. Several virtual sessions share one real session in keyd.
  Raw templates or embeddings are never accepted (AC-024). The direct path that loaded `tpm2-pkcs11` in the
  caller and received K over the unlock socket was removed: it cannot work without K crossing the socket.
- **PAM** — `pam_pkcs11` configured against `openhello-pkcs11` for the `sudo` and KDE lock-screen services,
  marked `sufficient` and placed before `pam_unix`, so any failure, timeout or missing daemon falls through
  to the Linux password (AC-029/030). A PAM text line shows "Looking for your face..." (Q-003).

## Findings before the PAM task

- Certificate mapping must be root-owned: `pam_pkcs11`'s default mapper reads a file in the user's home, which would let any user authorize their own software key (T-024).
- Under setuid `sudo` the keyd peer is root; a root peer names the target uid on the unlock socket (T-024). Module and socket paths come from root-owned config, never from the caller's environment (T-022).

- The lock screen runs as the user and cannot open the root-owned token. The wrapper becomes a proxy: keyd keeps the PKCS#11 session and does the signing, so K and the private key never reach a user process (T-025, owner decision 2026-10-21).

- The keyd ticket socket trusts uid 0 only. Checking the peer's executable (`OPENHELLO_KEYD_TICKET_EXE`) needs ptrace-read access to `/proc/<pid>/exe`, which the sandboxed keyd (only `CAP_DAC_OVERRIDE`) does not have, so the unit leaves it unset; granting `CAP_SYS_PTRACE` to the key daemon would cost more than the check protects against (a root attacker, already ASM-008). Found on the VM, 2026-10-21.

- PAM without `pam_pkcs11` (owner decision, 2026-10-21): `pam_openhello` generates a random challenge, calls openhellod `Verify` (which delivers the ticket to keyd), asks keyd to sign a domain-separated hash of the challenge with the TPM key, and verifies the signature against a public key file written by Provision in a root-owned directory. No certificate, NSS database, `certutil` or mapper is involved, which removes the build differences between distributions. The Windows Hello counterpart is the credential provider talking to the key service directly (`windows-hello-arquitetura.md`, "Credential Provider").
- Portability rules (`portability-paths.md`): our own files go to fixed neutral locations (units in `/usr/lib/systemd/system`, D-Bus policy in `/usr/share/dbus-1/system.d`, polkit actions in `/usr/share/polkit-1/actions`, daemons in a private directory written into the unit by template); third-party locations are discovered on the target (PAM directory from `ldconfig`, tpm2-pkcs11 module from `p11-kit` then by name); no path lists per distribution in Rust.

## Flows

- **Unlock**: PAM → `pam_pkcs11` → `C_Login` in `openhello-pkcs11` → `openhellod` `Verify` → ticket →
  `openhello-keyd` validates and keeps a single-use grant → the proxy sends the placeholder over the token socket →
  keyd unseals the Protector and logs in to `tpm2-pkcs11` → challenge signed by the TPM key inside keyd → PAM success.
- **PIN fallback**: same path, `C_Login` sends the PIN to keyd instead of the placeholder.
- **Recovery**: the unlock socket takes a recovery code and returns only a fresh code; it never returns K.
- **Purge**: `openhellod` Purge also calls `openhello-keyd` purge: evict the TPM key, delete Protectors, remove
  the token objects (AC-033, extends P-008).

## Spike findings (T-014, `spike.md`)

- `openhello-pkcs11` only needs to export `C_GetFunctionList` and `C_Login`; the Protector secret goes to `tpm2-pkcs11` as 40 hex characters.
- `pam_pkcs11` prompts for a PIN before `C_Login` and rejects an empty one, so the PAM conversation answers a fixed non-empty placeholder that the wrapper discards (T-019, T-022).
- The TPM dictionary-attack counter is global: a wrong PIN also counts against every other TPM use. T-017 sets `max-tries` and `recovery-time` explicitly.
- Tests run `tpm2-abrmd` over `swtpm`; without a resource manager the tools leak transient handles. `pamtester` is not packaged, so tests use a small `pam_wrapper` client.

## Order of work and risk

The spike (T-014) proved on `swtpm` that `tpm2-pkcs11` + `pam_pkcs11` + a `C_Login` override work with P-256, so
the design stands. Still unproven: the physical TPM, the real `sudo` stack and the KDE lock screen (ASM-011).

## Testing approach

- **TPM**: `swtpm`, never the physical TPM (same rule as `face-recognition-proof`).
- **Faces**: `openhellod` is replaced by a test ticket issuer; live face checks reuse the recorded-frame fixtures.
- **PAM**: run `pamtester` against a private PAM service file in a temp dir, not the system `sudo` stack.
- **Lock screen (AC-028)**: manual on the Plasma session, recorded as partial evidence like ASM-001 until a
  scripted check exists.
