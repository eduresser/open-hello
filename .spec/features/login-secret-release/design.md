# Design: Login secret release

> feature: login-secret-release

## Flow

```
password sign-in (root service)            face sign-in (root service)
──────────────────────────────            ───────────────────────────
pam_unix verifies the typed password      pam_openhello: face match → ticket to keyd
pam_setcred → pam_openhello setcred       OP_TOKEN_AUTH_RELEASE (challenge, uid, service)
  OP_TOKEN_SEAL_SECRET (uid, password)      keyd: ticket valid → TPM signature
  keyd (peer uid 0 only): AEAD-encrypt      keyd: peer uid 0 and secret sealed → password
  under the user's TPM-sealed key         pam_openhello: signature valid →
                                            PAM_AUTHTOK = password, return PAM_IGNORE
                                          keyring modules read PAM_AUTHTOK (KWallet, GNOME)
                                          pam_unix try/use_first_pass verifies it → grant
```

- No sealed password, or a non-root caller: unchanged behaviour (OpenHello grants alone with `sufficient`).
- Stale password: pam_unix rejects the token; with `try_first_pass` it prompts; the next password sign-in reseals (AC-080, AC-083).

## Components

| Component | Change |
|---|---|
| `openhello-keyd` `login_secret.rs` | per-user secret file: AEAD (as P-006) under a 32-byte key sealed by the TPM with the same primary as the protectors; seal replaces atomically; purge deletes the sealed key first (crypto-shred, P-008) |
| `openhello-keyd` `token_socket.rs` | `OP_TOKEN_AUTH_RELEASE` (AUTH + secret for uid-0 peers) and `OP_TOKEN_SEAL_SECRET` (uid-0 peers only); both refuse other peers without revealing whether a secret exists |
| `openhello-pam` | auth: use AUTH_RELEASE when running as root; set PAM_AUTHTOK and return PAM_IGNORE when a secret came back; setcred: when the auth stack succeeded with a typed password (PAM_AUTHTOK set, not set by OpenHello itself), seal it |
| tests | pam_wrapper harness: keyring stub module after OpenHello records the token; real distro stack files as fixtures for the spike |

## Decisions

- Release consumes the face ticket in the same request as the signature, so a ticket cannot be replayed for the secret (AC-086).
- The module tells "token released by OpenHello" from "token typed by the user" with its own pam data key, so setcred never reseals a released token (AC-084).
- The password lives in memory only inside zeroizing buffers in keyd and the module; PAM_AUTHTOK is cleared by libpam (P-002, AC-088).
