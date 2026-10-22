# Spike T-014: tpm2-pkcs11, pam_pkcs11 and a C_Login wrapper on swtpm

Date: 2026-10-20. Reproduce with `scripts/spike-pkcs11.sh` (no root, never touches `/dev/tpm0`; exit 0 when all checks pass).

## Verdict

| Assumption | Result | Suggested status |
|---|---|---|
| ASM-010 swtpm: ECC P-256 and dictionary-attack lockout | proved | validated |
| ASM-006 `pam_pkcs11` verifies P-256 from `tpm2-pkcs11` | proved (on swtpm, with the two caveats below) | validated |
| ASM-007 wrapper replaces only `C_Login` | proved for the call path; one caveat on the PAM prompt | validated, with the caveat recorded in the design |
| ASM-011 KDE lock screen runs the PAM service | not proved (needs a Plasma session) | open |

Recommendation: keep the design (ECDSA P-256, no RSA-2048 fallback needed). Adjust three details in `design.md`, listed under "Design adjustments".

## Environment

- openSUSE Tumbleweed, `tpm2.0-tools` 5.7, `swtpm` 0.10.2.
- Packages unavailable on the host were fetched with `zypper --pkg-cache-dir=<dir> download` (works as a normal user) and unpacked with `rpm2cpio | cpio` into a private prefix: `tpm2-pkcs11` 1.9.1, `pam_pkcs11` 0.6.13, `pam_wrapper` 1.1.8, `libtss2-tcti-swtpm0`, `tpm2.0-abrmd` 3.0.0, `mozilla-nss-tools` and Python dependencies.
- `pamtester` is not packaged for Tumbleweed. A 25-line C client (`pamtest`) on top of `pam_wrapper` replaces it: it runs a private PAM service file without root.
- No step required root. Nothing was installed system-wide.

## ASM-010: swtpm ECC P-256 and lockout (proved)

Direct swtpm TCTI, `tpm2-tools`:

```
tpm2_getcap ecc-curves        -> TPM2_ECC_NIST_P256: 0x3
tpm2_create -G ecc256:ecdsa-sha256 ... ; tpm2_sign -s ecdsa ; tpm2_verifysignature   -> verified
tpm2_dictionarylockout --setup-parameters --max-tries=3 --recovery-time=3600 --lockout-recovery-time=3600
3 x tpm2_sign -p wrong   -> "authorization HMAC check failed and DA counter incremented"
                            TPM2_PT_LOCKOUT_COUNTER: 0x3, inLockout: 1
tpm2_sign -p <correct>   -> 0x921 "authorizations for objects subject to DA protection are not allowed ... DA lockout mode"
tpm2_dictionarylockout --clear-lockout -> correct auth value works again
```

Notes for the implementation:

- `--recovery-time=0` disables the counter (wrong attempts are accepted without counting). Tests must set a non-zero recovery time.
- Without a resource manager, `tpm2-tools` leaks transient handles (swtpm has 3 slots): flush with `tpm2_flushcontext -t` between commands, or use `tpm2-abrmd` / `/dev/tpmrm0`. `tpm2_ptool` needs the resource manager; the script runs `tpm2-abrmd --session` on a private D-Bus against swtpm.
- The lockout is TPM-wide, not per key (see the design adjustments).

## ASM-006: pam_pkcs11 with a P-256 token (proved)

Token created with `tpm2_ptool addtoken` and `addkey --algorithm ecc256`; the PKCS#11 module reports `CKK_EC`, params `06082a8648ce3d030107` (prime256v1). A user certificate was issued by a throwaway CA over the TPM public key (`openssl x509 -force_pubkey`) and stored with `tpm2_ptool addcert`. `pam_pkcs11` runs through `pam_wrapper` with a private service file, `cert_policy` `signature` and `ca,signature`, subject mapper.

| Case | Outcome |
|---|---|
| correct PIN, `cert_policy=signature` | `pam_authenticate=0` |
| correct PIN, `cert_policy=ca,signature` (CA in an NSS db) | `pam_authenticate=0` |
| negative control: cert whose public key is not the TPM key | `Error 2342: Verifying signature failed`, `pam_authenticate=7` |
| wrong PIN | `Error 2320: Wrong smart card PIN`, `pam_authenticate=7` |
| empty PIN | `Error 2318: Empty smart card PIN not allowed` (rejected before `C_Login`) |
| direct `C_Login`+`C_Sign` with `CKM_ECDSA` | `CKR_OK`, 64-byte signature |
| direct `C_Login` with wrong PIN | `CKR_PIN_INCORRECT` (0xa0) and TPM `LOCKOUT_COUNTER` goes to 1 |

The negative control rules out a false positive: the module does verify the signature against the certificate key.

Limits: proved on swtpm with the packaged `pam_pkcs11` 0.6.13 on this system. Not proved against the physical TPM (`/dev/tpm0`) or a Plasma PAM stack.

## ASM-007: C_Login wrapper (proved)

`libopenhello_p11wrap.so` (about 45 lines of C, source embedded in the script) exports only `C_GetFunctionList`, `dlopen`s the real `libtpm2_pkcs11.so`, copies its function table and replaces `C_Login`. The stand-in for `openhello-keyd` is a ticket file plus a secret from the environment.

| Case | Outcome |
|---|---|
| no ticket, PAM answers `placeholder` | wrapper returns `CKR_PIN_INCORRECT`, PAM fails (`Error 2320`) |
| ticket present, PAM answers `placeholder` | wrapper ignores the PAM PIN, logs in with the real secret, `pam_authenticate=0` |
| same run | `[p11wrap] C_Login called` observed, ticket consumed (single use) |
| second attempt without a new ticket | fails |
| 40-char hex PIN (20 random bytes) on a P-256 token | `C_Login` + `C_Sign` succeed |

`pam_pkcs11` loads the module through NSS, which also works with the wrapper.

Caveat (affects T-019 and AC-028): `pam_pkcs11` asks the PAM conversation for a PIN before it calls `C_Login` and rejects an empty answer. The conversation therefore has to return any non-empty placeholder. A wrapper that advertises `CKF_PROTECTED_AUTHENTICATION_PATH` (to skip the prompt) was tried and did not work in 0.6.13: the prompt text changes to "Enter your PIN on the pinpad" but `C_Login` is never reached. Options: a tiny PAM module before `pam_pkcs11` that sets `PAM_AUTHTOK` to a placeholder with `use_first_pass`, or a PAM service whose conversation answers the prompt.

## Design adjustments

1. Wrapper scope: the wrapper only needs `C_GetFunctionList` and `C_Login`; `C_GetInterface` (PKCS#11 3.0) is not forwarded. `pam_pkcs11`/NSS do not use it. Revisit if SSH or Firefox are added later.
2. PIN encoding: `C_Login` takes text. Release the 20-byte Protector secret as 40 hex characters (proved), never as raw bytes.
3. Lockout scope: the TPM counter is global (the wrong PKCS#11 PIN raised the same `LOCKOUT_COUNTER` that guards the whole TPM, including other TPM users such as disk unlock). Recommend a dedicated `max-tries`/`recovery-time` decision in T-017 and an explicit warning in the PIN lockout message; it also means CI tests must `--clear-lockout` between cases.
4. Placeholder PIN: see the caveat above; T-019 must include it in the PAM service design.

## Not proved

- ASM-011: no Plasma session was driven. Lead for the manual test: `kscreenlocker6` ships `/usr/lib/pam.d/kde-smartcard` (uses `pam_pkcs11.so wait_for_card card_only`), so a dedicated service with the same shape is plausible. Not run.
- Behavior on the physical TPM (`/dev/tpm0`, `/dev/tpmrm0`): not tested by design. Firmware DA defaults on real hardware may differ from swtpm.
- `sudo` and display-manager stacks: only a private PAM service through `pam_wrapper` was run.
- The ticket check here is a file. Nothing was proved about the `openhellod` to `openhello-keyd` ticket protocol, `SO_PEERCRED` or the Protector storage (ASM-008, ASM-009).
