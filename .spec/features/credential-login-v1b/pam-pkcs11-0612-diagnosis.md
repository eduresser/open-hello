# pam_pkcs11 0.6.12 (Ubuntu noble) fails with the open-hello PKCS#11 proxy

Read-only diagnosis. Upstream sources: tags `pam_pkcs11-0.6.12` and `pam_pkcs11-0.6.13` of https://github.com/OpenSC/pam_pkcs11.

## Cause

The proxy chain rejects every `C_FindObjectsInit` template that holds an attribute other than `CKA_CLASS/TOKEN/ID/LABEL/VALUE/ISSUER/SERIAL_NUMBER/SUBJECT`. The OpenSSL build of pam_pkcs11 (Ubuntu) uses two templates with attributes outside that list. `C_FindObjectsInit` returns `CKR_ARGUMENTS_BAD` (0x7), pam_pkcs11 discards the error, and the certificate list stays empty.

1. Certificate template, [`pkcs11_lib.c#L1521-L1531`](https://github.com/OpenSC/pam_pkcs11/blob/pam_pkcs11-0.6.12/src/common/pkcs11_lib.c#L1521-L1531), used at [`#L1541`](https://github.com/OpenSC/pam_pkcs11/blob/pam_pkcs11-0.6.12/src/common/pkcs11_lib.c#L1541) with count 2:
   ```c
   CK_ATTRIBUTE cert_template[] = {
     {CKA_CLASS, &cert_class, sizeof(CK_OBJECT_CLASS)},
     {CKA_CERTIFICATE_TYPE, &cert_type, sizeof(CK_CERTIFICATE_TYPE)},   /* 0x80 */
     {CKA_ID, NULL, 0}, {CKA_VALUE, NULL, 0} };
   rv = h->fl->C_FindObjectsInit(h->session, cert_template, 2);
   ```
2. Private-key template, [`get_private_key`, `#L1676`](https://github.com/OpenSC/pam_pkcs11/blob/pam_pkcs11-0.6.12/src/common/pkcs11_lib.c#L1676): `{CKA_CLASS=PRIVATE_KEY, CKA_SIGN=true, [CKA_ID=cert id]}` (count 3 when the cert has an id). `CKA_SIGN` is 0x108.

Server side, [`parse_template`](../../../crates/openhello-keyd/src/token_socket.rs#L636-L667) turns the payload into `Attribute`s and ends with [`_ => return None`](../../../crates/openhello-keyd/src/token_socket.rs#L659). [`find`](../../../crates/openhello-keyd/src/token_socket.rs#L485) answers `TOKEN_BAD_REQUEST`, and [`failure_code`](../../../crates/openhello-pkcs11/src/proxy.rs#L82-L92) maps it to `CKR_ARGUMENTS_BAD`. The proxy's [`find_objects_init`](../../../crates/openhello-pkcs11/src/proxy.rs#L471-L508) forwards the template unchanged, so it is not the culprit.

## Why pam_pkcs11 only says "no valid certificate"

[`pam_pkcs11.c#L514-L516`](https://github.com/OpenSC/pam_pkcs11/blob/pam_pkcs11-0.6.12/src/pam_pkcs11/pam_pkcs11.c#L514-L516):
```c
cert_list = get_certificate_list(ph, &ncert);
if (rv<0) {          /* rv is the stale C_Login result: the failure is never seen */
```
`get_certificate_list` returns NULL and leaves `ncert` unset. The loop at [`#L529`](https://github.com/OpenSC/pam_pkcs11/blob/pam_pkcs11-0.6.12/src/pam_pkcs11/pam_pkcs11.c#L529) runs zero times (no "verifying the certificate" line), and [`#L631`](https://github.com/OpenSC/pam_pkcs11/blob/pam_pkcs11-0.6.12/src/pam_pkcs11/pam_pkcs11.c#L631) logs Error 2336. The success path logs "Found %d certificates in token"; that line is absent from the VM journal, which confirms the error path. The `ncert` value depends on the stack, so the stale value is a latent bug in 0.6.12 and 0.6.13 (unchanged).

## Why openSUSE 0.6.13 works

The openSUSE build is linked against NSS (`ldd` shows `libnss3`); the Ubuntu build links only OpenSSL (`libcrypto.so.3`, no `libnss3`). The NSS build does not run the raw `get_certificate_list` above: it reads objects through NSS (`PK11_*`), which builds its own templates. The 0.6.12 to 0.6.13 diff of `get_certificate_list` and `get_private_key` only changes memory handling, not templates. The difference is the build flavour, not the version. `nss_dir` in `pam_pkcs11.conf` is ignored by the OpenSSL build.

## Reproduction on the VM (no login, no face match)

Script: `/tmp/p11pam.py` on the VM (copy of `p11list.py`), run with `OPENHELLO_KEYD_TOKEN_SOCKET=/run/openhello/keyd-token.sock`:

```
{CLASS=cert, CERTIFICATE_TYPE=X509}      FindInit rv=0x7  count=0   <- fails before login
class only                               FindInit rv=0x0  count=1
GetAttr [CLASS,CERT_TYPE,ID]             rv=0x0 idlen=16            (pam's pass-1 call works)
GetAttr [CLASS,CERT_TYPE]                rv=0x0
{CLASS=privkey, SIGN=true}               FindInit rv=0x7            <- second break, also pre-login
{CLASS=privkey, SIGN=true, ID}           FindInit rv=0x7
class=privkey only                       FindInit rv=0x0  count=0   (private key appears only after login)
```

Provable only after login: that `get_private_key` finds the private key with the cert's `CKA_ID`, `C_GetAttributeValue(CKA_KEY_TYPE)` on the private key (`KeyType` is in `PRIVATE_KEY_READABLE`, so it should pass), `C_SignInit(CKM_ECDSA)` plus `C_Sign` over the raw 32-byte SHA-256 (`h_offset = 19` skips the DigestInfo for EC, [`#L1783-L1796`](https://github.com/OpenSC/pam_pkcs11/blob/pam_pkcs11-0.6.12/src/common/pkcs11_lib.c#L1783)), and `verify_signature` in `cert_vfy.c` (accepts raw r||s for EC, [`#L536-L543`](https://github.com/OpenSC/pam_pkcs11/blob/pam_pkcs11-0.6.12/src/common/cert_vfy.c#L536-L543)). Source reading gives no further blocker, but this part is not yet proven. `MAX_SIGN_INPUT=128` covers the 32 bytes.

## Minimal fix (not implemented)

File: `crates/openhello-keyd/src/token_socket.rs`, function `parse_template` (L636-667).

1. Add `const CKA_CERTIFICATE_TYPE: u64 = 0x80;` and `const CKA_SIGN: u64 = 0x108;` next to the other `CKA_*` constants (L50-57).
2. Add match arms before `_ => return None`:
   - `CKA_CERTIFICATE_TYPE` -> `Attribute::CertificateType(CertificateType::try_from(u64::from_ne_bytes(value.try_into().ok()?)).ok()?)` (8 bytes, native endian, like `CKA_CLASS`).
   - `CKA_SIGN` -> `Attribute::Sign(*value.first().filter(|_| value.len() == 1)? != 0)` (1 byte, like `CKA_TOKEN`).
   Keep the `_ => return None` default: an unknown attribute stays refused. No change in `proxy.rs` or in the exposed classes, and the `only_certificates` guard still holds.
3. Optional hardening, not needed for this bug: nothing in the proxy needs to change. If the process later reports the same pattern for other attributes, add `CKA_DECRYPT`/`CKA_VERIFY` etc. only when a client needs them.

Tests:
- Unit test in `token_socket.rs` for `parse_template`: `{CLASS=CERTIFICATE, CERTIFICATE_TYPE=X_509}` and `{CLASS=PRIVATE_KEY, SIGN=true, ID}` are accepted; a template with an unknown type (for example `CKA_MODULUS`) is still refused.
- Extend `crates/openhello-keyd/tests/token_proxy.rs`: after `OP_TOKEN_FIND` with the exact pam_pkcs11 templates, the reply holds 1 certificate before login and 1 private key after login.
- Extend `crates/openhello-pkcs11` (proxy) tests, or the VM script `/tmp/p11pam.py`, with the same templates; `FindInit` must return 0 and `count=1` for the certificate.
- End to end: `sudo true` on the VM with face match. The log must show "Found 1 certificates in token", "private key type: 0x00000003", "verifying signature..." and "authentication succeeded". The openSUSE NSS tests in `crates/openhello-cli/tests/pam_sudo.rs` do not cover the OpenSSL path; a case with the Ubuntu build (or a ctypes test that replays these templates) closes the gap.

## Compatibility and alternatives

Not fundamentally incompatible; only the template filter is too strict. Risks that remain after the fix: the stale-`rv` bug (a later transient error in the proxy would again look like "no certificate"), and the Ubuntu build ignoring NSS trust (`cert_policy=signature` skips the CA check, so the `CT,C,C` NSS entry is unused there). If the OpenSSL path shows more failures after login, fall back to: `pam_openhello` asks keyd to sign a random challenge (the `OP_TOKEN_SIGN` path already exists) and verifies it with the public key from the enrolled certificate, with no pam_pkcs11 in the chain.
