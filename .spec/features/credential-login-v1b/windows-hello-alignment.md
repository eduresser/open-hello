# Windows Hello alignment audit: credential-login-v1b

> Read-only audit. Owner rule: (1) what Windows Hello does, (2) the Linux equivalent, (3) other adaptations.
> Marks: **confirmed** = stated in `docs/windows-hello-arquitetura.md` (WH-doc, from reverse engineering) or in Microsoft documentation; **inferred** = reasoning, community sources or absence of evidence.
> Statuses: aligned / diverges-justifiable / diverges-unjustified / no-evidence-in-windows.

Sources (Microsoft):
- [MS-HOW] https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/how-it-works
- [MS-AUTH] https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/how-it-works-authentication
- [MS-OVR] https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/
- [MS-ESS] https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/windows-hello-enhanced-sign-in-security
- WinBio ticket functions (`WinBioVerifyAndReleaseTicket`, `WinBioGetCredentialWithTicket`): no public Microsoft page found (the learn.microsoft.com URLs return 404; search finds nothing). Only the WH-doc has them (export names).

## Highlights (top)

1. **ASM-014 was decided without citing the Windows key-trust / Cloud AP flow.** The design cites only "credential provider talks to the key service directly". Checked against level 1, the decision is **in the direction of Windows**, and closer than `pam_pkcs11` + certificate + NSS: in Windows (Entra, key trust, MSA) the verifier gets a nonce, the key signs it and the verifier checks it against a **public key registered by a trusted path** (no PKI for key trust). Status: diverges-justifiable, with two points that need an explicit decision (see item 3): where the verifier runs, and what the Linux doc (level 2) said (`pam_pkcs11`), which ASM-014 overrides without recording a Windows reason.
2. **Anti-spoofing absent is a divergence from the Windows baseline, not only from ESS.** [MS-OVR] requires anti-spoofing for every Hello face sensor (FAR < 0.001%, anti-spoofing required); ESS only adds VBS isolation. The spec compares itself to ESS (the wrong baseline). Accepted risk is documented (ASM-005), so it is justified, but the wording must change.
3. **Windows Hello for local accounts is not key-based.** [MS-OVR]: "This configuration isn't backed by asymmetric (public/private) key". The Linux PAM case is a local account, so there is no Windows precedent for a signed challenge on local logon; the key-based flows are MSA/Entra/AD. Our scheme is therefore stronger than the Windows local-account case and mirrors the MSA/Entra pattern (adaptation, level 1 by analogy).
4. Nothing found that diverges relevantly and is also unjustified. Items with a loose end: biometric failure counter (item 8), ticket details (item 1, no evidence), per-Protector HMAC binding mentioned by `arquitetura-linux.md` but absent from spec/design (item 2).

## Table by decision

### 1. Short-lived ticket between openhellod and keyd (TTL 5 s, single use, HMAC, ephemeral key)

| Aspect | Content |
|---|---|
| (a) Windows | Tickets exist: `WinBioVerifyAndReleaseTicket`/`IdentifyAndReleaseTicket`, `WinBioGetCredentialWithTicket`, `WinBioNgcGetAuthorizationWithTicket`; `FaceBioListener::RenewWinBioTicket`. **confirmed** (WH-doc, "Camada 1", "Credential Provider"). TTL, MAC, single use, lifetime: **no evidence** (no decompilation of the ticket path; no public MS page found). |
| (b) Ours | `{uid, nonce, expiry}` + HMAC-SHA256 with ephemeral key, TTL 5 s (ASM-009, provisional), single use, delivered over the root-only socket (design.md, `openhello-ticket`). |
| (c) Status | aligned in concept (confirmed); parameters: no-evidence-in-windows. Level 2 (`arquitetura-linux.md`, "Protector": ticket "assinado/HMAC com uma chave efêmera", "freshness") backs the mechanism. |
| (d) Recommendation | Keep. Mark TTL/single use as "Linux design (level 2/3), no Windows evidence" in ASM-009. `RenewWinBioTicket` (**confirmed** name only) suggests the Windows credential provider renews tickets during long camera sessions: not needed for our 4 s `Verify` flow. Optional, low priority: decompile `wbiosrvc.dll` ticket handling with `rea` only if the owner wants Windows numbers; not a blocker. |

### 2. Protectors (biometric, PIN, recovery); NGC model

| Aspect | Content |
|---|---|
| (a) Windows | Protector = any factor that unlocks the same container; PIN and biometrics are two Protectors, not two systems (WH-doc "Container NGC e Protector", "PIN como fallback", **confirmed**). [MS-HOW]: each gesture has its own protector key and each protector wraps its own copy of the authentication key; the PIN protector is a TPM seal with the PIN as entropy (**confirmed**). Bio Protector secret is software random (2×20 B + HMAC-SHA1), TPM not involved in creating it (WH-doc, decompilation, **confirmed**). PIN has soft lockout (`ContainerGetSoftLockoutInfo`, **confirmed**). Recovery: `ngcrecovery.dll` with a separate recovery secret, no key reissue (**confirmed**); [MS-HOW] "PIN reset" generates a new authentication key and re-wraps (**confirmed**). Rotation of the recovery secret on use: not evidenced (**inferred**). |
| (b) Ours | One key; Protector secrets of 20 B; PIN guarded by TPM dictionary-attack lockout (global); biometric secret sealed without authValue, released only against a ticket (ASM-008); recovery code shown once and rotated on use. |
| (c) Status | PIN and bio as Protectors of one key, recovery as separate secret: **aligned**. TPM DA lockout instead of software soft lockout: diverges-justifiable (level 2 improvement, `arquitetura-linux.md` threat-model table). Bio secret sealed without authValue and released by keyd: diverges-justifiable (non-ESS Windows also releases it from a normal-mode service; ESS uses a VBS-to-TPM channel, not available, ASM-008 documents it). Rotation on use: Linux adaptation (level 3, justified by single use). Per-Protector HMAC binding: `arquitetura-linux.md` says "20 bytes + HMAC-SHA256"; spec/design do not mention it: **to check** (diverges-unjustified if dropped without a note; low impact). |
| (d) Recommendation | Keep. Add one line to design.md: "Protector HMAC binding from the Linux doc is [kept / dropped because ...]". Note in ASM-008 that [MS-ESS] confirms the Windows weaker (non-ESS) mode has the same property. |

### 3. Local unlock proof of possession (ASM-014): signed challenge verified by pam_openhello

| Aspect | Content |
|---|---|
| (a) Windows | **Confirmed (MS-AUTH):** Entra join: Cloud AP asks the IdP for a nonce, signs it with the user's private key, "Microsoft Entra ID validates the signed nonce using the user's securely registered public key". AD **key trust**: the Kerberos provider signs the preauthentication data with the private key and sends the public key as a self-signed certificate; the KDC "retrieves the public key from the certificate... searches for the public key in Active Directory", checks the UPN and validates the signature (no PKI chain). **Certificate trust**: the KDC validates a certificate chain from the enterprise PKI. **Cloud Kerberos trust**: Entra validates the nonce and issues a partial TGT. Public key registration: [MS-HOW] "The public key is registered with the IdP, mapped to the user account"; in hybrid it is synchronized to `msDS-KeyCredentialLink`; provisioning requires prior authentication plus a second factor ("the provisioning flow requires a second factor ... before it can generate a public/private key pair"). Verifier = IdP/KDC/LSASS, never the process that shows the UI. Cache: LSASS caches PRT/TGT after success (offline sign-in needs a cached credential; [MS-AUTH] notes first-time sign-in needs line of sight). **WH-doc (confirmed):** the NGC container presents itself as a virtual GIDS smart card, so logon uses the smart-card/PKINIT stack; `NgcSerializeKeyCredential`/`NgcSerializeKeySspiCredential`/`NgcSerializeSmartCardCredential` serialize the unlocked key into a logon package that LSA validates (`ngckeyenum.dll`). **Local accounts (confirmed, MS-OVR):** Hello with a local account "isn't backed by asymmetric (public/private) key". What a local account really does at logon is not documented: community reports suggest the PIN unlocks locally stored material that yields the account credential (**inferred**, not in WH-doc). |
| (b) Ours | `pam_openhello` makes a random challenge, calls openhellod `Verify` (ticket to keyd), keyd signs `"openhello-pam-v1" || uid || challenge` with the TPM key, PAM verifies with `/etc/openhello/auth/<uid>.pub` (root-owned, written by Provision, removed by Purge). No certificate, NSS, mapper. |
| (c) Status | **diverges-justifiable; level 1 by analogy.** Pattern equals nonce-sign-verify-against-registered-public-key (Entra/MSA, AD key trust). Registry of public keys written on a trusted path = `msDS-KeyCredentialLink`/Entra user object. Skipping certificates = key trust (no PKI). It diverges from the Linux doc (level 2: `pam_pkcs11`, mirror of the GIDS/PKINIT trick), but level 1 does not require a certificate for key trust, so the override has a Windows basis the spec did not cite. Points where it differs from Windows: (i) **verifier location**: Windows verifies outside the UI process (KDC/IdP/LSASS); ours verifies inside the PAM module in the caller process: fine for `sudo` (root process), weaker for lock screens that run as the user (a user-level compromise can already kill the locker, so no new exposure, but say so); (ii) the nonce comes from the verifier: ours too (PAM is the verifier): aligned; (iii) no cache: not applicable, PAM is online; (iv) registration needs prior authentication: polkit `auth_self_keep`/`auth_self` for Provision/SetPin/Purge (checked in `io.openhello.Keyd1.policy`): aligned (**inferred** analog of the provisioning second factor). |
| (d) Recommendation | Record the Windows basis in ASM-014 (cite [MS-AUTH] key trust and Cloud AP, and "NgcSerializeKeyCredential" in WH-doc). Keep the design. Keep the registry root-owned and written only by keyd (the analog of the admin-controlled key sync). Say explicitly that the public key file is the `KeyCredentialLink` analog and that on lock screens the verifier runs in the user's process. Keep `pam_pkcs11` documented as the level 2 path for SSH/LUKS. |

### 4. Per-caller authorization (SO_PEERCRED + polkit; no peer executable check, uid 0 only)

| Aspect | Content |
|---|---|
| (a) Windows | RPC with `RpcImpersonateClient`/`RpcRevertToSelf` per call (WH-doc, **confirmed**). `NgcAddBioProtector` is reachable only from SYSTEM: security descriptor `D:(A;;GR;;;SY)` (WH-doc, decompilation, **confirmed**). `LogonIdentifiedUser`: the service (SYSTEM) authorizes logon, never the client (**confirmed**). `PlugInLoadCheckSigningLevel` checks the signature of **plugins at load**, not of the RPC caller (**confirmed**). No executable-of-caller check is described (**inferred** from absence). |
| (b) Ours | Ticket socket: uid 0 only (executable check dropped, needed ptrace). Token/unlock sockets: uid from `SO_PEERCRED`, root peer may name the target uid. D-Bus: sender + polkit. |
| (c) Status | **aligned** for uid 0 only (Windows' SDDL is "SYSTEM only", same trust level; the dropped executable check has no Windows counterpart). `SO_PEERCRED` = impersonation analog (level 2, `arquitetura-linux.md`, "RPC local... SO_PEERCRED"). polkit: no Windows evidence, level 2/3 adaptation, justified (D-Bus has no impersonation). |
| (d) Recommendation | None. Add the SDDL fact to the design finding as the Windows backing for "uid 0 only". Root peer naming the target uid: matches `LogonIdentifiedUser` (service-side authority); keep root-only. |

### 5. Purge (ASM-012: no persistent TPM handle)

| Aspect | Content |
|---|---|
| (a) Windows | Containers are "logical units": "There are no physical containers on disk, in the registry, or elsewhere" ([MS-HOW], **confirmed**); keys are blobs under the NGC store, protected by TPM; no persistent handle is described. Template purge exists (`purge.cpp` in the storage adapter, WH-doc **confirmed**). Resetting the PIN generates a new authentication key and re-wraps all material ([MS-HOW], **confirmed**). Deleting the NGC folder removes the PIN (community, **inferred**). WH-doc does not describe a full NGC key destruction path. |
| (b) Ours | Remove token, Protector blobs, certificate/map, (T-034) public key file. No persistent TPM object to evict. |
| (c) Status | **aligned** with Windows structure (blobs, no persistent handle). The residual attack (copy of the store + same TPM + protector blobs) exists in Windows too (**inferred**). Spec wording "TPM key is evicted" (AC-033) overstates; ASM-012 is right to flag it. |
| (d) Recommendation | Close ASM-012 as accepted-by-Windows-parity: do **not** add a persistent handle (it would diverge from the level 1 model). Rewrite AC-033 wording to "key and every Protector are deleted and unusable". Optional hardening with a Windows analog (key rotation on reset): on Purge, change the object's authValue (`TPM2_ObjectChangeAuth`) before deleting blobs, which invalidates stolen copies of the blob + old Protectors. |

### 6. Anti-spoofing absent in v1 (ASM-005) vs Enhanced Sign-in Security

| Aspect | Content |
|---|---|
| (a) Windows | [MS-OVR] (**confirmed**): face sensors "must also include anti-spoofing measures (required)"; FAR < 0.001%; FRR without anti-spoofing < 5%, with anti-spoofing < 10%. WH-doc: `AccountAntiSpoofPolicy`, framework can refuse devices below ESS (**confirmed**). [MS-ESS] (**confirmed**): ESS adds VBS isolation of the face algorithm, camera-to-VBS memory path, secure channel to the TPM, SDEV table; non-ESS Windows still runs anti-spoofing in a normal process. |
| (b) Ours | No anti-spoofing; printed-photo spoof accepted for v1a; appearance classifier deferred. FAR 1e-5 matches the Windows target (WH-doc). |
| (c) Status | **diverges-justifiable.** Documented in `arquitetura-linux.md` and ASM-005, but compared against the wrong baseline: the divergence is from the Windows non-ESS baseline (anti-spoofing required), not only from ESS. |
| (d) Recommendation | Reword every mention: "weaker than Windows Hello baseline (anti-spoofing required) and than ESS (isolation)". Keep the schedule (v2). Consider gating the lock screen face path as opt-in until anti-spoofing exists (Windows would not certify the sensor). |

### 7. Password fallback

| Aspect | Content |
|---|---|
| (a) Windows | PIN is a Protector of the same container, not the account password (WH-doc, [MS-OVR] "backed up with a PIN", **confirmed**). The account password is a separate credential provider tile (**inferred** from the credential-provider model); with local accounts both PIN and password remain available (community, **inferred**). |
| (b) Ours | PIN opt-in (second PAM line, no `use_first_pass`, because wrong PINs count on the global TPM lockout), password via the next PAM module. PIN not supported on non-interactive lock screens. |
| (c) Status | **aligned** in structure (Q-002 answered correctly). The missing PIN in a non-interactive PAM service is a Linux limitation, diverges-justifiable. |
| (d) Recommendation | None for the model. Document that on lock screens the fallback is the locker's own password path (Windows: PIN tile). Revisit when the greeter UX (v2) exists. |

### 8. Failure policy and user messages on the lock screen

| Aspect | Content |
|---|---|
| (a) Windows | Credential provider `FaceBioListener` handles camera states, group-policy lock, `ProcessWinBioRecognizeResult`; shared PIN/bio UI library `cngcredui.dll` (WH-doc, **confirmed**). PIN soft lockout with backoff (`ContainerGetSoftLockoutInfo`, **confirmed**). Windows also falls back to PIN after repeated failed biometric attempts (general product behavior, **not in the sources checked: inferred, unverified**). |
| (b) Ours | No text; the blinking IR emitter is the indicator (Q-003); failure falls through to the password within 5 s; three attempts within 10 s per request and no persistent failure counter (ASM-015, ASM-016); no state messages. |
| (c) Status | Messages: diverges-justifiable (greeter UX is roadmap v2, Q-003 documented). Failure counter: **no-evidence-in-windows** for the number of attempts; the concept (backoff on PIN) is confirmed for the PIN only. Biometric attempts are bounded by FAR only (ASM-008). |
| (d) Recommendation | Optional now: show short state lines through the PAM conversation (camera unavailable / no face / not recognized), same mechanism as the existing line. Decide a biometric retry cap per window (for example require PIN or password after N failures) as an explicit assumption; label it "Linux design", not "Windows behavior", until verified. |

### 9. Locked screen: parallel credential providers vs PAM services per locker

| Aspect | Content |
|---|---|
| (a) Windows | LogonUI hosts credential providers side by side (face, fingerprint, PIN, password), each a COM DLL implementing `ICredentialProvider` (WH-doc, **confirmed**); [MS-AUTH] phase A: Winlogon shows the Hello credential provider, LSASS validates. |
| (b) Ours | One line in the common PAM auth stack, a compiled denylist of non-desktop services; no desktop code. |
| (c) Status | **aligned in role** (level 2 mapping "LSA/LogonUI... PAM" in `arquitetura-linux.md`); a shared common-auth line is the Linux equivalent of one provider offered in every sign-in context. |
| (d) Recommendation | Prefer the per-service (level A) integration over editing common-auth (level B) as the default, consistent with this mapping. |

## Effect on T-034 and T-035 (signed challenge design and PAM verification)

T-034 (keyd side):
- Keep: root-owned public key registry written by Provision (analog of `msDS-KeyCredentialLink`/Entra user key); one signature per grant; no private key or K leaves keyd.
- Add to Notes: the challenge is generated by the verifier (PAM) and keyd signs only for the uid of the grant (Windows: the nonce comes from the verifier; keyd never picks it). Keep the domain-separated hash. Consider adding the PAM service name to the signed bytes (not a Windows requirement, hardening; the registry is per uid only).
- Add: Purge should delete the public key file and, optionally, rotate the key's authValue before deleting blobs (item 5).
- Registration path: Provision must stay behind prior authentication (polkit `auth_self_keep`, already in the policy), the analog of the provisioning second factor.

T-035 (PAM side):
- Keep: PAM generates the nonce (getrandom), verifies in pure Rust against `/etc/openhello/auth/<uid>.pub`.
- Add a documented decision: verification runs in the PAM module process. For `sudo` (root) it equals Windows in effect; on user-level lock screens it is weaker than Windows (verifier outside the UI process). Options: (A) accept and document (recommended for v1b: the locker is already user-owned); (B) later move verification to a root helper (like `unix_chkpwd`) or into keyd. Do not block T-035.
- Add: reject a missing or non-root-owned public key file as "ignore" (fall through), like the denylist rule.
- ASM-014: add the Windows basis (MS-AUTH key trust/Cloud AP; WH-doc `NgcSerializeKeyCredential`) and note that Windows local accounts are not key-backed, so this is an MSA/Entra-pattern adaptation, not a copy of the local-account flow.
