# Spec: Login secret release

> feature: login-secret-release
> status: draft

## Context

When the owner signs in with the face, no password is typed, so password-derived keyrings (KWallet through `pam_kwallet5`, GNOME Keyring, encrypted homes) stay locked and ask for the password after the first login; like Windows Hello for local accounts, OpenHello keeps the login password sealed by the TPM and hands it to the rest of the sign-in after a TPM-verified face match, with no desktop-specific code.

Decisions taken with the owner (2026-10-23): release only to system sign-in services that run as root (login managers, console login, su, sudo, polkit), never to processes of the user such as lock screens; learn the password on every successful password sign-in by such a service; before implementing, a spike runs the release against the real PAM stacks of openSUSE, Fedora, Debian/Ubuntu and Arch, and any stack that prompts again goes back to the owner.

After the spike (T-079, tests/fixtures/pam-stacks/README.md): a correct released token signs in without a prompt on openSUSE, Debian and Arch; a stale token makes the sign-in fail with no prompt, so the release is withheld when the account password changed since sealing (owner decision); PAM_AUTHTOK is already cleared at setcred, so the password is learned by a second OpenHello line placed after the password check (owner decision).

## Stories

### US-025 — Keyrings unlock when I sign in with my face

As the owner who signs in with the face, I want my keyrings to open as if I had typed my password, so that I am not asked for the KWallet password after a face login.

#### AC-078 — The rest of the sign-in receives the sealed password after a face match

- **Given** a user with an enrolled face and a sealed login password
- **When** a system sign-in service (running as root) authenticates them and the face matches with a valid TPM signature
- **Then** the modules after OpenHello in the PAM stack see the exact sealed password as the authentication token (PAM_AUTHTOK)
- **And** the keyring module stub placed after OpenHello records that it received it

#### AC-079 — The system's own password check confirms the released password

- **Given** a face match that released the sealed password
- **When** OpenHello finishes
- **Then** OpenHello does not grant the sign-in by itself: it returns "ignore" and the sign-in is granted by the next password module accepting that token, with no password prompt shown

#### AC-080 — A password changed since sealing is never released

- **Given** a sealed password and an account password that changed afterwards (its /etc/shadow entry differs from the one recorded at sealing)
- **When** the face matches
- **Then** no password is released, the stale sealed password is discarded, and the face signs in alone as before this feature

#### AC-081 — Without a sealed password, face sign-in works as before

- **Given** a user with an enrolled face and no sealed password yet
- **When** a system sign-in service authenticates them and the face matches
- **Then** the sign-in is granted by OpenHello alone, exactly as before this feature, and no token is set

### US-026 — OpenHello learns my password and keeps it current

As the owner, I want OpenHello to learn my password whenever I sign in with it, so that a password change never needs a separate step.

#### AC-082 — A successful password sign-in seals the verified password

- **Given** a user with an enrolled face and OpenHello's capture line placed after the password check
- **When** a system sign-in service verifies their typed password and ends the PAM transaction with success (pam_end), whether or not it calls pam_setcred
- **Then** openhello-keyd holds that password sealed by the TPM for that user (no plaintext copy on disk), together with a fingerprint of their current /etc/shadow entry

#### AC-083 — A new password replaces the sealed one

- **Given** a user whose sealed password is the old one
- **When** they sign in with the new password through a system sign-in service
- **Then** the next face sign-in releases the new password

#### AC-084 — Failed or password-less sign-ins never change the sealed password

- **Given** a user with a sealed password
- **When** a sign-in fails, or succeeds without a typed password (face only, or another module)
- **Then** the sealed password is unchanged

#### AC-091 — Enrolling the face teaches OpenHello the password

- **Given** a user enrolling their face for the first time, who types their password at the system's authorization prompt (polkit) that the Open Hello window triggers
- **When** that prompt succeeds (polkit's helper authenticates and ends the transaction without calling pam_setcred)
- **Then** the password is sealed, so the very first face sign-in afterwards releases it and the keyrings open with no extra step

### US-027 — Only the system can obtain my password

As the owner, I want the sealed password released only to the system sign-in, so that a program running in my account cannot extract it by triggering the camera.

#### AC-085 — Processes of the user never receive the password

- **Given** a user with a sealed password
- **When** a process running as that user (for example a lock screen) authenticates them with a face match
- **Then** no password is released and face sign-in behaves as it does today

#### AC-086 — openhello-keyd releases the password only against a fresh face ticket

- **Given** a sealed password for a user
- **When** a root caller asks openhello-keyd to release it without a valid, unused face ticket for that user, or with a ticket for another user
- **Then** the request is refused and nothing is returned
- **And** a ticket that released the password once cannot release it again

#### AC-087 — Only root may seal a password

- **Given** openhello-keyd running
- **When** a non-root process asks it to seal a password for any user
- **Then** the request is refused and the sealed password is unchanged

#### AC-088 — The password never shows up in logs, errors or stored files

- **Given** sealing, releasing and failing operations with a known password
- **When** their logs, error messages and the keyd store are inspected
- **Then** the password text appears nowhere

#### AC-089 — Deleting the face data destroys the sealed password

- **Given** a user with a sealed password
- **When** they delete their face data (purge)
- **Then** the sealed password can no longer be released, because its key lived only inside the TPM and is destroyed there
- **And** restoring a backup of OpenHello's files taken before the purge does not bring it back

### US-028 — It works on the main distributions without asking for the password

As the owner, I want the release proven on real distribution PAM stacks before shipping, so that a face login never shows an unexpected password prompt.

#### AC-090 — The release signs in without a prompt on the real stacks of the main distributions

- **Given** the unmodified login-manager and common auth PAM files of openSUSE Tumbleweed, Debian and Arch, with OpenHello enabled the way the package enables it
- **When** a face match releases the correct password through each stack (pam_wrapper)
- **Then** each stack grants the sign-in without any password prompt and the keyring stub receives the password

## Out of scope

- Lock screens and other user-owned processes (US-027 decision): their keyrings are already open.
- A `pam_sm_chauthtok` hook: the next password sign-in refreshes the sealed password (AC-083).
- Accounts whose password is not in /etc/shadow (LDAP, AD, SSSD): AC-080 cannot tell a changed password, so nothing is released for them.
- Stacks where the password module ends the stack on success (`auth sufficient pam_unix.so`, e.g. Fedora's authselect profiles): the capture line never runs there; together with the existing authselect placement gap, Fedora is not covered by this feature.
- Typing the password in the Open Hello window to seal it.
- Remote sessions (ssh) and services the module already ignores.
- Desktop- or keyring-specific code (no KWallet/GNOME data keys, no per-desktop PAM files).

## Assumptions

| ID | Assumption | Status | Resolution |
|---|---|---|---|
| ASM-025 | Linux-PAM calls `pam_sm_setcred` of every module in the auth stack after a successful authentication, with the typed password still in PAM_AUTHTOK, even when OpenHello returned "ignore" | invalidated | T-079 spike: setcred is called but PAM_AUTHTOK is empty on all four distributions; capture moves to a second auth line (owner, 2026-10-23) |
| ASM-026 | The distribution password modules reuse a PAM_AUTHTOK set by an earlier module without prompting (try_first_pass/use_first_pass or pam_get_authtok behaviour) | confirmed | T-079 spike: a correct token is reused with zero prompts on openSUSE, Debian and Arch pam_unix, with or without try_first_pass; a wrong token fails with error 7 and no prompt |
| ASM-027 | The login password is sealed with envelope encryption (AEAD under a TPM-sealed key, as P-006) because a TPM sealed object holds at most 128 bytes | confirmed | T-080: XChaCha20-Poly1305 under a 64-byte TPM-sealed key; the key moves to a persistent TPM handle in T-084 (owner, 2026-10-24) |
| ASM-028 | Until the first password sign-in after this feature ships, a face login still asks for the keyring password once | invalidated | Owner wants no extra step (2026-10-24): the enrollment's polkit prompt seals the password (AC-091). Users enrolled before this feature still need one typed password anywhere (for example Set up again) |
| ASM-029 | A second OpenHello auth line appended after the password check of the common stack runs after pam_unix verified the typed password and still sees it, on openSUSE, Debian and Arch | confirmed | T-083 container run (`pam_release_stacks.rs`, tests/fixtures/pam-stacks/README.md): the line `pam enable` appends after the last auth line logged the typed `Correct-Horse-7` after the prompt on openSUSE (after `include common-auth-pc`), Debian (after `pam_permit.so`) and Arch (after `pam_faillock.so authsucc`); PAM_AUTHTOK is unset again in setcred, so the module stashes it during authenticate |

## Open questions

| ID | Question | Status | Answer |
|---|---|---|---|
| Q-006 | If the spike (AC-090) finds a distribution whose stack prompts again, what should OpenHello do there? | answered | No stack prompted with a correct token. Stale tokens fail without a prompt: withhold the release when /etc/shadow changed (AC-080). Fedora fails only because `pam enable` cannot place the module under authselect: out of scope here (owner, 2026-10-23) |
