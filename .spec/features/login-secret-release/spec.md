# Spec: Login secret release

> feature: login-secret-release
> status: draft

## Context

When the owner signs in with the face, no password is typed, so password-derived keyrings (KWallet through `pam_kwallet5`, GNOME Keyring, encrypted homes) stay locked and ask for the password after the first login; like Windows Hello for local accounts, OpenHello keeps the login password sealed by the TPM and hands it to the rest of the sign-in after a TPM-verified face match, with no desktop-specific code.

Decisions taken with the owner (2026-10-23): release only to system sign-in services that run as root (login managers, console login, su, sudo, polkit), never to processes of the user such as lock screens; learn the password on every successful password sign-in by such a service; before implementing, a spike runs the release against the real PAM stacks of openSUSE, Fedora, Debian/Ubuntu and Arch, and any stack that prompts again goes back to the owner.

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

#### AC-080 — A stale sealed password falls back to the normal password prompt

- **Given** a sealed password that no longer matches the account (the password was changed elsewhere)
- **When** the face matches and the password module rejects the released token
- **Then** the user is asked for the password as usual, with no extra lockout or delay from OpenHello

#### AC-081 — Without a sealed password, face sign-in works as before

- **Given** a user with an enrolled face and no sealed password yet
- **When** a system sign-in service authenticates them and the face matches
- **Then** the sign-in is granted by OpenHello alone, exactly as before this feature, and no token is set

### US-026 — OpenHello learns my password and keeps it current

As the owner, I want OpenHello to learn my password whenever I sign in with it, so that a password change never needs a separate step.

#### AC-082 — A successful password sign-in seals the verified password

- **Given** a user with an enrolled face
- **When** a system sign-in service grants them access after they typed their password and establishes credentials (pam_setcred)
- **Then** openhello-keyd holds that password sealed by the TPM for that user (no plaintext copy on disk)

#### AC-083 — A new password replaces the sealed one

- **Given** a user whose sealed password is the old one
- **When** they sign in with the new password through a system sign-in service
- **Then** the next face sign-in releases the new password

#### AC-084 — Failed or password-less sign-ins never change the sealed password

- **Given** a user with a sealed password
- **When** a sign-in fails, or succeeds without a typed password (face only, or another module)
- **Then** the sealed password is unchanged

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
- **Then** the sealed password can no longer be released, because its TPM key is destroyed

### US-028 — It works on the main distributions without asking for the password

As the owner, I want the release proven on real distribution PAM stacks before shipping, so that a face login never shows an unexpected password prompt.

#### AC-090 — The release signs in without a prompt on the real stacks of the main distributions

- **Given** the unmodified login-manager and common auth PAM files of openSUSE Tumbleweed, Fedora, Debian/Ubuntu and Arch, with OpenHello enabled the way the package enables it
- **When** a face match releases the correct password through each stack (pam_wrapper)
- **Then** each stack grants the sign-in without any password prompt and the keyring stub receives the password

## Out of scope

- Lock screens and other user-owned processes (US-027 decision): their keyrings are already open.
- A `pam_sm_chauthtok` hook: the next password sign-in refreshes the sealed password (AC-083).
- Typing the password in the Open Hello window to seal it.
- Remote sessions (ssh) and services the module already ignores.
- Desktop- or keyring-specific code (no KWallet/GNOME data keys, no per-desktop PAM files).

## Assumptions

| ID | Assumption | Status | Resolution |
|---|---|---|---|
| ASM-025 | Linux-PAM calls `pam_sm_setcred` of every module in the auth stack after a successful authentication, with the typed password still in PAM_AUTHTOK, even when OpenHello returned "ignore" | open | — |
| ASM-026 | The distribution password modules reuse a PAM_AUTHTOK set by an earlier module without prompting (try_first_pass/use_first_pass or pam_get_authtok behaviour) | open | — |
| ASM-027 | The login password is sealed with envelope encryption (AEAD under a TPM-sealed key, as P-006) because a TPM sealed object holds at most 128 bytes | open | — |
| ASM-028 | Until the first password sign-in after this feature ships, a face login still asks for the keyring password once | open | — |

## Open questions

| ID | Question | Status | Answer |
|---|---|---|---|
| Q-006 | If the spike (AC-090) finds a distribution whose stack prompts again, what should OpenHello do there? | open | Owner chose to decide after seeing the spike data (2026-10-23) |
