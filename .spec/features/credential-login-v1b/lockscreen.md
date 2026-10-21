# Lock screen verification

open-hello has no per-distro or per-desktop code and no per-interface command. `pam_openhello` sits once in the common PAM auth stack; any locker, greeter or `polkit` agent that authenticates through PAM reaches it by including that stack. The module acts only for a user with a registered credential (`/etc/openhello/auth/<uid>.pub`), only in a local session, only for services in the root-owned `/etc/openhello/pam-services`, and never as `required`.

Enable and undo: `sudo openhello-cli pam enable` (the installer runs it unless `--no-pam`), `sudo openhello-cli pam disable`, `openhello-cli pam status`.

## What every locker shares

- It calls `pam_authenticate` with a PAM conversation and its own service name.
- Most run as the user, so the keyd token proxy needs no root.
- Most services include the distro's common stack (`common-auth` or `system-auth`); `scripts/pam-survey.sh` lists the includes on a machine without sudo.
- Whether the locker shows PAM info messages, or finishes the unlock after a prompt-less success, is the locker's own behaviour and is not changed by open-hello.

## Verification procedure (any desktop)

1. Keep a second session or `sudo -s` open until the end.
2. `sudo openhello-cli pam status` shows the common stack, the allowlist and the service in use.
3. Lock the screen and face the IR camera; expected: the face authenticates without a password.
4. Failure path: `sudo systemctl stop openhellod`, lock again; the password must work within a few seconds.

Logs: `journalctl -b -u openhellod -u openhello-keyd`; with the `debug` module argument, `journalctl -b -t pam_openhello` (`reason=<code> service=<name>`).

## Record per VM

| Distro | Desktop | Locker | PAM service | Result | Notes |
|---|---|---|---|---|---|
| KDE neon (Ubuntu noble) | KDE Plasma 6.8.0 | kscreenlocker | kde | passed | Face authenticated without a password (`reason=success service=kde`, 2026-10-21). The locker then shows its own single Unlock button; open-hello does not change that. |

Only `sudo` and the service above are verified on a real system; the other allowlist entries are not verified. The face does not unlock a keyring that needs the password (for example KWallet or GNOME Keyring).
