# Lock screen verification

open-hello has no per-distro or per-desktop code and no per-interface command. `pam_openhello` sits once in the common PAM auth stack; any locker, greeter or `polkit` agent that authenticates through PAM reaches it by including that stack. The module acts only for a user with a registered credential (`/etc/openhello/auth/<uid>.pub`), only in a local session, for every service except a compiled denylist of non-desktop services (`login`, `su`, `sshd`, `cron` and similar), and never as `required`.

Enable and undo: `sudo openhello-cli pam enable` (the installer runs it unless `--no-pam`), `sudo openhello-cli pam disable`, `openhello-cli pam status`.

## What every locker shares

- It calls `pam_authenticate` with a PAM conversation and its own service name.
- Most run as the user, so the keyd token proxy needs no root.
- Most services include the distro's common stack (`common-auth` or `system-auth`); `scripts/pam-survey.sh` lists the includes on a machine without sudo.
- Whether the locker shows PAM info messages, or finishes the unlock after a prompt-less success, is the locker's own behaviour and is not changed by open-hello.

## Verification procedure (any desktop)

1. Keep a second session or `sudo -s` open until the end.
2. `sudo openhello-cli pam status` shows the common stack and any per-service line.
3. Lock the screen and face the IR camera; expected: the face authenticates without a password.
4. Failure path: `sudo systemctl stop openhellod`, lock again; the password must work within a few seconds.

Logs: `journalctl -b -u openhellod -u openhello-keyd`; with the `debug` module argument, `journalctl -b -t pam_openhello` (`reason=<code> service=<name>`).

## Login screen (display manager greeter)

The module also acts at the login screen: the greeter's helper runs as root inside the display manager's service, with no user session, so the module treats it as local when logind lists a local `CLASS=greeter` session. No display-manager name is involved.

When the face starts depends on the greeter, not on open-hello:

| Greeter | PAM starts | What the user does |
|---|---|---|
| SDDM, plasmalogin | when the form is submitted | choose the user, press Enter with an empty password, face the camera |
| GDM, LightDM, greetd | when the user is chosen (not verified here) | face the camera |

The face is tried only when the password field is empty. At the login screen the module reads the submitted password (`pam_get_authtok`, only to tell empty from non-empty, never stored or logged); anything typed returns `password-typed` and `pam_unix` decides, so a wrong password is refused and a correct one never turns the camera on. This applies only to the login manager's helper (no user session, a local greeter in logind); `sudo`, `polkit` and the lock screen still start the camera by themselves. A failed face is a wrong password: the user types the password. An automatic Enter was built and removed (2026-10-22): every variant (virtual keyboard, fixed delay, burst of Enters, human-activity guard) adds a fragile surface, and a burst can trip `pam_faillock`.

Upstream paths to watch: SDDM pull request 2176 (parallel authentication) and the Plasma Login Manager prototype that reuses the lock screen authenticators.

## Record per VM

| Distro | Desktop | Locker | PAM service | Result | Notes |
|---|---|---|---|---|---|
| KDE neon VM (Ubuntu noble) | Plasma Login Manager | greeter | `plasmalogin` | passed | Face authenticated at the login screen after Enter with an empty password (`reason=success`, 2026-10-22). |
| KDE neon VM (Ubuntu noble) | Plasma Login Manager | greeter | `plasmalogin` | passed | Typed passwords (wrong or correct) give `reason=password-typed` and the camera stays off; an empty password still gives `reason=success` (2026-10-22). |
| KDE neon VM (Ubuntu noble) | graphical session | PAM-based locker | locker's own | passed | Face authenticated without a password (`reason=success`, 2026-10-21). The locker then shows its own confirmation; open-hello does not change that. |
| KDE neon VM (Ubuntu noble) | any | terminal | `sudo` | passed (fingerprint) | Virtual reader (libfprint `virtual_device`): the enrolled finger authenticated `sudo` with no password and no camera frames (`modality=finger accepted=true`, 2026-10-22); a wrong finger three times refused the request after the face budget (`finger=refused`) with no ticket. |
| KDE neon VM (Ubuntu noble) | any | polkit agent | `polkit-1` | passed (fingerprint) | Same virtual reader: matching finger gave `reason=success service=polkit-1`; wrong finger three times gave `reason=face-refused service=polkit-1`, no ticket (2026-10-22). With the user facing the camera the face won and the finger side was cancelled (`modality=face finger=cancelled`). |

Fingerprint: `sudo` and `polkit-1` are verified with the libfprint virtual reader (rows above); the lock screen and the greeter are not verified with a finger. Face: only `sudo`, the locker above and the plasmalogin login screen (Enter with an empty password, `reason=success service=plasmalogin`, 2026-10-22) are verified on a real system; others are not verified. The face does not unlock a keyring that needs the password.
