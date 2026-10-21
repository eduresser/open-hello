# Portability research: PAM integration across distros and lockers

Research only; no code or spec changed. Marks: **C** = confirmed by the cited source (or measured on this machine, openSUSE Tumbleweed, KDE Plasma 6.8.0); **I** = inferred, needs a VM check. Fetched 2026-10-21.

## 1. Summary

- Every distro keeps the same PAM model (one file per service in `/etc/pam.d`, shared `auth` stack included by services). What differs is the supported way to add a module to the shared stack.
- The common core already in the repo is right: one gated block (`pam_openhello` + `pam_pkcs11` + `clear`) placed before the password module. Only the delivery differs per distro: pam-auth-update profile (Debian family), authselect custom profile (Fedora/RHEL), `/etc/pam.d` edit (openSUSE, Arch, Gentoo, Alpine, Void), `security.pam.services` (NixOS).
- Lockers split in two groups: those that call PAM at lock time or after Enter, one prompt at a time (i3lock, swaylock, xscreensaver, xsecurelock, MATE, XFCE, Cinnamon, hyprlock), and those with parallel per-method PAM services (GNOME `gdm-fingerprint`, KDE `kde-fingerprint`/`kde-face`). Face fits the first group by putting it before the password line; the second group needs its own service file.

## 2. Distro integration mechanisms

| Distro family | Supported mechanism | Minimal artifact | Status |
|---|---|---|---|
| Debian, Ubuntu | `pam-auth-update` profiles in `/usr/share/pam-configs/`; packages call `pam-auth-update --package` in postinst and `--package --remove NAME` in prerm | see 2.1 | C |
| Fedora, RHEL, Alma, Rocky | `authselect` profiles; custom profiles in `/etc/authselect/custom/NAME`; select with `authselect select custom/NAME with-feature` | see 2.2 | C (layout), I (feature declaration) |
| openSUSE, SLE | `pam-config` generates `common-{auth,account,password,session}-pc`; modules from the supported list (`--pkcs11`, `--fprintd` exist); override dirs `/usr/lib/pam-config.d`, `/usr/local/lib/pam-config.d`, `/etc/pam-config.d` | no profile format for new modules found; use `pam-config -a --pkcs11` or edit service files | C (list), I (snippet format) |
| Arch | No tool; edit `/etc/pam.d/*` (stacks `system-auth`, `system-local-login`) | manual lines | C (gdm Arch files include `system-local-login`), I (no tool) |
| NixOS | Declarative: `security.pam.services.<name>.text` or `.rules.auth.<rule>` with `order`/`control`/`modulePath`/`args` | Nix module generating the three lines | C |
| Gentoo | Edit `/etc/pam.d/` files by hand; no management tool documented | manual lines | C |
| Alpine | Edit `/etc/pam.d/*`; fprintd guide says keep `pam_unix.so` before `pam_fprintd.so` for password fallback | manual lines | C |
| Void | No source found | manual lines | I |

Sources: Debian/Ubuntu [unix profile](https://git.launchpad.net/ubuntu/+source/pam/plain/debian/pam-configs/unix), [fprintd profile](https://git.launchpad.net/ubuntu/+source/fprintd/plain/debian/pam-configs/fprintd), [postinst](https://git.launchpad.net/ubuntu/+source/fprintd/plain/debian/libpam-fprintd.postinst), [prerm](https://git.launchpad.net/ubuntu/+source/fprintd/plain/debian/libpam-fprintd.prerm), [pam-auth-update(8)](https://manpages.ubuntu.com/manpages/noble/man8/pam-auth-update.8.html). authselect: [profiles(5)](https://www.mankier.com/5/authselect-profiles), [authselect(8)](https://www.mankier.com/8/authselect), [sssd system-auth template](https://raw.githubusercontent.com/authselect/authselect/master/profiles/sssd/system-auth), [sssd README features](https://raw.githubusercontent.com/authselect/authselect/master/profiles/sssd/README). openSUSE: [pam-config(8)](https://manpages.opensuse.org/Tumbleweed/pam-config/pam-config.8.en.html). NixOS: [pam.nix](https://raw.githubusercontent.com/NixOS/nixpkgs/master/nixos/modules/security/pam.nix). Gentoo: [PAM](https://wiki.gentoo.org/wiki/PAM). Alpine: [fprintd for swaylock](https://wiki.alpinelinux.org/wiki/Setting_up_fprintd_for_swaylock).

### 2.1 Debian family: `/usr/share/pam-configs/openhello` (minimal)

Format taken from the real `fprintd` and `unix` profiles (C). Fields seen: `Name`, `Default`, `Priority`, `Conflicts`, `Auth-Type` (Primary/Additional), `Auth`, `Auth-Initial`; one control+module per indented line.

```
Name: open-hello face
Default: no
Priority: 270
Auth-Type: Primary
Auth:
	[success=ignore ignore=2 default=ignore]	pam_openhello.so allowlist=/etc/openhello/allowed-services
	sufficient	pam_pkcs11.so use_first_pass config_file=/etc/openhello/pam_pkcs11.conf
	optional	pam_openhello.so clear
```

- `fprintd` ships `Default: no`, `Priority: 260`, above `unix` (256) (C). Higher priority lands earlier in `common-auth` (I; consistent with those values).
- A Primary profile lands in `common-auth`, so it reaches every service including it: the existing allowlist gate in `pam_openhello` is mandatory (C, lib.rs `permitted`).
- Open: whether `pam-auth-update` keeps the numeric jump `ignore=2` and `success=ignore` verbatim in a multi-line Primary block (I). Check with `pam-auth-update --enable openhello` then read `/etc/pam.d/common-auth`.
- Removal: `pam-auth-update --package --remove openhello` in prerm (C).

### 2.2 Fedora/RHEL: custom authselect profile (minimal)

Profile directory is a template set: `README` (first line = name, only mandatory file), `system-auth`, `password-auth`, `fingerprint-auth`, `smartcard-auth`, `postlogin`, `nsswitch.conf` (C). Template operators: `{include if "feature"}`, `{exclude if "feature"}`, `{imply ...}`, `{if "f":text}` (C). Upstream pattern for an optional module is a line with a trailing conditional, e.g. `auth sufficient pam_fprintd.so {include if "with-fingerprint"}` (C).

```
authselect create-profile openhello -b sssd --symlink-meta   # -> /etc/authselect/custom/openhello (C)
# edit system-auth and password-auth, before the pam_unix line:
auth [success=ignore ignore=2 default=ignore] pam_openhello.so allowlist=/etc/openhello/allowed-services {include if "with-openhello"}
auth sufficient pam_pkcs11.so use_first_pass config_file=/etc/openhello/pam_pkcs11.conf {include if "with-openhello"}
auth optional pam_openhello.so clear {include if "with-openhello"}
authselect select custom/openhello with-openhello
```

- Do not use `--symlink-pam` when editing PAM templates: it edits the base profile (C, Red Hat doc via authselect(8) search).
- Open: whether a custom feature needs declaring outside the template (I). The template conditional alone is how upstream features work (C).
- Open: a profile based on `sssd` vs `minimal`; pick the base the VM uses (`authselect current`) (I).
- Selecting a profile rewrites `/etc/pam.d/system-auth` and others; hand edits there are overwritten (I).

## 3. Lockers and greeters

"Runs as" and "multi-factor" describe PAM use. "Common stack" = the service includes `common-auth`/`system-auth`.

| Locker / greeter | PAM service | Runs as | PAM flow | Common stack | Marks |
|---|---|---|---|---|---|
| KDE kscreenlocker (Plasma 6) | `kde` (password), `kde-fingerprint`, `kde-smartcard`; Plasma 6.8 adds `kde-face` (pam_howdy), `kde-u2f` | user (greeter spawns `kscreenlocker_worker`) | password plus parallel non-interactive authenticators, one active at a time; `kde-face` is a copy of `kde-smartcard` | `kde`: `include common-auth` (C local); fingerprint/smartcard files do not include it (C local) | service names C ([MR 318](https://invent.kde.org/plasma/kscreenlocker/-/merge_requests/318), local `/usr/lib/pam.d`, strings of `kscreenlocker_greet`); user I |
| GNOME Shell lock screen and GDM | `gdm-password`, `gdm-fingerprint`, `gdm-smartcard` (+ `gdm-switchable-auth` on RHEL passwordless) | gdm session worker (I: root); not the user | one PAM conversation per service, run concurrently; fingerprint messages become a hint | Fedora: `substack gdm-password-auth-substack`; Arch: `include system-local-login`; Arch `gdm-fingerprint` is its own stack with `pam_fprintd` (C) | C ([authServicesLegacy.js](https://gitlab.gnome.org/GNOME/gnome-shell/-/raw/main/js/gdm/authServicesLegacy.js), [gdm-password.pam redhat](https://gitlab.gnome.org/GNOME/gdm/-/raw/main/data/pam-redhat/gdm-password.pam), [gdm-fingerprint.pam redhat](https://gitlab.gnome.org/GNOME/gdm/-/raw/main/data/pam-redhat/gdm-fingerprint.pam), [arch](https://gitlab.gnome.org/GNOME/gdm/-/raw/main/data/pam-arch/gdm-fingerprint.pam), [session worker](https://gitlab.gnome.org/GNOME/gdm/-/raw/main/daemon/gdm-session-worker.c)); same services used by the in-session lock screen I |
| SDDM | `sddm`, `sddm-greeter`, `sddm-autologin` | root helper (I) | single prompt flow (I) | `substack common-auth` (C local) | names C (local `/usr/lib/pam.d`) |
| LightDM / light-locker | `lightdm`, `lightdm-greeter`, `lightdm-autologin` | root (I) | greeter prompt flow (I); light-locker switches to the greeter, so it reuses `lightdm` (I) | upstream sample is `pam_unix` only (C); distros differ | C for sample ([upstream data/pam/lightdm](https://raw.githubusercontent.com/canonical/lightdm/main/data/pam/lightdm), [Arch wiki](https://wiki.archlinux.org/title/LightDM)), rest I |
| xscreensaver | `xscreensaver` | user, or setuid `xscreensaver-auth` if installed so | password prompt | `include common-auth` (C local) | C ([man](https://man.archlinux.org/man/xscreensaver.1), local) |
| xsecurelock | `XSECURELOCK_PAM_SERVICE` (build default; docs recommend `xscreensaver` or `common-auth`) | user on Linux | `authproto_pam` conversation; `XSECURELOCK_AUTH_TIMEOUT` reverts to saver after no prompt reply | depends on chosen service | C ([README](https://raw.githubusercontent.com/google/xsecurelock/master/README.md)) |
| i3lock | `i3lock` (fixed) | user | `pam_authenticate` only after Enter, synchronous; answers only echo prompts; ignores `PAM_TEXT_INFO`; empty password + Enter does call PAM | via `/etc/pam.d/i3lock` content (distro) | C ([i3lock.c](https://raw.githubusercontent.com/i3/i3lock/main/i3lock.c)) |
| swaylock | `swaylock` (fixed) | user (PAM in a forked child) | `pam_authenticate` after the typed password arrives; one echo-off answer, a second prompt gets `PAM_ABORT`; `PAM_TEXT_INFO` ignored | via `/etc/pam.d/swaylock` | C ([pam.c](https://raw.githubusercontent.com/swaywm/swaylock/master/pam.c)) |
| hyprlock | `hyprlock`, configurable (`auth:pam:module`); falls back to `su` if file missing | user | `pam_authenticate` starts at lock time in a worker thread; waits on UI only when PAM asks a prompt; `PAM_TEXT_INFO` shown only if text contains "Place your finger" or "left to unlock"; optional own fprintd client "in parallel" | via `/etc/pam.d/hyprlock` | C ([Pam.cpp](https://raw.githubusercontent.com/hyprwm/hyprlock/main/src/auth/Pam.cpp), [wiki](https://wiki.hypr.land/Hypr-Ecosystem/hyprlock/)) |
| XFCE xfce4-screensaver | `xfce4-screensaver` | user; dialog helper may need root-owned (shadow) | prompt flow | Arch example: `auth include system-auth` | C ([FreeBSD PR 252837](https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=252837)); flow I |
| MATE mate-screensaver | `PAM_SERVICE_NAME` macro (I: `mate-screensaver`) | not determinable from source | auth in a helper thread; every PAM message, including `TEXT_INFO`, goes to the GUI and the PAM thread blocks until it answers; no timeout in file | I | C ([gs-auth-pam.c](https://raw.githubusercontent.com/mate-desktop/mate-screensaver/master/src/gs-auth-pam.c)); name I |
| Cinnamon cinnamon-screensaver | I: `cinnamon-screensaver` | I | I | I | I (no source fetched; name only in `pam-survey.sh`) |
| Budgie budgie-screensaver | not found | I | I | I | I ([man](https://man.archlinux.org/man/budgie-screensaver-command.1.en)) |
| LXQt | none; uses any locker through `lxqt-leave --lockscreen` / `xdg-screensaver`; 2.1+ configurable lock command | n/a | n/a | n/a | C ([wiki](https://lxqt-project.org/wiki/Screensaver-and-Screen-Locker.html)) |
| greetd | I: `greetd` | root (C: PAM ops expect root) | greeter must handle `visible`, `secret`, `info`, `error` messages and "should not make any assumptions" | I | C ([greetd-ipc(7)](https://man.archlinux.org/man/greetd-ipc.7), [man.sr.ht](https://man.sr.ht/~kennylevinsen/greetd/)) |
| sudo, su, polkit | `sudo`, `su`, `polkit-1` | root (setuid) | tty or agent prompt | `common-auth` (C local) | C (local) |

Local measurement (this machine): only `kscreenlocker6` (6.8.0) and `xscreensaver` are installed. `/usr/lib/pam.d` has `kde`, `kde-fingerprint`, `kde-smartcard`, `sddm`, `sddm-greeter`, `xscreensaver`, `sudo`, `polkit-1`, `login`, `sshd`; `kde-face` and `kde-u2f` exist only as strings in `kscreenlocker_greet` (C). `pam-config` binary is not installed here although `common-*-pc` files exist (C).

## 4. Incompatibility points for a long-wait biometric module

| Point | Evidence | Effect on open-hello | Marks |
|---|---|---|---|
| PAM stack is serial: no password and biometric at the same time inside one service; apps wanting several methods must use separate services (gdm named) | [pam_fprintd(8)](https://manpages.debian.org/unstable/libpam-fprintd/pam_fprintd.8.en.html) | Face before password in one stack blocks the password prompt until the face attempt ends | C |
| How fprintd works around it: separate per-method service (`gdm-fingerprint`, `kde-fingerprint`) run next to the password service; pam_fprintd options `timeout` (default 30 s) and `max-tries` (default 3); negative values mean no limit | pam_fprintd(8); GNOME [authServicesLegacy.js](https://gitlab.gnome.org/GNOME/gnome-shell/-/raw/main/js/gdm/authServicesLegacy.js); KDE MR 318 (SIGINT cancels the running authenticator, "pam_fprint handles SIGINT") | open-hello needs a finite budget and must handle SIGINT/termination during the camera wait; today the only constant is `BUDGET` = 5 s for service availability in `lib.rs`; the camera wait itself sits in the PKCS#11 login path (I) | C |
| GNOME: fingerprint service starts 500 ms after the conversation; its messages are not shown, they become the hint "(or place finger on reader)"; a fast failure is counted as a service failure; fingerprint failures do not increment the password fail counter | authServicesLegacy.js | Face through `gdm-fingerprint` would be labelled "finger" and needs the GNOME fingerprint mechanism enabled (I: gsettings key) | C |
| KDE: an authenticator with more than 3 failures within 2 s is marked unavailable; worker D-Bus calls have no timeout (blocking calls expected) | [pamauthenticator.cpp](https://invent.kde.org/plasma/kscreenlocker/-/raw/master/greeter/pamauthenticator.cpp) | A quick PAM_IGNORE/failure loop (daemon down) disables Face until re-lock; this matches the "password still works" requirement | C |
| i3lock, swaylock call PAM only after Enter; i3lock blocks its event loop in `pam_authenticate` | [i3lock.c](https://raw.githubusercontent.com/i3/i3lock/main/i3lock.c), [swaylock pam.c](https://raw.githubusercontent.com/swaywm/swaylock/master/pam.c) | Face starts only after the user presses Enter on an empty field; i3lock screen freezes during the camera wait (I: single-threaded loop, synchronous call); no "Looking for your face" text (TEXT_INFO ignored) | C / I |
| hyprlock starts PAM at lock time; its own fprintd client is the parallel path; info text is filtered to two substrings | [Pam.cpp](https://raw.githubusercontent.com/hyprwm/hyprlock/main/src/auth/Pam.cpp) | Face works without Enter; message only visible if text contains "Place your finger" | C |
| swaylock + fprintd users report pressing Enter first, or no unlock | Alpine and Arch forum threads via [Alpine wiki](https://wiki.alpinelinux.org/wiki/Setting_up_fprintd_for_swaylock) | same as i3lock | C (reports) |
| MATE forwards every PAM message to the GUI and blocks until answered | [gs-auth-pam.c](https://raw.githubusercontent.com/mate-desktop/mate-screensaver/master/src/gs-auth-pam.c) | `tell()` (PAM_TEXT_INFO) may need an acknowledgement and stall the stack if the GUI returns false (conv error) | C / I |
| Pluggable modules in the common stack run for every service in it | Debian Primary profile semantics; `permitted()` in `lib.rs` | allowlist is required for level B | C |
| NixOS upstream guidance for `fprintAuth`: enable only "for clients that can ensure user attention, such as lockscreens" | [pam.nix](https://raw.githubusercontent.com/NixOS/nixpkgs/master/nixos/modules/security/pam.nix) | Same rule as our allowlist: not for sudo by default in a headless context | C |
| Howdy (face PAM module) claims to work "everywhere you would otherwise need your password"; no per-locker compatibility list found | [README](https://raw.githubusercontent.com/boltgolt/howdy/master/README.md) | Not evidence of portability; treat as same risk class | C |

## 5. Recommendation

Smallest set of integration points that covers most distros and desktops:

1. **One generic stack file** (exists): `openhello-lockscreen` for services where the locker lets us pick the PAM service (KDE `kde-face`, hyprlock `auth:pam:module`, xsecurelock `XSECURELOCK_PAM_SERVICE`). Face-only, ends with `pam_deny`.
2. **One gated block per PAM manager** (the level B three lines, with `allowlist=`), delivered as: pam-auth-update profile (Debian family), authselect custom feature (Fedora/RHEL), `pam-config`/manual snippet (openSUSE), manual snippet with backup (Arch, Gentoo, Alpine, Void), a NixOS module. This replaces hand-editing `/etc/pam.d` where a manager exists and covers lockers with a fixed service name (i3lock, swaylock, xscreensaver, MATE, XFCE, Cinnamon) through the stack they already include.
3. **Per-locker adapters, only where the generic block fails**: KDE `kde-face` (done), GNOME `gdm-fingerprint` stack (face as a "fingerprint-like" service, if the GNOME hint text is acceptable), and nothing for i3lock/swaylock beyond documenting "press Enter".

Start with the allowlist containing only `sudo`, then add lockers one by one (same rule as the current guide). Keep the face attempt budget finite everywhere.

Risks:

- Common-stack placement affects login, polkit and cron; mitigated by `permitted()` but a manager profile applied by mistake can still break all logins. Keep a root TTY.
- GNOME and KDE parallel services need the daemon to fail fast; KDE disables the authenticator after 3 failures in 2 s.
- i3lock freezes its UI during the wait; swaylock/i3lock need Enter; MATE may stall on `PAM_TEXT_INFO`.
- authselect and pam-auth-update rewrite the shared stacks; a profile update could drop hand edits (I).
- Info text (`Looking for your face...`) is not displayed by i3lock/swaylock/hyprlock (unless matched) and is relabelled by GNOME.

## 6. Checks for the VMs (mark in the `lockscreen.md` table)

| # | Check | How | Pass criterion |
|---|---|---|---|
| 1 | Run `scripts/pam-survey.sh` | no sudo | file attached to the row |
| 2 | Which locker and which PAM service it uses | `journalctl -b \| grep -i pam` while locking; `strace`-free: `grep -l pam_openhello /etc/pam.d/*` after enabling | service name recorded |
| 3 | Locker includes the common stack | survey `includes` column | `common-auth`/`system-auth` listed |
| 4 | PAM manager present | `command -v pam-auth-update authselect pam-config` | one of them, or none (manual) |
| 5 | Manager profile applies cleanly | Debian: `pam-auth-update` then `grep openhello /etc/pam.d/common-auth`; Fedora: `authselect select custom/openhello with-openhello` then `grep openhello /etc/pam.d/system-auth` | the three lines present in order; `authselect check` / no errors |
| 6 | `ignore=2` and `success=ignore` survive generation | read generated `common-auth` | lines unchanged |
| 7 | Face unlocks the locker | lock, look at camera | unlock without password |
| 8 | Password still works with daemon stopped | `systemctl stop openhellod`, lock, type password | unlock within a few seconds, no freeze |
| 9 | Needs Enter first? | lock, wait without typing; then press Enter on empty field | record: auto / after Enter |
| 10 | UI frozen during the camera wait? | move mouse or type during the attempt | record: responsive / frozen |
| 11 | Message `Looking for your face...` visible? | observe | visible / hidden / relabelled |
| 12 | Wrong face or covered camera | cover camera | falls back to password within budget; no lockout loop |
| 13 | KDE only: authenticator marked unavailable after quick failures | stop `openhellod`, lock 4 times fast | `journalctl -t kscreenlocker_greet` shows unavailable; password works |
| 14 | GNOME only: `gdm-fingerprint` service shown/hinted | enable `org.gnome.login-screen enable-fingerprint-authentication` (I) | face attempt starts, hint text recorded |
| 15 | sudo, ssh, cron untouched | `ssh localhost true`, `sudo -k; sudo true`, cron job | ssh and cron return `ignore` immediately (journal shows no camera use) |
| 16 | Removal | remove profile / feature | stack back to original; password login intact |
