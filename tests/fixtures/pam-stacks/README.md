# Released password on real distribution PAM stacks (T-079)

Spike for AC-090, ASM-025 and ASM-026. Run with `cargo test -p openhello-cli --test pam_release_stacks` (needs podman).

## Method

- One root container per distribution, built from `<distro>.Containerfile`: the distribution image, its compiler and PAM headers, `sudo`, and the `sddm` package's own PAM files (extracted from the package, not edited). User `hello` with password `Correct-Horse-7` in the real `/etc/shadow`.
- `run.sh` compiles three stubs and runs the real `openhello-cli pam enable` (the host build, mounted at `/opt/openhello-cli`):
  - `pam_openhello_stub.c` installed as `pam_openhello.so`: in authenticate, sets PAM_AUTHTOK from `/run/pamstack/release` when present, returns PAM_IGNORE; logs PAM_AUTHTOK in authenticate and setcred. With the `capture` argument (the second line `pam enable` places, T-083) it only logs, as `OPENHELLO capture`.
  - `pam_keyring_stub.c` installed as `pam_kwallet5.so`, so the unmodified `sddm` file loads it at the distribution's own keyring position; logs PAM_AUTHTOK.
  - `client.c`: `pam_start("sddm", "hello")`, `pam_authenticate`, then `pam_setcred(PAM_ESTABLISH_CRED)` on success; prints every conversation prompt.
- openSUSE only: `pam-config -a --kwallet5` first, which is what the `pam_kwallet` package runs in `%post`.
- Scenarios: `release` (correct password released, conversation answers empty), `wrong-token` (stale password released, conversation answers the correct one), `typed` (nothing released, conversation answers the correct password), `typed-wrong` (nothing released, conversation answers a wrong password).

## Stacks (lines on the sddm auth path after `pam enable`)

| Distro | Login manager file | Common stack after enable | Password module | Keyring position |
|---|---|---|---|---|
| openSUSE Tumbleweed | `/usr/lib/pam.d/sddm`: `auth substack common-auth` | `/etc/pam.d/common-auth` wrapper: `auth sufficient pam_openhello.so` + `auth include common-auth-pc` | `auth required pam_unix.so try_first_pass` | `auth optional pam_kwallet5.so` inside `common-auth-pc`, **before** pam_unix |
| Fedora 44 | `/etc/pam.d/sddm`: `auth substack password-auth` | enable **failed** (rc 3): `/etc/pam.d/system-auth is a symlink` (to `/etc/authselect/system-auth`) | `auth sufficient pam_unix.so nullok` | `-auth optional pam_kwallet5.so` in sddm, after the substack |
| Debian 13 | `/etc/pam.d/sddm`: `@include common-auth` | `/etc/pam.d/common-auth`: `auth sufficient pam_openhello.so` first | `auth [success=1 default=ignore] pam_unix.so nullok` | `-auth optional pam_kwallet5.so` in sddm, after the include |
| Arch | `/etc/pam.d/sddm`: `auth include system-login` -> `auth include system-auth` | `/etc/pam.d/system-auth`: `auth sufficient pam_openhello.so` first (before `pam_faillock.so preauth`) | `auth [success=1 default=bad] pam_unix.so try_first_pass nullok` | `-auth optional pam_kwallet5.so` in sddm, after the include |

Fedora: `sudo` includes `system-auth`, sddm uses `password-auth`. Even if enable handled the authselect symlink, `pam enable` discovers the common stack from `sudo`, so it would edit `system-auth`, which sddm does not read (inferred from `pam_enable.rs`, not run). An extra Fedora scenario places `auth sufficient pam_openhello.so` by hand as the first line of `/etc/authselect/password-auth` (`manual-password-auth`).

## Results

| Distro | Release: granted | Prompts | Keyring saw password | Verdict |
|---|---|---|---|---|
| openSUSE Tumbleweed | yes | 0 | yes | GO |
| Fedora 44 (as packaged) | no (PAM_AUTH_ERR) | 1 (`Password:`) | no | NO-GO: OpenHello is not in the sddm stack |
| Fedora 44 (manual line in password-auth) | yes | 0 | yes | GO once placement exists |
| Debian 13 | yes | 0 | yes | GO |
| Arch | yes | 0 | yes | GO |

ASM-026 holds: every pam_unix variant (`try_first_pass`, `nullok` only on Fedora and Debian) used the PAM_AUTHTOK set by the first-line module without prompting.

## Wrong (stale) token

On every stack where OpenHello sits (openSUSE, Debian, Arch, Fedora manual) the result is `pam_authenticate = PAM_AUTH_ERR` with **zero prompts**: pam_unix does not ask again after rejecting the existing token, `try_first_pass` included. AC-080 as written (prompt for the password) does not happen on its own. On openSUSE the keyring stub runs before pam_unix, so it also received the stale token.

## setcred (ASM-025)

- After a typed-password success, `pam_sm_setcred` of the first-line module **is** called (openSUSE, Debian, Arch, Fedora with the manual line), even though its authenticate returned PAM_IGNORE.
- PAM_AUTHTOK is **unset** in every setcred call, for OpenHello and the keyring stub, after both typed and released passwords. Inferred cause: libpam clears PAM_AUTHTOK at the end of `pam_authenticate` (`_pam_sanitize`).
- In the typed scenario OpenHello's own authenticate saw PAM_AUTHTOK unset (it runs before the prompt). Only modules after pam_unix saw the typed password (Debian, Arch, Fedora keyring stub); on openSUSE the keyring stub before pam_unix saw it unset.

ASM-025 is false: the typed password cannot be read in setcred.

## Capture line after the password check (T-083, ASM-029)

`pam enable` also places `auth optional pam_openhello.so capture` after the last `auth` line of the common stack (appending keeps every `[success=N]` jump valid). Run by `capture_line_placed_by_enable_sees_only_the_typed_password_that_pam_unix_verified`.

| Distro | Capture line position | `typed`: capture saw | `typed-wrong` |
|---|---|---|---|
| openSUSE Tumbleweed | wrapper `common-auth`: after `auth include common-auth-pc` (so after `auth required pam_unix.so try_first_pass`) | `Correct-Horse-7`, setcred called | runs (pam_unix is `required`, the stack continues) and sees the wrong password; AUTH 7, no setcred |
| Debian 13 | `common-auth`: after `auth required pam_permit.so` | `Correct-Horse-7`, setcred called | does not run (`pam_deny.so` is `requisite`); AUTH 7 |
| Arch | `system-auth`: after `auth required pam_faillock.so authsucc`, before the account lines | `Correct-Horse-7`, setcred called | does not run (`pam_faillock.so authfail` is `default=die`); AUTH 7 |
| Fedora 44 | not placed (enable fails as above) | — | — |

ASM-029 holds on openSUSE, Debian and Arch: the capture line runs after pam_unix verified the typed password and still sees it in PAM_AUTHTOK. In setcred PAM_AUTHTOK is unset again, so the module stashes the password during authenticate. A failed sign-in can still reach the capture line (openSUSE), so the module seals only in setcred, which applications call only after a successful pam_authenticate. In the `release` scenario the capture line sees the released password; the real module skips it because OpenHello marked the release.
