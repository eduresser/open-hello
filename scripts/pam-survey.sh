#!/usr/bin/env bash
# Read-only survey of the PAM, desktop and hardware facts open-hello depends on; run per VM and compare the outputs.
# usage: scripts/pam-survey.sh [OUTPUT_FILE]   (default: ./pam-survey-<hostname>.md; the only file written)
set -u
OUT="${1:-./pam-survey-$(hostname 2>/dev/null || echo host).md}"
exec 3>"$OUT" || { echo "cannot write $OUT" >&2; exit 1; }

say() { printf '%s\n' "$*" >&3; }
kv() { say "- $1: ${2:-n/a}"; }
have() { command -v "$1" >/dev/null 2>&1; }
state() { systemctl "$1" "$2" 2>/dev/null | head -1 | grep . || echo n/a; }
exists() { if [ -e "$1" ]; then echo yes; else echo no; fi; }

say "# pam-survey"
say
say "## System"
os_value() { (. /etc/os-release 2>/dev/null && eval "printf '%s' \"\${$1:-}\""); }
kv distro "$(os_value PRETTY_NAME)"
kv id "$(os_value ID) like=$(os_value ID_LIKE)"
kv kernel "$(uname -r)"
kv systemd "$(systemctl --version 2>/dev/null | head -1)"
kv package_managers "$(for m in apt-get dnf zypper pacman; do have "$m" && printf '%s ' "$m"; done)"

say
say "## Session"
kv XDG_SESSION_TYPE "${XDG_SESSION_TYPE:-}"

say
say "## PAM"
PAM_DIRS=""
for d in /etc/pam.d /usr/lib/pam.d /usr/etc/pam.d; do [ -d "$d" ] && PAM_DIRS="$PAM_DIRS $d"; done
kv pam_dirs "${PAM_DIRS# }"
say
say "| service | where | includes |"
say "|---|---|---|"
SERVICES="login sudo su polkit-1 passwd sshd cron common-auth system-auth password-auth sudo-openhello openhello-lockscreen"
for s in $SERVICES; do
  for d in $PAM_DIRS; do
    f="$d/$s"
    [ -f "$f" ] || continue
    inc="$(grep -E '^[[:space:]]*(@include|auth[[:space:]]+(include|substack)|-?auth[[:space:]]+\[?[^#]*pam_)' "$f" 2>/dev/null \
      | grep -E '@include|include|substack' | sed -E 's/^[[:space:]]*//; s/[[:space:]]+/ /g' | tr '\n' ';')"
    say "| $s | $d | ${inc:-none} |"
  done
done
say
say "### Modules in auth stacks of common files"
for f in /etc/pam.d/common-auth /etc/pam.d/system-auth /usr/lib/pam.d/common-auth /usr/lib/pam.d/system-auth; do
  [ -f "$f" ] && { say "- $f:"; grep -E '^[[:space:]]*-?auth' "$f" | sed -E 's/^[[:space:]]*/  - /; s/[[:space:]]+/ /g' >&3; }
done

say
say "## Dependencies"
find_lib() { for d in /usr/lib64 /usr/lib /usr/lib/x86_64-linux-gnu /usr/lib/aarch64-linux-gnu; do for pat in "$@"; do ls "$d"/$pat 2>/dev/null; done; done | head -1; }
kv pam_pkcs11.so "$(find_lib 'security/pam_pkcs11.so')"
kv tpm2_pkcs11 "$(find_lib 'pkcs11/libtpm2_pkcs11.so' 'libtpm2_pkcs11.so*')"
kv certutil "$(command -v certutil || true)"
kv tpm2-abrmd "$(command -v tpm2-abrmd || true) service=$(state is-enabled tpm2-abrmd)"
kv /dev/tpmrm0 "$(exists /dev/tpmrm0)"
kv /dev/tpm0 "$(exists /dev/tpm0)"
kv pam_openhello.so "$(find_lib 'security/pam_openhello.so')"

say
say "## Cameras (V4L2)"
if have v4l2-ctl; then
  for dev in /dev/video*; do
    [ -e "$dev" ] || continue
    fmts="$(v4l2-ctl -d "$dev" --list-formats 2>/dev/null | grep -oE "'[A-Z0-9 ]{4}'" | tr -d "'" | tr '\n' ',' )"
    grey=no; case "$fmts" in *GREY*) grey=yes ;; esac
    say "- $dev: name=$(cat /sys/class/video4linux/"$(basename "$dev")"/name 2>/dev/null) formats=${fmts:-none} grey=$grey"
  done
else
  kv v4l2-ctl "missing (install v4l-utils to list formats)"
  for dev in /dev/video*; do [ -e "$dev" ] && say "- $dev: name=$(cat /sys/class/video4linux/"$(basename "$dev")"/name 2>/dev/null)"; done
fi

say
say "## open-hello"
for u in openhello-keyd openhellod; do
  kv "$u.service" "installed=$(exists /etc/systemd/system/$u.service) active=$(state is-active $u)"
done
kv /etc/openhello "$(exists /etc/openhello)"
echo "wrote $OUT"
