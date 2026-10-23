#!/bin/sh
# Runs after install and after upgrade on deb, rpm and Arch; PAM is enabled only the first time so a later `pam disable` survives upgrades.
set -u

STATE_DIR="${OPENHELLO_PKG_STATE_DIR:-/var/lib/openhello}"
SYSTEMD_RUN_DIR="${OPENHELLO_PKG_SYSTEMD_RUN_DIR:-/run/systemd/system}"
PAM_DECIDED="$STATE_DIR/pam-enabled-by-package"
SUDO_DECIDED="$STATE_DIR/sudo-own-password-by-package"
INSTALLER_UID="${SUDO_UID:-${PKEXEC_UID:-}}"

warn() { echo "openhello: $*" >&2; }

mkdir -p -m 0700 "$STATE_DIR"

openhello-cli pam migrate >/dev/null 2>&1 || warn "could not migrate PAM files left by an earlier installer; run: sudo openhello-cli pam migrate"

if [ ! -e "$PAM_DECIDED" ]; then
  if openhello-cli pam enable; then
    : > "$PAM_DECIDED"
  else
    warn "could not enable face sign-in in the common PAM stack; passwords are untouched. Enable later with: sudo openhello-cli pam enable"
  fi
fi

# Whoever ran the install through sudo or pkexec already proved they are an administrator.
if [ ! -e "$SUDO_DECIDED" ] && [ -n "$INSTALLER_UID" ] && [ "$INSTALLER_UID" != 0 ]; then
  if openhello-cli sudo own-password "$INSTALLER_UID" >/dev/null; then
    : > "$SUDO_DECIDED"
  else
    warn "sudo keeps asking for the root password; open Open Hello to let it accept your face"
  fi
fi

if [ -d "$SYSTEMD_RUN_DIR" ]; then
  systemctl daemon-reload || true
  systemctl reload dbus 2>/dev/null || true
  systemctl enable openhello-keyd.service openhellod.service || true
  systemctl reset-failed openhello-keyd.service openhellod.service 2>/dev/null || true
  systemctl restart openhello-keyd.service || true
  systemctl restart openhellod.service || true
fi

command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database -q /usr/share/applications || true
command -v gtk-update-icon-cache >/dev/null 2>&1 && gtk-update-icon-cache -q -t /usr/share/icons/hicolor || true

if [ -x /usr/local/bin/openhello-cli ]; then
  warn "an older copy from scripts/install.sh is still in /usr/local/bin and hides this package; remove /usr/local/bin/openhello-cli and /usr/local/bin/openhello-gui"
fi

echo "Open Hello installed. Check OPENHELLO_DEVICE (the IR camera node) in /etc/openhello/openhello.env, then open Open Hello to enroll a face."
exit 0
