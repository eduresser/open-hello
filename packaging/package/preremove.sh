#!/bin/sh
# $1 is "remove"/"upgrade" on deb, 0 (remove) or 1 (upgrade) on rpm, the old version on Arch (pre_remove runs only on removal).
set -u

STATE_DIR="${OPENHELLO_PKG_STATE_DIR:-/var/lib/openhello}"
SYSTEMD_RUN_DIR="${OPENHELLO_PKG_SYSTEMD_RUN_DIR:-/run/systemd/system}"

case "${1:-}" in
  upgrade|failed-upgrade|1) exit 0 ;;
esac

openhello-cli pam disable || echo "openhello: could not remove pam_openhello from /etc/pam.d; check with: openhello-cli pam status" >&2
rm -f "$STATE_DIR/pam-enabled-by-package"

if [ -d "$SYSTEMD_RUN_DIR" ]; then
  systemctl disable --now openhellod.service openhello-keyd.service || true
fi
exit 0
