#!/usr/bin/env bash
# Installs open-hello on a fresh Linux VM: dependencies, build, files, D-Bus/polkit/systemd integration.
# usage: sudo scripts/install.sh [--dry-run] [--no-deps]
set -euo pipefail

DRY_RUN=0
INSTALL_DEPS=1
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    --no-deps) INSTALL_DEPS=0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIB_DIR=/usr/lib/openhello
BIN_DIR=/usr/libexec/openhello
CONF_DIR=/etc/openhello

run() {
  if [ "$DRY_RUN" = 1 ]; then echo "+ $*"; else "$@"; fi
}

[ "$DRY_RUN" = 1 ] || [ "$(id -u)" = 0 ] || { echo "run as root (sudo)" >&2; exit 1; }

install_deps() {
  . /etc/os-release
  case "${ID_LIKE:-$ID}" in
    *debian*|*ubuntu*)
      run apt-get update
      run apt-get install -y build-essential pkg-config curl ca-certificates tpm2-tools swtpm \
        libtss2-tcti-swtpm0 dbus polkitd ;;
    *fedora*|*rhel*|*centos*)
      run dnf install -y gcc make pkgconf-pkg-config curl tpm2-tools swtpm tpm2-tss dbus-daemon polkit ;;
    *suse*)
      run zypper --non-interactive install gcc make pkg-config curl tpm2.0-tools swtpm \
        libtss2-tcti-swtpm0 dbus-1-daemon polkit ;;
    *) echo "unsupported distro ($ID); install manually: rust, tpm2-tools, swtpm, libtss2-tcti-swtpm, dbus, polkit" >&2; exit 1 ;;
  esac
}

ensure_rust() {
  if command -v cargo >/dev/null 2>&1; then return; fi
  run sh -c "curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal"
  export PATH="$HOME/.cargo/bin:$PATH"
}

[ "$INSTALL_DEPS" = 1 ] && install_deps
ensure_rust

run cargo build --release --manifest-path "$REPO/Cargo.toml" \
  -p openhellod -p openhello-cli -p sensor-adapter-ir -p engine-adapter-face -p storage-adapter-templates

T="$REPO/target/release"
run install -d -m 0755 "$LIB_DIR" "$BIN_DIR" "$CONF_DIR"
run install -d -m 0700 /var/lib/openhello
for lib in libsensor_adapter_ir libengine_adapter_face libstorage_adapter_templates; do
  run install -m 0644 "$T/$lib.so" "$LIB_DIR/$lib.so"
done
run install -m 0755 "$T/openhellod" "$BIN_DIR/openhellod"
run install -m 0755 "$T/openhello-cli" /usr/local/bin/openhello-cli
run install -m 0644 "$REPO/packaging/io.openhello.Biometrics1.conf" /usr/share/dbus-1/system.d/io.openhello.Biometrics1.conf
run install -m 0644 "$REPO/crates/openhellod/io.openhello.Biometrics1.policy" /usr/share/polkit-1/actions/io.openhello.Biometrics1.policy
run install -m 0644 "$REPO/packaging/openhellod.service" /etc/systemd/system/openhellod.service

if [ ! -e "$CONF_DIR/openhello.env" ]; then
  if [ "$DRY_RUN" = 1 ]; then
    echo "+ write $CONF_DIR/openhello.env"
  else
    cat > "$CONF_DIR/openhello.env" <<ENV
OPENHELLO_DEVICE=/dev/video2
# OPENHELLO_IR_EMITTER=unit:selector:hexpayload   (find it with linux-enable-ir-emitter)
# OPENHELLO_TPM_TCTI=device:/dev/tpmrm0
ENV
  fi
fi

run systemctl daemon-reload
run systemctl reload dbus 2>/dev/null || true

cat <<MSG

open-hello installed. The daemon is NOT started yet; it needs inputs this script cannot provide:
  1. $CONF_DIR/engine.json  {"models_dir": "...", "calibration_path": "..."}
     models_dir must hold yunet.onnx and glintr100.onnx; calibration_path is the FAR calibration file.
  2. libonnxruntime on the loader path (or ORT_DYLIB_PATH in $CONF_DIR/openhello.env).
  3. OPENHELLO_IR_EMITTER and OPENHELLO_DEVICE in $CONF_DIR/openhello.env.
Then: systemctl enable --now openhellod && openhello-cli verify
MSG
