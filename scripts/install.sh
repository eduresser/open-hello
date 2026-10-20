#!/usr/bin/env bash
# Installs open-hello on a fresh Linux VM: dependencies, build, files, D-Bus/polkit/systemd integration.
# usage: sudo scripts/install.sh [--dry-run] [--no-deps] [--calibration-images DIR | --calibration-url URL]
set -euo pipefail

DRY_RUN=0
INSTALL_DEPS=1
CALIBRATION_IMAGES=""
CALIBRATION_URL=""
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=1 ;;
    --no-deps) INSTALL_DEPS=0 ;;
    --calibration-images) CALIBRATION_IMAGES="${2:?--calibration-images needs a directory}"; shift ;;
    --calibration-url) CALIBRATION_URL="${2:?--calibration-url needs a URL}"; shift ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIB_DIR=/usr/lib/openhello
BIN_DIR=/usr/libexec/openhello
CONF_DIR=/etc/openhello
MODELS_DIR=/usr/share/openhello/models
STATE_DIR=/var/lib/openhello
CALIBRATION_FILE="$STATE_DIR/calibration.bin"

ORT_VERSION=1.31.0
ORT_SHA256=cc5c72baf5ae5c8238a6841f0897227be2d02826b9cf98eaf02fdefaeeb03a57
YUNET_URL=https://github.com/opencv/opencv_zoo/raw/main/models/face_detection_yunet/face_detection_yunet_2023mar.onnx
YUNET_SHA256=8f2383e4dd3cfbb4553ea8718107fc0423210dc964f9f4280604804ed2552fa4
AURAFACE_URL=https://huggingface.co/fal/AuraFace-v1/resolve/main/glintr100.onnx
AURAFACE_SHA256=a7933ea5330113b01c9b60351d8f4c33003f145d8470ac5f0e52ee2effe25c60

run() {
  if [ "$DRY_RUN" = 1 ]; then echo "+ $*"; else "$@"; fi
}

[ "$DRY_RUN" = 1 ] || [ "$(id -u)" = 0 ] || { echo "run as root (sudo)" >&2; exit 1; }

install_deps() {
  . /etc/os-release
  case "${ID_LIKE:-$ID}" in
    *debian*|*ubuntu*)
      # A broken third-party index (e.g. a mirror mid-sync) must not block packages from the main archives
      run apt-get update || echo "warning: apt-get update reported errors; continuing with the cached indexes" >&2
      run apt-get install -y build-essential pkg-config curl ca-certificates tpm2-tools swtpm \
        libtss2-tcti-swtpm0 dbus polkitd unzip ;;
    *fedora*|*rhel*|*centos*)
      run dnf install -y gcc make pkgconf-pkg-config curl unzip tpm2-tools swtpm tpm2-tss dbus-daemon polkit ;;
    *suse*)
      run zypper --non-interactive install gcc make pkg-config curl unzip tpm2.0-tools swtpm \
        libtss2-tcti-swtpm0 dbus-1-daemon polkit ;;
    *) echo "unsupported distro ($ID); install manually: rust, tpm2-tools, swtpm, libtss2-tcti-swtpm, dbus, polkit" >&2; exit 1 ;;
  esac
}

ensure_rust() {
  if command -v cargo >/dev/null 2>&1; then return; fi
  run sh -c "curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal"
  export PATH="$HOME/.cargo/bin:$PATH"
}

fetch_verified() {
  local url="$1" sha="$2" dest="$3"
  if [ -f "$dest" ] && [ "$(sha256sum "$dest" | cut -d' ' -f1)" = "$sha" ]; then return; fi
  run curl -fL --retry 3 -o "$dest.part" "$url"
  if [ "$DRY_RUN" = 0 ]; then
    [ "$(sha256sum "$dest.part" | cut -d' ' -f1)" = "$sha" ] || { rm -f "$dest.part"; echo "checksum mismatch for $url" >&2; exit 1; }
  fi
  run mv "$dest.part" "$dest"
}

install_runtime_and_models() {
  run install -d -m 0755 "$MODELS_DIR" "$LIB_DIR"
  local work
  work="$(mktemp -d)"
  fetch_verified "https://github.com/microsoft/onnxruntime/releases/download/v$ORT_VERSION/onnxruntime-linux-x64-$ORT_VERSION.tgz" "$ORT_SHA256" "$work/ort.tgz"
  run tar -xzf "$work/ort.tgz" --no-same-owner -C "$work"
  run cp -a --no-preserve=ownership "$work/onnxruntime-linux-x64-$ORT_VERSION/lib/." "$LIB_DIR/"
  fetch_verified "$YUNET_URL" "$YUNET_SHA256" "$MODELS_DIR/yunet.onnx"
  fetch_verified "$AURAFACE_URL" "$AURAFACE_SHA256" "$MODELS_DIR/glintr100.onnx"
  rm -rf "$work"
}

calibrate() {
  local images="$CALIBRATION_IMAGES" work=""
  if [ -z "$images" ] && [ -n "$CALIBRATION_URL" ]; then
    work="$(mktemp -d)"
    run curl -fL --retry 3 -o "$work/dataset.archive" "$CALIBRATION_URL"
    case "$CALIBRATION_URL" in
      *.zip) run unzip -q "$work/dataset.archive" -d "$work/images" ;;
      *) run mkdir -p "$work/images"; run tar -xf "$work/dataset.archive" -C "$work/images" ;;
    esac
    images="$work/images"
  fi
  [ -n "$images" ] || return 1
  ORT_DYLIB_PATH="$LIB_DIR/libonnxruntime.so" run "$BIN_DIR/openhello-calibrate" \
    --models-dir "$MODELS_DIR" --images-dir "$images" --out "$CALIBRATION_FILE"
  [ -z "$work" ] || rm -rf "$work"
}

[ "$INSTALL_DEPS" = 1 ] && install_deps
ensure_rust

run cargo build --release --manifest-path "$REPO/Cargo.toml" \
  -p openhellod -p openhello-cli -p sensor-adapter-ir -p engine-adapter-face -p storage-adapter-templates

if [ -n "${SUDO_USER:-}" ] && [ "$DRY_RUN" = 0 ]; then chown -R "$SUDO_USER" "$REPO/target"; fi
T="$REPO/target/release"
run install -d -m 0755 "$LIB_DIR" "$BIN_DIR" "$CONF_DIR"
run install -d -m 0700 /var/lib/openhello
for lib in libsensor_adapter_ir libengine_adapter_face libstorage_adapter_templates; do
  run install -m 0644 "$T/$lib.so" "$LIB_DIR/$lib.so"
done
run install -m 0755 "$T/openhellod" "$BIN_DIR/openhellod"
run install -m 0755 "$T/openhello-cli" /usr/local/bin/openhello-cli
run install -m 0755 "$T/openhello-calibrate" "$BIN_DIR/openhello-calibrate"
install_runtime_and_models
run install -m 0644 "$REPO/packaging/io.openhello.Biometrics1.conf" /usr/share/dbus-1/system.d/io.openhello.Biometrics1.conf
run install -m 0644 "$REPO/crates/openhellod/io.openhello.Biometrics1.policy" /usr/share/polkit-1/actions/io.openhello.Biometrics1.policy
run install -m 0644 "$REPO/packaging/openhellod.service" /etc/systemd/system/openhellod.service

if [ ! -e "$CONF_DIR/openhello.env" ]; then
  if [ "$DRY_RUN" = 1 ]; then
    echo "+ write $CONF_DIR/openhello.env"
  else
    cat > "$CONF_DIR/openhello.env" <<ENV
OPENHELLO_DEVICE=/dev/video2
ORT_DYLIB_PATH=$LIB_DIR/libonnxruntime.so
# Emitter is detected automatically. Only for cameras that stay dark: OPENHELLO_IR_EMITTER=unit:selector:hexpayload
# (find it with linux-enable-ir-emitter) or OPENHELLO_IR_EMITTER_ALLOW_WRITE=1 to let open-hello switch the Microsoft face-auth mode
# OPENHELLO_TPM_TCTI=device:/dev/tpmrm0
ENV
  fi
fi

CALIBRATED=0
if [ -f "$CALIBRATION_FILE" ] || calibrate; then CALIBRATED=1; fi
if [ "$CALIBRATED" = 1 ] && [ "$DRY_RUN" = 0 ]; then
  printf '{"models_dir": "%s", "calibration_path": "%s"}\n' "$MODELS_DIR" "$CALIBRATION_FILE" > "$CONF_DIR/engine.json"
fi

run systemctl daemon-reload
run systemctl reload dbus 2>/dev/null || true

if [ "$CALIBRATED" = 1 ]; then
  run systemctl enable --now openhellod 2>/dev/null || true
  echo
  echo "open-hello installed and started. Check OPENHELLO_DEVICE (the IR camera node) in $CONF_DIR/openhello.env"
else
  cat <<MSG

open-hello installed (binaries, ONNX Runtime, models). The daemon is NOT started: no FAR calibration yet.
Calibrate from a folder of face photos (one sub-folder per person) and start it:
  sudo scripts/install.sh --no-deps --calibration-images /path/to/photos
  (or --calibration-url URL of a .tar/.tgz/.zip archive with the same layout)
Also check OPENHELLO_DEVICE (the IR camera node) in $CONF_DIR/openhello.env.
MSG
fi
