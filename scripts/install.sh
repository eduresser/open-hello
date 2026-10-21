#!/usr/bin/env bash
# Installs open-hello on a fresh Linux VM: dependencies, build, files, D-Bus/polkit/systemd integration.
# Also wires `sudo` to face/PIN login (pam_pkcs11 + TPM key); certutil (nss-tools) is required by openhello-keyd to trust the key certificate.
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
PAM_SERVICE_DIR=/etc/pam.d
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
  if command -v apt-get >/dev/null 2>&1; then
    # A broken third-party index (e.g. a mirror mid-sync) must not block packages from the main archives
    run apt-get update || echo "warning: apt-get update reported errors; continuing with the cached indexes" >&2
    run apt-get install -y build-essential pkg-config curl ca-certificates tpm2-tools swtpm \
      libtss2-tcti-swtpm0 dbus polkitd unzip libpam-pkcs11 libtpm2-pkcs11-1 libtpm2-pkcs11-tools libnss3-tools
  elif command -v dnf >/dev/null 2>&1; then
    run dnf install -y gcc make pkgconf-pkg-config curl unzip tpm2-tools swtpm tpm2-tss dbus-daemon polkit pam_pkcs11 tpm2-pkcs11 tpm2-pkcs11-tools nss-tools
  elif command -v zypper >/dev/null 2>&1; then
    run zypper --non-interactive install gcc make pkg-config curl unzip tpm2.0-tools swtpm \
      libtss2-tcti-swtpm0 dbus-1-daemon polkit pam_pkcs11 tpm2-pkcs11 mozilla-nss-tools
  elif command -v pacman >/dev/null 2>&1; then
    run pacman -S --needed --noconfirm base-devel pkgconf curl unzip tpm2-tools swtpm tpm2-tss dbus polkit nss tpm2-pkcs11
    echo "note: pam_pkcs11 is not in the Arch repositories; install it from the AUR before enabling the PAM stacks" >&2
  else
    echo "no supported package manager (apt, dnf, zypper, pacman); install manually: rust, tpm2-tools, swtpm, libtss2-tcti-swtpm, dbus, polkit, pam_pkcs11, tpm2-pkcs11, nss tools" >&2
    exit 1
  fi
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
  run cp -a --no-preserve=ownership --remove-destination "$work/onnxruntime-linux-x64-$ORT_VERSION/lib/." "$LIB_DIR/"
  fetch_verified "$YUNET_URL" "$YUNET_SHA256" "$MODELS_DIR/yunet.onnx"
  fetch_verified "$AURAFACE_URL" "$AURAFACE_SHA256" "$MODELS_DIR/glintr100.onnx"
  rm -rf "$work"
}

single_subdirectory() {
  local entries
  entries="$(find "$1" -mindepth 1 -maxdepth 1)"
  if [ "$(printf '%s\n' "$entries" | wc -l)" = 1 ] && [ -d "$entries" ]; then printf '%s\n' "$entries"; else printf '%s\n' "$1"; fi
}

calibrate() {
  local images="$CALIBRATION_IMAGES" work="" status=0
  if [ -z "$images" ] && [ -n "$CALIBRATION_URL" ]; then
    work="$(mktemp -d)"
    run curl -fL --retry 3 -o "$work/dataset.archive" "$CALIBRATION_URL"
    case "$CALIBRATION_URL" in
      *.zip) run unzip -q "$work/dataset.archive" -d "$work/images" ;;
      *) run mkdir -p "$work/images"; run tar -xf "$work/dataset.archive" -C "$work/images" ;;
    esac
    images="$work/images"
    [ "$DRY_RUN" = 1 ] || images="$(single_subdirectory "$images")"
  fi
  [ -n "$images" ] || return 1
  ORT_DYLIB_PATH="$LIB_DIR/libonnxruntime.so" run "$BIN_DIR/openhello-calibrate" \
    --models-dir "$MODELS_DIR" --images-dir "$images" --out "$CALIBRATION_FILE" || status=$?
  [ -z "$work" ] || rm -rf "$work"
  return "$status"
}

[ "$INSTALL_DEPS" = 1 ] && install_deps
ensure_rust

run cargo build --release --manifest-path "$REPO/Cargo.toml" \
  -p openhellod -p openhello-cli -p sensor-adapter-ir -p engine-adapter-face -p storage-adapter-templates \
  -p openhello-keyd -p openhello-pkcs11 -p openhello-pam

if [ -n "${SUDO_USER:-}" ] && [ "$DRY_RUN" = 0 ]; then chown -R "$SUDO_USER" "$REPO/target"; fi
T="$REPO/target/release"
run systemctl stop openhellod openhello-keyd 2>/dev/null || true
run install -d -m 0755 "$LIB_DIR" "$BIN_DIR" "$CONF_DIR"
run install -d -m 0700 /var/lib/openhello
for lib in libsensor_adapter_ir libengine_adapter_face libstorage_adapter_templates; do
  run install -m 0644 "$T/$lib.so" "$LIB_DIR/$lib.so"
done
run install -m 0755 "$T/openhellod" "$BIN_DIR/openhellod"
run install -m 0755 "$T/openhello-cli" /usr/local/bin/openhello-cli
run install -m 0755 "$T/openhello-calibrate" "$BIN_DIR/openhello-calibrate"
install_runtime_and_models

first_existing() {
  local candidate
  for candidate in "$@"; do
    if [ -e "$candidate" ]; then echo "$candidate"; return 0; fi
  done
  return 1
}

install_sudo_login() {
  command -v certutil >/dev/null 2>&1 || [ "$DRY_RUN" = 1 ] || { echo "certutil not found: install nss-tools (libnss3-tools, mozilla-nss-tools)" >&2; exit 1; }
  local pam_dir pkcs11_dir tpm2_module
  pam_dir="$(first_existing /usr/lib64/security /usr/lib/security /usr/lib/x86_64-linux-gnu/security)" || pam_dir=/usr/lib64/security
  pkcs11_dir="$(first_existing /usr/lib64/pam_pkcs11 /usr/lib/pam_pkcs11 /usr/lib/x86_64-linux-gnu/pam_pkcs11)" || pkcs11_dir=/usr/lib64/pam_pkcs11
  tpm2_module="$(first_existing /usr/lib64/pkcs11/libtpm2_pkcs11.so /usr/lib/x86_64-linux-gnu/pkcs11/libtpm2_pkcs11.so /usr/lib/pkcs11/libtpm2_pkcs11.so)" || tpm2_module=/usr/lib64/pkcs11/libtpm2_pkcs11.so

  run install -m 0755 "$T/openhello-keyd" "$BIN_DIR/openhello-keyd"
  run install -m 0644 "$T/libopenhello_pkcs11.so" "$LIB_DIR/libopenhello_pkcs11.so"
  run install -m 0644 "$T/libpam_openhello.so" "$pam_dir/pam_openhello.so"
  run install -d -m 0755 "$CONF_DIR/cacerts" "$CONF_DIR/crls"
  run install -m 0644 "$REPO/packaging/io.openhello.Keyd1.conf" /usr/share/dbus-1/system.d/io.openhello.Keyd1.conf
  run install -m 0644 "$REPO/crates/openhello-keyd/io.openhello.Keyd1.policy" /usr/share/polkit-1/actions/io.openhello.Keyd1.policy
  run install -m 0644 "$REPO/packaging/openhello-keyd.service" /etc/systemd/system/openhello-keyd.service
  run install -m 0644 "$REPO/packaging/pam/sudo-openhello" $PAM_SERVICE_DIR/sudo-openhello
  run install -m 0644 "$REPO/packaging/pam/openhello-lockscreen" "$PAM_SERVICE_DIR/openhello-lockscreen"
  run install -D -m 0644 "$REPO/packaging/pam/openhello-common-auth" /usr/share/openhello/pam/openhello-common-auth
  if [ "$DRY_RUN" = 1 ]; then
    echo "+ write $CONF_DIR/pam_pkcs11.conf and $CONF_DIR/pkcs11.conf (root-owned, 0644)"
  else
    sed "s|/usr/lib64/pam_pkcs11|$pkcs11_dir|" "$REPO/packaging/pam/pam_pkcs11.conf" > "$CONF_DIR/pam_pkcs11.conf"
    sed "s|/usr/lib64/pkcs11/libtpm2_pkcs11.so|$tpm2_module|" "$REPO/packaging/pam/pkcs11.conf" > "$CONF_DIR/pkcs11.conf"
    chown root:root "$CONF_DIR/pam_pkcs11.conf" "$CONF_DIR/pkcs11.conf"
    chmod 0644 "$CONF_DIR/pam_pkcs11.conf" "$CONF_DIR/pkcs11.conf"
  fi
  enable_sudo_stack
  enable_lock_screen_face
}

# Only the stack is installed for every locker; wiring it into a locker is per environment (see .spec/features/credential-login-v1b/lockscreen.md).
# KDE is the one adapter automated here: kscreenlocker_greet starts its "Face" authenticator only when kde-face exists, and the `kde` password service is never touched. Undo with `rm $PAM_SERVICE_DIR/kde-face`.
enable_lock_screen_face() {
  local face_file="$PAM_SERVICE_DIR/kde-face" include='auth include openhello-lockscreen'
  [ "$DRY_RUN" = 1 ] || first_existing /usr/libexec/kscreenlocker_greet /usr/lib/kscreenlocker_greet /usr/lib64/libexec/kscreenlocker_greet >/dev/null || return 0
  if [ "$DRY_RUN" = 0 ] && [ -e "$face_file" ] && ! grep -qxF "$include" "$face_file"; then
    echo "$face_file already exists and is not ours; add '$include' to it manually" >&2
    return
  fi
  if [ "$DRY_RUN" = 1 ]; then
    echo "+ write $face_file ($include, account include common-account) when kscreenlocker is present"
  else
    printf '#%%PAM-1.0\n%s\naccount include common-account\n' "$include" > "$face_file"
    chmod 0644 "$face_file"
  fi
}

# A backup is kept; undo with `mv $PAM_SERVICE_DIR/sudo.openhello.bak $PAM_SERVICE_DIR/sudo`.
enable_sudo_stack() {
  local sudo_file="$PAM_SERVICE_DIR/sudo" vendor_dir include='auth include sudo-openhello'
  vendor_dir="$(first_existing /usr/lib/pam.d /usr/etc/pam.d)" || vendor_dir=/usr/lib/pam.d
  if [ ! -e "$sudo_file" ] && [ -e "$vendor_dir/sudo" ]; then run cp "$vendor_dir/sudo" "$sudo_file"; fi
  if [ ! -e "$sudo_file" ] && [ "$DRY_RUN" = 0 ]; then
    echo "no $sudo_file: add '$include' above the password module of your sudo PAM service" >&2
    return
  fi
  if [ "$DRY_RUN" = 0 ] && grep -qxF "$include" "$sudo_file"; then return; fi
  run cp -n "$sudo_file" "$sudo_file.openhello.bak"
  run sed -i "0,/^\(auth\|@include\)[[:space:]]/s//$include\n&/" "$sudo_file"
}

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

ensure_env() {
  if [ "$DRY_RUN" = 1 ]; then echo "+ ensure $1 in $CONF_DIR/openhello.env"; return; fi
  grep -q "^$1=" "$CONF_DIR/openhello.env" || printf '%s=%s\n' "$1" "$2" >> "$CONF_DIR/openhello.env"
}
ensure_env OPENHELLO_KEYD_TICKET_SOCKET /run/openhello/keyd-ticket.sock
ensure_env OPENHELLO_KEYD_PURGE_BUS system

CALIBRATED=0
if [ -f "$CALIBRATION_FILE" ] || calibrate; then CALIBRATED=1; fi
if [ "$CALIBRATED" = 1 ] && [ "$DRY_RUN" = 0 ]; then
  printf '{"models_dir": "%s", "calibration_path": "%s"}\n' "$MODELS_DIR" "$CALIBRATION_FILE" > "$CONF_DIR/engine.json"
fi

install_sudo_login

run systemctl daemon-reload
run systemctl reload dbus 2>/dev/null || true
run systemctl enable openhello-keyd 2>/dev/null || true
run systemctl restart openhello-keyd 2>/dev/null || true

if [ "$CALIBRATED" = 1 ]; then
  run systemctl reset-failed openhellod 2>/dev/null || true
  run systemctl enable openhellod 2>/dev/null || true
  run systemctl restart openhellod 2>/dev/null || true
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
