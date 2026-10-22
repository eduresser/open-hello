#!/usr/bin/env bash
# PAM directory = dirname of libpam.so.0 from the loader cache + /security: covers openSUSE (/usr/lib64), Debian/Ubuntu (multiarch) and Arch (/usr/lib).
# Installs open-hello without touching the system's package manager: it checks capabilities, builds, and installs to neutral locations.
# usage: sudo scripts/install.sh [--dry-run] [--skip-checks] [--no-pam] [--calibration-images DIR | --calibration-url URL]
# The PAM module is enabled once in the common auth stack unless --no-pam is given; undo with `sudo openhello-cli pam disable`.
set -euo pipefail

DRY_RUN=0
SKIP_CHECKS=0
ENABLE_PAM=1
CALIBRATION_IMAGES=""
CALIBRATION_URL=""
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=1 ;;
    --skip-checks) SKIP_CHECKS=1 ;;
    --no-pam) ENABLE_PAM=0 ;;
    --no-deps) echo "warning: --no-deps is deprecated and ignored; the installer no longer installs packages" >&2 ;;
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
UNIT_DIR=/usr/lib/systemd/system
DBUS_POLICY_DIR=/usr/share/dbus-1/system.d
POLKIT_ACTIONS_DIR=/usr/share/polkit-1/actions
LEGACY_UNIT_DIR=/etc/systemd/system
LDCONFIG="$(command -v ldconfig || echo /sbin/ldconfig)"
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

missing=()
need() { missing+=("$1"); }

check_capabilities() {
  local ld_cache
  ld_cache="$($LDCONFIG -p 2>/dev/null || true)"
  command -v cc >/dev/null 2>&1 || need "C compiler and linker"
  command -v curl >/dev/null 2>&1 || need "HTTPS downloader (curl)"
  command -v tpm2_createprimary >/dev/null 2>&1 || need "TPM 2.0 command-line tools (tpm2_createprimary)"
  command -v tpm2_ptool >/dev/null 2>&1 || need "PKCS#11 TPM store tool (tpm2_ptool)"
  python3 -c 'import tpm2_pkcs11' >/dev/null 2>&1 || need "Python module tpm2_pkcs11 for the interpreter at $(command -v python3 || echo python3)"
  grep -q 'libtss2-esys\.so' <<<"$ld_cache" || need "TPM software stack libraries (libtss2-esys)"
  grep -q 'libtss2-tcti-device\.so' <<<"$ld_cache" || need "TPM device transport library (libtss2-tcti-device)"
  if ! { command -v p11-kit >/dev/null 2>&1 && p11-kit list-modules 2>/dev/null | grep -q 'libtpm2_pkcs11\.so'; } && ! grep -q 'libtpm2_pkcs11\.so' <<<"$ld_cache"; then
    need "PKCS#11 module for the TPM (libtpm2_pkcs11.so)"
  fi
  command -v polkitd >/dev/null 2>&1 || [ -x /usr/lib/polkit-1/polkitd ] || [ -x /usr/libexec/polkitd ] || need "polkit authorization daemon (polkitd)"
  command -v pkttyagent >/dev/null 2>&1 || need "polkit text agent (pkttyagent)"
  command -v dbus-daemon >/dev/null 2>&1 || need "D-Bus message daemon (dbus-daemon)"
  [ -S /run/dbus/system_bus_socket ] || need "running D-Bus system bus (/run/dbus/system_bus_socket)"
  command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ] || need "systemd as the running init system"
  if [ "${#missing[@]}" -gt 0 ]; then
    echo "missing capabilities:" >&2
    printf '  - %s\n' "${missing[@]}" >&2
    echo "provide them with your system's tools and run again, or pass --skip-checks" >&2
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

[ "$SKIP_CHECKS" = 1 ] || check_capabilities
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

pam_module_dir() {
  local libpam
  libpam="$($LDCONFIG -p 2>/dev/null | awk '/libpam\.so\.0/{print $NF; exit}')"
  [ -n "$libpam" ] || { echo "libpam.so.0 not found in the loader cache ($LDCONFIG -p): the PAM library is not installed" >&2; exit 1; }
  echo "$(dirname "$(readlink -f "$libpam")")/security"
}

install_unit() {
  if [ "$DRY_RUN" = 1 ]; then echo "+ install unit $1 to $UNIT_DIR with @LIBEXECDIR@=$BIN_DIR"; return; fi
  sed "s|@LIBEXECDIR@|$BIN_DIR|g" "$REPO/packaging/$1" > "$UNIT_DIR/$1"
  chmod 0644 "$UNIT_DIR/$1"
}

remove_legacy_units() {
  local unit file
  for unit in openhellod.service openhello-keyd.service; do
    file="$LEGACY_UNIT_DIR/$unit"
    if [ -f "$file" ] && [ ! -L "$file" ] && grep -q '^Description=open-hello' "$file"; then run rm -f "$file"; fi
  done
}

install_key_daemon() {
  run install -m 0755 "$T/openhello-keyd" "$BIN_DIR/openhello-keyd"
  run install -m 0644 "$T/libopenhello_pkcs11.so" "$LIB_DIR/libopenhello_pkcs11.so"
  run install -d -m 0755 "$CONF_DIR/cacerts" "$CONF_DIR/crls"
  run install -m 0644 "$REPO/packaging/io.openhello.Keyd1.conf" "$DBUS_POLICY_DIR/io.openhello.Keyd1.conf"
  run install -m 0644 "$REPO/crates/openhello-keyd/io.openhello.Keyd1.policy" "$POLKIT_ACTIONS_DIR/io.openhello.Keyd1.policy"
  install_unit openhello-keyd.service
}

install_pam_module() {
  local pam_dir
  pam_dir="$(pam_module_dir)"
  run /usr/local/bin/openhello-cli pam migrate || echo "warning: could not migrate PAM files left by an earlier installer; run openhello-cli pam migrate as root before using sudo" >&2
  run install -d -m 0755 "$pam_dir"
  run install -m 0755 "$T/libpam_openhello.so" "$pam_dir/pam_openhello.so"
  PAM_MODULE_DIR="$pam_dir"
  PAM_ENABLED=0
  [ "$ENABLE_PAM" = 1 ] || return 0
  if run /usr/local/bin/openhello-cli pam enable; then
    PAM_ENABLED=1
  else
    echo "warning: could not enable the PAM module in the common auth stack; password authentication is untouched. Fix the cause above, or enable per service with: sudo openhello-cli pam enable <service>..." >&2
  fi
}

run install -m 0644 "$REPO/packaging/io.openhello.Biometrics1.conf" "$DBUS_POLICY_DIR/io.openhello.Biometrics1.conf"
run install -m 0644 "$REPO/crates/openhellod/io.openhello.Biometrics1.policy" "$POLKIT_ACTIONS_DIR/io.openhello.Biometrics1.policy"
install_unit openhellod.service

if [ ! -e "$CONF_DIR/openhello.env" ]; then
  if [ "$DRY_RUN" = 1 ]; then
    echo "+ write $CONF_DIR/openhello.env"
  else
    cat > "$CONF_DIR/openhello.env" <<ENV
OPENHELLO_DEVICE=/dev/video2
ORT_DYLIB_PATH=$LIB_DIR/libonnxruntime.so
# Emitter is detected and switched on automatically. Only for cameras that stay dark: OPENHELLO_IR_EMITTER=unit:selector:hexpayload
# (find it with linux-enable-ir-emitter)
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

CALIBRATION_OVERRIDE=0
if [ -f "$CALIBRATION_FILE" ]; then
  CALIBRATION_OVERRIDE=1
elif [ -n "$CALIBRATION_IMAGES$CALIBRATION_URL" ]; then
  if calibrate; then
    CALIBRATION_OVERRIDE=1
  else
    echo "Calibration override failed; continuing with the built-in FAR calibration." >&2
  fi
fi
if [ "$DRY_RUN" = 0 ]; then
  if [ "$CALIBRATION_OVERRIDE" = 1 ]; then
    printf '{"models_dir": "%s", "calibration_path": "%s"}\n' "$MODELS_DIR" "$CALIBRATION_FILE" > "$CONF_DIR/engine.json"
  else
    printf '{"models_dir": "%s"}\n' "$MODELS_DIR" > "$CONF_DIR/engine.json"
  fi
else
  echo "+ write $CONF_DIR/engine.json (models_dir$([ "$CALIBRATION_OVERRIDE" = 1 ] && echo ", calibration_path=$CALIBRATION_FILE"))"
fi

install_key_daemon
install_pam_module

remove_legacy_units
run systemctl daemon-reload
run systemctl reload dbus 2>/dev/null || true
run systemctl enable openhello-keyd 2>/dev/null || true
run systemctl restart openhello-keyd 2>/dev/null || true
run systemctl reset-failed openhellod 2>/dev/null || true
run systemctl enable openhellod 2>/dev/null || true
run systemctl restart openhellod 2>/dev/null || true

echo
echo "open-hello installed and started. Check OPENHELLO_DEVICE (the IR camera node) in $CONF_DIR/openhello.env"
echo "PAM module installed at $PAM_MODULE_DIR/pam_openhello.so"
if [ "$PAM_ENABLED" = 1 ] || { [ "$DRY_RUN" = 1 ] && [ "$ENABLE_PAM" = 1 ]; }; then
  echo "PAM module enabled once in the common auth stack (every local service except login, su, sshd, cron and similar). It only acts for users who enrolled a face; passwords keep working. Undo with: sudo openhello-cli pam disable (check with: openhello-cli pam status)"
else
  echo "PAM module not enabled. Enable it with: sudo openhello-cli pam enable (whole integration) or per service: sudo openhello-cli pam enable <service>..."
fi
[ ! -d "$CONF_DIR/nssdb" ] || echo "$CONF_DIR/nssdb was created by an older installer and is no longer used; it can be deleted"
