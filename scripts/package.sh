#!/usr/bin/env bash
# usage: scripts/package.sh VERSION [--skip-build]
set -euo pipefail

VERSION="${1:?usage: scripts/package.sh VERSION [--skip-build]}"
VERSION="${VERSION#v}"
SKIP_BUILD=0
[ "${2:-}" = "--skip-build" ] && SKIP_BUILD=1

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAGE="$REPO/dist/stage"
T="${CARGO_TARGET_DIR:-$REPO/target}/release"

ORT_VERSION=1.31.0
ORT_SHA256=cc5c72baf5ae5c8238a6841f0897227be2d02826b9cf98eaf02fdefaeeb03a57
YUNET_URL=https://github.com/opencv/opencv_zoo/raw/main/models/face_detection_yunet/face_detection_yunet_2023mar.onnx
YUNET_SHA256=8f2383e4dd3cfbb4553ea8718107fc0423210dc964f9f4280604804ed2552fa4
AURAFACE_URL=https://huggingface.co/fal/AuraFace-v1/resolve/main/glintr100.onnx
AURAFACE_SHA256=a7933ea5330113b01c9b60351d8f4c33003f145d8470ac5f0e52ee2effe25c60

command -v nfpm >/dev/null 2>&1 || { echo "nfpm not found: https://nfpm.goreleaser.com/install/" >&2; exit 1; }

fetch_verified() {
  local url="$1" sha="$2" dest="$3"
  if [ -f "$dest" ] && [ "$(sha256sum "$dest" | cut -d' ' -f1)" = "$sha" ]; then return; fi
  curl -fL --retry 3 -o "$dest.part" "$url"
  [ "$(sha256sum "$dest.part" | cut -d' ' -f1)" = "$sha" ] || { rm -f "$dest.part"; echo "checksum mismatch for $url" >&2; exit 1; }
  mv "$dest.part" "$dest"
}

if [ "$SKIP_BUILD" = 0 ]; then
  cargo build --release --locked --manifest-path "$REPO/Cargo.toml" \
    -p openhellod -p openhello-cli -p sensor-adapter-ir -p engine-adapter-face -p storage-adapter-templates \
    -p openhello-keyd -p openhello-pkcs11 -p openhello-pam -p openhello-gui
fi

mkdir -p "$REPO/dist/cache"
rm -rf "$STAGE"
mkdir -p "$STAGE/models" "$STAGE/onnxruntime"

for file in openhellod openhello-keyd openhello-cli openhello-gui openhello-calibrate \
  libpam_openhello.so libopenhello_pkcs11.so libsensor_adapter_ir.so libengine_adapter_face.so libstorage_adapter_templates.so; do
  cp "$T/$file" "$STAGE/$file"
done
strip --strip-unneeded "$STAGE"/*.so "$STAGE"/openhello*

for unit in openhellod.service openhello-keyd.service; do
  sed "s|@LIBEXECDIR@|/usr/libexec/openhello|g" "$REPO/packaging/$unit" > "$STAGE/$unit"
done

fetch_verified "https://github.com/microsoft/onnxruntime/releases/download/v$ORT_VERSION/onnxruntime-linux-x64-$ORT_VERSION.tgz" "$ORT_SHA256" "$REPO/dist/cache/ort.tgz"
tar -xzf "$REPO/dist/cache/ort.tgz" --no-same-owner -C "$REPO/dist/cache"
cp -a "$REPO/dist/cache/onnxruntime-linux-x64-$ORT_VERSION/lib/"libonnxruntime*.so* "$STAGE/onnxruntime/"
fetch_verified "$YUNET_URL" "$YUNET_SHA256" "$REPO/dist/cache/yunet.onnx"
fetch_verified "$AURAFACE_URL" "$AURAFACE_SHA256" "$REPO/dist/cache/glintr100.onnx"
cp "$REPO/dist/cache/yunet.onnx" "$REPO/dist/cache/glintr100.onnx" "$STAGE/models/"

cd "$REPO"
for format in deb rpm archlinux; do
  VERSION="$VERSION" nfpm package --config packaging/nfpm.yaml --packager "$format" --target dist/
done
(cd dist && sha256sum ./*.deb ./*.rpm ./*.pkg.tar.zst > SHA256SUMS)
ls -lh dist/*.deb dist/*.rpm dist/*.pkg.tar.zst
