#!/usr/bin/env bash
# usage: scripts/package-portable.sh VERSION
# Compiles inside AlmaLinux 8 so the binaries only need glibc 2.28, the floor set by the bundled ONNX Runtime; packaging runs on the host.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE=localhost/openhello-build-el8

podman build -q -t "$IMAGE" -f "$REPO/packaging/build/Containerfile" "$REPO/packaging/build"

podman run --rm -v "$REPO:/work:Z" -w /work -e CARGO_TARGET_DIR=/work/target/el8 "$IMAGE" \
  cargo build --release --locked \
  -p openhellod -p openhello-cli -p sensor-adapter-ir -p engine-adapter-face -p storage-adapter-templates \
  -p openhello-keyd -p openhello-pkcs11 -p openhello-pam -p openhello-gui

CARGO_TARGET_DIR="$REPO/target/el8" "$REPO/scripts/package.sh" "$@" --skip-build
