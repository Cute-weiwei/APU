#!/usr/bin/env bash
# Build the ARM64 redroid fallback runtime for an x86_64 host.
#
# The official redroid ARM64 image advertises 32-bit ARM ABIs but the image
# does not ship the 32-bit userspace. Android init then runs
# boringssl_self_test32, fails with ENOENT and reboots with exit code 129.
# This script patches the image to be genuinely 64-bit-only and adds the
# entrypoint that the multi-arch index normally carries.
#
# It also registers QEMU user-mode binfmt so ARM64 binaries can run on x86_64.
# Run as root (or with sudo). Re-running is safe: images are rebuilt.
set -euo pipefail

BASE_IMAGE="${BASE_IMAGE:-docker.1panel.live/redroid/redroid:12.0.0_64only-latest}"
FINAL_IMAGE="${FINAL_IMAGE:-apu-redroid-arm64:12-64only}"
BINFMT_IMAGE="${BINFMT_IMAGE:-tonistiigi/binfmt:latest}"
DEPLOY_DIR=$(cd "$(dirname "$0")" && pwd)

if [ "$(id -u)" -ne 0 ]; then
  echo "run as root: sudo $0" >&2
  exit 1
fi

if ! grep -q '^enabled' /proc/sys/fs/binfmt_misc/qemu-aarch64 2>/dev/null; then
  echo "[arm] registering qemu-aarch64 binfmt handler"
  docker run --privileged --rm "$BINFMT_IMAGE" --install arm64 >/dev/null
fi

echo "[arm] pulling $BASE_IMAGE (arm64)"
docker pull --platform linux/arm64 "$BASE_IMAGE"

WORK="$(mktemp -d)"
TMP_CONTAINER="apu-arm-build-$$"
trap 'docker rm -f "$TMP_CONTAINER" >/dev/null 2>&1 || true; rm -rf "$WORK"' EXIT

echo "[arm] creating temporary container"
docker create --platform linux/arm64 --name "$TMP_CONTAINER" "$BASE_IMAGE" >/dev/null
docker cp "$TMP_CONTAINER:/system/build.prop" "$WORK/system-build.prop"
docker cp "$TMP_CONTAINER:/vendor/build.prop" "$WORK/vendor-build.prop" 2>/dev/null || true

# Android derives ro.product.cpu.abilist32 from this file. Removing the
# 32-bit entries makes init skip the missing boringssl_self_test32.
sed -i \
  -e 's|^ro.product.cpu.abilist=.*|ro.product.cpu.abilist=arm64-v8a|' \
  -e 's|^ro.product.cpu.abilist32=.*|# disabled: ARM64-on-QEMU image has no 32-bit userspace|' \
  "$WORK/system-build.prop"
if [ -s "$WORK/vendor-build.prop" ]; then
  sed -i \
    -e 's|^ro.vendor.product.cpu.abilist=.*|ro.vendor.product.cpu.abilist=arm64-v8a|' \
    -e 's|^ro.vendor.product.cpu.abilist32=.*|# disabled: ARM64-on-QEMU image has no 32-bit userspace|' \
    "$WORK/vendor-build.prop"
  docker cp "$WORK/vendor-build.prop" "$TMP_CONTAINER:/vendor/build.prop"
fi
docker cp "$WORK/system-build.prop" "$TMP_CONTAINER:/system/build.prop"

# Opt in to the project's native-kernel interoperability profile. The patched
# interpreter rejects unsupported tagged syscall pointers and allows netd's
# native-endian netlink protocols on the ARM64/x86_64 pair.
printf '%s\n' 'APK Unpack Agents ARM64 Binder compatibility profile' > "$WORK/apu-binder-compat"
docker cp "$WORK/apu-binder-compat" "$TMP_CONTAINER:/apu-binder-compat"
# Enable Android's USB host service even when the emulator has no attached USB
# devices. Applications may enumerate an empty bus during Application.onCreate.
docker cp "$DEPLOY_DIR/permissions/apu-usb-host.xml" \
  "$TMP_CONTAINER:/vendor/etc/permissions/apu-usb-host.xml"

BASE_TAG="${FINAL_IMAGE}-base"
echo "[arm] committing patched filesystem"
docker commit "$TMP_CONTAINER" "$BASE_TAG" >/dev/null

cat > "$WORK/Dockerfile" <<EOF
FROM $BASE_TAG
ENTRYPOINT ["/init","qemu=1","androidboot.hardware=redroid"]
EOF
echo "[arm] building $FINAL_IMAGE"
docker build -q -t "$FINAL_IMAGE" "$WORK" >/dev/null

docker image inspect "$FINAL_IMAGE" --format \
  'arch={{.Architecture}} entrypoint={{json .Config.Entrypoint}} size={{.Size}}'

cat <<'EOF'
[arm] done.
The backend provisions ARM containers automatically after an x86 unpack
failure when APU_WEB_DEVICE_ARM_ENABLED=1 and APU_WEB_DEVICE_ARM_FALLBACK=1.
Keep the binfmt registration across reboots with:
  deploy/install-arm-binfmt-service.sh
EOF
