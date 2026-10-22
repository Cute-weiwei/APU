#!/usr/bin/env bash
# Build a patched QEMU user-mode aarch64 binary for the ARM64 redroid fallback.
#
# Stock QEMU returns ENOTTY for every ioctl it does not enumerate. Android's
# binder_alloc and all Binder transactions rely on such ioctls, so a stock
# qemu-user cannot boot redroid. The patch in deploy/qemu-binder.patch:
#   - passes unknown ioctls through to the host (guest memory is 1:1 on x86_64)
#   - keeps Binder write/read buffers in host memory and strips ARM64 TBI tags
#   - forwards PR_SET_VMA so dalvik region names stay visible in /proc maps
#   - accepts Android's partial CLONE_THREAD flag set
#   - defaults to cortex-a76 instead of "any" so MTE/tagged pointers are off
# This is experimental: it lets init run and create binder devices, but full
# Android boot still needs work. Run as root.
set -euo pipefail

QEMU_VERSION="${QEMU_VERSION:-8.2.2}"
SRC="${SRC:-/opt/qemu-$QEMU_VERSION}"
DEPLOY_DIR=$(cd "$(dirname "$0")" && pwd)
PATCH_FILE="${PATCH_FILE:-$DEPLOY_DIR/qemu-binder.patch}"
JOBS="${JOBS:-$(nproc)}"

if [ "$(id -u)" -ne 0 ]; then
  echo "run as root: sudo $0" >&2
  exit 1
fi

if [ ! -d "$SRC" ]; then
  echo "[qemu] downloading $QEMU_VERSION"
  curl -L --fail --retry 3 -o "/opt/qemu-$QEMU_VERSION.tar.xz" \
    "https://download.qemu.org/qemu-$QEMU_VERSION.tar.xz"
  tar -C /opt -xf "/opt/qemu-$QEMU_VERSION.tar.xz"
fi

if ! grep -q "do_binder_write_read" "$SRC/linux-user/syscall.c"; then
  echo "[qemu] applying binder/prctl patch"
  patch -d "$SRC" -p1 < "$PATCH_FILE"
fi
if grep -Fq 'uint64_t ptr_off[2] = { 0, UINT64_MAX };' "$SRC/linux-user/syscall.c"; then
  echo "[qemu] correcting existing Binder command boundaries"
  patch -d "$SRC" -p1 < "$DEPLOY_DIR/qemu-binder-boundary.patch"
fi
if ! grep -Fq 'access("/apu-binder-compat", F_OK)' "$SRC/linux-user/aarch64/target_prctl.h"; then
  patch -d "$SRC" -p1 < "$DEPLOY_DIR/qemu-binder-tagged-syscalls.patch"
fi
if ! grep -q 'apu_native_android_netlink' "$SRC/linux-user/syscall.c"; then
  patch -d "$SRC" -p1 < "$DEPLOY_DIR/qemu-android-netlink.patch"
fi
if ! grep -q "ARM64 Linux uses the host's integer option 36" "$SRC/linux-user/syscall.c"; then
  patch -d "$SRC" -p1 < "$DEPLOY_DIR/qemu-android-netd-sockets.patch"
fi
if ! grep -q 'apu_guest_task_entry' "$SRC/linux-user/syscall.c"; then
  patch -d "$SRC" -p1 < "$DEPLOY_DIR/qemu-android-guest-tasks.patch"
fi

echo "[qemu] configuring"
cd "$SRC"
if [ ! -f build/config-host.mak ]; then
  ./configure --target-list=aarch64-linux-user --static --disable-system \
    --disable-docs --disable-tools --disable-guest-agent --disable-werror
fi

echo "[qemu] building qemu-aarch64 (static)"
make -j"$JOBS" qemu-aarch64

BIN="$SRC/build/qemu-aarch64"
if [ ! -x "$BIN" ]; then
  BIN="$SRC/qemu-aarch64"
fi
if [ ! -x "$BIN" ]; then
  echo "qemu-aarch64 binary not found after build" >&2
  exit 1
fi

INSTALLED=/usr/libexec/qemu-binfmt/aarch64-binfmt-P
if [ -f "$INSTALLED" ] && [ ! -f "$INSTALLED.orig" ]; then
  cp -a "$INSTALLED" "$INSTALLED.orig"
fi
install -m 0755 "$BIN" "$INSTALLED"

# qemu-user-static registers this through systemd-binfmt's binfmt.d config,
# not through update-binfmts. Re-register so the active handler points at the
# freshly installed patched binary; also replace a stock tonistiigi handler.
ENTRY=/proc/sys/fs/binfmt_misc/qemu-aarch64
if [ ! -f /usr/lib/binfmt.d/qemu-aarch64.conf ] && [ ! -f /etc/binfmt.d/qemu-aarch64.conf ]; then
  echo "[qemu] qemu-aarch64 binfmt.d config missing; install qemu-user-static" >&2
  exit 1
fi
if ! command -v systemctl >/dev/null 2>&1; then
  echo "[qemu] systemctl not found; systemd-binfmt is required" >&2
  exit 1
fi
# Always reopen the interpreter after install: the F flag can retain the old
# inode even when the registration already displays the correct pathname.
bash "$DEPLOY_DIR/refresh-arm-binfmt.sh"
if ! grep -Fq "$INSTALLED" "$ENTRY" 2>/dev/null; then
  echo "[qemu] active binfmt handler does not use $INSTALLED" >&2
  echo "[qemu] ARM64 emulation would run the wrong QEMU binary" >&2
  exit 1
fi

echo "[qemu] installed patched interpreter at $INSTALLED"
ls -l "$INSTALLED" "$INSTALLED.orig" 2>/dev/null || true
