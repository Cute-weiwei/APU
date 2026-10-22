#!/usr/bin/env bash
# Reopen the configured ARM64 interpreter after its binary was replaced.
# binfmt_misc F holds an open file: an unchanged pathname does not mean that
# the kernel is executing the current file at that pathname.
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "run as root" >&2
  exit 1
fi

PATCHED=/usr/libexec/qemu-binfmt/aarch64-binfmt-P
ENTRY=/proc/sys/fs/binfmt_misc/qemu-aarch64
CONFIG=/etc/binfmt.d/qemu-aarch64.conf
[ -f "$CONFIG" ] || CONFIG=/usr/lib/binfmt.d/qemu-aarch64.conf
[ -x "$PATCHED" ] || { echo "missing $PATCHED" >&2; exit 1; }
[ -f "$CONFIG" ] || { echo "missing ARM64 binfmt configuration" >&2; exit 1; }
REGISTRATION=$(grep '^:qemu-aarch64:' "$CONFIG")
case "$REGISTRATION" in
  *":$PATCHED:"*) ;;
  *) echo "configured interpreter differs from $PATCHED" >&2; exit 1 ;;
esac
# Validate before unregistering a working handler.
ELF_HEADERS=$(readelf -l "$PATCHED")
if grep -q 'INTERP' <<< "$ELF_HEADERS"; then
  echo "ARM64 binfmt interpreter must be statically linked" >&2
  exit 1
fi
[ -w /proc/sys/fs/binfmt_misc/register ] || { echo "binfmt registration is not writable" >&2; exit 1; }
if [ -f "$ENTRY" ]; then
  echo -1 > "$ENTRY"
fi
printf '%s\n' "$REGISTRATION" > /proc/sys/fs/binfmt_misc/register
grep -Fq "interpreter $PATCHED" "$ENTRY"
