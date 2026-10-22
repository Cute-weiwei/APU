#!/usr/bin/env bash
# Verify and persist the patched ARM64 QEMU binfmt handler across reboots.
#
# qemu-user-static registers binfmt handlers through systemd-binfmt and
# binfmt.d, not through update-binfmts. Do NOT use tonistiigi/binfmt here: it
# registers a bundled stock qemu-aarch64 that shadows the interpreter built by
# build-qemu-binder.sh, so Binder ioctls fail again after a reboot.
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "run as root: sudo $0" >&2
  exit 1
fi

PATCHED=/usr/libexec/qemu-binfmt/aarch64-binfmt-P
if [ ! -x "$PATCHED" ]; then
  echo "patched interpreter missing: $PATCHED" >&2
  echo "run deploy/build-qemu-binder.sh first" >&2
  exit 1
fi
if [ ! -f /usr/lib/binfmt.d/qemu-aarch64.conf ] && [ ! -f /etc/binfmt.d/qemu-aarch64.conf ]; then
  echo "qemu-aarch64 binfmt.d config missing; install qemu-user-static" >&2
  exit 1
fi

HELPER=/usr/local/sbin/apu-refresh-arm-binfmt
cp "$(dirname "$0")/refresh-arm-binfmt.sh" "$HELPER"
chmod 0755 "$HELPER"

cat > /etc/systemd/system/apu-arm-binfmt.service <<'EOF'
[Unit]
Description=Verify the patched ARM64 QEMU binfmt handler
After=systemd-binfmt.service
Wants=systemd-binfmt.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/apu-refresh-arm-binfmt
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable apu-arm-binfmt.service
systemctl restart apu-arm-binfmt.service
systemctl --no-pager --full status apu-arm-binfmt.service | head -12
