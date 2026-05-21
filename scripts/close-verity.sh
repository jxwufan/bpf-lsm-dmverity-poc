#!/usr/bin/env bash
# Unmount + close the verity demo device. Triggers bdev_free_security so
# the BPF cache evicts the entry.

set -euo pipefail

DM_NAME="${DM_NAME:-verity-demo}"
MOUNT_POINT="${MOUNT_POINT:-/mnt/verity-demo}"

if [ "$(id -u)" -ne 0 ]; then
    echo "must run as root" >&2
    exit 1
fi

umount "$MOUNT_POINT" 2>/dev/null || true
if [ -e "/dev/mapper/$DM_NAME" ]; then
    veritysetup close "$DM_NAME"
    echo "[+] closed /dev/mapper/$DM_NAME"
fi
