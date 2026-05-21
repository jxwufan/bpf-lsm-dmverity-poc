#!/usr/bin/env bash
# Open the verity image produced by make-verity-image.sh and mount it.
# Triggers the bdev_setintegrity LSM hook, so the BPF cache fills.

set -euo pipefail

OUT_DIR="${OUT_DIR:-/var/lib/verity-demo}"
DM_NAME="${DM_NAME:-verity-demo}"
MOUNT_POINT="${MOUNT_POINT:-/mnt/verity-demo}"

if [ "$(id -u)" -ne 0 ]; then
    echo "must run as root" >&2
    exit 1
fi

DATA="$OUT_DIR/data.img"
HASH="$OUT_DIR/hash.img"
ROOTHASH_FILE="$OUT_DIR/roothash"

if [ ! -f "$ROOTHASH_FILE" ]; then
    echo "no $ROOTHASH_FILE -- run scripts/make-verity-image.sh first" >&2
    exit 1
fi

ROOTHASH="$(cat "$ROOTHASH_FILE")"

# If already open, close first so setintegrity fires again.
if [ -e "/dev/mapper/$DM_NAME" ]; then
    echo "[+] closing existing $DM_NAME"
    umount "$MOUNT_POINT" 2>/dev/null || true
    veritysetup close "$DM_NAME"
fi

echo "[+] opening verity device $DM_NAME (roothash=$ROOTHASH)"
veritysetup open "$DATA" "$DM_NAME" "$HASH" "$ROOTHASH"

mkdir -p "$MOUNT_POINT"
mount -o ro "/dev/mapper/$DM_NAME" "$MOUNT_POINT"

echo "[+] mounted /dev/mapper/$DM_NAME on $MOUNT_POINT"
echo "    roothash: $ROOTHASH"
echo "    test:     $MOUNT_POINT/hello"
