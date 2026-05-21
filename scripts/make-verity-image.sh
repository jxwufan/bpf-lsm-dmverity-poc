#!/usr/bin/env bash
# Create a small dm-verity-backed ext4 image with a test binary inside it.
#
# Produces three files in $OUT_DIR:
#   data.img   - read-only ext4 filesystem, contents = a hello binary
#   hash.img   - dm-verity hash tree for data.img
#   roothash   - the dm-verity root hash (hex), one line
#
# Run on the host or inside the VM. Needs root for losetup + ext4 mkfs.

set -euo pipefail

OUT_DIR="${OUT_DIR:-/var/lib/verity-demo}"
DATA_SIZE_MB="${DATA_SIZE_MB:-8}"
BINARY_SRC="${BINARY_SRC:-}"   # optional: path to a binary to drop in. If empty, a tiny C hello-world is compiled.

if [ "$(id -u)" -ne 0 ]; then
    echo "must run as root (losetup + mkfs)" >&2
    exit 1
fi

mkdir -p "$OUT_DIR"

DATA="$OUT_DIR/data.img"
HASH="$OUT_DIR/hash.img"
ROOTHASH_FILE="$OUT_DIR/roothash"

# 1. Make a blank file, format ext4.
echo "[+] creating $DATA (${DATA_SIZE_MB} MiB ext4)"
rm -f "$DATA"
truncate -s "${DATA_SIZE_MB}M" "$DATA"
mkfs.ext4 -q -F -L verity-demo "$DATA"

# 2. Mount, drop a test binary in, unmount.
MNT="$(mktemp -d)"
trap 'umount "$MNT" 2>/dev/null || true; rmdir "$MNT" 2>/dev/null || true' EXIT
mount -o loop "$DATA" "$MNT"

if [ -n "$BINARY_SRC" ] && [ -x "$BINARY_SRC" ]; then
    echo "[+] copying $BINARY_SRC into verity image"
    cp "$BINARY_SRC" "$MNT/hello"
else
    echo "[+] compiling hello.c into verity image"
    cat > /tmp/.verity-hello.c <<'EOF'
#include <stdio.h>
int main(void) { puts("hello from verity"); return 0; }
EOF
    cc -static -O2 /tmp/.verity-hello.c -o "$MNT/hello"
    rm -f /tmp/.verity-hello.c
fi
chmod 0755 "$MNT/hello"
sync

umount "$MNT"
rmdir "$MNT"
trap - EXIT

# 3. Generate the verity hash tree.
echo "[+] generating verity hash tree at $HASH"
rm -f "$HASH"
ROOTHASH="$(veritysetup format "$DATA" "$HASH" | awk '/Root hash/ {print $NF}')"

if [ -z "$ROOTHASH" ]; then
    echo "veritysetup format produced no root hash" >&2
    exit 1
fi

echo "$ROOTHASH" > "$ROOTHASH_FILE"

cat <<EOF

verity image ready:
  data:     $DATA
  hash:     $HASH
  roothash: $ROOTHASH

open with:
  veritysetup open $DATA verity-demo $HASH $ROOTHASH
  mount -o ro /dev/mapper/verity-demo /mnt
EOF
