#!/usr/bin/env bash
# Bring up a single-VM qemu setup for the demo. Downloads an Ubuntu
# cloud image whose stock kernel includes the bdev_setintegrity hook
# (>= 6.12, so Ubuntu 25.04 "Plucky" or newer), provisions it via
# cloud-init, and forwards ssh to 127.0.0.1:2222.
#
# An ssh key is generated under $VM_DIR/id_demo on first run and
# injected into the guest via cloud-init.
#
# After bringup:
#   scp -P 2222 -i $VM_DIR/id_demo -r ../bpf-lsm-dmverity-poc demo@127.0.0.1:
#   ssh -p 2222 -i $VM_DIR/id_demo demo@127.0.0.1
#   cd bpf-lsm-dmverity-poc && sudo ./scripts/e2e.sh

set -euo pipefail

VM_DIR="${VM_DIR:-$HOME/.cache/bpf-dmverity-vm}"
UBUNTU_RELEASE="${UBUNTU_RELEASE:-resolute}"   # 26.04 LTS - kernel >= 6.17
UBUNTU_IMG_URL="${UBUNTU_IMG_URL:-https://cloud-images.ubuntu.com/${UBUNTU_RELEASE}/current/${UBUNTU_RELEASE}-server-cloudimg-amd64.img}"
DETACH="${DETACH:-0}"

BASE_IMG="$VM_DIR/base.qcow2"
DISK="$VM_DIR/disk.qcow2"
SEED="$VM_DIR/seed.iso"
PIDFILE="$VM_DIR/qemu.pid"
SERIAL="$VM_DIR/serial.log"
SSH_KEY="$VM_DIR/id_demo"

mkdir -p "$VM_DIR"

# Generate an SSH key for the demo user if one doesn't exist yet.
if [ ! -f "$SSH_KEY" ]; then
    echo "[+] generating SSH key at $SSH_KEY"
    ssh-keygen -t ed25519 -N "" -f "$SSH_KEY" -C "bpf-dmverity-demo" >/dev/null
fi
PUBKEY="$(cat "${SSH_KEY}.pub")"

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing: $1" >&2; exit 1; }; }
need qemu-system-x86_64
need qemu-img

if [ ! -f "$BASE_IMG" ]; then
    echo "[+] downloading $UBUNTU_IMG_URL"
    curl -L --fail -o "$BASE_IMG.tmp" "$UBUNTU_IMG_URL"
    mv "$BASE_IMG.tmp" "$BASE_IMG"
fi

if [ ! -f "$DISK" ]; then
    echo "[+] creating overlay disk"
    qemu-img create -f qcow2 -F qcow2 -b "$BASE_IMG" "$DISK" 20G
fi

if [ ! -f "$SEED" ]; then
    echo "[+] building cloud-init seed"
    UD_RENDERED="$VM_DIR/user-data"
    sed "s|__SSH_PUBKEY__|$PUBKEY|" "$(dirname "$0")/cloud-init/user-data" > "$UD_RENDERED"
    if command -v cloud-localds >/dev/null 2>&1; then
        cloud-localds "$SEED" "$UD_RENDERED" \
            "$(dirname "$0")/cloud-init/meta-data"
    elif command -v genisoimage >/dev/null 2>&1; then
        TMP="$(mktemp -d)"
        cp "$UD_RENDERED" "$TMP/user-data"
        cp "$(dirname "$0")/cloud-init/meta-data" "$TMP/meta-data"
        genisoimage -output "$SEED" -volid cidata -joliet -rock \
            "$TMP/user-data" "$TMP/meta-data"
        rm -rf "$TMP"
    else
        echo "neither cloud-localds nor genisoimage found" >&2
        exit 1
    fi
fi

SSH_PORT="${SSH_PORT:-2222}"

QEMU_ARGS=(
    -name bpf-dmverity-demo
    -enable-kvm
    -m 4G -smp 4
    -cpu host
    -drive file="$DISK",if=virtio,format=qcow2
    -drive file="$SEED",if=virtio,format=raw,readonly=on
    -netdev user,id=n0,hostfwd=tcp::"$SSH_PORT"-:22
    -device virtio-net-pci,netdev=n0
)

if [ "$DETACH" = "1" ]; then
    echo "[+] launching VM in background; serial log at $SERIAL"
    QEMU_LOG="$VM_DIR/qemu.stderr"
    nohup qemu-system-x86_64 "${QEMU_ARGS[@]}" \
        -display none \
        -serial file:"$SERIAL" \
        -pidfile "$PIDFILE" \
        </dev/null >"$QEMU_LOG" 2>&1 &
    QPID=$!
    disown $QPID 2>/dev/null || true
    sleep 2
    if ! kill -0 "$QPID" 2>/dev/null; then
        echo "qemu failed to start:" >&2
        cat "$QEMU_LOG" >&2
        exit 1
    fi
    echo "    pid=$QPID  ssh: ssh -p $SSH_PORT demo@127.0.0.1"
else
    echo "[+] launching VM (Ctrl-A X to quit)"
    echo "    ssh -p $SSH_PORT demo@127.0.0.1"
    exec qemu-system-x86_64 "${QEMU_ARGS[@]}" -nographic
fi
