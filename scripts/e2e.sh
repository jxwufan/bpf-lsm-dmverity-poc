#!/usr/bin/env bash
# End-to-end demo: build, attach, open verity, expect allow, block hash,
# expect EPERM, unblock, expect allow again, then close.
#
# Run as root inside a VM whose kernel:
#   - has bdev_setintegrity / bdev_free_security LSM hooks (>= v6.12)
#   - boots with `lsm=...,bpf` (bpf placed *after* selinux on selinux distros)

set -euo pipefail

REPO_DIR="${REPO_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"
OUT_DIR="${OUT_DIR:-/var/lib/verity-demo}"
DM_NAME="${DM_NAME:-verity-demo}"
MOUNT_POINT="${MOUNT_POINT:-/mnt/verity-demo}"

if [ "$(id -u)" -ne 0 ]; then
    echo "must run as root" >&2
    exit 1
fi

say() { printf '\n=== %s ===\n' "$*"; }

# Sanity: required kernel surface.
if ! grep -q bpf /sys/kernel/security/lsm 2>/dev/null; then
    echo "BPF LSM not active. Check /sys/kernel/security/lsm and the lsm= cmdline." >&2
    exit 1
fi
if ! grep -q bpf_lsm_bdev_setintegrity /proc/kallsyms 2>/dev/null; then
    echo "bpf_lsm_bdev_setintegrity not present -- kernel too old for this demo." >&2
    exit 1
fi

# 1. Build.
say "build"
make -C "$REPO_DIR"

# 2. Create the verity image if missing.
if [ ! -f "$OUT_DIR/roothash" ]; then
    say "make-verity-image"
    "$REPO_DIR/scripts/make-verity-image.sh"
fi
ROOTHASH="$(cat "$OUT_DIR/roothash")"

# 3. Attach BPF programs.
say "load BPF programs"
"$REPO_DIR/dmverityctl" load

# 4. Open verity (so the cache hook fires after load).
say "open verity device"
"$REPO_DIR/scripts/open-verity.sh"

# 5. Cache should now contain our digest.
say "kernel cache"
"$REPO_DIR/dmverityctl" cache

# 6. Baseline: empty deny list -> allow.
say "baseline exec (expect: hello from verity)"
"$MOUNT_POINT/hello"

# 7. Block the hash -> expect EPERM.
say "block roothash -> exec should fail with EPERM"
"$REPO_DIR/dmverityctl" block "$ROOTHASH"
if "$MOUNT_POINT/hello" 2>/dev/null; then
    echo "FAIL: exec succeeded while hash was blocked" >&2
    exit 1
fi
echo "exec was denied (good)."

# 8. Unblock -> expect allow.
say "unblock roothash -> exec should succeed"
"$REPO_DIR/dmverityctl" unblock "$ROOTHASH"
"$MOUNT_POINT/hello"

# 9. Stats.
say "stats"
"$REPO_DIR/dmverityctl" stats

# 10. Close verity -> eviction counter should bump.
#     bdev_free_security fires from softirq context after the close syscall
#     returns, so give it a moment to land before reading stats.
say "close verity"
"$REPO_DIR/scripts/close-verity.sh"
sleep 1
"$REPO_DIR/dmverityctl" stats

# Eviction requires some LSM (typically IPE) to allocate a per-bdev blob;
# otherwise security_bdev_free() returns early and our hook never fires.
# Report this as info, not a failure.
if ! grep -q '\bipe\b' /sys/kernel/security/lsm 2>/dev/null; then
    echo
    echo "note: 'ipe' is not in /sys/kernel/security/lsm. Without IPE (or"
    echo "another LSM allocating a bdev blob), bdev_evicted will stay 0."
    echo "Add 'ipe' to your lsm= cmdline to exercise the eviction path."
fi

say "done"
echo "to detach BPF programs: sudo $REPO_DIR/dmverityctl unload"
