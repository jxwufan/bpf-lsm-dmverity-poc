// SPDX-License-Identifier: GPL-2.0
/*
 * Phase 2: BPF LSM dm-verity root-hash denylist (IPE-style, no kernel
 * patch).
 *
 * Three programs sharing two maps:
 *
 *   1. lsm/bdev_setintegrity  (push-mode cache, IPE-equivalent)
 *      - dm-verity preresume passes us (bdev, LSM_INT_DMVERITY_ROOTHASH,
 *        struct dm_verity_digest *)
 *      - We copy digest bytes into dev_to_hash[bdev->bd_dev]
 *
 *   2. lsm/bdev_free_security  (lifecycle cleanup)
 *      - When the block_device is being freed, evict its entry from
 *        dev_to_hash so a future dev_t reuse doesn't inherit the stale
 *        digest binding.  IPE solves this via per-bdev LSM blob; BPF LSM
 *        has no per-bdev storage so we do it manually.
 *
 *   3. lsm/bprm_check_security  (enforcement)
 *      - execve: file -> i_sb -> s_bdev -> bd_dev
 *      - dev_to_hash[bd_dev] -> digest
 *      - blocked_hashes[digest] present -> -EPERM
 *      - Otherwise (not on tracked dm-verity, or not on denylist) -> allow
 *
 * No new kernel kfuncs needed.  `bdev_setintegrity` / `bdev_free_security`
 * are already LSM hooks; `struct dm_verity_digest` is in
 * include/linux/security.h (public) so BTF has it.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define DIGEST_MAX 64  /* covers sha256 (32), sha512 (64) */

#define LSM_INT_DMVERITY_SIG_VALID 0
#define LSM_INT_DMVERITY_ROOTHASH  1

/* Cache: dm-verity dev -> root digest (filled by setintegrity hook,
 * evicted by bdev_free_security hook, read by bprm_check hook). */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, __u32);            /* dev_t */
	__type(value, __u8[DIGEST_MAX]);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} dev_to_hash SEC(".maps");

/* Denylist: which root hashes are forbidden to execute. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, __u8[DIGEST_MAX]);
	__type(value, __u8);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} blocked_hashes SEC(".maps");

/* Counters. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 6);
	__type(key, __u32);
	__type(value, __u64);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} counters SEC(".maps");

#define CNT_SETINT_CACHED     0
#define CNT_BDEV_EVICTED      1
#define CNT_EXEC_TOTAL_DMV    2
#define CNT_EXEC_ALLOW        3
#define CNT_EXEC_BLOCKED      4
#define CNT_EXEC_PASSTHROUGH  5

static __always_inline void bump(__u32 idx)
{
	__u64 *c = bpf_map_lookup_elem(&counters, &idx);
	if (c)
		__sync_fetch_and_add(c, 1);
}

/* ---- Program 1: cache digest at dm-verity preresume ---- */
SEC("lsm/bdev_setintegrity")
int BPF_PROG(cache_dmverity_hash, struct block_device *bdev,
	     enum lsm_integrity_type type, const void *value, size_t size)
{
	const struct dm_verity_digest *vd;
	__u8 digest[DIGEST_MAX] = {};
	__u32 dl;
	__u32 bd_dev;

	if (type != LSM_INT_DMVERITY_ROOTHASH)
		return 0;
	if (!value || !size)
		return 0;

	vd = (const struct dm_verity_digest *)value;
	/* Mask first so the verifier sees a bounded u32 across the call. */
	dl = (__u32)BPF_CORE_READ(vd, digest_len) & 0x7F;
	if (dl == 0 || dl > DIGEST_MAX)
		return 0;

	bpf_probe_read_kernel(digest, dl, BPF_CORE_READ(vd, digest));

	bd_dev = BPF_CORE_READ(bdev, bd_dev);
	bpf_map_update_elem(&dev_to_hash, &bd_dev, digest, BPF_ANY);
	bump(CNT_SETINT_CACHED);

	return 0;
}

/* ---- Program 2: evict cache entry when bdev is being freed ---- */
SEC("lsm/bdev_free_security")
int BPF_PROG(evict_dmverity_hash, struct block_device *bdev)
{
	__u32 bd_dev = BPF_CORE_READ(bdev, bd_dev);

	if (bpf_map_delete_elem(&dev_to_hash, &bd_dev) == 0)
		bump(CNT_BDEV_EVICTED);

	return 0;
}

/* ---- Program 3: enforce denylist on execve ---- */
SEC("lsm/bprm_check_security")
int BPF_PROG(enforce_dmverity_denylist, struct linux_binprm *bprm)
{
	struct file *file;
	struct super_block *sb;
	struct block_device *bdev;
	__u32 bd_dev;
	__u8 *digest;
	__u8 *blocked;

	file = bprm->file;
	if (!file)
		return 0;

	sb = BPF_CORE_READ(file, f_inode, i_sb);
	if (!sb)
		return 0;

	bdev = BPF_CORE_READ(sb, s_bdev);
	if (!bdev) {
		bump(CNT_EXEC_PASSTHROUGH);
		return 0;
	}

	bd_dev = BPF_CORE_READ(bdev, bd_dev);
	digest = bpf_map_lookup_elem(&dev_to_hash, &bd_dev);
	if (!digest) {
		/* Not a tracked dm-verity device -> pass-through. */
		bump(CNT_EXEC_PASSTHROUGH);
		return 0;
	}

	bump(CNT_EXEC_TOTAL_DMV);

	blocked = bpf_map_lookup_elem(&blocked_hashes, digest);
	if (blocked && *blocked) {
		bump(CNT_EXEC_BLOCKED);
		return -1; /* -EPERM */
	}

	bump(CNT_EXEC_ALLOW);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
