// SPDX-License-Identifier: GPL-2.0
/*
 * Phase 1 observe: hook lsm/bdev_setintegrity, print the dm-verity root
 * digest that gets passed in at preresume time.
 *
 * Purpose: confirm we correctly destructure `struct dm_verity_digest`
 * from the LSM hook arg before any enforcement code runs.
 *
 * No maps, no enforcement. Trigger by closing + reopening a verity
 * device:
 *   sudo umount /mnt/verity-runc
 *   sudo veritysetup close verity-runc
 *   sudo veritysetup open <data.img> verity-runc <hash.img> <root-hash>
 *   sudo mount -o ro /dev/mapper/verity-runc /mnt/verity-runc
 * Then read trace_pipe.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

/* From include/linux/security.h, public. */
#define LSM_INT_DMVERITY_SIG_VALID  0
#define LSM_INT_DMVERITY_ROOTHASH   1

/* dev_t encoding (mirrors include/linux/kdev_t.h). */
#define MINORBITS 20
#define MINORMASK ((1U << MINORBITS) - 1)
#define MAJOR(dev) ((unsigned int)((dev) >> MINORBITS))
#define MINOR(dev) ((unsigned int)((dev) & MINORMASK))

SEC("lsm/bdev_setintegrity")
int BPF_PROG(observe_bdev_setintegrity, struct block_device *bdev,
	     enum lsm_integrity_type type, const void *value, size_t size)
{
	const struct dm_verity_digest *vd;
	u8 digest_buf[8] = {};
	u32 digest_len;
	dev_t bd_dev;

	if (type != LSM_INT_DMVERITY_ROOTHASH)
		return 0;

	if (!value || !size)
		return 0;

	vd = (const struct dm_verity_digest *)value;
	digest_len = BPF_CORE_READ(vd, digest_len);

	bpf_probe_read_kernel(digest_buf, sizeof(digest_buf),
			      BPF_CORE_READ(vd, digest));

	bd_dev = BPF_CORE_READ(bdev, bd_dev);

	bpf_printk("dmv-obs: dev=%d:%d dlen=%d %02x%02x%02x%02x%02x%02x%02x%02x...",
		   MAJOR(bd_dev), MINOR(bd_dev), digest_len,
		   digest_buf[0], digest_buf[1], digest_buf[2], digest_buf[3],
		   digest_buf[4], digest_buf[5], digest_buf[6], digest_buf[7]);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
