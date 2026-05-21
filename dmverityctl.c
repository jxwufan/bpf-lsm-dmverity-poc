// SPDX-License-Identifier: GPL-2.0
/*
 * dmverityctl: load BPF LSM dm-verity denylist + manage maps.
 *
 *   ./dmverityctl load                 # load 3 programs (cache, evict,
 *                                       enforce), pin links + maps
 *   ./dmverityctl block <hex-digest>   # add hash to denylist
 *   ./dmverityctl unblock <hex-digest> # remove from denylist
 *   ./dmverityctl list                 # print blocked hashes
 *   ./dmverityctl cache                # debug: print kernel's dev_to_hash
 *   ./dmverityctl stats                # counters
 *   ./dmverityctl unload               # detach + unpin
 *
 * Note: dev_to_hash is populated by the kernel-side cache program when
 * dm-verity's bdev_setintegrity hook fires at preresume.  If a verity
 * device was activated before this loader started, close+reopen it to
 * re-trigger setintegrity.  Userspace only manages the hash denylist.
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "dmverity_allowlist.skel.h"

#define DIGEST_MAX 64

/* Match kernel dev_t encoding (include/linux/kdev_t.h) — used only by
 * `cache` debug command to print dev_t entries the kernel stored. */
#define MINORBITS 20
#define MINORMASK ((1U << MINORBITS) - 1)
#define MAJOR(dev) ((unsigned int)((dev) >> MINORBITS))
#define MINOR(dev) ((unsigned int)((dev) & MINORMASK))

#define PINDIR "/sys/fs/bpf/dmverity_denylist"
#define PIN_LINK_CACHE       PINDIR "/link_cache"
#define PIN_LINK_EVICT       PINDIR "/link_evict"
#define PIN_LINK_ENFORCE     PINDIR "/link_enforce"
#define PIN_DEV_TO_HASH      PINDIR "/dev_to_hash"
#define PIN_BLOCKED          PINDIR "/blocked_hashes"
#define PIN_COUNTERS         PINDIR "/counters"

static int hex2digest(const char *hex, uint8_t *digest, size_t maxlen)
{
	size_t hexlen = strlen(hex);
	size_t bytes = hexlen / 2;
	size_t i;

	if (hexlen % 2 || bytes > maxlen)
		return -1;
	memset(digest, 0, maxlen);
	for (i = 0; i < bytes; i++) {
		char h = hex[2 * i], l = hex[2 * i + 1];
		int hi, lo;
		if (!isxdigit(h) || !isxdigit(l))
			return -1;
		hi = (h <= '9') ? h - '0' : (tolower(h) - 'a' + 10);
		lo = (l <= '9') ? l - '0' : (tolower(l) - 'a' + 10);
		digest[i] = (hi << 4) | lo;
	}
	return (int)bytes;
}

static void digest2hex(const uint8_t *digest, size_t len, char *hex)
{
	static const char *hc = "0123456789abcdef";
	size_t i;
	for (i = 0; i < len; i++) {
		hex[2 * i] = hc[(digest[i] >> 4) & 0xF];
		hex[2 * i + 1] = hc[digest[i] & 0xF];
	}
	hex[2 * len] = '\0';
}

static int open_map(const char *path)
{
	int fd = bpf_obj_get(path);
	if (fd < 0)
		fprintf(stderr, "open %s: %s (loaded?)\n", path, strerror(errno));
	return fd;
}

static int cmd_load(void)
{
	struct dmverity_allowlist *skel;
	int err;

	mkdir("/sys/fs/bpf", 0700);
	mkdir(PINDIR, 0700);

	skel = dmverity_allowlist__open();
	if (!skel) {
		fprintf(stderr, "open skeleton: %s\n", strerror(errno));
		return 1;
	}
	bpf_map__set_pin_path(skel->maps.dev_to_hash, PIN_DEV_TO_HASH);
	bpf_map__set_pin_path(skel->maps.blocked_hashes, PIN_BLOCKED);
	bpf_map__set_pin_path(skel->maps.counters, PIN_COUNTERS);

	err = dmverity_allowlist__load(skel);
	if (err) {
		fprintf(stderr, "load: %s\n", strerror(-err));
		dmverity_allowlist__destroy(skel);
		return 1;
	}
	err = dmverity_allowlist__attach(skel);
	if (err) {
		fprintf(stderr, "attach: %s\n", strerror(-err));
		dmverity_allowlist__destroy(skel);
		return 1;
	}
	if (bpf_link__pin(skel->links.cache_dmverity_hash, PIN_LINK_CACHE) &&
	    errno != EEXIST) {
		fprintf(stderr, "pin link_cache: %s\n", strerror(errno));
	}
	if (bpf_link__pin(skel->links.evict_dmverity_hash, PIN_LINK_EVICT) &&
	    errno != EEXIST) {
		fprintf(stderr, "pin link_evict: %s\n", strerror(errno));
	}
	if (bpf_link__pin(skel->links.enforce_dmverity_denylist,
			  PIN_LINK_ENFORCE) && errno != EEXIST) {
		fprintf(stderr, "pin link_enforce: %s\n", strerror(errno));
	}
	printf("loaded.\n");
	dmverity_allowlist__destroy(skel);
	return 0;
}

static int cmd_block_or_unblock(const char *hex, int block)
{
	uint8_t digest[DIGEST_MAX];
	int fd, ret;

	if (hex2digest(hex, digest, DIGEST_MAX) <= 0) {
		fprintf(stderr, "bad hex digest\n");
		return 1;
	}
	fd = open_map(PIN_BLOCKED);
	if (fd < 0)
		return 1;
	if (block) {
		uint8_t one = 1;
		ret = bpf_map_update_elem(fd, digest, &one, BPF_ANY);
	} else {
		ret = bpf_map_delete_elem(fd, digest);
	}
	close(fd);
	if (ret) {
		fprintf(stderr, "map op: %s\n", strerror(errno));
		return 1;
	}
	printf("%s %s\n", block ? "blocked" : "unblocked", hex);
	return 0;
}

static int cmd_list_blocked(void)
{
	uint8_t key[DIGEST_MAX] = {}, next_key[DIGEST_MAX];
	uint8_t val;
	char hex[DIGEST_MAX * 2 + 1];
	int fd, count = 0;

	fd = open_map(PIN_BLOCKED);
	if (fd < 0)
		return 1;
	while (bpf_map_get_next_key(fd, count ? key : NULL, next_key) == 0) {
		memcpy(key, next_key, DIGEST_MAX);
		if (bpf_map_lookup_elem(fd, key, &val) == 0 && val) {
			digest2hex(key, 32, hex);  /* sha256-style 32 bytes */
			printf("%s\n", hex);
		}
		count++;
	}
	close(fd);
	return 0;
}

static int cmd_cache(void)
{
	uint32_t key = 0, next_key;
	uint8_t digest[DIGEST_MAX];
	char hex[DIGEST_MAX * 2 + 1];
	int fd, count = 0;

	fd = open_map(PIN_DEV_TO_HASH);
	if (fd < 0)
		return 1;
	while (bpf_map_get_next_key(fd, count ? &key : NULL, &next_key) == 0) {
		key = next_key;
		if (bpf_map_lookup_elem(fd, &key, digest) == 0) {
			digest2hex(digest, 32, hex);
			printf("dev=%u:%u hash=%s\n",
			       MAJOR(key), MINOR(key), hex);
		}
		count++;
	}
	close(fd);
	return 0;
}

static int cmd_stats(void)
{
	const char *names[] = { "setint_cached",
				"bdev_evicted",
				"exec_total_dmverity",
				"exec_allow",
				"exec_blocked",
				"exec_passthrough" };
	uint64_t val;
	uint32_t key;
	int fd;

	fd = open_map(PIN_COUNTERS);
	if (fd < 0)
		return 1;
	for (key = 0; key < 6; key++) {
		if (bpf_map_lookup_elem(fd, &key, &val) == 0)
			printf("%-25s %llu\n", names[key],
			       (unsigned long long)val);
	}
	close(fd);
	return 0;
}

static int cmd_unload(void)
{
	unlink(PIN_LINK_CACHE);
	unlink(PIN_LINK_EVICT);
	unlink(PIN_LINK_ENFORCE);
	unlink(PIN_DEV_TO_HASH);
	unlink(PIN_BLOCKED);
	unlink(PIN_COUNTERS);
	rmdir(PINDIR);
	printf("unloaded\n");
	return 0;
}

int main(int argc, char **argv)
{
	if (argc < 2)
		goto usage;

	if (!strcmp(argv[1], "load"))      return cmd_load();
	if (!strcmp(argv[1], "block") && argc == 3)
		return cmd_block_or_unblock(argv[2], 1);
	if (!strcmp(argv[1], "unblock") && argc == 3)
		return cmd_block_or_unblock(argv[2], 0);
	if (!strcmp(argv[1], "list"))      return cmd_list_blocked();
	if (!strcmp(argv[1], "cache"))     return cmd_cache();
	if (!strcmp(argv[1], "stats"))     return cmd_stats();
	if (!strcmp(argv[1], "unload"))    return cmd_unload();

usage:
	fprintf(stderr,
		"usage:\n"
		"  %s load                       load + attach + pin\n"
		"  %s block <hex-digest>         add hash to denylist (deny execve)\n"
		"  %s unblock <hex-digest>       remove from denylist\n"
		"  %s list                       print denylist\n"
		"  %s cache                      debug: print kernel's dev_to_hash\n"
		"  %s stats                      counters\n"
		"  %s unload                     detach + cleanup\n",
		argv[0], argv[0], argv[0], argv[0], argv[0], argv[0],
		argv[0]);
	return 1;
}
