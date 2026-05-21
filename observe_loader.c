// SPDX-License-Identifier: GPL-2.0
/*
 * Minimal loader for the phase 1 observe-only BPF LSM program.
 *
 *   ./observe_loader              # load, attach, then sleep until Ctrl-C
 *
 * View trace output in another terminal:
 *   sudo cat /sys/kernel/debug/tracing/trace_pipe
 */

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "dmverity_observe.skel.h"

static volatile sig_atomic_t stop;
static void sig(int s) { (void)s; stop = 1; }

int main(void)
{
	struct dmverity_observe *skel;
	int err;

	signal(SIGINT, sig);
	signal(SIGTERM, sig);

	skel = dmverity_observe__open_and_load();
	if (!skel) {
		fprintf(stderr, "open_and_load: %s\n", strerror(errno));
		return 1;
	}

	err = dmverity_observe__attach(skel);
	if (err) {
		fprintf(stderr, "attach: %s\n", strerror(-err));
		dmverity_observe__destroy(skel);
		return 1;
	}

	fprintf(stderr,
		"attached. trigger setintegrity by closing+reopening a "
		"dm-verity device:\n"
		"  sudo umount /mnt/verity-runc\n"
		"  sudo veritysetup close verity-runc\n"
		"  sudo veritysetup open <data.img> verity-runc <hash.img> <root-hash>\n"
		"then watch:\n"
		"  sudo cat /sys/kernel/debug/tracing/trace_pipe\n"
		"Ctrl-C to detach.\n");

	while (!stop)
		pause();

	dmverity_observe__destroy(skel);
	fprintf(stderr, "detached.\n");
	return 0;
}
