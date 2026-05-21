# BPF LSM dm-verity allowlist PoC

LLC      ?= llc
CLANG    ?= clang
BPFTOOL  ?= bpftool

VMLINUX_BTF ?= /sys/kernel/btf/vmlinux

# Adjust if libbpf headers / pkg-config aren't found by default
CFLAGS   = -O2 -Wall $(shell pkg-config --cflags libbpf 2>/dev/null)
LDFLAGS  = $(shell pkg-config --libs libbpf 2>/dev/null)
ifeq ($(LDFLAGS),)
LDFLAGS  = -lbpf -lelf -lz
endif

BPF_CFLAGS = -g -O2 -Wall -target bpf \
             -D__TARGET_ARCH_x86 \
             -I. -I/usr/include/bpf

all: observe_loader dmverityctl

vmlinux.h:
	$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c > vmlinux.h

# Phase 1: observe-only
dmverity_observe.bpf.o: dmverity_observe.bpf.c vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

dmverity_observe.skel.h: dmverity_observe.bpf.o
	$(BPFTOOL) gen skeleton $< name dmverity_observe > $@

observe_loader: observe_loader.c dmverity_observe.skel.h
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

# Phase 2: enforce
dmverity_allowlist.bpf.o: dmverity_allowlist.bpf.c vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

dmverity_allowlist.skel.h: dmverity_allowlist.bpf.o
	$(BPFTOOL) gen skeleton $< name dmverity_allowlist > $@

dmverityctl: dmverityctl.c dmverity_allowlist.skel.h
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

clean:
	rm -f observe_loader dmverityctl
	rm -f dmverity_observe.bpf.o dmverity_observe.skel.h
	rm -f dmverity_allowlist.bpf.o dmverity_allowlist.skel.h

distclean: clean
	rm -f vmlinux.h

.PHONY: all clean distclean
