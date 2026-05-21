# BPF LSM dm-verity denylist — a demo

> AI-generated PoC, mostly written by Claude. Not reviewed by anyone
> but the person hitting accept. Treat it as a sketch.

Can IPE's `dmverity_roothash=<H>` deny rule be done from BPF LSM alone,
no kernel patches? Roughly yes.

Three hooks, two maps:

- `bdev_setintegrity` — kernel writes the verity digest into
  `dev_to_hash`, keyed by `dev_t`.
- `bdev_free_security` — evicts the entry when the bdev goes away.
- `bprm_check_security` — looks the digest up on execve, returns
  `-EPERM` if it's in `blocked_hashes` (userspace deny list).

`dev_to_hash` stands in for IPE's per-bdev LSM blob. It's only safe
because the paired free hook evicts on close.

## Run it

```bash
./vm/bringup.sh
scp -P 2222 -i ~/.cache/bpf-dmverity-vm/id_demo -r . \
    demo@127.0.0.1:bpf-lsm-dmverity-poc
ssh -p 2222 -i ~/.cache/bpf-dmverity-vm/id_demo demo@127.0.0.1 \
    'cd bpf-lsm-dmverity-poc && sudo ./scripts/e2e.sh'
```

Or on a host with kernel ≥6.12, `CONFIG_BPF_LSM=y`, and
`lsm=...,ipe,bpf` (both — `ipe` allocates the per-bdev blob, without
it `security_bdev_free()` early-returns and eviction is skipped):

```bash
make && sudo ./scripts/e2e.sh
```

## Limitations

- `dev_t` is a stand-in, not an identity. Reuse after free would
  produce wrong bindings without the eviction hook.
- Needs another LSM (in practice `ipe`) to allocate the bdev blob, or
  `security_bdev_free()` skips the chain.
- Pre-existing verity devices are invisible until reopened.
- Overlayfs (runc 1.2+) passes through — `s_bdev` is NULL on overlay.
- `bprm_check_security` only; `mmap`/`mprotect` bypass it.
- `blocked_hashes` is writable by anything with `CAP_BPF`. No signing.
- dm-verity only.
- Deny-list, not allow-list.

Not a replacement for IPE.
