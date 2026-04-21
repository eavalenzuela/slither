# BPF headers

`vmlinux.h` is generated from `/sys/kernel/btf/vmlinux` via `bpftool`. It is
committed so that `bpf2go` produces deterministic bytecode across machines
(otherwise `make verify-gen` would fail for every contributor whose kernel
differs from CI's).

Regenerate with:

```bash
make gen-vmlinux
```

This only needs to happen when the referenced kernel API surface changes —
not routinely. CO-RE re-resolves field offsets at load time using the target
host's BTF, so a vmlinux.h generated on one kernel runs correctly on any
other kernel ≥ the floor declared in ADR-0001 (5.10).
