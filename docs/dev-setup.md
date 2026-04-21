# Developer Setup

System-package prerequisites per distro. `make tools` installs the Go tools on top of these.

## Required (all platforms)

- **Go 1.24 or newer** — agent + server language.
- **Docker** (or Podman with docker-compose shim) — dev stack via `make compose-up`.
- **git** — DCO enforcement relies on commit trailers.

## Required for Phase 1+ (agent / eBPF)

- **clang 16 or newer** — eBPF bytecode compilation (CO-RE requires modern clang).
- **llvm** — linker for clang.
- **Kernel with BTF** — check `/sys/kernel/btf/vmlinux` exists. Linux 5.10+ distros generally ship this.
- **Development headers** — `linux-headers-$(uname -r)` on Debian/Ubuntu, `kernel-devel` on RHEL/Fedora.

## Ubuntu 22.04 / 24.04

```bash
# Go (if your distro's version is old, use the official tarball instead)
sudo apt-get install -y golang-1.24 build-essential git

# Docker
sudo apt-get install -y docker.io docker-compose-plugin
sudo usermod -aG docker "$USER"  # log out/in after this

# eBPF toolchain (Phase 1+)
sudo apt-get install -y clang llvm libbpf-dev linux-headers-$(uname -r)
```

## Fedora / RHEL 9 / Rocky 9

```bash
sudo dnf install -y golang git clang llvm libbpf-devel kernel-devel
sudo dnf install -y docker docker-compose-plugin   # or podman + podman-compose
```

Note: RHEL 9 ships Go 1.21 at time of writing. If your distro lags, install Go from the [official release tarball](https://go.dev/dl/) and ensure `go version` reports 1.24+.

## Debian 12

```bash
sudo apt-get install -y golang-1.24 clang llvm libbpf-dev linux-headers-$(uname -r)
sudo apt-get install -y docker.io docker-compose-plugin
```

## Verification

```bash
go version            # go1.24+ expected
clang --version       # 16+ expected (only required Phase 1+)
docker --version
ls /sys/kernel/btf/vmlinux   # must exist (Phase 1+)
```

Then:

```bash
make tools
make which-tools      # should show all tools installed
make build            # compiles agent + server skeleton
```

## Troubleshooting

**`cannot find package 'github.com/bufbuild/buf/cmd/buf'` during `make tools`**

Run `go env GOPROXY` — it should point to `https://proxy.golang.org,direct`. If your environment restricts module downloads, set `GOPROXY` appropriately or use a private proxy.

**eBPF compile failures (Phase 1+)**

CO-RE requires both clang 16+ and `/sys/kernel/btf/vmlinux` on the build host. Check both before filing an issue.

**`make verify-gen` fails after editing a `.proto` file**

Run `make gen` and commit the regenerated files. CI treats generated-code drift as an error.
