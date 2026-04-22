//go:build linux

package bpf

// bpf2go generates Go wrappers and embedded bytecode from the .bpf.c sources.
// Run via `make gen` (which invokes `go generate ./...` in the agent module).
//
// The -target bpfel option produces a little-endian build. We only release for
// linux/amd64 and linux/arm64 in v1; both are little-endian.
//
// -cc clang pins the compiler; -cflags align with libbpf examples.

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel -type process_event -go-package bpf -output-dir . -output-stem process Process src/process.bpf.c -- -I./src/headers -Wall -O2 -g
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel -type file_event -go-package bpf -output-dir . -output-stem file File src/file.bpf.c -- -I./src/headers -Wall -O2 -g
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel -type net_event -go-package bpf -output-dir . -output-stem net Net src/net.bpf.c -- -I./src/headers -Wall -O2 -g
