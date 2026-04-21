#!/usr/bin/env bash
# Install developer tools at pinned versions into $GOBIN.
#
# Pins live in this script (single source of truth). `tools/tools.go` exists only
# to make `go mod` aware of the module paths for IDEs; it is not used to resolve
# tool versions, which keeps transitive upgrades in the linter graph from forcing
# a Go toolchain bump on contributors.
#
# Prerequisites (not installed by this script):
#   - Go 1.24+
#   - clang 16+ (for eBPF compilation, Phase 1+)
#   - Docker / Podman (for compose dev stack)
#
# See docs/dev-setup.md for distro-specific system packages.

set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v go >/dev/null 2>&1; then
    echo "error: go not found on PATH" >&2
    exit 1
fi

GOBIN="$(go env GOBIN)"
if [[ -z "$GOBIN" ]]; then
    GOBIN="$(go env GOPATH)/bin"
fi
mkdir -p "$GOBIN"
export GOBIN

# ---------------------------------------------------------------------------
# Pinned tool versions. Bump these deliberately; CI re-runs the full build
# after any change here. Compatible with Go 1.24.
# ---------------------------------------------------------------------------
readonly BUF_VERSION=v1.47.2
readonly TEMPL_VERSION=v0.3.819
readonly PROTOC_GEN_GO_VERSION=v1.36.5
readonly PROTOC_GEN_GO_GRPC_VERSION=v1.5.1
readonly GOLANGCI_LINT_VERSION=v1.63.4
readonly GOVULNCHECK_VERSION=v1.1.4
readonly GOTESTSUM_VERSION=v1.12.0

declare -a TOOLS=(
    "github.com/bufbuild/buf/cmd/buf@${BUF_VERSION}"
    "github.com/a-h/templ/cmd/templ@${TEMPL_VERSION}"
    "google.golang.org/protobuf/cmd/protoc-gen-go@${PROTOC_GEN_GO_VERSION}"
    "google.golang.org/grpc/cmd/protoc-gen-go-grpc@${PROTOC_GEN_GO_GRPC_VERSION}"
    "github.com/golangci/golangci-lint/cmd/golangci-lint@${GOLANGCI_LINT_VERSION}"
    "golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK_VERSION}"
    "gotest.tools/gotestsum@${GOTESTSUM_VERSION}"
)

echo "▶ installing tools into $GOBIN"
for pkg in "${TOOLS[@]}"; do
    echo "  • $pkg"
    go install "$pkg"
done

echo "▶ verifying install"
for t in buf templ protoc-gen-go protoc-gen-go-grpc golangci-lint govulncheck gotestsum; do
    if command -v "$t" >/dev/null 2>&1; then
        printf "  ✓ %-24s %s\n" "$t" "$(command -v "$t")"
    else
        printf "  ✗ %-24s NOT INSTALLED\n" "$t"
        exit 1
    fi
done
