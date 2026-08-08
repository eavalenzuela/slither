#!/usr/bin/env bash
# Install developer tools at pinned versions into $GOBIN.
#
# Pins live in this script (single source of truth). `tools/tools.go` exists only
# to make `go mod` aware of the module paths for IDEs; it is not used to resolve
# tool versions, which keeps transitive upgrades in the linter graph from forcing
# a Go toolchain bump on contributors.
#
# Prerequisites (not installed by this script):
#   - Go 1.25+
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
# after any change here.
#
# Two of these are version-COUPLED to a library in a shipped module and
# cannot be bumped alone:
#
#   templ          -> github.com/a-h/templ in server/go.mod. The CLI
#                     emits calls into the runtime package, so a CLI
#                     ahead of the runtime produces code that does not
#                     compile (v0.3.1020's generated attribute rendering
#                     calls templ.ResolveAttributeValue, absent in
#                     v0.3.1001).
#   protoc-gen-go  -> google.golang.org/protobuf in agent/server/pkg.
#                     Generated code requires runtime >= generator.
#
# `make verify-gen` is the backstop: it regenerates and fails on any
# diff, so a pin that drifts from what produced the committed output
# turns CI red rather than going unnoticed. verify_pins below catches
# the other half — this file disagreeing with tools/go.mod.
#
# Toolchain note: some tools now require a Go newer than the project's
# pinned toolchain (buf v1.72.0 needs >= 1.25.6). That is fine and
# deliberate — GOTOOLCHAIN fetches what each tool needs at install time,
# while the project itself still builds under the go.work toolchain pin
# for reproducibility. Tool build toolchain and project build toolchain
# are independent.
# ---------------------------------------------------------------------------
readonly BUF_VERSION=v1.72.0
readonly TEMPL_VERSION=v0.3.1020
readonly PROTOC_GEN_GO_VERSION=v1.36.11
readonly PROTOC_GEN_GO_GRPC_VERSION=v1.6.1
readonly GOLANGCI_LINT_VERSION=v2.11.4
readonly GOVULNCHECK_VERSION=v1.6.0
readonly GOTESTSUM_VERSION=v1.13.0

declare -a TOOLS=(
    "github.com/bufbuild/buf/cmd/buf@${BUF_VERSION}"
    "github.com/a-h/templ/cmd/templ@${TEMPL_VERSION}"
    "google.golang.org/protobuf/cmd/protoc-gen-go@${PROTOC_GEN_GO_VERSION}"
    "google.golang.org/grpc/cmd/protoc-gen-go-grpc@${PROTOC_GEN_GO_GRPC_VERSION}"
    "github.com/golangci/golangci-lint/v2/cmd/golangci-lint@${GOLANGCI_LINT_VERSION}"
    "golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK_VERSION}"
    "gotest.tools/gotestsum@${GOTESTSUM_VERSION}"
)

# verify_pins cross-checks the versions above against tools/go.mod.
#
# These two drifted badly and silently before this check existed: the
# script installed buf v1.47.2 while tools/go.mod claimed v1.68.4, and
# since the script is what actually installs, the buf that ran was 21
# minor versions behind the one the repo appeared to declare — carrying
# a docker/containerd dependency stack that had long since been dropped
# upstream. Nothing failed, because nothing compared them.
#
# tools/go.mod is not authoritative for versions (see tools/tools.go),
# but it should not contradict the thing that is. Warn rather than fail:
# `go mod tidy` in tools/ can legitimately move a version, and blocking
# tool installation on a documentation mismatch would be worse than the
# mismatch.
verify_pins() {
    local gomod="tools/go.mod"
    [[ -f "$gomod" ]] || return 0
    local drift=0
    local entry module want have
    for entry in \
        "github.com/bufbuild/buf ${BUF_VERSION}" \
        "github.com/a-h/templ ${TEMPL_VERSION}" \
        "google.golang.org/protobuf ${PROTOC_GEN_GO_VERSION}" \
        "google.golang.org/grpc/cmd/protoc-gen-go-grpc ${PROTOC_GEN_GO_GRPC_VERSION}" \
        "github.com/golangci/golangci-lint/v2 ${GOLANGCI_LINT_VERSION}" \
        "golang.org/x/vuln ${GOVULNCHECK_VERSION}" \
        "gotest.tools/gotestsum ${GOTESTSUM_VERSION}"
    do
        module="${entry%% *}"
        want="${entry##* }"
        have="$(awk -v m="$module" '$1==m {print $2; exit}' "$gomod")"
        [[ -z "$have" ]] && continue
        if [[ "$have" != "$want" ]]; then
            printf "  ! %-46s script=%-12s tools/go.mod=%s\n" "$module" "$want" "$have" >&2
            drift=1
        fi
    done
    if (( drift )); then
        echo "warning: tool pins disagree with tools/go.mod (script wins); run 'go get' in tools/ to reconcile" >&2
    fi
}

echo "▶ checking pin consistency"
verify_pins

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
