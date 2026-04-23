# Slither — build entry points.
# Tool versions are pinned in tools/tools.go; run `make tools` to install them.

SHELL := /usr/bin/env bash
.DEFAULT_GOAL := help

ROOT := $(CURDIR)
BIN  := $(ROOT)/bin

# Go may not be in PATH when `make` runs under sudo (sudo's secure_path
# strips /usr/local/go/bin on Debian/Ubuntu/RHEL). Skip the go env probe
# in that case — targets that don't need go (e.g. load-test, which only
# execs a pre-built binary) must still work. Targets that do need go
# will get a clear "go: command not found" from their own recipe.
HAVE_GO := $(shell command -v go 2>/dev/null)
ifneq ($(HAVE_GO),)
GOBIN ?= $(shell go env GOBIN)
ifeq ($(GOBIN),)
GOBIN := $(shell go env GOPATH)/bin
endif
export GOBIN
export PATH := $(GOBIN):$(PATH)
endif

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/t3rmit3/slither/pkg/version.Version=$(VERSION)

GO_MODULES := pkg agent server

# ----------------------------------------------------------------------------
# Help
# ----------------------------------------------------------------------------

.PHONY: help
help: ## Show this help
	@awk 'BEGIN { FS = ":.*##"; printf "\nUsage: make \033[36m<target>\033[0m\n\nTargets:\n" } \
	     /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

# ----------------------------------------------------------------------------
# Tooling
# ----------------------------------------------------------------------------

.PHONY: tools
tools: ## Install pinned Go tools to GOBIN
	@bash scripts/install-tools.sh

.PHONY: which-tools
which-tools: ## Print paths to installed tools
	@for t in buf templ protoc-gen-go protoc-gen-go-grpc golangci-lint gotestsum govulncheck; do \
		printf "%-24s %s\n" "$$t" "$$(command -v $$t || echo NOT INSTALLED)"; \
	done

# ----------------------------------------------------------------------------
# Code generation
# ----------------------------------------------------------------------------

.PHONY: gen
gen: gen-proto gen-templ gen-bpf ## Run all code generators

.PHONY: gen-proto
gen-proto: ## Regenerate protobuf + gRPC bindings
	@cd proto && buf lint && buf generate

.PHONY: gen-templ
gen-templ: ## Regenerate templ components (Phase 2+)
	@if [ -d server/internal/console/templates ]; then templ generate -path server/internal/console/templates; fi

.PHONY: gen-bpf
gen-bpf: ## Regenerate eBPF Go wrappers + bytecode via bpf2go
	@command -v clang >/dev/null || { echo "error: clang required for eBPF codegen"; exit 1; }
	@cd agent && go generate ./internal/bpf/...

.PHONY: gen-vmlinux
gen-vmlinux: ## Regenerate agent/internal/bpf/src/headers/vmlinux.h from /sys/kernel/btf/vmlinux
	@command -v bpftool >/dev/null || { echo "error: bpftool required"; exit 1; }
	@test -r /sys/kernel/btf/vmlinux || { echo "error: kernel BTF not available at /sys/kernel/btf/vmlinux"; exit 1; }
	@bpftool btf dump file /sys/kernel/btf/vmlinux format c > agent/internal/bpf/src/headers/vmlinux.h
	@echo "wrote agent/internal/bpf/src/headers/vmlinux.h"

.PHONY: verify-gen
verify-gen: ## Fail if `make gen` would produce a diff (CI guard)
	@$(MAKE) --no-print-directory gen
	@# bpf2go emits ELF .o files whose bytes depend on clang version + build
	@# path, so they're not reproducible across machines. The Go wrappers
	@# and embedded bytecode loader are, so we diff those and ignore the .o.
	@# If the wrapper is out of date, this still catches it.
	@if ! git diff --quiet --exit-code -- \
			proto server/internal/console agent/internal/bpf \
			':(exclude)agent/internal/bpf/*.o'; then \
		echo "ERROR: generated code is out of date. Run 'make gen' and commit the result."; \
		git --no-pager diff -- proto server/internal/console agent/internal/bpf \
			':(exclude)agent/internal/bpf/*.o'; \
		exit 1; \
	fi

# ----------------------------------------------------------------------------
# Build
# ----------------------------------------------------------------------------

.PHONY: build
build: build-agent build-server ## Build all binaries

.PHONY: build-agent
build-agent: ## Build slither-agent → bin/
	@mkdir -p $(BIN)
	@cd agent && CGO_ENABLED=0 go build -trimpath -ldflags='$(LDFLAGS)' -o $(BIN)/slither-agent ./cmd/slither-agent

.PHONY: build-server
build-server: ## Build slither-server → bin/
	@mkdir -p $(BIN)
	@cd server && CGO_ENABLED=0 go build -trimpath -ldflags='$(LDFLAGS)' -o $(BIN)/slither-server ./cmd/slither-server

# ----------------------------------------------------------------------------
# Test
# ----------------------------------------------------------------------------

.PHONY: test
test: ## Run unit tests across all modules
	@for m in $(GO_MODULES); do \
		echo "▶ $$m"; \
		(cd $$m && go test -race -count=1 ./...) || exit 1; \
	done

.PHONY: test-integration
test-integration: ## Run integration tests (requires root + kernel BTF)
	@echo "Integration tests require root and kernel BTF; re-running with sudo -E if needed."
	@for m in $(GO_MODULES); do \
		(cd $$m && go test -tags=integration -count=1 ./...) || exit 1; \
	done

.PHONY: load-test
load-test: ## Run stress-ng load baseline (requires root + stress-ng; build agent first with `make build-agent`)
	@bash scripts/load-test.sh

.PHONY: cover
cover: ## Produce coverage.out and coverage.html (agent + server combined)
	@echo "mode: atomic" > coverage.out
	@for m in $(GO_MODULES); do \
		(cd $$m && go test -coverprofile=../coverage.$$m.out -covermode=atomic ./... >/dev/null) || exit 1; \
		tail -n +2 coverage.$$m.out >> coverage.out; \
		rm -f coverage.$$m.out; \
	done
	@go tool cover -html=coverage.out -o coverage.html
	@echo "wrote coverage.html"

# ----------------------------------------------------------------------------
# Lint
# ----------------------------------------------------------------------------

.PHONY: lint
lint: ## golangci-lint + govulncheck across modules
	@for m in $(GO_MODULES); do \
		echo "▶ lint $$m"; \
		(cd $$m && golangci-lint run ./...) || exit 1; \
	done
	@for m in $(GO_MODULES); do \
		echo "▶ vulncheck $$m"; \
		(cd $$m && govulncheck ./...) || exit 1; \
	done

.PHONY: fmt
fmt: ## gofmt across modules
	@gofmt -s -w $(GO_MODULES)

# ----------------------------------------------------------------------------
# CI
# ----------------------------------------------------------------------------

.PHONY: ci
ci: verify-gen build test lint ## Everything CI runs

# ----------------------------------------------------------------------------
# Compose / dev stack
# ----------------------------------------------------------------------------

.PHONY: compose-up
compose-up: ## Bring up ClickHouse + Postgres dev stack
	@docker compose -f deploy/compose/docker-compose.yml up -d

.PHONY: compose-down
compose-down: ## Tear down dev stack and remove volumes
	@docker compose -f deploy/compose/docker-compose.yml down -v

.PHONY: compose-logs
compose-logs: ## Tail dev stack logs
	@docker compose -f deploy/compose/docker-compose.yml logs -f

# ----------------------------------------------------------------------------
# Housekeeping
# ----------------------------------------------------------------------------

.PHONY: clean
clean: ## Remove build artifacts
	@rm -rf $(BIN) coverage.out coverage.html
