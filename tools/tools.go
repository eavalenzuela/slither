//go:build tools

// Package tools lists the developer tools this repo depends on so IDEs and
// `go mod` understand the module paths. Tool *versions* are pinned in
// scripts/install-tools.sh (single source of truth) — not here — to keep
// transitive linter dependencies from forcing a Go-toolchain bump.
package tools

import (
	_ "github.com/a-h/templ/cmd/templ"
	_ "github.com/bufbuild/buf/cmd/buf"
	_ "github.com/golangci/golangci-lint/cmd/golangci-lint"
	_ "golang.org/x/vuln/cmd/govulncheck"
	_ "google.golang.org/grpc/cmd/protoc-gen-go-grpc"
	_ "google.golang.org/protobuf/cmd/protoc-gen-go"
	_ "gotest.tools/gotestsum"
)
