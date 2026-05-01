# Phase 5 #93 — Slither agent OCI image. Multi-arch (amd64 + arm64).
#
# The agent runs as root inside the container because BPF program load
# + tracepoint attach require CAP_BPF + CAP_PERFMON which are gated on
# uid 0 by default kernel policy. The k8s daemonset shape grants the
# narrow capability set via securityContext.capabilities.add — never
# `privileged: true`. See deploy/k8s/daemonset.yaml.
#
# Distroless base: scratch + ca-certificates so the agent can verify
# the server's TLS cert. No shell, no package manager, no userland
# beyond what the binary brings. Phase 5 #89 build flags applied so
# the in-image binary is byte-reproducible at a given commit.

# Build stage. TARGETARCH is set by docker buildx for each platform
# in the build matrix; we cross-compile via GOARCH=$TARGETARCH so a
# single buildx invocation produces both amd64 and arm64 images.
FROM --platform=$BUILDPLATFORM golang:1.25-bookworm AS build
ARG TARGETARCH
ARG VERSION=dev
WORKDIR /src

COPY go.work go.work.sum ./
COPY pkg/go.mod pkg/go.sum pkg/
COPY proto/go.mod proto/go.sum proto/
COPY agent/go.mod agent/go.sum agent/
COPY server/go.mod server/go.sum server/
COPY tools/go.mod tools/go.sum tools/

RUN go mod download

COPY . .

# CGO_ENABLED=0 for fully static binary; flags mirror GO_BUILD_FLAGS
# from the workspace Makefile so `verify-reproducible` covers the
# image build path too.
ENV CGO_ENABLED=0
RUN GOOS=linux GOARCH=$TARGETARCH \
    go build -trimpath -buildvcs=true -mod=readonly \
        -ldflags="-s -w -X github.com/t3rmit3/slither/pkg/version.Version=$VERSION" \
        -o /out/slither-agent ./agent/cmd/slither-agent

# Runtime stage. distroless/static-debian12 ships glibc-free with
# /etc/ssl/certs/ca-certificates.crt for outbound TLS verification.
# No nonroot variant — agent needs uid 0 + capabilities the daemonset
# grants explicitly.
FROM gcr.io/distroless/static-debian12:latest
COPY --from=build /out/slither-agent /usr/local/bin/slither-agent

# Provide a default config path. Operators mount the real config via
# a Kubernetes Secret at /etc/slither/agent.yaml; this entrypoint
# leaves it implicit so the container fails fast on a missing config
# rather than silently using a baked-in placeholder.
ENTRYPOINT ["/usr/local/bin/slither-agent"]
CMD ["--config", "/etc/slither/agent.yaml"]
