# Multi-stage build for the slither server image. Phase 5 #93 —
# multi-arch via docker buildx ($TARGETARCH); Phase 5 #89 build flags
# applied so the embedded binaries are byte-reproducible at a given
# commit (verify-reproducible covers this path too).
#
# Build stage uses the official Go toolchain image, pinned to the
# workspace's Go 1.25 floor (memory: project_toolchain). Runtime is a
# small distroless image with shell access deliberately dropped; the
# bootstrap container has its own image with a shell.
#
# Embeds slither-server, slither-db, slither-ch in /usr/local/bin so the
# compose stack can invoke any of them without extra image layers; the
# k8s sidecar pattern uses slither-db for `db migrate-up` jobs.

FROM --platform=$BUILDPLATFORM golang:1.25-bookworm AS build
ARG TARGETARCH
ARG VERSION=dev
WORKDIR /src

# Copy module files first to maximise layer caching across edits.
COPY go.work go.work.sum ./
COPY pkg/go.mod pkg/go.sum pkg/
COPY proto/go.mod proto/go.sum proto/
COPY agent/go.mod agent/go.sum agent/
COPY server/go.mod server/go.sum server/
COPY tools/go.mod tools/go.sum tools/

RUN go mod download

# Now the source.
COPY . .

ENV CGO_ENABLED=0
RUN GOOS=linux GOARCH=$TARGETARCH \
    go build -trimpath -buildvcs=true -mod=readonly \
        -ldflags="-s -w -X github.com/t3rmit3/slither/pkg/version.Version=$VERSION" \
        -o /out/slither-server ./server/cmd/slither-server && \
    GOOS=linux GOARCH=$TARGETARCH \
    go build -trimpath -buildvcs=true -mod=readonly \
        -ldflags="-s -w -X github.com/t3rmit3/slither/pkg/version.Version=$VERSION" \
        -o /out/slither-db     ./server/cmd/slither-db && \
    GOOS=linux GOARCH=$TARGETARCH \
    go build -trimpath -buildvcs=true -mod=readonly \
        -ldflags="-s -w -X github.com/t3rmit3/slither/pkg/version.Version=$VERSION" \
        -o /out/slither-ch     ./server/cmd/slither-ch

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/slither-server /usr/local/bin/slither-server
COPY --from=build /out/slither-db     /usr/local/bin/slither-db
COPY --from=build /out/slither-ch     /usr/local/bin/slither-ch

USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/slither-server"]
