# Multi-stage build for the slither server image.
#
# Build stage uses the official Go toolchain image — pinned to the
# workspace's Go 1.25 floor (memory: project_toolchain). Runtime is a
# small distroless image with shell access deliberately dropped; the
# bootstrap container has its own image with a shell.
#
# Embeds slither-server, slither-db, slither-ch in /usr/local/bin so the
# compose stack can invoke any of them without extra image layers.

FROM golang:1.25-bookworm AS build
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
RUN go build -o /out/slither-server ./server/cmd/slither-server && \
    go build -o /out/slither-db     ./server/cmd/slither-db && \
    go build -o /out/slither-ch     ./server/cmd/slither-ch

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/slither-server /usr/local/bin/slither-server
COPY --from=build /out/slither-db     /usr/local/bin/slither-db
COPY --from=build /out/slither-ch     /usr/local/bin/slither-ch

USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/slither-server"]
