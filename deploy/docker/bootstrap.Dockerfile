# Bootstrap image — runs once per fresh compose stack to mint PKI,
# apply migrations, and seed the admin user. Re-runs are no-ops because
# every operation is idempotent (gen-ca.sh skips when ca.crt exists,
# goose no-ops at head, BootstrapAdmin no-ops when an admin row exists).
#
# Carries openssl + the slither-db / slither-ch CLIs in a Debian slim
# image (we need a real shell + openssl, so the distroless server image
# isn't reusable here).

FROM golang:1.25-bookworm AS build
WORKDIR /src
COPY go.work go.work.sum ./
COPY pkg/go.mod pkg/go.sum pkg/
COPY proto/go.mod proto/go.sum proto/
COPY agent/go.mod agent/go.sum agent/
COPY server/go.mod server/go.sum server/
COPY tools/go.mod tools/go.sum tools/
RUN go mod download
COPY . .
ENV CGO_ENABLED=0
RUN go build -o /out/slither-db ./server/cmd/slither-db && \
    go build -o /out/slither-ch ./server/cmd/slither-ch

FROM debian:12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /out/slither-db /usr/local/bin/slither-db
COPY --from=build /out/slither-ch /usr/local/bin/slither-ch
COPY scripts/gen-ca.sh                       /usr/local/bin/gen-ca.sh
COPY deploy/docker/bootstrap-entrypoint.sh   /usr/local/bin/bootstrap-entrypoint.sh
RUN chmod +x /usr/local/bin/gen-ca.sh /usr/local/bin/bootstrap-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/bootstrap-entrypoint.sh"]
