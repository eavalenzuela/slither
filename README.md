# Slither

A free, open-source Endpoint Detection and Response (EDR) platform for Linux.

> **Status: pre-alpha (Phase 0).** The plan is stable; the code is not. See [PROJECT.md](./PROJECT.md) for design, [IMPLEMENTATION.md](./IMPLEMENTATION.md) for build plan.

## What it is

- An **eBPF-based Linux endpoint agent** that collects process, file, and network telemetry.
- A **self-hosted server** that ingests events, runs Sigma-based detections, and surfaces alerts in an HTMX web console.
- A **hybrid detection engine** that runs stateless rules on the agent for low-latency response and correlates across hosts on the server.
- Built for small security teams without 24/7 SOC coverage — protection-first, operator-first, honest scope.

## What it is not

- Not an AV replacement.
- Not cross-platform in v1 (Linux only — macOS/Windows deferred).
- Not a SaaS. Self-hosted only.
- Not a compliance-framework product.

## Tech stack

| Component | Choice |
|---|---|
| Agent language | Go + eBPF C (via `cilium/ebpf`, CO-RE) |
| Server language | Go |
| Transport | gRPC bidi streams over mTLS |
| Event store | ClickHouse |
| Control-plane store | Postgres |
| Event schema | OCSF 1.3 (curated subset) |
| Rule format | Sigma |
| Web console | HTMX + `templ` + Tailwind; D2 for server-rendered alert graphs |
| License | MIT |

Full rationale in [PROJECT.md §9.1](./PROJECT.md#9-decisions--remaining-open-items).

## Building from source

```bash
# One-time: install pinned Go tools into GOBIN
make tools

# Run the full CI pipeline locally
make ci

# Build binaries → bin/
make build

# Bring up the dev stack (ClickHouse + Postgres)
make compose-up
```

See [docs/dev-setup.md](./docs/dev-setup.md) for distro-specific prerequisites (Go, clang, Docker).

## Contributing

PRs welcome. All commits must be DCO-signed (`git commit -s`). See [CONTRIBUTING.md](./CONTRIBUTING.md).

## Security

To report a vulnerability, use GitHub's private vulnerability reporting — do not file a public issue. See [SECURITY.md](./SECURITY.md).

## License

[MIT](./LICENSE).
