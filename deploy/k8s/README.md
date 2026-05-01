# Slither on Kubernetes

Reference manifests for running Slither as a daemonset (agent on every
node) plus a deployment (server). Phase 5 #93.

## Prerequisites

- Cluster running kernel ≥ 5.15 with BTF (`/sys/kernel/btf/vmlinux`
  available on host nodes — verifiable per-node via
  `kubectl debug node/<n> -it --image=alpine -- ls /host/sys/kernel/btf/`).
- Postgres + ClickHouse instances reachable from the cluster network.
  Self-managed (in-cluster), CloudSQL/RDS/Aiven, or Altinity Cloud all
  work; the server reads connection strings from env.
- An mTLS CA you control. `scripts/gen-ca.sh` from this repo produces
  a self-signed pair adequate for development; production deployments
  should integrate with cert-manager + an internal PKI.

## Apply

```bash
# 1. Namespace
kubectl apply -f deploy/k8s/namespace.yaml

# 2. Secrets + ConfigMaps (operator-supplied; not committed)
kubectl -n slither create secret generic slither-server-config \
    --from-literal=SLITHER_STORAGE_POSTGRES_DSN='postgres://...' \
    --from-literal=SLITHER_STORAGE_CLICKHOUSE_DSN='clickhouse://...'

kubectl -n slither create secret generic slither-server-pki \
    --from-file=ca.crt=path/to/ca.crt \
    --from-file=server.crt=path/to/server.crt \
    --from-file=server.key=path/to/server.key

kubectl -n slither create configmap slither-server-yaml \
    --from-file=server.yaml=deploy/config/server.yaml.sample

kubectl -n slither create configmap slither-agent-config \
    --from-file=agent.yaml=deploy/config/agent.yaml.sample

kubectl -n slither create secret generic slither-agent-cert \
    --from-file=client.crt=path/to/client.crt \
    --from-file=client.key=path/to/client.key \
    --from-file=ca.crt=path/to/ca.crt

# 3. Run Postgres migrations (one-shot Job)
kubectl -n slither create job slither-db-migrate \
    --image=ghcr.io/t3rmit3/slither/server:latest \
    --command -- /usr/local/bin/slither-db migrate-up

# 4. Deploy
kubectl apply -f deploy/k8s/server.yaml
kubectl apply -f deploy/k8s/daemonset.yaml
```

## Verify the images first

Both `ghcr.io/t3rmit3/slither/agent:vX.Y.Z` and `…/server:vX.Y.Z` are
cosign-signed by the release workflow (Phase 5 #91). Verify before
applying:

```bash
cosign verify \
    --certificate-identity-regexp "^https://github.com/t3rmit3/slither/.github/workflows/release.yml@refs/tags/v" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    ghcr.io/t3rmit3/slither/agent:vX.Y.Z
```

For supply-chain hardening, pin the manifest digest (`@sha256:...`)
in the manifests rather than the tag — the release workflow output
prints the digest for each image.

## Capability model — why no `privileged: true`

The agent's `securityContext.capabilities.add` enumerates the seven
Linux capabilities the eBPF + Phase 4 response paths need:

| Capability | Used for |
|------------|----------|
| `BPF` | load + attach eBPF programs (kernel ≥ 5.8) |
| `PERFMON` | `perf_event_open` for tracepoints |
| `SYS_PTRACE` | `/proc/<pid>/exe` + `cmdline` cross-PID-namespace |
| `DAC_READ_SEARCH` | hash arbitrary executables for OCSF enrichment |
| `DAC_OVERRIDE` | `quarantine_file` reads paths owned by other UIDs |
| `KILL` | `kill_process` / `kill_tree` response actions |
| `NET_ADMIN` | `isolate_host` iptables chain manipulation |

Each is a precise, kernel-checked grant. `privileged: true` is the
operator-namespace equivalent of `chmod -R 777` — every capability,
every device, every namespace bypass. We never reach for it.

If the cluster's PodSecurity admission rejects this profile, switch
to `pod-security.kubernetes.io/enforce: privileged` on the namespace
(only needed if `baseline` is too strict for your hostPath volumes
+ capability set on a particular kubelet).

## Single-replica server caveat

`server.yaml` ships `replicas: 1`. The rule-NOTIFY watcher path (#39)
isn't leader-elected; running multiple replicas would fan a single
NOTIFY into N concurrent `Hub.Refresh` calls and N rule-pack pushes
to every agent. Phase 6+ work for HA. For now: run one server,
accept the SPOF, scale Postgres + ClickHouse independently.
