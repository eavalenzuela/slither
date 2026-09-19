# ADR-0044: Agent updates ride the OS package manager; no server-pushed self-update

**Status:** accepted

**Date:** 2026-09-19

## Context

PROJECT.md §3.5 lists "Agent updates: signed, server-pushed, with
rollback" as a v1 operational capability. Like YARA (ADR-0043) it
never got a Phase, and the 2026-09-19 review found no code behind it.

What does exist:

- Phase 5 #91 / #92 / #93: every release ships cosign-keyless-signed
  binaries, deb and rpm packages, and OCI images, with SBOMs. The
  packages carry the systemd unit and a config sample and install
  cleanly over a previous version (`docs/install.md` §1.0).
- Phase 5 #88c: the agent reports its version in every heartbeat;
  `hosts.agent_version` is persisted and shown in the console host
  inventory, so version drift across the fleet is already visible.
- PROJECT.md §4.4 already excludes "auto-update" from the extension
  surface, with the rationale "keeping the surface small is the
  point."

What a server-pushed updater would add is a channel by which the
server can replace the agent binary on every host. That is the single
most valuable thing an attacker who compromises the server — or the
release pipeline feeding it — could ask for, and it is exactly the
mechanism behind the best-known supply-chain compromises of security
and management software. Every operator this project targets
(PROJECT.md §2: 50–500 hosts, small team) already has a package
manager with a signed repository, unattended-upgrade tooling
(`unattended-upgrades`, `dnf-automatic`, Ansible / Salt / Puppet), and
a rollback story (`apt install slither-agent=<prev>`, `dnf downgrade`)
that is audited, familiar, and not slither's to get wrong.

## Decision

**Agent updates are delivered as signed OS packages through the
operator's package manager. slither does not implement a server-pushed
self-update channel, in v1 or as a Phase 7 item.** Specifically:

1. The release pipeline stays the delivery mechanism: signed deb / rpm
   per release, verifiable with cosign against the project identity
   (ADR-0039 trust root). Publishing an apt / yum repository is the
   one piece of "server-pushed" convenience worth adding and is a
   release-infrastructure task, not an agent feature.
2. Rollback is the package manager's downgrade path. The agent's
   on-disk state (`/var/lib/slither`, the keystore, the spool, the
   tamper chain) is versioned additively (ADR-0038, Phase 5 #96,
   ADR-0042) precisely so an older binary can start against it.
3. The server keeps doing what it does: record the reported version
   per host and show it. A follow-up may add an "agents behind
   release X" console banner and an audit row when a host's reported
   version *decreases* (a downgrade nobody ordered is a signal).
4. The agent never writes to its own binary, its unit file, or its
   package database, and never executes a package-manager command on
   the server's instruction. This is a self-protection property
   (Phase 5 #95) and is now a stated invariant.

PROJECT.md §3.5's line is amended to point here.

## Consequences

- No new privileged code path in the agent; the self-protection
  posture is unchanged and now explicitly covers "the server cannot
  make the agent replace itself".
- Fleet update cadence is the operator's, with the operator's tools.
  That is a feature for the target user and a non-feature for anyone
  wanting one-click fleet upgrades from the console.
- Operators on distros without a slither package (or with a pinned
  image pipeline) update the way they update anything else there;
  the signed release tarball path in `docs/install.md` §1.2 covers
  them.
- A signed apt / yum repository is the natural next release-infra
  step and is tracked in IMPLEMENTATION.md §9.

## Alternatives considered

- **Server-pushed updater with cosign verification on the agent.**
  Rejected: verification limits the blast radius of a compromised
  server but not of a compromised release identity, and the channel's
  existence is itself the target. The package manager gives the same
  verification with an audited, operator-owned trigger.
- **Updater as an extension.** Same channel, one process removed; the
  extension model (ADR-0027) already excludes auto-update.
- **Container-only delivery (OCI image per release).** Shipped
  already for Kubernetes (Phase 6 #119); it is one of the package
  shapes, not a replacement for host packages.

## References

- PROJECT.md §3.5, §4.4, §2
- ADR-0038 (keystore), ADR-0039 (signing), ADR-0042 (chain)
- IMPLEMENTATION.md Phase 5 #88c, #91–#93, #95, #96
