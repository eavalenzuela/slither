# ADR-0034: Response model + auth boundary

**Status:** accepted

**Date:** 2026-04-29

## Context

Phase 4 lights up response actions on the agent — kill process,
quarantine file, isolate host, collect artefacts. Three architectural
decisions need pinning before code lands:

1. **Auth boundary.** Where does the operator-or-rule authorisation
   live? Two surfaces overlap: (a) operator-driven response from the
   console, (b) edge auto-respond when a rule with
   `slither.response` block fires on a host whose policy permits.
2. **Audit invariants.** What's the smallest fact-set that must be
   captured for every action so an incident review reconstructs the
   chain of custody? How are reversals linked back to the original
   action?
3. **Action surface freeze.** The proto already enumerates six
   actions (`RESPONSE_ACTION_KILL_PROCESS`, `_TREE`, `QUARANTINE_FILE`,
   `ISOLATE_HOST`, `UNISOLATE_HOST`, `COLLECT_ARTIFACTS`). Phase 4
   v1 ships those exactly; future actions need an ADR + an additive
   enum bump per §2.4 wire-freeze rules.

ADR-0021 (immediate response opt-in) and ADR-0022 (protection-first)
set the gating posture. This ADR is the implementation contract.

## Decision

### Two-layer auth, both required for any action to fire

Combining ADR-0021's per-rule + per-host gating with the operator
path:

| Path | Gates required |
|------|----------------|
| Operator-driven (console) | (a) operator has `analyst` or `admin` role + (b) per-host policy permits the action class |
| Edge auto-respond | (a) rule's `slither.response` block declares the action + (b) per-host policy permits the action class |

A single per-host policy table governs both paths. Default policy is
**detect-only** — every host enrolled by the existing flow lands here
until an operator promotes it. An action attempted against a
detect-only host:
- For console-driven actions: the dispatcher rejects synchronously
  (`response_actions.status = 'denied_by_policy'`); UI shows an
  "action not permitted on this host" flash.
- For edge auto-respond: the agent records the finding as normal +
  emits a `would_have_executed` marker so operators see real data
  for the promotion decision.

### Per-action class permission, not all-or-nothing

The policy is a column-per-action-class set rather than one
boolean. An operator can promote a host to allow `kill_process`
without also permitting `isolate_host` (which is much more
disruptive). Six action classes, six booleans:

```
host_response_policies (
    host_id            uuid PRIMARY KEY REFERENCES hosts (id),
    allow_kill_process boolean NOT NULL DEFAULT false,
    allow_kill_tree    boolean NOT NULL DEFAULT false,
    allow_quarantine   boolean NOT NULL DEFAULT false,
    allow_isolate      boolean NOT NULL DEFAULT false,
    allow_collect      boolean NOT NULL DEFAULT false,
    -- Unisolate is permitted whenever isolate is, by design — the
    -- operator who can isolate must always be able to undo it.
    updated_at         timestamptz NOT NULL DEFAULT now(),
    updated_by         uuid REFERENCES users (id) ON DELETE SET NULL
);
```

`allow_unisolate` is intentionally omitted. Reverse actions (un-isolate,
un-quarantine) inherit their parent's permission so an operator can
never trap themselves in a state they can't roll back.

### `response_actions` table is the audit + state-machine row

Every action — operator-issued or edge-auto-fired — gets one row:

```
response_actions (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_id        uuid REFERENCES alerts (id) ON DELETE SET NULL,
    host_id         uuid NOT NULL REFERENCES hosts (id),
    action          text NOT NULL CHECK (action IN ('kill_process','kill_tree',
                       'quarantine_file','isolate_host','unisolate_host','collect_artifacts')),
    target          text NOT NULL,
    operator_id     uuid REFERENCES users (id) ON DELETE SET NULL,
    -- One of operator_id or rule_uid must be non-null:
    --   operator_id non-null -> console-driven response
    --   rule_uid    non-null -> edge auto-respond firing
    rule_uid        text,
    status          text NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending','running','done','failed','denied_by_policy','reverted')),
    reason_code     text,
    result_blob     bytea,
    parent_action   uuid REFERENCES response_actions (id),  -- reversal link
    created_at      timestamptz NOT NULL DEFAULT now(),
    started_at      timestamptz,
    completed_at    timestamptz,
    CHECK (operator_id IS NOT NULL OR rule_uid IS NOT NULL)
);
```

The status state machine matches what the operator UI surfaces:
`pending → running → done` (success) / `failed` (terminal). Reversals
are *new rows* that point at their parent via `parent_action`; the
parent flips to `reverted` only after the reverse action's `status` is
`done`. This gives forensics a full forward + reverse chain in pg,
not just a Δ.

`audit_log` continues to capture the operator action (who clicked
what, when), one row per state transition. `response_actions` is the
durable record of *what happened on the host* — separate concerns,
joined on `response_actions.id` via `audit_log.target_id`.

### Wire surface

`proto.ResponseRequest` is already in `slither.v1` with the right
shape (#34 baseline). Phase 4 adds ONE additive bump:
`ClientMessage.response_result = 5` (new oneof field) carrying:

```
message ResponseResult {
    string control_id   = 1;   // echoes ResponseRequest.control_id
    string action_id    = 2;   // response_actions.id
    ResponseStatus status = 3; // done/failed
    string detail       = 4;   // error message or summary
    bytes  result_blob  = 5;   // tarball for collect_artifacts
}

enum ResponseStatus {
    RESPONSE_STATUS_UNSPECIFIED = 0;
    RESPONSE_STATUS_DONE        = 1;
    RESPONSE_STATUS_FAILED      = 2;
}
```

The agent emits `ResponseResult` after each `ResponseRequest`
completes. Server resolves to `response_actions` by `action_id`,
flips the row's status, audits the transition.

### Host policy on the wire

Per-host policy travels alongside the ruleset. New `HostPolicy`
message in the control proto (additive):

```
message HostPolicy {
    bool allow_kill_process = 1;
    bool allow_kill_tree    = 2;
    bool allow_quarantine   = 3;
    bool allow_isolate      = 4;
    bool allow_collect      = 5;
    string version          = 6;
}
```

Server pushes a `HostPolicy` once on Session open, then on every
policy edit (NOTIFY-driven, same pattern as `rules_changed`). Agent
caches the latest in memory; the auto-respond gate consults the
cached copy. A new agent that never received a policy stays at the
zero-value (all false = detect-only) — fail closed.

### Action surface freeze

The six existing enum values are the v1 surface. New actions need:

1. ADR adopting the action + its reversal semantics.
2. Additive enum bump (next value, never re-using).
3. New permission column on `host_response_policies`.
4. Agent-side handler.

`hunt`-style actions (Phase 6 osquery query dispatch) and
`run_script`-style actions are explicitly **not** in v1. Adding
arbitrary-script execution is a different threat model and needs its
own ADR.

## Consequences

- Default-detect-only on every freshly enrolled host means operators
  can deploy slither without immediately exposing themselves to
  auto-kill blast radius. Promotion is an explicit operator decision
  with a paper trail.
- Per-action-class permission keeps the blast radius inverse to
  disruption: ops teams typically allow `collect_artifacts` and
  `kill_process` widely; gate `isolate_host` to a narrow on-call
  group.
- Reversal-as-new-row gives forensics a full chain. Operators can
  query "every action against host X" and reconstruct order +
  reversals.
- `ClientMessage.response_result` is the only wire-surface change
  Phase 4 needs. Same additive-bump pattern Phase 3 used for
  `ast_version=2`. No `slither.v2` discussion.
- Action surface frozen at six until Phase 5+ proposes an ADR for
  expansion. Avoids feature-creep into arbitrary-script-execution
  territory.

## References

- ADR-0021 (immediate-response opt-in)
- ADR-0022 (protection-first)
- ADR-0011 (transport gRPC mTLS)
- IMPLEMENTATION.md §6, §2.4 wire-freeze
- proto/slither/v1/control.proto (ResponseRequest, ResponseAction)
