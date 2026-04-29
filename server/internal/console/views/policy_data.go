package views

import "github.com/t3rmit3/slither/server/internal/store/pg"

// hostLabel returns the friendliest display string for a host —
// hostname when present, ID otherwise. Used by templ files; mirrors
// the package-internal helper in server/internal/console/hosts.go.
func hostLabel(h pg.HostRow) string {
	if h.Hostname != "" {
		return h.Hostname
	}
	if h.ID != "" {
		return h.ID
	}
	return "—"
}

// HostPolicyData drives the /hosts/{id}/policy admin page. Pulls
// hostname + the existing policy off pg so the form can render
// current state plus the human-readable label of the host an
// operator is about to grant response permissions on.
type HostPolicyData struct {
	Host    pg.HostRow
	Policy  pg.HostPolicy
	Flash   string
	Error   string
	IsAdmin bool
}

// ResponseActionLabel maps a stored ResponseAction to a UI-friendly
// string for action buttons + history rows. Kept here so the templ
// doesn't sprout a per-action switch inline.
func ResponseActionLabel(a pg.ResponseAction) string {
	switch a {
	case pg.ResponseActionKillProcess:
		return "Kill process"
	case pg.ResponseActionKillTree:
		return "Kill process tree"
	case pg.ResponseActionQuarantineFile:
		return "Quarantine file"
	case pg.ResponseActionIsolateHost:
		return "Isolate host"
	case pg.ResponseActionUnisolateHost:
		return "Un-isolate host"
	case pg.ResponseActionCollectArtifacts:
		return "Collect artefacts"
	}
	return string(a)
}

// ResponseActionDestructive flags actions that need a typed
// confirmation in the modal (vs. a single-click confirm). The line
// "destructive" follows the ADR-0034 guidance: anything that kills,
// moves files, or cuts network is destructive; collect / unisolate
// are recoverable / restorative.
func ResponseActionDestructive(a pg.ResponseAction) bool {
	switch a {
	case pg.ResponseActionKillProcess,
		pg.ResponseActionKillTree,
		pg.ResponseActionQuarantineFile,
		pg.ResponseActionIsolateHost:
		return true
	}
	return false
}

// ResponseStatusLabel renders the lifecycle status for the action
// history table. Falls back to the raw value for forwards-compatibility
// with future enum additions (which would land via a new ADR + CHECK
// widening).
func ResponseStatusLabel(s pg.ResponseStatus) string {
	switch s {
	case pg.ResponseStatusPending:
		return "pending"
	case pg.ResponseStatusRunning:
		return "running"
	case pg.ResponseStatusDone:
		return "done"
	case pg.ResponseStatusFailed:
		return "failed"
	case pg.ResponseStatusDeniedByPolicy:
		return "denied (policy)"
	case pg.ResponseStatusReverted:
		return "reverted"
	}
	return string(s)
}
