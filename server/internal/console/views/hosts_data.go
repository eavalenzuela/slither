package views

import (
	"time"

	"github.com/t3rmit3/slither/server/internal/store/pg"
)

// HostsPageData drives the inventory list. Now is captured by the
// handler so status derivation in the template is a pure function of
// the data — easier to test, deterministic across rows on the page.
type HostsPageData struct {
	Hosts        []pg.HostRow
	Now          time.Time
	HeartbeatTTL time.Duration // status thresholds derive from this
	IsAdmin      bool
}

// HostStatus is the operator-visible state derived from last_seen.
type HostStatus string

const (
	HostStatusOnline  HostStatus = "online"
	HostStatusStale   HostStatus = "stale"
	HostStatusOffline HostStatus = "offline"
	HostStatusUnknown HostStatus = "unknown" // never connected
	HostStatusRevoked HostStatus = "revoked"
)

// Status implements the §2.4 "3 missed heartbeats" rule:
//
//   - Revoked rows always render as "revoked"; the badge takes
//     precedence over connectivity state because that's what the
//     operator just clicked the revoke button to make visible.
//   - last_seen NULL → "unknown" (host enrolled but never connected).
//   - Within heartbeat TTL → online.
//   - 1×–3× TTL → stale.
//   - Beyond 3× TTL → offline.
//
// HeartbeatTTL is the configured cadence; defaults to 30s when zero
// (matches agent default).
func Status(d HostsPageData, h pg.HostRow) HostStatus {
	if h.RevokedAt != nil {
		return HostStatusRevoked
	}
	if h.LastSeen == nil {
		return HostStatusUnknown
	}
	ttl := d.HeartbeatTTL
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	age := d.Now.Sub(*h.LastSeen)
	switch {
	case age < ttl:
		return HostStatusOnline
	case age < 3*ttl:
		return HostStatusStale
	default:
		return HostStatusOffline
	}
}

// FormatLastSeen renders the last_seen cell. Uses RFC3339Nano for
// machine-readable precision; "—" when never connected.
func FormatLastSeen(h pg.HostRow) string {
	if h.LastSeen == nil {
		return "—"
	}
	return h.LastSeen.UTC().Format(time.RFC3339)
}

// FormatEnrolledAt renders the enrolled_at cell.
func FormatEnrolledAt(h pg.HostRow) string {
	if h.EnrolledAt.IsZero() {
		return "—"
	}
	return h.EnrolledAt.UTC().Format(time.RFC3339)
}
