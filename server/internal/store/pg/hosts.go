package pg

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// ErrHostNotFound is returned when a hosts row lookup misses. Callers
// usually treat this as Unauthenticated since a missing host on the
// mTLS path means the cert was issued by a since-dropped row.
var ErrHostNotFound = errors.New("pg: host not found")

// UpdateHostLastSeen sets hosts.last_seen = now() for hostID. Used by
// the Session handler (#37) on every Heartbeat. Returns ErrHostNotFound
// if no row matches.
func (s *Store) UpdateHostLastSeen(ctx context.Context, hostID string) error {
	return s.UpdateHostHeartbeat(ctx, hostID, "")
}

// UpdateHostHeartbeat sets hosts.last_seen = now() and, when
// agentVersion is non-empty, writes hosts.agent_version. Phase 5 #88c
// — the column has been on the schema since #32 but went unwritten
// through Phase 4. Empty agentVersion preserves the existing column
// value rather than nulling it, so older agents that don't populate
// AgentHealth.AgentVersion don't blank out a previously-recorded
// version. Returns ErrHostNotFound if no row matches.
func (s *Store) UpdateHostHeartbeat(ctx context.Context, hostID, agentVersion string) error {
	id, err := parseUUID(hostID)
	if err != nil {
		return fmt.Errorf("pg.UpdateHostHeartbeat: parse host_id: %w", err)
	}
	const query = `
		UPDATE hosts
		SET last_seen = now(),
		    agent_version = CASE WHEN $2 = '' THEN agent_version ELSE $2 END
		WHERE id = $1`
	tag, err := s.pool.Exec(ctx, query, id, agentVersion)
	if err != nil {
		return fmt.Errorf("pg.UpdateHostHeartbeat: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrHostNotFound
	}
	return nil
}

// HostExists reports whether hostID is a known, non-revoked host. Used
// by the Session handler to reject cert-CN values that no longer have a
// matching hosts row (cert outlived the row, or operator revoked).
func (s *Store) HostExists(ctx context.Context, hostID string) (bool, error) {
	id, err := parseUUID(hostID)
	if err != nil {
		return false, fmt.Errorf("pg.HostExists: parse host_id: %w", err)
	}
	var exists bool
	err = s.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM hosts WHERE id = $1 AND revoked_at IS NULL)`,
		id).Scan(&exists)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return false, fmt.Errorf("pg.HostExists: %w", err)
	}
	return exists, nil
}

// HostRow is the projection returned by ListHosts. last_seen and
// revoked_at are pointers so the template can distinguish "never
// connected" from "online" without a sentinel value.
type HostRow struct {
	ID            string
	Hostname      string
	MachineID     string
	OSName        string
	OSVersion     string
	KernelVersion string
	Arch          string
	AgentVersion  string
	CertSerial    string
	EnrolledAt    time.Time
	LastSeen      *time.Time
	RevokedAt     *time.Time
}

// ListHosts returns every hosts row, ordered by hostname (revoked
// rows included so the inventory shows them with a "revoked" badge
// rather than vanishing on revoke). Phase 3 may add filters; v1 is
// fleet-scale (50–500 hosts per ADR-0004) so a single page is fine.
func (s *Store) ListHosts(ctx context.Context) ([]HostRow, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, hostname, machine_id, os_name, os_version,
		       kernel_version, arch, COALESCE(agent_version, ''),
		       cert_serial, enrolled_at, last_seen, revoked_at
		FROM hosts
		ORDER BY hostname, id
	`)
	if err != nil {
		return nil, fmt.Errorf("pg.ListHosts: %w", err)
	}
	defer rows.Close()

	var out []HostRow
	for rows.Next() {
		var (
			r        HostRow
			id       pgtype.UUID
			lastSeen pgtype.Timestamptz
			revoked  pgtype.Timestamptz
		)
		if err := rows.Scan(
			&id, &r.Hostname, &r.MachineID, &r.OSName, &r.OSVersion,
			&r.KernelVersion, &r.Arch, &r.AgentVersion,
			&r.CertSerial, &r.EnrolledAt, &lastSeen, &revoked,
		); err != nil {
			return nil, fmt.Errorf("pg.ListHosts: scan: %w", err)
		}
		r.ID = uuidString(id)
		if lastSeen.Valid {
			t := lastSeen.Time
			r.LastSeen = &t
		}
		if revoked.Valid {
			t := revoked.Time
			r.RevokedAt = &t
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetHost returns one hosts row by id. ErrHostNotFound for unknown
// UUIDs; revoked rows are returned (the caller decides whether to act
// on them — process-tree #65 surfaces revoked hosts as historical).
func (s *Store) GetHost(ctx context.Context, hostID string) (HostRow, error) {
	id, err := parseUUID(hostID)
	if err != nil {
		return HostRow{}, fmt.Errorf("pg.GetHost: parse host_id: %w", err)
	}
	var (
		r        HostRow
		idCol    pgtype.UUID
		lastSeen pgtype.Timestamptz
		revoked  pgtype.Timestamptz
	)
	err = s.pool.QueryRow(ctx, `
		SELECT id, hostname, machine_id, os_name, os_version,
		       kernel_version, arch, COALESCE(agent_version, ''),
		       cert_serial, enrolled_at, last_seen, revoked_at
		FROM hosts
		WHERE id = $1
	`, id).Scan(
		&idCol, &r.Hostname, &r.MachineID, &r.OSName, &r.OSVersion,
		&r.KernelVersion, &r.Arch, &r.AgentVersion,
		&r.CertSerial, &r.EnrolledAt, &lastSeen, &revoked,
	)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return HostRow{}, ErrHostNotFound
	case err != nil:
		return HostRow{}, fmt.Errorf("pg.GetHost: %w", err)
	}
	r.ID = uuidString(idCol)
	if lastSeen.Valid {
		t := lastSeen.Time
		r.LastSeen = &t
	}
	if revoked.Valid {
		t := revoked.Time
		r.RevokedAt = &t
	}
	return r, nil
}

// RevokeHost flips hosts.revoked_at = now() and audits the action.
// The next Session-stream authn for this host will fail because
// HostExists treats revoked_at IS NOT NULL as "not present". Existing
// sessions stay open until they reconnect; force-disconnect lands
// post-Phase-2. ErrHostNotFound is returned for unknown UUIDs.
//
// actorID is the operator's users.id (for the audit row); empty when
// a system path triggers the revoke (none today).
func (s *Store) RevokeHost(ctx context.Context, hostID, actorID string) error {
	id, err := parseUUID(hostID)
	if err != nil {
		return fmt.Errorf("pg.RevokeHost: parse host_id: %w", err)
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE hosts SET revoked_at = now()
		WHERE id = $1 AND revoked_at IS NULL
	`, id)
	if err != nil {
		return fmt.Errorf("pg.RevokeHost: %w", err)
	}
	if tag.RowsAffected() == 0 {
		// Either the host doesn't exist or it's already revoked. Map
		// both to ErrHostNotFound so callers get a single shape; the
		// audit log still distinguishes via the LogAudit detail.
		return ErrHostNotFound
	}
	_ = s.LogAudit(ctx, AuditEntry{
		ActorType:  ActorUser,
		ActorID:    actorID,
		Action:     "host.revoke",
		TargetKind: "host",
		TargetID:   hostID,
	})
	return nil
}
