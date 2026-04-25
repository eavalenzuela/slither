package pg

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// Sentinel errors surfaced by enrollment helpers. Callers map these to
// gRPC status codes (typically FailedPrecondition for operational errors
// that aren't bugs — reused, expired, missing).
var (
	ErrTokenNotFound = errors.New("pg: enrollment token not found")
	ErrTokenUsed     = errors.New("pg: enrollment token already used")
	ErrTokenExpired  = errors.New("pg: enrollment token expired")
)

// HashEnrollmentToken returns the sha256 of a token string. The token
// plaintext is never stored — only this hash lands in the database. Keeps
// a compromised DB from handing out valid tokens.
func HashEnrollmentToken(plaintext string) []byte {
	h := sha256.Sum256([]byte(plaintext))
	return h[:]
}

// HostFingerprint mirrors the slither.v1.HostFingerprint proto shape so
// the Enroll RPC can persist exactly what the agent sent.
type HostFingerprint struct {
	Hostname      string
	MachineID     string
	OSName        string
	OSVersion     string
	KernelVersion string
	Arch          string
}

// EnrollResult is what ClaimEnrollmentToken returns after a successful
// atomic burn. HostID is the UUID to stamp on the issued cert; the
// caller uses TokenID to correlate audit log entries.
type EnrollResult struct {
	HostID  string
	TokenID string
}

// ClaimEnrollmentToken runs the full atomic enrollment sequence in one
// transaction:
//
//  1. SELECT ... FROM enrollment_tokens WHERE token_hash = $1 FOR UPDATE
//  2. Validate not-used + not-expired.
//  3. INSERT INTO hosts (fingerprint, cert_serial) → host_id.
//  4. UPDATE enrollment_tokens SET used_at = now(), used_by_host = host_id
//     WHERE id = token_id.
//
// FOR UPDATE holds the row lock until COMMIT, so two concurrent Enroll
// calls with the same token will serialise — the second one sees
// used_at IS NOT NULL and gets ErrTokenUsed.
//
// certSerial is the X.509 serial number (lowercased hex or any stable
// string — the store does not interpret it; hosts_cert_serial_idx only
// requires uniqueness). Passing the actual issued serial ties revocation
// lookups to the issued cert exactly.
func (s *Store) ClaimEnrollmentToken(
	ctx context.Context,
	tokenHash []byte,
	fp HostFingerprint,
	certSerial string,
) (EnrollResult, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return EnrollResult{}, fmt.Errorf("pg.ClaimEnrollmentToken: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after Commit

	var (
		tokenID   pgtype.UUID
		expiresAt time.Time
		usedAt    pgtype.Timestamptz
	)
	err = tx.QueryRow(ctx, `
		SELECT id, expires_at, used_at
		FROM enrollment_tokens
		WHERE token_hash = $1
		FOR UPDATE
	`, tokenHash).Scan(&tokenID, &expiresAt, &usedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return EnrollResult{}, ErrTokenNotFound
	}
	if err != nil {
		return EnrollResult{}, fmt.Errorf("pg.ClaimEnrollmentToken: select: %w", err)
	}
	if usedAt.Valid {
		return EnrollResult{}, ErrTokenUsed
	}
	if time.Now().After(expiresAt) {
		return EnrollResult{}, ErrTokenExpired
	}

	var hostID pgtype.UUID
	err = tx.QueryRow(ctx, `
		INSERT INTO hosts (hostname, machine_id, os_name, os_version, kernel_version, arch, cert_serial)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id
	`, fp.Hostname, fp.MachineID, fp.OSName, fp.OSVersion, fp.KernelVersion, fp.Arch, certSerial).Scan(&hostID)
	if err != nil {
		return EnrollResult{}, fmt.Errorf("pg.ClaimEnrollmentToken: insert host: %w", err)
	}

	if _, err := tx.Exec(ctx, `
		UPDATE enrollment_tokens
		SET used_at = now(), used_by_host = $2
		WHERE id = $1
	`, tokenID, hostID); err != nil {
		return EnrollResult{}, fmt.Errorf("pg.ClaimEnrollmentToken: burn token: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return EnrollResult{}, fmt.Errorf("pg.ClaimEnrollmentToken: commit: %w", err)
	}
	return EnrollResult{
		HostID:  uuidString(hostID),
		TokenID: uuidString(tokenID),
	}, nil
}

// EnrollmentTokenRow is the projection returned by ListEnrollmentTokens.
// HostnameHint is exposed as a value (empty string when NULL) so the
// template renders trivially. Status is derived in Go from the
// expires_at + used_at columns rather than as a CASE in SQL — keeps
// the source of truth in one place.
type EnrollmentTokenRow struct {
	ID           string
	HostnameHint string
	CreatedBy    string
	CreatedAt    time.Time
	ExpiresAt    time.Time
	UsedAt       *time.Time
	UsedByHost   string
}

// ListEnrollmentTokens returns every enrollment_tokens row, newest
// first. Used + expired rows are kept so operators can see audit
// trail at a glance; Phase 3 may add filters.
func (s *Store) ListEnrollmentTokens(ctx context.Context) ([]EnrollmentTokenRow, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, COALESCE(hostname_hint, ''), created_by,
		       created_at, expires_at, used_at,
		       COALESCE(used_by_host::text, '')
		FROM enrollment_tokens
		ORDER BY created_at DESC
		LIMIT 200
	`)
	if err != nil {
		return nil, fmt.Errorf("pg.ListEnrollmentTokens: %w", err)
	}
	defer rows.Close()

	var out []EnrollmentTokenRow
	for rows.Next() {
		var (
			r       EnrollmentTokenRow
			id      pgtype.UUID
			created pgtype.UUID
			usedAt  pgtype.Timestamptz
		)
		if err := rows.Scan(&id, &r.HostnameHint, &created,
			&r.CreatedAt, &r.ExpiresAt, &usedAt, &r.UsedByHost); err != nil {
			return nil, fmt.Errorf("pg.ListEnrollmentTokens: scan: %w", err)
		}
		r.ID = uuidString(id)
		r.CreatedBy = uuidString(created)
		if usedAt.Valid {
			t := usedAt.Time
			r.UsedAt = &t
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// RevokeEnrollmentToken sets used_at = now() on a still-unused token
// so the Enroll RPC's atomic ClaimEnrollmentToken treats it as
// already-burnt on the next attempt. Returns ErrTokenUsed if the
// token has already been revoked or claimed; ErrTokenNotFound for
// unknown IDs. Idempotent in the same shape as RevokeHost.
func (s *Store) RevokeEnrollmentToken(ctx context.Context, tokenID, actorID string) error {
	id, err := parseUUID(tokenID)
	if err != nil {
		return fmt.Errorf("pg.RevokeEnrollmentToken: parse id: %w", err)
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE enrollment_tokens
		SET used_at = now()
		WHERE id = $1 AND used_at IS NULL
	`, id)
	if err != nil {
		return fmt.Errorf("pg.RevokeEnrollmentToken: %w", err)
	}
	if tag.RowsAffected() == 0 {
		// Either unknown or already used. The console maps both to
		// "gone" so there's no information leak between the two.
		var exists bool
		if err := s.pool.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM enrollment_tokens WHERE id = $1)`, id,
		).Scan(&exists); err != nil {
			return fmt.Errorf("pg.RevokeEnrollmentToken: probe: %w", err)
		}
		if !exists {
			return ErrTokenNotFound
		}
		return ErrTokenUsed
	}
	_ = s.LogAudit(ctx, AuditEntry{
		ActorType:  ActorUser,
		ActorID:    actorID,
		Action:     "enrollment_token.revoke",
		TargetKind: "enrollment_token",
		TargetID:   tokenID,
	})
	return nil
}

// InsertEnrollmentToken is used by operators (#45 console flow) and tests
// to create a token record. Plaintext is never sent or stored; callers
// generate it, display once, pass the hash here.
func (s *Store) InsertEnrollmentToken(
	ctx context.Context,
	hash []byte,
	createdBy string, // users.id (UUID) as a string
	hostnameHint string,
	expiresAt time.Time,
) (string, error) {
	var id pgtype.UUID
	createdByUUID, err := parseUUID(createdBy)
	if err != nil {
		return "", fmt.Errorf("pg.InsertEnrollmentToken: parse created_by: %w", err)
	}
	var hint pgtype.Text
	if hostnameHint != "" {
		hint = pgtype.Text{String: hostnameHint, Valid: true}
	}
	err = s.pool.QueryRow(ctx, `
		INSERT INTO enrollment_tokens (token_hash, created_by, hostname_hint, expires_at)
		VALUES ($1, $2, $3, $4)
		RETURNING id
	`, hash, createdByUUID, hint, expiresAt).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("pg.InsertEnrollmentToken: %w", err)
	}
	return uuidString(id), nil
}

func uuidString(u pgtype.UUID) string {
	if !u.Valid {
		return ""
	}
	return fmt.Sprintf("%x-%x-%x-%x-%x",
		u.Bytes[0:4], u.Bytes[4:6], u.Bytes[6:8], u.Bytes[8:10], u.Bytes[10:16])
}

func parseUUID(s string) (pgtype.UUID, error) {
	var u pgtype.UUID
	if err := u.Scan(s); err != nil {
		return pgtype.UUID{}, err
	}
	return u, nil
}
