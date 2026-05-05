package pg

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// APIKeyTokenPrefix is the literal prefix every minted bearer token
// carries on the wire. Phase 6 #120. The prefix is NOT secret — the
// shape just makes leaked tokens trivially recognisable in logs +
// gives operators a quick visual confirmation a string is a slither
// key vs. some other base64 blob.
const APIKeyTokenPrefix = "slither_apikey_"

// APIKeyPrefixLen bounds the per-row prefix column. 16 base64 chars
// = 96 bits — enough entropy to keep the lookup index's candidate
// count at 1 in any realistic deployment, but still cheap to write
// + grep.
const APIKeyPrefixLen = 16

// APIKeyRow is one /api/keys table row, projected for the operator
// console. The on-the-wire token is NEVER round-tripped through this
// struct — only at mint time, where InsertAPIKey returns it once.
type APIKeyRow struct {
	ID         string
	Name       string
	Prefix     string
	CreatedBy  string
	CreatedAt  time.Time
	LastUsedAt *time.Time
	RevokedAt  *time.Time
	Scopes     []string
}

// IsRevoked reports whether the key has been revoked. Inline rather
// than a separate column so the audit chain reads "revoked_at = X"
// for forensic compare.
func (r APIKeyRow) IsRevoked() bool { return r.RevokedAt != nil }

// MintedAPIKey is the one-shot insert response — the plaintext token
// is returned exactly once and never persisted. Console flashes it
// to the operator who minted the key.
type MintedAPIKey struct {
	ID    string
	Token string // plaintext; show once, then forget
}

// ErrAPIKeyNotFound — sentinel for the get/revoke helpers.
var ErrAPIKeyNotFound = errors.New("pg: api key not found")

// ErrAPIKeyRevoked — the key exists but is revoked. Callers fold
// this into the same 401 the auth middleware returns for unknown
// tokens so probing for valid-but-revoked keys doesn't leak.
var ErrAPIKeyRevoked = errors.New("pg: api key revoked")

// InsertAPIKey mints a fresh key + persists the argon2id hash. The
// returned MintedAPIKey carries the only plaintext copy of the
// token — the caller is responsible for surfacing it to the
// operator before discarding. createdBy may be empty for
// system-minted keys (none ship in v1; the column stays nullable).
func (s *Store) InsertAPIKey(ctx context.Context, name, createdBy string, scopes []string) (MintedAPIKey, error) {
	if name == "" {
		return MintedAPIKey{}, fmt.Errorf("pg.InsertAPIKey: name required")
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return MintedAPIKey{}, fmt.Errorf("pg.InsertAPIKey: rand: %w", err)
	}
	body := base64.RawURLEncoding.EncodeToString(raw)
	token := APIKeyTokenPrefix + body
	prefix := body
	if len(prefix) > APIKeyPrefixLen {
		prefix = prefix[:APIKeyPrefixLen]
	}
	hash, err := HashArgon2id(token)
	if err != nil {
		return MintedAPIKey{}, fmt.Errorf("pg.InsertAPIKey: hash: %w", err)
	}
	if len(scopes) == 0 {
		scopes = []string{"read"}
	}

	var createdByArg any
	if createdBy != "" {
		uid, perr := parseUUID(createdBy)
		if perr != nil {
			return MintedAPIKey{}, fmt.Errorf("pg.InsertAPIKey: parse created_by: %w", perr)
		}
		createdByArg = uid
	}
	var id pgtype.UUID
	err = s.pool.QueryRow(ctx, `
		INSERT INTO api_keys (name, prefix, hash, created_by, scopes)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id
	`, name, prefix, hash, createdByArg, scopes).Scan(&id)
	if err != nil {
		return MintedAPIKey{}, fmt.Errorf("pg.InsertAPIKey: %w", err)
	}
	return MintedAPIKey{ID: uuidString(id), Token: token}, nil
}

// LookupAPIKey is the auth-middleware entry. Splits the token into
// its prefix + body, narrows api_keys via the prefix index, then
// verifies the argon2id hash on the (typically single) candidate
// row. Returns ErrAPIKeyNotFound on unknown tokens, ErrAPIKeyRevoked
// when a matching row is revoked. Touches last_used_at on success.
//
// Constant-time-friendly: argon2id verify is the bulk of the work
// regardless of the token's correctness, so unknown vs. wrong-hash
// timing differs only in the prefix-lookup hit (single index probe);
// the auth middleware folds both into a single 401 to keep the
// observable behaviour uniform.
func (s *Store) LookupAPIKey(ctx context.Context, token string) (APIKeyRow, error) {
	if !strings.HasPrefix(token, APIKeyTokenPrefix) {
		return APIKeyRow{}, ErrAPIKeyNotFound
	}
	body := strings.TrimPrefix(token, APIKeyTokenPrefix)
	if len(body) < APIKeyPrefixLen {
		return APIKeyRow{}, ErrAPIKeyNotFound
	}
	prefix := body[:APIKeyPrefixLen]

	rows, err := s.pool.Query(ctx, `
		SELECT id, name, prefix, hash, created_by, created_at,
		       last_used_at, revoked_at, scopes
		FROM api_keys
		WHERE prefix = $1
	`, prefix)
	if err != nil {
		return APIKeyRow{}, fmt.Errorf("pg.LookupAPIKey: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			row        APIKeyRow
			rawID      pgtype.UUID
			hash       string
			createdBy  pgtype.UUID
			lastUsedAt pgtype.Timestamptz
			revokedAt  pgtype.Timestamptz
		)
		if err := rows.Scan(&rawID, &row.Name, &row.Prefix, &hash,
			&createdBy, &row.CreatedAt,
			&lastUsedAt, &revokedAt, &row.Scopes); err != nil {
			return APIKeyRow{}, fmt.Errorf("pg.LookupAPIKey: scan: %w", err)
		}
		if !VerifyArgon2id(hash, token) {
			continue
		}
		row.ID = uuidString(rawID)
		if createdBy.Valid {
			row.CreatedBy = uuidString(createdBy)
		}
		if lastUsedAt.Valid {
			t := lastUsedAt.Time
			row.LastUsedAt = &t
		}
		if revokedAt.Valid {
			t := revokedAt.Time
			row.RevokedAt = &t
		}
		if row.IsRevoked() {
			return row, ErrAPIKeyRevoked
		}
		// Best-effort last_used_at touch. Errors don't fail the auth.
		_, _ = s.pool.Exec(ctx,
			`UPDATE api_keys SET last_used_at = now() WHERE id = $1`,
			rawID)
		return row, nil
	}
	if err := rows.Err(); err != nil {
		return APIKeyRow{}, fmt.Errorf("pg.LookupAPIKey: iter: %w", err)
	}
	return APIKeyRow{}, ErrAPIKeyNotFound
}

// ListAPIKeys returns every key newest-first for the admin console.
// Plaintext tokens are NEVER round-tripped — only the prefix +
// metadata.
func (s *Store) ListAPIKeys(ctx context.Context, limit int) ([]APIKeyRow, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, name, prefix, created_by, created_at,
		       last_used_at, revoked_at, scopes
		FROM api_keys
		ORDER BY created_at DESC
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("pg.ListAPIKeys: %w", err)
	}
	defer rows.Close()
	var out []APIKeyRow
	for rows.Next() {
		var (
			row        APIKeyRow
			rawID      pgtype.UUID
			createdBy  pgtype.UUID
			lastUsedAt pgtype.Timestamptz
			revokedAt  pgtype.Timestamptz
		)
		if err := rows.Scan(&rawID, &row.Name, &row.Prefix,
			&createdBy, &row.CreatedAt,
			&lastUsedAt, &revokedAt, &row.Scopes); err != nil {
			return nil, fmt.Errorf("pg.ListAPIKeys: scan: %w", err)
		}
		row.ID = uuidString(rawID)
		if createdBy.Valid {
			row.CreatedBy = uuidString(createdBy)
		}
		if lastUsedAt.Valid {
			t := lastUsedAt.Time
			row.LastUsedAt = &t
		}
		if revokedAt.Valid {
			t := revokedAt.Time
			row.RevokedAt = &t
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// RevokeAPIKey flips revoked_at = now(). Idempotent — a second
// revoke on an already-revoked key returns nil so the operator
// console doesn't have to special-case it.
func (s *Store) RevokeAPIKey(ctx context.Context, id string) error {
	uid, err := parseUUID(id)
	if err != nil {
		return fmt.Errorf("pg.RevokeAPIKey: parse id: %w", err)
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE api_keys
		SET revoked_at = COALESCE(revoked_at, now())
		WHERE id = $1
	`, uid)
	if err != nil {
		return fmt.Errorf("pg.RevokeAPIKey: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrAPIKeyNotFound
	}
	return nil
}

// GetHostByName looks up a host row by hostname. Phase 6 #120 — the
// JSON API accepts either host_id or host_name in events/search;
// this helper resolves the latter before the CH query. Empty
// hostname returns ErrHostNotFound to keep the 404-not-200-empty
// shape the API spec requires.
func (s *Store) GetHostByName(ctx context.Context, hostname string) (HostRow, error) {
	if strings.TrimSpace(hostname) == "" {
		return HostRow{}, ErrHostNotFound
	}
	var row HostRow
	var (
		rawID    pgtype.UUID
		lastSeen pgtype.Timestamptz
		revoked  pgtype.Timestamptz
	)
	err := s.pool.QueryRow(ctx, `
		SELECT id, hostname, machine_id, os_name, os_version,
		       kernel_version, arch, agent_version, cert_serial,
		       enrolled_at, last_seen, revoked_at
		FROM hosts
		WHERE hostname = $1
		ORDER BY enrolled_at DESC
		LIMIT 1
	`, hostname).Scan(
		&rawID, &row.Hostname, &row.MachineID, &row.OSName, &row.OSVersion,
		&row.KernelVersion, &row.Arch, &row.AgentVersion, &row.CertSerial,
		&row.EnrolledAt, &lastSeen, &revoked,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return HostRow{}, ErrHostNotFound
	}
	if err != nil {
		return HostRow{}, fmt.Errorf("pg.GetHostByName: %w", err)
	}
	row.ID = uuidString(rawID)
	if lastSeen.Valid {
		t := lastSeen.Time
		row.LastSeen = &t
	}
	if revoked.Valid {
		t := revoked.Time
		row.RevokedAt = &t
	}
	return row, nil
}
