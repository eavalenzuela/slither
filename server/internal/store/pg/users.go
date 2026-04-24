package pg

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgtype"
)

// UserRole mirrors the Postgres user_role enum. Kept as a narrow string
// type so callers cannot accidentally pass a free-form string.
type UserRole string

const (
	RoleViewer  UserRole = "viewer"
	RoleAnalyst UserRole = "analyst"
	RoleAdmin   UserRole = "admin"
)

// InsertUser creates a user and returns its UUID. passwordHash must
// already be an argon2id encoded string — this helper does NOT hash.
func (s *Store) InsertUser(ctx context.Context, username, passwordHash string, role UserRole) (string, error) {
	var id pgtype.UUID
	err := s.pool.QueryRow(ctx, `
		INSERT INTO users (username, password_hash, role)
		VALUES ($1, $2, $3)
		RETURNING id
	`, username, passwordHash, string(role)).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("pg.InsertUser: %w", err)
	}
	return uuidString(id), nil
}
