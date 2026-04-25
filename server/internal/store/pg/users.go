package pg

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
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

// User is the projection returned by GetUserByUsername. Id is hex-
// formatted to match the rest of the pg helpers; consumers store it
// in the session as the actor identifier on subsequent audit rows.
type User struct {
	ID           string
	Username     string
	PasswordHash string
	Role         UserRole
}

// GetUserByUsername loads the row for username. Returns ErrUserNotFound
// when the row is missing — callers fold both cases into a generic
// "invalid credentials" response so timing-leak about which side of the
// pair was wrong is not handed to clients.
func (s *Store) GetUserByUsername(ctx context.Context, username string) (User, error) {
	var (
		id   pgtype.UUID
		role string
		out  User
	)
	err := s.pool.QueryRow(ctx, `
		SELECT id, username, password_hash, role
		FROM users
		WHERE username = $1
	`, username).Scan(&id, &out.Username, &out.PasswordHash, &role)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrUserNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("pg.GetUserByUsername: %w", err)
	}
	out.ID = uuidString(id)
	out.Role = UserRole(role)
	return out, nil
}

// ErrUserNotFound is returned by GetUserByUsername when the row is
// absent. Callers map this + bad-password to the same response.
var ErrUserNotFound = errors.New("pg: user not found")
