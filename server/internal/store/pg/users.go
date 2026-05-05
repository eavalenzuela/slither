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
//
// OIDCSubject is empty for password-only users; non-empty for users
// minted by the SSO flow (Phase 6 #113). PasswordHash is empty for
// SSO-only users since their row carries no local credential.
type User struct {
	ID           string
	Username     string
	PasswordHash string
	Role         UserRole
	OIDCSubject  string
}

// GetUserByUsername loads the row for username. Returns ErrUserNotFound
// when the row is missing — callers fold both cases into a generic
// "invalid credentials" response so timing-leak about which side of the
// pair was wrong is not handed to clients.
func (s *Store) GetUserByUsername(ctx context.Context, username string) (User, error) {
	var (
		id          pgtype.UUID
		role        string
		passhash    pgtype.Text
		oidcSubject pgtype.Text
		out         User
	)
	err := s.pool.QueryRow(ctx, `
		SELECT id, username, password_hash, role, oidc_subject
		FROM users
		WHERE username = $1
	`, username).Scan(&id, &out.Username, &passhash, &role, &oidcSubject)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrUserNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("pg.GetUserByUsername: %w", err)
	}
	out.ID = uuidString(id)
	out.Role = UserRole(role)
	if passhash.Valid {
		out.PasswordHash = passhash.String
	}
	if oidcSubject.Valid {
		out.OIDCSubject = oidcSubject.String
	}
	return out, nil
}

// GetUserByOIDCSubject is the SSO-login lookup. Returns ErrUserNotFound
// on a fresh subject (the caller then provisions a new row via
// InsertOIDCUser). Phase 6 #113.
func (s *Store) GetUserByOIDCSubject(ctx context.Context, subject string) (User, error) {
	var (
		id          pgtype.UUID
		role        string
		passhash    pgtype.Text
		oidcSubject pgtype.Text
		out         User
	)
	err := s.pool.QueryRow(ctx, `
		SELECT id, username, password_hash, role, oidc_subject
		FROM users
		WHERE oidc_subject = $1
	`, subject).Scan(&id, &out.Username, &passhash, &role, &oidcSubject)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrUserNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("pg.GetUserByOIDCSubject: %w", err)
	}
	out.ID = uuidString(id)
	out.Role = UserRole(role)
	if passhash.Valid {
		out.PasswordHash = passhash.String
	}
	if oidcSubject.Valid {
		out.OIDCSubject = oidcSubject.String
	}
	return out, nil
}

// InsertOIDCUser provisions a new SSO-only user row on first sign-in.
// password_hash is left NULL — the row's only auth material is the
// IdP's subject claim. username is typically the IdP's preferred_username
// or email claim; uniqueness is enforced at the DB level so a colliding
// local user with the same name forces the operator to rename one side.
//
// On username collision the helper returns ErrUserExists so the caller
// can surface a clean operator-facing error rather than leaking the pg
// constraint name.
func (s *Store) InsertOIDCUser(ctx context.Context, username, oidcSubject string, role UserRole) (string, error) {
	if username == "" {
		return "", fmt.Errorf("pg.InsertOIDCUser: username required")
	}
	if oidcSubject == "" {
		return "", fmt.Errorf("pg.InsertOIDCUser: oidc_subject required")
	}
	var id pgtype.UUID
	err := s.pool.QueryRow(ctx, `
		INSERT INTO users (username, password_hash, role, oidc_subject)
		VALUES ($1, NULL, $2, $3)
		RETURNING id
	`, username, string(role), oidcSubject).Scan(&id)
	if err != nil {
		// 23505 == unique_violation in PostgreSQL. The constraint
		// name distinguishes username vs oidc_subject collisions
		// but both fold into ErrUserExists for the caller.
		if isPGUniqueViolation(err) {
			return "", ErrUserExists
		}
		return "", fmt.Errorf("pg.InsertOIDCUser: %w", err)
	}
	return uuidString(id), nil
}

// UpdateUserRole changes a user's role. Used by the OIDC role-mapping
// path on subsequent logins so an IdP claim change refreshes the
// stored role without forcing the operator to re-create the row.
// Returns ErrUserNotFound when the id doesn't match any row.
func (s *Store) UpdateUserRole(ctx context.Context, userID string, role UserRole) error {
	uid, err := parseUUID(userID)
	if err != nil {
		return fmt.Errorf("pg.UpdateUserRole: parse id: %w", err)
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE users SET role = $1, updated_at = now()
		WHERE id = $2
	`, string(role), uid)
	if err != nil {
		return fmt.Errorf("pg.UpdateUserRole: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrUserNotFound
	}
	return nil
}

// ErrUserNotFound is returned by GetUserByUsername when the row is
// absent. Callers map this + bad-password to the same response.
var ErrUserNotFound = errors.New("pg: user not found")

// ErrUserExists is returned by InsertOIDCUser when the username or
// oidc_subject collides with an existing row.
var ErrUserExists = errors.New("pg: user already exists")

// isPGUniqueViolation tests for SQLSTATE 23505 without importing the
// driver's error type at every call site.
func isPGUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	type sqlStater interface{ SQLState() string }
	var s sqlStater
	if errors.As(err, &s) {
		return s.SQLState() == "23505"
	}
	return false
}
