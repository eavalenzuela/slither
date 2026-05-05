package pg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// SavedQuerySurface mirrors the saved_queries.surface CHECK
// constraint. Kept as a narrow string type so callers can't pass
// free-form text and trip the constraint.
type SavedQuerySurface string

const (
	SavedQuerySurfaceEvents SavedQuerySurface = "events"
	SavedQuerySurfaceAlerts SavedQuerySurface = "alerts"
	SavedQuerySurfaceHunts  SavedQuerySurface = "hunts"
)

// SavedQuery is one /queries row. params is rendered back into a URL
// query string by the surface that owns it (the events list re-builds
// /events?host_id=..., the alerts list re-builds /alerts?status=...).
type SavedQuery struct {
	ID        string
	UserID    string
	Name      string
	Surface   SavedQuerySurface
	Params    map[string]string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// SavedQueryInsert is the writer side. Phase 6 #115.
type SavedQueryInsert struct {
	UserID  string
	Name    string
	Surface SavedQuerySurface
	Params  map[string]string
}

// ErrSavedQueryNotFound — sentinel for the get/delete helpers.
var ErrSavedQueryNotFound = errors.New("pg: saved query not found")

// ErrSavedQueryExists — duplicate (user_id, surface, name) — surfaces
// to the operator as "name already in use".
var ErrSavedQueryExists = errors.New("pg: saved query name already in use")

// InsertSavedQuery creates one /queries row. Returns the generated
// id; ErrSavedQueryExists on a (surface, name) collision for the user.
func (s *Store) InsertSavedQuery(ctx context.Context, in SavedQueryInsert) (string, error) {
	if in.Name == "" {
		return "", fmt.Errorf("pg.InsertSavedQuery: name required")
	}
	switch in.Surface {
	case SavedQuerySurfaceEvents, SavedQuerySurfaceAlerts, SavedQuerySurfaceHunts:
	default:
		return "", fmt.Errorf("pg.InsertSavedQuery: invalid surface %q", in.Surface)
	}
	uid, err := parseUUID(in.UserID)
	if err != nil {
		return "", fmt.Errorf("pg.InsertSavedQuery: parse user_id: %w", err)
	}
	params := in.Params
	if params == nil {
		params = map[string]string{}
	}
	raw, err := json.Marshal(params)
	if err != nil {
		return "", fmt.Errorf("pg.InsertSavedQuery: marshal params: %w", err)
	}
	var id pgtype.UUID
	err = s.pool.QueryRow(ctx, `
		INSERT INTO saved_queries (user_id, name, surface, params)
		VALUES ($1, $2, $3, $4)
		RETURNING id
	`, uid, in.Name, string(in.Surface), raw).Scan(&id)
	if err != nil {
		if isPGUniqueViolation(err) {
			return "", ErrSavedQueryExists
		}
		return "", fmt.Errorf("pg.InsertSavedQuery: %w", err)
	}
	return uuidString(id), nil
}

// ListSavedQueries returns the user's saved queries newest-first.
// limit is clamped to [1, 200].
func (s *Store) ListSavedQueries(ctx context.Context, userID string, limit int) ([]SavedQuery, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	uid, err := parseUUID(userID)
	if err != nil {
		return nil, fmt.Errorf("pg.ListSavedQueries: parse user_id: %w", err)
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, user_id, name, surface, params, created_at, updated_at
		FROM saved_queries
		WHERE user_id = $1
		ORDER BY created_at DESC
		LIMIT $2
	`, uid, limit)
	if err != nil {
		return nil, fmt.Errorf("pg.ListSavedQueries: %w", err)
	}
	defer rows.Close()
	var out []SavedQuery
	for rows.Next() {
		var (
			r       SavedQuery
			rawID   pgtype.UUID
			rawUID  pgtype.UUID
			surface string
			rawJSON []byte
		)
		if err := rows.Scan(&rawID, &rawUID, &r.Name, &surface, &rawJSON, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, fmt.Errorf("pg.ListSavedQueries: scan: %w", err)
		}
		r.ID = uuidString(rawID)
		r.UserID = uuidString(rawUID)
		r.Surface = SavedQuerySurface(surface)
		r.Params = decodeParams(rawJSON)
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetSavedQuery loads a single saved query by id, restricted to the
// owning user (no shared queries in v1). Returns ErrSavedQueryNotFound
// for missing / wrong-user rows so an operator probing other users'
// ids can't enumerate.
func (s *Store) GetSavedQuery(ctx context.Context, userID, queryID string) (SavedQuery, error) {
	uid, err := parseUUID(userID)
	if err != nil {
		return SavedQuery{}, fmt.Errorf("pg.GetSavedQuery: parse user_id: %w", err)
	}
	qid, err := parseUUID(queryID)
	if err != nil {
		return SavedQuery{}, fmt.Errorf("pg.GetSavedQuery: parse id: %w", err)
	}
	var (
		r       SavedQuery
		rawID   pgtype.UUID
		rawUID  pgtype.UUID
		surface string
		rawJSON []byte
	)
	err = s.pool.QueryRow(ctx, `
		SELECT id, user_id, name, surface, params, created_at, updated_at
		FROM saved_queries
		WHERE id = $1 AND user_id = $2
	`, qid, uid).Scan(&rawID, &rawUID, &r.Name, &surface, &rawJSON, &r.CreatedAt, &r.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return SavedQuery{}, ErrSavedQueryNotFound
	}
	if err != nil {
		return SavedQuery{}, fmt.Errorf("pg.GetSavedQuery: %w", err)
	}
	r.ID = uuidString(rawID)
	r.UserID = uuidString(rawUID)
	r.Surface = SavedQuerySurface(surface)
	r.Params = decodeParams(rawJSON)
	return r, nil
}

// DeleteSavedQuery removes one row, restricted to the owning user.
// Returns ErrSavedQueryNotFound if no row matched (missing or wrong
// user) so the caller can surface a clean 404.
func (s *Store) DeleteSavedQuery(ctx context.Context, userID, queryID string) error {
	uid, err := parseUUID(userID)
	if err != nil {
		return fmt.Errorf("pg.DeleteSavedQuery: parse user_id: %w", err)
	}
	qid, err := parseUUID(queryID)
	if err != nil {
		return fmt.Errorf("pg.DeleteSavedQuery: parse id: %w", err)
	}
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM saved_queries WHERE id = $1 AND user_id = $2`,
		qid, uid)
	if err != nil {
		return fmt.Errorf("pg.DeleteSavedQuery: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrSavedQueryNotFound
	}
	return nil
}

// decodeParams unmarshals saved_queries.params back into the
// string-string map the surfaces serialise into URL queries. A
// malformed jsonb cell (shouldn't happen — we only write maps) folds
// into an empty map so the page renders something rather than 500'ing.
func decodeParams(raw []byte) map[string]string {
	if len(raw) == 0 {
		return map[string]string{}
	}
	out := map[string]string{}
	if err := json.Unmarshal(raw, &out); err != nil {
		return map[string]string{}
	}
	return out
}
