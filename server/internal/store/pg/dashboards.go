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

// DashboardCard is one entry in a dashboard's layout array. QueryID
// references saved_queries.id by uuid string; deletion of the
// referenced query is intentionally NOT cascaded (the rendering layer
// surfaces a "(query deleted)" placeholder per ADR-0037 / the spec).
//
// Label is an optional per-card display override; empty falls back to
// the saved query's name. Order is implicit in the slice position so
// reorder is a layout-rewrite, not a per-card UPDATE.
type DashboardCard struct {
	QueryID string `json:"query_id"`
	Label   string `json:"label,omitempty"`
}

// Dashboard is one dashboards row + its decoded card layout.
type Dashboard struct {
	ID        string
	UserID    string
	Name      string
	Cards     []DashboardCard
	CreatedAt time.Time
	UpdatedAt time.Time
}

// ErrDashboardNotFound — sentinel for the get/delete helpers.
var ErrDashboardNotFound = errors.New("pg: dashboard not found")

// ErrDashboardExists — duplicate (user_id, name) — surfaces as
// "name already in use".
var ErrDashboardExists = errors.New("pg: dashboard name already in use")

// InsertDashboard creates one /dashboards row with an empty layout.
// Cards are added later via UpdateDashboardLayout — splitting create
// from layout-edit keeps the create UX trivial (just a name).
func (s *Store) InsertDashboard(ctx context.Context, userID, name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("pg.InsertDashboard: name required")
	}
	uid, err := parseUUID(userID)
	if err != nil {
		return "", fmt.Errorf("pg.InsertDashboard: parse user_id: %w", err)
	}
	var id pgtype.UUID
	err = s.pool.QueryRow(ctx, `
		INSERT INTO dashboards (user_id, name, layout)
		VALUES ($1, $2, '[]'::jsonb)
		RETURNING id
	`, uid, name).Scan(&id)
	if err != nil {
		if isPGUniqueViolation(err) {
			return "", ErrDashboardExists
		}
		return "", fmt.Errorf("pg.InsertDashboard: %w", err)
	}
	return uuidString(id), nil
}

// ListDashboards returns the user's dashboards newest-first.
func (s *Store) ListDashboards(ctx context.Context, userID string, limit int) ([]Dashboard, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	uid, err := parseUUID(userID)
	if err != nil {
		return nil, fmt.Errorf("pg.ListDashboards: parse user_id: %w", err)
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, user_id, name, layout, created_at, updated_at
		FROM dashboards
		WHERE user_id = $1
		ORDER BY created_at DESC
		LIMIT $2
	`, uid, limit)
	if err != nil {
		return nil, fmt.Errorf("pg.ListDashboards: %w", err)
	}
	defer rows.Close()
	var out []Dashboard
	for rows.Next() {
		var (
			d       Dashboard
			rawID   pgtype.UUID
			rawUID  pgtype.UUID
			rawJSON []byte
		)
		if err := rows.Scan(&rawID, &rawUID, &d.Name, &rawJSON, &d.CreatedAt, &d.UpdatedAt); err != nil {
			return nil, fmt.Errorf("pg.ListDashboards: scan: %w", err)
		}
		d.ID = uuidString(rawID)
		d.UserID = uuidString(rawUID)
		d.Cards = decodeCards(rawJSON)
		out = append(out, d)
	}
	return out, rows.Err()
}

// GetDashboard loads one dashboard by id restricted to the owning
// user. Returns ErrDashboardNotFound for missing / wrong-user rows.
func (s *Store) GetDashboard(ctx context.Context, userID, dashboardID string) (Dashboard, error) {
	uid, err := parseUUID(userID)
	if err != nil {
		return Dashboard{}, fmt.Errorf("pg.GetDashboard: parse user_id: %w", err)
	}
	did, err := parseUUID(dashboardID)
	if err != nil {
		return Dashboard{}, fmt.Errorf("pg.GetDashboard: parse id: %w", err)
	}
	var (
		d       Dashboard
		rawID   pgtype.UUID
		rawUID  pgtype.UUID
		rawJSON []byte
	)
	err = s.pool.QueryRow(ctx, `
		SELECT id, user_id, name, layout, created_at, updated_at
		FROM dashboards
		WHERE id = $1 AND user_id = $2
	`, did, uid).Scan(&rawID, &rawUID, &d.Name, &rawJSON, &d.CreatedAt, &d.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Dashboard{}, ErrDashboardNotFound
	}
	if err != nil {
		return Dashboard{}, fmt.Errorf("pg.GetDashboard: %w", err)
	}
	d.ID = uuidString(rawID)
	d.UserID = uuidString(rawUID)
	d.Cards = decodeCards(rawJSON)
	return d, nil
}

// UpdateDashboardLayout replaces the entire layout array. Card-add
// and card-remove are both implemented client-side as
// "fetch + mutate slice + put back" — keeps the pg surface tiny at
// the cost of two round-trips per add/remove (acceptable for a UI
// page, not a hot path). updated_at is bumped on every successful
// write.
func (s *Store) UpdateDashboardLayout(ctx context.Context, userID, dashboardID string, cards []DashboardCard) error {
	uid, err := parseUUID(userID)
	if err != nil {
		return fmt.Errorf("pg.UpdateDashboardLayout: parse user_id: %w", err)
	}
	did, err := parseUUID(dashboardID)
	if err != nil {
		return fmt.Errorf("pg.UpdateDashboardLayout: parse id: %w", err)
	}
	if cards == nil {
		cards = []DashboardCard{}
	}
	raw, err := json.Marshal(cards)
	if err != nil {
		return fmt.Errorf("pg.UpdateDashboardLayout: marshal: %w", err)
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE dashboards
		SET layout = $1, updated_at = now()
		WHERE id = $2 AND user_id = $3
	`, raw, did, uid)
	if err != nil {
		return fmt.Errorf("pg.UpdateDashboardLayout: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrDashboardNotFound
	}
	return nil
}

// DeleteDashboard removes one dashboard restricted to the owning user.
func (s *Store) DeleteDashboard(ctx context.Context, userID, dashboardID string) error {
	uid, err := parseUUID(userID)
	if err != nil {
		return fmt.Errorf("pg.DeleteDashboard: parse user_id: %w", err)
	}
	did, err := parseUUID(dashboardID)
	if err != nil {
		return fmt.Errorf("pg.DeleteDashboard: parse id: %w", err)
	}
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM dashboards WHERE id = $1 AND user_id = $2`,
		did, uid)
	if err != nil {
		return fmt.Errorf("pg.DeleteDashboard: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrDashboardNotFound
	}
	return nil
}

// decodeCards unmarshals dashboards.layout into the typed slice. A
// malformed cell (shouldn't happen — we only write valid arrays)
// folds into an empty slice so the page renders empty rather than 500.
func decodeCards(raw []byte) []DashboardCard {
	if len(raw) == 0 {
		return nil
	}
	var out []DashboardCard
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil
	}
	return out
}
