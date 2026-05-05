//go:build integration

package pg

import (
	"context"
	"errors"
	"testing"
	"time"
)

// seedUserForQueries creates a viewer user the saved_queries +
// dashboards FKs can point at.
func seedUserForQueries(ctx context.Context, t *testing.T, s *Store) string {
	t.Helper()
	id, _, err := s.BootstrapAdmin(ctx, "queries-tester", "p4ssw0rd-with-some-len")
	if err != nil {
		t.Fatalf("BootstrapAdmin: %v", err)
	}
	return id
}

func TestSavedQuery_LifecycleAndCollisions(t *testing.T) {
	requireDocker(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	dsn, cleanup := startPostgres(ctx, t)
	defer cleanup()

	if err := Migrate(ctx, dsn); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	s, err := Open(ctx, dsn)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	userID := seedUserForQueries(ctx, t, s)

	// Insert.
	id1, err := s.InsertSavedQuery(ctx, SavedQueryInsert{
		UserID: userID, Name: "today", Surface: SavedQuerySurfaceEvents,
		Params: map[string]string{"class_uid": "1007"},
	})
	if err != nil {
		t.Fatalf("Insert: %v", err)
	}

	// Same name, different surface → allowed.
	if _, err := s.InsertSavedQuery(ctx, SavedQueryInsert{
		UserID: userID, Name: "today", Surface: SavedQuerySurfaceAlerts,
	}); err != nil {
		t.Fatalf("cross-surface dup name should be allowed: %v", err)
	}

	// Same surface + name → ErrSavedQueryExists.
	_, err = s.InsertSavedQuery(ctx, SavedQueryInsert{
		UserID: userID, Name: "today", Surface: SavedQuerySurfaceEvents,
	})
	if !errors.Is(err, ErrSavedQueryExists) {
		t.Errorf("dup not flagged: %v", err)
	}

	// Get round-trips params.
	got, err := s.GetSavedQuery(ctx, userID, id1)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Params["class_uid"] != "1007" {
		t.Errorf("params didn't round-trip: %+v", got.Params)
	}

	// List returns ≥2 rows newest-first.
	rows, err := s.ListSavedQueries(ctx, userID, 50)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(rows) < 2 {
		t.Fatalf("List returned %d rows, want ≥2", len(rows))
	}

	// Other-user lookup → not found.
	otherID, _, err := s.BootstrapAdmin(ctx, "another-user", "anotherp4ss-also-long-enough")
	if err != nil {
		t.Fatalf("seed other user: %v", err)
	}
	if _, err := s.GetSavedQuery(ctx, otherID, id1); !errors.Is(err, ErrSavedQueryNotFound) {
		t.Errorf("cross-user Get should fail with NotFound, got %v", err)
	}

	// Delete.
	if err := s.DeleteSavedQuery(ctx, userID, id1); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.GetSavedQuery(ctx, userID, id1); !errors.Is(err, ErrSavedQueryNotFound) {
		t.Errorf("post-delete Get: %v", err)
	}
}

func TestDashboard_LayoutLifecycle(t *testing.T) {
	requireDocker(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	dsn, cleanup := startPostgres(ctx, t)
	defer cleanup()

	if err := Migrate(ctx, dsn); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	s, err := Open(ctx, dsn)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	userID := seedUserForQueries(ctx, t, s)
	qID, err := s.InsertSavedQuery(ctx, SavedQueryInsert{
		UserID: userID, Name: "q1", Surface: SavedQuerySurfaceEvents,
	})
	if err != nil {
		t.Fatalf("Insert query: %v", err)
	}

	// Create dashboard, add card, list.
	dashID, err := s.InsertDashboard(ctx, userID, "ops")
	if err != nil {
		t.Fatalf("InsertDashboard: %v", err)
	}
	if err := s.UpdateDashboardLayout(ctx, userID, dashID, []DashboardCard{
		{QueryID: qID, Label: "today's events"},
	}); err != nil {
		t.Fatalf("UpdateDashboardLayout: %v", err)
	}
	got, err := s.GetDashboard(ctx, userID, dashID)
	if err != nil {
		t.Fatalf("GetDashboard: %v", err)
	}
	if len(got.Cards) != 1 || got.Cards[0].QueryID != qID || got.Cards[0].Label != "today's events" {
		t.Errorf("layout didn't round-trip: %+v", got.Cards)
	}

	// Dup name → ErrDashboardExists.
	if _, err := s.InsertDashboard(ctx, userID, "ops"); !errors.Is(err, ErrDashboardExists) {
		t.Errorf("dup dashboard name not flagged: %v", err)
	}

	// Delete saved query → card stays in layout (dangling reference
	// surfaces as "(query deleted)" in the rendering layer).
	if err := s.DeleteSavedQuery(ctx, userID, qID); err != nil {
		t.Fatalf("DeleteSavedQuery: %v", err)
	}
	got, err = s.GetDashboard(ctx, userID, dashID)
	if err != nil {
		t.Fatalf("GetDashboard after query delete: %v", err)
	}
	if len(got.Cards) != 1 {
		t.Errorf("layout dropped card on saved-query delete: %+v", got.Cards)
	}

	// Empty layout replace works.
	if err := s.UpdateDashboardLayout(ctx, userID, dashID, nil); err != nil {
		t.Fatalf("UpdateDashboardLayout(nil): %v", err)
	}
	got, err = s.GetDashboard(ctx, userID, dashID)
	if err != nil {
		t.Fatalf("GetDashboard: %v", err)
	}
	if len(got.Cards) != 0 {
		t.Errorf("layout not cleared: %+v", got.Cards)
	}

	// Delete dashboard.
	if err := s.DeleteDashboard(ctx, userID, dashID); err != nil {
		t.Fatalf("DeleteDashboard: %v", err)
	}
	if _, err := s.GetDashboard(ctx, userID, dashID); !errors.Is(err, ErrDashboardNotFound) {
		t.Errorf("post-delete Get: %v", err)
	}
}
