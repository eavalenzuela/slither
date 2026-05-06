package ch

import (
	"strings"
	"testing"
)

// listMigrationFiles must return every shipped migration in
// version-ascending order. The sort is what DryRun relies on for
// "pending after current" filtering.
func TestListMigrationFiles_SortedAscending(t *testing.T) {
	t.Parallel()
	files, err := listMigrationFiles()
	if err != nil {
		t.Fatalf("listMigrationFiles: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("expected at least one migration on the embedded FS")
	}
	for i := 1; i < len(files); i++ {
		if files[i].version <= files[i-1].version {
			t.Errorf("not strictly ascending at index %d: %v after %v",
				i, files[i].version, files[i-1].version)
		}
	}
	// Sanity-check the lowest is one of the originals.
	if files[0].version != 1 {
		t.Errorf("lowest version = %d, want 1", files[0].version)
	}
}

// readMigrationSection returns the body between `-- +goose Up` (or
// Down) and the next +goose marker (or EOF). Phase 5 #99 dry-run
// surfaces this content to operators previewing a migration.
func TestReadMigrationSection_UpAndDown(t *testing.T) {
	t.Parallel()
	files, err := listMigrationFiles()
	if err != nil {
		t.Fatalf("listMigrationFiles: %v", err)
	}
	if len(files) == 0 {
		t.Skip("no migrations to read")
	}

	// Find a migration that has both Up and Down sections (Phase 5
	// migrations have both per ADR-0033). Use the first such file.
	var withDown string
	for _, f := range files {
		body, sErr := readMigrationSection(f.name, "Down")
		if sErr != nil {
			t.Fatalf("readMigrationSection Down %s: %v", f.name, sErr)
		}
		if !strings.HasPrefix(body, "-- (no Down section)") {
			withDown = f.name
			break
		}
	}
	if withDown == "" {
		t.Skip("no migration with both Up and Down sections")
	}

	upBody, err := readMigrationSection(withDown, "Up")
	if err != nil {
		t.Fatalf("Up: %v", err)
	}
	if upBody == "" || strings.HasPrefix(upBody, "-- (no") {
		t.Errorf("Up section empty or missing for %s: %q", withDown, upBody)
	}
	if !strings.Contains(strings.ToUpper(upBody), "CREATE") &&
		!strings.Contains(strings.ToUpper(upBody), "ALTER") {
		t.Errorf("Up section %q lacks a CREATE/ALTER statement", withDown)
	}

	downBody, err := readMigrationSection(withDown, "Down")
	if err != nil {
		t.Fatalf("Down: %v", err)
	}
	if downBody == "" || strings.HasPrefix(downBody, "-- (no") {
		t.Errorf("Down section empty or missing for %s: %q", withDown, downBody)
	}
}

func TestReadMigrationSection_MissingMarkerReturnsSentinel(t *testing.T) {
	t.Parallel()
	// First migration's filename is real; ask for a section that
	// doesn't exist (an arbitrary string goose doesn't define).
	files, err := listMigrationFiles()
	if err != nil || len(files) == 0 {
		t.Skip("no migrations to read")
	}
	body, err := readMigrationSection(files[0].name, "Sideways")
	if err != nil {
		t.Fatalf("missing-section: %v", err)
	}
	if !strings.Contains(body, "no Sideways section") {
		t.Errorf("missing-section body = %q, want sentinel", body)
	}
}
