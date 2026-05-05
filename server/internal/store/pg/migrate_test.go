package pg

import (
	"context"
	"io/fs"
	"sort"
	"strings"
	"testing"

	"github.com/t3rmit3/slither/server/migrations"
)

// TestEmbeddedMigrationsPresent asserts every numbered migration file the
// v1 schema expects is packaged into the binary. Guards against forgetting
// a new file in `//go:embed` when Phase 3+ adds migrations.
func TestEmbeddedMigrationsPresent(t *testing.T) {
	want := []string{
		"00001_extensions.sql",
		"00002_users.sql",
		"00003_hosts.sql",
		"00004_enrollment_tokens.sql",
		"00005_rules.sql",
		"00006_alerts.sql",
		"00007_audit_log.sql",
		"00008_rules_notify.sql",
		"00009_sessions.sql",
		"00010_rules_server_plan.sql",
		"00011_iocs.sql",
		"00012_rules_dedupe_window.sql",
		"00013_alerts_filter_indexes.sql",
		"00014_response_actions.sql",
		"00015_host_response_policies.sql",
		"00016_hosts_mgmt_subnet.sql",
		"00017_hunts.sql",
		"00018_chain_summaries.sql",
		"00019_users_oidc.sql",
	}
	got, err := fs.Glob(migrations.FS, "*.sql")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	sort.Strings(got)
	sort.Strings(want)
	if len(got) != len(want) {
		t.Fatalf("migrations = %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("migration[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestResetRefusedWithoutEnv proves the Reset safety gate is effective
// without needing a real database — the env check fires before any DB work.
func TestResetRefusedWithoutEnv(t *testing.T) {
	t.Setenv("SLITHER_ALLOW_RESET", "")
	err := Reset(context.Background(), "postgres://ignored/ignored")
	if err == nil {
		t.Fatal("Reset succeeded without SLITHER_ALLOW_RESET=1")
	}
	if !strings.Contains(err.Error(), "SLITHER_ALLOW_RESET") {
		t.Errorf("error should reference the guard env var: %v", err)
	}
}
