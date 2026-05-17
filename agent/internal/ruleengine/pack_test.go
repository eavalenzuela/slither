package ruleengine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/t3rmit3/slither/pkg/ruleast"
)

// TestShippedPackCompiles is the guard for the rules/linux/ pack: every
// shipped rule must parse via ruleast.Compile and survive the engine's
// CompileRules step, and no two rules may share an `id:`. Unlike the
// integration scenario tests (root + kernel BTF), this runs anywhere —
// so a malformed or duplicate-id rule fails CI on the regular test path
// rather than only when someone runs the privileged suite.
func TestShippedPackCompiles(t *testing.T) {
	root := findRepoRoot(t)
	packDir := filepath.Join(root, "rules", "linux")

	ymls, err := filepath.Glob(filepath.Join(packDir, "*.yml"))
	if err != nil {
		t.Fatalf("glob pack: %v", err)
	}
	if len(ymls) < 40 {
		t.Fatalf("expected >=40 shipped rules; found %d", len(ymls))
	}

	idToFile := make(map[string]string, len(ymls))
	for _, path := range ymls {
		name := filepath.Base(path)
		t.Run(name, func(t *testing.T) {
			src, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			art, _, _, err := ruleast.Compile(src)
			if err != nil {
				t.Fatalf("ruleast.Compile: %v", err)
			}
			if _, err := CompileRules([]*ruleast.Rule{art.Rule}, nil, nil); err != nil {
				t.Fatalf("CompileRules: %v", err)
			}
			id := art.Rule.ID
			if prev, dup := idToFile[id]; dup {
				t.Fatalf("duplicate rule id %s — also used by %s", id, prev)
			}
			idToFile[id] = name
			if !strings.HasPrefix(id, "8b7c4d00-0001-4000-8000-") {
				t.Errorf("rule id %s outside the pack's UID namespace", id)
			}
		})
	}
}
