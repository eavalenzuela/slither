package app

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/t3rmit3/slither/agent/internal/config"
	"github.com/t3rmit3/slither/agent/internal/ruleengine"
	"github.com/t3rmit3/slither/pkg/ruleast"
)

// loadRules expands cfg.Rules.Paths (glob-supporting) and compiles every file
// via ruleast.Compile, then wraps the edge artefacts in engine adapters.
// Server-only rules in a local pack are skipped — the agent has no detection
// engine of its own. Returns a nil slice when no paths are configured.
func loadRules(cfg *config.Config) ([]ruleengine.CompiledRule, error) {
	if cfg == nil || len(cfg.Rules.Paths) == 0 {
		return nil, nil
	}

	var files []string
	seen := make(map[string]struct{})
	for _, pat := range cfg.Rules.Paths {
		matches, err := filepath.Glob(pat)
		if err != nil {
			return nil, fmt.Errorf("rules: bad glob %q: %w", pat, err)
		}
		for _, m := range matches {
			if _, ok := seen[m]; ok {
				continue
			}
			seen[m] = struct{}{}
			files = append(files, m)
		}
	}

	parsed := make([]*ruleast.Rule, 0, len(files))
	for _, f := range files {
		body, err := os.ReadFile(f) //nolint:gosec // paths come from operator config
		if err != nil {
			return nil, fmt.Errorf("rules: read %q: %w", f, err)
		}
		artefact, _, class, err := ruleast.Compile(body)
		if err != nil {
			return nil, fmt.Errorf("rules: compile %q: %w", f, err)
		}
		if class == ruleast.ClassificationServerOnly {
			continue
		}
		parsed = append(parsed, artefact.Rule)
	}
	return ruleengine.CompileRules(parsed)
}
