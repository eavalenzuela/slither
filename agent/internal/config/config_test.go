package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validYAML = `
agent:
  host_id_file: /var/lib/slither/host_id
  log_level: info
collectors:
  process:
    enabled: true
  file:
    enabled: true
    include_paths:
      - /etc/**
    exclude_paths:
      - /proc/**
  net:
    enabled: true
rules:
  paths:
    - /etc/slither/rules/*.yml
output:
  kind: stdout
`

func writeTmp(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "agent.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write tmp: %v", err)
	}
	return p
}

func TestLoadValid(t *testing.T) {
	cfg, err := Load(writeTmp(t, validYAML))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Agent.LogLevel != "info" {
		t.Errorf("log_level = %q, want info", cfg.Agent.LogLevel)
	}
	if !cfg.Collectors.Process.Enabled || !cfg.Collectors.File.Enabled || !cfg.Collectors.Net.Enabled {
		t.Errorf("collectors not all enabled: %+v", cfg.Collectors)
	}
	if got := cfg.Collectors.File.IncludePaths; len(got) != 1 || got[0] != "/etc/**" {
		t.Errorf("include_paths = %v", got)
	}
	if len(cfg.Rules.Paths) != 1 {
		t.Errorf("rules.paths = %v", cfg.Rules.Paths)
	}
	if cfg.Output.Kind != "stdout" {
		t.Errorf("output.kind = %q", cfg.Output.Kind)
	}
}

func TestLoadUnknownTopLevelKeySuggests(t *testing.T) {
	_, err := Load(writeTmp(t, "collecor:\n  process:\n    enabled: true\n"))
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("error not wrapped with ErrInvalidConfig: %v", err)
	}
	if !strings.Contains(err.Error(), `did you mean "collectors"`) {
		t.Errorf("missing suggestion in error: %v", err)
	}
}

func TestLoadUnknownNestedKeyStrict(t *testing.T) {
	y := `
collectors:
  process:
    enabeld: true
`
	_, err := Load(writeTmp(t, y))
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("error not wrapped: %v", err)
	}
	if !strings.Contains(err.Error(), "enabeld") {
		t.Errorf("error should cite offending key: %v", err)
	}
}

func TestLoadInvalidLogLevel(t *testing.T) {
	y := `
agent:
  log_level: verbose
collectors:
  process:
    enabled: true
`
	_, err := Load(writeTmp(t, y))
	if err == nil || !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("want ErrInvalidConfig, got %v", err)
	}
	if !strings.Contains(err.Error(), "agent.log_level") {
		t.Errorf("error should mention agent.log_level: %v", err)
	}
}

func TestLoadInvalidOutputKind(t *testing.T) {
	y := `
collectors:
  process:
    enabled: true
output:
  kind: syslog
`
	_, err := Load(writeTmp(t, y))
	if err == nil || !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("want ErrInvalidConfig, got %v", err)
	}
}

func TestLoadNoCollectorsEnabled(t *testing.T) {
	y := `
collectors:
  process:
    enabled: false
`
	_, err := Load(writeTmp(t, y))
	if err == nil || !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("want ErrInvalidConfig, got %v", err)
	}
	if !strings.Contains(err.Error(), "no collectors") {
		t.Errorf("expected 'no collectors' in error: %v", err)
	}
}

func TestLoadDefaultsApplied(t *testing.T) {
	y := `
collectors:
  process:
    enabled: true
`
	cfg, err := Load(writeTmp(t, y))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Agent.LogLevel != "info" {
		t.Errorf("default log_level = %q, want info", cfg.Agent.LogLevel)
	}
	if cfg.Output.Kind != "stdout" {
		t.Errorf("default output.kind = %q, want stdout", cfg.Output.Kind)
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load("/does/not/exist/agent.yaml")
	if err == nil {
		t.Fatal("expected error")
	}
	if errors.Is(err, ErrInvalidConfig) {
		t.Errorf("file-open errors should not be ErrInvalidConfig: %v", err)
	}
}

func TestEnvOverrides(t *testing.T) {
	t.Setenv("SLITHER_AGENT_LOG_LEVEL", "debug")
	t.Setenv("SLITHER_COLLECTORS_NET_ENABLED", "false")
	t.Setenv("SLITHER_RULES_PATHS", "/a/*.yml, /b/*.yml")

	cfg, err := Load(writeTmp(t, validYAML))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Agent.LogLevel != "debug" {
		t.Errorf("env override log_level = %q", cfg.Agent.LogLevel)
	}
	if cfg.Collectors.Net.Enabled {
		t.Error("env override should have disabled net collector")
	}
	if got := cfg.Rules.Paths; len(got) != 2 || got[0] != "/a/*.yml" || got[1] != "/b/*.yml" {
		t.Errorf("env override rules.paths = %v", got)
	}
}

func TestEnvOverrideIgnoresMalformedBool(t *testing.T) {
	t.Setenv("SLITHER_COLLECTORS_NET_ENABLED", "yesplease")
	cfg, err := Load(writeTmp(t, validYAML))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Collectors.Net.Enabled {
		t.Error("malformed bool should leave YAML value intact")
	}
}

func TestSuggestLevenshtein(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"collecor", "collectors"},
		{"ageent", "agent"},
		{"rues", "rules"},
		{"banana", ""},
	}
	for _, tc := range tests {
		if got := suggest(topLevelKeys, tc.input); got != tc.want {
			t.Errorf("suggest(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestEmptyRulesPathEntryInvalid(t *testing.T) {
	y := `
collectors:
  process:
    enabled: true
rules:
  paths:
    - "   "
`
	_, err := Load(writeTmp(t, y))
	if err == nil || !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("want ErrInvalidConfig, got %v", err)
	}
}
