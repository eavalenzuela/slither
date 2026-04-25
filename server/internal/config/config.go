// Package config loads and validates the server's YAML configuration.
//
// Phase 2 §4.1 task #31 scaffold: mirrors agent/internal/config's strict decode
// (yaml.v3 + KnownFields) + Levenshtein typo suggestions. The struct shape is
// intentionally forward-looking — later Phase 2 tasks (#32 Postgres, #33/#34
// mTLS + enroll, #38 ClickHouse, #41 console) fill in real validation as each
// subsystem lands. #31 only validates what it actually uses: log level.
package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the root server configuration.
type Config struct {
	Server    Server    `yaml:"server"`
	Listeners Listeners `yaml:"listeners"`
	Storage   Storage   `yaml:"storage"`
	MTLS      MTLS      `yaml:"mtls"`
	Console   Console   `yaml:"console"`
}

// Server holds top-level server settings.
type Server struct {
	LogLevel string `yaml:"log_level"`
}

// Listeners groups every TCP listen address the server owns.
type Listeners struct {
	// GRPC is the mTLS-authenticated agent Session listener.
	GRPC string `yaml:"grpc"`
	// Enroll is a separate pre-cert listener for AgentService.Enroll.
	Enroll string `yaml:"enroll"`
	// Console is the HTTP listener for the HTMX console.
	Console string `yaml:"console"`
}

// Storage groups backing stores.
type Storage struct {
	Postgres Postgres   `yaml:"postgres"`
	CH       ClickHouse `yaml:"clickhouse"`
}

// Postgres configures the control-plane database.
type Postgres struct {
	DSN string `yaml:"dsn"`
}

// ClickHouse configures the event store and the writer cadence
// (ADR-0031). Zero values fall back to the writer's documented defaults.
type ClickHouse struct {
	DSN           string        `yaml:"dsn"`
	BatchSize     int           `yaml:"batch_size"`
	FlushInterval time.Duration `yaml:"flush_interval"`
}

// MTLS configures CA and server cert material.
type MTLS struct {
	CACert     string `yaml:"ca_cert"`
	CAKey      string `yaml:"ca_key"`
	ServerCert string `yaml:"server_cert"`
	ServerKey  string `yaml:"server_key"`
}

// Console configures the operator UI.
type Console struct {
	SessionKeyFile string `yaml:"session_key_file"`
}

// ErrInvalidConfig wraps every user-visible config error. Callers use
// errors.Is to distinguish config problems from IO problems.
var ErrInvalidConfig = errors.New("config: invalid")

var validLogLevels = []string{"debug", "info", "warn", "error"}

var topLevelKeys = []string{"server", "listeners", "storage", "mtls", "console"}

// Load reads, decodes, env-overrides, and validates the YAML file at path.
func Load(path string) (*Config, error) {
	f, err := os.Open(path) //nolint:gosec // operator-supplied config path
	if err != nil {
		return nil, fmt.Errorf("config: open %q: %w", path, err)
	}
	defer f.Close()

	raw, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("config: read %q: %w", path, err)
	}

	if err := checkTopLevel(raw); err != nil {
		return nil, err
	}

	var cfg Config
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: %s", ErrInvalidConfig, cleanYAMLError(err))
	}

	cfg.applyEnv()

	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func checkTopLevel(raw []byte) error {
	var top map[string]yaml.Node
	if err := yaml.Unmarshal(raw, &top); err != nil {
		return nil
	}
	for k := range top {
		if known(topLevelKeys, k) {
			continue
		}
		if sug := suggest(topLevelKeys, k); sug != "" {
			return fmt.Errorf("%w: unknown key %q — did you mean %q?", ErrInvalidConfig, k, sug)
		}
		return fmt.Errorf("%w: unknown key %q (valid: %s)", ErrInvalidConfig, k, strings.Join(topLevelKeys, ", "))
	}
	return nil
}

// Validate is deliberately narrow in #31: only fields the scaffold actually
// reads are checked. Later tasks add real validation as their subsystems come
// online (#32 Postgres DSN, #33 mTLS paths, #38 CH DSN, #40/#41 listeners).
func (c *Config) Validate() error {
	if c == nil {
		return fmt.Errorf("%w: nil config", ErrInvalidConfig)
	}
	if c.Server.LogLevel == "" {
		c.Server.LogLevel = "info"
	}
	if !known(validLogLevels, c.Server.LogLevel) {
		return fmt.Errorf("%w: server.log_level %q (valid: %s)",
			ErrInvalidConfig, c.Server.LogLevel, strings.Join(validLogLevels, ", "))
	}
	return nil
}

func (c *Config) applyEnv() {
	if v := os.Getenv("SLITHER_SERVER_LOG_LEVEL"); v != "" {
		c.Server.LogLevel = v
	}
	if v := os.Getenv("SLITHER_LISTENERS_GRPC"); v != "" {
		c.Listeners.GRPC = v
	}
	if v := os.Getenv("SLITHER_LISTENERS_ENROLL"); v != "" {
		c.Listeners.Enroll = v
	}
	if v := os.Getenv("SLITHER_LISTENERS_CONSOLE"); v != "" {
		c.Listeners.Console = v
	}
	if v := os.Getenv("SLITHER_STORAGE_POSTGRES_DSN"); v != "" {
		c.Storage.Postgres.DSN = v
	}
	if v := os.Getenv("SLITHER_STORAGE_CLICKHOUSE_DSN"); v != "" {
		c.Storage.CH.DSN = v
	}
}

func known(set []string, s string) bool {
	for _, v := range set {
		if v == s {
			return true
		}
	}
	return false
}

func suggest(candidates []string, input string) string {
	type scored struct {
		s string
		d int
	}
	out := make([]scored, 0, len(candidates))
	for _, c := range candidates {
		out = append(out, scored{c, editDistance(input, c)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].d < out[j].d })
	if len(out) == 0 || out[0].d > 2 {
		return ""
	}
	return out[0].s
}

func editDistance(a, b string) int {
	if a == b {
		return 0
	}
	ra, rb := []rune(a), []rune(b)
	prev := make([]int, len(rb)+1)
	curr := make([]int, len(rb)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ra); i++ {
		curr[0] = i
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			curr[j] = min3(curr[j-1]+1, prev[j]+1, prev[j-1]+cost)
		}
		prev, curr = curr, prev
	}
	return prev[len(rb)]
}

func min3(a, b, c int) int {
	m := a
	if b < m {
		m = b
	}
	if c < m {
		m = c
	}
	return m
}

func cleanYAMLError(err error) string {
	return strings.TrimPrefix(err.Error(), "yaml: ")
}
