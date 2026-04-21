// Package config loads and validates the agent's YAML configuration.
//
// Phase 1 shape (see IMPLEMENTATION.md §3.7). Validation is intentionally
// strict — unknown keys produce actionable errors with suggested corrections.
package config

import (
	"errors"
	"fmt"
)

// Config is the root agent configuration.
type Config struct {
	Agent      Agent      `yaml:"agent"`
	Collectors Collectors `yaml:"collectors"`
	Rules      Rules      `yaml:"rules"`
	Output     Output     `yaml:"output"`
}

// Agent holds host-level agent settings.
type Agent struct {
	HostIDFile string `yaml:"host_id_file"`
	LogLevel   string `yaml:"log_level"`
}

// Collectors toggles individual collectors on or off.
type Collectors struct {
	Process ProcessCollector `yaml:"process"`
	File    FileCollector    `yaml:"file"`
	Net     NetCollector     `yaml:"net"`
}

// ProcessCollector configures the process lifecycle collector.
type ProcessCollector struct {
	Enabled bool `yaml:"enabled"`
}

// FileCollector configures the file-event collector, including path filters.
type FileCollector struct {
	Enabled      bool     `yaml:"enabled"`
	IncludePaths []string `yaml:"include_paths"`
	ExcludePaths []string `yaml:"exclude_paths"`
}

// NetCollector configures the network-event collector.
type NetCollector struct {
	Enabled bool `yaml:"enabled"`
}

// Rules configures rule loading.
type Rules struct {
	Paths []string `yaml:"paths"`
}

// Output configures the event sink.
type Output struct {
	Kind string `yaml:"kind"`
}

// ErrNotImplemented is returned by loaders that are not yet wired up.
var ErrNotImplemented = errors.New("config: loader not yet implemented")

// Load reads and validates a YAML file at path.
// Phase 1 scaffold: signature only.
func Load(path string) (*Config, error) {
	return nil, fmt.Errorf("%w: Load(%q)", ErrNotImplemented, path)
}

// Validate returns nil if the config is internally consistent.
// Phase 1 scaffold: signature only.
func (c *Config) Validate() error {
	return ErrNotImplemented
}
