// Package config loads and validates the agent's YAML configuration.
//
// Phase 1 shape (see IMPLEMENTATION.md §3.7). Validation is intentionally
// strict — unknown keys produce actionable errors with suggested corrections.
package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the root agent configuration.
type Config struct {
	Agent      Agent       `yaml:"agent"`
	Collectors Collectors  `yaml:"collectors"`
	Rules      Rules       `yaml:"rules"`
	Output     Output      `yaml:"output"`
	Extensions []Extension `yaml:"extensions"`
}

// Extension declares one out-of-process first-party extension the agent
// supervises (Phase 6 #107). The agent verifies the binary's cosign
// signature on every spawn, intersects the operator-declared
// capabilities with what the extension claims on Hello, and supervises
// the process with backoff.
type Extension struct {
	// Name is the operator-friendly identifier; surfaces in logs +
	// telemetry. Must be unique across the extensions list.
	Name string `yaml:"name"`
	// BinaryPath is the absolute path to the extension binary.
	BinaryPath string `yaml:"binary_path"`
	// SignaturePath points at the cosign sign-blob output. When empty,
	// the agent looks for {BinaryPath}.sig + {BinaryPath}.pem alongside.
	SignaturePath string `yaml:"signature_path"`
	// CertificatePath is the cosign-keyless certificate. When empty,
	// the agent looks for {BinaryPath}.pem alongside.
	CertificatePath string `yaml:"certificate_path"`
	// Capabilities the operator authorises this extension to hold.
	// Any capability the extension declares on Hello that is not in
	// this list is refused; the connection is torn down and the
	// extension is restarted with backoff.
	Capabilities []string `yaml:"capabilities"`
	// SignatureVerification controls signing enforcement. "cosign" (the
	// default) shells out to the cosign CLI; "disabled" skips verify
	// entirely (dev/CI only). Production deployments must leave this
	// at the default.
	SignatureVerification string `yaml:"signature_verification"`
	// RSSLimitMiB is a soft RSS cap enforced via setrlimit(RLIMIT_AS).
	// Zero defaults to 256 MiB. Process exceeding the cap is killed by
	// the kernel; the agent's supervisor records ext_rss_kills and
	// restarts under backoff.
	RSSLimitMiB int `yaml:"rss_limit_mib"`
	// CosignIdentityRegexp is the certificate-identity regexp passed
	// to `cosign verify-blob`. Defaults to the slither release pipeline
	// identity. Operators with their own signing pipeline can override.
	CosignIdentityRegexp string `yaml:"cosign_identity_regexp"`
	// CosignOIDCIssuer is the issuer claim cosign requires. Defaults
	// to GitHub's actions issuer for keyless OIDC verification.
	CosignOIDCIssuer string `yaml:"cosign_oidc_issuer"`
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
//
// GRPC fields are only consulted when Kind == "grpc". They're still
// present in the struct so unknown-key errors fire cleanly when the
// operator misspells one, regardless of the selected kind.
type Output struct {
	Kind string   `yaml:"kind"`
	GRPC GRPCSink `yaml:"grpc"`
}

// GRPCSink configures the grpc output sink (IMPLEMENTATION.md §4.1 #35).
type GRPCSink struct {
	ServerAddr        string        `yaml:"server_addr"`
	CAPath            string        `yaml:"ca_path"`
	CertPath          string        `yaml:"cert_path"`
	KeyPath           string        `yaml:"key_path"`
	HostIDPath        string        `yaml:"host_id_path"`
	HeartbeatInterval time.Duration `yaml:"heartbeat_interval"`
	BufferSize        int           `yaml:"buffer_size"`
	// KeystoreDir, when non-empty, switches cert loading to the
	// Phase 5 #98 keystore (kernel keyring on Linux when usable,
	// file under this dir otherwise). Empty preserves the legacy
	// path-triplet shape (CAPath/CertPath/KeyPath).
	KeystoreDir string `yaml:"keystore_dir"`
	// Buffer is the Phase 5 #96 offline disk-buffer config. Empty Dir
	// (the zero value) disables disk buffering — the in-memory
	// channel still drops oldest on overflow exactly as before.
	Buffer GRPCBuffer `yaml:"buffer"`
}

// GRPCBuffer configures the on-disk replay buffer (Phase 5 #96).
type GRPCBuffer struct {
	// Dir is the on-disk root for spooled segments. When empty,
	// disk buffering is disabled.
	Dir string `yaml:"dir"`
	// DiskMaxBytes caps total spool size; oldest segments are
	// evicted when the cap is exceeded. Zero defaults to 256 MiB.
	DiskMaxBytes int64 `yaml:"disk_max_bytes"`
	// MaxAge bounds replay-on-reconnect; events older than this
	// are skipped to avoid post-multi-day-disconnection backfill
	// storms. Zero defaults to 6h.
	MaxAge time.Duration `yaml:"max_age"`
	// SegmentBytes is the per-segment rotation threshold. Zero
	// defaults to 16 MiB.
	SegmentBytes int64 `yaml:"segment_bytes"`
}

// ErrInvalidConfig is returned when validation fails. Callers can use
// errors.Is to distinguish user-config errors from IO errors.
var ErrInvalidConfig = errors.New("config: invalid")

// validLogLevels are the log levels accepted by agent.log_level.
var validLogLevels = []string{"debug", "info", "warn", "error"}

// validOutputKinds are the sink kinds recognised today. stdout for dev +
// scenario tests, grpc for production (Phase 2 §4.1 #35).
var validOutputKinds = []string{"stdout", "grpc"}

// topLevelKeys is the authoritative set of root keys for typo suggestions.
var topLevelKeys = []string{"agent", "collectors", "rules", "output", "extensions"}

// validSignatureVerification are the supported per-extension verify modes.
var validSignatureVerification = []string{"cosign", "disabled"}

// validExtensionCapabilities are the wire-defined capability strings.
// They mirror the Capability enum on extension.proto via lowercase
// strings the operator writes in YAML; the supervisor maps to the
// proto enum when handshaking with extensions.
var validExtensionCapabilities = []string{"ocsf_emit", "live_query_respond", "snapshot_provide"}

// Load reads, decodes, env-overrides, and validates the YAML file at path.
// Top-level unknown keys come back as "did you mean X?" errors; every other
// structural mismatch is surfaced with the offending path.
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

// checkTopLevel decodes the document into a map so we can flag unknown
// top-level keys with a "did you mean?" suggestion before strict decode
// gives a less friendly error.
func checkTopLevel(raw []byte) error {
	var top map[string]yaml.Node
	if err := yaml.Unmarshal(raw, &top); err != nil {
		// Structural errors are better-surfaced by the strict pass.
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

// Validate returns nil if the config is internally consistent. It runs after
// YAML decode and env overrides.
func (c *Config) Validate() error {
	if c == nil {
		return fmt.Errorf("%w: nil config", ErrInvalidConfig)
	}
	if c.Agent.LogLevel == "" {
		c.Agent.LogLevel = "info"
	}
	if !known(validLogLevels, c.Agent.LogLevel) {
		return fmt.Errorf("%w: agent.log_level %q (valid: %s)",
			ErrInvalidConfig, c.Agent.LogLevel, strings.Join(validLogLevels, ", "))
	}
	if c.Output.Kind == "" {
		c.Output.Kind = "stdout"
	}
	if !known(validOutputKinds, c.Output.Kind) {
		return fmt.Errorf("%w: output.kind %q (valid: %s)",
			ErrInvalidConfig, c.Output.Kind, strings.Join(validOutputKinds, ", "))
	}
	if c.Output.Kind == "grpc" {
		g := &c.Output.GRPC
		if g.ServerAddr == "" {
			return fmt.Errorf("%w: output.grpc.server_addr required when kind=grpc", ErrInvalidConfig)
		}
		if g.CAPath == "" || g.CertPath == "" || g.KeyPath == "" {
			return fmt.Errorf("%w: output.grpc requires ca_path, cert_path, key_path", ErrInvalidConfig)
		}
		if g.HostIDPath == "" {
			return fmt.Errorf("%w: output.grpc.host_id_path required", ErrInvalidConfig)
		}
		if g.HeartbeatInterval <= 0 {
			g.HeartbeatInterval = 30 * time.Second // §2.4 default
		}
		if g.BufferSize <= 0 {
			g.BufferSize = 4096
		}
	}
	if !c.Collectors.Process.Enabled && !c.Collectors.File.Enabled && !c.Collectors.Net.Enabled {
		return fmt.Errorf("%w: no collectors enabled", ErrInvalidConfig)
	}
	for i, p := range c.Rules.Paths {
		if strings.TrimSpace(p) == "" {
			return fmt.Errorf("%w: rules.paths[%d] is empty", ErrInvalidConfig, i)
		}
	}
	if err := c.validateExtensions(); err != nil {
		return err
	}
	return nil
}

// validateExtensions enforces the per-extension invariants. Defaults
// land here so the supervisor can read fields directly without
// re-deriving them.
func (c *Config) validateExtensions() error {
	seen := make(map[string]int, len(c.Extensions))
	for i := range c.Extensions {
		ext := &c.Extensions[i]
		if strings.TrimSpace(ext.Name) == "" {
			return fmt.Errorf("%w: extensions[%d].name required", ErrInvalidConfig, i)
		}
		if dup, ok := seen[ext.Name]; ok {
			return fmt.Errorf("%w: extensions[%d].name %q duplicates extensions[%d].name", ErrInvalidConfig, i, ext.Name, dup)
		}
		seen[ext.Name] = i
		if !strings.HasPrefix(ext.BinaryPath, "/") {
			return fmt.Errorf("%w: extensions[%d=%s].binary_path must be absolute", ErrInvalidConfig, i, ext.Name)
		}
		if ext.SignatureVerification == "" {
			ext.SignatureVerification = "cosign"
		}
		if !known(validSignatureVerification, ext.SignatureVerification) {
			return fmt.Errorf("%w: extensions[%d=%s].signature_verification %q (valid: %s)",
				ErrInvalidConfig, i, ext.Name, ext.SignatureVerification, strings.Join(validSignatureVerification, ", "))
		}
		if len(ext.Capabilities) == 0 {
			return fmt.Errorf("%w: extensions[%d=%s].capabilities cannot be empty", ErrInvalidConfig, i, ext.Name)
		}
		for j, cap := range ext.Capabilities {
			if !known(validExtensionCapabilities, cap) {
				return fmt.Errorf("%w: extensions[%d=%s].capabilities[%d]=%q (valid: %s)",
					ErrInvalidConfig, i, ext.Name, j, cap, strings.Join(validExtensionCapabilities, ", "))
			}
		}
		if ext.RSSLimitMiB < 0 {
			return fmt.Errorf("%w: extensions[%d=%s].rss_limit_mib cannot be negative", ErrInvalidConfig, i, ext.Name)
		}
		if ext.RSSLimitMiB == 0 {
			ext.RSSLimitMiB = 256
		}
		if ext.SignatureVerification == "cosign" {
			if ext.CosignIdentityRegexp == "" {
				ext.CosignIdentityRegexp = `^https://github\.com/t3rmit3/slither/\.github/workflows/release\.yml@refs/tags/v.*$`
			}
			if ext.CosignOIDCIssuer == "" {
				ext.CosignOIDCIssuer = "https://token.actions.githubusercontent.com"
			}
		}
	}
	return nil
}

// applyEnv applies a small, explicit set of env-var overrides. Unknown or
// empty env vars are silently ignored; malformed booleans fall back to the
// YAML value so a stray shell export doesn't take the agent down.
func (c *Config) applyEnv() {
	if v := os.Getenv("SLITHER_AGENT_LOG_LEVEL"); v != "" {
		c.Agent.LogLevel = v
	}
	if v := os.Getenv("SLITHER_AGENT_HOST_ID_FILE"); v != "" {
		c.Agent.HostIDFile = v
	}
	if v := os.Getenv("SLITHER_OUTPUT_KIND"); v != "" {
		c.Output.Kind = v
	}
	if v := os.Getenv("SLITHER_COLLECTORS_PROCESS_ENABLED"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			c.Collectors.Process.Enabled = b
		}
	}
	if v := os.Getenv("SLITHER_COLLECTORS_FILE_ENABLED"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			c.Collectors.File.Enabled = b
		}
	}
	if v := os.Getenv("SLITHER_COLLECTORS_NET_ENABLED"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			c.Collectors.Net.Enabled = b
		}
	}
	if v := os.Getenv("SLITHER_RULES_PATHS"); v != "" {
		parts := strings.Split(v, ",")
		paths := parts[:0]
		for _, p := range parts {
			if p = strings.TrimSpace(p); p != "" {
				paths = append(paths, p)
			}
		}
		c.Rules.Paths = paths
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

// suggest returns the closest candidate by Levenshtein distance if it is
// within edit-distance 2 of input, otherwise empty. Two is enough to catch
// single-char typos and transpositions ("collecor" → "collectors") without
// proposing wild guesses.
func suggest(candidates []string, input string) string {
	type scored struct {
		s string
		d int
	}
	scored_ := make([]scored, 0, len(candidates))
	for _, c := range candidates {
		scored_ = append(scored_, scored{c, editDistance(input, c)})
	}
	sort.Slice(scored_, func(i, j int) bool { return scored_[i].d < scored_[j].d })
	if len(scored_) == 0 || scored_[0].d > 2 {
		return ""
	}
	return scored_[0].s
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

// cleanYAMLError strips the "yaml: " prefix and "line N:" noise yaml.v3
// produces for strict-decode failures so the wrapped error reads cleanly.
func cleanYAMLError(err error) string {
	s := err.Error()
	s = strings.TrimPrefix(s, "yaml: ")
	return s
}
