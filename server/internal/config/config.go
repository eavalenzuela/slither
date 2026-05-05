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
	// GraphsDir is the on-disk root for the alert flow-graph SVG
	// cache (Phase 3 #64). Empty falls back to /var/lib/slither/graphs
	// — matches the systemd unit's StateDirectory pattern.
	GraphsDir string `yaml:"graphs_dir"`
	// ArtefactsDir is the on-disk root for collect_artifacts result
	// blobs (Phase 4 #81). Empty falls back to
	// /var/lib/slither/artefacts — same StateDirectory pattern as
	// GraphsDir. Bundles land as <action_id>.tgz.
	ArtefactsDir string `yaml:"artefacts_dir"`
	// OIDC, when populated, enables Phase 6 #113 SSO. The /login
	// page renders a "Sign in with SSO" button alongside the local
	// username/password form; users provisioned via SSO carry
	// users.oidc_subject and have NULL password_hash. Local-user
	// login keeps working alongside SSO so the bootstrap admin can
	// still log in if the IdP is down.
	OIDC ConsoleOIDC `yaml:"oidc"`
}

// ConsoleOIDC is the SSO config block. Empty/zero means SSO is off
// — the /login page hides the SSO button and the OIDC routes return
// 404. Validation runs in Validate() and refuses partially-filled
// configs (an operator who set issuer but not client_id sees a clear
// error rather than a 5xx at first sign-in).
type ConsoleOIDC struct {
	// IssuerURL is the IdP's OIDC discovery base. The handler
	// appends /.well-known/openid-configuration via the go-oidc
	// provider constructor, which expects the bare issuer URL.
	// Empty disables SSO.
	IssuerURL string `yaml:"issuer_url"`

	// ClientID + ClientSecret are the operator's IdP-registered
	// confidential-client credentials. Auth-code flow with PKCE
	// still benefits from a confidential client for the token
	// endpoint exchange.
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`

	// RedirectURL is the public URL the IdP redirects back to after
	// auth. Must end in /oidc/callback (the route the handler
	// registers); operators set this to e.g. https://slither.acme.io/oidc/callback.
	RedirectURL string `yaml:"redirect_url"`

	// Scopes additive to the OIDC defaults. The handler always
	// requests "openid". Operators add "email" / "profile" / IdP-
	// specific group scopes here. Empty defaults to ["openid",
	// "email", "profile"].
	Scopes []string `yaml:"scopes"`

	// RoleClaim names the ID-token claim carrying the operator's
	// IdP role. Default "groups" matches Dex / Okta / Azure AD's
	// group-membership claim shape.
	RoleClaim string `yaml:"role_claim"`

	// RoleMappings translates a claim value to a Slither role. The
	// handler walks the claim's array values in order; the first
	// mapping that hits sets the user's role. No match → reject the
	// login with auth.oidc.failure reason="no_role_mapping".
	// Operators express this as e.g.:
	//   role_mappings:
	//     slither-admin:   admin
	//     slither-analyst: analyst
	//     slither-viewer:  viewer
	RoleMappings map[string]string `yaml:"role_mappings"`

	// UsernameClaim picks the claim used to populate users.username
	// on first SSO login. Default "email".
	UsernameClaim string `yaml:"username_claim"`
}

// Enabled reports whether the OIDC block is populated enough to wire
// the SSO routes. Returns true only when every load-bearing field is
// set; partial configs fail Validate() upfront.
func (c ConsoleOIDC) Enabled() bool {
	return c.IssuerURL != "" && c.ClientID != "" && c.ClientSecret != "" && c.RedirectURL != ""
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
	if err := c.Console.OIDC.validate(); err != nil {
		return err
	}
	return nil
}

// validate enforces the all-or-nothing shape on the OIDC block. A
// partially-filled block (e.g. issuer set but client_id blank) is a
// likely operator typo; failing Validate at boot beats discovering it
// at first sign-in.
func (o *ConsoleOIDC) validate() error {
	if o == nil {
		return nil
	}
	anyField := o.IssuerURL != "" || o.ClientID != "" || o.ClientSecret != "" || o.RedirectURL != ""
	if !anyField {
		return nil
	}
	missing := []string{}
	if o.IssuerURL == "" {
		missing = append(missing, "issuer_url")
	}
	if o.ClientID == "" {
		missing = append(missing, "client_id")
	}
	if o.ClientSecret == "" {
		missing = append(missing, "client_secret")
	}
	if o.RedirectURL == "" {
		missing = append(missing, "redirect_url")
	}
	if len(missing) > 0 {
		return fmt.Errorf("%w: console.oidc partially set; missing: %s",
			ErrInvalidConfig, strings.Join(missing, ", "))
	}
	if len(o.RoleMappings) == 0 {
		return fmt.Errorf("%w: console.oidc.role_mappings required when SSO enabled (no IdP claim → no role grant)",
			ErrInvalidConfig)
	}
	for claim, role := range o.RoleMappings {
		switch role {
		case "viewer", "analyst", "admin":
		default:
			return fmt.Errorf("%w: console.oidc.role_mappings[%q]=%q invalid (valid: viewer, analyst, admin)",
				ErrInvalidConfig, claim, role)
		}
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
