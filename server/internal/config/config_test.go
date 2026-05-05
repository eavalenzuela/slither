package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validYAML = `
server:
  log_level: info
listeners:
  grpc: ":9443"
  enroll: ":9444"
  console: ":8080"
storage:
  postgres:
    dsn: postgres://localhost/slither
  clickhouse:
    dsn: clickhouse://localhost:9000/slither
mtls:
  ca_cert: /etc/slither/pki/ca.crt
  ca_key: /etc/slither/pki/ca.key
  server_cert: /etc/slither/pki/server.crt
  server_key: /etc/slither/pki/server.key
console:
  session_key_file: /var/lib/slither/session.key
`

func writeTmp(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "server.yaml")
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
	if cfg.Server.LogLevel != "info" {
		t.Errorf("log_level = %q", cfg.Server.LogLevel)
	}
	if cfg.Listeners.GRPC != ":9443" || cfg.Listeners.Enroll != ":9444" || cfg.Listeners.Console != ":8080" {
		t.Errorf("listeners = %+v", cfg.Listeners)
	}
	if cfg.Storage.Postgres.DSN == "" || cfg.Storage.CH.DSN == "" {
		t.Errorf("storage DSNs empty: %+v", cfg.Storage)
	}
	if cfg.MTLS.CACert == "" || cfg.MTLS.ServerKey == "" {
		t.Errorf("mtls fields empty: %+v", cfg.MTLS)
	}
}

func TestLoadDefaultsLogLevel(t *testing.T) {
	cfg, err := Load(writeTmp(t, "server: {}\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.LogLevel != "info" {
		t.Errorf("default log_level = %q, want info", cfg.Server.LogLevel)
	}
}

func TestLoadUnknownTopLevelKeySuggests(t *testing.T) {
	_, err := Load(writeTmp(t, "listener:\n  grpc: ':9443'\n"))
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("not wrapped with ErrInvalidConfig: %v", err)
	}
	if !strings.Contains(err.Error(), `did you mean "listeners"`) {
		t.Errorf("missing suggestion: %v", err)
	}
}

func TestLoadUnknownNestedKeyStrict(t *testing.T) {
	y := "server:\n  loglevel: info\n"
	_, err := Load(writeTmp(t, y))
	if err == nil {
		t.Fatal("expected error on unknown nested key")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("not wrapped with ErrInvalidConfig: %v", err)
	}
}

func TestLoadBadLogLevel(t *testing.T) {
	_, err := Load(writeTmp(t, "server:\n  log_level: verbose\n"))
	if err == nil || !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("want ErrInvalidConfig, got %v", err)
	}
}

func TestEnvOverride(t *testing.T) {
	t.Setenv("SLITHER_SERVER_LOG_LEVEL", "debug")
	t.Setenv("SLITHER_LISTENERS_GRPC", ":7000")
	t.Setenv("SLITHER_STORAGE_POSTGRES_DSN", "postgres://env/slither")
	cfg, err := Load(writeTmp(t, "server:\n  log_level: info\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.LogLevel != "debug" {
		t.Errorf("log_level = %q", cfg.Server.LogLevel)
	}
	if cfg.Listeners.GRPC != ":7000" {
		t.Errorf("grpc listener = %q", cfg.Listeners.GRPC)
	}
	if cfg.Storage.Postgres.DSN != "postgres://env/slither" {
		t.Errorf("pg dsn = %q", cfg.Storage.Postgres.DSN)
	}
}

func TestValidateOIDC_PartialBlockRejected(t *testing.T) {
	yaml := "server:\n  log_level: info\nconsole:\n  oidc:\n    issuer_url: https://idp.example.com\n"
	_, err := Load(writeTmp(t, yaml))
	if err == nil || !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("want ErrInvalidConfig on partial OIDC block, got %v", err)
	}
}

func TestValidateOIDC_RoleMappingsRequired(t *testing.T) {
	yaml := `server:
  log_level: info
console:
  oidc:
    issuer_url: https://idp.example.com
    client_id: slither
    client_secret: shh
    redirect_url: https://slither.example.com/oidc/callback
`
	_, err := Load(writeTmp(t, yaml))
	if err == nil || !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("want ErrInvalidConfig on missing role_mappings, got %v", err)
	}
}

func TestValidateOIDC_BadRole(t *testing.T) {
	yaml := `server:
  log_level: info
console:
  oidc:
    issuer_url: https://idp.example.com
    client_id: slither
    client_secret: shh
    redirect_url: https://slither.example.com/oidc/callback
    role_mappings:
      slither-everyone: superuser
`
	_, err := Load(writeTmp(t, yaml))
	if err == nil || !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("want ErrInvalidConfig on invalid role, got %v", err)
	}
}

func TestValidateOIDC_AcceptsFullBlock(t *testing.T) {
	yaml := `server:
  log_level: info
console:
  oidc:
    issuer_url: https://idp.example.com
    client_id: slither
    client_secret: shh
    redirect_url: https://slither.example.com/oidc/callback
    role_mappings:
      slither-admin:   admin
      slither-analyst: analyst
      slither-viewer:  viewer
`
	cfg, err := Load(writeTmp(t, yaml))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Console.OIDC.Enabled() {
		t.Error("OIDC.Enabled() false on a fully-populated block")
	}
}

func TestValidateOIDC_EmptyBlockOK(t *testing.T) {
	cfg, err := Load(writeTmp(t, "server:\n  log_level: info\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Console.OIDC.Enabled() {
		t.Error("OIDC.Enabled() true on empty block")
	}
}
