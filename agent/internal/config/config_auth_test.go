package config

import (
	"strings"
	"testing"
)

func TestAuthCollectorConfigParses(t *testing.T) {
	body := strings.Replace(validYAML, "  net:\n    enabled: true\n",
		"  net:\n    enabled: true\n  auth:\n    enabled: true\n    libpam_path: /opt/pam/libpam.so.0\n", 1)
	cfg, err := Load(writeTmp(t, body))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Collectors.Auth.Enabled {
		t.Error("auth.enabled should parse true")
	}
	if cfg.Collectors.Auth.LibpamPath != "/opt/pam/libpam.so.0" {
		t.Errorf("libpam_path = %q", cfg.Collectors.Auth.LibpamPath)
	}
}

func TestAuthCollectorDefaultsOff(t *testing.T) {
	cfg, err := Load(writeTmp(t, validYAML))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Collectors.Auth.Enabled {
		t.Error("auth collector must be opt-in when the block is absent")
	}
}

func TestAuthCollectorEnvOverride(t *testing.T) {
	t.Setenv("SLITHER_COLLECTORS_AUTH_ENABLED", "true")
	cfg, err := Load(writeTmp(t, validYAML))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Collectors.Auth.Enabled {
		t.Error("SLITHER_COLLECTORS_AUTH_ENABLED=true should enable the auth collector")
	}
}

// TestAuthOnlyConfigIsValid — the "no collectors enabled" guard must
// count auth as a collector, so an auth-only deployment (a bastion
// that wants login telemetry and nothing else) is accepted.
func TestAuthOnlyConfigIsValid(t *testing.T) {
	body := strings.NewReplacer(
		"  process:\n    enabled: true\n", "  process:\n    enabled: false\n",
		"    enabled: true\n    include_paths:", "    enabled: false\n    include_paths:",
		"  net:\n    enabled: true\n", "  net:\n    enabled: false\n  auth:\n    enabled: true\n",
	).Replace(validYAML)
	if _, err := Load(writeTmp(t, body)); err != nil {
		t.Fatalf("auth-only config should validate: %v", err)
	}
}
