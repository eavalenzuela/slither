package config

import (
	"strings"
	"testing"
)

func TestDNSCollectorConfigAndEnv(t *testing.T) {
	body := strings.Replace(validYAML, "  net:\n    enabled: true\n",
		"  net:\n    enabled: true\n  dns:\n    enabled: true\n", 1)
	cfg, err := Load(writeTmp(t, body))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Collectors.DNS.Enabled {
		t.Error("dns.enabled should parse true")
	}
	t.Setenv("SLITHER_COLLECTORS_DNS_ENABLED", "0")
	cfg, err = Load(writeTmp(t, body))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Collectors.DNS.Enabled {
		t.Error("env override should disable the dns collector")
	}
}
