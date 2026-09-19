package config

import (
	"strings"
	"testing"
)

func TestContainerCollectorConfigAndEnv(t *testing.T) {
	body := strings.Replace(validYAML, "  net:\n    enabled: true\n",
		"  net:\n    enabled: true\n  container:\n    enabled: true\n", 1)
	cfg, err := Load(writeTmp(t, body))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Collectors.Container.Enabled {
		t.Error("container.enabled should parse true")
	}
	t.Setenv("SLITHER_COLLECTORS_CONTAINER_ENABLED", "false")
	cfg, err = Load(writeTmp(t, body))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Collectors.Container.Enabled {
		t.Error("env override should disable the container collector")
	}
}
