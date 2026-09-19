package config

import (
	"strings"
	"testing"
)

func TestKernelCollectorConfigAndEnv(t *testing.T) {
	body := strings.Replace(validYAML, "  net:\n    enabled: true\n",
		"  net:\n    enabled: true\n  kernel:\n    enabled: true\n", 1)
	cfg, err := Load(writeTmp(t, body))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Collectors.Kernel.Enabled {
		t.Error("kernel.enabled should parse true")
	}

	t.Setenv("SLITHER_COLLECTORS_KERNEL_ENABLED", "false")
	cfg, err = Load(writeTmp(t, body))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Collectors.Kernel.Enabled {
		t.Error("SLITHER_COLLECTORS_KERNEL_ENABLED=false should disable the kernel collector")
	}
}
