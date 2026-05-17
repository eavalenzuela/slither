package ruleengine

import (
	"context"
	"testing"

	"github.com/t3rmit3/slither/agent/internal/telemetry"
	"github.com/t3rmit3/slither/pkg/ocsf"
	"github.com/t3rmit3/slither/pkg/ruleast"
)

// runFileEvent feeds a single file-system event through a one-rule engine
// and returns the number of DetectionFinding events emitted.
func runFileEvent(t *testing.T, rule *ruleast.Rule, ev *ocsf.FileSystemActivity) int {
	t.Helper()
	compiled, err := CompileRules([]*ruleast.Rule{rule}, nil, nil)
	if err != nil {
		t.Fatalf("CompileRules: %v", err)
	}
	eng := New(compiled, telemetry.NewCounters()).(*engine)

	in := make(chan ocsf.Event, 1)
	in <- ev
	close(in)

	done := make(chan error, 1)
	go func() { done <- eng.Run(context.Background(), in) }()

	var findings int
	for out := range eng.Output() {
		if _, ok := out.(*ocsf.DetectionFinding); ok {
			findings++
		}
	}
	<-done
	return findings
}

// TestNewFileRulesFireAndExclude exercises the three file_event rules added
// from the theorycraft backlog (#5/#9/#10) against the shipped YAML: an
// attacker-shaped write must fire, a package-manager write must not, and a
// path that misses the suffix gate must not.
func TestNewFileRulesFireAndExclude(t *testing.T) {
	cases := []struct {
		name     string
		rulePath string
		target   string
		writer   string
		want     int
	}{
		{"systemd-unit-attacker", "rules/linux/file-systemd-system-unit-write.yml",
			"/etc/systemd/system/evil.service", "/tmp/dropper", 1},
		{"systemd-unit-dpkg", "rules/linux/file-systemd-system-unit-write.yml",
			"/etc/systemd/system/nginx.service", "/usr/bin/dpkg", 0},
		{"systemd-non-unit-suffix", "rules/linux/file-systemd-system-unit-write.yml",
			"/etc/systemd/system/override.conf", "/tmp/dropper", 0},

		{"ld-preload-attacker", "rules/linux/file-ld-preload-write.yml",
			"/etc/ld.so.preload", "/tmp/implant", 1},
		{"ld-preload-dpkg", "rules/linux/file-ld-preload-write.yml",
			"/etc/ld.so.preload", "/usr/bin/dpkg", 0},

		{"pam-attacker", "rules/linux/file-pam-module-drop.yml",
			"/lib/x86_64-linux-gnu/security/pam_evil.so", "/tmp/implant", 1},
		{"pam-dpkg", "rules/linux/file-pam-module-drop.yml",
			"/usr/lib/x86_64-linux-gnu/security/pam_unix.so", "/usr/bin/dpkg", 0},

		{"cloud-cred-by-cat", "rules/linux/file-cloud-cred-file-read.yml",
			"/home/u/.kube/config", "/usr/bin/cat", 1},
		{"cloud-cred-by-kubectl", "rules/linux/file-cloud-cred-file-read.yml",
			"/home/u/.kube/config", "/usr/bin/kubectl", 0},
		{"cloud-cred-unrelated-path", "rules/linux/file-cloud-cred-file-read.yml",
			"/home/u/.config/other/settings", "/usr/bin/cat", 0},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			rule := loadRule(t, tc.rulePath)
			ev := fileActivityFixture(tc.target, tc.writer)
			if got := runFileEvent(t, rule, ev); got != tc.want {
				t.Errorf("%s: findings=%d want=%d", tc.name, got, tc.want)
			}
		})
	}
}
