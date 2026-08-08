package ruleengine

import (
	"testing"

	"github.com/t3rmit3/slither/pkg/ocsf"
)

// processActivityWithEnv builds a process_creation event carrying the
// allowlisted EnvVars the agent captures when capture_env is on.
func processActivityWithEnv(image string, env []string) *ocsf.ProcessActivity {
	ev := processActivity(image, image)
	ev.Process.EnvVars = env
	return ev
}

// The rule this test covers was the last BLOCKED entry in
// DETECTION_THEORYCRAFTING.md's batch-1 backlog (#4) — it needed an
// EnvVars field that did not exist. Both halves of its conjunction are
// exercised here, because either alone is noise: pkexec on its own is a
// normal interactive command, and a loader variable on its own is set
// by plenty of legitimate software.
func TestPkexecSuspiciousEnvRule(t *testing.T) {
	rule := loadRule(t, "rules/linux/proc-pkexec-suspicious-env.yml")

	cases := []struct {
		name  string
		image string
		env   []string
		want  int
	}{
		// CVE-2021-4034 (PwnKit) — GCONV_PATH is the payload vector.
		{"pwnkit gconv", "/usr/bin/pkexec", []string{"GCONV_PATH=/tmp/pwnkit"}, 1},
		// CVE-2023-4911 (Looney Tunables).
		{"looney tunables", "/usr/bin/pkexec",
			[]string{"GLIBC_TUNABLES=glibc.malloc.tcache_count=257"}, 1},
		{"ld_preload", "/usr/bin/pkexec", []string{"LD_PRELOAD=/tmp/eve.so"}, 1},
		{"ld_audit", "/usr/bin/pkexec", []string{"LD_AUDIT=/tmp/a.so"}, 1},
		{"ld_library_path", "/usr/bin/pkexec", []string{"LD_LIBRARY_PATH=/tmp"}, 1},

		// One suspicious variable among ordinary ones still fires — the
		// agent only ever reports allowlisted names, so anything present
		// here is already interesting.
		{"suspicious among several", "/usr/bin/pkexec",
			[]string{"PYTHONPATH=/opt/app", "GCONV_PATH=/tmp/x"}, 1},

		// Half the conjunction is not a detection.
		{"pkexec with no overrides", "/usr/bin/pkexec", nil, 0},
		{"pkexec with only benign allowlisted vars", "/usr/bin/pkexec",
			[]string{"PYTHONPATH=/opt/app"}, 0},
		{"ld_preload on a non-setuid binary", "/usr/bin/curl",
			[]string{"LD_PRELOAD=/tmp/eve.so"}, 0},

		// The match is anchored with startswith, so a variable that
		// merely mentions one of the names in its VALUE must not fire.
		// Without the anchor, `PYTHONPATH=/opt/LD_PRELOAD` would.
		{"name appearing inside another value", "/usr/bin/pkexec",
			[]string{"PYTHONPATH=/opt/LD_PRELOAD=x"}, 0},

		// Capture disabled is the default deployment: the field is empty
		// and the rule is inert rather than wrong.
		{"capture_env off", "/usr/bin/pkexec", []string{}, 0},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			ev := processActivityWithEnv(tc.image, tc.env)
			if got := runOne(t, rule, ev); got != tc.want {
				t.Errorf("findings=%d want=%d (image=%s env=%q)",
					got, tc.want, tc.image, tc.env)
			}
		})
	}
}
