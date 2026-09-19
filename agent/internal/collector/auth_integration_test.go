//go:build linux && integration

package collector

import (
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/t3rmit3/slither/agent/internal/config"
	"github.com/t3rmit3/slither/agent/internal/pipeline"
)

// TestAuthCollector_SuSessionObserved attaches the libpam uprobes and
// drives a real PAM transaction: `su` as root to an unprivileged account
// runs pam_authenticate (pam_rootok short-circuits it to success, so no
// password prompt) and then pam_open_session / pam_close_session. The
// assertion is on the session open, which every PAM login path shares.
func TestAuthCollector_SuSessionObserved(t *testing.T) {
	requirePrivileged(t)
	suPath, err := exec.LookPath("su")
	if err != nil {
		t.Skip("su not on PATH")
	}
	if _, err := resolveLibpam(""); err != nil {
		t.Skipf("no libpam on this host: %v", err)
	}
	target := "nobody"
	if _, err := os.Stat("/etc/passwd"); err != nil {
		t.Skip("no /etc/passwd")
	}

	out := make(chan pipeline.RawAuthEvent, 256)
	c := newAuthCollector(out, config.AuthCollector{}, newCounters())
	_, stop := startCollector(t, c)
	defer stop()

	time.Sleep(200 * time.Millisecond)

	cmd := exec.Command(suPath, "-s", "/bin/true", target, "-c", "true")
	cmd.Stdin = nil
	if outb, err := cmd.CombinedOutput(); err != nil {
		t.Logf("su exited %v (%s) — still expecting PAM events", err, string(outb))
	}

	ev, ok := waitForEvent(t, out, func(e pipeline.RawAuthEvent) bool {
		return e.Kind == pipeline.AuthSessionOpen && e.Service == "su" && e.User == target
	}, 3*time.Second)
	if !ok {
		t.Fatalf("no session_open for service=su user=%s within 3s", target)
	}
	if ev.Result != 0 {
		t.Errorf("root su to %s should open a session cleanly; PAM result %d", target, ev.Result)
	}
	if ev.PID == 0 {
		t.Error("event should carry the su process tgid")
	}
}
