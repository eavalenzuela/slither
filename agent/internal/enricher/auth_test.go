package enricher

import (
	"context"
	"testing"
	"time"

	"github.com/t3rmit3/slither/agent/internal/pipeline"
	"github.com/t3rmit3/slither/pkg/ocsf"
)

func TestAuthActivityIDMapping(t *testing.T) {
	cases := map[pipeline.RawAuthKind]ocsf.AuthActivity{
		pipeline.AuthAttempt:      ocsf.AuthActivityLogon,
		pipeline.AuthSessionOpen:  ocsf.AuthActivityLogon,
		pipeline.AuthSessionClose: ocsf.AuthActivityLogoff,
		pipeline.AuthUnknown:      ocsf.AuthActivityOther,
	}
	for k, want := range cases {
		if got := authActivityID(k); got != want {
			t.Errorf("authActivityID(%v) = %d, want %d", k, got, want)
		}
	}
}

func TestAuthStatusFromPAMCode(t *testing.T) {
	if s, id := authStatus(0); s != "Success" || id != 1 {
		t.Errorf("PAM_SUCCESS → %q/%d", s, id)
	}
	for _, code := range []int32{7, 10, 11, 19, 31} {
		if s, id := authStatus(code); s != "Failure" || id != 2 {
			t.Errorf("code %d → %q/%d, want Failure/2", code, s, id)
		}
	}
}

func TestPAMResultNames(t *testing.T) {
	cases := map[int32]string{
		0:  "PAM_SUCCESS",
		7:  "PAM_AUTH_ERR",
		10: "PAM_USER_UNKNOWN",
		11: "PAM_MAXTRIES",
		31: "PAM_INCOMPLETE",
		99: "PAM_99",
		-1: "PAM_-1",
	}
	for code, want := range cases {
		if got := pamResultName(code); got != want {
			t.Errorf("pamResultName(%d) = %q, want %q", code, got, want)
		}
	}
}

func TestAuthLogonType(t *testing.T) {
	cases := []struct {
		name string
		raw  pipeline.RawAuthEvent
		want string
		id   uint8
	}{
		{"ssh with rhost", pipeline.RawAuthEvent{Service: "sshd", RemoteHost: "10.0.0.1", TTY: "ssh"}, "Remote Interactive", 10},
		{"console login", pipeline.RawAuthEvent{Service: "login", TTY: "tty1"}, "Interactive", 2},
		{"sudo on a tty", pipeline.RawAuthEvent{Service: "sudo", TTY: "/dev/pts/0"}, "sudo", 99},
		{"su without tty", pipeline.RawAuthEvent{Service: "su"}, "su", 99},
		{"nothing known", pipeline.RawAuthEvent{}, "Other", 99},
	}
	for _, c := range cases {
		got, id := authLogonType(c.raw)
		if got != c.want || id != c.id {
			t.Errorf("%s: (%q, %d), want (%q, %d)", c.name, got, id, c.want, c.id)
		}
	}
}

func TestAuthEndpointIPvsHostname(t *testing.T) {
	if ep := authEndpoint("203.0.113.9"); ep.IP != "203.0.113.9" || ep.Hostname != "" {
		t.Errorf("v4 rhost → %+v", ep)
	}
	if ep := authEndpoint("::ffff:203.0.113.9"); ep.IP != "203.0.113.9" {
		t.Errorf("v4-mapped v6 should unmap: %+v", ep)
	}
	if ep := authEndpoint("bastion.example"); ep.Hostname != "bastion.example" || ep.IP != "" {
		t.Errorf("name rhost → %+v", ep)
	}
}

// TestHandleAuthFailedSSHBuildsValidOCSF — a failed sshd password check
// from a remote host, with the sshd monitor in the process cache.
func TestHandleAuthFailedSSHBuildsValidOCSF(t *testing.T) {
	e := newTestEnricher(t)
	e.cache.upsert(procEntry{
		pid: 900, uid: 0, comm: "sshd", exe: "/usr/sbin/sshd",
		cmdline: "sshd: alice [priv]",
	})

	raw := pipeline.RawAuthEvent{
		Kind: pipeline.AuthAttempt, PID: 900, UID: 0, Result: 7,
		Service: "sshd", User: "alice", RemoteHost: "203.0.113.9", TTY: "ssh",
		Comm: "sshd", Timestamp: time.Unix(100, 0),
	}
	e.handleAuth(context.Background(), raw)

	ev := <-e.out
	a, ok := ev.(*ocsf.Authentication)
	if !ok {
		t.Fatalf("emitted %T, want *Authentication", ev)
	}
	if err := a.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if a.ClassUID != ocsf.ClassAuthentication || a.TypeUID != 300201 {
		t.Errorf("class/type = %d/%d", a.ClassUID, a.TypeUID)
	}
	if a.Metadata.EventCode != "auth_attempt" || a.Metadata.LogName != "auth" {
		t.Errorf("metadata = %+v", a.Metadata)
	}
	if a.Status != "Failure" || a.StatusID != 2 || a.StatusCode != "7" || a.StatusDetail != "PAM_AUTH_ERR" {
		t.Errorf("status = %q/%d/%q/%q", a.Status, a.StatusID, a.StatusCode, a.StatusDetail)
	}
	if a.User.Name != "alice" || a.User.Type != "User" {
		t.Errorf("user = %+v", a.User)
	}
	if a.Service == nil || a.Service.Name != "sshd" {
		t.Errorf("service = %+v", a.Service)
	}
	if a.SrcEndpoint == nil || a.SrcEndpoint.IP != "203.0.113.9" {
		t.Errorf("src_endpoint = %+v", a.SrcEndpoint)
	}
	if a.Session == nil || !a.Session.IsRemote {
		t.Errorf("session = %+v", a.Session)
	}
	if a.LogonTypeID != 10 {
		t.Errorf("logon_type_id = %d", a.LogonTypeID)
	}
	if a.Actor.Process.PID != 900 || a.Actor.Process.File == nil || a.Actor.Process.File.Path != "/usr/sbin/sshd" {
		t.Errorf("actor process = %+v", a.Actor.Process)
	}
	if a.Actor.User.Name != "root" || a.Actor.User.Type != "Admin" {
		t.Errorf("actor user = %+v", a.Actor.User)
	}
	if a.AuthProto != "pam" || a.TTY != "ssh" {
		t.Errorf("auth_protocol/tty = %q/%q", a.AuthProto, a.TTY)
	}
}

// TestHandleAuthCacheMissUsesBPFIdentity — sudo run by a user whose
// process the cache never saw (agent started mid-session). The BPF
// record's uid + comm must still yield a valid, attributable event.
func TestHandleAuthCacheMissUsesBPFIdentity(t *testing.T) {
	e := newTestEnricher(t)

	raw := pipeline.RawAuthEvent{
		Kind: pipeline.AuthSessionOpen, PID: 77, UID: 1000, Result: 0,
		Service: "sudo", User: "alice", TTY: "/dev/pts/3",
		Comm: "sudo", Timestamp: time.Unix(200, 0),
	}
	e.handleAuth(context.Background(), raw)

	a := (<-e.out).(*ocsf.Authentication)
	if err := a.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if a.Metadata.EventCode != "session_open" || a.ActivityID != ocsf.AuthActivityLogon {
		t.Errorf("event_code/activity = %q/%d", a.Metadata.EventCode, a.ActivityID)
	}
	if a.Status != "Success" || a.StatusDetail != "PAM_SUCCESS" {
		t.Errorf("status = %q/%q", a.Status, a.StatusDetail)
	}
	if a.Actor.Process.PID != 77 || a.Actor.Process.Name != "sudo" {
		t.Errorf("actor process = %+v", a.Actor.Process)
	}
	if a.Actor.User.Name != "alice" || a.Actor.User.UID != "1000" {
		t.Errorf("actor user should resolve uid 1000 from passwd: %+v", a.Actor.User)
	}
	if a.SrcEndpoint != nil || a.Session != nil {
		t.Errorf("local sudo must not carry a remote endpoint: src=%+v session=%+v", a.SrcEndpoint, a.Session)
	}
	if a.LogonType != "sudo" || a.LogonTypeID != 99 {
		t.Errorf("logon_type = %q/%d", a.LogonType, a.LogonTypeID)
	}
}

func TestHandleAuthDropsUnknownKind(t *testing.T) {
	e := newTestEnricher(t)
	e.handleAuth(context.Background(), pipeline.RawAuthEvent{Kind: pipeline.AuthUnknown, PID: 1})
	select {
	case ev := <-e.out:
		t.Fatalf("unknown kind should be dropped, got %T", ev)
	default:
	}
}
