package ruleengine

import (
	"context"
	"testing"
	"time"

	"github.com/t3rmit3/slither/agent/internal/telemetry"
	"github.com/t3rmit3/slither/pkg/ocsf"
	"github.com/t3rmit3/slither/pkg/ruleast"
)

// authEvent builds an Authentication event the way the enricher would
// for one libpam result.
func authEvent(service, eventCode, user, rhost string, pamResult int32) *ocsf.Authentication {
	ts := time.Now().UnixMilli()
	status, statusID := "Success", uint8(1)
	if pamResult != 0 {
		status, statusID = "Failure", 2
	}
	activity := ocsf.AuthActivityLogon
	if eventCode == "session_close" {
		activity = ocsf.AuthActivityLogoff
	}
	ev := &ocsf.Authentication{
		Metadata:   ocsf.Metadata{Version: ocsf.Version, OriginalT: ts, UID: "ev-auth", EventCode: eventCode},
		ClassUID:   ocsf.ClassAuthentication,
		ClassName:  ocsf.ClassAuthentication.String(),
		ActivityID: activity,
		Severity:   ocsf.SeverityInformational,
		Time:       ocsf.TimeOCSF(ts),
		Device:     ocsf.Device{HostID: "host-a"},
		Actor: ocsf.Actor{
			Process: ocsf.Process{PID: 900, Name: service, File: &ocsf.File{Path: "/usr/sbin/" + service}},
			User:    ocsf.User{Name: "root", UID: "0", Type: "Admin"},
		},
		User:     ocsf.User{Name: user},
		Status:   status,
		StatusID: statusID,
		Service:  &ocsf.Service{Name: service},
	}
	if rhost != "" {
		ev.SrcEndpoint = &ocsf.NetEndpoint{IP: rhost}
	}
	return ev
}

func shippedAuthRule(t *testing.T, file string) *sigmaCompiledRule {
	t.Helper()
	rule := loadRule(t, "rules/linux/"+file)
	rules, err := CompileRules([]*ruleast.Rule{rule}, telemetry.NewCounters(), nil)
	if err != nil {
		t.Fatalf("CompileRules: %v", err)
	}
	scr, ok := rules[0].(*sigmaCompiledRule)
	if !ok {
		t.Fatalf("expected sigmaCompiledRule, got %T", rules[0])
	}
	return scr
}

func TestAuthSSHRootLogin(t *testing.T) {
	scr := shippedAuthRule(t, "auth-ssh-root-login.yml")
	if !scr.Match(authEvent("sshd", "session_open", "root", "203.0.113.9", 0)) {
		t.Error("sshd session_open as root should fire")
	}
	for name, ev := range map[string]*ocsf.Authentication{
		"non-root user":         authEvent("sshd", "session_open", "alice", "203.0.113.9", 0),
		"root over sudo":        authEvent("sudo", "session_open", "root", "", 0),
		"root credential check": authEvent("sshd", "auth_attempt", "root", "203.0.113.9", 0),
		"failed root session":   authEvent("sshd", "session_open", "root", "203.0.113.9", 14),
	} {
		if scr.Match(ev) {
			t.Errorf("%s should not fire", name)
		}
	}
}

// TestAuthSSHBruteForceCountsPerRemoteHost — six failures from one host
// inside the window fire on the sixth; the same six spread across two
// hosts never cross the threshold.
func TestAuthSSHBruteForceCountsPerRemoteHost(t *testing.T) {
	scr := shippedAuthRule(t, "auth-ssh-password-bruteforce.yml")
	clk := &fakeNow{t: time.Unix(1_700_000_000, 0)}
	defer withFakeClock(scr, clk.Now)()

	users := []string{"root", "admin", "alice", "ubuntu", "git", "test"}
	for i := 0; i < 5; i++ {
		if scr.Match(authEvent("sshd", "auth_attempt", users[i], "198.51.100.7", 7)) {
			t.Fatalf("failure %d should not fire (threshold >5)", i+1)
		}
		clk.advance(2 * time.Second)
	}
	// A success from the same host does not count.
	if scr.Match(authEvent("sshd", "auth_attempt", "alice", "198.51.100.7", 0)) {
		t.Fatal("a successful check must not advance the failure count")
	}
	if !scr.Match(authEvent("sshd", "auth_attempt", users[5], "198.51.100.7", 7)) {
		t.Error("6th failure from one host (spray across users) should fire")
	}

	scr2 := shippedAuthRule(t, "auth-ssh-password-bruteforce.yml")
	defer withFakeClock(scr2, clk.Now)()
	for i := 0; i < 6; i++ {
		host := "198.51.100.7"
		if i%2 == 1 {
			host = "198.51.100.8"
		}
		if scr2.Match(authEvent("sshd", "auth_attempt", "root", host, 7)) {
			t.Errorf("failure %d split across two hosts should not fire", i+1)
		}
		clk.advance(2 * time.Second)
	}
}

func TestAuthSudoFailureBurstPerUser(t *testing.T) {
	scr := shippedAuthRule(t, "auth-sudo-failure-burst.yml")
	clk := &fakeNow{t: time.Unix(1_700_000_000, 0)}
	defer withFakeClock(scr, clk.Now)()

	for i := 0; i < 3; i++ {
		if scr.Match(authEvent("sudo", "auth_attempt", "bob", "", 7)) {
			t.Fatalf("failure %d should not fire (threshold >3)", i+1)
		}
		clk.advance(10 * time.Second)
	}
	// Another user's failure lands in a different partition.
	if scr.Match(authEvent("sudo", "auth_attempt", "carol", "", 7)) {
		t.Fatal("carol's first failure should not fire")
	}
	if !scr.Match(authEvent("sudo", "auth_attempt", "bob", "", 7)) {
		t.Error("bob's 4th failure inside 120s should fire")
	}
}

// TestAuthRulesRideTheEngine — the engine indexes Authentication by
// class and produces a DetectionFinding whose envelope is stamped from
// the auth event, not dropped by the class switch.
func TestAuthRulesRideTheEngine(t *testing.T) {
	compiled, err := CompileRules([]*ruleast.Rule{loadRule(t, "rules/linux/auth-ssh-root-login.yml")}, nil, nil)
	if err != nil {
		t.Fatalf("CompileRules: %v", err)
	}
	eng := New(compiled, telemetry.NewCounters()).(*engine)

	in := make(chan ocsf.Event, 1)
	in <- authEvent("sshd", "session_open", "root", "203.0.113.9", 0)
	close(in)

	done := make(chan error, 1)
	go func() { done <- eng.Run(context.Background(), in) }()

	var findings []*ocsf.DetectionFinding
	for out := range eng.Output() {
		if f, ok := out.(*ocsf.DetectionFinding); ok {
			findings = append(findings, f)
		}
	}
	<-done
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].Device.HostID != "host-a" {
		t.Errorf("finding device not stamped from the auth event: %+v", findings[0].Device)
	}
}
