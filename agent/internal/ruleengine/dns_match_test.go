package ruleengine

import (
	"testing"
	"time"

	"github.com/t3rmit3/slither/agent/internal/telemetry"
	"github.com/t3rmit3/slither/pkg/ocsf"
	"github.com/t3rmit3/slither/pkg/ruleast"
)

func dnsEvent(code, name, qtype, rcode, image string, pid uint32) *ocsf.DnsActivity {
	ts := time.Now().UnixMilli()
	activity := ocsf.DnsActivityQuery
	if code == "dns_response" {
		activity = ocsf.DnsActivityResponse
	}
	return &ocsf.DnsActivity{
		Metadata:   ocsf.Metadata{Version: ocsf.Version, OriginalT: ts, UID: "ev-dns", EventCode: code},
		ClassUID:   ocsf.ClassDnsActivity,
		ClassName:  ocsf.ClassDnsActivity.String(),
		ActivityID: activity,
		Severity:   ocsf.SeverityInformational,
		Time:       ocsf.TimeOCSF(ts),
		Device:     ocsf.Device{HostID: "host-a"},
		Actor: ocsf.Actor{
			Process: ocsf.Process{PID: pid, Name: "x", File: &ocsf.File{Path: image}},
			User:    ocsf.User{Name: "alice"},
		},
		Query: ocsf.DnsQuery{Name: name, Type: qtype, Class: "IN"},
		RCode: rcode,
	}
}

func shippedDNSRule(t *testing.T, file string) *sigmaCompiledRule {
	t.Helper()
	rules, err := CompileRules([]*ruleast.Rule{loadRule(t, "rules/linux/"+file)}, telemetry.NewCounters(), nil)
	if err != nil {
		t.Fatalf("CompileRules: %v", err)
	}
	return rules[0].(*sigmaCompiledRule)
}

func TestDNSLongLabel(t *testing.T) {
	scr := shippedDNSRule(t, "dns-query-long-label.yml")
	long := "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHR1bm5lbCBwYXlsb2Fk.t.evil.example"
	if !scr.Match(dnsEvent("dns_query", long, "A", "", "/usr/bin/curl", 1)) {
		t.Error("a 40+ char label should fire")
	}
	if scr.Match(dnsEvent("dns_query", long, "A", "", "/usr/lib/systemd/systemd-resolved", 2)) {
		t.Error("the stub resolver's upstream copy is excluded")
	}
	if scr.Match(dnsEvent("dns_query", "d3abcdef0123456789.cloudfront.net", "A", "", "/usr/bin/curl", 1)) {
		t.Error("a 19-char label must not fire")
	}
	if scr.Match(dnsEvent("dns_response", long, "A", "NOERROR", "/usr/bin/curl", 1)) {
		t.Error("responses are not queries")
	}
}

func TestDNSTXTBurstPerProcess(t *testing.T) {
	scr := shippedDNSRule(t, "dns-query-txt-burst.yml")
	clk := &fakeNow{t: time.Unix(1_700_000_000, 0)}
	defer withFakeClock(scr, clk.Now)()
	for i := 0; i < 20; i++ {
		if scr.Match(dnsEvent("dns_query", "c.evil.example", "TXT", "", "/tmp/beacon", 900)) {
			t.Fatalf("TXT query %d should not fire (threshold >20)", i+1)
		}
		clk.advance(time.Second)
	}
	if scr.Match(dnsEvent("dns_query", "c.evil.example", "A", "", "/tmp/beacon", 900)) {
		t.Fatal("an A query must not count")
	}
	if !scr.Match(dnsEvent("dns_query", "c.evil.example", "TXT", "", "/tmp/beacon", 900)) {
		t.Error("21st TXT query inside 60s should fire")
	}
	for i := 0; i < 25; i++ {
		if scr.Match(dnsEvent("dns_query", "mail.example", "TXT", "", "/usr/lib/postfix/sbin/smtpd", 901)) {
			t.Fatal("an MTA's SPF/DKIM lookups are excluded")
		}
	}
}

func TestDNSNXDomainBurst(t *testing.T) {
	scr := shippedDNSRule(t, "dns-response-nxdomain-burst.yml")
	clk := &fakeNow{t: time.Unix(1_700_000_000, 0)}
	defer withFakeClock(scr, clk.Now)()
	for i := 0; i < 30; i++ {
		if scr.Match(dnsEvent("dns_response", "x.example", "A", "NXDOMAIN", "/tmp/dga", 950)) {
			t.Fatalf("NXDOMAIN %d should not fire (threshold >30)", i+1)
		}
		clk.advance(time.Second)
	}
	if scr.Match(dnsEvent("dns_response", "ok.example", "A", "NOERROR", "/tmp/dga", 950)) {
		t.Fatal("a successful response must not count")
	}
	if !scr.Match(dnsEvent("dns_response", "y.example", "A", "NXDOMAIN", "/tmp/dga", 950)) {
		t.Error("31st NXDOMAIN inside 60s should fire")
	}
}

func TestDNSPasteSites(t *testing.T) {
	scr := shippedDNSRule(t, "dns-query-paste-and-transfer-sites.yml")
	if !scr.Match(dnsEvent("dns_query", "pastebin.com", "A", "", "/usr/bin/curl", 1)) || !scr.Match(dnsEvent("dns_query", "cdn.transfer.sh", "AAAA", "", "/usr/bin/wget", 1)) {
		t.Error("paste / transfer sites should fire")
	}
	if scr.Match(dnsEvent("dns_query", "github.com", "A", "", "/usr/bin/git", 1)) {
		t.Error("github must not fire")
	}
}
