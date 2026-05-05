package console

import (
	"strings"
	"testing"
	"time"
)

func TestParseEventsQuery_Empty(t *testing.T) {
	t.Parallel()
	p, err := ParseEventsQuery("")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if p.HostID != "" || p.ClassUID != "" || p.RawContains != "" {
		t.Errorf("non-zero on empty input: %+v", p)
	}
}

func TestParseEventsQuery_StructuredAxes(t *testing.T) {
	t.Parallel()
	p, err := ParseEventsQuery("host:abc class:1007 severity:4")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if p.HostID != "abc" {
		t.Errorf("host = %q", p.HostID)
	}
	if p.ClassUID != "1007" {
		t.Errorf("class = %q", p.ClassUID)
	}
	if p.SeverityID != "4" {
		t.Errorf("severity = %q", p.SeverityID)
	}
}

func TestParseEventsQuery_BadClass(t *testing.T) {
	t.Parallel()
	_, err := ParseEventsQuery("class:foo")
	if err == nil {
		t.Fatal("expected parse error")
	}
}

func TestParseEventsQuery_BadSeverity(t *testing.T) {
	t.Parallel()
	for _, v := range []string{"0", "7", "low"} {
		if _, err := ParseEventsQuery("severity:" + v); err == nil {
			t.Errorf("severity:%s should error", v)
		}
	}
}

func TestParseEventsQuery_DurationShorthand(t *testing.T) {
	t.Parallel()
	p, err := ParseEventsQuery("since:24h")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	since, err := time.Parse(time.RFC3339Nano, p.Since)
	if err != nil {
		t.Fatalf("Since not RFC3339: %v", err)
	}
	gap := time.Since(since)
	if gap < 23*time.Hour || gap > 25*time.Hour {
		t.Errorf("Since gap = %s, want ~24h", gap)
	}
}

func TestParseEventsQuery_DayShorthand(t *testing.T) {
	t.Parallel()
	p, err := ParseEventsQuery("since:7d")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	since, err := time.Parse(time.RFC3339Nano, p.Since)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	gap := time.Since(since)
	if gap < 6*24*time.Hour || gap > 8*24*time.Hour {
		t.Errorf("Since gap = %s, want ~7d", gap)
	}
}

func TestParseEventsQuery_RFC3339(t *testing.T) {
	t.Parallel()
	p, err := ParseEventsQuery("since:2026-05-01T00:00:00Z")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !strings.HasPrefix(p.Since, "2026-05-01T00:00:00") {
		t.Errorf("Since = %q", p.Since)
	}
}

func TestParseEventsQuery_QuotedRawFallthrough(t *testing.T) {
	t.Parallel()
	p, err := ParseEventsQuery(`"curl http://x"`)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if p.RawContains != "curl http://x" {
		t.Errorf("rawContains = %q, want %q", p.RawContains, "curl http://x")
	}
}

func TestParseEventsQuery_UnknownAxis(t *testing.T) {
	t.Parallel()
	p, err := ParseEventsQuery("foo:bar host:x")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if p.HostID != "x" {
		t.Errorf("host axis missed: %+v", p)
	}
	if len(p.Unknown) != 1 || p.Unknown[0] != "foo:bar" {
		t.Errorf("unknown = %+v", p.Unknown)
	}
}

func TestParseEventsQuery_UnterminatedQuote(t *testing.T) {
	t.Parallel()
	if _, err := ParseEventsQuery(`host:"x`); err == nil {
		t.Fatal("expected error on unterminated quote")
	}
}

func TestParseEventsQuery_RawAxis(t *testing.T) {
	t.Parallel()
	p, err := ParseEventsQuery(`raw:passwd raw:shadow`)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !strings.Contains(p.RawContains, "passwd") || !strings.Contains(p.RawContains, "shadow") {
		t.Errorf("rawContains lost a value: %q", p.RawContains)
	}
}

func TestParsedQuery_ToURLValuesRoundTrip(t *testing.T) {
	t.Parallel()
	p, err := ParseEventsQuery("host:abc class:1007 severity:3")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	v := p.ToURLValues()
	if v.Get("host_id") != "abc" {
		t.Errorf("host_id = %q", v.Get("host_id"))
	}
	if v.Get("class_uid") != "1007" {
		t.Errorf("class_uid = %q", v.Get("class_uid"))
	}
	if v.Get("severity_id") != "3" {
		t.Errorf("severity_id = %q", v.Get("severity_id"))
	}
}
