package ruleast

import (
	"errors"
	"strings"
	"testing"
)

// stubIOCRegistry is a tiny test registry — Lookup returns whatever
// the test's table says.
type stubIOCRegistry map[string]int

func (s stubIOCRegistry) Lookup(feedID string) (entryCount int, kind string, ok bool) {
	count, present := s[feedID]
	if !present {
		return 0, "", false
	}
	return count, "sha256", true
}

// stubIOCEnv pairs Lookup (selection field resolution) with MatchIOC
// (IOC feed lookup) so a fired predicate can short-circuit on a real
// hit/miss decision.
type stubIOCEnv struct {
	fields map[string][]string
	feeds  map[string]map[string]bool
}

func (s stubIOCEnv) Lookup(field string) ([]string, bool) {
	v, ok := s.fields[field]
	return v, ok
}
func (s stubIOCEnv) MatchIOC(feedID, value string) bool {
	feed, ok := s.feeds[feedID]
	if !ok {
		return false
	}
	return feed[strings.ToLower(value)]
}

const iocRuleSrc = `
title: IOC test
id: 8b7c4d00-0001-4000-8000-00000000ioc1
logsource:
  product: linux
  category: network_connection
detection:
  selection:
    DstAddr|ioc:
      - bad-ips
  condition: selection
`

func TestCompileIOC_EdgeOnlyWhenFeedFits(t *testing.T) {
	t.Parallel()
	reg := stubIOCRegistry{"bad-ips": 50_000}
	art, plan, class, err := Compile([]byte(iocRuleSrc), WithIOCRegistry(reg))
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if class != ClassificationEdgeOnly {
		t.Fatalf("class = %s, want edge_only", class)
	}
	if plan != nil {
		t.Fatalf("plan should be nil for edge-only rule, got %#v", plan)
	}
	if art == nil {
		t.Fatal("EdgeArtefact unexpectedly nil")
	}
	if len(art.IOCFeeds) != 1 || art.IOCFeeds[0] != "bad-ips" {
		t.Fatalf("EdgeArtefact.IOCFeeds = %v, want [bad-ips]", art.IOCFeeds)
	}
}

func TestCompileIOC_ServerOnlyWhenFeedTooLarge(t *testing.T) {
	t.Parallel()
	reg := stubIOCRegistry{"big-feed": MaxIOCFeedEntries + 1}
	src := strings.ReplaceAll(iocRuleSrc, "bad-ips", "big-feed")
	art, plan, class, err := Compile([]byte(src), WithIOCRegistry(reg))
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if class != ClassificationServerOnly {
		t.Fatalf("class = %s, want server_only", class)
	}
	if art != nil {
		t.Fatalf("EdgeArtefact should be nil for server-only rule, got %#v", art)
	}
	if plan == nil {
		t.Fatal("ServerPlan unexpectedly nil")
	}
	if len(plan.IOCFeeds) != 1 || plan.IOCFeeds[0] != "big-feed" {
		t.Fatalf("ServerPlan.IOCFeeds = %v, want [big-feed]", plan.IOCFeeds)
	}
}

func TestCompileIOC_ForceEdgeOnOversizeFails(t *testing.T) {
	t.Parallel()
	reg := stubIOCRegistry{"big-feed": MaxIOCFeedEntries + 1}
	src := strings.ReplaceAll(iocRuleSrc, "bad-ips", "big-feed")
	src = strings.Replace(src, "detection:", "force_edge: true\ndetection:", 1)
	_, _, _, err := Compile([]byte(src), WithIOCRegistry(reg))
	if err == nil {
		t.Fatal("expected force_edge against oversize feed to fail compile")
	}
	if !errors.Is(err, ErrCompile) {
		t.Errorf("error does not wrap ErrCompile: %v", err)
	}
	if !strings.Contains(err.Error(), "ioc_feed_too_large") {
		t.Errorf("error missing predicate citation: %v", err)
	}
}

func TestCompileIOC_UnknownFeedFails(t *testing.T) {
	t.Parallel()
	reg := stubIOCRegistry{}
	_, _, _, err := Compile([]byte(iocRuleSrc), WithIOCRegistry(reg))
	if err == nil {
		t.Fatal("expected unknown feed to fail compile")
	}
	if !strings.Contains(err.Error(), "not found in registry") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCompileIOC_NoRegistryFails(t *testing.T) {
	t.Parallel()
	_, _, _, err := Compile([]byte(iocRuleSrc))
	if err == nil {
		t.Fatal("expected compile with no registry to fail when ioc references present")
	}
	if !strings.Contains(err.Error(), "no registry") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCompileIOC_NoOpRulesIgnoreRegistry(t *testing.T) {
	t.Parallel()
	// Rule without any |ioc references compiles fine even when the
	// registry is nil — the gate is a no-op.
	src := `
title: plain rule
id: 8b7c4d00-0001-4000-8000-00000000ioc2
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    Image|endswith: /bash
  condition: selection
`
	_, _, class, err := Compile([]byte(src))
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if class != ClassificationEdgeOnly {
		t.Fatalf("class = %s, want edge_only", class)
	}
}

func TestEval_IOCFeedHit(t *testing.T) {
	t.Parallel()
	reg := stubIOCRegistry{"bad-ips": 10}
	art, _, _, err := Compile([]byte(iocRuleSrc), WithIOCRegistry(reg))
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	env := stubIOCEnv{
		fields: map[string][]string{"DstAddr": {"203.0.113.5"}},
		feeds: map[string]map[string]bool{
			"bad-ips": {"203.0.113.5": true},
		},
	}
	if !art.Rule.Match(env) {
		t.Fatal("rule did not fire on IOC hit")
	}
	missEnv := stubIOCEnv{
		fields: map[string][]string{"DstAddr": {"198.51.100.1"}},
		feeds:  map[string]map[string]bool{"bad-ips": {"203.0.113.5": true}},
	}
	if art.Rule.Match(missEnv) {
		t.Fatal("rule fired on IOC miss")
	}
}
