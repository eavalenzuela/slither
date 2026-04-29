package app

import (
	"strings"
	"testing"

	"github.com/t3rmit3/slither/agent/internal/ioc"
	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
)

// newIOCStoreForTest mirrors production wiring (ioc.New) so tests use
// the same code path as the agent.
func newIOCStoreForTest() *ioc.Store { return ioc.New() }

const stubStatelessYAML = `title: Test rule
id: 11111111-1111-4111-8111-111111111111
description: Test
level: high
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    Image|endswith: /bin/true
  condition: selection
`

func TestCompileRuleSet_AcceptsV1AndV2(t *testing.T) {
	rs := &pb.RuleSet{Rules: []*pb.EdgeRule{
		{
			RuleId:      "stateless",
			AstVersion:  1,
			CompiledAst: []byte(stubStatelessYAML),
		},
	}}
	compiled, warns, err := compileRuleSet(rs, nil, nil)
	if err != nil {
		t.Fatalf("compileRuleSet: %v", err)
	}
	if len(compiled) != 1 {
		t.Errorf("compiled = %d rules, want 1", len(compiled))
	}
	if len(warns) != 0 {
		t.Errorf("warnings = %v, want none", warns)
	}
}

func TestCompileRuleSet_RefusesUnsupportedAST(t *testing.T) {
	rs := &pb.RuleSet{Rules: []*pb.EdgeRule{
		{RuleId: "future", AstVersion: 99, CompiledAst: []byte(stubStatelessYAML)},
	}}
	compiled, warns, err := compileRuleSet(rs, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(compiled) != 0 {
		t.Errorf("compiled = %d, want 0", len(compiled))
	}
	if len(warns) != 1 || !strings.Contains(warns[0], "ast_version_unsupported") {
		t.Errorf("warnings = %v, want one ast_version_unsupported", warns)
	}
	if !strings.HasPrefix(warns[0], "rule:future:") {
		t.Errorf("warning shape = %q, want rule:<id>:<reason>", warns[0])
	}
}

func TestCompileRuleSet_RefusesOverCapWindow(t *testing.T) {
	rs := &pb.RuleSet{Rules: []*pb.EdgeRule{
		{
			RuleId:          "fat-window",
			AstVersion:      2,
			StateWindowSecs: 600, // > 300
			StateCap:        1024,
			CompiledAst:     []byte(stubStatelessYAML),
		},
	}}
	_, warns, err := compileRuleSet(rs, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(warns) != 1 || !strings.Contains(warns[0], "state_window_too_large") {
		t.Errorf("warnings = %v, want state_window_too_large", warns)
	}
}

func TestCompileRuleSet_RefusesOverCapStateCap(t *testing.T) {
	rs := &pb.RuleSet{Rules: []*pb.EdgeRule{
		{
			RuleId:          "fat-cap",
			AstVersion:      2,
			StateWindowSecs: 60,
			StateCap:        4096, // > 1024
			CompiledAst:     []byte(stubStatelessYAML),
		},
	}}
	_, warns, err := compileRuleSet(rs, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(warns) != 1 || !strings.Contains(warns[0], "state_cap_too_large") {
		t.Errorf("warnings = %v, want state_cap_too_large", warns)
	}
}

func TestCompileRuleSet_RefusesUncompilable(t *testing.T) {
	rs := &pb.RuleSet{Rules: []*pb.EdgeRule{
		{RuleId: "bad", AstVersion: 1, CompiledAst: []byte("not sigma yaml ::: {{")},
	}}
	_, warns, err := compileRuleSet(rs, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(warns) != 1 || !strings.Contains(warns[0], "compile_failed") {
		t.Errorf("warnings = %v, want compile_failed", warns)
	}
}

func TestCompileRuleSet_PartialSuccess(t *testing.T) {
	rs := &pb.RuleSet{Rules: []*pb.EdgeRule{
		{RuleId: "good", AstVersion: 1, CompiledAst: []byte(stubStatelessYAML)},
		{RuleId: "future", AstVersion: 99, CompiledAst: []byte(stubStatelessYAML)},
	}}
	compiled, warns, err := compileRuleSet(rs, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(compiled) != 1 {
		t.Errorf("compiled = %d, want 1 (good rule survives)", len(compiled))
	}
	if len(warns) != 1 {
		t.Errorf("warnings = %d, want 1", len(warns))
	}
}

const stubIOCRuleYAML = `title: IOC test
id: 22222222-2222-4222-8222-222222222222
level: high
logsource:
  product: linux
  category: network_connection
detection:
  selection:
    DstAddr|ioc:
      - bad-ips
  condition: selection
`

func TestCompileRuleSet_LoadsIOCFeedsAndCompilesReferences(t *testing.T) {
	store := newIOCStoreForTest()
	rs := &pb.RuleSet{
		Rules: []*pb.EdgeRule{
			{RuleId: "ioc-rule", AstVersion: 1, CompiledAst: []byte(stubIOCRuleYAML)},
		},
		IocFeeds: []*pb.IocFeed{{
			FeedId:  "bad-ips",
			Kind:    pb.FeedKind_FEED_KIND_IPV4,
			Entries: []string{"203.0.113.5"},
		}},
	}
	compiled, warns, err := compileRuleSet(rs, nil, store)
	if err != nil {
		t.Fatalf("compileRuleSet: %v", err)
	}
	if len(warns) != 0 {
		t.Fatalf("unexpected warnings: %v", warns)
	}
	if len(compiled) != 1 {
		t.Fatalf("compiled = %d, want 1", len(compiled))
	}
	count, kind, ok := store.Lookup("bad-ips")
	if !ok || count != 1 || kind != "ipv4" {
		t.Errorf("store after Apply = (%d, %q, %v), want (1, ipv4, true)", count, kind, ok)
	}
}

func TestCompileRuleSet_NilStoreDropsIOCRules(t *testing.T) {
	rs := &pb.RuleSet{Rules: []*pb.EdgeRule{
		{RuleId: "ioc-rule", AstVersion: 1, CompiledAst: []byte(stubIOCRuleYAML)},
	}}
	compiled, warns, err := compileRuleSet(rs, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(compiled) != 0 {
		t.Errorf("compiled = %d, want 0 (no registry, ioc rule must drop)", len(compiled))
	}
	if len(warns) != 1 || !strings.Contains(warns[0], "compile_failed") {
		t.Errorf("warnings = %v, want compile_failed", warns)
	}
}
