package app

import (
	"fmt"

	"github.com/t3rmit3/slither/agent/internal/ruleengine"
	"github.com/t3rmit3/slither/agent/internal/telemetry"
	"github.com/t3rmit3/slither/pkg/ruleast"
	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
)

// compileRuleSet turns a server-pushed RuleSet into the engine's
// CompiledRule slice. v1 (stateless) and v2 (bounded-stateful, Phase 3
// #54d/#56) are both honoured; rules carrying any other ast_version are
// skipped so an older agent silently degrades rather than crashing on
// an unknown wire shape. ADR-0032 codifies this as the agent-side
// refusal vocabulary; #57 will surface the skips via DiagReport.
//
// Compile errors on individual rules are skipped with a count returned
// so callers can log without aborting the whole reload.
func compileRuleSet(rs *pb.RuleSet, telem *telemetry.Counters) (compiled []ruleengine.CompiledRule, skipped int, err error) {
	if rs == nil {
		return nil, 0, nil
	}
	parsed := make([]*ruleast.Rule, 0, len(rs.GetRules()))
	for _, er := range rs.GetRules() {
		v := ruleast.ASTVersion(er.GetAstVersion())
		if v != ruleast.ASTVersionV1 && v != ruleast.ASTVersionV2 {
			skipped++
			continue
		}
		artefact, _, class, cerr := ruleast.Compile(er.GetCompiledAst())
		if cerr != nil || class == ruleast.ClassificationServerOnly {
			skipped++
			continue
		}
		parsed = append(parsed, artefact.Rule)
	}
	out, err := ruleengine.CompileRules(parsed, telem)
	if err != nil {
		return nil, skipped, fmt.Errorf("compileRuleSet: wrap: %w", err)
	}
	return out, skipped, nil
}
