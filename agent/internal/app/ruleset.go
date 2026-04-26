package app

import (
	"fmt"

	"github.com/t3rmit3/slither/agent/internal/ruleengine"
	"github.com/t3rmit3/slither/pkg/ruleast"
	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
)

// compileRuleSet turns a server-pushed RuleSet into the engine's
// CompiledRule slice. EdgeRules whose ast_version isn't recognised are
// skipped — #54a only emits v1; v2 (stateful) lights up with #54d, at
// which point the agent's deserialiser branches per ADR-0032's refusal
// vocabulary. For now, anything outside v1 is silently dropped because
// no server should be emitting it yet.
//
// Compile errors on individual rules are skipped with a count returned
// so callers can log without aborting the whole reload.
func compileRuleSet(rs *pb.RuleSet) (compiled []ruleengine.CompiledRule, skipped int, err error) {
	if rs == nil {
		return nil, 0, nil
	}
	parsed := make([]*ruleast.Rule, 0, len(rs.GetRules()))
	for _, er := range rs.GetRules() {
		if ruleast.ASTVersion(er.GetAstVersion()) != ruleast.ASTVersionV1 {
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
	out, err := ruleengine.CompileRules(parsed)
	if err != nil {
		return nil, skipped, fmt.Errorf("compileRuleSet: wrap: %w", err)
	}
	return out, skipped, nil
}
