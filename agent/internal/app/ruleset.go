package app

import (
	"fmt"

	"github.com/t3rmit3/slither/agent/internal/ruleengine"
	"github.com/t3rmit3/slither/pkg/ruleast"
	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
)

// astVersionV1 mirrors server/internal/control.astVersion. Phase 2 wire
// format: EdgeRule.compiled_ast carries raw Sigma YAML bytes that the
// agent feeds back into pkg/ruleast.CompileSigma. Future ast versions
// may switch to a serialised AST.
const astVersionV1 = 1

// compileRuleSet turns a server-pushed RuleSet into the engine's
// CompiledRule slice. EdgeRules whose ast_version isn't recognised are
// skipped — Phase 2 only emits v1, so a mismatch means the wire freeze
// has been broken or a future server is talking to an older agent;
// either way silently dropping is safer than guessing the encoding.
// Compile errors on individual rules are skipped too with a count
// returned so callers can log without aborting the whole reload.
func compileRuleSet(rs *pb.RuleSet) (compiled []ruleengine.CompiledRule, skipped int, err error) {
	if rs == nil {
		return nil, 0, nil
	}
	parsed := make([]*ruleast.Rule, 0, len(rs.GetRules()))
	for _, er := range rs.GetRules() {
		if er.GetAstVersion() != astVersionV1 {
			skipped++
			continue
		}
		r, cerr := ruleast.CompileSigma(er.GetCompiledAst())
		if cerr != nil {
			skipped++
			continue
		}
		parsed = append(parsed, r)
	}
	out, err := ruleengine.CompileRules(parsed)
	if err != nil {
		return nil, skipped, fmt.Errorf("compileRuleSet: wrap: %w", err)
	}
	return out, skipped, nil
}
