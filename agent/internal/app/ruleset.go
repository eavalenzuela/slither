package app

import (
	"fmt"

	"github.com/t3rmit3/slither/agent/internal/ioc"
	"github.com/t3rmit3/slither/agent/internal/ruleengine"
	"github.com/t3rmit3/slither/agent/internal/telemetry"
	"github.com/t3rmit3/slither/pkg/ruleast"
	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
)

// ADR-0018 hard caps the agent enforces at runtime per ADR-0032. The
// server's compiler already rejects rules that exceed these, but a
// misconfigured server (e.g. one that drops the cap check) would
// otherwise push agent-side state corruption. Better to refuse loud.
const (
	maxStateWindowSecs uint32 = 300
	maxStateCap        uint32 = 1024
)

// Refusal reasons emitted into DiagReport.warnings as
// `rule:<rule_id>:<reason>`. Vocabulary fixed by ADR-0032 — keep these
// in sync with the server's parser before changing strings.
const (
	reasonASTVersionUnsupported = "ast_version_unsupported"
	reasonStateWindowTooLarge   = "state_window_too_large"
	reasonStateCapTooLarge      = "state_cap_too_large"
	reasonCompileFailed         = "compile_failed"
)

// compileRuleSet turns a server-pushed RuleSet into the engine's
// CompiledRule slice. v1 (stateless) and v2 (bounded-stateful, Phase 3
// #54d/#56) are both honoured; rules carrying any other ast_version are
// skipped. Rules whose wire-stamped state bounds exceed ADR-0018's hard
// caps are skipped with the failed predicate cited. ADR-0032 codifies
// this as the agent-side refusal vocabulary; the returned warnings are
// emitted to the server via DiagReport so operators can see refusals
// without scraping agent stderr.
//
// IOC feeds (#67) are loaded into iocStore *before* the compile pass
// so `|ioc:<feed_id>` references resolve against the freshly-loaded
// snapshot. iocStore may be nil for callers that don't need IOC
// matching (legacy local-only rule packs).
//
// Compile errors on individual rules are skipped with their UID added
// to warnings so callers can attribute without re-walking the slice.
func compileRuleSet(rs *pb.RuleSet, telem *telemetry.Counters, iocStore *ioc.Store) (compiled []ruleengine.CompiledRule, warnings []string, err error) {
	if rs == nil {
		return nil, nil, nil
	}

	// Load feeds first so the registry resolves on this same call.
	// Apply is safe even when iocStore is nil — we just skip it.
	if iocStore != nil {
		iocStore.Apply(rs.GetIocFeeds())
	}

	var compileOpts []ruleast.CompileOption
	if iocStore != nil {
		compileOpts = append(compileOpts, ruleast.WithIOCRegistry(iocStore))
	}

	parsed := make([]*ruleast.EdgeArtefact, 0, len(rs.GetRules()))
	for _, er := range rs.GetRules() {
		v := ruleast.ASTVersion(er.GetAstVersion())
		if v != ruleast.ASTVersionV1 && v != ruleast.ASTVersionV2 {
			warnings = append(warnings, formatWarning(er.GetRuleId(), reasonASTVersionUnsupported))
			continue
		}
		if er.GetStateWindowSecs() > maxStateWindowSecs {
			warnings = append(warnings, formatWarning(er.GetRuleId(), reasonStateWindowTooLarge))
			continue
		}
		if er.GetStateCap() > maxStateCap {
			warnings = append(warnings, formatWarning(er.GetRuleId(), reasonStateCapTooLarge))
			continue
		}
		artefact, _, class, cerr := ruleast.Compile(er.GetCompiledAst(), compileOpts...)
		if cerr != nil {
			warnings = append(warnings, formatWarning(er.GetRuleId(), reasonCompileFailed))
			continue
		}
		if class == ruleast.ClassificationServerOnly {
			// Server-only rules slipping onto the wire is an upstream bug,
			// not a runtime-cap violation. Skip silently — the next
			// Refresh() on the server will repair the wire payload.
			continue
		}
		parsed = append(parsed, artefact)
	}
	var matcher ruleast.IOCEnv
	if iocStore != nil {
		matcher = iocStore
	}
	out, err := ruleengine.CompileArtefacts(parsed, telem, matcher)
	if err != nil {
		return nil, warnings, fmt.Errorf("compileRuleSet: wrap: %w", err)
	}
	return out, warnings, nil
}

// formatWarning renders a refusal as the wire-level
// `rule:<id>:<reason>` shape. The empty rule_id is preserved so the
// server log shows `rule::reason` rather than dropping the warning —
// makes operator sees-something-wrong easier than sees-nothing.
func formatWarning(ruleID, reason string) string {
	return fmt.Sprintf("rule:%s:%s", ruleID, reason)
}
