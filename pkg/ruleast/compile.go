package ruleast

// Compile is the §5.1 #54 entry point that returns the three-artefact
// trio defined in ADR-0032: an edge artefact for the agent, a server
// plan for the detection engine, and a classification routing the rule
// between them.
//
// #54a (this commit): every rule classifies as EdgeOnly. ServerPlan is
// always nil. ASTVersion is always V1. State bounds are always zero.
// The point of #54a is the API surface — the classification logic
// lights up in #54d. Until then, Compile is CompileSigma + a wrapper.
//
// Rules that fail YAML/Sigma parse return (nil, nil, "", err) wrapping
// ErrCompile, matching the previous CompileSigma contract.
func Compile(src []byte) (*EdgeArtefact, *ServerPlan, Classification, error) {
	rule, err := compileSigma(src)
	if err != nil {
		return nil, nil, "", err
	}
	return &EdgeArtefact{
		Rule:            rule,
		ASTVersion:      ASTVersionV1,
		StateWindowSecs: 0,
		StateCap:        0,
	}, nil, ClassificationEdgeOnly, nil
}
