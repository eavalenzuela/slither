package ruleast

import (
	"errors"
	"fmt"
)

// ErrCompile is the sentinel wrapping every compile-time rejection so callers
// can errors.Is() against it without depending on concrete types.
var ErrCompile = errors.New("ruleast: compile failed")

// compileError wraps an inner error with rule-identifying context. Keeping a
// named type lets tests assert on the rule id without depending on wording.
type compileError struct {
	ID    string
	Stage string
	Inner error
}

func (e *compileError) Error() string {
	if e.ID == "" {
		return fmt.Sprintf("%s: %v", e.Stage, e.Inner)
	}
	return fmt.Sprintf("%s rule %q: %v", e.Stage, e.ID, e.Inner)
}

func (e *compileError) Unwrap() error { return e.Inner }

func (e *compileError) Is(target error) bool { return target == ErrCompile }

func compileErr(id, stage string, inner error) error {
	return &compileError{ID: id, Stage: stage, Inner: inner}
}
