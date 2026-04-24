package ruleast

import (
	"fmt"
	"regexp"
	"strings"
)

// Category is the Sigma logsource category slither recognises in Phase 1.
type Category string

const (
	CategoryProcessCreation   Category = "process_creation"
	CategoryFileEvent         Category = "file_event"
	CategoryNetworkConnection Category = "network_connection"
)

// Level maps Sigma's severity vocabulary to slither's own enum. We keep
// strings round-trippable so rule authors aren't surprised by remapping.
type Level string

const (
	LevelInformational Level = "informational"
	LevelLow           Level = "low"
	LevelMedium        Level = "medium"
	LevelHigh          Level = "high"
	LevelCritical      Level = "critical"
)

// Operator enumerates the Sigma field modifiers we honour. The default (no
// modifier) is OpEquals; Sigma matches on substring equality after case-fold.
type Operator uint8

const (
	OpEquals Operator = iota
	OpContains
	OpStartsWith
	OpEndsWith
	OpRegex
)

func (o Operator) String() string {
	switch o {
	case OpEquals:
		return "equals"
	case OpContains:
		return "contains"
	case OpStartsWith:
		return "startswith"
	case OpEndsWith:
		return "endswith"
	case OpRegex:
		return "regex"
	}
	return fmt.Sprintf("op(%d)", o)
}

// Rule is the compiled form of a Sigma YAML document.
type Rule struct {
	ID          string
	Title       string
	Description string
	Level       Level
	Category    Category
	Tags        []string

	Selections map[string]*Selection
	Condition  Expr

	cost int
}

// Cost returns the sum of predicates across the rule. The ruleengine uses
// this to order rules cheap-first so short-circuit evaluation pays off.
func (r *Rule) Cost() int { return r.cost }

// Match evaluates the rule's condition against env. A nil rule panics — rules
// are always constructed by the compiler, so a nil receiver is a bug.
func (r *Rule) Match(env Env) bool {
	if r.Condition == nil {
		return false
	}
	return r.Condition.Eval(env)
}

// Env is the lookup interface the rule evaluates against. The ruleengine
// supplies an OCSF-event-backed implementation; tests supply a map.
type Env interface {
	// Lookup returns the string values bound to field in the current event,
	// or (nil, false) if the field isn't populated. Non-string values are
	// expected to be stringified by the Env — the AST operates on strings
	// so Sigma's string-modifier semantics stay uniform.
	Lookup(field string) ([]string, bool)
}

// Selection is a named conjunction of field predicates. Sigma's selection
// semantics: within a map, keys AND; the value side (scalar or list) ORs.
type Selection struct {
	Name   string
	Fields []FieldPredicate
}

// Eval returns true when every FieldPredicate matches.
func (s *Selection) Eval(env Env) bool {
	for i := range s.Fields {
		if !s.Fields[i].Eval(env) {
			return false
		}
	}
	return true
}

// Cost reports the number of predicates in the selection.
func (s *Selection) Cost() int { return len(s.Fields) }

// FieldPredicate is a single "field[|modifier]: value-or-list" entry.
type FieldPredicate struct {
	Field   string
	Op      Operator
	Values  []string // OR across values
	regexps []*regexp.Regexp
}

// Eval returns true when at least one of Values matches any bound value of
// Field according to Op. Case-insensitive string comparison follows Sigma
// defaults for equals/contains/startswith/endswith; regex is case-sensitive.
func (p *FieldPredicate) Eval(env Env) bool {
	bound, ok := env.Lookup(p.Field)
	if !ok {
		return false
	}
	for _, have := range bound {
		for i, want := range p.Values {
			if p.matchOne(have, want, i) {
				return true
			}
		}
	}
	return false
}

func (p *FieldPredicate) matchOne(have, want string, idx int) bool {
	switch p.Op {
	case OpEquals:
		return strings.EqualFold(have, want)
	case OpContains:
		return strings.Contains(strings.ToLower(have), strings.ToLower(want))
	case OpStartsWith:
		return strings.HasPrefix(strings.ToLower(have), strings.ToLower(want))
	case OpEndsWith:
		return strings.HasSuffix(strings.ToLower(have), strings.ToLower(want))
	case OpRegex:
		if idx < 0 || idx >= len(p.regexps) || p.regexps[idx] == nil {
			return false
		}
		return p.regexps[idx].MatchString(have)
	}
	return false
}

// Expr is the boolean tree produced by the condition parser.
type Expr interface {
	// Eval walks the tree against env and returns the rule outcome.
	Eval(env Env) bool
	// Cost is the sum of predicate costs reachable from this node. Used by
	// the engine for cheap-first rule ordering.
	Cost() int
	// String renders the expression for debugging / golden tests.
	String() string
}

// NodeSelection references a named selection by pointer. The compiler
// resolves the name at compile time so runtime eval doesn't hit the map.
type NodeSelection struct {
	Name string
	Sel  *Selection
}

func (n *NodeSelection) Eval(env Env) bool { return n.Sel.Eval(env) }
func (n *NodeSelection) Cost() int         { return n.Sel.Cost() }
func (n *NodeSelection) String() string    { return n.Name }

// NodeAnd is short-circuit logical AND.
type NodeAnd struct{ L, R Expr }

func (n *NodeAnd) Eval(env Env) bool { return n.L.Eval(env) && n.R.Eval(env) }
func (n *NodeAnd) Cost() int         { return n.L.Cost() + n.R.Cost() }
func (n *NodeAnd) String() string    { return fmt.Sprintf("(%s and %s)", n.L, n.R) }

// NodeOr is short-circuit logical OR.
type NodeOr struct{ L, R Expr }

func (n *NodeOr) Eval(env Env) bool { return n.L.Eval(env) || n.R.Eval(env) }
func (n *NodeOr) Cost() int         { return n.L.Cost() + n.R.Cost() }
func (n *NodeOr) String() string    { return fmt.Sprintf("(%s or %s)", n.L, n.R) }

// NodeNot negates its child.
type NodeNot struct{ X Expr }

func (n *NodeNot) Eval(env Env) bool { return !n.X.Eval(env) }
func (n *NodeNot) Cost() int         { return n.X.Cost() }
func (n *NodeNot) String() string    { return fmt.Sprintf("(not %s)", n.X) }
