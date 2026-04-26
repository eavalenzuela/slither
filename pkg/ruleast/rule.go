package ruleast

import (
	"fmt"
	"net/netip"
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

// Operator enumerates the Sigma field-match shapes we honour. The default
// (no modifier) is OpEquals; Sigma matches on case-insensitive equality.
// OpCIDR replaces the match shape entirely — values are parsed as CIDR
// prefixes and the field is checked with Prefix.Contains.
type Operator uint8

const (
	OpEquals Operator = iota
	OpContains
	OpStartsWith
	OpEndsWith
	OpRegex
	OpCIDR
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
	case OpCIDR:
		return "cidr"
	}
	return fmt.Sprintf("op(%d)", o)
}

// Modifiers is a bitmask of the orthogonal Sigma modifiers that compose
// with an Operator. The encoding modifiers (Base64, Base64Offset,
// UTF16LE, UTF16BE) transform the *value* at compile time; the result
// lands directly in FieldPredicate.Values so the runtime hot path
// stays branch-light. ModAll changes value-side semantics from OR to
// AND. ModNull short-circuits Eval to check field absence.
type Modifiers uint16

const (
	// ModAll: every value in the predicate must match (instead of any).
	ModAll Modifiers = 1 << iota
	// ModNull: predicate matches when the field is unset / empty.
	// Standalone — combines with no other modifier.
	ModNull
	// ModBase64: each value is base64-encoded at compile time so the
	// runtime sees only the encoded form. Match shape stays whatever
	// the operator says (equals by default, or contains if chained).
	ModBase64
	// ModBase64Offset: each value is encoded three times at offsets
	// 0/1/2 to detect base64-embedded substrings regardless of byte
	// alignment. Implies contains semantics — exact-match offsets are
	// not meaningful.
	ModBase64Offset
	// ModUTF16LE: UTF-16 little-endian encoded value. Each ASCII byte
	// becomes (low, 0).
	ModUTF16LE
	// ModUTF16BE: UTF-16 big-endian. Each ASCII byte becomes (0, low).
	ModUTF16BE
	// ModUTF16: equivalent to ModUTF16LE plus a UTF-16 BOM (0xFF 0xFE)
	// prefix on each value.
	ModUTF16
)

func (m Modifiers) Has(flag Modifiers) bool { return m&flag != 0 }

// String renders the active flags for debugging / golden tests.
// Returns "" for an empty mask so leaf-only predicates stay readable.
func (m Modifiers) String() string {
	if m == 0 {
		return ""
	}
	parts := make([]string, 0, 4)
	if m.Has(ModAll) {
		parts = append(parts, "all")
	}
	if m.Has(ModNull) {
		parts = append(parts, "null")
	}
	if m.Has(ModBase64) {
		parts = append(parts, "base64")
	}
	if m.Has(ModBase64Offset) {
		parts = append(parts, "base64offset")
	}
	if m.Has(ModUTF16LE) {
		parts = append(parts, "utf16le")
	}
	if m.Has(ModUTF16BE) {
		parts = append(parts, "utf16be")
	}
	if m.Has(ModUTF16) {
		parts = append(parts, "utf16")
	}
	return strings.Join(parts, "|")
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

// Selection is a named OR-of-AND group of field predicates. Sigma's
// selection semantics:
//
//   - A map body produces a single branch where keys AND together.
//   - A list-of-maps body (added in §5.1 #54c) produces one branch per
//     list element; branches OR together. Each map within the list
//     keeps the standard keys-AND semantics.
//
// Single-branch selections (the common case) keep len(Branches) == 1
// so the golden output stays identical to pre-#54c.
type Selection struct {
	Name     string
	Branches [][]FieldPredicate
}

// Eval returns true when at least one branch's predicates all match.
func (s *Selection) Eval(env Env) bool {
	for _, branch := range s.Branches {
		all := true
		for i := range branch {
			if !branch[i].Eval(env) {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	return false
}

// Cost reports the total number of predicates across every branch —
// the engine uses this to order rules cheap-first.
func (s *Selection) Cost() int {
	n := 0
	for _, b := range s.Branches {
		n += len(b)
	}
	return n
}

// FieldPredicate is a single "field[|modifier...]: value-or-list" entry.
// Encoding modifiers (base64, utf16*) are applied at compile time to
// produce the strings in Values; the runtime evaluator deals only with
// the post-transform forms.
type FieldPredicate struct {
	Field   string
	Op      Operator
	Mods    Modifiers
	Values  []string // OR across values, unless ModAll flips to AND
	regexps []*regexp.Regexp
	cidrs   []netip.Prefix // populated when Op == OpCIDR
}

// Eval returns true when the predicate's match condition holds against
// env. Semantics by modifier:
//
//   - ModNull alone: true when the field is absent or has no values.
//   - ModAll: every value in Values must match somewhere in the field's
//     bound values. Without ModAll: any single value match suffices.
//   - OpCIDR: at least one CIDR contains the field's value (or all,
//     under ModAll). Field values must parse as netip.Addr; non-IP
//     values match nothing.
//   - default: Op-specific case-insensitive string match across the
//     bound values × Values cross product.
func (p *FieldPredicate) Eval(env Env) bool {
	if p.Mods.Has(ModNull) {
		bound, ok := env.Lookup(p.Field)
		return !ok || len(bound) == 0
	}
	bound, ok := env.Lookup(p.Field)
	if !ok || len(bound) == 0 {
		return false
	}
	if p.Mods.Has(ModAll) {
		for i, want := range p.Values {
			matched := false
			for _, have := range bound {
				if p.matchOne(have, want, i) {
					matched = true
					break
				}
			}
			if !matched {
				return false
			}
		}
		return true
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
	case OpCIDR:
		if idx < 0 || idx >= len(p.cidrs) || !p.cidrs[idx].IsValid() {
			return false
		}
		addr, err := netip.ParseAddr(have)
		if err != nil {
			return false
		}
		return p.cidrs[idx].Contains(addr)
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

// NodeQuantifier is the compiled form of "<count> of <target>".
// Targets are pre-resolved at compile time so runtime evaluation never
// touches the selection map. Threshold reflects the effective count
// after wildcard expansion ("all" → len(targets), "any" → 1, numeric
// counts clamped to len(targets) so "5 of x*" with 3 matches becomes
// AND across all 3).
type NodeQuantifier struct {
	Threshold int
	Targets   []*Selection
	Label     string
}

// Eval short-circuits as soon as Threshold matches accumulate.
func (n *NodeQuantifier) Eval(env Env) bool {
	if n.Threshold <= 0 || len(n.Targets) == 0 {
		return false
	}
	hits := 0
	for _, sel := range n.Targets {
		if sel.Eval(env) {
			hits++
			if hits >= n.Threshold {
				return true
			}
		}
	}
	return false
}

// Cost is the sum of target selection costs — the engine treats
// quantifiers as the "compound" expense of every branch they cover.
func (n *NodeQuantifier) Cost() int {
	total := 0
	for _, sel := range n.Targets {
		total += sel.Cost()
	}
	return total
}

func (n *NodeQuantifier) String() string {
	if n.Label != "" {
		return n.Label
	}
	return fmt.Sprintf("%d of (%d targets)", n.Threshold, len(n.Targets))
}
