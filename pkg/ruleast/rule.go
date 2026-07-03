package ruleast

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
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
	// OpIOC matches a field's value against the entries of one or
	// more IOC feeds. Predicate values are interpreted as feed_ids;
	// the runtime resolves them via Env.MatchIOC. Composes with no
	// other modifiers (#66).
	OpIOC
	// OpGT/OpGTE/OpLT/OpLTE are Sigma's numeric comparison modifiers
	// (`|gt`, `|gte`, `|lt`, `|lte`). The field value and the predicate
	// value are both parsed as numbers at runtime; a value that doesn't
	// parse numerically never matches. Useful for ports, PIDs, sizes.
	// They compose only with ModAll — encoding/CIDR/regex modifiers are
	// rejected at compile time.
	OpGT
	OpGTE
	OpLT
	OpLTE
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
	case OpIOC:
		return "ioc"
	case OpGT:
		return "gt"
	case OpGTE:
		return "gte"
	case OpLT:
		return "lt"
	case OpLTE:
		return "lte"
	}
	return fmt.Sprintf("op(%d)", o)
}

// isNumeric reports whether the operator is one of the numeric
// comparison shapes (gt/gte/lt/lte).
func (o Operator) isNumeric() bool {
	return o == OpGT || o == OpGTE || o == OpLT || o == OpLTE
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
	// ModExists: presence check driven by a boolean value —
	// `Field|exists: true` matches when the field is populated,
	// `Field|exists: false` when it is absent. Standalone, like ModNull.
	ModExists
	// ModCased: switch the string match from Sigma's default
	// case-insensitive comparison to a case-sensitive one. Composes with
	// the string operators (equals/contains/startswith/endswith) and the
	// encoding modifiers; rejected on cidr/ioc/regex/numeric operators.
	ModCased
	// ModReI/ModReM/ModReS are regex sub-modifiers (`|re|i`, `|re|m`,
	// `|re|s`) that set the case-insensitive, multiline, and dot-all
	// flags on the compiled pattern. Only valid alongside OpRegex.
	ModReI
	ModReM
	ModReS
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
	if m.Has(ModExists) {
		parts = append(parts, "exists")
	}
	if m.Has(ModCased) {
		parts = append(parts, "cased")
	}
	if m.Has(ModReI) {
		parts = append(parts, "re_i")
	}
	if m.Has(ModReM) {
		parts = append(parts, "re_m")
	}
	if m.Has(ModReS) {
		parts = append(parts, "re_s")
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

	// Aggregation is non-nil for stateful rules carrying a `| count() …`
	// pipe. The boolean tree in Condition still evaluates per-event; the
	// aggregation is applied by the stateful runtime (#56) on the matching
	// stream. Stateless rules leave this nil and the runtime evaluates
	// Condition directly.
	Aggregation *Aggregation

	cost int
}

// AggFunc enumerates the pipe-aggregation functions the compiler accepts.
// #54d ships only count(); near() and avg()/sum() arrive with #54e and
// later phases.
type AggFunc uint8

const (
	AggCount AggFunc = iota + 1
)

func (a AggFunc) String() string {
	if a == AggCount {
		return "count"
	}
	return "?"
}

// AggOp is the comparison operator on the aggregation's threshold.
type AggOp uint8

const (
	AggGT AggOp = iota + 1
	AggGTE
	AggLT
	AggLTE
	AggEQ
	AggNE
)

func (o AggOp) String() string {
	switch o {
	case AggGT:
		return ">"
	case AggGTE:
		return ">="
	case AggLT:
		return "<"
	case AggLTE:
		return "<="
	case AggEQ:
		return "=="
	case AggNE:
		return "!="
	}
	return "?"
}

// Aggregation is the parsed form of a Sigma pipe expression
// (`| count() [by Field[, Field...]] OP N`). The compiler attaches it to
// Rule when the condition string contains a pipe; the agent's stateful
// runtime (Phase 3 #56) consumes it.
type Aggregation struct {
	Function  AggFunc
	By        []string
	Op        AggOp
	Threshold int64

	// TimeframeSecs is the rule's top-level `timeframe` rendered in
	// seconds. Zero means no timeframe, which is rejected at compile time
	// for stateful rules — every aggregation must be bounded.
	TimeframeSecs uint32
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

// IOCEnv is an optional capability an Env can advertise to evaluate
// `|ioc:<feed_id>` predicates. An Env that doesn't implement IOCEnv
// causes IOC predicates to evaluate false — useful in tests, but in
// production every agent + server Env wires this up.
type IOCEnv interface {
	// MatchIOC reports whether value is present in the IOC feed
	// identified by feedID. A missing feed returns false (rather than
	// erroring) so a runtime feed reload race can't crash the
	// evaluator; the compile-time gate already validated feed
	// presence.
	MatchIOC(feedID, value string) bool
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
	Field  string
	Op     Operator
	Mods   Modifiers
	Values []string // OR across values, unless ModAll flips to AND.
	// FeedIDs holds the IOC feed identifiers Op == OpIOC resolves at
	// runtime. Sigma's `|ioc` modifier puts feed_ids into the YAML
	// value position; the compiler moves them here so Values stays
	// reserved for string-match Operators.
	FeedIDs []string
	regexps []*regexp.Regexp
	cidrs   []netip.Prefix // populated when Op == OpCIDR
	// foldValues holds the pre-lowercased form of Values for the
	// case-insensitive string operators (contains/startswith/endswith),
	// computed once at compile time so the runtime hot path never
	// re-folds a constant. Empty for cased/regex/cidr/numeric/ioc
	// predicates. Indexed in lockstep with Values.
	foldValues []string
	// existsWant is the boolean carried by a `|exists` predicate: true
	// means "match when present", false means "match when absent".
	existsWant bool
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
	if p.Mods.Has(ModExists) {
		bound, ok := env.Lookup(p.Field)
		present := ok && len(bound) > 0
		return present == p.existsWant
	}
	if p.Mods.Has(ModNull) {
		bound, ok := env.Lookup(p.Field)
		return !ok || len(bound) == 0
	}
	bound, ok := env.Lookup(p.Field)
	if !ok || len(bound) == 0 {
		return false
	}
	if p.Op == OpIOC {
		ioc, ok := env.(IOCEnv)
		if !ok {
			return false
		}
		// OR across feeds AND OR across bound values: any (feed, value)
		// hit fires the predicate. ModAll is rejected at compile time
		// for OpIOC since intersecting feeds rarely makes sense for
		// indicator matching.
		for _, feed := range p.FeedIDs {
			for _, have := range bound {
				if ioc.MatchIOC(feed, have) {
					return true
				}
			}
		}
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
	cased := p.Mods.Has(ModCased)
	switch p.Op {
	case OpEquals:
		if cased {
			return have == want
		}
		return strings.EqualFold(have, want)
	case OpContains:
		if cased {
			return strings.Contains(have, want)
		}
		return strings.Contains(strings.ToLower(have), p.fold(want, idx))
	case OpStartsWith:
		if cased {
			return strings.HasPrefix(have, want)
		}
		return strings.HasPrefix(strings.ToLower(have), p.fold(want, idx))
	case OpEndsWith:
		if cased {
			return strings.HasSuffix(have, want)
		}
		return strings.HasSuffix(strings.ToLower(have), p.fold(want, idx))
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
		// Dual-stack sockets surface v4-mapped v6 addresses
		// (::ffff:a.b.c.d). Unmap so they still match v4 CIDR rules;
		// no-op for genuine v6 addresses.
		return p.cidrs[idx].Contains(addr.Unmap())
	case OpGT, OpGTE, OpLT, OpLTE:
		hv, herr := strconv.ParseFloat(have, 64)
		wv, werr := strconv.ParseFloat(want, 64)
		if herr != nil || werr != nil {
			return false
		}
		switch p.Op {
		case OpGT:
			return hv > wv
		case OpGTE:
			return hv >= wv
		case OpLT:
			return hv < wv
		case OpLTE:
			return hv <= wv
		}
	}
	return false
}

// fold returns the pre-lowercased want at idx when foldValues is
// populated, otherwise lowercases on the spot. The fast path (compiled
// predicates) always has foldValues; the fallback keeps hand-built
// predicates in tests correct.
func (p *FieldPredicate) fold(want string, idx int) string {
	if idx >= 0 && idx < len(p.foldValues) {
		return p.foldValues[idx]
	}
	return strings.ToLower(want)
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

// NodeNear is the compiled form of "<sel_a> near <sel_b>". Sigma's
// `near` is a temporal join: both selections must each match an event
// inside the rule's timeframe. Detection requires correlating two event
// streams, which an agent cannot do for events it never sees, so any
// rule containing NodeNear classifies ServerOnly and is consumed by
// the server detection engine (#58) — never by Rule.Match. Eval returns
// false defensively so a misuse panics loud rather than silently hits.
type NodeNear struct {
	L, R       *Selection
	WithinSecs uint32 // populated by compileSigma from the rule's top-level timeframe
}

// Eval is intentionally false — near requires temporal context the
// stateless evaluator can't supply. The detection engine recompiles the
// rule and walks ServerPlan.TemporalJoin instead.
func (n *NodeNear) Eval(env Env) bool { return false }
func (n *NodeNear) Cost() int         { return n.L.Cost() + n.R.Cost() }
func (n *NodeNear) String() string    { return fmt.Sprintf("(%s near %s)", n.L.Name, n.R.Name) }

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
