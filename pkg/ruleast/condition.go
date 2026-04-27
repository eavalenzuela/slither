package ruleast

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// parseCondition turns a Sigma condition string into an Expr plus an
// optional Aggregation when the condition carries a pipe. Grammar
// accepted as of §5.1 #54e:
//
//	condition := near | or [ "|" aggregation ]
//	near      := IDENT "near" IDENT
//	or        := and ("or" and)*
//	and       := not ("and" not)*
//	not       := "not" not | primary
//	primary   := quantifier | IDENT | "(" or ")"
//	quantifier := count "of" target
//	count     := NUMBER | "all" | "any"
//	target    := "them" | IDENT [ "*" trailing... ]
//	aggregation := "count" "(" ")" [ "by" idlist ] cmpop NUMBER
//	cmpop       := ">" | ">=" | "<" | "<=" | "==" | "!="
//	idlist      := IDENT ("," IDENT)*
//
// "1 of selection*" expands to OR over all selection-name matches;
// "all of them" expands to AND over every defined selection. Numeric
// thresholds (N of selection*) require at least N branches to match.
//
// The pipe-aggregation tail makes the rule stateful — Compile turns it
// into a Rule.Aggregation and bumps ASTVersion. Stateless rules return
// (expr, nil, nil) and behave exactly as before #54d.
//
// `near` is a temporal-join keyword (#54e). The accepted form is binary
// `IDENT near IDENT`; richer compositions (e.g. `(sel_a or sel_b) near
// sel_c and not sel_d`) are rejected loud rather than silently allowed
// — Sigma 2.0 deprecated `near` and our compatibility scope is
// explicitly the binary form. Rules carrying `near` always classify
// ServerOnly per ADR-0018 predicate 1 (cross-stream correlation is not
// locally observable).
func parseCondition(src string, selections map[string]*Selection) (Expr, *Aggregation, error) {
	toks, err := tokenizeCondition(src)
	if err != nil {
		return nil, nil, err
	}
	p := &condParser{toks: toks, sels: selections}

	// Look ahead for binary near at the top level. Only `IDENT near
	// IDENT` is supported; anything more elaborate trips parseOr below
	// and falls through to the standard error path.
	if len(p.toks) == 3 && p.toks[0].kind == tokIdent && p.toks[1].kind == tokNear && p.toks[2].kind == tokIdent {
		left, lok := selections[p.toks[0].value]
		right, rok := selections[p.toks[2].value]
		if !lok {
			return nil, nil, fmt.Errorf("unknown selection %q", p.toks[0].value)
		}
		if !rok {
			return nil, nil, fmt.Errorf("unknown selection %q", p.toks[2].value)
		}
		return &NodeNear{L: left, R: right}, nil, nil
	}

	expr, err := p.parseOr()
	if err != nil {
		return nil, nil, err
	}
	if t, ok := p.peek(); ok && t.kind == tokNear {
		return nil, nil, fmt.Errorf("`near` is supported only in the binary form `selection_a near selection_b`; richer compositions are rejected per Phase 3 #54e")
	}
	var agg *Aggregation
	if t, ok := p.peek(); ok && t.kind == tokPipe {
		p.pos++
		agg, err = p.parseAggregation()
		if err != nil {
			return nil, nil, err
		}
	}
	if p.pos != len(p.toks) {
		return nil, nil, fmt.Errorf("unexpected token %q after expression", p.toks[p.pos].value)
	}
	return expr, agg, nil
}

type tokKind int

const (
	tokIdent tokKind = iota
	tokAnd
	tokOr
	tokNot
	tokLparen
	tokRparen
	tokNumber
	tokOf
	tokThem
	tokPipe
	tokComma
	tokCmp  // >, >=, <, <=, ==, !=
	tokNear // temporal-join keyword (#54e)
)

type condToken struct {
	kind  tokKind
	value string
}

func tokenizeCondition(src string) ([]condToken, error) {
	var out []condToken
	i := 0
	for i < len(src) {
		r := rune(src[i])
		if unicode.IsSpace(r) {
			i++
			continue
		}
		if r == '(' {
			out = append(out, condToken{kind: tokLparen, value: "("})
			i++
			continue
		}
		if r == ')' {
			out = append(out, condToken{kind: tokRparen, value: ")"})
			i++
			continue
		}
		if r == '|' {
			out = append(out, condToken{kind: tokPipe, value: "|"})
			i++
			continue
		}
		if r == ',' {
			out = append(out, condToken{kind: tokComma, value: ","})
			i++
			continue
		}
		if r == '>' || r == '<' {
			if i+1 < len(src) && src[i+1] == '=' {
				out = append(out, condToken{kind: tokCmp, value: src[i : i+2]})
				i += 2
				continue
			}
			out = append(out, condToken{kind: tokCmp, value: string(r)})
			i++
			continue
		}
		if r == '=' || r == '!' {
			if i+1 < len(src) && src[i+1] == '=' {
				out = append(out, condToken{kind: tokCmp, value: src[i : i+2]})
				i += 2
				continue
			}
			return nil, fmt.Errorf("unexpected character %q in condition (did you mean \"==\" / \"!=\"?)", r)
		}
		if unicode.IsDigit(r) {
			j := i
			for j < len(src) && unicode.IsDigit(rune(src[j])) {
				j++
			}
			out = append(out, condToken{kind: tokNumber, value: src[i:j]})
			i = j
			continue
		}
		if isIdentStart(r) {
			j := i
			for j < len(src) && isIdentPart(rune(src[j])) {
				j++
			}
			word := src[i:j]
			switch strings.ToLower(word) {
			case "and":
				out = append(out, condToken{kind: tokAnd, value: word})
			case "or":
				out = append(out, condToken{kind: tokOr, value: word})
			case "not":
				out = append(out, condToken{kind: tokNot, value: word})
			case "of":
				out = append(out, condToken{kind: tokOf, value: word})
			case "them":
				out = append(out, condToken{kind: tokThem, value: word})
			case "near":
				out = append(out, condToken{kind: tokNear, value: word})
			default:
				out = append(out, condToken{kind: tokIdent, value: word})
			}
			i = j
			continue
		}
		return nil, fmt.Errorf("unexpected character %q in condition", r)
	}
	return out, nil
}

func isIdentStart(r rune) bool {
	return unicode.IsLetter(r) || r == '_'
}

func isIdentPart(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '-' || r == '*'
}

type condParser struct {
	toks []condToken
	pos  int
	sels map[string]*Selection
}

func (p *condParser) peek() (condToken, bool) {
	if p.pos >= len(p.toks) {
		return condToken{}, false
	}
	return p.toks[p.pos], true
}

func (p *condParser) consume() (condToken, bool) {
	t, ok := p.peek()
	if ok {
		p.pos++
	}
	return t, ok
}

func (p *condParser) parseOr() (Expr, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for {
		t, ok := p.peek()
		if !ok || t.kind != tokOr {
			return left, nil
		}
		p.pos++
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = &NodeOr{L: left, R: right}
	}
}

func (p *condParser) parseAnd() (Expr, error) {
	left, err := p.parseNot()
	if err != nil {
		return nil, err
	}
	for {
		t, ok := p.peek()
		if !ok || t.kind != tokAnd {
			return left, nil
		}
		p.pos++
		right, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		left = &NodeAnd{L: left, R: right}
	}
}

func (p *condParser) parseNot() (Expr, error) {
	t, ok := p.peek()
	if ok && t.kind == tokNot {
		p.pos++
		inner, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		return &NodeNot{X: inner}, nil
	}
	return p.parsePrimary()
}

func (p *condParser) parsePrimary() (Expr, error) {
	t, ok := p.consume()
	if !ok {
		return nil, fmt.Errorf("unexpected end of condition")
	}
	switch t.kind {
	case tokLparen:
		inner, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		closing, ok := p.consume()
		if !ok || closing.kind != tokRparen {
			return nil, fmt.Errorf("missing ')' in condition")
		}
		return inner, nil
	case tokNumber:
		n, err := strconv.Atoi(t.value)
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("quantifier count %q must be a positive integer", t.value)
		}
		return p.parseQuantifier(n)
	case tokIdent:
		// Lower-cased "all" / "any" before "of" act as quantifier
		// counts. Anywhere else they're regular identifiers (and a
		// rule author who happens to name a selection "all" pays for
		// the surprise once).
		lower := strings.ToLower(t.value)
		if lower == "all" || lower == "any" {
			if next, ok := p.peek(); ok && next.kind == tokOf {
				count := -1 // sentinel: "all"
				if lower == "any" {
					count = 1
				}
				return p.parseQuantifier(count)
			}
		}
		sel, ok := p.sels[t.value]
		if !ok {
			return nil, fmt.Errorf("unknown selection %q", t.value)
		}
		return &NodeSelection{Name: t.value, Sel: sel}, nil
	default:
		return nil, fmt.Errorf("unexpected token %q", t.value)
	}
}

// parseQuantifier consumes the "of <target>" tail. count == -1 stands
// for "all" — resolved against the matched target slice at compile
// time. The returned Expr is a NodeQuantifier whose Targets slice has
// the resolved selections in lexicographic order.
func (p *condParser) parseQuantifier(count int) (Expr, error) {
	of, ok := p.consume()
	if !ok || of.kind != tokOf {
		return nil, fmt.Errorf("expected \"of\" after quantifier count")
	}
	t, ok := p.consume()
	if !ok {
		return nil, fmt.Errorf("expected target after \"of\"")
	}
	var targets []*Selection
	var label string
	switch t.kind {
	case tokThem:
		label = "them"
		for _, sel := range p.sels {
			targets = append(targets, sel)
		}
	case tokIdent:
		label = t.value
		match, err := matchSelections(p.sels, t.value)
		if err != nil {
			return nil, err
		}
		targets = match
	default:
		return nil, fmt.Errorf("unexpected quantifier target %q", t.value)
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("quantifier %q matched zero selections", label)
	}
	sort.SliceStable(targets, func(i, j int) bool {
		return targets[i].Name < targets[j].Name
	})
	threshold := count
	if threshold == -1 || threshold > len(targets) {
		threshold = len(targets)
	}
	return &NodeQuantifier{
		Threshold: threshold,
		Targets:   targets,
		Label:     fmt.Sprintf("%s of %s", quantifierCountString(count), label),
	}, nil
}

func quantifierCountString(count int) string {
	if count == -1 {
		return "all"
	}
	return strconv.Itoa(count)
}

// parseAggregation consumes the tail of the pipe expression. The pipe
// itself was already consumed by the caller. Grammar:
//
//	"count" "(" ")" [ "by" IDENT ("," IDENT)* ] cmp NUMBER
//
// The function set is single-entry today (count). near() / sum() etc.
// arrive with #54e and are intentionally not handled here so an unknown
// function fails compile loud rather than being silently accepted.
func (p *condParser) parseAggregation() (*Aggregation, error) {
	t, ok := p.consume()
	if !ok {
		return nil, fmt.Errorf("expected aggregation function after \"|\"")
	}
	if t.kind != tokIdent {
		return nil, fmt.Errorf("expected aggregation function after \"|\", got %q", t.value)
	}
	var fn AggFunc
	switch strings.ToLower(t.value) {
	case "count":
		fn = AggCount
	default:
		return nil, fmt.Errorf("unsupported aggregation function %q (only \"count\" is recognised in Phase 3 #54d)", t.value)
	}
	if open, openOk := p.consume(); !openOk || open.kind != tokLparen {
		return nil, fmt.Errorf("expected \"(\" after aggregation function")
	}
	if closeTok, closeOk := p.consume(); !closeOk || closeTok.kind != tokRparen {
		return nil, fmt.Errorf("expected \")\" after aggregation arguments (count() takes no field arg in this version)")
	}
	var by []string
	if next, nextOk := p.peek(); nextOk && next.kind == tokIdent && strings.EqualFold(next.value, "by") {
		p.pos++
		for {
			id, idOk := p.consume()
			if !idOk || id.kind != tokIdent {
				return nil, fmt.Errorf("expected field identifier after \"by\"")
			}
			by = append(by, id.value)
			peek, peekOk := p.peek()
			if !peekOk || peek.kind != tokComma {
				break
			}
			p.pos++
		}
	}
	cmp, cmpOk := p.consume()
	if !cmpOk || cmp.kind != tokCmp {
		return nil, fmt.Errorf("expected comparison operator after aggregation")
	}
	op, err := parseAggOp(cmp.value)
	if err != nil {
		return nil, err
	}
	num, numOk := p.consume()
	if !numOk || num.kind != tokNumber {
		return nil, fmt.Errorf("expected numeric threshold after %q", cmp.value)
	}
	threshold, err := strconv.ParseInt(num.value, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid threshold %q: %w", num.value, err)
	}
	return &Aggregation{
		Function:  fn,
		By:        by,
		Op:        op,
		Threshold: threshold,
	}, nil
}

func parseAggOp(s string) (AggOp, error) {
	switch s {
	case ">":
		return AggGT, nil
	case ">=":
		return AggGTE, nil
	case "<":
		return AggLT, nil
	case "<=":
		return AggLTE, nil
	case "==":
		return AggEQ, nil
	case "!=":
		return AggNE, nil
	}
	return 0, fmt.Errorf("unknown comparison operator %q", s)
}

// matchSelections expands a wildcard or bare-identifier target. A
// trailing "*" globs against every selection name; a literal IDENT
// resolves to a single selection or returns ErrCompile when missing.
func matchSelections(sels map[string]*Selection, pattern string) ([]*Selection, error) {
	if !strings.ContainsRune(pattern, '*') {
		sel, ok := sels[pattern]
		if !ok {
			return nil, fmt.Errorf("unknown selection %q", pattern)
		}
		return []*Selection{sel}, nil
	}
	// Sigma's wildcard is positional: only the trailing "*" is supported
	// today. A leading or middle "*" would require a real glob engine
	// and isn't used in any rule we've seen — reject loud.
	if !strings.HasSuffix(pattern, "*") || strings.Count(pattern, "*") != 1 {
		return nil, fmt.Errorf("selection wildcard %q must be a single trailing \"*\"", pattern)
	}
	prefix := strings.TrimSuffix(pattern, "*")
	var out []*Selection
	for name, sel := range sels {
		if strings.HasPrefix(name, prefix) {
			out = append(out, sel)
		}
	}
	return out, nil
}
