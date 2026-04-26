package ruleast

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// parseCondition turns a Sigma condition string into an Expr. Grammar
// accepted as of §5.1 #54c:
//
//	expr      := or
//	or        := and ("or" and)*
//	and       := not ("and" not)*
//	not       := "not" not | primary
//	primary   := quantifier | IDENT | "(" expr ")"
//	quantifier := count "of" target
//	count     := NUMBER | "all" | "any"
//	target    := "them" | IDENT [ "*" trailing... ]
//
// "1 of selection*" expands to OR over all selection-name matches;
// "all of them" expands to AND over every defined selection. Numeric
// thresholds (N of selection*) require at least N branches to match.
func parseCondition(src string, selections map[string]*Selection) (Expr, error) {
	toks, err := tokenizeCondition(src)
	if err != nil {
		return nil, err
	}
	p := &condParser{toks: toks, sels: selections}
	expr, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.pos != len(p.toks) {
		return nil, fmt.Errorf("unexpected token %q after expression", p.toks[p.pos].value)
	}
	return expr, nil
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
			// Pipe operators introduce aggregations (`| count() > N`)
			// which are scoped to #54d's stateful work.
			return nil, fmt.Errorf("pipe-aggregation forms not supported until #54d (e.g. \"| count\")")
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
