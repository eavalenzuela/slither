package ruleast

import (
	"fmt"
	"strings"
	"unicode"
)

// parseCondition turns a Sigma condition string into an Expr. The grammar
// we accept in Phase 1:
//
//   expr   := or
//   or     := and ("or" and)*
//   and    := not ("and" not)*
//   not    := "not" not | primary
//   primary:= IDENT | "(" expr ")"
//
// Every IDENT must resolve against selections. "1 of", "all of", "them"
// wildcard forms return a compile error so unsupported shapes fail loudly.
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
		if unicode.IsDigit(r) || r == '|' {
			// Numeric prefixes and pipe operators only appear in the
			// quantified forms ("1 of ...", "all of ... | count() > 5")
			// which are explicitly outside Phase 1.
			return nil, fmt.Errorf("numeric/pipe operators not supported in Phase 1 (e.g. \"1 of\", \"| count\")")
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
			case "of", "them":
				return nil, fmt.Errorf("unsupported condition keyword %q (Phase 1 rejects \"N of\" / \"them\" forms)", word)
			default:
				if strings.ContainsRune(word, '*') {
					return nil, fmt.Errorf("selection wildcard %q not supported in Phase 1", word)
				}
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
	case tokIdent:
		sel, ok := p.sels[t.value]
		if !ok {
			return nil, fmt.Errorf("unknown selection %q", t.value)
		}
		return &NodeSelection{Name: t.value, Sel: sel}, nil
	default:
		return nil, fmt.Errorf("unexpected token %q", t.value)
	}
}
