package enricher

import (
	"path"
	"strings"
)

// pathGlob is the Phase 1 userspace substitute for the in-kernel LPM-trie
// path filter described in IMPLEMENTATION.md §3.2. It supports the shape the
// sample config uses:
//
//   - `/prefix/**`          — any path under `/prefix`, inclusive
//   - `/prefix/*.suffix`    — path.Match semantics per segment (no cross-segment `*`)
//   - literal paths         — equality
//
// Empty include list means "allow any"; non-empty requires a match.
// Exclude always wins when both match.
type pathGlob struct {
	includes []string
	excludes []string
}

func newPathGlob(includes, excludes []string) *pathGlob {
	return &pathGlob{includes: includes, excludes: excludes}
}

// allow returns true when p should be emitted.
func (g *pathGlob) allow(p string) bool {
	if p == "" {
		return false
	}
	for _, pat := range g.excludes {
		if matchPattern(pat, p) {
			return false
		}
	}
	if len(g.includes) == 0 {
		return true
	}
	for _, pat := range g.includes {
		if matchPattern(pat, p) {
			return true
		}
	}
	return false
}

// matchPattern is a minimal glob implementation covering the two shapes we
// accept. Anything else falls through to literal equality so unexpected
// patterns don't silently over-match.
func matchPattern(pattern, p string) bool {
	if suffix, ok := strings.CutSuffix(pattern, "/**"); ok {
		// `/etc/**` matches `/etc` and anything under `/etc/`.
		if suffix == "" {
			return true
		}
		return p == suffix || strings.HasPrefix(p, suffix+"/")
	}
	if strings.ContainsAny(pattern, "*?[") {
		ok, err := path.Match(pattern, p)
		if err == nil && ok {
			return true
		}
	}
	return pattern == p
}
