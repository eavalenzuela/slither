package console

import (
	"testing"

	"github.com/t3rmit3/slither/server/internal/store/pg"
)

func TestMapOIDCRole_StringClaim(t *testing.T) {
	t.Parallel()
	role, ok := mapOIDCRole(map[string]any{"role": "slither-admin"}, "role",
		map[string]string{"slither-admin": "admin"})
	if !ok {
		t.Fatal("not mapped")
	}
	if role != pg.RoleAdmin {
		t.Errorf("role = %s, want admin", role)
	}
}

func TestMapOIDCRole_ArrayClaim_FirstMatchWins(t *testing.T) {
	t.Parallel()
	role, ok := mapOIDCRole(
		map[string]any{"groups": []any{"unrelated", "slither-analyst", "slither-admin"}},
		"groups",
		map[string]string{
			"slither-admin":   "admin",
			"slither-analyst": "analyst",
		},
	)
	if !ok {
		t.Fatal("not mapped")
	}
	// "slither-analyst" appears first in the claim array → wins.
	if role != pg.RoleAnalyst {
		t.Errorf("role = %s, want analyst (first match in array)", role)
	}
}

func TestMapOIDCRole_NoMatch(t *testing.T) {
	t.Parallel()
	_, ok := mapOIDCRole(
		map[string]any{"groups": []any{"unrelated"}},
		"groups",
		map[string]string{"slither-admin": "admin"},
	)
	if ok {
		t.Error("expected no mapping")
	}
}

func TestMapOIDCRole_MissingClaim(t *testing.T) {
	t.Parallel()
	_, ok := mapOIDCRole(
		map[string]any{"other": "x"},
		"groups",
		map[string]string{"x": "admin"},
	)
	if ok {
		t.Error("mapped despite missing claim")
	}
}

func TestMapOIDCRole_StringSliceClaim(t *testing.T) {
	t.Parallel()
	role, ok := mapOIDCRole(
		map[string]any{"groups": []string{"slither-viewer"}},
		"groups",
		map[string]string{"slither-viewer": "viewer"},
	)
	if !ok {
		t.Fatal("not mapped")
	}
	if role != pg.RoleViewer {
		t.Errorf("role = %s, want viewer", role)
	}
}

func TestPKCEChallenge_RFC7636Reference(t *testing.T) {
	t.Parallel()
	// RFC 7636 §B sample: verifier "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	// → S256 challenge "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	got := pkceChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
	want := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if got != want {
		t.Errorf("pkceChallenge = %q, want %q", got, want)
	}
}

func TestRandURLString_NonEmptyAndUnique(t *testing.T) {
	t.Parallel()
	a, err := randURLString(32)
	if err != nil {
		t.Fatalf("rand: %v", err)
	}
	b, err := randURLString(32)
	if err != nil {
		t.Fatalf("rand: %v", err)
	}
	if a == "" || b == "" {
		t.Fatal("empty random")
	}
	if a == b {
		t.Error("two random strings identical (extreme bad luck or bug)")
	}
}

func TestStringClaim_TrimsAndDefaults(t *testing.T) {
	t.Parallel()
	if got := stringClaim(map[string]any{"email": "  alice@example.com  "}, "email"); got != "alice@example.com" {
		t.Errorf("got %q, want trimmed", got)
	}
	if got := stringClaim(map[string]any{"email": 42}, "email"); got != "" {
		t.Errorf("non-string claim returned %q", got)
	}
	if got := stringClaim(nil, ""); got != "" {
		t.Errorf("empty name returned %q", got)
	}
}

func TestClaimValueStrings_Variants(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   any
		want []string
	}{
		{"string", "x", []string{"x"}},
		{"[]string", []string{"a", "b"}, []string{"a", "b"}},
		{"[]any-strings", []any{"a", "b"}, []string{"a", "b"}},
		{"[]any-mixed", []any{"a", 5, "c"}, []string{"a", "c"}},
		{"int", 42, nil},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			got := claimValueStrings(c.in)
			if len(got) != len(c.want) {
				t.Errorf("len = %d, want %d (got %v)", len(got), len(c.want), got)
				return
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Errorf("got[%d] = %q, want %q", i, got[i], c.want[i])
				}
			}
		})
	}
}
