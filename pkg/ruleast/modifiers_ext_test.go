package ruleast

import (
	"strings"
	"testing"
)

// compileRuleBody wraps a detection block in the minimal valid Sigma
// envelope and returns the compiled edge Rule. Category defaults to
// network_connection because most of the new-modifier fixtures key on
// ports; callers needing another category pass it explicitly.
func compileRuleBody(t *testing.T, category, detection string) *Rule {
	t.Helper()
	src := "title: t\nid: 8b7c4d00-0001-4000-8000-0000000000ff\n" +
		"logsource:\n  product: linux\n  category: " + category + "\n" +
		"detection:\n" + detection
	art, _, _, err := Compile([]byte(src))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if art == nil {
		t.Fatalf("expected edge artefact, got server-only classification")
	}
	return art.Rule
}

func expectCompileErr(t *testing.T, category, detection, want string) {
	t.Helper()
	src := "title: t\nid: 8b7c4d00-0001-4000-8000-0000000000ff\n" +
		"logsource:\n  product: linux\n  category: " + category + "\n" +
		"detection:\n" + detection
	_, _, _, err := Compile([]byte(src))
	if err == nil {
		t.Fatalf("expected compile error containing %q, got nil", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("error %q does not contain %q", err.Error(), want)
	}
}

// --- Feature: numeric comparison operators (|gt |gte |lt |lte) ---------

func TestNumericComparisonOperators(t *testing.T) {
	rule := compileRuleBody(t, "network_connection",
		"  selection:\n    DestinationPort|gte: 1024\n  condition: selection\n")

	if !rule.Match(mapEnv{"DestinationPort": {"8080"}}) {
		t.Errorf("8080 >= 1024 should match")
	}
	if rule.Match(mapEnv{"DestinationPort": {"80"}}) {
		t.Errorf("80 >= 1024 should not match")
	}
	if rule.Match(mapEnv{"DestinationPort": {"not-a-number"}}) {
		t.Errorf("non-numeric field value must never match a numeric op")
	}

	lt := compileRuleBody(t, "network_connection",
		"  selection:\n    DestinationPort|lt: 1024\n  condition: selection\n")
	if !lt.Match(mapEnv{"DestinationPort": {"22"}}) {
		t.Errorf("22 < 1024 should match")
	}
	if lt.Match(mapEnv{"DestinationPort": {"1024"}}) {
		t.Errorf("1024 < 1024 should not match")
	}
}

func TestNumericOperatorRejectsNonNumericValue(t *testing.T) {
	expectCompileErr(t, "network_connection",
		"  selection:\n    DestinationPort|gt: banana\n  condition: selection\n",
		"numeric modifier")
}

func TestNumericOperatorRejectsEncodingModifier(t *testing.T) {
	expectCompileErr(t, "network_connection",
		"  selection:\n    DestinationPort|gt|base64: 10\n  condition: selection\n",
		"composes only with")
}

// --- Feature: |exists modifier -----------------------------------------

func TestExistsModifier(t *testing.T) {
	present := compileRuleBody(t, "process_creation",
		"  selection:\n    User|exists: true\n  condition: selection\n")
	if !present.Match(mapEnv{"User": {"root"}}) {
		t.Errorf("exists:true should match a populated field")
	}
	if present.Match(mapEnv{"Image": {"/bin/sh"}}) {
		t.Errorf("exists:true should not match when the field is absent")
	}

	absent := compileRuleBody(t, "process_creation",
		"  selection:\n    User|exists: false\n  condition: selection\n")
	if !absent.Match(mapEnv{"Image": {"/bin/sh"}}) {
		t.Errorf("exists:false should match when the field is absent")
	}
	if absent.Match(mapEnv{"User": {"root"}}) {
		t.Errorf("exists:false should not match a populated field")
	}
}

func TestExistsRejectsNonBoolAndComposition(t *testing.T) {
	expectCompileErr(t, "process_creation",
		"  selection:\n    User|exists: root\n  condition: selection\n",
		"boolean value")
	expectCompileErr(t, "process_creation",
		"  selection:\n    User|exists|contains: x\n  condition: selection\n",
		"takes no match operator")
	expectCompileErr(t, "process_creation",
		"  selection:\n    User|exists|all: true\n  condition: selection\n",
		"standalone")
}

// --- Feature: |cased modifier ------------------------------------------

func TestCasedModifier(t *testing.T) {
	eq := compileRuleBody(t, "process_creation",
		"  selection:\n    Image|cased: /usr/bin/SSH\n  condition: selection\n")
	if !eq.Match(mapEnv{"Image": {"/usr/bin/SSH"}}) {
		t.Errorf("cased equals should match the exact case")
	}
	if eq.Match(mapEnv{"Image": {"/usr/bin/ssh"}}) {
		t.Errorf("cased equals should not match a different case")
	}

	contains := compileRuleBody(t, "process_creation",
		"  selection:\n    CommandLine|cased|contains: AWS_SECRET\n  condition: selection\n")
	if !contains.Match(mapEnv{"CommandLine": {"export AWS_SECRET=1"}}) {
		t.Errorf("cased contains should match the exact-case substring")
	}
	if contains.Match(mapEnv{"CommandLine": {"export aws_secret=1"}}) {
		t.Errorf("cased contains should not match a lowercased substring")
	}
}

func TestCasedRejectsNonStringOp(t *testing.T) {
	expectCompileErr(t, "network_connection",
		"  selection:\n    SourceIp|cased|cidr: 10.0.0.0/8\n  condition: selection\n",
		"cased")
}

// --- Feature: regex flag sub-modifiers (|re|i |re|m |re|s) -------------

func TestRegexFlagInsensitive(t *testing.T) {
	rule := compileRuleBody(t, "process_creation",
		"  selection:\n    CommandLine|re|i: powershell\n  condition: selection\n")
	if !rule.Match(mapEnv{"CommandLine": {"PowerShell -enc"}}) {
		t.Errorf("re|i should match case-insensitively")
	}
	// Without the flag the same pattern is case-sensitive.
	sensitive := compileRuleBody(t, "process_creation",
		"  selection:\n    CommandLine|re: powershell\n  condition: selection\n")
	if sensitive.Match(mapEnv{"CommandLine": {"PowerShell -enc"}}) {
		t.Errorf("plain re should stay case-sensitive")
	}
}

func TestRegexFlagRejectedWithoutRegexOp(t *testing.T) {
	expectCompileErr(t, "process_creation",
		"  selection:\n    CommandLine|i: x\n  condition: selection\n",
		"regex flags")
}

// --- Improvement: UTF-16 surrogate-pair encoding -----------------------

func TestEncodeUTF16NonBMP(t *testing.T) {
	// U+1F600 (grinning face) is outside the BMP; a correct UTF-16LE
	// encoding is the surrogate pair D8 3D DE 00 (little-endian bytes
	// 3D D8 00 DE). The old truncating encoder produced 2 bytes and
	// dropped the high surrogate entirely.
	got := encodeUTF16LE("\U0001F600")
	want := string([]byte{0x3D, 0xD8, 0x00, 0xDE})
	if got != want {
		t.Errorf("encodeUTF16LE(non-BMP) = % x, want % x", got, want)
	}
	if len(encodeUTF16BE("\U0001F600")) != 4 {
		t.Errorf("encodeUTF16BE(non-BMP) should be a 4-byte surrogate pair")
	}
	// ASCII stays byte-identical to the naive encoding.
	if encodeUTF16LE("A") != string([]byte{'A', 0}) {
		t.Errorf("ASCII UTF-16LE regressed")
	}
}

// --- Improvement: timeframe decimal-overflow guard ---------------------

func TestTimeframeOverflowRejected(t *testing.T) {
	if _, err := parseUintStrict("99999999999999999999999"); err == nil {
		t.Errorf("expected overflow error for a 23-digit value")
	}
	if v, err := parseUintStrict("4294967295"); err != nil || v != 4294967295 {
		t.Errorf("parseUintStrict lost a legitimate value: %d, %v", v, err)
	}
}
