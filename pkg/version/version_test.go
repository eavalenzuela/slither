package version

import "testing"

func TestStringEmbedsVersionAndRevision(t *testing.T) {
	got := String()
	// Version defaults to "dev" in tests (no -ldflags override).
	if got == "" {
		t.Fatal("String() must not be empty")
	}
	if !contains(got, Version) {
		t.Errorf("String() = %q, want it to contain version %q", got, Version)
	}
	if !contains(got, Revision()) {
		t.Errorf("String() = %q, want it to contain revision %q", got, Revision())
	}
	// The dirty marker is present iff the tree was modified at build time.
	if Modified() != contains(got, "+dirty") {
		t.Errorf("String() dirty marker (%q) disagrees with Modified()=%v", got, Modified())
	}
}

func contains(s, sub string) bool {
	if sub == "" {
		return true
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
