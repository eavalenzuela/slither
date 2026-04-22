package enricher

import "testing"

func TestPathGlobEmptyIncludesAllows(t *testing.T) {
	g := newPathGlob(nil, nil)
	if !g.allow("/tmp/foo") {
		t.Fatal("empty includes + empty excludes must allow")
	}
	if g.allow("") {
		t.Fatal("empty path must not be allowed")
	}
}

func TestPathGlobDoubleStar(t *testing.T) {
	g := newPathGlob([]string{"/etc/**", "/usr/bin/**"}, nil)

	cases := map[string]bool{
		"/etc/passwd":          true,
		"/etc/ssh/sshd_config": true,
		"/etc":                 true, // bare dir matches `/etc/**`
		"/usr/bin/sudo":        true,
		"/usr/local/bin/x":     false,
		"/etcpasswd":           false, // prefix must be followed by `/`
		"/var/log/syslog":      false,
	}
	for p, want := range cases {
		if got := g.allow(p); got != want {
			t.Errorf("allow(%q) = %v, want %v", p, got, want)
		}
	}
}

func TestPathGlobExcludeWins(t *testing.T) {
	g := newPathGlob([]string{"/etc/**"}, []string{"/etc/shadow"})
	if g.allow("/etc/shadow") {
		t.Fatal("exclude must beat include")
	}
	if !g.allow("/etc/passwd") {
		t.Fatal("non-excluded match should still pass")
	}
}

func TestPathGlobPatternMatchAndLiteral(t *testing.T) {
	g := newPathGlob([]string{"/tmp/*.log", "/exact/path"}, nil)

	if !g.allow("/tmp/app.log") {
		t.Errorf("glob /tmp/*.log should match /tmp/app.log")
	}
	// path.Match's `*` is per-segment — it must not cross `/`.
	if g.allow("/tmp/sub/app.log") {
		t.Errorf("glob /tmp/*.log must not cross segments")
	}
	if !g.allow("/exact/path") {
		t.Errorf("literal match failed")
	}
	if g.allow("/exact/path/extra") {
		t.Errorf("literal must not prefix-match")
	}
}
