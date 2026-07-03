package log

import (
	"log/slog"
	"testing"
)

func TestParseLevel(t *testing.T) {
	cases := map[string]slog.Level{
		"debug":     slog.LevelDebug,
		"info":      slog.LevelInfo,
		"warn":      slog.LevelWarn,
		"warning":   slog.LevelWarn, // alias
		"error":     slog.LevelError,
		"  DEBUG  ": slog.LevelDebug, // trimmed + case-folded
		"WARN":      slog.LevelWarn,
		"":          slog.LevelInfo, // empty falls back to info
		"nonsense":  slog.LevelInfo, // unknown falls back to info
	}
	for in, want := range cases {
		if got := ParseLevel(in); got != want {
			t.Errorf("ParseLevel(%q) = %v, want %v", in, got, want)
		}
	}
}
