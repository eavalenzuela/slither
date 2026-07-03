// Package log is a minimal slog facade so the agent and server binaries
// can honour the log_level config knob without each maintaining their
// own logger setup. The standard library's log/slog does the work; this
// package exists to make level parsing and TextHandler defaults shared.
//
// Both binaries call Init(cfg.LogLevel) once at startup, then use slog
// directly (slog.Info, slog.Debug, …). The package is deliberately
// thin — no JSON handler, no field helpers, no leveller types. Add
// only when a caller needs more.
package log

import (
	"io"
	"log/slog"
	"os"
	"strings"
)

// Init points slog's default logger at os.Stderr through a TextHandler
// at the parsed level. Unknown level strings fall back to info.
func Init(level string) {
	slog.SetDefault(New(os.Stderr, level))
}

// New builds a *slog.Logger writing to w at the parsed level. Useful in
// tests that want to inspect log output without touching the package
// default.
func New(w io.Writer, level string) *slog.Logger {
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{
		Level: ParseLevel(level),
	}))
}

// ParseLevel maps the agent.log_level / server.log_level vocabulary
// (debug/info/warn/error) to slog.Level. The input is trimmed and
// lowercased and the common "warning" alias is accepted so a slightly-off
// config value degrades to the intended level instead of silently
// dropping to info. Unrecognised strings still fall back to info — config
// validation rejects unknown values up front, so that branch is
// defensive only.
func ParseLevel(level string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	}
	return slog.LevelInfo
}
