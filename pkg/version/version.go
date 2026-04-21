// Package version exposes build-time identification shared by agent and server binaries.
package version

import "runtime/debug"

// Version is the semver string, overridden at link time via -ldflags="-X ...Version=v0.1.0".
var Version = "dev"

// Revision returns the VCS revision from build info, or "unknown" when unavailable.
func Revision() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	for _, s := range info.Settings {
		if s.Key == "vcs.revision" {
			if len(s.Value) >= 12 {
				return s.Value[:12]
			}
			return s.Value
		}
	}
	return "unknown"
}

// Modified reports whether the working tree was dirty at build time.
func Modified() bool {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return false
	}
	for _, s := range info.Settings {
		if s.Key == "vcs.modified" {
			return s.Value == "true"
		}
	}
	return false
}
