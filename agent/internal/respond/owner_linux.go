//go:build linux

package respond

import (
	"os"
	"syscall"
)

// ownerOf extracts uid/gid from a FileInfo on Linux. Wrapped here so
// quarantine.go stays portable-shaped while the actual stat-cast
// stays Linux-only. Returns (0, 0, false) if the underlying type
// isn't *syscall.Stat_t — covers fakefs in tests + the unusual
// non-syscall FileInfo a custom os.FileInfo implementation might
// return.
func ownerOf(info os.FileInfo) (uid, gid int, ok bool) {
	st, sok := info.Sys().(*syscall.Stat_t)
	if !sok {
		return 0, 0, false
	}
	return int(st.Uid), int(st.Gid), true
}
