//go:build linux

package enricher

import "syscall"

// statKey derives the cache key from the Linux stat fields directly:
// Dev/Ino are already uint64 and the mtime lives in Mtim (Timespec).
func statKey(path string) (hashKey, bool) {
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return hashKey{}, false
	}
	return hashKey{
		dev:   st.Dev,
		inode: st.Ino,
		mtime: st.Mtim.Nano(),
	}, true
}
