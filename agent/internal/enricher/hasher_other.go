//go:build !linux

package enricher

import "syscall"

// statKey derives the cache key on non-Linux platforms. Darwin's
// syscall.Stat_t types Dev as int32 (cast to the uint64 cache field) and
// carries the mtime in Mtimespec rather than Mtim. The cache semantics are
// identical to the Linux path; only the field plumbing differs.
func statKey(path string) (hashKey, bool) {
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return hashKey{}, false
	}
	return hashKey{
		dev:   uint64(st.Dev),
		inode: st.Ino,
		mtime: st.Mtimespec.Nano(),
	}, true
}
