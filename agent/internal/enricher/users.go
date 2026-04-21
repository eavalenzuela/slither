package enricher

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
)

// userResolver maps uid → username from an /etc/passwd snapshot. The snapshot
// is swapped atomically on reload so lookups are wait-free. SIGHUP handling
// lives in the enricher Run loop; reload() is the action.
type userResolver struct {
	path string
	snap atomic.Pointer[userSnapshot]
}

type userSnapshot struct {
	byUID map[uint32]string
}

func newUserResolver(path string) *userResolver {
	r := &userResolver{path: path}
	r.reload()
	return r
}

// reload re-reads the passwd file and atomically swaps in the new snapshot.
// Failure (missing file, partial read) leaves an empty snapshot in place so
// Name() always returns "" rather than stale data after a reload attempt.
func (r *userResolver) reload() {
	snap := &userSnapshot{byUID: map[uint32]string{}}
	f, err := os.Open(r.path)
	if err != nil {
		r.snap.Store(snap)
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		// passwd: name:passwd:uid:gid:gecos:home:shell
		parts := strings.SplitN(line, ":", 4)
		if len(parts) < 3 {
			continue
		}
		uid, err := strconv.ParseUint(parts[2], 10, 32)
		if err != nil {
			continue
		}
		snap.byUID[uint32(uid)] = parts[0]
	}
	r.snap.Store(snap)
}

// Name returns the username for uid, or "" if unknown.
func (r *userResolver) Name(uid uint32) string {
	snap := r.snap.Load()
	if snap == nil {
		return ""
	}
	return snap.byUID[uid]
}
