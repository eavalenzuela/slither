//go:build linux

package respond

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
)

// killGracePeriod is how long the agent waits between SIGTERM and the
// follow-up SIGKILL. ADR-0034 doesn't pin a number; 3 s matches the
// Linux convention for "give the process a chance to flush, then
// hammer" — short enough that an operator-driven kill feels
// instantaneous in the console, long enough that a co-operating
// process gets to fsync.
const killGracePeriod = 3 * time.Second

// killTreeMaxDescendants caps the recursion blast radius. A
// pathological fork-bomb tree could expand linearly; cap matches
// the per-rule state-cap in ADR-0018 so the order of magnitude is
// familiar. Hitting the cap means the tree was bigger than expected
// — surface as FAILED rather than silently truncate.
const killTreeMaxDescendants = 1024

// KillProcessHandler returns the per-PID kill handler. Wired by
// agent/internal/app via executor.SetHandler at startup.
func KillProcessHandler() Handler {
	return func(ctx context.Context, req *pb.ResponseRequest) (pb.ResponseStatus, string, []byte) {
		pid, err := parseTargetPID(req.GetTarget())
		if err != nil {
			return pb.ResponseStatus_RESPONSE_STATUS_FAILED, err.Error(), nil
		}
		if err := refuseDangerousPID(pid); err != nil {
			return pb.ResponseStatus_RESPONSE_STATUS_FAILED, err.Error(), nil
		}
		if err := killOne(ctx, pid); err != nil {
			return pb.ResponseStatus_RESPONSE_STATUS_FAILED, err.Error(), nil
		}
		return pb.ResponseStatus_RESPONSE_STATUS_DONE,
			fmt.Sprintf("killed pid %d (SIGTERM + grace + SIGKILL on stragglers)", pid),
			nil
	}
}

// KillTreeHandler returns the kill-tree handler. Walks
// /proc/<pid>/task/<tid>/children recursively, sends SIGTERM to every
// PID it finds (root + descendants), waits, then SIGKILLs anything
// still alive.
func KillTreeHandler() Handler {
	return func(ctx context.Context, req *pb.ResponseRequest) (pb.ResponseStatus, string, []byte) {
		root, err := parseTargetPID(req.GetTarget())
		if err != nil {
			return pb.ResponseStatus_RESPONSE_STATUS_FAILED, err.Error(), nil
		}
		if rerr := refuseDangerousPID(root); rerr != nil {
			return pb.ResponseStatus_RESPONSE_STATUS_FAILED, rerr.Error(), nil
		}

		tree, err := collectDescendants(root, killTreeMaxDescendants)
		if err != nil {
			return pb.ResponseStatus_RESPONSE_STATUS_FAILED, err.Error(), nil
		}
		// Refuse if any pid in the collected set is the agent's own
		// PID or a process-tree ancestor of the agent. Defence in
		// depth — refuseDangerousPID(root) catches the easy case;
		// this guards against a malicious or misconfigured target
		// that happens to dominate the agent.
		for _, pid := range tree {
			if rerr := refuseDangerousPID(pid); rerr != nil {
				return pb.ResponseStatus_RESPONSE_STATUS_FAILED,
					fmt.Sprintf("descendant %d: %v", pid, rerr), nil
			}
		}

		// SIGTERM everything; sweep with SIGKILL after the grace.
		for _, pid := range tree {
			_ = unix.Kill(pid, unix.SIGTERM)
		}
		select {
		case <-ctx.Done():
			return pb.ResponseStatus_RESPONSE_STATUS_FAILED,
				"context cancelled before grace expired", nil
		case <-time.After(killGracePeriod):
		}
		stragglers := 0
		for _, pid := range tree {
			if pidAlive(pid) {
				stragglers++
				_ = unix.Kill(pid, unix.SIGKILL)
			}
		}

		return pb.ResponseStatus_RESPONSE_STATUS_DONE,
			fmt.Sprintf("killed pid tree rooted at %d (%d pids; %d stragglers needed SIGKILL)",
				root, len(tree), stragglers),
			nil
	}
}

// killOne SIGTERMs pid, waits the grace period, SIGKILLs if still
// alive. Returns nil on success even when the process exited from
// SIGTERM alone — the operator wanted the pid dead, and it is.
func killOne(ctx context.Context, pid int) error {
	if err := unix.Kill(pid, unix.SIGTERM); err != nil {
		// ESRCH means the pid is already gone — that's a successful
		// outcome from the operator's perspective, not a failure.
		if errors.Is(err, unix.ESRCH) {
			return nil
		}
		return fmt.Errorf("kill -TERM %d: %w", pid, err)
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(killGracePeriod):
	}
	if !pidAlive(pid) {
		return nil
	}
	if err := unix.Kill(pid, unix.SIGKILL); err != nil && !errors.Is(err, unix.ESRCH) {
		return fmt.Errorf("kill -KILL %d: %w", pid, err)
	}
	return nil
}

// parseTargetPID converts the wire target string to an int PID with
// usable bounds checks. Reject zero (a bare "kill 0" hits every
// process in the process group) and negatives (the same shape signals
// "process group" to unix.Kill).
func parseTargetPID(target string) (int, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return 0, errors.New("target pid required")
	}
	pid, err := strconv.Atoi(target)
	if err != nil {
		return 0, fmt.Errorf("target %q is not a pid: %w", target, err)
	}
	if pid <= 0 {
		return 0, fmt.Errorf("target pid %d invalid (must be > 0)", pid)
	}
	return pid, nil
}

// refuseDangerousPID guards against the small set of pids the agent
// must never touch:
//
//   - 1 (init / systemd) — killing pid 1 panics the kernel.
//   - The agent's own PID — kills the watchdog mid-action.
//   - Any process-tree ancestor of the agent — same risk, indirect.
//
// Pid-namespace ancestors aren't visible from inside our ns, so the
// last check uses /proc/<pid>/status's PPid chain. Walking up from
// the agent's own pid produces every ancestor; we refuse if `pid`
// shows up in that chain.
func refuseDangerousPID(pid int) error {
	if pid == 1 {
		return errors.New("refusing to kill pid 1")
	}
	self := os.Getpid()
	if pid == self {
		return errors.New("refusing to kill the slither-agent's own PID")
	}
	ancestor, err := pidIsAgentAncestor(pid, self)
	if err != nil {
		// /proc walking failure surfaces as a refusal — fail closed
		// rather than potentially kill an ancestor.
		return fmt.Errorf("ancestor check failed for pid %d: %w", pid, err)
	}
	if ancestor {
		return fmt.Errorf("refusing to kill pid %d (ancestor of slither-agent pid %d)", pid, self)
	}
	return nil
}

// pidIsAgentAncestor reports whether targetPID is on the agent's
// process-tree ancestor chain. Walks /proc/<pid>/status PPid up to
// 256 hops; cycles or runaway depth surface as an error.
func pidIsAgentAncestor(targetPID, agentPID int) (bool, error) {
	cur := agentPID
	for hop := 0; hop < 256; hop++ {
		if cur == 0 || cur == 1 {
			return false, nil
		}
		if cur == targetPID {
			return true, nil
		}
		ppid, err := readPPID(cur)
		if err != nil {
			return false, err
		}
		cur = ppid
	}
	return false, errors.New("ancestor chain longer than 256 hops")
}

// readPPID extracts the PPid field from /proc/<pid>/status. Returns 0
// when the process is gone (race with a fast-exiting pid is fine —
// the agent's chain doesn't include a vanished pid).
func readPPID(pid int) (int, error) {
	body, err := os.ReadFile(procPath(pid, "status")) //nolint:gosec // kernel-managed /proc
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	for _, line := range strings.Split(string(body), "\n") {
		if !strings.HasPrefix(line, "PPid:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0, errors.New("malformed PPid line")
		}
		return strconv.Atoi(fields[1])
	}
	return 0, errors.New("PPid line not found in /proc status")
}

// pidAlive returns true when the kernel still has a /proc entry for
// pid. Cheaper than `kill -0` for our use; the call site already
// follows up with SIGKILL for a positive result, so a TOCTOU race
// just means an unnecessary SIGKILL on a dead pid (which ESRCHes
// harmlessly).
func pidAlive(pid int) bool {
	_, err := os.Stat(procPath(pid))
	return err == nil
}

// procPath returns "/proc/<pid>[/parts...]". Centralised so the
// gocritic filepathJoin nag fires once on the helper rather than at
// every call site, and so unit tests can override the procfs root
// (currently unused — left as a hook for #80's namespace-aware
// isolate handler that may want a netns-private /proc).
func procPath(pid int, parts ...string) string {
	const root = "/proc"
	out := root + "/" + strconv.Itoa(pid)
	for _, p := range parts {
		out += "/" + p
	}
	return out
}

// collectDescendants returns root + every descendant up to maxPids,
// reading /proc/<pid>/task/<tid>/children files (one whitespace-
// separated PID list per task). Returns an error when the count
// would exceed maxPids — a fork-bomb-shaped tree should fail loud
// rather than silently truncate the kill set.
func collectDescendants(root, maxPids int) ([]int, error) {
	out := []int{root}
	seen := map[int]struct{}{root: {}}
	queue := []int{root}

	for len(queue) > 0 {
		pid := queue[0]
		queue = queue[1:]

		taskDir := procPath(pid, "task")
		entries, err := os.ReadDir(taskDir)
		if err != nil {
			// Process probably exited between read and walk —
			// continue with what we have.
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("read %s: %w", taskDir, err)
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			body, err := os.ReadFile(filepath.Join(taskDir, e.Name(), "children")) //nolint:gosec // kernel-managed /proc
			if err != nil {
				if os.IsNotExist(err) {
					continue
				}
				return nil, fmt.Errorf("read children: %w", err)
			}
			for _, f := range strings.Fields(string(body)) {
				cpid, err := strconv.Atoi(f)
				if err != nil || cpid <= 0 {
					continue
				}
				if _, dup := seen[cpid]; dup {
					continue
				}
				seen[cpid] = struct{}{}
				out = append(out, cpid)
				queue = append(queue, cpid)
				if len(out) > maxPids {
					return nil, fmt.Errorf("descendant count exceeds cap %d (refusing to walk further)", maxPids)
				}
			}
		}
	}
	return out, nil
}
