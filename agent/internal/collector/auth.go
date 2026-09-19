//go:build linux

package collector

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	bpfpkg "github.com/t3rmit3/slither/agent/internal/bpf"
	"github.com/t3rmit3/slither/agent/internal/config"
	"github.com/t3rmit3/slither/agent/internal/pipeline"
	"github.com/t3rmit3/slither/agent/internal/telemetry"
)

// authCollector loads auth.bpf.c and attaches its uprobes to the host's
// libpam.so.0. Every PAM client on the host — sshd, sudo, su, login,
// getty, display managers — then reports credential checks and session
// open/close through one ringbuffer, with no per-daemon log parsing.
//
// The probe attaches to one inode, so a libpam inside a container image
// is not covered; that is a documented limit, not a bug (see auth.bpf.c).
type authCollector struct {
	out   chan<- pipeline.RawAuthEvent
	cfg   config.AuthCollector
	telem *telemetry.Counters
}

func newAuthCollector(out chan<- pipeline.RawAuthEvent, cfg config.AuthCollector, telem *telemetry.Counters) Collector {
	return &authCollector{out: out, cfg: cfg, telem: telem}
}

func (a *authCollector) Name() string { return "auth" }

// libpamCandidates is the probe order when collectors.auth.libpam_path is
// unset: Debian/Ubuntu multiarch first, then RHEL/Fedora/SUSE lib64,
// then the unqualified fallbacks (Arch, Alpine, NixOS-style layouts).
var libpamCandidates = []string{
	"/lib/x86_64-linux-gnu/libpam.so.0",
	"/usr/lib/x86_64-linux-gnu/libpam.so.0",
	"/lib/aarch64-linux-gnu/libpam.so.0",
	"/usr/lib/aarch64-linux-gnu/libpam.so.0",
	"/lib64/libpam.so.0",
	"/usr/lib64/libpam.so.0",
	"/usr/lib/libpam.so.0",
	"/lib/libpam.so.0",
}

// resolveLibpam returns the libpam path to probe. An explicit override
// is used as-is (and must exist); otherwise the first candidate that
// stats wins.
func resolveLibpam(override string) (string, error) {
	if override != "" {
		if _, err := os.Stat(override); err != nil {
			return "", fmt.Errorf("auth: collectors.auth.libpam_path %q: %w", override, err)
		}
		return override, nil
	}
	for _, p := range libpamCandidates {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", errors.New("auth: libpam.so.0 not found in any standard location; set collectors.auth.libpam_path or disable the auth collector")
}

func (a *authCollector) Run(ctx context.Context) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("auth: rlimit: %w", err)
	}

	path, rerr := resolveLibpam(a.cfg.LibpamPath)
	if rerr != nil {
		return rerr
	}
	ex, oerr := link.OpenExecutable(path)
	if oerr != nil {
		return fmt.Errorf("auth: open %s: %w", path, oerr)
	}

	var objs bpfpkg.AuthObjects
	if err := bpfpkg.LoadAuthObjects(&objs, nil); err != nil {
		return fmt.Errorf("auth: load bpf objects: %w", err)
	}
	defer objs.Close()

	var links []link.Link
	defer func() {
		for _, l := range links {
			_ = l.Close()
		}
	}()

	// attach wires one probe. optional symbols are allowed to be absent
	// (pam_start_confdir only exists on libpam >= 1.4); everything else
	// is part of LIBPAM_1.0 and its absence means this is not libpam.
	attach := func(symbol string, prog *ebpf.Program, ret, optional bool) error {
		var (
			l    link.Link
			kind = "uprobe"
		)
		var aerr error
		if ret {
			kind = "uretprobe"
			l, aerr = ex.Uretprobe(symbol, prog, nil)
		} else {
			l, aerr = ex.Uprobe(symbol, prog, nil)
		}
		if aerr != nil {
			if optional && errors.Is(aerr, link.ErrNoSymbol) {
				slog.Debug("auth: optional symbol absent; skipping", "symbol", symbol, "libpam", path)
				return nil
			}
			return fmt.Errorf("auth: attach %s/%s on %s: %w", kind, symbol, path, aerr)
		}
		links = append(links, l)
		return nil
	}

	probes := []struct {
		symbol   string
		prog     *ebpf.Program
		ret      bool
		optional bool
	}{
		{"pam_start", objs.HandlePamStart, false, false},
		{"pam_start_confdir", objs.HandlePamStartConfdir, false, true},
		{"pam_set_item", objs.HandlePamSetItem, false, false},
		{"pam_authenticate", objs.HandlePamAuthenticateRet, true, false},
		{"pam_open_session", objs.HandlePamOpenSessionRet, true, false},
		{"pam_close_session", objs.HandlePamCloseSessionRet, true, false},
		{"pam_end", objs.HandlePamEnd, false, false},
	}
	for _, p := range probes {
		if err := attach(p.symbol, p.prog, p.ret, p.optional); err != nil {
			return err
		}
	}
	slog.Info("auth collector attached", "libpam", path, "probes", len(links))

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return fmt.Errorf("auth: open ringbuf: %w", err)
	}
	defer rd.Close()

	go func() {
		<-ctx.Done()
		_ = rd.Close()
	}()

	return a.drain(ctx, rd)
}

func (a *authCollector) drain(ctx context.Context, rd *ringbuf.Reader) error {
	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return ctx.Err()
			}
			return fmt.Errorf("auth: ringbuf read: %w", err)
		}

		if len(rec.RawSample) < int(unsafe.Sizeof(bpfpkg.AuthAuthEvent{})) {
			a.telem.IncDrops()
			continue
		}
		raw := *(*bpfpkg.AuthAuthEvent)(unsafe.Pointer(&rec.RawSample[0])) //nolint:gosec // G103: deliberate zero-copy decode of BPF-emitted fixed-layout record
		a.telem.IncEvents()

		select {
		case a.out <- decodeAuthEvent(raw):
		case <-ctx.Done():
			return ctx.Err()
		default:
			a.telem.IncDropCollector()
		}
	}
}

func decodeAuthEvent(r bpfpkg.AuthAuthEvent) pipeline.RawAuthEvent {
	return pipeline.RawAuthEvent{
		Kind:       decodeAuthKind(r.Kind),
		PID:        r.Tgid,
		UID:        r.Uid,
		Result:     r.Result,
		Service:    cstr(r.Service[:]),
		User:       cstr(r.User[:]),
		RemoteHost: cstr(r.Rhost[:]),
		TTY:        cstr(r.Tty[:]),
		Comm:       cstr(r.Comm[:]),
		Timestamp:  time.Now(),
	}
}

func decodeAuthKind(k uint32) pipeline.RawAuthKind {
	// Values mirror SL_AUTH_* in auth.bpf.c.
	switch k {
	case 1:
		return pipeline.AuthAttempt
	case 2:
		return pipeline.AuthSessionOpen
	case 3:
		return pipeline.AuthSessionClose
	default:
		return pipeline.AuthUnknown
	}
}
