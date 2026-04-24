// Package app wires the server's subsystems together and runs them under a
// single cancellation context.
//
// Phase 2 §4.1 task #31 scaffold: Run validates config, prints a startup
// banner naming the listeners the later tasks will open, blocks until ctx
// is cancelled, then dumps the final telemetry snapshot to stderr. Zero
// RPCs are served yet — #33/#34 (mTLS + Enroll), #37 (Session/ingest),
// #41 (console) each plug into this skeleton.
package app

import (
	"context"
	"fmt"
	"os"

	"github.com/t3rmit3/slither/server/internal/config"
	"github.com/t3rmit3/slither/server/internal/telemetry"
)

// Run blocks until ctx is cancelled. It will grow per-task as Phase 2
// subsystems land; the signature is stable.
func Run(ctx context.Context, cfg *config.Config, configPath string) error {
	if cfg == nil {
		return fmt.Errorf("app: nil config")
	}
	_ = configPath // reserved for future SIGHUP-driven reload (rules, log level)

	telem := telemetry.NewCounters()

	fmt.Fprintf(os.Stderr,
		"slither-server: log_level=%s grpc=%q enroll=%q console=%q\n",
		cfg.Server.LogLevel,
		cfg.Listeners.GRPC, cfg.Listeners.Enroll, cfg.Listeners.Console)
	fmt.Fprintln(os.Stderr, "slither-server: scaffold up — no listeners active (Phase 2 task #31)")

	<-ctx.Done()

	snap := telem.Snapshot()
	fmt.Fprintf(os.Stderr,
		"telemetry: events_received=%d dropped=%d (ingest=%d subscriber=%d) batches_flushed=%d rulesets_pushed=%d enroll=%d/%d sessions_active=%d\n",
		snap.EventsReceived, snap.EventsDropped,
		snap.DropsIngest, snap.DropsSubscriber,
		snap.BatchesFlushed, snap.RulesetsPushed,
		snap.EnrollSuccess, snap.EnrollRejected,
		snap.SessionsActive)

	if err := ctx.Err(); err != nil && err != context.Canceled {
		return err
	}
	return nil
}
