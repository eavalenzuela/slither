// Package app wires the server's subsystems together and runs them
// under a single cancellation context.
//
// Phase 2 §4.1 task #40 turns the #31 scaffold into a real binary:
// open Postgres + ClickHouse stores, build the ingest bus, start the
// ClickHouse writer, mount AgentService.Enroll on the unauthenticated
// enrollment listener and AgentService.Session on the mTLS listener,
// run the rule-distribution control plane (#39). Everything is
// torn down on ctx cancellation; goroutine errors propagate so the
// process exits non-zero on subsystem failures.
package app

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"net/http"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	applog "github.com/t3rmit3/slither/pkg/log"
	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
	"github.com/t3rmit3/slither/server/internal/config"
	"github.com/t3rmit3/slither/server/internal/console"
	"github.com/t3rmit3/slither/server/internal/control"
	"github.com/t3rmit3/slither/server/internal/detect"
	"github.com/t3rmit3/slither/server/internal/grpcserv"
	"github.com/t3rmit3/slither/server/internal/ingest"
	"github.com/t3rmit3/slither/server/internal/mtls"
	"github.com/t3rmit3/slither/server/internal/store/ch"
	"github.com/t3rmit3/slither/server/internal/store/pg"
	"github.com/t3rmit3/slither/server/internal/telemetry"
)

// Run blocks until ctx is cancelled or any subsystem fails. configPath
// is reserved for SIGHUP-driven reload (rules + log level); not used
// today.
func Run(ctx context.Context, cfg *config.Config, configPath string) error {
	if cfg == nil {
		return fmt.Errorf("app: nil config")
	}
	_ = configPath
	applog.Init(cfg.Server.LogLevel)

	telem := telemetry.NewCounters()

	slog.Info("slither-server: starting",
		"log_level", cfg.Server.LogLevel,
		"grpc", cfg.Listeners.GRPC,
		"enroll", cfg.Listeners.Enroll,
		"console", cfg.Listeners.Console)

	// --- Stores ---
	pgStore, err := pg.Open(ctx, cfg.Storage.Postgres.DSN)
	if err != nil {
		return fmt.Errorf("app: pg open: %w", err)
	}
	defer pgStore.Close()

	chStore, err := ch.Open(ctx, cfg.Storage.CH.DSN)
	if err != nil {
		return fmt.Errorf("app: ch open: %w", err)
	}
	defer chStore.Close()

	// --- mTLS material ---
	ca, err := mtls.LoadCA(cfg.MTLS.CACert, cfg.MTLS.CAKey)
	if err != nil {
		return fmt.Errorf("app: load ca: %w", err)
	}
	serverCert, err := mtls.LoadServerKeyPair(cfg.MTLS.ServerCert, cfg.MTLS.ServerKey)
	if err != nil {
		return fmt.Errorf("app: load server cert: %w", err)
	}

	// --- Ingest bus + ClickHouse writer ---
	bus := ingest.NewBus(func(string) { telem.IncDropSubscriber() })
	defer bus.Close()

	writer := ch.NewWriter(chStore, bus, telem, ch.WriterOptions{
		BatchSize:     cfg.Storage.CH.BatchSize,
		FlushInterval: cfg.Storage.CH.FlushInterval,
	})
	writer.SetFlushErrorHandler(func(err error) {
		slog.Error("ch flush", "err", err)
	})

	// --- Rule distribution hub ---
	hub := control.NewHub(pgStore, telem)

	// --- Server-side detection engine (Phase 3 #58) ---
	detectEngine := detect.New(bus, pgStore, telem, detect.Options{})

	// --- gRPC services ---
	enrollSvc := grpcserv.NewEnrollService(pgStore, ca, telem)
	sessionSvc := grpcserv.NewSessionService(pgStore, bus, telem)
	sessionSvc.RuleHub = hub

	enrollSrv := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(mtls.ServerEnrollTLSConfig(serverCert))),
	)
	pb.RegisterAgentServiceServer(enrollSrv, enrollSvc)

	sessionSrv := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(mtls.ServerMTLSConfig(serverCert, ca.Cert))),
	)
	pb.RegisterAgentServiceServer(sessionSrv, sessionSvc)

	// --- Listeners ---
	lc := &net.ListenConfig{}
	enrollLis, err := lc.Listen(ctx, "tcp", cfg.Listeners.Enroll)
	if err != nil {
		return fmt.Errorf("app: enroll listen: %w", err)
	}
	sessionLis, err := lc.Listen(ctx, "tcp", cfg.Listeners.GRPC)
	if err != nil {
		_ = enrollLis.Close()
		return fmt.Errorf("app: grpc listen: %w", err)
	}

	// Console — Phase 2 #41 onwards. chi router with templ views,
	// scs/pgxstore session manager, argon2id auth.
	sessionKey, err := console.LoadOrCreateSessionKey(cfg.Console.SessionKeyFile)
	if err != nil {
		_ = enrollLis.Close()
		_ = sessionLis.Close()
		return fmt.Errorf("app: session key: %w", err)
	}
	consoleSvc := console.New(console.Options{
		Store:      pgStore,
		Telem:      telem,
		Bus:        bus,
		ChStore:    chStore,
		SessionKey: sessionKey,
		// /enrolment-tokens (#45) renders this into the copy-paste
		// command. Operators override per-deployment via the
		// SLITHER_LISTENERS_ENROLL config + a public hostname; the
		// listener bind alone is good enough for compose smoke.
		DefaultEnrollServer: defaultEnrollServer(cfg.Listeners.Enroll),
	})
	consoleSrv := &http.Server{
		Addr:              cfg.Listeners.Console,
		Handler:           consoleSvc.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	slog.Info("slither-server: listeners up",
		"enroll", enrollLis.Addr().String(),
		"grpc", sessionLis.Addr().String(),
		"console", cfg.Listeners.Console)

	// --- Subsystem goroutines ---
	var wg sync.WaitGroup
	errs := make(chan error, 4)

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := writer.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			errs <- fmt.Errorf("ch writer: %w", err)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := control.Run(ctx, hub, pgStore, control.RunnerOptions{}); err != nil {
			errs <- fmt.Errorf("control runner: %w", err)
		}
	}()

	// Detection engine + finding logger (placeholder until #60's
	// alert sink lands — we surface fired findings at INFO so
	// operators see them in the server log during Phase 3
	// validation).
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := detectEngine.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			errs <- fmt.Errorf("detect engine: %w", err)
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		for f := range detectEngine.Findings() {
			slog.Info("detect: finding",
				"rule_uid", f.RuleID,
				"rule_title", f.RuleTitle,
				"severity", f.Severity,
				"host_id", f.HostID,
				"group_key", f.GroupKey,
				"event_count", len(f.EventIDs),
				"reason", f.Reason)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := enrollSrv.Serve(enrollLis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			errs <- fmt.Errorf("enroll grpc: %w", err)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := sessionSrv.Serve(sessionLis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			errs <- fmt.Errorf("session grpc: %w", err)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := consoleSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errs <- fmt.Errorf("console http: %w", err)
		}
	}()

	// --- Block until ctx done or first error ---
	var runErr error
	select {
	case <-ctx.Done():
	case runErr = <-errs:
		slog.Error("slither-server: shutting down on subsystem error", "err", runErr)
	}

	// Graceful shutdown — bounded so a hung Send doesn't block forever.
	// Detached from the cancelled run ctx so an Interrupt doesn't
	// instantly time the drain out.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stopGRPC(shutdownCtx, enrollSrv)     //nolint:contextcheck // detached on purpose
	stopGRPC(shutdownCtx, sessionSrv)    //nolint:contextcheck // detached on purpose
	_ = consoleSrv.Shutdown(shutdownCtx) //nolint:contextcheck // detached on purpose
	wg.Wait()

	// Operational contract: docs/phase2-validation.md greps `telemetry:`
	// from server logs at shutdown — keep this as a raw fmt.Fprintf so
	// the line shape stays stable across log_level changes.
	snap := telem.Snapshot()
	fmt.Fprintf(os.Stderr,
		"telemetry: events_received=%d dropped=%d (ingest=%d subscriber=%d) batches_flushed=%d ruleset_refreshes=%d rulesets_pushed=%d enroll=%d/%d sessions_active=%d sessions_closed=%d heartbeats=%d authn_failures=%d\n",
		snap.EventsReceived, snap.EventsDropped,
		snap.DropsIngest, snap.DropsSubscriber,
		snap.BatchesFlushed, snap.RulesetRefreshes, snap.RulesetsPushed,
		snap.EnrollSuccess, snap.EnrollRejected,
		snap.SessionsActive, snap.SessionsClosed,
		snap.Heartbeats, snap.AuthnFailures)
	for sub, n := range snap.SubscriberPublishes {
		slog.Info("hub: subscriber publish total",
			"subscriber", sub,
			"publishes", n)
	}

	return runErr
}

// stopGRPC GracefulStops srv with a timeout — falls back to Stop on
// expiry so a misbehaving stream doesn't hold shutdown open.
func stopGRPC(ctx context.Context, srv *grpc.Server) {
	done := make(chan struct{})
	go func() {
		srv.GracefulStop()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		srv.Stop()
	}
}

// ensure the tls import isn't dropped by future refactors (LoadServerKeyPair
// returns tls.Certificate and is consumed by ServerMTLSConfig).
var _ = tls.Certificate{}

// defaultEnrollServer renders the listener bind into a host:port the
// console UI can paste into a `slither-agent enroll --server …`
// command. ":9444" → "<server>:9444" so operators see the placeholder
// to substitute; bound IPs round-trip unchanged.
func defaultEnrollServer(bind string) string {
	if bind == "" {
		return "<server>:9444"
	}
	if strings.HasPrefix(bind, ":") {
		return "<server>" + bind
	}
	return bind
}
