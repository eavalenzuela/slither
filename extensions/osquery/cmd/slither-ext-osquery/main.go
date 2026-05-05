// slither-ext-osquery is the slither agent's first-party osquery
// bridge extension. The agent supervisor (Phase 6 #107) cosign-
// verifies this binary, spawns it with FD 3 wired to a unix
// socketpair, and reads ExtensionToAgent envelopes back.
//
// Behaviour:
//
//   - Send Hello(name=osquery, capabilities=[OCSF_EMIT, LIVE_QUERY_RESPOND]).
//   - Spawn a polling loop against a configurable osqueryd socket
//     (--socket; default /var/osquery/osquery.em). Each tick, run a
//     curated SELECT against process_events / socket_events /
//     file_events / listening_ports / kernel_modules / ssh_keys /
//     authorized_keys; map every row through bridge/mappers; emit one
//     ExtensionToAgent_OcsfEvent per row.
//   - Concurrently read AgentToExtension envelopes; for now, ack
//     LiveQueryRequest with a "pending #110" complete and refuse
//     SnapshotRequest with a "capability not declared" complete.
//
// FD 3 is the wire. Stdout/stderr land in the agent's slog at INFO
// (per supervisor `drainToLog`), reserved for human-readable diagnostics.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/t3rmit3/slither/extensions/osquery/internal/bridge"
)

// version is overwritten by -ldflags at release time, matching the
// agent + server convention.
var version = "dev"

func main() {
	os.Exit(run())
}

func run() int {
	socket := flag.String("socket", "/var/osquery/osquery.em",
		"path to osqueryd extension socket; pass empty to skip --connect (events tables stay empty)")
	binary := flag.String("osqueryi", "osqueryi",
		"path to osqueryi binary (defaults to $PATH lookup)")
	interval := flag.Duration("interval", 10*time.Second,
		"poll cadence for the curated table set")
	flag.Parse()

	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	slog.Info("osquery bridge starting", "version", version, "socket", *socket, "interval", *interval)

	wire, err := openAgentSocket()
	if err != nil {
		slog.Error("failed to open FD 3 wire", "err", err)
		return 2
	}
	defer wire.Close()

	send, recv := bridge.LockedSender(wire)

	if err := bridge.SendHello(send, version); err != nil {
		slog.Error("hello write failed", "err", err)
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	client := bridge.NewOsqueryiClient(*binary, *socket)
	defer client.Close()

	pump := bridge.NewPump(client, bridge.DefaultTables(), *interval, send)

	// Inbound goroutine: agent → extension envelopes (live-query +
	// snapshot dispatch). Errors here drop us back to the supervisor
	// for restart-with-backoff.
	inboundErr := make(chan error, 1)
	go func() {
		for {
			msg, err := recv()
			if err != nil {
				inboundErr <- err
				return
			}
			if err := pump.HandleAgentMessage(ctx, msg); err != nil {
				inboundErr <- err
				return
			}
		}
	}()

	// Run the pump on the foreground goroutine; it returns when ctx
	// is cancelled.
	pumpDone := make(chan error, 1)
	go func() { pumpDone <- pump.Run(ctx) }()

	select {
	case err := <-inboundErr:
		slog.Warn("inbound goroutine ended", "err", err)
	case err := <-pumpDone:
		slog.Info("pump ended", "err", err)
	case <-ctx.Done():
		slog.Info("signal received, exiting")
	}
	return 0
}

// openAgentSocket returns the *os.File the agent supervisor passed as
// FD 3. The supervisor wraps the agent end of an AF_UNIX SOCK_STREAM
// socketpair and we just use it.
func openAgentSocket() (*os.File, error) {
	const fd = 3
	f := os.NewFile(uintptr(fd), "agent-wire")
	if f == nil {
		return nil, fmt.Errorf("FD %d not present (must be spawned by agent supervisor)", fd)
	}
	return f, nil
}
