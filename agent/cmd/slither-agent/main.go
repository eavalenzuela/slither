// Command slither-agent runs the Linux endpoint agent.
//
// Phase 1 shape: wire every internal stage end-to-end under a cancellable
// context. The individual stages are stubs today; each Phase 1 task fills
// one in.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/t3rmit3/slither/agent/internal/app"
	"github.com/t3rmit3/slither/agent/internal/config"
	"github.com/t3rmit3/slither/pkg/version"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

func run() error {
	configPath := flag.String("config", "/etc/slither/agent.yaml", "Path to agent YAML config")
	showVersion := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	dirty := ""
	if version.Modified() {
		dirty = "+dirty"
	}
	banner := fmt.Sprintf("slither-agent %s (%s%s)", version.Version, version.Revision(), dirty)

	if *showVersion {
		fmt.Println(banner)
		return nil
	}

	fmt.Fprintln(os.Stderr, banner)

	cfg, err := config.Load(*configPath)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := app.Run(ctx, cfg, *configPath); err != nil && !errors.Is(err, context.Canceled) {
		return fmt.Errorf("agent: %w", err)
	}
	return nil
}
