// Command slither-server runs the ingest, detection, and console server.
//
// Phase 2 §4.1 task #31: scaffold wired to config.Load + app.Run with
// signal-driven cancellation. Real listeners come online in later tasks.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/t3rmit3/slither/pkg/version"
	"github.com/t3rmit3/slither/server/internal/app"
	"github.com/t3rmit3/slither/server/internal/config"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

func run() error {
	configPath := flag.String("config", "/etc/slither/server.yaml", "Path to server YAML config")
	showVersion := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	banner := "slither-server " + version.String()

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
		return fmt.Errorf("server: %w", err)
	}
	return nil
}
