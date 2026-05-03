package extensions

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/t3rmit3/slither/agent/internal/config"
	"github.com/t3rmit3/slither/agent/internal/telemetry"
	"github.com/t3rmit3/slither/pkg/ocsf"
)

// Manager is the per-agent supervisor of all extensions. It owns the
// merged event channel that the engine consumes alongside the native
// collectors' enricher output, and it owns the per-extension Process
// instances that supervise individual extension binaries.
//
// Lifecycle: NewManager → Run (blocks) → ctx cancel → Run returns →
// Events channel is closed.
type Manager struct {
	exts   []*Process
	events chan ocsf.Event
	telem  *telemetry.Counters
}

// NewManager wires one Process per extension config entry. verifierFor
// supplies the SignatureVerifier appropriate to each extension's
// signature_verification mode (cosign vs disabled). device is the
// stamp the supervisor copies onto every extension-emitted OCSF event.
//
// bufferSize is the depth of the merged events channel. Bursts beyond
// this back-pressure into the per-Process Recv loop, which is
// acceptable: the agent's existing collector → engine path uses
// bounded channels everywhere.
func NewManager(cfgs []config.Extension, verifierFor func(config.Extension) SignatureVerifier, device ocsf.Device, telem *telemetry.Counters, bufferSize int) (*Manager, error) {
	if bufferSize <= 0 {
		bufferSize = 1024
	}
	events := make(chan ocsf.Event, bufferSize)
	exts := make([]*Process, 0, len(cfgs))
	for _, c := range cfgs {
		v := verifierFor(c)
		if v == nil {
			return nil, fmt.Errorf("extensions: %s: nil verifier", c.Name)
		}
		exts = append(exts, NewProcess(c, v, device, telem, events))
	}
	return &Manager{exts: exts, events: events, telem: telem}, nil
}

// Events is the merged OCSF event channel — every Process writes
// stamped events here. Closed when Run returns.
func (m *Manager) Events() <-chan ocsf.Event { return m.events }

// Run starts every Process supervisor goroutine and blocks until ctx
// is cancelled. Closes Events on return so downstream merging
// goroutines see the close cleanly. Per-Process errors log but never
// bubble up — one extension's misbehaviour shouldn't crater the
// agent.
func (m *Manager) Run(ctx context.Context) error {
	if len(m.exts) == 0 {
		// No extensions configured. Block on ctx so the caller's
		// goroutine model stays uniform; close events on exit.
		<-ctx.Done()
		close(m.events)
		return ctx.Err()
	}

	var wg sync.WaitGroup
	for _, p := range m.exts {
		p := p
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := p.Run(ctx); err != nil && ctx.Err() == nil {
				slog.Warn("ext: supervisor exited",
					"ext", p.cfg.Name,
					"err", err)
			}
		}()
	}
	wg.Wait()
	close(m.events)
	return ctx.Err()
}

// DefaultVerifierFor returns the SignatureVerifier matching the
// extension's signature_verification config field. Cosign mode reads
// the operator-supplied identity regexp + issuer from the config
// (defaults applied during config validation).
func DefaultVerifierFor(c config.Extension) SignatureVerifier {
	switch c.SignatureVerification {
	case "disabled":
		return DisabledVerifier{}
	case "cosign", "":
		return &CosignVerifier{
			IdentityRegexp:  c.CosignIdentityRegexp,
			OIDCIssuer:      c.CosignOIDCIssuer,
			SignaturePath:   c.SignaturePath,
			CertificatePath: c.CertificatePath,
		}
	}
	return nil
}
