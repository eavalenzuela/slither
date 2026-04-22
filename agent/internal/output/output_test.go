package output

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/t3rmit3/slither/pkg/ocsf"
)

// safeBuf is a bytes.Buffer guarded by a mutex. The sink runs in a goroutine
// that writes concurrently with the test reading snapshots, so the raw
// bytes.Buffer would race.
type safeBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *safeBuf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *safeBuf) snapshot() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]byte, b.buf.Len())
	copy(out, b.buf.Bytes())
	return out
}

func TestStdoutJSONL_EmitsOnePerLine(t *testing.T) {
	var buf safeBuf
	sink := NewStdoutJSONL(&buf)

	in := make(chan ocsf.Event, 2)
	in <- &ocsf.DetectionFinding{
		ClassUID: ocsf.ClassDetectionFinding,
		Finding:  ocsf.Finding{UID: "a"},
		RuleInfo: ocsf.Rule{UID: "r1"},
	}
	in <- &ocsf.DetectionFinding{
		ClassUID: ocsf.ClassDetectionFinding,
		Finding:  ocsf.Finding{UID: "b"},
		RuleInfo: ocsf.Rule{UID: "r2"},
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- sink.Run(ctx, in) }()

	deadline := time.After(2 * time.Second)
	var snap []byte
	for {
		snap = buf.snapshot()
		if bytes.Count(snap, []byte{'\n'}) >= 2 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for two lines: %q", snap)
		case <-time.After(10 * time.Millisecond):
		}
	}

	cancel()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("sink.Run: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("sink did not return within 2s of cancel")
	}

	final := buf.snapshot()
	lines := bytes.Split(bytes.TrimRight(final, "\n"), []byte{'\n'})
	if len(lines) != 2 {
		t.Fatalf("want 2 lines, got %d: %q", len(lines), final)
	}
	for i, line := range lines {
		var v map[string]any
		if err := json.Unmarshal(line, &v); err != nil {
			t.Fatalf("line %d not JSON: %v (%q)", i, err, line)
		}
	}
}
