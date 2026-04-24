package enricher

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/t3rmit3/slither/agent/internal/pipeline"
	"github.com/t3rmit3/slither/pkg/ocsf"
)

// TestHandleProcessExecAttachesHashInline warms the hasher cache before
// dispatch so the exec path takes the cached branch and stamps the hash on
// the emitted event synchronously — no followup.
func TestHandleProcessExecAttachesHashInline(t *testing.T) {
	e := newTestEnricher(t)

	body := []byte("#!/bin/sh\necho hi\n")
	bin := filepath.Join(t.TempDir(), "hi.sh")
	if err := os.WriteFile(bin, body, 0o600); err != nil {
		t.Fatal(err)
	}
	want := sha256Hex(body)

	ch, _, _ := e.hasher.Submit(bin)
	<-ch

	e.cache.upsert(procEntry{
		pid: 321, ppid: 1, uid: 0, comm: "hi.sh", exe: bin,
		createdAt: time.Unix(10, 0),
	})

	raw := pipeline.RawProcessEvent{
		Kind: pipeline.ProcExec, PID: 321, UID: 0, Comm: "hi.sh",
		Timestamp: time.Unix(11, 0),
	}
	e.handleProcess(context.Background(), raw)

	ev := (<-e.out).(*ocsf.ProcessActivity)
	if ev.Process.File == nil || ev.Process.File.HashesSHA256 != want {
		t.Fatalf("inline hash not attached: file=%+v", ev.Process.File)
	}
	if ev.Metadata.CorrelationUID != "" {
		t.Errorf("cached path should not emit a correlation uid")
	}
	select {
	case extra := <-e.out:
		t.Fatalf("unexpected extra emit on cached path: %+v", extra)
	default:
	}
}

// TestAwaitHashEmitsInlineWhenFast exercises the in-budget branch of
// awaitHash by pre-closing the channel with a hash value. No followup
// should fire.
func TestAwaitHashEmitsInlineWhenFast(t *testing.T) {
	e := newTestEnricher(t)
	e.opts.HashInlineTimeoutMs = 1000

	ch := make(chan string, 1)
	ch <- "deadbeef"
	close(ch)

	ev := &ocsf.ProcessActivity{
		Metadata: ocsf.Metadata{UID: "orig", Version: ocsf.Version},
		Process:  ocsf.Process{File: &ocsf.File{Path: "/bin/x"}},
	}
	e.awaitHash(context.Background(), ev, ch)

	got := (<-e.out).(*ocsf.ProcessActivity)
	if got.Process.File.HashesSHA256 != "deadbeef" {
		t.Errorf("inline hash = %q, want deadbeef", got.Process.File.HashesSHA256)
	}
	select {
	case extra := <-e.out:
		t.Fatalf("inline branch should not emit followup, got %+v", extra)
	case <-time.After(20 * time.Millisecond):
	}
}

// TestAwaitHashEmitsFollowupWhenSlow forces the timeout branch by using a
// never-closed channel. The bare event emits first; the followup lands when
// the channel later yields a hash.
func TestAwaitHashEmitsFollowupWhenSlow(t *testing.T) {
	e := newTestEnricher(t)
	e.opts.HashInlineTimeoutMs = 1

	ch := make(chan string, 1)

	ev := &ocsf.ProcessActivity{
		Metadata: ocsf.Metadata{UID: "orig-123", Version: ocsf.Version, Labels: nil},
		Process:  ocsf.Process{File: &ocsf.File{Path: "/bin/x", Name: "x"}},
		Actor:    ocsf.Actor{User: ocsf.User{Name: "root"}},
	}

	go func() {
		// Ensure awaitHash hits its timeout branch before the hash lands.
		time.Sleep(30 * time.Millisecond)
		ch <- "cafef00d"
		close(ch)
	}()

	e.awaitHash(context.Background(), ev, ch)

	var orig, followup *ocsf.ProcessActivity
	deadline := time.After(2 * time.Second)
	for followup == nil {
		select {
		case got := <-e.out:
			pa := got.(*ocsf.ProcessActivity)
			if pa.Metadata.CorrelationUID == "" {
				orig = pa
			} else {
				followup = pa
			}
		case <-deadline:
			t.Fatalf("followup not emitted within 2s; orig=%v", orig)
		}
	}

	if orig == nil {
		t.Fatal("bare original never emitted")
	}
	if orig.Process.File.HashesSHA256 != "" {
		t.Errorf("bare event should carry no hash, got %q", orig.Process.File.HashesSHA256)
	}
	if followup.Metadata.CorrelationUID != "orig-123" {
		t.Errorf("correlation_uid = %q, want orig-123", followup.Metadata.CorrelationUID)
	}
	if followup.Process.File.HashesSHA256 != "cafef00d" {
		t.Errorf("followup hash = %q, want cafef00d", followup.Process.File.HashesSHA256)
	}
	if followup.Metadata.EventCode != "hash_followup" {
		t.Errorf("event_code = %q, want hash_followup", followup.Metadata.EventCode)
	}
	foundLabel := false
	for _, l := range followup.Metadata.Labels {
		if l == "followup" {
			foundLabel = true
		}
	}
	if !foundLabel {
		t.Errorf("followup missing 'followup' label: %v", followup.Metadata.Labels)
	}
}

// TestFollowupHashNoOpOnEmptyHash ensures a read-failed hash doesn't spawn a
// useless followup event.
func TestFollowupHashNoOpOnEmptyHash(t *testing.T) {
	e := newTestEnricher(t)
	ch := make(chan string, 1)
	ch <- ""
	close(ch)

	orig := &ocsf.ProcessActivity{
		Metadata: ocsf.Metadata{UID: "orig-xx"},
	}
	e.followupHash(context.Background(), orig, ch)

	select {
	case ev := <-e.out:
		t.Fatalf("empty hash should produce no followup, got %+v", ev)
	case <-time.After(20 * time.Millisecond):
	}
}
