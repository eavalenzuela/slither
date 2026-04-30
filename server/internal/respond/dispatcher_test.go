package respond

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
	"github.com/t3rmit3/slither/server/internal/store/pg"
	"github.com/t3rmit3/slither/server/internal/telemetry"
)

func TestResponseActionToProto_FullSurface(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   pg.ResponseAction
		want pb.ResponseAction
	}{
		{pg.ResponseActionKillProcess, pb.ResponseAction_RESPONSE_ACTION_KILL_PROCESS},
		{pg.ResponseActionKillTree, pb.ResponseAction_RESPONSE_ACTION_KILL_PROCESS_TREE},
		{pg.ResponseActionQuarantineFile, pb.ResponseAction_RESPONSE_ACTION_QUARANTINE_FILE},
		{pg.ResponseActionIsolateHost, pb.ResponseAction_RESPONSE_ACTION_ISOLATE_HOST},
		{pg.ResponseActionUnisolateHost, pb.ResponseAction_RESPONSE_ACTION_UNISOLATE_HOST},
		{pg.ResponseActionCollectArtifacts, pb.ResponseAction_RESPONSE_ACTION_COLLECT_ARTIFACTS},
		{pg.ResponseAction("future-unknown"), pb.ResponseAction_RESPONSE_ACTION_UNSPECIFIED},
	}
	for _, c := range cases {
		if got := responseActionToProto(c.in); got != c.want {
			t.Errorf("responseActionToProto(%q) = %s, want %s", c.in, got, c.want)
		}
	}
}

// queueDepth is hub-internal; the constant lives next to the production
// code so tests reaching for "fill the queue" use the same value.
func TestEnqueueDropsOnFull(t *testing.T) {
	t.Parallel()
	// NewHub panics on nil store; build the bare structure by hand
	// for tests that only exercise enqueue + Subscribe.
	h2 := &Hub{
		telem:  telemetry.NewCounters(),
		queues: make(map[string]chan *pb.ResponseRequest),
	}
	hostID := "host-x"
	ch, unsub := h2.Subscribe(hostID)
	defer unsub()

	for i := 0; i < queueDepth; i++ {
		if !h2.enqueue(hostID, &pb.ResponseRequest{ControlId: "c"}) {
			t.Fatalf("enqueue %d unexpectedly dropped", i)
		}
	}
	// One past capacity should drop.
	if h2.enqueue(hostID, &pb.ResponseRequest{ControlId: "overflow"}) {
		t.Fatal("enqueue past capacity should drop, did not")
	}

	// Drain one slot and verify enqueue accepts again.
	<-ch
	if !h2.enqueue(hostID, &pb.ResponseRequest{ControlId: "post-drain"}) {
		t.Fatal("enqueue after drain unexpectedly dropped")
	}

	// Stale-host enqueue is a drop, not a panic.
	if h2.enqueue("nobody-home", &pb.ResponseRequest{}) {
		t.Fatal("enqueue to unknown host should drop, did not")
	}
}

func TestSubscribe_DuplicateClosesPrevious(t *testing.T) {
	t.Parallel()
	h := &Hub{
		telem:  telemetry.NewCounters(),
		queues: make(map[string]chan *pb.ResponseRequest),
	}
	hostID := "host-x"
	first, _ := h.Subscribe(hostID)
	second, unsub2 := h.Subscribe(hostID)
	defer unsub2()

	// The first channel should be closed by the second Subscribe.
	select {
	case _, ok := <-first:
		if ok {
			t.Fatal("first Subscribe channel still open after duplicate Subscribe")
		}
	case <-time.After(time.Second):
		t.Fatal("first Subscribe channel not closed after duplicate Subscribe")
	}

	// Enqueue should now land on the second subscriber.
	if !h.enqueue(hostID, &pb.ResponseRequest{ControlId: "c"}) {
		t.Fatal("enqueue after duplicate Subscribe dropped unexpectedly")
	}
	select {
	case <-second:
	case <-time.After(time.Second):
		t.Fatal("second Subscribe channel didn't receive the enqueued request")
	}
}

// Hub.Dispatch + Hub.OnResult round-trip through *pg.Store, so the
// full happy-path coverage lives in the testcontainers integration
// test (dispatcher_integration_test.go). The unit suite above
// covers the in-process surfaces (enqueue / Subscribe /
// responseActionToProto) that don't need pg.

func TestPersistArtefact_WritesToDisk(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	h := &Hub{
		telem:       telemetry.NewCounters(),
		queues:      make(map[string]chan *pb.ResponseRequest),
		artefactDir: dir,
	}
	const actionID = "11111111-1111-1111-1111-111111111111"
	blob := []byte("fake-tarball")
	if err := h.persistArtefact(actionID, blob); err != nil {
		t.Fatalf("persistArtefact: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, actionID+".tgz"))
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !bytes.Equal(got, blob) {
		t.Errorf("contents = %q, want round-trip", got)
	}
}

func TestPersistArtefact_CreatesParentDir(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	nested := filepath.Join(root, "nested", "artefacts")
	h := &Hub{
		telem:       telemetry.NewCounters(),
		queues:      make(map[string]chan *pb.ResponseRequest),
		artefactDir: nested,
	}
	if err := h.persistArtefact("22222222-2222-2222-2222-222222222222", []byte("x")); err != nil {
		t.Fatalf("persistArtefact: %v", err)
	}
	if _, err := os.Stat(nested); err != nil {
		t.Errorf("nested dir not created: %v", err)
	}
}

func TestReverseActionFor_FullSurface(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   pg.ResponseAction
		want pg.ResponseAction
		err  bool
	}{
		{pg.ResponseActionQuarantineFile, pg.ResponseActionQuarantineFile, false},
		{pg.ResponseActionIsolateHost, pg.ResponseActionUnisolateHost, false},
		// Non-reversible classes.
		{pg.ResponseActionKillProcess, "", true},
		{pg.ResponseActionKillTree, "", true},
		{pg.ResponseActionUnisolateHost, "", true},
		{pg.ResponseActionCollectArtifacts, "", true},
	}
	for _, c := range cases {
		c := c
		t.Run(string(c.in), func(t *testing.T) {
			t.Parallel()
			got, err := reverseActionFor(c.in)
			if c.err {
				if err == nil {
					t.Errorf("reverseActionFor(%q) err = nil, want non-nil", c.in)
				}
				return
			}
			if err != nil {
				t.Errorf("reverseActionFor(%q) err = %v, want nil", c.in, err)
			}
			if got != c.want {
				t.Errorf("reverseActionFor(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestOnResultRejectsBadControlID(t *testing.T) {
	t.Parallel()
	h := &Hub{
		telem:  telemetry.NewCounters(),
		queues: make(map[string]chan *pb.ResponseRequest),
	}
	if err := h.OnResult(context.Background(), nil); err == nil {
		t.Fatal("nil result should error")
	}
	if err := h.OnResult(context.Background(), &pb.ResponseResult{}); err == nil {
		t.Fatal("empty control_id should error")
	}
	if err := h.OnResult(context.Background(), &pb.ResponseResult{ControlId: "not-a-uuid"}); err == nil {
		t.Fatal("non-uuid control_id should error")
	}
}
