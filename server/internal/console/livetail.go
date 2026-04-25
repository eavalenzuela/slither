package console

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
	"github.com/t3rmit3/slither/server/internal/console/views"
)

// liveBufferDepth bounds the per-connection bus subscription buffer.
// Drops past this point are counted and surfaced in the UI footer so
// operators see when their tab is falling behind ingest. 1024 covers
// roughly 100 ms of the Phase 1 baseline (≈12k events/s on Debian 13)
// at full firehose without imposing a memory cliff per connection.
const liveBufferDepth = 1024

// liveDropsHeartbeat is how often the SSE handler emits the running
// drop count to the client. Long enough that idle tabs aren't noisy,
// short enough that a flapping subscriber surfaces within a few seconds.
const liveDropsHeartbeat = 2 * time.Second

// livePage renders the live-tail template.
func (s *Server) livePage(w http.ResponseWriter, r *http.Request) {
	render(w, r, views.LiveTail(views.LiveTailData{}))
}

// liveStream is the SSE handler. Subscribes a per-request name on the
// bus, writes one envelope per default-typed SSE message, and drops
// drop-count updates as a "drops" SSE event every liveDropsHeartbeat.
//
// Filters are query params: host_id / class_uid / contains. host_id
// matches as substring (operators typically paste a full UUID, but
// the bigger value is "type a hostname prefix and watch its events"
// once #44 surfaces hostname). class_uid is exact-match on the
// numeric uid; "contains" runs a bytes.Contains over the canonical
// JSON payload.
func (s *Server) liveStream(w http.ResponseWriter, r *http.Request) {
	if s.bus == nil {
		http.Error(w, "live tail unavailable", http.StatusServiceUnavailable)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // disable proxy buffering

	filt := parseLiveFilter(r)

	// Per-connection drop counter. The bus drop-callback mutates this
	// from the publisher's goroutine; the writer reads via Load on
	// the heartbeat tick.
	var drops atomic.Uint64
	subName := fmt.Sprintf("live:%s:%d", s.userID(r), time.Now().UnixNano())
	defer s.bus.Unsubscribe(subName)
	s.bus.SetDropObserver(subName, func() { drops.Add(1) })
	sub := s.bus.Subscribe(subName, liveBufferDepth)

	dropTick := time.NewTicker(liveDropsHeartbeat)
	defer dropTick.Stop()

	emit := func(eventType, data string) bool {
		var msg string
		if eventType != "" {
			msg = "event: " + eventType + "\n"
		}
		msg += "data: " + data + "\n\n"
		if _, err := w.Write([]byte(msg)); err != nil {
			return false
		}
		flusher.Flush()
		return true
	}

	// Send an initial drops=0 so the UI footer has a value before any
	// envelope arrives.
	if !emit("drops", "0") {
		return
	}

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case env, ok := <-sub:
			if !ok {
				return
			}
			if !filt.matches(env) {
				continue
			}
			payload, err := json.Marshal(envelopeAsJSON(env))
			if err != nil {
				continue
			}
			if !emit("", string(payload)) {
				return
			}
		case <-dropTick.C:
			if !emit("drops", strconv.FormatUint(drops.Load(), 10)) {
				return
			}
		}
	}
}

// liveFilter holds the parsed request filters.
type liveFilter struct {
	hostSubstring string
	classUID      uint32 // 0 = wildcard
	contains      []byte // empty = wildcard
}

func parseLiveFilter(r *http.Request) liveFilter {
	q := r.URL.Query()
	f := liveFilter{
		hostSubstring: q.Get("host_id"),
		contains:      []byte(q.Get("contains")),
	}
	if v := q.Get("class_uid"); v != "" {
		if n, err := strconv.ParseUint(v, 10, 32); err == nil {
			f.classUID = uint32(n) //nolint:gosec // bounded by ParseUint(0,32)
		}
	}
	return f
}

func (f liveFilter) matches(env *pb.Envelope) bool {
	if env == nil {
		return false
	}
	if f.hostSubstring != "" && !containsString(env.GetHostId(), f.hostSubstring) {
		return false
	}
	if f.classUID != 0 && uint32(env.GetClassId()) != f.classUID {
		return false
	}
	if len(f.contains) > 0 && !bytes.Contains(env.GetPayload(), f.contains) {
		return false
	}
	return true
}

// containsString is a tiny wrapper rather than pulling strings into
// the hot path; the receiver is small enough that the inline cost is
// nil and the dependency surface stays contained.
func containsString(haystack, needle string) bool {
	if needle == "" {
		return true
	}
	return bytes.Contains([]byte(haystack), []byte(needle))
}

// envelopeAsJSON projects an envelope into a JSON-serialisable shape
// for the live-tail UI. The proto Envelope includes binary payload
// and timestamps that don't round-trip cleanly through the default
// json marshaller; this struct hand-codes the shape operators actually
// want to see streamed.
type liveEnvelope struct {
	EventID     string          `json:"event_id"`
	HostID      string          `json:"host_id"`
	ClassID     int32           `json:"class_id"`
	ObservedAt  string          `json:"observed_at"`
	CollectedAt string          `json:"collected_at"`
	Payload     json.RawMessage `json:"payload"`
}

func envelopeAsJSON(env *pb.Envelope) liveEnvelope {
	out := liveEnvelope{
		EventID: env.GetEventId(),
		HostID:  env.GetHostId(),
		ClassID: int32(env.GetClassId()),
		Payload: env.GetPayload(),
	}
	if t := env.GetObservedAt(); t != nil {
		out.ObservedAt = t.AsTime().UTC().Format(time.RFC3339Nano)
	}
	if t := env.GetCollectedAt(); t != nil {
		out.CollectedAt = t.AsTime().UTC().Format(time.RFC3339Nano)
	}
	return out
}
