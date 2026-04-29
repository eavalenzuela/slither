package ioc

import (
	"context"
	"errors"
	"testing"

	"github.com/t3rmit3/slither/server/internal/store/pg"
)

type stubFeedSource struct {
	feeds   []pg.IOCFeed
	entries map[string][]string
	err     error
}

func (s *stubFeedSource) ListIOCFeeds(_ context.Context) ([]pg.IOCFeed, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.feeds, nil
}

func (s *stubFeedSource) GetIOCFeedEntries(_ context.Context, feedID string) (pg.IOCFeedWithEntries, error) {
	if s.err != nil {
		return pg.IOCFeedWithEntries{}, s.err
	}
	for _, f := range s.feeds {
		if f.FeedID != feedID {
			continue
		}
		return pg.IOCFeedWithEntries{
			IOCFeed: f,
			Entries: s.entries[feedID],
		}, nil
	}
	return pg.IOCFeedWithEntries{}, pg.ErrIOCFeedNotFound
}

func TestRegistry_LookupReturnsMissForUnknown(t *testing.T) {
	t.Parallel()
	r := New(&stubFeedSource{})
	if count, _, ok := r.Lookup("nope"); ok || count != 0 {
		t.Fatalf("Lookup(nope) = (%d, _, %v), want (0, _, false)", count, ok)
	}
}

func TestRegistry_RefreshAndLookup(t *testing.T) {
	t.Parallel()
	src := &stubFeedSource{
		feeds: []pg.IOCFeed{
			{FeedID: "ips", EntryCount: 4, Kind: pg.IOCKindIPv4},
			{FeedID: "hashes", EntryCount: 100_001, Kind: pg.IOCKindSHA256},
		},
		entries: map[string][]string{
			"ips":    {"203.0.113.1", "203.0.113.2"},
			"hashes": nil,
		},
	}
	r := New(src)
	n, err := r.Refresh(context.Background())
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if n != 2 {
		t.Fatalf("Refresh returned %d, want 2", n)
	}
	count, kind, ok := r.Lookup("ips")
	if !ok || count != 4 || kind != "ipv4" {
		t.Fatalf("Lookup(ips) = (%d, %q, %v), want (4, ipv4, true)", count, kind, ok)
	}
	count, _, ok = r.Lookup("hashes")
	if !ok || count != 100_001 {
		t.Fatalf("Lookup(hashes) = (%d, _, %v), want oversize", count, ok)
	}
}

func TestRegistry_RefreshErrorKeepsPreviousSnapshot(t *testing.T) {
	t.Parallel()
	src := &stubFeedSource{
		feeds: []pg.IOCFeed{
			{FeedID: "alpha", EntryCount: 1, Kind: pg.IOCKindDomain},
		},
		entries: map[string][]string{"alpha": {"evil.example.com"}},
	}
	r := New(src)
	if _, err := r.Refresh(context.Background()); err != nil {
		t.Fatalf("first Refresh: %v", err)
	}

	src.err = errors.New("simulated pg blip")
	if _, err := r.Refresh(context.Background()); err == nil {
		t.Fatal("expected refresh to surface the simulated error")
	}
	// Snapshot from the first successful Refresh must still resolve.
	if _, _, ok := r.Lookup("alpha"); !ok {
		t.Fatal("snapshot lost after errored refresh")
	}
}
