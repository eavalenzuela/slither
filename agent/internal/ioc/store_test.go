package ioc

import (
	"sync"
	"testing"

	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
)

func TestStore_ApplyAndMatchSHA256(t *testing.T) {
	t.Parallel()
	s := New()
	loaded, dropped := s.Apply([]*pb.IocFeed{{
		FeedId: "hashes",
		Kind:   pb.FeedKind_FEED_KIND_SHA256,
		// 64-char hex (sha256 of "hello world")
		Entries: []string{
			"b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
			"NOT-A-HEX", // dropped silently
		},
	}})
	if loaded != 1 {
		t.Fatalf("loaded = %d, want 1", loaded)
	}
	if dropped != 1 {
		t.Fatalf("dropped = %d, want 1", dropped)
	}
	if !s.MatchIOC("hashes", "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9") {
		t.Fatal("expected hit on canonical sha256")
	}
	if !s.MatchIOC("hashes", "B94D27B9934D3E08A52E52D7DA7DABFAC484EFE37A5380EE9088F7ACE2EFCDE9") {
		t.Fatal("expected hit on uppercase sha256 (lowercased before lookup)")
	}
	if s.MatchIOC("hashes", "0000000000000000000000000000000000000000000000000000000000000000") {
		t.Fatal("unexpected hit on absent hash")
	}
	if s.MatchIOC("missing-feed", "anything") {
		t.Fatal("unknown feed should miss, not panic")
	}
}

func TestStore_ApplyAndMatchIPv4(t *testing.T) {
	t.Parallel()
	s := New()
	s.Apply([]*pb.IocFeed{{
		FeedId:  "ips",
		Kind:    pb.FeedKind_FEED_KIND_IPV4,
		Entries: []string{"203.0.113.5", "10.0.0.1"},
	}})
	if !s.MatchIOC("ips", "203.0.113.5") {
		t.Fatal("expected hit on 203.0.113.5")
	}
	if s.MatchIOC("ips", "203.0.113.6") {
		t.Fatal("unexpected hit on 203.0.113.6")
	}
}

func TestStore_ApplyDomainFallback(t *testing.T) {
	t.Parallel()
	s := New()
	s.Apply([]*pb.IocFeed{{
		FeedId:  "domains",
		Kind:    pb.FeedKind_FEED_KIND_DOMAIN,
		Entries: []string{"evil.example.com", "OTHER.example.com"},
	}})
	if !s.MatchIOC("domains", "evil.example.com") {
		t.Fatal("missing canonical hit")
	}
	if !s.MatchIOC("domains", "Other.Example.com") {
		t.Fatal("missing case-insensitive hit")
	}
}

func TestStore_LookupFollowsApply(t *testing.T) {
	t.Parallel()
	s := New()
	s.Apply([]*pb.IocFeed{{
		FeedId:  "ips",
		Kind:    pb.FeedKind_FEED_KIND_IPV4,
		Entries: []string{"10.0.0.1"},
	}})
	count, kind, ok := s.Lookup("ips")
	if !ok || count != 1 || kind != "ipv4" {
		t.Fatalf("Lookup(ips) = (%d, %q, %v), want (1, ipv4, true)", count, kind, ok)
	}
	if _, _, ok := s.Lookup("nope"); ok {
		t.Fatal("Lookup(unknown) returned ok=true")
	}
}

func TestStore_AtomicSwapUnderConcurrentMatches(t *testing.T) {
	t.Parallel()
	s := New()
	s.Apply([]*pb.IocFeed{{
		FeedId:  "ips",
		Kind:    pb.FeedKind_FEED_KIND_IPV4,
		Entries: []string{"10.0.0.1"},
	}})

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = s.MatchIOC("ips", "10.0.0.1")
				}
			}
		}()
	}
	for i := 0; i < 50; i++ {
		s.Apply([]*pb.IocFeed{{
			FeedId:  "ips",
			Kind:    pb.FeedKind_FEED_KIND_IPV4,
			Entries: []string{"10.0.0.1", "10.0.0.2"},
		}})
	}
	close(stop)
	wg.Wait()
}
