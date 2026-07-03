package ioc

import (
	"testing"

	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
)

// Improvement: domain feeds normalise a trailing FQDN dot so a
// fully-qualified candidate matches a bare-domain indicator.
func TestStore_DomainTrailingDot(t *testing.T) {
	t.Parallel()
	s := New()
	s.Apply([]*pb.IocFeed{{
		FeedId:  "domains",
		Kind:    pb.FeedKind_FEED_KIND_DOMAIN,
		Entries: []string{"evil.example.com"},
	}})
	if !s.MatchIOC("domains", "evil.example.com.") {
		t.Error("FQDN with trailing dot should match a bare-domain indicator")
	}
	// The reverse: an indicator stored with a trailing dot also matches
	// the bare candidate.
	s.Apply([]*pb.IocFeed{{
		FeedId:  "domains",
		Kind:    pb.FeedKind_FEED_KIND_DOMAIN,
		Entries: []string{"bad.example.net."},
	}})
	if !s.MatchIOC("domains", "bad.example.net") {
		t.Error("bare candidate should match an indicator stored with a trailing dot")
	}
}

// Improvement: IPv4 feeds match a v4-mapped v6 address (dual-stack peer).
func TestStore_IPv4MatchesMappedIPv6(t *testing.T) {
	t.Parallel()
	s := New()
	s.Apply([]*pb.IocFeed{{
		FeedId:  "ips",
		Kind:    pb.FeedKind_FEED_KIND_IPV4,
		Entries: []string{"203.0.113.5"},
	}})
	if !s.MatchIOC("ips", "::ffff:203.0.113.5") {
		t.Error("v4-mapped v6 form should match the IPv4 indicator")
	}
	if s.MatchIOC("ips", "::ffff:203.0.113.6") {
		t.Error("non-matching v4-mapped v6 must miss")
	}
}

// Improvement: Stats reports per-feed counts + total for the live snapshot.
func TestStore_Stats(t *testing.T) {
	t.Parallel()
	s := New()
	s.Apply([]*pb.IocFeed{
		{FeedId: "ips", Kind: pb.FeedKind_FEED_KIND_IPV4, Entries: []string{"10.0.0.1", "10.0.0.2"}},
		{FeedId: "domains", Kind: pb.FeedKind_FEED_KIND_DOMAIN, Entries: []string{"evil.example.com"}},
	})
	per, total := s.Stats()
	if per["ips"] != 2 || per["domains"] != 1 {
		t.Errorf("per-feed counts = %v, want ips:2 domains:1", per)
	}
	if total != 3 {
		t.Errorf("total = %d, want 3", total)
	}
}
