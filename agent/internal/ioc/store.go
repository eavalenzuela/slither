// Package ioc owns the agent-side IOC feed store (Phase 3 #67).
//
// The server pushes feed entries inline on every RuleSet so the agent
// has the indicators ready before the rules that reference them
// evaluate. Storage is type-specific so the per-event match stays
// allocation-free: SHA-256 → [32]byte set; IPv4 → uint32 set;
// IPv6 → [16]byte set; domain/filename → string set. Total budget at
// the 100k cap is ~10 MB per feed.
//
// Reload is an atomic.Pointer swap: Apply builds the new snapshot off
// the hot path, then swaps it in so concurrent matchers see either
// the old or the new feed atomically. The previous snapshot is
// garbage-collected once the last in-flight Match returns.
package ioc

import (
	"encoding/hex"
	"net/netip"
	"strings"
	"sync/atomic"

	"github.com/t3rmit3/slither/pkg/ruleast"
	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
)

// Store is the agent's in-memory IOC feed map.
type Store struct {
	snapshot atomic.Pointer[snapshot]
}

type snapshot struct {
	feeds map[string]*feed
}

type feed struct {
	kind    pb.FeedKind
	count   int
	sha256  map[[32]byte]struct{}
	ipv4    map[uint32]struct{}
	ipv6    map[[16]byte]struct{}
	strings map[string]struct{}
}

// New returns an empty store. Apply with the first RuleSet's feeds
// before serving any matches.
func New() *Store {
	s := &Store{}
	s.snapshot.Store(&snapshot{feeds: map[string]*feed{}})
	return s
}

// Apply replaces the entire feed set with the given pb.IocFeed slice.
// Entries that fail per-kind parsing are dropped silently — the
// server's compile-time gate already rejected malformed entries via
// pg.normaliseEntries; any survivors here are belt-and-braces.
//
// Returns the number of feeds loaded; reports a structured warning
// when any individual feed had parse drops so the caller can log
// observability without rejecting the whole set.
func (s *Store) Apply(feeds []*pb.IocFeed) (loaded, dropped int) {
	next := &snapshot{feeds: make(map[string]*feed, len(feeds))}
	for _, raw := range feeds {
		if raw == nil || raw.GetFeedId() == "" {
			continue
		}
		f := &feed{kind: raw.GetKind()}
		for _, entry := range raw.GetEntries() {
			if !f.add(entry) {
				dropped++
			}
		}
		next.feeds[raw.GetFeedId()] = f
		loaded++
	}
	s.snapshot.Store(next)
	return loaded, dropped
}

// MatchIOC satisfies ruleast.IOCEnv. Returns false for unknown feeds
// and for values that don't parse for the feed's kind.
func (s *Store) MatchIOC(feedID, value string) bool {
	snap := s.snapshot.Load()
	if snap == nil {
		return false
	}
	f, ok := snap.feeds[feedID]
	if !ok {
		return false
	}
	return f.match(value)
}

// Lookup satisfies ruleast.IOCRegistry. Returns (count, kind-string,
// true) for known feeds. The compiler treats unknown feeds as a hard
// error so a typo in a `|ioc:` reference doesn't silently miss.
func (s *Store) Lookup(feedID string) (entryCount int, kind string, ok bool) {
	snap := s.snapshot.Load()
	if snap == nil {
		return 0, "", false
	}
	f, present := snap.feeds[feedID]
	if !present {
		return 0, "", false
	}
	return f.count, kindString(f.kind), true
}

// Compile-time guards.
var (
	_ ruleast.IOCEnv      = (*Store)(nil)
	_ ruleast.IOCRegistry = (*Store)(nil)
)

func (f *feed) add(raw string) bool {
	v := strings.ToLower(strings.TrimSpace(raw))
	if v == "" {
		return false
	}
	switch f.kind {
	case pb.FeedKind_FEED_KIND_SHA256:
		if len(v) != 64 {
			return false
		}
		var arr [32]byte
		if _, err := hex.Decode(arr[:], []byte(v)); err != nil {
			return false
		}
		if f.sha256 == nil {
			f.sha256 = make(map[[32]byte]struct{}, 256)
		}
		f.sha256[arr] = struct{}{}
	case pb.FeedKind_FEED_KIND_IPV4:
		addr, err := netip.ParseAddr(v)
		if err != nil || !addr.Is4() {
			return false
		}
		ip := addr.As4()
		key := uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
		if f.ipv4 == nil {
			f.ipv4 = make(map[uint32]struct{}, 256)
		}
		f.ipv4[key] = struct{}{}
	case pb.FeedKind_FEED_KIND_IPV6:
		addr, err := netip.ParseAddr(v)
		if err != nil || !addr.Is6() || addr.Is4In6() {
			return false
		}
		if f.ipv6 == nil {
			f.ipv6 = make(map[[16]byte]struct{}, 256)
		}
		f.ipv6[addr.As16()] = struct{}{}
	default:
		// Domain, filename, and any future string-shaped kind go in
		// the string map untransformed beyond lowercasing.
		if f.strings == nil {
			f.strings = make(map[string]struct{}, 256)
		}
		f.strings[v] = struct{}{}
	}
	f.count++
	return true
}

func (f *feed) match(raw string) bool {
	v := strings.ToLower(strings.TrimSpace(raw))
	if v == "" {
		return false
	}
	switch f.kind {
	case pb.FeedKind_FEED_KIND_SHA256:
		if len(v) != 64 {
			return false
		}
		var arr [32]byte
		if _, err := hex.Decode(arr[:], []byte(v)); err != nil {
			return false
		}
		_, ok := f.sha256[arr]
		return ok
	case pb.FeedKind_FEED_KIND_IPV4:
		addr, err := netip.ParseAddr(v)
		if err != nil || !addr.Is4() {
			return false
		}
		ip := addr.As4()
		key := uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
		_, ok := f.ipv4[key]
		return ok
	case pb.FeedKind_FEED_KIND_IPV6:
		addr, err := netip.ParseAddr(v)
		if err != nil || !addr.Is6() || addr.Is4In6() {
			return false
		}
		_, ok := f.ipv6[addr.As16()]
		return ok
	default:
		_, ok := f.strings[v]
		return ok
	}
}

func kindString(k pb.FeedKind) string {
	switch k {
	case pb.FeedKind_FEED_KIND_SHA256:
		return "sha256"
	case pb.FeedKind_FEED_KIND_IPV4:
		return "ipv4"
	case pb.FeedKind_FEED_KIND_IPV6:
		return "ipv6"
	case pb.FeedKind_FEED_KIND_DOMAIN:
		return "domain"
	case pb.FeedKind_FEED_KIND_FILENAME:
		return "filename"
	}
	return ""
}
