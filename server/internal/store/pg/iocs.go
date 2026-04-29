package pg

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// IOCKind enumerates the indicator types the iocs table CHECK
// constraint accepts. Adding a kind requires a migration to widen the
// CHECK and a code update to validateEntry.
type IOCKind string

const (
	IOCKindSHA256 IOCKind = "sha256"
	IOCKindIPv4   IOCKind = "ipv4"
	IOCKindIPv6   IOCKind = "ipv6"
	IOCKindDomain IOCKind = "domain"
)

// MaxIOCFeedEntries caps the number of indicators per feed. Per
// ADR-0018 predicate 3, larger feeds can't be held in agent memory
// within the project's footprint budget, so they force ServerOnly
// classification at compile time.
const MaxIOCFeedEntries = 100_000

// IOCFeed is the projection used by the console + the compile-time
// registry. UpdatedAt advances on every entry change so the hub can
// spot real changes via NOTIFY (post-#66 wiring).
type IOCFeed struct {
	ID         string
	FeedID     string
	Name       string
	Kind       IOCKind
	EntryCount int
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// IOCFeedWithEntries extends IOCFeed with the full entry set. Returned
// by GetIOCFeedEntries — the agent reload (#67) needs the entries; the
// console list does not.
type IOCFeedWithEntries struct {
	IOCFeed
	Entries []string
}

// ErrIOCFeedNotFound is returned by GetIOCFeed* and DeleteIOCFeed when
// the feed_id (or row id) doesn't exist.
var ErrIOCFeedNotFound = errors.New("pg: ioc feed not found")

// ErrIOCFeedTooLarge is returned by InsertIOCFeed and UpdateIOCFeed
// when the entries list exceeds MaxIOCFeedEntries. The CHECK
// constraint catches it too, but raising a clean Go error lets the
// console surface the limit before round-tripping through Postgres.
var ErrIOCFeedTooLarge = errors.New("pg: ioc feed exceeds max entries")

// IOCFeedInsert is the input shape for InsertIOCFeed.
type IOCFeedInsert struct {
	FeedID  string
	Name    string
	Kind    IOCKind
	Entries []string
	ActorID string // operator user id; empty when system-driven
}

// InsertIOCFeed lands a new feed row. Returns ErrIOCFeedTooLarge when
// entries exceeds the cap; bubbles up the unique-constraint violation
// when feed_id already exists so the handler can surface a clean 409.
func (s *Store) InsertIOCFeed(ctx context.Context, ins IOCFeedInsert) (IOCFeed, error) {
	if ins.FeedID == "" {
		return IOCFeed{}, errors.New("pg.InsertIOCFeed: feed_id required")
	}
	if ins.Name == "" {
		return IOCFeed{}, errors.New("pg.InsertIOCFeed: name required")
	}
	if !validKind(ins.Kind) {
		return IOCFeed{}, fmt.Errorf("pg.InsertIOCFeed: unknown kind %q", ins.Kind)
	}
	if len(ins.Entries) > MaxIOCFeedEntries {
		return IOCFeed{}, ErrIOCFeedTooLarge
	}
	cleaned, err := normaliseEntries(ins.Kind, ins.Entries)
	if err != nil {
		return IOCFeed{}, fmt.Errorf("pg.InsertIOCFeed: %w", err)
	}

	var actor *string
	if ins.ActorID != "" {
		actor = &ins.ActorID
	}

	var feed IOCFeed
	err = s.pool.QueryRow(ctx, `
		INSERT INTO iocs (feed_id, name, kind, entries, updated_by)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, feed_id, name, kind, cardinality(entries), created_at, updated_at
	`, ins.FeedID, ins.Name, string(ins.Kind), cleaned, actor).Scan(
		&feed.ID, &feed.FeedID, &feed.Name, &feed.Kind, &feed.EntryCount,
		&feed.CreatedAt, &feed.UpdatedAt,
	)
	if err != nil {
		return IOCFeed{}, fmt.Errorf("pg.InsertIOCFeed: %w", err)
	}
	return feed, nil
}

// UpdateIOCFeed replaces a feed's entries (and optionally name). Pass
// an empty Name to leave it unchanged. Same cap + validation as Insert.
func (s *Store) UpdateIOCFeed(ctx context.Context, feedID, name string, entries []string, actorID string) (IOCFeed, error) {
	if feedID == "" {
		return IOCFeed{}, errors.New("pg.UpdateIOCFeed: feed_id required")
	}
	if len(entries) > MaxIOCFeedEntries {
		return IOCFeed{}, ErrIOCFeedTooLarge
	}

	// We need the kind to validate entries; one round-trip beats
	// asking the caller to plumb it.
	var kind IOCKind
	if err := s.pool.QueryRow(ctx,
		`SELECT kind FROM iocs WHERE feed_id = $1`, feedID,
	).Scan(&kind); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return IOCFeed{}, ErrIOCFeedNotFound
		}
		return IOCFeed{}, fmt.Errorf("pg.UpdateIOCFeed: lookup kind: %w", err)
	}
	cleaned, err := normaliseEntries(kind, entries)
	if err != nil {
		return IOCFeed{}, fmt.Errorf("pg.UpdateIOCFeed: %w", err)
	}

	var actor *string
	if actorID != "" {
		actor = &actorID
	}

	var feed IOCFeed
	err = s.pool.QueryRow(ctx, `
		UPDATE iocs
		SET entries    = $2,
		    name       = COALESCE(NULLIF($3, ''), name),
		    updated_at = now(),
		    updated_by = $4
		WHERE feed_id = $1
		RETURNING id, feed_id, name, kind, cardinality(entries), created_at, updated_at
	`, feedID, cleaned, name, actor).Scan(
		&feed.ID, &feed.FeedID, &feed.Name, &feed.Kind, &feed.EntryCount,
		&feed.CreatedAt, &feed.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return IOCFeed{}, ErrIOCFeedNotFound
	}
	if err != nil {
		return IOCFeed{}, fmt.Errorf("pg.UpdateIOCFeed: %w", err)
	}
	return feed, nil
}

// DeleteIOCFeed removes a feed row by feed_id. ErrIOCFeedNotFound when
// no matching row exists.
func (s *Store) DeleteIOCFeed(ctx context.Context, feedID string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM iocs WHERE feed_id = $1`, feedID)
	if err != nil {
		return fmt.Errorf("pg.DeleteIOCFeed: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrIOCFeedNotFound
	}
	return nil
}

// ListIOCFeeds returns every feed, ordered by feed_id. Entries are
// not loaded — the console list shows only counts.
func (s *Store) ListIOCFeeds(ctx context.Context) ([]IOCFeed, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, feed_id, name, kind, cardinality(entries), created_at, updated_at
		FROM iocs
		ORDER BY feed_id
	`)
	if err != nil {
		return nil, fmt.Errorf("pg.ListIOCFeeds: %w", err)
	}
	defer rows.Close()

	var out []IOCFeed
	for rows.Next() {
		var f IOCFeed
		if err := rows.Scan(&f.ID, &f.FeedID, &f.Name, &f.Kind, &f.EntryCount,
			&f.CreatedAt, &f.UpdatedAt); err != nil {
			return nil, fmt.Errorf("pg.ListIOCFeeds: scan: %w", err)
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// GetIOCFeed returns one feed without entries.
func (s *Store) GetIOCFeed(ctx context.Context, feedID string) (IOCFeed, error) {
	var f IOCFeed
	err := s.pool.QueryRow(ctx, `
		SELECT id, feed_id, name, kind, cardinality(entries), created_at, updated_at
		FROM iocs
		WHERE feed_id = $1
	`, feedID).Scan(&f.ID, &f.FeedID, &f.Name, &f.Kind, &f.EntryCount,
		&f.CreatedAt, &f.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return IOCFeed{}, ErrIOCFeedNotFound
	}
	if err != nil {
		return IOCFeed{}, fmt.Errorf("pg.GetIOCFeed: %w", err)
	}
	return f, nil
}

// GetIOCFeedEntries returns one feed with the full entry list — used
// by the agent push (#67) and by the console edit screen.
func (s *Store) GetIOCFeedEntries(ctx context.Context, feedID string) (IOCFeedWithEntries, error) {
	var (
		f       IOCFeedWithEntries
		entries []string
	)
	err := s.pool.QueryRow(ctx, `
		SELECT id, feed_id, name, kind, cardinality(entries), created_at, updated_at, entries
		FROM iocs
		WHERE feed_id = $1
	`, feedID).Scan(&f.ID, &f.FeedID, &f.Name, &f.Kind, &f.EntryCount,
		&f.CreatedAt, &f.UpdatedAt, &entries)
	if errors.Is(err, pgx.ErrNoRows) {
		return IOCFeedWithEntries{}, ErrIOCFeedNotFound
	}
	if err != nil {
		return IOCFeedWithEntries{}, fmt.Errorf("pg.GetIOCFeedEntries: %w", err)
	}
	f.Entries = entries
	return f, nil
}

func validKind(k IOCKind) bool {
	switch k {
	case IOCKindSHA256, IOCKindIPv4, IOCKindIPv6, IOCKindDomain:
		return true
	}
	return false
}

var (
	sha256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	domainPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)
)

// normaliseEntries lower-cases / canonicalises each entry and rejects
// malformed values. The cap is enforced again here so a direct call
// path that bypasses Insert/Update can't slip through.
func normaliseEntries(kind IOCKind, entries []string) ([]string, error) {
	if len(entries) > MaxIOCFeedEntries {
		return nil, ErrIOCFeedTooLarge
	}
	out := make([]string, 0, len(entries))
	seen := make(map[string]struct{}, len(entries))
	for i, raw := range entries {
		v := strings.ToLower(strings.TrimSpace(raw))
		if v == "" {
			continue
		}
		if err := validateEntry(kind, v); err != nil {
			return nil, fmt.Errorf("entry %d (%q): %w", i, raw, err)
		}
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out, nil
}

func validateEntry(kind IOCKind, v string) error {
	switch kind {
	case IOCKindSHA256:
		if !sha256Pattern.MatchString(v) {
			return errors.New("not a sha256 hex digest")
		}
	case IOCKindIPv4:
		addr, err := netip.ParseAddr(v)
		if err != nil || !addr.Is4() {
			return errors.New("not an IPv4 address")
		}
	case IOCKindIPv6:
		addr, err := netip.ParseAddr(v)
		if err != nil || !addr.Is6() || addr.Is4In6() {
			return errors.New("not an IPv6 address")
		}
	case IOCKindDomain:
		if !domainPattern.MatchString(v) {
			return errors.New("not a domain name")
		}
	default:
		return fmt.Errorf("unknown kind %q", kind)
	}
	return nil
}
