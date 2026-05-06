package console

import (
	"context"
	"errors"
	"testing"

	"github.com/t3rmit3/slither/server/internal/store/pg"
)

// fakeHostLookup is a hostByNameLookup stub that resolveHostFilter can
// hit without a live pg connection.
type fakeHostLookup struct {
	byName map[string]pg.HostRow
	err    error
}

func (f *fakeHostLookup) GetHostByName(_ context.Context, hostname string) (pg.HostRow, error) {
	if f.err != nil {
		return pg.HostRow{}, f.err
	}
	row, ok := f.byName[hostname]
	if !ok {
		return pg.HostRow{}, pg.ErrHostNotFound
	}
	return row, nil
}

func TestResolveHostFilter_EmptyInputPassesThrough(t *testing.T) {
	t.Parallel()
	got, err := resolveHostFilter(context.Background(), &fakeHostLookup{}, "")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != "" {
		t.Errorf("empty input got %q, want empty", got)
	}
}

func TestResolveHostFilter_UUIDPassesThrough(t *testing.T) {
	t.Parallel()
	const id = "550e8400-e29b-41d4-a716-446655440000"
	store := &fakeHostLookup{} // GetHostByName must NOT be called
	got, err := resolveHostFilter(context.Background(), store, id)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != id {
		t.Errorf("UUID input got %q, want %q", got, id)
	}
}

func TestResolveHostFilter_HostnameResolves(t *testing.T) {
	t.Parallel()
	const id = "11111111-2222-3333-4444-555555555555"
	store := &fakeHostLookup{byName: map[string]pg.HostRow{
		"ip-172-31-26-27": {ID: id, Hostname: "ip-172-31-26-27"},
	}}
	got, err := resolveHostFilter(context.Background(), store, "ip-172-31-26-27")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != id {
		t.Errorf("hostname → got %q, want %q", got, id)
	}
}

func TestResolveHostFilter_NotFoundSurfaces(t *testing.T) {
	t.Parallel()
	store := &fakeHostLookup{byName: map[string]pg.HostRow{}}
	_, err := resolveHostFilter(context.Background(), store, "nope")
	if !errors.Is(err, pg.ErrHostNotFound) {
		t.Errorf("err = %v, want ErrHostNotFound", err)
	}
}

func TestResolveHostFilter_PropagatesOtherErrors(t *testing.T) {
	t.Parallel()
	custom := errors.New("pg dead")
	store := &fakeHostLookup{err: custom}
	_, err := resolveHostFilter(context.Background(), store, "anyname")
	if !errors.Is(err, custom) {
		t.Errorf("err = %v, want %v", err, custom)
	}
}
