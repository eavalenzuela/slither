// Package bridge wires the slither agent's extension supervisor to a
// running osqueryd. It owns the post-FD-3 wire (length-delimited
// protobuf via pkg/extsdk), dispatches per-table polling against the
// osquery extension socket, and forwards results as OCSF events back
// up to the agent.
//
// Phase 6 #109. ADR-0028 records the integration shape: not bundled,
// operator-installed osqueryd, optional per host.
package bridge

import (
	"context"
	"errors"
)

// Row is one osquery result row — column → value, both strings since
// osquery's JSON output preserves all values as strings regardless of
// the underlying SQL type. Mappers parse numeric fields per-call.
type Row map[string]string

// Client is the contract the bridge uses to talk to osqueryd. The v1
// shipped implementation is OsqueryiClient (subprocess invocation of
// `osqueryi --connect <socket> --json "<sql>"`). A persistent Thrift
// implementation may replace it in a future task; the interface is
// deliberately small enough that swap is painless.
type Client interface {
	// QueryRows runs sql against osqueryd and returns rows in column-
	// preserving order. Empty result sets return an empty slice + nil
	// err; transient transport errors should bubble up so the bridge's
	// poll loop can record + retry.
	QueryRows(ctx context.Context, sql string) ([]Row, error)
	// Close releases any client-held resources. Idempotent.
	Close() error
}

// ErrClientUnavailable signals osqueryd was not reachable on this poll
// cycle. The bridge logs + skips the cycle rather than tearing down —
// osqueryd may be transiently down during package upgrades or systemd
// restarts and the agent supervisor's restart-with-backoff would
// over-react.
var ErrClientUnavailable = errors.New("osquery: client unavailable")
