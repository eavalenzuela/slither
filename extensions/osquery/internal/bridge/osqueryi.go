package bridge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// OsqueryiClient runs `osqueryi --connect <socket> --json <sql>` per
// query. Subprocess overhead is real (~50ms/call on a warm host) but
// keeps the extension binary thrift-free; persistent-connection
// thrift is a future task.
//
// When SocketPath is non-empty we pass --connect, which makes osqueryi
// share the running daemon's subscriber state — events tables
// (process_events, socket_events, file_events) only return rows under
// this mode. Empty SocketPath drops back to standalone mode (suitable
// for inventory tables but events tables stay empty).
type OsqueryiClient struct {
	// BinaryPath is the path to osqueryi. Defaults to "osqueryi" on $PATH.
	BinaryPath string
	// SocketPath is the osqueryd extension socket. Defaults to
	// "/var/osquery/osquery.em" — osquery's standard install location.
	SocketPath string

	// runCmd is overridable for tests; production calls exec.CommandContext.
	runCmd func(ctx context.Context, name string, args ...string) ([]byte, error)
}

// NewOsqueryiClient returns a client with sensible defaults.
func NewOsqueryiClient(binaryPath, socketPath string) *OsqueryiClient {
	if binaryPath == "" {
		binaryPath = "osqueryi"
	}
	if socketPath == "" {
		socketPath = "/var/osquery/osquery.em"
	}
	return &OsqueryiClient{
		BinaryPath: binaryPath,
		SocketPath: socketPath,
		runCmd:     defaultRunCmd,
	}
}

func defaultRunCmd(ctx context.Context, name string, args ...string) ([]byte, error) {
	// G204: name + args come from operator-supplied config (osqueryi
	// path + the bridge's own SQL strings). The bridge is the security
	// boundary owner here — operators who control agent.yaml already
	// have arbitrary-binary execution; this exec is the contract.
	cmd := exec.CommandContext(ctx, name, args...) // #nosec G204
	var out, errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		// exec error after a successful start: stderr carries the
		// useful message (e.g. "Error connecting to socket: ...").
		stderr := strings.TrimSpace(errBuf.String())
		if stderr != "" {
			return nil, fmt.Errorf("osqueryi: %s: %w", stderr, err)
		}
		return nil, fmt.Errorf("osqueryi: %w", err)
	}
	return out.Bytes(), nil
}

// QueryRows shells out to osqueryi and parses its JSON response. osqueryi
// writes a JSON array of objects on stdout when --json is set; an
// empty result set is `[]`.
func (c *OsqueryiClient) QueryRows(ctx context.Context, sql string) ([]Row, error) {
	if sql == "" {
		return nil, errors.New("osquery: empty sql")
	}
	if c.runCmd == nil {
		c.runCmd = defaultRunCmd
	}
	args := []string{"--json"}
	if c.SocketPath != "" {
		args = append(args, "--connect", c.SocketPath)
	}
	args = append(args, sql)

	out, err := c.runCmd(ctx, c.BinaryPath, args...)
	if err != nil {
		// Distinguish "binary missing" from "daemon unreachable" so the
		// bridge can skip-and-retry rather than crash-loop. exec.Error
		// types both surface as the underlying error chain.
		var execErr *exec.Error
		if errors.As(err, &execErr) {
			return nil, fmt.Errorf("%w: %v", ErrClientUnavailable, err)
		}
		// Daemon-unreachable errors come back via stderr embedded in the
		// wrapped run error; treat any non-binary-missing error as
		// transient and let the caller decide.
		return nil, err
	}
	out = bytes.TrimSpace(out)
	if len(out) == 0 {
		return nil, nil
	}
	var raw []map[string]string
	if err := json.Unmarshal(out, &raw); err != nil {
		return nil, fmt.Errorf("osquery: parse json: %w", err)
	}
	rows := make([]Row, len(raw))
	for i, m := range raw {
		rows[i] = Row(m)
	}
	return rows, nil
}

// Close is a no-op for the subprocess client — there's no persistent
// connection to release.
func (c *OsqueryiClient) Close() error { return nil }
