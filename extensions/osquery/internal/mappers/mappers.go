// Package mappers maps osquery rows into OCSF events. Each curated
// table has its own file (process_events.go, socket_events.go, etc.)
// with a Map function that converts one Row → one ocsf.Event.
//
// Mappers do NOT stamp device.uid, time, or metadata.product.name —
// the agent's extension supervisor stamps those after receiving the
// event over the wire (see agent/internal/extensions/process.go's
// stampAndDecode). What the mapper produces is the per-event payload:
// activity_id, actor.process, file/network/kernel-specific fields,
// severity_id.
//
// Empty / unparseable string fields fall through to zero values rather
// than producing errors — osquery's typing is loose and per-row
// validation belongs in the rule engine, not here.
package mappers

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/t3rmit3/slither/pkg/ocsf"
)

// Row mirrors bridge.Row to avoid an import cycle. Same shape:
// column → string value.
type Row map[string]string

// Mapper converts one osquery row into one OCSF event. Implementations
// return nil + nil when the row should be silently skipped (e.g. an
// unsupported action_id whose mapping is undefined). Errors signal a
// genuinely malformed row — the bridge logs and continues.
type Mapper func(Row) (ocsf.Event, error)

func atoiU32(s string) uint32 {
	if s == "" {
		return 0
	}
	n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 32)
	if err != nil {
		return 0
	}
	return uint32(n)
}

func atoiU16(s string) uint16 {
	if s == "" {
		return 0
	}
	n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 16)
	if err != nil {
		return 0
	}
	return uint16(n)
}

func atoiU64(s string) uint64 {
	if s == "" {
		return 0
	}
	n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0
	}
	return n
}

// requireField returns a friendly error when a required column is
// empty. Used by mappers whose OCSF target has hard validation.
func requireField(name, value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("osquery row missing required field %q", name)
	}
	return nil
}
