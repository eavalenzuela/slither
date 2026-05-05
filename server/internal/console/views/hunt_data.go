package views

import (
	"time"

	"github.com/t3rmit3/slither/server/internal/store/pg"
)

// HuntListData drives the /hunt page.
type HuntListData struct {
	Hunts  []pg.HuntRow
	CanRun bool   // analyst+admin
	Flash  string // post-redirect message
	Error  string // form-error display
	Form   HuntForm
	// RawQuery is r.URL.RawQuery for the Phase 6 #115 "Save filter"
	// partial. /hunt has no list filter today; the field is plumbed
	// for symmetry with /events + /alerts so the partial can render
	// consistently.
	RawQuery string
}

// HuntForm holds the dispatch form state. Empty in normal renders;
// re-populated on validation error so the operator sees their input
// preserved.
type HuntForm struct {
	Query          string
	HostFilter     string
	TimeoutSecs    int
	MaxRowsPerHost int
}

// HuntDetailRow is one row returned for the detail page (host + cols/vals).
type HuntDetailRow struct {
	HostID     string
	HostName   string
	ObservedAt time.Time
	Columns    []string
	Values     []string
}

// HuntDetailData drives /hunt/{id}.
type HuntDetailData struct {
	Hunt          pg.HuntRow
	Rows          []HuntDetailRow
	PerHostCount  map[string]uint64
	HostnamesByID map[string]string
	Limit         int
	Offset        int
	HasNextPage   bool
}
