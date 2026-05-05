// Phase 6 #120 — POST/GET /api/v1/events/search.
//
// The handler accepts the eyeexam-spec request body (POST) or the
// equivalent query-string form (GET), normalises into a single
// ch.EventFilter + ch.Cursor, fetches one page from CH, attaches
// the per-row hostname (resolved once via pg.GetHost / GetHostByName),
// and returns the canonical {hits, next_cursor} body.
//
// The handler is intentionally thin — every field validation +
// pagination shape lives in the helpers below so the wire-shape
// change-surface is small.

package v1

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/t3rmit3/slither/server/internal/store/ch"
	"github.com/t3rmit3/slither/server/internal/store/pg"
)

// eventsSearchRequest mirrors the eyeexam contract body.
type eventsSearchRequest struct {
	HostID    string   `json:"host_id,omitempty"`
	HostName  string   `json:"host_name,omitempty"`
	SigmaID   string   `json:"sigma_id,omitempty"`
	RuleUID   string   `json:"rule_uid,omitempty"`
	Tag       string   `json:"tag,omitempty"`
	ClassUIDs []uint32 `json:"class_uids,omitempty"`
	Severity  uint8    `json:"severity_id,omitempty"`
	Since     string   `json:"since,omitempty"`  // RFC3339
	Until     string   `json:"until,omitempty"`  // RFC3339
	Cursor    string   `json:"cursor,omitempty"` // opaque
	Limit     int      `json:"limit,omitempty"`
}

// eventsSearchResponse is the wire shape the API returns. NextCursor
// is empty when the result set ended on this page.
type eventsSearchResponse struct {
	Hits       []eventHit `json:"hits"`
	NextCursor string     `json:"next_cursor,omitempty"`
}

// eventHit is one row in the response. raw is the canonical OCSF
// JSON for the event — not a class-specific projection — so the
// consumer doesn't have to round-trip through the detail endpoint.
type eventHit struct {
	ID         string          `json:"id"`
	HostID     string          `json:"host_id"`
	HostName   string          `json:"host_name,omitempty"`
	ClassUID   uint32          `json:"class_uid"`
	SeverityID uint8           `json:"severity_id"`
	ObservedAt time.Time       `json:"observed_at"`
	RuleUID    string          `json:"rule_uid,omitempty"`
	RuleName   string          `json:"rule_name,omitempty"`
	Raw        json.RawMessage `json:"raw,omitempty"`
}

// eventsSearch routes both POST (JSON body) and GET (query string).
// Phase 6 #120.
func (s *Server) eventsSearch(w http.ResponseWriter, r *http.Request) {
	if s.ch == nil {
		writeError(w, http.StatusServiceUnavailable,
			"ch_unavailable", "ClickHouse store not wired")
		return
	}
	req, err := parseEventsSearchRequest(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}

	hostID := strings.TrimSpace(req.HostID)
	if hostID == "" && strings.TrimSpace(req.HostName) != "" {
		row, gerr := s.pg.GetHostByName(r.Context(), strings.TrimSpace(req.HostName))
		if errors.Is(gerr, pg.ErrHostNotFound) {
			// Empty result rather than 404 — host_name not resolving
			// is a valid filter outcome; the consumer infers "no
			// events for that name" from the empty hits array.
			writeJSON(w, http.StatusOK, eventsSearchResponse{Hits: []eventHit{}})
			return
		}
		if gerr != nil {
			writeError(w, http.StatusInternalServerError,
				"internal_error", "host lookup failed")
			return
		}
		hostID = row.ID
	}

	ruleUID := req.RuleUID
	if ruleUID == "" {
		ruleUID = req.SigmaID // sigma_id is an alias the eyeexam spec accepts
	}

	filter := ch.EventFilter{
		HostID:     hostID,
		RuleUID:    ruleUID,
		Tag:        strings.TrimSpace(req.Tag),
		ClassUIDs:  req.ClassUIDs,
		SeverityID: req.Severity,
	}
	if req.Since != "" {
		t, perr := time.Parse(time.RFC3339Nano, req.Since)
		if perr != nil {
			writeError(w, http.StatusBadRequest, "bad_since", perr.Error())
			return
		}
		filter.Since = t.UTC()
	}
	if req.Until != "" {
		t, perr := time.Parse(time.RFC3339Nano, req.Until)
		if perr != nil {
			writeError(w, http.StatusBadRequest, "bad_until", perr.Error())
			return
		}
		filter.Until = t.UTC()
	}

	cursor, perr := ch.ParseCursor(req.Cursor)
	if perr != nil {
		writeError(w, http.StatusBadRequest, "bad_cursor", perr.Error())
		return
	}

	limit := req.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}

	rows, next, serr := s.ch.SearchEvents(r.Context(), filter, cursor, limit)
	if serr != nil {
		writeError(w, http.StatusInternalServerError,
			"internal_error", "ch search failed")
		return
	}

	hostNameByID := map[string]string{}
	hits := make([]eventHit, 0, len(rows))
	for _, row := range rows {
		hit := eventHit{
			ID:         row.EventID,
			HostID:     row.HostID,
			ClassUID:   row.ClassUID,
			SeverityID: row.SeverityID,
			ObservedAt: row.ObservedAt,
		}
		if name, ok := hostNameByID[row.HostID]; ok {
			hit.HostName = name
		} else if h, herr := s.pg.GetHost(r.Context(), row.HostID); herr == nil {
			hostNameByID[row.HostID] = h.Hostname
			hit.HostName = h.Hostname
		} else {
			hostNameByID[row.HostID] = ""
		}
		// raw + rule_uid + rule_name come from the per-class detail
		// endpoint. Phase 6 ships the row-level summary; consumers
		// wanting the raw OCSF go through GetEventByID.
		if detail, derr := s.ch.GetEventByID(r.Context(), row.ClassUID, row.EventID); derr == nil {
			hit.Raw = detail.Raw
			// EventRow's RuleUID/RuleName carry through from the
			// detection_finding projection but not the search row;
			// fold from raw when the class is 2004.
			if row.ClassUID == 2004 {
				var trans struct {
					RuleInfo struct {
						UID  string `json:"uid"`
						Name string `json:"name"`
					} `json:"rule"`
				}
				if uerr := json.Unmarshal(detail.Raw, &trans); uerr == nil {
					hit.RuleUID = trans.RuleInfo.UID
					hit.RuleName = trans.RuleInfo.Name
				}
			}
		}
		hits = append(hits, hit)
	}

	writeJSON(w, http.StatusOK, eventsSearchResponse{
		Hits:       hits,
		NextCursor: next.String(),
	})
}

// parseEventsSearchRequest accepts the body or the query string,
// returning the canonical request shape.
func parseEventsSearchRequest(r *http.Request) (eventsSearchRequest, error) {
	if r.Method == http.MethodPost {
		var req eventsSearchRequest
		r.Body = http.MaxBytesReader(nil, r.Body, 64*1024)
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return eventsSearchRequest{}, err
		}
		return req, nil
	}
	q := r.URL.Query()
	req := eventsSearchRequest{
		HostID:   strings.TrimSpace(q.Get("host_id")),
		HostName: strings.TrimSpace(q.Get("host_name")),
		SigmaID:  strings.TrimSpace(q.Get("sigma_id")),
		RuleUID:  strings.TrimSpace(q.Get("rule_uid")),
		Tag:      strings.TrimSpace(q.Get("tag")),
		Since:    strings.TrimSpace(q.Get("since")),
		Until:    strings.TrimSpace(q.Get("until")),
		Cursor:   strings.TrimSpace(q.Get("cursor")),
	}
	if v := strings.TrimSpace(q.Get("severity_id")); v != "" {
		n, err := strconv.ParseUint(v, 10, 8)
		if err != nil {
			return eventsSearchRequest{}, err
		}
		req.Severity = uint8(n)
	}
	if v := strings.TrimSpace(q.Get("limit")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return eventsSearchRequest{}, err
		}
		req.Limit = n
	}
	for _, v := range q["class_uid"] {
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return eventsSearchRequest{}, err
		}
		req.ClassUIDs = append(req.ClassUIDs, uint32(n))
	}
	return req, nil
}
