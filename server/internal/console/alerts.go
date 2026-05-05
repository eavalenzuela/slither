package console

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/t3rmit3/slither/pkg/ruleast"
	"github.com/t3rmit3/slither/server/internal/console/views"
	"github.com/t3rmit3/slither/server/internal/graph"
	"github.com/t3rmit3/slither/server/internal/store/pg"
)

const alertsPageSize = 50

// inputDatetimeLocal is the layout HTML's <input type=datetime-local>
// hands back on form submit. We render via this same layout when
// echoing values into the form so the browser doesn't reset to "now"
// on a refresh.
const inputDatetimeLocal = "2006-01-02T15:04"

// alertsList renders /alerts. Filters: status, severity, host_id,
// rule_uid, assigned_to (or "unassigned"), since/until time range.
// Cursor pagination via after_at + after_id.
func (s *Server) alertsList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	statusFilter := pg.AlertStatus(strings.TrimSpace(q.Get("status")))
	hostIDFilter := strings.TrimSpace(q.Get("host_id"))
	ruleUIDFilter := strings.TrimSpace(q.Get("rule_uid"))
	assigneeFilter := strings.TrimSpace(q.Get("assigned_to"))

	var severityFilter uint8
	if s := strings.TrimSpace(q.Get("severity")); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > 6 {
			http.Error(w, "bad severity", http.StatusBadRequest)
			return
		}
		severityFilter = uint8(n)
	}

	since, sinceStr, err := parseDatetimeLocal(q.Get("since"))
	if err != nil {
		http.Error(w, "bad since", http.StatusBadRequest)
		return
	}
	until, untilStr, err := parseDatetimeLocal(q.Get("until"))
	if err != nil {
		http.Error(w, "bad until", http.StatusBadRequest)
		return
	}

	filter := pg.AlertFilter{
		HostID:     hostIDFilter,
		RuleUID:    ruleUIDFilter,
		SeverityID: severityFilter,
		AssignedTo: assigneeFilter,
		Since:      since,
		Until:      until,
	}
	if statusFilter != "" {
		filter.Statuses = []pg.AlertStatus{statusFilter}
	}

	cursor := pg.AlertCursor{}
	if id := q.Get("after_id"); id != "" {
		if t, parseErr := time.Parse(views.AlertsCursorLayout(), q.Get("after_at")); parseErr == nil {
			cursor.CreatedAt = t
			cursor.AlertID = id
		}
	}

	alerts, next, err := s.store.ListAlerts(r.Context(), filter, cursor, alertsPageSize)
	if err != nil {
		http.Error(w, "list alerts failed", http.StatusInternalServerError)
		return
	}

	flash, _ := s.sm.Pop(r.Context(), "flash").(string)
	role := s.role(r)
	viewFilters := views.AlertsListFilters{
		Status:     statusFilter,
		HostID:     hostIDFilter,
		RuleUID:    ruleUIDFilter,
		SeverityID: severityFilter,
		AssignedTo: assigneeFilter,
		Since:      sinceStr,
		Until:      untilStr,
	}
	render(w, r, views.AlertsList(views.AlertsListData{
		Alerts:         alerts,
		Now:            time.Now().UTC(),
		StatusFilter:   statusFilter,
		HostIDFilter:   hostIDFilter,
		RuleUIDFilter:  ruleUIDFilter,
		SeverityFilter: severityFilter,
		AssigneeFilter: assigneeFilter,
		SinceFilter:    sinceStr,
		UntilFilter:    untilStr,
		NextCursorURL:  nextCursorURL(viewFilters, next),
		Flash:          flash,
		IsAnalyst:      role == pg.RoleAnalyst || role == pg.RoleAdmin,
	}))
}

// alertDetail renders /alerts/{id}. 404s on missing rows; 400 on a
// non-UUID id so a typo doesn't reach the DB.
func (s *Server) alertDetail(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	row, err := s.store.GetAlert(r.Context(), id)
	switch {
	case errors.Is(err, pg.ErrAlertNotFound):
		http.NotFound(w, r)
		return
	case err != nil:
		http.Error(w, "load alert failed", http.StatusInternalServerError)
		return
	}

	flash, _ := s.sm.Pop(r.Context(), "flash").(string)
	role := s.role(r)

	// HostPolicy gates the response action buttons. Failure here is
	// non-fatal — render the page without the response block rather
	// than 500 the operator out of seeing the alert detail.
	policy, perr := s.store.GetHostPolicy(r.Context(), row.HostID)
	if perr != nil {
		policy = pg.HostPolicy{HostID: row.HostID}
	}
	// Same posture for action history: best-effort.
	history, herr := s.store.ListResponseActions(r.Context(), row.HostID, 25)
	if herr != nil {
		history = nil
	}

	// Phase 6 #111: enumerate per-extension snapshot blobs that
	// dispatcher persistSnapshotArtefact wrote under
	// <artefactDir>/<alert_id>/*.tgz, plus surface the
	// "(no snapshot extensions configured)" hint when the alert's
	// rule asked for a snapshot but no extension delivered one.
	snapshots, snapshotRequested := s.loadSnapshotInventory(r.Context(), row.ID, row.RuleUID)

	render(w, r, views.AlertDetail(views.AlertDetailData{
		Alert:                   row,
		AllowedNext:             allowedNextStatuses(row.Status),
		IsAnalyst:               role == pg.RoleAnalyst || role == pg.RoleAdmin,
		IsAdmin:                 role == pg.RoleAdmin,
		Flash:                   flash,
		ShowGraph:               s.graphBuilder != nil && len(row.EventIDs) > 0,
		HostPolicy:              policy,
		ResponseHistory:         history,
		Snapshots:               snapshots,
		SnapshotRequested:       snapshotRequested,
		ShowProcessTreeExplorer: s.processTreeJSON != nil && len(row.EventIDs) > 0,
	}))
}

// loadSnapshotInventory lists per-extension snapshot blobs the
// dispatcher landed under <artefactDir>/<alertID>/*.tgz and
// independently checks whether the alert's rule declares
// `slither.snapshot: true`. The two pieces drive the alert-detail
// page's snapshot block:
//
//   - len(snapshots) > 0 → list them with download links.
//   - snapshotRequested && len(snapshots) == 0 → render the
//     "(no snapshot extensions configured)" no-op note.
//   - !snapshotRequested && len(snapshots) == 0 → omit the block
//     entirely.
//
// Best-effort: a missing rule row, a YAML parse failure, or a stat()
// error all degrade to "no snapshot UX" rather than 500'ing the page.
func (s *Server) loadSnapshotInventory(ctx context.Context, alertID, ruleUID string) ([]views.AlertSnapshot, bool) {
	requested := false
	if ruleUID != "" {
		rule, err := s.store.GetRuleByUID(ctx, ruleUID)
		if err == nil {
			art, plan, _, cerr := ruleast.Compile([]byte(rule.SourceYAML))
			if cerr == nil {
				if art != nil && art.Snapshot {
					requested = true
				}
				if plan != nil && plan.Snapshot {
					requested = true
				}
			}
		}
	}
	var out []views.AlertSnapshot
	if s.artefactDir != "" && alertID != "" {
		dir := filepath.Join(s.artefactDir, alertID)
		entries, err := os.ReadDir(dir)
		if err == nil {
			for _, e := range entries {
				if e.IsDir() || !strings.HasSuffix(e.Name(), ".tgz") {
					continue
				}
				info, ierr := e.Info()
				if ierr != nil {
					continue
				}
				out = append(out, views.AlertSnapshot{
					Extension: strings.TrimSuffix(e.Name(), ".tgz"),
					SizeBytes: info.Size(),
					ModTime:   info.ModTime().UTC(),
				})
			}
			sort.Slice(out, func(i, j int) bool { return out[i].Extension < out[j].Extension })
		}
	}
	return out, requested
}

// alertProcessTreeJSON serves Phase 6 #114's live process-tree
// explorer payload. Inputs (query string): root_pid (required, > 0;
// defaults to the alert's first triggering event's actor PID when
// omitted), depth (optional, 1..8, default 4). 404s on missing alert
// or when no PID can be derived; the page UX falls back to the
// SSR mini-graph in that case.
func (s *Server) alertProcessTreeJSON(w http.ResponseWriter, r *http.Request) {
	if s.processTreeJSON == nil {
		http.NotFound(w, r)
		return
	}
	id := chi.URLParam(r, "id")
	if id == "" {
		http.Error(w, "missing alert id", http.StatusBadRequest)
		return
	}
	row, err := s.store.GetAlert(r.Context(), id)
	switch {
	case errors.Is(err, pg.ErrAlertNotFound):
		http.NotFound(w, r)
		return
	case err != nil:
		http.Error(w, "load alert failed", http.StatusInternalServerError)
		return
	}

	q := r.URL.Query()
	depth := 4
	if d := strings.TrimSpace(q.Get("depth")); d != "" {
		v, perr := strconv.Atoi(d)
		if perr != nil || v < 1 || v > 8 {
			http.Error(w, "bad depth", http.StatusBadRequest)
			return
		}
		depth = v
	}

	var rootPID uint32
	if p := strings.TrimSpace(q.Get("root_pid")); p != "" {
		v, perr := strconv.ParseUint(p, 10, 32)
		if perr != nil || v == 0 {
			http.Error(w, "bad root_pid", http.StatusBadRequest)
			return
		}
		rootPID = uint32(v)
	} else {
		// Default root: the alert's first triggering event's actor PID.
		// GetEventNode walks every class table; process events expose
		// PID directly, file/net via ActorPID.
		if len(row.EventIDs) == 0 {
			http.Error(w, "alert has no triggering events; supply root_pid", http.StatusBadRequest)
			return
		}
		ev, lerr := s.chStore.GetEventNode(r.Context(), row.EventIDs[0])
		if lerr != nil {
			http.Error(w, "no triggering pid in CH; supply root_pid", http.StatusBadRequest)
			return
		}
		switch {
		case ev.PID != 0:
			rootPID = ev.PID
		case ev.ActorPID != 0:
			rootPID = ev.ActorPID
		default:
			http.Error(w, "no triggering pid in CH; supply root_pid", http.StatusBadRequest)
			return
		}
	}

	tree, berr := s.processTreeJSON.Build(r.Context(), row.HostID, rootPID, depth, time.Time{})
	if berr != nil {
		http.Error(w, "build process tree failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if encErr := json.NewEncoder(w).Encode(tree); encErr != nil {
		// Header is already flushed in most cases; logging is the only
		// useful action.
		_ = encErr
	}
}

// alertSnapshotDownload serves <artefactDir>/<alert_id>/<extension>.tgz
// as application/gzip. 404s on missing files OR when either path
// component fails the safe-name check (defence against
// directory-traversal in the URL). Phase 6 #111.
func (s *Server) alertSnapshotDownload(w http.ResponseWriter, r *http.Request) {
	if s.artefactDir == "" {
		http.NotFound(w, r)
		return
	}
	id := chi.URLParam(r, "id")
	ext := chi.URLParam(r, "extension")
	if !safeAlertPathComponent(id) || !safeAlertPathComponent(ext) {
		http.NotFound(w, r)
		return
	}
	path := filepath.Join(s.artefactDir, id, ext+".tgz")
	// #nosec G304,G703 -- id and ext are validated by
	// safeAlertPathComponent above; the path is rooted in
	// s.artefactDir.
	f, err := os.Open(path)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || info.IsDir() {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="%s-%s.tgz"`, id, ext))
	http.ServeContent(w, r, ext+".tgz", info.ModTime(), f)
}

// safeAlertPathComponent rejects empty strings, traversal shapes, and
// any character outside [A-Za-z0-9._-] so a crafted URL can't escape
// artefactDir.
func safeAlertPathComponent(s string) bool {
	if s == "" || s == "." || s == ".." {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '-', r == '_', r == '.':
			continue
		default:
			return false
		}
	}
	return true
}

// alertGraph renders the detection flow graph for one alert as SVG.
// The SVG is cached on disk + in memory keyed on (alert_id,
// hash(event_ids)) so refreshing the detail page is a cheap read.
//
// Cache misses do the full DAG walk (CH lookups + D2 render). Builds
// that exceed the alert's frozen event_ids invalidate naturally
// because the cache key changes.
func (s *Server) alertGraph(w http.ResponseWriter, r *http.Request) {
	if s.graphBuilder == nil || s.graphCache == nil {
		http.NotFound(w, r)
		return
	}
	id := chi.URLParam(r, "id")
	row, err := s.store.GetAlert(r.Context(), id)
	switch {
	case errors.Is(err, pg.ErrAlertNotFound):
		http.NotFound(w, r)
		return
	case err != nil:
		http.Error(w, "load alert failed", http.StatusInternalServerError)
		return
	}

	if len(row.EventIDs) == 0 {
		http.Error(w, "alert has no events to graph", http.StatusNoContent)
		return
	}

	key := graph.Key(row.ID, row.EventIDs)
	if svg, ok := s.graphCache.Get(key); ok {
		writeSVG(w, svg)
		return
	}

	source, err := s.graphBuilder.Build(r.Context(), row.ID, row.EventIDs)
	if err != nil {
		http.Error(w, fmt.Sprintf("build graph failed: %v", err), http.StatusInternalServerError)
		return
	}
	if source == "" {
		http.Error(w, "no events to graph", http.StatusNoContent)
		return
	}

	svg, err := graph.Render(r.Context(), source)
	if err != nil {
		http.Error(w, fmt.Sprintf("render graph failed: %v", err), http.StatusInternalServerError)
		return
	}
	if err := s.graphCache.Put(key, svg); err != nil {
		// Disk write failed — the SVG still renders this request,
		// but log via the existing audit-log surface so an operator
		// notices a chronically full StateDirectory. Best-effort.
		_ = s.store.LogAudit(r.Context(), pg.AuditEntry{
			ActorType: pg.ActorSystem,
			Action:    "alert.graph.cache_write_failed",
			Detail: map[string]any{
				"alert_id": row.ID,
				"err":      err.Error(),
			},
		})
	}
	writeSVG(w, svg)
}

func writeSVG(w http.ResponseWriter, svg []byte) {
	w.Header().Set("Content-Type", "image/svg+xml; charset=utf-8")
	w.Header().Set("Cache-Control", "private, max-age=60")
	_, _ = w.Write(svg)
}

// alertTransition handles POST /alerts/{id}/transition. The route is
// wrapped in RequireRole(analyst,admin) at registration; this handler
// trusts the role check and focuses on parsing + delegating.
func (s *Server) alertTransition(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	r.Body = http.MaxBytesReader(w, r.Body, 4*1024)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	to := pg.AlertStatus(strings.TrimSpace(r.PostFormValue("to")))
	reason := strings.TrimSpace(r.PostFormValue("reason"))
	if to == "" {
		http.Error(w, "missing target status", http.StatusBadRequest)
		return
	}

	row, err := s.store.TransitionAlert(r.Context(), pg.AlertTransition{
		AlertID: id,
		To:      to,
		Reason:  reason,
		Actor:   s.userID(r),
	})
	switch {
	case errors.Is(err, pg.ErrAlertNotFound):
		http.NotFound(w, r)
		return
	case errors.Is(err, pg.ErrInvalidTransition):
		s.sm.Put(r.Context(), "flash", "Transition not allowed from current state.")
		http.Redirect(w, r, "/alerts/"+id, http.StatusSeeOther)
		return
	case err != nil:
		http.Error(w, "transition failed", http.StatusInternalServerError)
		return
	}

	s.sm.Put(r.Context(), "flash", "Alert transitioned to "+string(row.Status)+".")
	http.Redirect(w, r, "/alerts/"+id, http.StatusSeeOther)
}

// allowedNextStatuses computes the buttons the detail page should
// render given the alert's current status. Order is intent-stable so
// the UI shows ack before close even when both are available.
func allowedNextStatuses(from pg.AlertStatus) []pg.AlertStatus {
	candidates := []pg.AlertStatus{pg.AlertAcknowledged, pg.AlertInProgress, pg.AlertClosed}
	out := make([]pg.AlertStatus, 0, len(candidates))
	for _, c := range candidates {
		if pg.IsValidAlertTransition(from, c) {
			out = append(out, c)
		}
	}
	return out
}

// nextCursorURL builds the next-page URL string the list view links
// to. Empty when no cursor — the template treats that as "last page".
func nextCursorURL(filters views.AlertsListFilters, cursor pg.AlertCursor) string {
	if cursor.AlertID == "" {
		return ""
	}
	return views.AlertsURLWithCursor(filters, cursor)
}

// parseDatetimeLocal accepts an HTML datetime-local field value
// (yyyy-mm-ddThh:mm) and returns the parsed UTC time + the original
// raw string for echo-back. An empty field is the no-op zero-value
// path; a malformed field is a 400 — the caller maps it to a user
// error rather than silently drop the filter.
func parseDatetimeLocal(raw string) (time.Time, string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, "", nil
	}
	t, err := time.Parse(inputDatetimeLocal, raw)
	if err != nil {
		return time.Time{}, "", err
	}
	return t.UTC(), raw, nil
}
