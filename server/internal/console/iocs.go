package console

import (
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/t3rmit3/slither/server/internal/console/views"
	"github.com/t3rmit3/slither/server/internal/store/pg"
)

// iocsList renders /iocs — admin-only landing page that lists every
// configured feed, links to a create form, and offers a delete action.
func (s *Server) iocsList(w http.ResponseWriter, r *http.Request) {
	feeds, err := s.store.ListIOCFeeds(r.Context())
	if err != nil {
		http.Error(w, "list ioc feeds failed", http.StatusInternalServerError)
		return
	}
	flash, _ := s.sm.Pop(r.Context(), "flash").(string)
	render(w, r, views.IOCsList(views.IOCsListData{
		Feeds: feeds,
		Flash: flash,
	}))
}

// iocsNew renders the create form. Separate page rather than inline on
// the list because pasting 100k entries needs a textarea-with-scroll
// not a modal.
func (s *Server) iocsNew(w http.ResponseWriter, r *http.Request) {
	render(w, r, views.IOCsForm(views.IOCsFormData{}))
}

// iocsCreate handles POST /iocs/new. On success redirects to /iocs
// with a flash. On validation failure re-renders the form preserving
// the operator's input + an error string.
func (s *Server) iocsCreate(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 16*1024*1024) // 100k SHA-256 ≈ 6.4 MB; allow headroom
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}

	feedID := strings.TrimSpace(r.PostFormValue("feed_id"))
	name := strings.TrimSpace(r.PostFormValue("name"))
	kind := pg.IOCKind(strings.TrimSpace(r.PostFormValue("kind")))
	entriesRaw := r.PostFormValue("entries")
	entries := splitEntries(entriesRaw)

	form := views.IOCsFormData{
		FeedID:     feedID,
		Name:       name,
		Kind:       kind,
		EntriesRaw: entriesRaw,
	}

	if feedID == "" || name == "" || kind == "" {
		form.Error = "feed_id, name, and kind are required."
		render(w, r, views.IOCsForm(form))
		return
	}

	feed, err := s.store.InsertIOCFeed(r.Context(), pg.IOCFeedInsert{
		FeedID:  feedID,
		Name:    name,
		Kind:    kind,
		Entries: entries,
		ActorID: s.userID(r),
	})
	switch {
	case errors.Is(err, pg.ErrIOCFeedTooLarge):
		form.Error = "Feed exceeds the 100,000-entry limit; split into multiple feeds."
		render(w, r, views.IOCsForm(form))
		return
	case err != nil:
		form.Error = err.Error()
		render(w, r, views.IOCsForm(form))
		return
	}

	_ = s.store.LogAudit(r.Context(), pg.AuditEntry{
		ActorType:  pg.ActorUser,
		ActorID:    s.userID(r),
		Action:     "ioc.feed.create",
		TargetKind: "ioc_feed",
		TargetID:   feed.FeedID,
		Detail: map[string]any{
			"kind":        feed.Kind,
			"entry_count": feed.EntryCount,
		},
	})
	s.sm.Put(r.Context(), "flash", "Feed "+feed.FeedID+" created with "+itoa(feed.EntryCount)+" entries.")
	http.Redirect(w, r, "/iocs", http.StatusSeeOther)
}

// iocsDelete handles POST /iocs/{feed_id}/delete.
func (s *Server) iocsDelete(w http.ResponseWriter, r *http.Request) {
	feedID := chi.URLParam(r, "feed_id")
	if feedID == "" {
		http.Error(w, "missing feed_id", http.StatusBadRequest)
		return
	}
	switch err := s.store.DeleteIOCFeed(r.Context(), feedID); {
	case errors.Is(err, pg.ErrIOCFeedNotFound):
		http.NotFound(w, r)
		return
	case err != nil:
		http.Error(w, "delete failed", http.StatusInternalServerError)
		return
	}
	_ = s.store.LogAudit(r.Context(), pg.AuditEntry{
		ActorType:  pg.ActorUser,
		ActorID:    s.userID(r),
		Action:     "ioc.feed.delete",
		TargetKind: "ioc_feed",
		TargetID:   feedID,
	})
	s.sm.Put(r.Context(), "flash", "Feed "+feedID+" deleted.")
	http.Redirect(w, r, "/iocs", http.StatusSeeOther)
}

// splitEntries breaks a textarea blob into one entry per non-empty
// line. Whitespace is trimmed; blank lines and `# …` comment lines
// drop. Operators paste curated feeds — keep the parser permissive.
func splitEntries(raw string) []string {
	if raw == "" {
		return nil
	}
	lines := strings.Split(raw, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		v := strings.TrimSpace(line)
		if v == "" || strings.HasPrefix(v, "#") {
			continue
		}
		out = append(out, v)
	}
	return out
}

// itoa wraps strconv.Itoa for one call site that doesn't justify the
// import alongside strings + errors.
func itoa(n int) string {
	const digits = "0123456789"
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = digits[n%10]
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
