package views

import "github.com/t3rmit3/slither/server/internal/store/pg"

// SavedQueriesData drives /queries — the user's saved-query list.
// Phase 6 #115.
type SavedQueriesData struct {
	Queries []pg.SavedQuery
	Flash   string
}

// DashboardsListData drives /dashboards — the user's dashboard
// inventory page.
type DashboardsListData struct {
	Dashboards []pg.Dashboard
	Flash      string
}

// DashboardCardResolved is one card after the handler resolved its
// QueryID into the saved-query row (or determined the row was
// deleted). The templ renders a "(query deleted)" placeholder when
// Deleted is true.
type DashboardCardResolved struct {
	QueryID string
	Label   string
	URL     string
	Query   pg.SavedQuery
	Deleted bool
}

// DashboardDetailData drives /dashboards/{id}. AvailableSQs is the
// "add card" picker's source list (the user's other saved queries).
type DashboardDetailData struct {
	Dashboard    pg.Dashboard
	Cards        []DashboardCardResolved
	AvailableSQs []pg.SavedQuery
	Flash        string
}
