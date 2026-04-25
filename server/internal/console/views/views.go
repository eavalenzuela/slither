// Package views holds the templ-rendered HTML for the operator console.
//
// Phase 2 §4.1 task #41 ships the layout shell, login form, and a
// dashboard placeholder. Pages added by #42–#44 share the same Layout
// component so the sidebar / styling stays consistent.
package views

import "github.com/t3rmit3/slither/server/internal/store/pg"

// LoginData drives the login form template.
type LoginData struct {
	Flash string // optional one-shot error message popped from the session
}

// DashboardData is the post-login landing page payload. Future page
// data structs live in this package alongside their templ.
type DashboardData struct {
	Username string
	Role     pg.UserRole
}
