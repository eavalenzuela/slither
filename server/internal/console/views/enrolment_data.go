package views

import (
	"time"

	"github.com/t3rmit3/slither/server/internal/store/pg"
)

// EnrolmentTokensPageData drives /enrolment-tokens. JustMinted is
// the plaintext token shown exactly once on the redirect after a
// successful POST /enrolment-tokens (carried via the scs flash
// store). Empty on every page after the first.
type EnrolmentTokensPageData struct {
	Tokens         []pg.EnrollmentTokenRow
	JustMinted     string // plaintext, displayed once
	JustMintedHint string // hostname_hint that was attached
	DefaultServer  string // for the copy-paste enroll command
	Now            time.Time
}

// TokenStatus is the operator-visible state derived from used_at +
// expires_at.
type TokenStatus string

const (
	TokenStatusActive  TokenStatus = "active"
	TokenStatusUsed    TokenStatus = "used"
	TokenStatusExpired TokenStatus = "expired"
)

// Status returns the current state of a token row given the current
// wallclock. Used trumps expired (a token used right before expiry
// is functionally consumed; the audit row still tells the full story).
func TokenRowStatus(d EnrolmentTokensPageData, r pg.EnrollmentTokenRow) TokenStatus {
	if r.UsedAt != nil {
		return TokenStatusUsed
	}
	if !r.ExpiresAt.IsZero() && d.Now.After(r.ExpiresAt) {
		return TokenStatusExpired
	}
	return TokenStatusActive
}

// FormatTimestamp shares the events page's RFC3339 rendering. Kept
// local to this file so adding more time-shaped columns in #45's
// follow-ups doesn't ping every page.
func FormatTimestamp(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.UTC().Format(time.RFC3339)
}

// FormatOptionalTimestamp is FormatTimestamp for a *time.Time.
func FormatOptionalTimestamp(t *time.Time) string {
	if t == nil {
		return "—"
	}
	return FormatTimestamp(*t)
}
