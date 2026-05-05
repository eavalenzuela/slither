// Phase 6 #116(a) — events query language parser.
//
// Tokenises a single text-input search of the form
//
//	host:foo class:1007 severity:4 since:24h until:2026-05-01
//
// into the same ch.EventFilter shape the form-driven /events page
// builds. Unknown bareword tokens (no `key:value` shape) fall through
// into a `raw_contains` substring filter the events search applies
// against the raw OCSF JSON column. v1 stays minimal — boolean
// operators (AND / OR / NOT) and parentheses are explicitly out of
// scope, since /events already supports the conjunctive form via
// repeated tokens.
//
// The parser is unicode-naive — every token is split on ASCII space.
// Quoted strings ("foo bar") are accepted so values with spaces
// (e.g. cmdline:"curl http") round-trip cleanly.

package console

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ParsedQuery is the structured shape the events handler consumes.
// All fields default to zero ("apply no constraint"); the parser
// returns this struct + the tokens it couldn't classify so the
// handler can surface "unknown axis: foo" as a clean form error
// rather than silently dropping the operator's intent.
type ParsedQuery struct {
	HostID      string
	ClassUID    string
	SeverityID  string
	Since       string // RFC3339Nano
	Until       string
	RawContains string

	// Unknown carries the literal token strings the parser could not
	// classify. The events handler surfaces these to the operator
	// rather than silently swallowing them.
	Unknown []string
}

// ToURLValues encodes the parsed query into the same querystring
// shape the existing /events filter form posts. Empty fields are
// elided so the resulting URL stays minimal.
func (p ParsedQuery) ToURLValues() url.Values {
	v := url.Values{}
	if p.HostID != "" {
		v.Set("host_id", p.HostID)
	}
	if p.ClassUID != "" {
		v.Set("class_uid", p.ClassUID)
	}
	if p.SeverityID != "" {
		v.Set("severity_id", p.SeverityID)
	}
	if p.Since != "" {
		v.Set("since", p.Since)
	}
	if p.Until != "" {
		v.Set("until", p.Until)
	}
	if p.RawContains != "" {
		v.Set("raw_contains", p.RawContains)
	}
	return v
}

// ParseEventsQuery parses the operator's free-form input. Returns the
// structured query + nil on success, or a *ParseQueryError naming the
// failing token on a hard parse failure (malformed since:/until:
// duration, unknown axis token shape).
//
// "Soft" failures — bareword tokens with no `key:value` shape — go
// into rawContains rather than aborting; the events search treats
// rawContains as a substring filter. This keeps natural typing
// ("curl etc/passwd") usable without forcing the operator to know
// the canonical axis names.
func ParseEventsQuery(input string) (ParsedQuery, error) {
	tokens, err := tokenizeQuery(input)
	if err != nil {
		return ParsedQuery{}, err
	}
	out := ParsedQuery{}
	var rawParts []string
	now := time.Now().UTC()
	for _, tok := range tokens {
		key, value, ok := splitKeyValue(tok)
		if !ok {
			rawParts = append(rawParts, tok)
			continue
		}
		switch strings.ToLower(key) {
		case "host", "host_id":
			out.HostID = value
		case "class", "class_uid":
			if _, err := strconv.ParseUint(value, 10, 32); err != nil {
				return ParsedQuery{}, &ParseQueryError{Token: tok, Reason: "class must be uint32"}
			}
			out.ClassUID = value
		case "severity", "severity_id":
			n, err := strconv.ParseUint(value, 10, 8)
			if err != nil || n < 1 || n > 6 {
				return ParsedQuery{}, &ParseQueryError{Token: tok, Reason: "severity must be 1..6"}
			}
			out.SeverityID = value
		case "since":
			t, perr := parseTimeOrDuration(value, now, true)
			if perr != nil {
				return ParsedQuery{}, &ParseQueryError{Token: tok, Reason: perr.Error()}
			}
			out.Since = t.Format(time.RFC3339Nano)
		case "until":
			t, perr := parseTimeOrDuration(value, now, false)
			if perr != nil {
				return ParsedQuery{}, &ParseQueryError{Token: tok, Reason: perr.Error()}
			}
			out.Until = t.Format(time.RFC3339Nano)
		case "raw":
			rawParts = append(rawParts, value)
		default:
			out.Unknown = append(out.Unknown, tok)
		}
	}
	if len(rawParts) > 0 {
		out.RawContains = strings.Join(rawParts, " ")
	}
	return out, nil
}

// ParseQueryError names the offending token + the human-readable
// reason so the events handler can surface it as a form error.
type ParseQueryError struct {
	Token  string
	Reason string
}

func (e *ParseQueryError) Error() string {
	return fmt.Sprintf("query parse failed at %q: %s", e.Token, e.Reason)
}

// tokenizeQuery splits the input on ASCII whitespace, honouring
// double-quoted runs as a single token. Returns an error on an
// unterminated quote.
func tokenizeQuery(input string) ([]string, error) {
	var (
		out     []string
		buf     strings.Builder
		inQuote bool
	)
	flush := func() {
		if buf.Len() > 0 {
			out = append(out, buf.String())
			buf.Reset()
		}
	}
	for _, r := range input {
		switch {
		case r == '"':
			inQuote = !inQuote
		case (r == ' ' || r == '\t') && !inQuote:
			flush()
		default:
			buf.WriteRune(r)
		}
	}
	if inQuote {
		return nil, errors.New("unterminated quote")
	}
	flush()
	return out, nil
}

// splitKeyValue returns key, value, true when tok matches the `k:v`
// shape. tok itself may contain colons inside the value half (e.g.
// since:2026-05-01T12:00:00Z); only the first colon delimits.
//
// Tokens whose key half contains whitespace (i.e. the token came from
// a quoted string with embedded spaces) are treated as bareword + the
// whole thing falls through to RawContains. Without this guard
// `"curl http://x"` would parse as key=`curl http` value=`//x` and
// silently land in Unknown.
func splitKeyValue(tok string) (key, value string, ok bool) {
	idx := strings.IndexByte(tok, ':')
	if idx <= 0 || idx == len(tok)-1 {
		return "", "", false
	}
	k := tok[:idx]
	if strings.ContainsAny(k, " \t") {
		return "", "", false
	}
	return k, tok[idx+1:], true
}

// parseTimeOrDuration accepts either an RFC3339 absolute timestamp or
// a duration shorthand like "24h", "30m", "7d". Negative durations
// are silently mirrored — `since:24h` and `since:-24h` both mean
// "the last 24 hours". forSince=true subtracts the duration from now;
// forSince=false adds it (until: 1h means "1 hour from now",
// covering scheduled-end queries).
func parseTimeOrDuration(value string, now time.Time, forSince bool) (time.Time, error) {
	if value == "" {
		return time.Time{}, errors.New("empty time")
	}
	if t, err := time.Parse(time.RFC3339Nano, value); err == nil {
		return t.UTC(), nil
	}
	// Day-shorthand: parse N + 'd' since stdlib time.ParseDuration
	// caps at hours. Treat trailing 'd' as 24h.
	if strings.HasSuffix(value, "d") {
		n, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(value, "-"), "d"), 10, 32)
		if err != nil {
			return time.Time{}, fmt.Errorf("bad duration %q", value)
		}
		dur := time.Duration(n) * 24 * time.Hour
		if forSince {
			return now.Add(-dur), nil
		}
		return now.Add(dur), nil
	}
	dur, err := time.ParseDuration(value)
	if err != nil {
		return time.Time{}, fmt.Errorf("bad duration %q", value)
	}
	if dur < 0 {
		dur = -dur
	}
	if forSince {
		return now.Add(-dur), nil
	}
	return now.Add(dur), nil
}
