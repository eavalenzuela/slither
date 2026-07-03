package ruleast

import (
	"encoding/base64"
	"fmt"
	"math/bits"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf16"

	"gopkg.in/yaml.v3"
)

// sigmaYAML mirrors the subset of Sigma we accept. Unknown top-level keys
// are ignored (Sigma adds metadata fields freely); unknown modifiers inside
// detection trigger a compile error because a silently-dropped modifier
// changes rule semantics.
type sigmaYAML struct {
	Title       string         `yaml:"title"`
	ID          string         `yaml:"id"`
	Status      string         `yaml:"status"`
	Description string         `yaml:"description"`
	Author      string         `yaml:"author"`
	References  []string       `yaml:"references"`
	Tags        []string       `yaml:"tags"`
	LogSource   logSourceYAML  `yaml:"logsource"`
	Detection   map[string]any `yaml:"detection"`
	Level       string         `yaml:"level"`

	// Phase 3 #54d adds three top-level keys. ForceEdge gates classification
	// per ADR-0018 — when true, an edge-ineligible rule fails compile with
	// the failed predicate cited rather than silently routing to the server
	// detection engine. Timeframe (e.g. "60s", "5m", "1h") bounds the
	// stateful runtime's window. Lookback opts the rule into #59's CH-replay
	// cold start.
	Timeframe string `yaml:"timeframe"`
	ForceEdge bool   `yaml:"force_edge"`
	Lookback  bool   `yaml:"lookback"`

	// Phase 3 #54e: CrossHost is operator-declared. The compiler can't
	// infer cross-host semantics from field names alone (the same
	// Field|user could mean "users on this box" or "users across the
	// fleet"), so authors flip this flag when the rule needs visibility
	// the agent cannot supply. Implies ServerOnly classification (ADR-
	// 0018 predicate 1). force_edge with cross_host fails compile.
	CrossHost bool `yaml:"cross_host"`

	// Phase 4 #82: optional auto-respond intent. Nil-pointer means
	// "no response block" — the historical detect-only behaviour.
	// `slither.response` is the YAML key by ADR-0034.
	Slither *slitherYAML `yaml:"slither"`
}

// slitherYAML is the namespaced container for slither-specific
// extensions on a Sigma rule. Phase 4 #82 added `response`; Phase 6
// #111 adds `snapshot` for forensic snapshot-on-alert routing.
// Future per-rule knobs (rate-limits, suppression windows) land here
// so the `slither.*` namespace stays a single decode struct.
type slitherYAML struct {
	Response *responseYAML `yaml:"response"`

	// Snapshot opts the rule into Phase 6 #111's snapshot-on-alert
	// path. When true, the agent's AutoResponder emits a SnapshotRequest
	// to every loaded extension declaring CAPABILITY_SNAPSHOT_PROVIDE
	// in addition to (or instead of) the response action. Independent
	// of `response`: a rule may carry snapshot=true with no response
	// block at all.
	Snapshot bool `yaml:"snapshot"`
}

type responseYAML struct {
	Action      string `yaml:"action"`
	TargetField string `yaml:"target_field"`
	Immediate   bool   `yaml:"immediate"`
}

type logSourceYAML struct {
	Product  string `yaml:"product"`
	Category string `yaml:"category"`
	Service  string `yaml:"service"`
}

// compileSigma parses one Sigma YAML document and returns the compiled
// boolean-tree rule along with the raw top-level metadata classify needs
// to evaluate ADR-0018 predicates. Internal as of §5.1 #54a — public
// callers use Compile. Every returned error wraps ErrCompile.
func compileSigma(src []byte) (*Rule, *sigmaYAML, error) {
	var doc sigmaYAML
	dec := yaml.NewDecoder(strings.NewReader(string(src)))
	dec.KnownFields(false)
	if err := dec.Decode(&doc); err != nil {
		return nil, nil, compileErr("", "ruleast/yaml", err)
	}

	if doc.Title == "" {
		return nil, nil, compileErr(doc.ID, "ruleast", fmt.Errorf("title required"))
	}
	if doc.ID == "" {
		return nil, nil, compileErr("", "ruleast", fmt.Errorf("id required"))
	}
	cat, err := checkLogSource(doc.LogSource)
	if err != nil {
		return nil, nil, compileErr(doc.ID, "ruleast", err)
	}

	selections, conditionStr, err := splitDetection(doc.Detection)
	if err != nil {
		return nil, nil, compileErr(doc.ID, "ruleast", err)
	}

	sels := make(map[string]*Selection, len(selections))
	for name, body := range selections {
		sel, selErr := compileSelection(name, body)
		if selErr != nil {
			return nil, nil, compileErr(doc.ID, "ruleast", fmt.Errorf("selection %q: %w", name, selErr))
		}
		sels[name] = sel
	}

	cond, agg, err := parseCondition(conditionStr, sels)
	if err != nil {
		return nil, nil, compileErr(doc.ID, "ruleast", fmt.Errorf("condition: %w", err))
	}

	timeframeSecs, err := parseTimeframe(doc.Timeframe)
	if err != nil {
		return nil, nil, compileErr(doc.ID, "ruleast", fmt.Errorf("timeframe: %w", err))
	}
	near, hasNear := cond.(*NodeNear)
	switch {
	case agg != nil:
		if timeframeSecs == 0 {
			return nil, nil, compileErr(doc.ID, "ruleast",
				fmt.Errorf("aggregation requires top-level timeframe (e.g. \"timeframe: 60s\")"))
		}
		agg.TimeframeSecs = timeframeSecs
	case hasNear:
		if timeframeSecs == 0 {
			return nil, nil, compileErr(doc.ID, "ruleast",
				fmt.Errorf("`near` requires top-level timeframe to bound the join window"))
		}
		near.WithinSecs = timeframeSecs
	default:
		if timeframeSecs > 0 {
			return nil, nil, compileErr(doc.ID, "ruleast",
				fmt.Errorf("timeframe is only meaningful with a pipe-aggregation or `near` condition"))
		}
	}
	if doc.Lookback && agg == nil && !hasNear {
		return nil, nil, compileErr(doc.ID, "ruleast",
			fmt.Errorf("lookback only applies to stateful (aggregating or `near`) rules"))
	}

	r := &Rule{
		ID:          doc.ID,
		Title:       doc.Title,
		Description: doc.Description,
		Level:       normaliseLevel(doc.Level),
		Category:    cat,
		Tags:        doc.Tags,
		Selections:  sels,
		Condition:   cond,
		Aggregation: agg,
		cost:        cond.Cost(),
	}

	// Phase 4 #82: validate the optional response block now that
	// selections are compiled — target_field is checked against the
	// fields actually referenced by the rule's predicates.
	if doc.Slither != nil && doc.Slither.Response != nil {
		if _, err := compileResponseIntent(r, doc.Slither.Response); err != nil {
			return nil, nil, compileErr(doc.ID, "ruleast", err)
		}
	}
	return r, &doc, nil
}

// compileResponseIntent validates a Sigma rule's `slither.response`
// block + returns the canonical ResponseIntent. Phase 4 #82.
//
// Validation rules:
//
//   - action must be one of the six ADR-0034 classes.
//   - target_field must be identifier-shaped. Required for entity-scoped
//     actions (kill/quarantine/collect); optional for host-scoped ones
//     (isolate/unisolate), which ignore it. Earlier
//     iterations required target_field to appear in a selection
//     predicate, but kill_process commonly matches on Image (which
//     binary fired) while targeting ProcessId (which PID to kill) —
//     a strict selection-membership check made that valid pattern
//     uncompilable. The agent's AutoResponder gracefully stamps
//     would_have_executed=true when target_field doesn't resolve at
//     runtime, so a typo here degrades into a detect-only firing
//     rather than a silent miss — soft enough to drop the
//     selection-membership constraint.
//   - immediate is a bare bool; no extra validation.
func compileResponseIntent(rule *Rule, in *responseYAML) (*ResponseIntent, error) {
	_ = rule // kept for future per-category field-taxonomy validation
	action := ResponseAction(strings.TrimSpace(in.Action))
	if action == "" {
		return nil, fmt.Errorf("slither.response.action required")
	}
	known := false
	for _, a := range allResponseActions {
		if a == action {
			known = true
			break
		}
	}
	if !known {
		return nil, fmt.Errorf("slither.response.action %q not recognised; valid: %v",
			action, allResponseActions)
	}
	target := strings.TrimSpace(in.TargetField)
	if target == "" {
		// Host-scoped actions (isolate/unisolate) don't draw a target
		// from the event — the executor autoderives the mgmt subnet —
		// so target_field is optional for them. Entity-scoped actions
		// still need one to name the PID/path to act on.
		if !action.IsHostScoped() {
			return nil, fmt.Errorf("slither.response.target_field required for action %q", action)
		}
	} else if !isIdentifierShape(target) {
		return nil, fmt.Errorf("slither.response.target_field %q must be identifier-shaped (alphanumeric, underscore, or dot)", target)
	}
	return &ResponseIntent{
		Action:      action,
		TargetField: target,
		Immediate:   in.Immediate,
	}, nil
}

// isIdentifierShape reports whether s is a plausible OCSF field name:
// non-empty, first char is a letter or underscore, rest are letters,
// digits, underscores, or dots (for nested fields like "process.uid").
func isIdentifierShape(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r == '_':
			continue
		case (r >= '0' && r <= '9' || r == '.') && i > 0:
			continue
		}
		return false
	}
	return true
}

// ruleReferencesField reports whether any selection's branch carries
// a predicate on the named field. Case-sensitive — Sigma field names
// are; if authors disagree, the typo'd name still fails the check.
//
//nolint:unused // Retained for future per-category taxonomy validation.
func ruleReferencesField(rule *Rule, field string) bool {
	if rule == nil {
		return false
	}
	for _, sel := range rule.Selections {
		for _, branch := range sel.Branches {
			for i := range branch {
				if branch[i].Field == field {
					return true
				}
			}
		}
	}
	return false
}

// parseTimeframe converts Sigma's timeframe scalar into seconds. The
// accepted suffixes mirror Sigma's spec: "s", "m", "h", "d". An empty
// string is "no timeframe" and returns 0; a malformed value returns an
// error so authors don't accidentally ship an unbounded stateful rule.
func parseTimeframe(s string) (uint32, error) {
	if s == "" {
		return 0, nil
	}
	if len(s) < 2 {
		return 0, fmt.Errorf("timeframe %q too short; expected NNs/NNm/NNh/NNd", s)
	}
	unit := s[len(s)-1]
	digits := s[:len(s)-1]
	var multSecs uint64
	switch unit {
	case 's':
		multSecs = 1
	case 'm':
		multSecs = 60
	case 'h':
		multSecs = 60 * 60
	case 'd':
		multSecs = 60 * 60 * 24
	default:
		return 0, fmt.Errorf("timeframe %q has unknown unit %q (expected s, m, h, or d)", s, string(unit))
	}
	n, err := parseUintStrict(digits)
	if err != nil {
		return 0, fmt.Errorf("timeframe %q: %w", s, err)
	}
	if n == 0 {
		return 0, fmt.Errorf("timeframe %q must be positive", s)
	}
	total := n * multSecs
	if total > 0xFFFFFFFF {
		return 0, fmt.Errorf("timeframe %q overflows uint32 seconds", s)
	}
	return uint32(total), nil
}

func parseUintStrict(s string) (uint64, error) {
	if s == "" {
		return 0, fmt.Errorf("missing digits")
	}
	var n uint64
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("non-digit %q", r)
		}
		d := uint64(r - '0')
		// Guard the accumulator against wrap: a silent overflow could turn
		// a pathologically-long timeframe into a tiny window and ship an
		// effectively-unbounded stateful rule.
		if n > (^uint64(0)-d)/10 {
			return 0, fmt.Errorf("value overflows uint64")
		}
		n = n*10 + d
	}
	return n, nil
}

func checkLogSource(ls logSourceYAML) (Category, error) {
	if !strings.EqualFold(ls.Product, "linux") {
		return "", fmt.Errorf("logsource.product = %q; only \"linux\" is accepted in Phase 1", ls.Product)
	}
	switch strings.ToLower(ls.Category) {
	case string(CategoryProcessCreation):
		return CategoryProcessCreation, nil
	case string(CategoryFileEvent):
		return CategoryFileEvent, nil
	case string(CategoryNetworkConnection):
		return CategoryNetworkConnection, nil
	}
	return "", fmt.Errorf("logsource.category = %q; accepted: process_creation, file_event, network_connection", ls.Category)
}

func normaliseLevel(s string) Level {
	switch strings.ToLower(s) {
	case "informational", "info":
		return LevelInformational
	case "low":
		return LevelLow
	case "medium":
		return LevelMedium
	case "high":
		return LevelHigh
	case "critical":
		return LevelCritical
	}
	return LevelMedium
}

// splitDetection pulls the condition string out of the detection map and
// leaves the remaining keys (selections). A detection without a condition
// is invalid — Sigma's implicit-single-selection shortcut is rejected so
// rules are explicit.
func splitDetection(det map[string]any) (selections map[string]any, condition string, err error) {
	if len(det) == 0 {
		return nil, "", fmt.Errorf("detection block empty")
	}
	raw, ok := det["condition"]
	if !ok {
		return nil, "", fmt.Errorf("detection.condition required")
	}
	cond, ok := raw.(string)
	if !ok {
		return nil, "", fmt.Errorf("detection.condition must be a string; got %T", raw)
	}
	sels := make(map[string]any, len(det)-1)
	for k, v := range det {
		if k == "condition" {
			continue
		}
		if k == "timeframe" {
			return nil, "", fmt.Errorf("timeframe must be a top-level rule key, not under detection (Slither §5.1 #54d)")
		}
		sels[k] = v
	}
	if len(sels) == 0 {
		return nil, "", fmt.Errorf("detection has no selections")
	}
	return sels, cond, nil
}

// compileSelection turns one selection YAML body into a Selection AST.
// Sigma selections accept two shapes:
//
//   - map[string]any: a single branch where keys AND together.
//   - []any of maps: one branch per list element, branches OR together.
//
// Both shapes feed the same Selection — the difference is whether
// Selection.Branches has length 1 or N.
func compileSelection(name string, body any) (*Selection, error) {
	switch v := body.(type) {
	case map[string]any:
		preds, err := compileBranch(v)
		if err != nil {
			return nil, err
		}
		return &Selection{Name: name, Branches: [][]FieldPredicate{preds}}, nil
	case []any:
		if len(v) == 0 {
			return nil, fmt.Errorf("empty list-of-maps selection")
		}
		branches := make([][]FieldPredicate, 0, len(v))
		for i, elem := range v {
			m, ok := elem.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("list-of-maps entry %d is %T, want map", i, elem)
			}
			preds, err := compileBranch(m)
			if err != nil {
				return nil, fmt.Errorf("list-of-maps entry %d: %w", i, err)
			}
			branches = append(branches, preds)
		}
		return &Selection{Name: name, Branches: branches}, nil
	}
	return nil, fmt.Errorf("must be a map or list-of-maps; got %T", body)
}

// compileBranch turns one map body into a single branch's worth of
// FieldPredicates (AND across keys).
func compileBranch(m map[string]any) ([]FieldPredicate, error) {
	preds := make([]FieldPredicate, 0, len(m))
	for rawKey, rawVal := range m {
		field, op, mods, err := parseFieldKey(rawKey)
		if err != nil {
			return nil, fmt.Errorf("field %q: %w", rawKey, err)
		}
		pred, err := buildPredicate(field, op, mods, rawVal)
		if err != nil {
			return nil, fmt.Errorf("field %q: %w", rawKey, err)
		}
		preds = append(preds, pred)
	}
	return preds, nil
}

// parseFieldKey splits "Image|endswith|all" into ("Image", OpEndsWith,
// ModAll). The first segment is always the field name; subsequent
// segments are modifiers. A single-segment key is a bare equals match
// with no flags.
func parseFieldKey(key string) (string, Operator, Modifiers, error) {
	parts := strings.Split(key, "|")
	if len(parts) == 1 {
		return parts[0], OpEquals, 0, nil
	}
	field := parts[0]
	op := OpEquals
	opSeen := false
	var mods Modifiers
	setOp := func(o Operator, name string) error {
		if opSeen {
			return fmt.Errorf("multiple match operators in modifier chain (already saw %s, also %s)", op, name)
		}
		op = o
		opSeen = true
		return nil
	}
	for _, raw := range parts[1:] {
		seg := strings.ToLower(raw)
		switch seg {
		case "contains":
			if err := setOp(OpContains, seg); err != nil {
				return "", 0, 0, err
			}
		case "startswith":
			if err := setOp(OpStartsWith, seg); err != nil {
				return "", 0, 0, err
			}
		case "endswith":
			if err := setOp(OpEndsWith, seg); err != nil {
				return "", 0, 0, err
			}
		case "re", "regex":
			if err := setOp(OpRegex, seg); err != nil {
				return "", 0, 0, err
			}
		case "cidr":
			if err := setOp(OpCIDR, seg); err != nil {
				return "", 0, 0, err
			}
		case "ioc":
			if err := setOp(OpIOC, seg); err != nil {
				return "", 0, 0, err
			}
		case "gt":
			if err := setOp(OpGT, seg); err != nil {
				return "", 0, 0, err
			}
		case "gte":
			if err := setOp(OpGTE, seg); err != nil {
				return "", 0, 0, err
			}
		case "lt":
			if err := setOp(OpLT, seg); err != nil {
				return "", 0, 0, err
			}
		case "lte":
			if err := setOp(OpLTE, seg); err != nil {
				return "", 0, 0, err
			}
		case "all":
			mods |= ModAll
		case "null":
			mods |= ModNull
		case "exists":
			mods |= ModExists
		case "cased":
			mods |= ModCased
		// Regex sub-modifiers set inline flags on the compiled pattern.
		// They are only meaningful after `re`/`regex`; validated below.
		case "i":
			mods |= ModReI
		case "m":
			mods |= ModReM
		case "s":
			mods |= ModReS
		case "base64":
			mods |= ModBase64
		case "base64offset":
			mods |= ModBase64Offset
		case "utf16le", "wide":
			mods |= ModUTF16LE
		case "utf16be":
			mods |= ModUTF16BE
		case "utf16":
			mods |= ModUTF16
		default:
			return "", 0, 0, fmt.Errorf("unknown modifier %q", raw)
		}
	}
	if mods.Has(ModBase64Offset) && !opSeen {
		// base64offset is meaningful only with contains semantics — the
		// three-offset trick exists to detect base64 substrings at any
		// byte alignment. Default to contains rather than reject so
		// authors can write "Field|base64offset: x" naturally.
		op = OpContains
	}
	if err := validateModifierComposition(mods, op); err != nil {
		return "", 0, 0, err
	}
	return field, op, mods, nil
}

// validateModifierComposition rejects modifier combinations whose
// semantics would be ambiguous or undefined. Better to fail loud at
// compile time than silently apply a guess.
func validateModifierComposition(mods Modifiers, op Operator) error {
	if mods.Has(ModNull) && mods != ModNull {
		return fmt.Errorf("modifier \"null\" must be standalone (no other modifiers)")
	}
	if mods.Has(ModExists) && mods != ModExists {
		return fmt.Errorf("modifier \"exists\" must be standalone (no other modifiers)")
	}
	if mods.Has(ModExists) && op != OpEquals {
		return fmt.Errorf("modifier \"exists\" is a presence check and takes no match operator")
	}
	// Regex sub-flags (i/m/s) are only meaningful on a regex predicate.
	reFlags := mods & (ModReI | ModReM | ModReS)
	if reFlags != 0 && op != OpRegex {
		return fmt.Errorf("regex flags (i/m/s) require the \"re\"/\"regex\" modifier")
	}
	if op == OpCIDR && mods != 0 {
		return fmt.Errorf("modifier \"cidr\" composes with no other modifiers")
	}
	if op == OpIOC && mods != 0 {
		return fmt.Errorf("modifier \"ioc\" composes with no other modifiers")
	}
	if op == OpRegex && mods&^(ModAll|ModReI|ModReM|ModReS) != 0 {
		return fmt.Errorf("modifier \"regex\" composes only with \"all\" and the i/m/s flags")
	}
	if op.isNumeric() && mods&^ModAll != 0 {
		return fmt.Errorf("numeric modifier %q composes only with \"all\"", op)
	}
	if mods.Has(ModCased) {
		switch op {
		case OpEquals, OpContains, OpStartsWith, OpEndsWith:
		default:
			return fmt.Errorf("modifier \"cased\" composes only with string match operators")
		}
	}
	encodings := mods & (ModBase64 | ModBase64Offset | ModUTF16LE | ModUTF16BE | ModUTF16)
	if bits.OnesCount16(uint16(encodings&(ModBase64|ModBase64Offset))) > 1 {
		return fmt.Errorf("modifiers \"base64\" and \"base64offset\" are mutually exclusive")
	}
	utfCount := bits.OnesCount16(uint16(encodings & (ModUTF16LE | ModUTF16BE | ModUTF16)))
	if utfCount > 1 {
		return fmt.Errorf("UTF-16 modifiers (utf16le/utf16be/utf16/wide) are mutually exclusive")
	}
	return nil
}

// buildPredicate normalises scalar/list values into []string, applies
// any compile-time value transforms (encoding modifiers, CIDR parse),
// and precompiles regexes so the runtime Match stays allocation-free.
func buildPredicate(field string, op Operator, mods Modifiers, raw any) (FieldPredicate, error) {
	values, err := coerceValues(raw, mods.Has(ModNull))
	if err != nil {
		return FieldPredicate{}, err
	}
	if mods.Has(ModNull) {
		// "null" is a presence check; the YAML value is irrelevant.
		// Allow `Field|null: null` and `Field|null: true` interchangeably.
		return FieldPredicate{Field: field, Op: op, Mods: mods}, nil
	}
	if mods.Has(ModExists) {
		// "exists" is a boolean presence check. The value must be a bare
		// true/false; anything else is a rule-author error worth failing
		// loud on rather than guessing.
		if len(values) != 1 || (values[0] != "true" && values[0] != "false") {
			return FieldPredicate{}, fmt.Errorf("\"exists\" modifier requires a boolean value (true or false)")
		}
		return FieldPredicate{Field: field, Op: op, Mods: mods, existsWant: values[0] == "true"}, nil
	}
	if len(values) == 0 {
		return FieldPredicate{}, fmt.Errorf("empty value list")
	}
	if op.isNumeric() {
		// Validate every threshold parses as a number now so a typo fails
		// compile rather than silently never matching at runtime.
		for _, v := range values {
			if _, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err != nil {
				return FieldPredicate{}, fmt.Errorf("numeric modifier %q needs numeric values; %q does not parse", op, v)
			}
		}
		return FieldPredicate{Field: field, Op: op, Mods: mods, Values: values}, nil
	}
	if op == OpIOC {
		// IOC values are feed_ids — light validation here keeps a
		// typo from sneaking through to runtime where it would just
		// silently miss.
		feeds := make([]string, 0, len(values))
		for _, v := range values {
			if strings.TrimSpace(v) == "" {
				return FieldPredicate{}, fmt.Errorf("ioc feed_id may not be empty")
			}
			feeds = append(feeds, strings.TrimSpace(v))
		}
		return FieldPredicate{Field: field, Op: op, Mods: mods, FeedIDs: feeds}, nil
	}
	values = applyEncodingModifiers(values, mods)
	pred := FieldPredicate{Field: field, Op: op, Mods: mods, Values: values}
	// Precompute the case-folded form of each value for the
	// case-insensitive substring operators so the runtime never re-folds
	// a constant. Skipped when |cased is set (raw comparison wanted).
	if !mods.Has(ModCased) {
		switch op {
		case OpContains, OpStartsWith, OpEndsWith:
			pred.foldValues = make([]string, len(values))
			for i, v := range values {
				pred.foldValues[i] = strings.ToLower(v)
			}
		}
	}
	switch op {
	case OpRegex:
		flagPrefix := regexFlagPrefix(mods)
		pred.regexps = make([]*regexp.Regexp, len(values))
		for i, v := range values {
			re, err := regexp.Compile(flagPrefix + v)
			if err != nil {
				return FieldPredicate{}, fmt.Errorf("regex %q: %w", v, err)
			}
			pred.regexps[i] = re
		}
	case OpCIDR:
		pred.cidrs = make([]netip.Prefix, len(values))
		for i, v := range values {
			p, err := netip.ParsePrefix(v)
			if err != nil {
				// Allow bare IPs as /32 or /128 to keep the YAML
				// natural for single-address blocks.
				addr, addrErr := netip.ParseAddr(v)
				if addrErr != nil {
					return FieldPredicate{}, fmt.Errorf("cidr %q: %w", v, err)
				}
				p = netip.PrefixFrom(addr, addr.BitLen())
			}
			pred.cidrs[i] = p
		}
	}
	return pred, nil
}

// regexFlagPrefix renders the `(?ims)` inline-flag group the regex
// sub-modifiers request, or "" when none are set. Order is fixed
// (i, m, s) so the compiled form is deterministic.
func regexFlagPrefix(mods Modifiers) string {
	var flags []byte
	if mods.Has(ModReI) {
		flags = append(flags, 'i')
	}
	if mods.Has(ModReM) {
		flags = append(flags, 'm')
	}
	if mods.Has(ModReS) {
		flags = append(flags, 's')
	}
	if len(flags) == 0 {
		return ""
	}
	return "(?" + string(flags) + ")"
}

// applyEncodingModifiers rewrites values into the encoded forms the
// runtime should match against. Base64 modifiers replace each value
// with its encoded byte string; UTF-16 modifiers similarly. The order
// is deterministic (UTF-16 first, then base64) so a future
// "Field|utf16le|base64" combination produces the same bytes pySigma
// would. Phase 3 v1 doesn't compose UTF-16 with base64; the order
// hook is preserved to avoid a re-architecture later.
func applyEncodingModifiers(values []string, mods Modifiers) []string {
	if !mods.Has(ModBase64) && !mods.Has(ModBase64Offset) &&
		!mods.Has(ModUTF16LE) && !mods.Has(ModUTF16BE) && !mods.Has(ModUTF16) {
		return values
	}
	switch {
	case mods.Has(ModUTF16LE):
		values = mapValues(values, encodeUTF16LE)
	case mods.Has(ModUTF16BE):
		values = mapValues(values, encodeUTF16BE)
	case mods.Has(ModUTF16):
		values = mapValues(values, encodeUTF16WithBOM)
	}
	switch {
	case mods.Has(ModBase64):
		values = mapValues(values, encodeBase64)
	case mods.Has(ModBase64Offset):
		out := make([]string, 0, len(values)*3)
		for _, v := range values {
			out = append(out, base64Offsets(v)...)
		}
		values = out
	}
	return values
}

func mapValues(in []string, fn func(string) string) []string {
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = fn(v)
	}
	return out
}

func encodeBase64(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

// base64Offsets returns the three offset-encoded forms of v that
// pySigma would emit for `base64offset`. The trick: prepend 0, 1, or 2
// padding bytes before encoding, then trim the encoded prefix that
// would change with surrounding data. Each output is the substring an
// operator should look for in the field.
func base64Offsets(v string) []string {
	out := make([]string, 0, 3)
	for off := 0; off < 3; off++ {
		buf := make([]byte, 0, off+len(v))
		for i := 0; i < off; i++ {
			buf = append(buf, 0)
		}
		buf = append(buf, v...)
		enc := base64.StdEncoding.EncodeToString(buf)
		// Strip the leading characters introduced by the padding
		// bytes — they vary with surrounding data and would prevent
		// a contains-style match.
		strip := (off * 4) / 3
		if strip > len(enc) {
			strip = len(enc)
		}
		// Strip the trailing '=' padding the same way pySigma does;
		// it isn't significant inside a containing string.
		enc = strings.TrimRight(enc, "=")
		if strip < len(enc) {
			out = append(out, enc[strip:])
		}
	}
	return out
}

func encodeUTF16LE(s string) string {
	units := utf16.Encode([]rune(s))
	b := make([]byte, 0, len(units)*2)
	for _, u := range units {
		b = append(b, byte(u), byte(u>>8))
	}
	return string(b)
}

func encodeUTF16BE(s string) string {
	units := utf16.Encode([]rune(s))
	b := make([]byte, 0, len(units)*2)
	for _, u := range units {
		b = append(b, byte(u>>8), byte(u))
	}
	return string(b)
}

func encodeUTF16WithBOM(s string) string {
	return string([]byte{0xFF, 0xFE}) + encodeUTF16LE(s)
}

func coerceValues(raw any, allowNull bool) ([]string, error) {
	switch v := raw.(type) {
	case string:
		return []string{v}, nil
	case int:
		return []string{fmt.Sprintf("%d", v)}, nil
	case int64:
		return []string{fmt.Sprintf("%d", v)}, nil
	case float64:
		return []string{fmt.Sprintf("%g", v)}, nil
	case bool:
		if v {
			return []string{"true"}, nil
		}
		return []string{"false"}, nil
	case []any:
		out := make([]string, 0, len(v))
		for _, x := range v {
			sub, err := coerceValues(x, allowNull)
			if err != nil {
				return nil, err
			}
			out = append(out, sub...)
		}
		return out, nil
	case nil:
		if allowNull {
			return nil, nil
		}
		return nil, fmt.Errorf("null values not allowed (use \"|null\" modifier for presence checks)")
	}
	return nil, fmt.Errorf("unsupported value type %T", raw)
}
