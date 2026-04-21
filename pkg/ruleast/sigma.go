package ruleast

import (
	"fmt"
	"regexp"
	"strings"

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
}

type logSourceYAML struct {
	Product  string `yaml:"product"`
	Category string `yaml:"category"`
	Service  string `yaml:"service"`
}

// CompileSigma parses one Sigma YAML document and returns the compiled rule.
// Every returned error wraps ErrCompile.
func CompileSigma(src []byte) (*Rule, error) {
	var doc sigmaYAML
	dec := yaml.NewDecoder(strings.NewReader(string(src)))
	dec.KnownFields(false)
	if err := dec.Decode(&doc); err != nil {
		return nil, compileErr("", "ruleast/yaml", err)
	}

	if doc.Title == "" {
		return nil, compileErr(doc.ID, "ruleast", fmt.Errorf("title required"))
	}
	if doc.ID == "" {
		return nil, compileErr("", "ruleast", fmt.Errorf("id required"))
	}
	cat, err := checkLogSource(doc.LogSource)
	if err != nil {
		return nil, compileErr(doc.ID, "ruleast", err)
	}

	selections, conditionStr, err := splitDetection(doc.Detection)
	if err != nil {
		return nil, compileErr(doc.ID, "ruleast", err)
	}

	sels := make(map[string]*Selection, len(selections))
	for name, body := range selections {
		sel, err := compileSelection(name, body)
		if err != nil {
			return nil, compileErr(doc.ID, "ruleast", fmt.Errorf("selection %q: %w", name, err))
		}
		sels[name] = sel
	}

	cond, err := parseCondition(conditionStr, sels)
	if err != nil {
		return nil, compileErr(doc.ID, "ruleast", fmt.Errorf("condition: %w", err))
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
		cost:        cond.Cost(),
	}
	return r, nil
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
func splitDetection(det map[string]any) (map[string]any, string, error) {
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
		if k == "condition" || k == "timeframe" {
			if k == "timeframe" {
				return nil, "", fmt.Errorf("detection.timeframe not supported in Phase 1 (ADR-0019)")
			}
			continue
		}
		sels[k] = v
	}
	if len(sels) == 0 {
		return nil, "", fmt.Errorf("detection has no selections")
	}
	return sels, cond, nil
}

// compileSelection turns one selection YAML body into a Selection AST.
// Sigma selections accept two shapes: a map[string]any, or a list of maps
// (implicit OR of AND-maps). Phase 1 accepts only the map form; the list
// form gets a rejection that cites the rule.
func compileSelection(name string, body any) (*Selection, error) {
	m, ok := body.(map[string]any)
	if !ok {
		if _, isList := body.([]any); isList {
			return nil, fmt.Errorf("list-of-maps selection form not supported in Phase 1")
		}
		return nil, fmt.Errorf("must be a map of field -> value-or-list; got %T", body)
	}
	preds := make([]FieldPredicate, 0, len(m))
	for rawKey, rawVal := range m {
		field, op, err := parseFieldKey(rawKey)
		if err != nil {
			return nil, fmt.Errorf("field %q: %w", rawKey, err)
		}
		pred, err := buildPredicate(field, op, rawVal)
		if err != nil {
			return nil, fmt.Errorf("field %q: %w", rawKey, err)
		}
		preds = append(preds, pred)
	}
	return &Selection{Name: name, Fields: preds}, nil
}

// parseFieldKey splits "Image|endswith" into ("Image", OpEndsWith).
func parseFieldKey(key string) (string, Operator, error) {
	parts := strings.Split(key, "|")
	if len(parts) == 1 {
		return parts[0], OpEquals, nil
	}
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("only one modifier allowed per field in Phase 1")
	}
	switch strings.ToLower(parts[1]) {
	case "contains":
		return parts[0], OpContains, nil
	case "startswith":
		return parts[0], OpStartsWith, nil
	case "endswith":
		return parts[0], OpEndsWith, nil
	case "re", "regex":
		return parts[0], OpRegex, nil
	case "all":
		return "", 0, fmt.Errorf("modifier \"all\" not supported (Phase 1 list semantics are OR-only)")
	case "cased":
		return "", 0, fmt.Errorf("modifier \"cased\" not supported in Phase 1")
	case "base64", "base64offset", "utf16", "utf16le", "utf16be", "wide":
		return "", 0, fmt.Errorf("modifier %q not supported in Phase 1", parts[1])
	}
	return "", 0, fmt.Errorf("unknown modifier %q", parts[1])
}

// buildPredicate normalises scalar/list values into []string and precompiles
// regexes up front so runtime Match stays allocation-free.
func buildPredicate(field string, op Operator, raw any) (FieldPredicate, error) {
	values, err := coerceValues(raw)
	if err != nil {
		return FieldPredicate{}, err
	}
	if len(values) == 0 {
		return FieldPredicate{}, fmt.Errorf("empty value list")
	}
	pred := FieldPredicate{Field: field, Op: op, Values: values}
	if op == OpRegex {
		pred.regexps = make([]*regexp.Regexp, len(values))
		for i, v := range values {
			re, err := regexp.Compile(v)
			if err != nil {
				return FieldPredicate{}, fmt.Errorf("regex %q: %w", v, err)
			}
			pred.regexps[i] = re
		}
	}
	return pred, nil
}

func coerceValues(raw any) ([]string, error) {
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
			sub, err := coerceValues(x)
			if err != nil {
				return nil, err
			}
			out = append(out, sub...)
		}
		return out, nil
	case nil:
		return nil, fmt.Errorf("null values not allowed")
	}
	return nil, fmt.Errorf("unsupported value type %T", raw)
}
