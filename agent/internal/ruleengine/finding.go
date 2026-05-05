package ruleengine

import (
	"strings"
	"time"

	"github.com/t3rmit3/slither/pkg/ocsf"
	"github.com/t3rmit3/slither/pkg/ruleast"
)

// buildFinding projects a rule match into an OCSF DetectionFinding. The
// triggering event's device + metadata.product are copied through so the
// finding lands in the same identity envelope as the event that caused it.
func buildFinding(rule *ruleast.Rule, trigger ocsf.Event, now time.Time) *ocsf.DetectionFinding {
	device, product, triggerUID := envelope(trigger)
	ts := now.UnixMilli()

	return &ocsf.DetectionFinding{
		Metadata: ocsf.Metadata{
			Version:   ocsf.Version,
			Product:   product,
			LogName:   "detection",
			EventCode: "sigma_match",
			UID:       ocsf.NewUID(),
			OriginalT: ts,
		},
		ClassUID:   ocsf.ClassDetectionFinding,
		ClassName:  ocsf.ClassDetectionFinding.String(),
		ActivityID: ocsf.FindingActivityCreate,
		TypeUID:    uint64(ocsf.ClassDetectionFinding)*100 + uint64(ocsf.FindingActivityCreate),
		Severity:   severityFromLevel(rule.Level),
		Time:       ocsf.TimeOCSF(ts),
		Device:     device,
		Finding: ocsf.Finding{
			UID:    ocsf.NewUID(),
			Title:  rule.Title,
			Desc:   rule.Description,
			Status: "New",
		},
		RuleInfo: ocsf.Rule{
			UID:         rule.ID,
			Name:        rule.Title,
			Category:    []string{string(rule.Category)},
			Description: rule.Description,
		},
		TriggeringEventIDs: []string{triggerUID},
		MitreATTACK:        mitreTagsFromSigma(rule.Tags),
	}
}

// mitreTagsFromSigma normalises Sigma `tags:` strings into the OCSF
// MitreTag shape. Phase 6 #120 — the agent's buildFinding used to
// drop rule.Tags on the floor; the JSON API contract requires them
// on every detection_finding row.
//
// Sigma tag conventions (per the Sigma project's tag taxonomy):
//
//   - `attack.t1070.003` → technique T1070.003 (sub-technique form)
//   - `attack.t1059`     → technique T1059 (top-level)
//   - `attack.s0096`     → software ID (parsed but not surfaced — OCSF
//     MitreTag has no software field; future-proof if needed)
//   - `attack.g0007`     → group ID (same shape, parked)
//
// Anything outside the `attack.` namespace is dropped — non-MITRE
// Sigma tags (e.g. `cve.2024.0001`, `tlp.amber`) don't belong in
// MitreATTACK. The CH writer extracts technique UIDs into the
// existing `mitre_techniques Array(String)` column.
func mitreTagsFromSigma(tags []string) []ocsf.MitreTag {
	if len(tags) == 0 {
		return nil
	}
	out := make([]ocsf.MitreTag, 0, len(tags))
	for _, raw := range tags {
		t := strings.ToLower(strings.TrimSpace(raw))
		if !strings.HasPrefix(t, "attack.") {
			continue
		}
		body := strings.TrimPrefix(t, "attack.")
		if body == "" {
			continue
		}
		// First-letter shape filter: t = technique, s = software,
		// g = group. Only `t*` lands on MitreATTACK in v1; the OCSF
		// schema's MitreTag carries Tactic + Technique + SubTechnique
		// fields and has no software/group counterpart.
		if body[0] != 't' {
			continue
		}
		out = append(out, mitreTagFromTechnique(body))
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// mitreTagFromTechnique parses a `t1070.003`-style body into an
// OCSF MitreTag with Technique.UID set canonically uppercase
// (T1070.003) and SubTechnique split out when the input carries the
// dotted sub-form. Bare `t1059` lands as Technique.UID = "T1059"
// with no sub.
func mitreTagFromTechnique(body string) ocsf.MitreTag {
	canon := strings.ToUpper(body)
	tag := ocsf.MitreTag{
		Technique: ocsf.MitreTechnique{UID: canon},
	}
	if idx := strings.IndexByte(canon, '.'); idx > 0 {
		parent := canon[:idx]
		sub := canon
		tag.Technique = ocsf.MitreTechnique{UID: parent}
		tag.SubTech = &ocsf.MitreTechnique{UID: sub}
	}
	return tag
}

// envelope pulls the device, product stamp, and metadata.uid from whatever
// OCSF class the triggering event happens to be. Keeping this in one place
// means new class types only need to extend this switch, not every caller.
func envelope(e ocsf.Event) (ocsf.Device, ocsf.Product, string) {
	switch v := e.(type) {
	case *ocsf.ProcessActivity:
		return v.Device, v.Metadata.Product, v.Metadata.UID
	case *ocsf.FileSystemActivity:
		return v.Device, v.Metadata.Product, v.Metadata.UID
	case *ocsf.NetworkActivity:
		return v.Device, v.Metadata.Product, v.Metadata.UID
	}
	return ocsf.Device{}, ocsf.Product{}, ""
}

// severityFromLevel maps Sigma's level vocabulary onto OCSF severity_id.
// Unknown levels collapse to Informational rather than failing — the engine
// should never drop a finding just because an author used a non-standard
// level string.
func severityFromLevel(l ruleast.Level) ocsf.Severity {
	switch l {
	case ruleast.LevelCritical:
		return ocsf.SeverityCritical
	case ruleast.LevelHigh:
		return ocsf.SeverityHigh
	case ruleast.LevelMedium:
		return ocsf.SeverityMedium
	case ruleast.LevelLow:
		return ocsf.SeverityLow
	case ruleast.LevelInformational:
		return ocsf.SeverityInformational
	}
	return ocsf.SeverityInformational
}
