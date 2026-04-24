package ruleengine

import (
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
	}
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
