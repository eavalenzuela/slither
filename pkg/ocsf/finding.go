package ocsf

import "fmt"

// DetectionFinding (OCSF class_uid 2004).
// Emitted when a rule fires, carrying pointers to the triggering events.
type DetectionFinding struct {
	Metadata    Metadata    `json:"metadata"`
	ClassUID    ClassID     `json:"class_uid"`
	ClassName   string      `json:"class_name"`
	ActivityID  FindingActivityID `json:"activity_id"`
	TypeUID     uint64      `json:"type_uid"`
	Severity    Severity    `json:"severity_id"`
	SeverityStr string      `json:"severity,omitempty"`
	Time        TimeOCSF    `json:"time"`
	Device      Device      `json:"device"`

	Finding     Finding     `json:"finding"`
	RuleInfo    Rule        `json:"rule"`
	MitreATTACK []MitreTag  `json:"attacks,omitempty"`

	// event_id values of the events that caused this finding. Server uses these
	// to build the detection flow graph.
	TriggeringEventIDs []string `json:"x_triggering_event_ids,omitempty"`
}

type FindingActivityID uint8

const (
	FindingActivityUnknown FindingActivityID = 0
	FindingActivityCreate  FindingActivityID = 1
	FindingActivityUpdate  FindingActivityID = 2
	FindingActivityClose   FindingActivityID = 3
	FindingActivityOther   FindingActivityID = 99
)

type Finding struct {
	UID    string `json:"uid"`            // alert id
	Title  string `json:"title"`
	Desc   string `json:"desc,omitempty"`
	Status string `json:"status,omitempty"` // New, InProgress, Closed
}

type Rule struct {
	UID         string   `json:"uid"`
	Name        string   `json:"name"`
	Version     string   `json:"version,omitempty"`
	Category    []string `json:"category,omitempty"`
	Description string   `json:"desc,omitempty"`
}

type MitreTag struct {
	Tactic    MitreTactic     `json:"tactic,omitempty"`
	Technique MitreTechnique  `json:"technique,omitempty"`
	SubTech   *MitreTechnique `json:"sub_technique,omitempty"`
	Version   string          `json:"version,omitempty"` // e.g. "14.1"
}

type MitreTactic struct {
	UID  string `json:"uid,omitempty"`
	Name string `json:"name,omitempty"`
}

type MitreTechnique struct {
	UID  string `json:"uid,omitempty"` // e.g. "T1059.004"
	Name string `json:"name,omitempty"`
}

func (d *DetectionFinding) ClassID() ClassID { return ClassDetectionFinding }

func (d *DetectionFinding) Validate() error {
	if d.ClassUID != ClassDetectionFinding {
		return fmt.Errorf("%w: class_uid %d != %d", ErrInvalidEvent, d.ClassUID, ClassDetectionFinding)
	}
	if d.ActivityID == FindingActivityUnknown {
		return fmt.Errorf("%w: activity_id required", ErrInvalidEvent)
	}
	if d.Time == 0 {
		return fmt.Errorf("%w: time required", ErrInvalidEvent)
	}
	if d.Finding.UID == "" {
		return fmt.Errorf("%w: finding.uid required", ErrInvalidEvent)
	}
	if d.RuleInfo.UID == "" {
		return fmt.Errorf("%w: rule.uid required", ErrInvalidEvent)
	}
	if len(d.TriggeringEventIDs) == 0 {
		return fmt.Errorf("%w: at least one triggering event id required", ErrInvalidEvent)
	}
	return nil
}
