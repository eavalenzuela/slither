package ocsf

import "fmt"

// Authentication (OCSF class_uid 3002).
type Authentication struct {
	Metadata    Metadata     `json:"metadata"`
	ClassUID    ClassID      `json:"class_uid"`
	ClassName   string       `json:"class_name"`
	ActivityID  AuthActivity `json:"activity_id"`
	TypeUID     uint64       `json:"type_uid"`
	Severity    Severity     `json:"severity_id"`
	SeverityStr string       `json:"severity,omitempty"`
	Time        TimeOCSF     `json:"time"`
	Device      Device       `json:"device"`
	Actor       Actor        `json:"actor"`
	User        User         `json:"user"`
	Status      string       `json:"status,omitempty"` // Success, Failure, Other
	StatusID    uint8        `json:"status_id,omitempty"`
	// StatusCode is the raw authenticator result — for the PAM collector
	// the libpam return code as a decimal string ("7" == PAM_AUTH_ERR) —
	// and StatusDetail its symbolic name. Kept separately from Status so
	// a rule can tell "user unknown" from "bad password" from "max tries".
	StatusCode   string `json:"status_code,omitempty"`
	StatusDetail string `json:"status_detail,omitempty"`
	AuthProto    string `json:"auth_protocol,omitempty"` // ssh, pam, sudo
	LogonType    string `json:"logon_type,omitempty"`
	LogonTypeID  uint8  `json:"logon_type_id,omitempty"`
	// Service is the authenticating service (OCSF `service` object): for
	// the PAM collector, the PAM service name — sshd, sudo, su, login.
	Service *Service `json:"service,omitempty"`
	// TTY is the terminal the client reported (PAM_TTY). slither
	// extension; OCSF authentication has no terminal attribute.
	TTY         string       `json:"x_tty,omitempty"`
	SrcEndpoint *NetEndpoint `json:"src_endpoint,omitempty"`
	DstEndpoint *NetEndpoint `json:"dst_endpoint,omitempty"`
	Session     *Session     `json:"session,omitempty"`
}

type AuthActivity uint8

const (
	AuthActivityUnknown AuthActivity = 0
	AuthActivityLogon   AuthActivity = 1
	AuthActivityLogoff  AuthActivity = 2
	AuthActivityAuthTkt AuthActivity = 3
	AuthActivityServTkt AuthActivity = 4
	AuthActivityOther   AuthActivity = 99
)

// Service is the OCSF `service` object, reduced to what the agent knows.
type Service struct {
	Name string `json:"name,omitempty"`
	UID  string `json:"uid,omitempty"`
}

type Session struct {
	UID      string   `json:"uid,omitempty"`
	CreatedT TimeOCSF `json:"created_time,omitempty"`
	IsRemote bool     `json:"is_remote,omitempty"`
}

func (a *Authentication) ClassID() ClassID { return ClassAuthentication }

func (a *Authentication) Validate() error {
	if a.ClassUID != ClassAuthentication {
		return fmt.Errorf("%w: class_uid %d != %d", ErrInvalidEvent, a.ClassUID, ClassAuthentication)
	}
	if a.ActivityID == AuthActivityUnknown {
		return fmt.Errorf("%w: activity_id required", ErrInvalidEvent)
	}
	if a.Time == 0 {
		return fmt.Errorf("%w: time required", ErrInvalidEvent)
	}
	if a.User.Name == "" && a.User.UID == "" {
		return fmt.Errorf("%w: user.name or user.uid required", ErrInvalidEvent)
	}
	return nil
}
