package enricher

import (
	"context"
	"net/netip"
	"strconv"

	"github.com/t3rmit3/slither/agent/internal/pipeline"
	"github.com/t3rmit3/slither/pkg/ocsf"
)

// handleAuth converts a raw libpam event into an OCSF Authentication
// (3002) event. The actor is the PAM client process (sshd, sudo, su,
// login) resolved through the process cache; the subject is the account
// PAM was asked about, which is a different thing — for sudo the actor
// user is the invoker and the PAM user is whoever sudo is authenticating,
// normally the same person, but not when targetpw/rootpw is configured.
func (e *enricher) handleAuth(ctx context.Context, raw pipeline.RawAuthEvent) {
	if raw.Kind == pipeline.AuthUnknown {
		e.telem.IncDrops()
		return
	}

	ent, ok := e.cache.get(raw.PID)
	if !ok {
		// Not in the cache: sshd's per-connection monitor forks from a
		// long-lived parent that predates the agent, and login/getty may
		// too. The BPF record carries uid + comm, so the actor is still
		// identifiable; exe is backfilled from /proc when it is cheap.
		ent = procEntry{pid: raw.PID, uid: raw.UID, comm: raw.Comm}
		if exe := e.proc.exe(raw.PID); exe != "" {
			ent.exe = exe
		}
	}
	if ent.comm == "" {
		ent.comm = raw.Comm
	}

	ev := e.buildAuthOCSF(raw, ent)

	select {
	case e.out <- ev:
	case <-ctx.Done():
	default:
		e.telem.IncDropEnricher()
	}
}

func (e *enricher) buildAuthOCSF(raw pipeline.RawAuthEvent, ent procEntry) *ocsf.Authentication {
	actorName := e.users.Name(ent.uid)
	actorProc := processFromEntry(ent, actorName)

	activity := authActivityID(raw.Kind)
	status, statusID := authStatus(raw.Result)
	logonType, logonTypeID := authLogonType(raw)
	ts := raw.Timestamp.UnixMilli()

	ev := &ocsf.Authentication{
		Metadata: ocsf.Metadata{
			Version:   ocsf.Version,
			Product:   slitherProduct(),
			LogName:   "auth",
			EventCode: authEventCode(raw.Kind),
			UID:       ocsf.NewUID(),
			OriginalT: ts,
		},
		ClassUID:   ocsf.ClassAuthentication,
		ClassName:  ocsf.ClassAuthentication.String(),
		ActivityID: activity,
		TypeUID:    uint64(ocsf.ClassAuthentication)*100 + uint64(activity),
		Severity:   ocsf.SeverityInformational,
		Time:       ocsf.TimeOCSF(ts),
		Device:     e.opts.Device,
		Actor: ocsf.Actor{
			Process: *actorProc,
			User: ocsf.User{
				UID:  actorProc.UID,
				Name: actorName,
				Type: userType(ent.uid),
			},
		},
		User: ocsf.User{
			Name: raw.User,
			Type: authUserType(raw.User),
		},
		Status:       status,
		StatusID:     statusID,
		StatusCode:   strconv.FormatInt(int64(raw.Result), 10),
		StatusDetail: pamResultName(raw.Result),
		AuthProto:    "pam",
		LogonType:    logonType,
		LogonTypeID:  logonTypeID,
		TTY:          raw.TTY,
	}
	if raw.Service != "" {
		ev.Service = &ocsf.Service{Name: raw.Service}
	}
	if raw.RemoteHost != "" {
		ev.SrcEndpoint = authEndpoint(raw.RemoteHost)
		ev.Session = &ocsf.Session{IsRemote: true}
	}
	return ev
}

// authActivityID maps the libpam call onto OCSF activity: a credential
// check and a session open are both "Logon" (1) — the distinction lives
// in metadata.event_code, which rules bind as EventCode — and a session
// close is "Logoff" (2).
func authActivityID(k pipeline.RawAuthKind) ocsf.AuthActivity {
	switch k {
	case pipeline.AuthAttempt, pipeline.AuthSessionOpen:
		return ocsf.AuthActivityLogon
	case pipeline.AuthSessionClose:
		return ocsf.AuthActivityLogoff
	default:
		return ocsf.AuthActivityOther
	}
}

func authEventCode(k pipeline.RawAuthKind) string {
	switch k {
	case pipeline.AuthAttempt:
		return "auth_attempt"
	case pipeline.AuthSessionOpen:
		return "session_open"
	case pipeline.AuthSessionClose:
		return "session_close"
	default:
		return "unknown"
	}
}

// authStatus maps a PAM return code onto OCSF status (1 Success,
// 2 Failure). Every non-zero code is a failure from the caller's point
// of view — the session did not open, the credential was not accepted —
// even when the reason is a module error rather than a bad password;
// status_code/status_detail keep the reason.
func authStatus(result int32) (label string, id uint8) {
	if result == 0 {
		return "Success", 1
	}
	return "Failure", 2
}

// authLogonType derives OCSF logon_type from what PAM saw: a remote host
// means Remote Interactive (10), a tty without one means Interactive (2),
// and neither means the client was a service or a privilege broker
// (sudo, su, polkit) rather than a login — Other (99) with the PAM
// service name as the label, which is what an operator wants to read.
func authLogonType(raw pipeline.RawAuthEvent) (label string, id uint8) {
	switch {
	case raw.RemoteHost != "":
		return "Remote Interactive", 10
	case raw.TTY != "" && raw.Service != "sudo" && raw.Service != "su" && raw.Service != "su-l":
		return "Interactive", 2
	default:
		if raw.Service != "" {
			return raw.Service, 99
		}
		return "Other", 99
	}
}

func authUserType(name string) string {
	if name == "root" {
		return "Admin"
	}
	if name == "" {
		return ""
	}
	return "User"
}

// authEndpoint places PAM_RHOST in ip or hostname depending on what the
// client set. sshd sets a numeric address; login-over-telnet-style
// clients and some PAM modules set a name.
func authEndpoint(rhost string) *ocsf.NetEndpoint {
	if addr, err := netip.ParseAddr(rhost); err == nil {
		return &ocsf.NetEndpoint{IP: addr.Unmap().String()}
	}
	return &ocsf.NetEndpoint{Hostname: rhost}
}

// pamResultName returns the Linux-PAM symbolic name for a return code.
// Numbering is from security/_pam_types.h and has been stable since
// Linux-PAM 0.x; an unknown code renders as PAM_<n>.
func pamResultName(code int32) string {
	if int(code) >= 0 && int(code) < len(pamResultNames) {
		return pamResultNames[code]
	}
	return "PAM_" + strconv.FormatInt(int64(code), 10)
}

var pamResultNames = [...]string{
	"PAM_SUCCESS",
	"PAM_OPEN_ERR",
	"PAM_SYMBOL_ERR",
	"PAM_SERVICE_ERR",
	"PAM_SYSTEM_ERR",
	"PAM_BUF_ERR",
	"PAM_PERM_DENIED",
	"PAM_AUTH_ERR",
	"PAM_CRED_INSUFFICIENT",
	"PAM_AUTHINFO_UNAVAIL",
	"PAM_USER_UNKNOWN",
	"PAM_MAXTRIES",
	"PAM_NEW_AUTHTOK_REQD",
	"PAM_ACCT_EXPIRED",
	"PAM_SESSION_ERR",
	"PAM_CRED_UNAVAIL",
	"PAM_CRED_EXPIRED",
	"PAM_CRED_ERR",
	"PAM_NO_MODULE_DATA",
	"PAM_CONV_ERR",
	"PAM_AUTHTOK_ERR",
	"PAM_AUTHTOK_RECOVERY_ERR",
	"PAM_AUTHTOK_LOCK_BUSY",
	"PAM_AUTHTOK_DISABLE_AGING",
	"PAM_TRY_AGAIN",
	"PAM_IGNORE",
	"PAM_ABORT",
	"PAM_AUTHTOK_EXPIRED",
	"PAM_MODULE_UNKNOWN",
	"PAM_BAD_ITEM",
	"PAM_CONV_AGAIN",
	"PAM_INCOMPLETE",
}
