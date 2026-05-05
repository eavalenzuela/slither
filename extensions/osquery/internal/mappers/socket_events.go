package mappers

import (
	"strings"

	"github.com/t3rmit3/slither/pkg/ocsf"
)

// SocketEvents maps osquery's socket_events table (audit-driven
// connect/bind observations). One row = one OCSF NetworkActivity.
//
// Schema reference (osquery 5.x):
//
//	action ("connect" / "bind"), pid, path, fd, auid, uid, family,
//	protocol, local_address, remote_address, local_port, remote_port,
//	socket, time, status.
//
// connect → NetActivityOpen, bind → NetActivityListen, anything else
// falls through to NetActivityOther.
func SocketEvents(row Row) (ocsf.Event, error) {
	activity := ocsf.NetActivityOther
	direction := "outbound"
	switch row["action"] {
	case "connect":
		activity = ocsf.NetActivityOpen
	case "bind":
		activity = ocsf.NetActivityListen
		direction = "inbound"
	}
	proto := strings.ToLower(row["protocol"])
	switch proto {
	case "":
		// osquery reports the IANA protocol number when the symbolic
		// form isn't filled in. Map the two we care about.
		switch row["protocol_num"] {
		case "6":
			proto = "tcp"
		case "17":
			proto = "udp"
		case "1":
			proto = "icmp"
		}
	case "6":
		proto = "tcp"
	case "17":
		proto = "udp"
	case "1":
		proto = "icmp"
	}

	pid := atoiU32(row["pid"])
	ev := &ocsf.NetworkActivity{
		ClassUID:   ocsf.ClassNetworkActivity,
		ClassName:  ocsf.ClassNetworkActivity.String(),
		ActivityID: activity,
		Severity:   ocsf.SeverityInformational,
		Actor: ocsf.Actor{
			Process: ocsf.Process{
				PID:  pid,
				Name: row["path"],
			},
			User: ocsf.User{UID: row["uid"]},
		},
		Connection: ocsf.NetConnectionInfo{
			Protocol:  proto,
			Direction: direction,
		},
		SrcEndpoint: ocsf.NetEndpoint{
			IP:   row["local_address"],
			Port: atoiU16(row["local_port"]),
		},
		DstEndpoint: ocsf.NetEndpoint{
			IP:   row["remote_address"],
			Port: atoiU16(row["remote_port"]),
		},
	}
	return ev, nil
}
