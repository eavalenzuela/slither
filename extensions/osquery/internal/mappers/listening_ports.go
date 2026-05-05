package mappers

import (
	"strings"

	"github.com/t3rmit3/slither/pkg/ocsf"
)

// ListeningPorts maps osquery's listening_ports inventory table (a
// snapshot of every socket currently in LISTEN state). Each row
// becomes a NetworkActivity{NetActivityListen}.
//
// Schema reference (osquery 5.x):
//
//	pid, port, protocol, family, address, fd, socket, path, net_namespace.
//
// Inventory tables don't have an action column — every row in the
// snapshot represents an "as-of-now" observation. The poll loop emits
// the full snapshot every cycle; downstream dedup is the rule
// engine's responsibility.
func ListeningPorts(row Row) (ocsf.Event, error) {
	proto := "tcp"
	switch strings.ToLower(row["protocol"]) {
	case "17", "udp":
		proto = "udp"
	case "1", "icmp":
		proto = "icmp"
	}
	pid := atoiU32(row["pid"])
	ev := &ocsf.NetworkActivity{
		ClassUID:   ocsf.ClassNetworkActivity,
		ClassName:  ocsf.ClassNetworkActivity.String(),
		ActivityID: ocsf.NetActivityListen,
		Severity:   ocsf.SeverityInformational,
		Actor: ocsf.Actor{
			Process: ocsf.Process{
				PID:  pid,
				Name: row["path"],
			},
		},
		Connection: ocsf.NetConnectionInfo{
			Protocol:  proto,
			Direction: "inbound",
		},
		SrcEndpoint: ocsf.NetEndpoint{
			IP:   row["address"],
			Port: atoiU16(row["port"]),
		},
	}
	return ev, nil
}
