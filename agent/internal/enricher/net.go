package enricher

import (
	"context"

	"github.com/t3rmit3/slither/agent/internal/pipeline"
	"github.com/t3rmit3/slither/pkg/ocsf"
)

// handleNet converts a raw network-event into an OCSF NetworkActivity and
// emits it on the enricher output. The actor process (if cached) is stamped
// so downstream rules can key on process identity alongside endpoint fields.
func (e *enricher) handleNet(ctx context.Context, raw pipeline.RawNetEvent) {
	if raw.Kind == pipeline.NetUnknown {
		e.telem.IncDrops()
		return
	}

	ent, ok := e.cache.get(raw.PID)
	if !ok {
		ent = procEntry{pid: raw.PID}
		if comm := e.proc.comm(raw.PID); comm != "" {
			ent.comm = comm
		}
		if exe := e.proc.exe(raw.PID); exe != "" {
			ent.exe = exe
		}
	}

	ev := e.buildNetOCSF(raw, ent)

	select {
	case e.out <- ev:
	case <-ctx.Done():
	default:
		e.telem.IncDrops()
	}
}

func (e *enricher) buildNetOCSF(raw pipeline.RawNetEvent, ent procEntry) *ocsf.NetworkActivity {
	username := e.users.Name(ent.uid)
	actorProc := processFromEntry(ent, username)

	activity := netActivityID(raw.Kind)
	direction, directionID := netDirection(raw.Kind)
	ts := raw.Timestamp.UnixMilli()

	// For tcp_accept the kernel-emitted sock's "dst" is the remote client.
	// Presenting it as src for the inbound OCSF event keeps "src = initiator,
	// dst = listener" consistent with outbound events.
	src := ocsf.NetEndpoint{IP: raw.SrcAddr, Port: raw.SrcPort}
	dst := ocsf.NetEndpoint{IP: raw.DstAddr, Port: raw.DstPort}
	if raw.Kind == pipeline.NetTCPAccept {
		src, dst = dst, src
	}

	ev := &ocsf.NetworkActivity{
		Metadata: ocsf.Metadata{
			Version:   ocsf.Version,
			Product:   slitherProduct(),
			LogName:   "net",
			EventCode: netEventCode(raw.Kind),
			OriginalT: ts,
		},
		ClassUID:   ocsf.ClassNetworkActivity,
		ClassName:  ocsf.ClassNetworkActivity.String(),
		ActivityID: activity,
		TypeUID:    uint64(ocsf.ClassNetworkActivity)*100 + uint64(activity),
		Severity:   ocsf.SeverityInformational,
		Time:       ocsf.TimeOCSF(ts),
		Device:     e.opts.Device,
		Actor: ocsf.Actor{
			Process: *actorProc,
			User: ocsf.User{
				UID:  actorProc.UID,
				Name: username,
				Type: userType(ent.uid),
			},
		},
		Connection: ocsf.NetConnectionInfo{
			Protocol:  protoName(raw.Proto),
			ProtoNum:  raw.Proto,
			Direction: direction,
			DirID:     directionID,
		},
		SrcEndpoint: src,
		DstEndpoint: dst,
	}
	return ev
}

func netActivityID(k pipeline.RawNetKind) ocsf.NetActivityID {
	switch k {
	case pipeline.NetTCPConnect, pipeline.NetTCPAccept:
		return ocsf.NetActivityOpen
	case pipeline.NetUDPSend:
		return ocsf.NetActivityTraffic
	default:
		return ocsf.NetActivityOther
	}
}

// netDirection returns the OCSF direction label + id. inbound = 1, outbound = 2
// per the OCSF spec; lateral isn't classifiable from a single sock observation
// so we don't emit it here.
func netDirection(k pipeline.RawNetKind) (string, uint8) {
	switch k {
	case pipeline.NetTCPConnect, pipeline.NetUDPSend:
		return "outbound", 2
	case pipeline.NetTCPAccept:
		return "inbound", 1
	default:
		return "", 0
	}
}

func netEventCode(k pipeline.RawNetKind) string {
	switch k {
	case pipeline.NetTCPConnect:
		return "tcp_connect"
	case pipeline.NetTCPAccept:
		return "tcp_accept"
	case pipeline.NetUDPSend:
		return "udp_send"
	default:
		return "unknown"
	}
}

func protoName(p uint8) string {
	switch p {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 1:
		return "icmp"
	}
	return ""
}
