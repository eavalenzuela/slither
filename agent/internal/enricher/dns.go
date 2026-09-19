package enricher

import (
	"context"
	"net/netip"
	"strconv"
	"strings"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/t3rmit3/slither/agent/internal/pipeline"
	"github.com/t3rmit3/slither/pkg/ocsf"
)

// handleDNS parses one UDP/53 datagram into an OCSF DnsActivity (4003)
// event. Malformed payloads (not DNS on port 53, truncated past the
// question) are counted as drops rather than emitted half-parsed.
func (e *enricher) handleDNS(ctx context.Context, raw pipeline.RawDNSEvent) {
	if raw.Kind == pipeline.DNSUnknown {
		e.telem.IncDrops()
		return
	}
	msg, ok := parseDNS(raw.Payload)
	if !ok {
		e.telem.IncDrops()
		return
	}

	ent, found := e.cache.get(raw.PID)
	if !found {
		ent = procEntry{pid: raw.PID, uid: raw.UID, comm: raw.Comm}
		if exe := e.proc.exe(raw.PID); exe != "" {
			ent.exe = exe
		}
	}
	if ent.comm == "" {
		ent.comm = raw.Comm
	}

	ev := e.buildDNSOCSF(raw, msg, ent)

	select {
	case e.out <- ev:
	case <-ctx.Done():
	default:
		e.telem.IncDropEnricher()
	}
}

// dnsMessage is the parsed subset of a DNS message the event carries.
type dnsMessage struct {
	id       uint16
	response bool
	opcode   string
	rcode    string
	rcodeID  uint16
	name     string
	qtype    string
	qclass   string
	answers  []ocsf.DnsAnswer
}

// parseDNS decodes header, first question and — for responses — the
// answer section. Additional / authority sections are skipped; EDNS
// OPT records live there and carry nothing a rule keys on.
func parseDNS(payload []byte) (dnsMessage, bool) {
	var p dnsmessage.Parser
	hdr, err := p.Start(payload)
	if err != nil {
		return dnsMessage{}, false
	}
	m := dnsMessage{
		id:       hdr.ID,
		response: hdr.Response,
		opcode:   dnsOpcodeName(hdr.OpCode),
		rcode:    dnsRCodeName(hdr.RCode),
		rcodeID:  uint16(hdr.RCode),
	}
	q, err := p.Question()
	if err == nil {
		m.name = strings.TrimSuffix(q.Name.String(), ".")
		m.qtype = dnsTypeName(q.Type)
		m.qclass = dnsClassName(q.Class)
	} else if err != dnsmessage.ErrSectionDone {
		return dnsMessage{}, false
	}
	if m.name == "" && !m.response {
		// A query with no question is not something a resolver sends.
		return dnsMessage{}, false
	}
	if !m.response {
		return m, true
	}
	if err := p.SkipAllQuestions(); err != nil {
		return m, true
	}
	for {
		rr, err := p.Answer()
		if err != nil {
			break
		}
		if a, ok := dnsAnswerFrom(rr); ok {
			m.answers = append(m.answers, a)
		}
		if len(m.answers) >= 32 {
			break
		}
	}
	return m, true
}

func dnsAnswerFrom(rr dnsmessage.Resource) (ocsf.DnsAnswer, bool) {
	a := ocsf.DnsAnswer{
		Type:  dnsTypeName(rr.Header.Type),
		Class: dnsClassName(rr.Header.Class),
		TTL:   rr.Header.TTL,
	}
	switch b := rr.Body.(type) {
	case *dnsmessage.AResource:
		a.RData = netip.AddrFrom4(b.A).String()
	case *dnsmessage.AAAAResource:
		a.RData = netip.AddrFrom16(b.AAAA).String()
	case *dnsmessage.CNAMEResource:
		a.RData = strings.TrimSuffix(b.CNAME.String(), ".")
	case *dnsmessage.NSResource:
		a.RData = strings.TrimSuffix(b.NS.String(), ".")
	case *dnsmessage.PTRResource:
		a.RData = strings.TrimSuffix(b.PTR.String(), ".")
	case *dnsmessage.MXResource:
		a.RData = strings.TrimSuffix(b.MX.String(), ".")
	case *dnsmessage.SRVResource:
		a.RData = strings.TrimSuffix(b.Target.String(), ".")
	case *dnsmessage.TXTResource:
		a.RData = strings.Join(b.TXT, " ")
		if len(a.RData) > 512 {
			a.RData = a.RData[:512]
		}
	case *dnsmessage.SOAResource:
		a.RData = strings.TrimSuffix(b.NS.String(), ".")
	default:
		// Unknown / unparsed rdata: keep the type, no data.
	}
	return a, true
}

func (e *enricher) buildDNSOCSF(raw pipeline.RawDNSEvent, m dnsMessage, ent procEntry) *ocsf.DnsActivity {
	username := e.users.Name(ent.uid)
	actorProc := processFromEntry(ent, username)

	activity := ocsf.DnsActivityQuery
	code := "dns_query"
	if raw.Kind == pipeline.DNSResponse {
		activity = ocsf.DnsActivityResponse
		code = "dns_response"
	}
	ts := raw.Timestamp.UnixMilli()

	ev := &ocsf.DnsActivity{
		Metadata: ocsf.Metadata{
			Version:   ocsf.Version,
			Product:   slitherProduct(),
			LogName:   "dns",
			EventCode: code,
			UID:       ocsf.NewUID(),
			OriginalT: ts,
		},
		ClassUID:   ocsf.ClassDnsActivity,
		ClassName:  ocsf.ClassDnsActivity.String(),
		ActivityID: activity,
		TypeUID:    uint64(ocsf.ClassDnsActivity)*100 + uint64(activity),
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
		Query: ocsf.DnsQuery{
			Name:   m.name,
			Type:   m.qtype,
			Class:  m.qclass,
			Opcode: m.opcode,
		},
		SrcEndpoint:   &ocsf.NetEndpoint{IP: raw.SrcAddr, Port: raw.SrcPort},
		DstEndpoint:   &ocsf.NetEndpoint{IP: raw.DstAddr, Port: raw.DstPort},
		TransactionID: m.id,
	}
	if raw.Kind == pipeline.DNSResponse {
		ev.RCode = m.rcode
		ev.RCodeID = m.rcodeID
		ev.Answers = m.answers
	}
	return ev
}

func dnsOpcodeName(op dnsmessage.OpCode) string {
	switch op {
	case 0:
		return "QUERY"
	case 1:
		return "IQUERY"
	case 2:
		return "STATUS"
	case 4:
		return "NOTIFY"
	case 5:
		return "UPDATE"
	}
	return "OPCODE" + strconv.Itoa(int(op))
}

func dnsRCodeName(rc dnsmessage.RCode) string {
	switch rc {
	case dnsmessage.RCodeSuccess:
		return "NOERROR"
	case dnsmessage.RCodeFormatError:
		return "FORMERR"
	case dnsmessage.RCodeServerFailure:
		return "SERVFAIL"
	case dnsmessage.RCodeNameError:
		return "NXDOMAIN"
	case dnsmessage.RCodeNotImplemented:
		return "NOTIMP"
	case dnsmessage.RCodeRefused:
		return "REFUSED"
	}
	return "RCODE" + strconv.Itoa(int(rc))
}

// dnsTypeName covers the record types that matter for detection; the
// rest render as TYPE<n>, which is what dig prints too.
func dnsTypeName(t dnsmessage.Type) string {
	switch t {
	case dnsmessage.TypeA:
		return "A"
	case dnsmessage.TypeNS:
		return "NS"
	case dnsmessage.TypeCNAME:
		return "CNAME"
	case dnsmessage.TypeSOA:
		return "SOA"
	case dnsmessage.TypePTR:
		return "PTR"
	case dnsmessage.TypeMX:
		return "MX"
	case dnsmessage.TypeTXT:
		return "TXT"
	case dnsmessage.TypeAAAA:
		return "AAAA"
	case dnsmessage.TypeSRV:
		return "SRV"
	case dnsmessage.TypeOPT:
		return "OPT"
	case dnsmessage.TypeAXFR:
		return "AXFR"
	case dnsmessage.TypeALL:
		return "ANY"
	case 65:
		return "HTTPS"
	case 64:
		return "SVCB"
	case 35:
		return "NAPTR"
	case 43:
		return "DS"
	case 46:
		return "RRSIG"
	case 48:
		return "DNSKEY"
	case 257:
		return "CAA"
	}
	return "TYPE" + strconv.Itoa(int(t))
}

func dnsClassName(c dnsmessage.Class) string {
	switch c {
	case dnsmessage.ClassINET:
		return "IN"
	case dnsmessage.ClassCHAOS:
		return "CH"
	case dnsmessage.ClassANY:
		return "ANY"
	}
	return "CLASS" + strconv.Itoa(int(c))
}
