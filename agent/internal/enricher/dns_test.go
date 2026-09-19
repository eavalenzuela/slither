package enricher

import (
	"context"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/t3rmit3/slither/agent/internal/pipeline"
	"github.com/t3rmit3/slither/pkg/ocsf"
)

func buildQuery(t *testing.T, name string, typ dnsmessage.Type) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 0xbeef, RecursionDesired: true})
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: typ, Class: dnsmessage.ClassINET}); err != nil {
		t.Fatal(err)
	}
	out, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func buildResponse(t *testing.T, name string, rcode dnsmessage.RCode, answers ...dnsmessage.Resource) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 0xbeef, Response: true, RCode: rcode})
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}); err != nil {
		t.Fatal(err)
	}
	if err := b.StartAnswers(); err != nil {
		t.Fatal(err)
	}
	for _, a := range answers {
		switch body := a.Body.(type) {
		case *dnsmessage.AResource:
			if err := b.AResource(a.Header, *body); err != nil {
				t.Fatal(err)
			}
		case *dnsmessage.CNAMEResource:
			if err := b.CNAMEResource(a.Header, *body); err != nil {
				t.Fatal(err)
			}
		case *dnsmessage.TXTResource:
			if err := b.TXTResource(a.Header, *body); err != nil {
				t.Fatal(err)
			}
		}
	}
	out, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestParseDNSQuery(t *testing.T) {
	m, ok := parseDNS(buildQuery(t, "evil.example.com.", dnsmessage.TypeTXT))
	if !ok {
		t.Fatal("query should parse")
	}
	if m.response || m.name != "evil.example.com" || m.qtype != "TXT" || m.qclass != "IN" || m.opcode != "QUERY" || m.id != 0xbeef {
		t.Errorf("parsed %+v", m)
	}
}

func TestParseDNSResponseAnswers(t *testing.T) {
	hdr := func(name string, typ dnsmessage.Type) dnsmessage.ResourceHeader {
		return dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(name), Type: typ, Class: dnsmessage.ClassINET, TTL: 300}
	}
	payload := buildResponse(t, "www.example.com.", dnsmessage.RCodeSuccess,
		dnsmessage.Resource{Header: hdr("www.example.com.", dnsmessage.TypeCNAME), Body: &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName("edge.example.net.")}},
		dnsmessage.Resource{Header: hdr("edge.example.net.", dnsmessage.TypeA), Body: &dnsmessage.AResource{A: [4]byte{203, 0, 113, 9}}},
		dnsmessage.Resource{Header: hdr("edge.example.net.", dnsmessage.TypeTXT), Body: &dnsmessage.TXTResource{TXT: []string{"v=spf1", "-all"}}},
	)
	m, ok := parseDNS(payload)
	if !ok || !m.response {
		t.Fatalf("response should parse: %+v %v", m, ok)
	}
	if m.rcode != "NOERROR" || m.name != "www.example.com" || len(m.answers) != 3 {
		t.Fatalf("parsed %+v", m)
	}
	if m.answers[0].Type != "CNAME" || m.answers[0].RData != "edge.example.net" || m.answers[0].TTL != 300 {
		t.Errorf("cname = %+v", m.answers[0])
	}
	if m.answers[1].Type != "A" || m.answers[1].RData != "203.0.113.9" {
		t.Errorf("a = %+v", m.answers[1])
	}
	if m.answers[2].Type != "TXT" || m.answers[2].RData != "v=spf1 -all" {
		t.Errorf("txt = %+v", m.answers[2])
	}

	nx, ok := parseDNS(buildResponse(t, "dga-candidate.example.", dnsmessage.RCodeNameError))
	if !ok || nx.rcode != "NXDOMAIN" || nx.rcodeID != 3 || len(nx.answers) != 0 {
		t.Errorf("nxdomain parsed %+v %v", nx, ok)
	}
}

func TestParseDNSRejectsGarbage(t *testing.T) {
	for _, p := range [][]byte{nil, {1, 2, 3}, make([]byte, 12), []byte("this is not a dns message at all, just bytes on port 53")} {
		if _, ok := parseDNS(p); ok {
			t.Errorf("payload %x should not parse", p)
		}
	}
}

func TestDNSNameTables(t *testing.T) {
	if dnsTypeName(dnsmessage.TypeAAAA) != "AAAA" || dnsTypeName(65) != "HTTPS" || dnsTypeName(9999) != "TYPE9999" {
		t.Error("type table drifted")
	}
	if dnsRCodeName(dnsmessage.RCodeRefused) != "REFUSED" || dnsRCodeName(9) != "RCODE9" {
		t.Error("rcode table drifted")
	}
	if dnsClassName(dnsmessage.ClassCHAOS) != "CH" {
		t.Error("class table drifted")
	}
}

func TestHandleDNSQueryBuildsValidOCSF(t *testing.T) {
	e := newTestEnricher(t)
	e.cache.upsert(procEntry{pid: 700, uid: 1000, comm: "curl", exe: "/usr/bin/curl", cmdline: "curl http://evil.example.com/x", container: "abc"})

	e.handleDNS(context.Background(), pipeline.RawDNSEvent{
		Kind: pipeline.DNSQuery, PID: 700, UID: 1000,
		SrcAddr: "10.0.0.5", SrcPort: 41000, DstAddr: "127.0.0.53", DstPort: 53,
		Payload: buildQuery(t, "evil.example.com.", dnsmessage.TypeA), Comm: "curl", Timestamp: time.Unix(100, 0),
	})
	d := (<-e.out).(*ocsf.DnsActivity)
	if err := d.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if d.TypeUID != 400301 || d.Metadata.EventCode != "dns_query" || d.Metadata.LogName != "dns" {
		t.Errorf("type/event_code = %d/%q", d.TypeUID, d.Metadata.EventCode)
	}
	if d.Query.Name != "evil.example.com" || d.Query.Type != "A" || d.Query.Class != "IN" || d.TransactionID != 0xbeef {
		t.Errorf("query = %+v txid=%d", d.Query, d.TransactionID)
	}
	if d.DstEndpoint == nil || d.DstEndpoint.IP != "127.0.0.53" || d.DstEndpoint.Port != 53 || d.SrcEndpoint.Port != 41000 {
		t.Errorf("endpoints = %+v / %+v", d.SrcEndpoint, d.DstEndpoint)
	}
	if d.Actor.Process.PID != 700 || d.Actor.Process.ContainerID != "abc" || d.Actor.User.Name != "alice" {
		t.Errorf("actor = %+v", d.Actor)
	}
	if d.RCode != "" || len(d.Answers) != 0 {
		t.Errorf("a query must carry no response fields: %+v", d)
	}
}

func TestHandleDNSResponseCarriesAnswers(t *testing.T) {
	e := newTestEnricher(t)
	payload := buildResponse(t, "www.example.com.", dnsmessage.RCodeSuccess,
		dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("www.example.com."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AResource{A: [4]byte{203, 0, 113, 9}}},
	)
	e.handleDNS(context.Background(), pipeline.RawDNSEvent{
		Kind: pipeline.DNSResponse, PID: 701, UID: 0, SrcAddr: "127.0.0.53", SrcPort: 53, DstAddr: "10.0.0.5", DstPort: 41000,
		Payload: payload, Comm: "wget", Timestamp: time.Unix(100, 0),
	})
	d := (<-e.out).(*ocsf.DnsActivity)
	if d.ActivityID != ocsf.DnsActivityResponse || d.Metadata.EventCode != "dns_response" || d.RCode != "NOERROR" || d.RCodeID != 0 {
		t.Errorf("response = %+v", d)
	}
	if len(d.Answers) != 1 || d.Answers[0].RData != "203.0.113.9" || d.Answers[0].TTL != 60 {
		t.Errorf("answers = %+v", d.Answers)
	}
	if d.Actor.Process.Name != "wget" {
		t.Errorf("cache miss should still name the actor: %+v", d.Actor.Process)
	}
}

func TestHandleDNSDropsUnparseable(t *testing.T) {
	e := newTestEnricher(t)
	e.handleDNS(context.Background(), pipeline.RawDNSEvent{Kind: pipeline.DNSQuery, PID: 1, Payload: []byte{0, 1, 2}})
	select {
	case ev := <-e.out:
		t.Fatalf("garbage must not emit: %+v", ev)
	default:
	}
}
