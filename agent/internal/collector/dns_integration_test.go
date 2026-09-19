//go:build linux && integration

package collector

import (
	"net"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/t3rmit3/slither/agent/internal/pipeline"
)

// TestDNSCollector_QueryObserved attaches dns.bpf.c and sends one DNS
// query datagram to 127.0.0.1:53. Nothing needs to be listening: the
// kprobe on ip_send_skb fires for the outbound datagram either way, and
// the payload must come back with the name intact.
func TestDNSCollector_QueryObserved(t *testing.T) {
	requirePrivileged(t)

	out := make(chan pipeline.RawDNSEvent, 1024)
	c := newDNSCollector(out, newCounters())
	_, stop := startCollector(t, c)
	defer stop()

	time.Sleep(200 * time.Millisecond)

	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 0x5117, RecursionDesired: true})
	_ = b.StartQuestions()
	_ = b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName("slither-integration.example."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	payload, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}

	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53})
	if err != nil {
		t.Fatalf("dial udp: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("send: %v", err)
	}

	ev, ok := waitForEvent(t, out, func(e pipeline.RawDNSEvent) bool {
		if e.Kind != pipeline.DNSQuery || e.DstPort != 53 || e.DstAddr != "127.0.0.1" {
			return false
		}
		var p dnsmessage.Parser
		if _, err := p.Start(e.Payload); err != nil {
			return false
		}
		q, err := p.Question()
		return err == nil && q.Name.String() == "slither-integration.example."
	}, 3*time.Second)
	if !ok {
		t.Fatal("no dns query event for slither-integration.example within 3s")
	}
	if ev.PID == 0 || len(ev.Payload) != len(payload) {
		t.Errorf("event = pid %d payload %d bytes (sent %d)", ev.PID, len(ev.Payload), len(payload))
	}
}
