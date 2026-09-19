//go:build linux

package collector

import (
	"testing"

	bpfpkg "github.com/t3rmit3/slither/agent/internal/bpf"
	"github.com/t3rmit3/slither/agent/internal/pipeline"
)

func TestDecodeDNSEventCopiesPayload(t *testing.T) {
	r := &bpfpkg.DnsDnsEvent{}
	r.Kind, r.Tgid, r.Uid, r.Family, r.Sport, r.Dport, r.PayloadLen = 1, 700, 1000, 4, 41000, 53, 5
	r.Saddr = [16]uint8{10, 0, 0, 5}
	r.Daddr = [16]uint8{127, 0, 0, 53}
	copy(r.Payload[:], []byte{0xbe, 0xef, 1, 0, 0, 99, 99})
	fill(r.Comm[:], "curl")

	ev := decodeDNSEvent(r)
	if ev.Kind != pipeline.DNSQuery || ev.PID != 700 || ev.UID != 1000 || ev.SrcAddr != "10.0.0.5" || ev.DstAddr != "127.0.0.53" || ev.SrcPort != 41000 || ev.DstPort != 53 || ev.Comm != "curl" {
		t.Errorf("decoded %+v", ev)
	}
	if len(ev.Payload) != 5 || ev.Payload[0] != 0xbe || ev.Payload[4] != 0 {
		t.Errorf("payload = %x, want the first 5 bytes only", ev.Payload)
	}
	// The copy must not alias the record.
	r.Payload[0] = 0
	if ev.Payload[0] != 0xbe {
		t.Error("payload aliases the ring record")
	}

	r.Family, r.PayloadLen = 6, 5000
	r.Daddr = [16]uint8{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	ev = decodeDNSEvent(r)
	if ev.DstAddr != "2001:0db8:0000:0000:0000:0000:0000:0001" {
		t.Errorf("v6 dst = %q", ev.DstAddr)
	}
	if len(ev.Payload) != len(r.Payload) {
		t.Errorf("oversized payload_len must clamp to the record: %d", len(ev.Payload))
	}
	r.Kind = 2
	if decodeDNSEvent(r).Kind != pipeline.DNSResponse {
		t.Error("kind 2 → response")
	}
	r.Kind = 9
	if decodeDNSEvent(r).Kind != pipeline.DNSUnknown {
		t.Error("kind 9 → unknown")
	}
}
