//go:build linux

package collector

import "testing"

func TestFormatAddrIPv4(t *testing.T) {
	addr := [16]uint8{10, 0, 0, 5}
	if got := formatAddr(2, addr); got != "10.0.0.5" {
		t.Errorf("formatAddr v4 = %q, want 10.0.0.5", got)
	}
}

func TestFormatAddrIPv6(t *testing.T) {
	// 2001:0db8:0000:0000:0000:0000:0000:0001
	addr := [16]uint8{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	want := "2001:0db8:0000:0000:0000:0000:0000:0001"
	if got := formatAddr(10, addr); got != want {
		t.Errorf("formatAddr v6 = %q, want %q", got, want)
	}
}

func TestFormatAddrUnknownFamily(t *testing.T) {
	if got := formatAddr(99, [16]uint8{1}); got != "" {
		t.Errorf("formatAddr unknown family = %q, want empty", got)
	}
}

func TestDecodeNetKind(t *testing.T) {
	cases := map[uint32]string{
		0: "unknown",
		1: "tcp_connect",
		2: "tcp_accept",
		3: "udp_send",
		9: "unknown",
	}
	for raw, wantCat := range cases {
		got := decodeNetKind(raw)
		// Spot-check via the zero-value comparison — the enum has String()-less
		// values in the pipeline package, so we roundtrip through a label map
		// in the test to keep the assertion readable.
		label := map[uint8]string{0: "unknown", 1: "tcp_connect", 2: "tcp_accept", 3: "udp_send"}[uint8(got)]
		if label != wantCat {
			t.Errorf("decodeNetKind(%d) label = %q, want %q", raw, label, wantCat)
		}
	}
}
