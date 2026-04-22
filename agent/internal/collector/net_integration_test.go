//go:build linux && integration

package collector

import (
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/t3rmit3/slither/agent/internal/pipeline"
)

// TestNetCollector_TCPConnectObserved loads net.bpf.c, dials a local listener,
// and asserts the tcp_connect kprobe emits a record for that connection.
func TestNetCollector_TCPConnectObserved(t *testing.T) {
	requirePrivileged(t)

	out := make(chan pipeline.RawNetEvent, 1024)
	c := newNetCollector(out, newCounters())
	_, stop := startCollector(t, c)
	defer stop()

	time.Sleep(200 * time.Millisecond)

	// Loopback listener; the kprobe on tcp_connect fires on the dialer side.
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			_ = conn.Close()
		}
	}()

	_, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}

	conn, err := net.DialTimeout("tcp4", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = conn.Close()

	_, ok := waitForEvent(t, out, func(e pipeline.RawNetEvent) bool {
		return e.Kind == pipeline.NetTCPConnect &&
			e.DstAddr == "127.0.0.1" &&
			e.DstPort == uint16(port)
	}, 3*time.Second)
	if !ok {
		t.Fatalf("no tcp_connect event seen for 127.0.0.1:%d within 3s", port)
	}
}
