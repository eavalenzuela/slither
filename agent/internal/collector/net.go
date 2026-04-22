//go:build linux

package collector

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	bpfpkg "github.com/t3rmit3/slither/agent/internal/bpf"
	"github.com/t3rmit3/slither/agent/internal/pipeline"
	"github.com/t3rmit3/slither/agent/internal/telemetry"
)

// netCollector loads net.bpf.c, attaches its three kprobes (one of them as a
// kretprobe for inet_csk_accept), and drains the shared ringbuffer into
// RawNetEvent records. Addresses are emitted as raw bytes + family; the
// enricher handles v4/v6 stringification.
type netCollector struct {
	out   chan<- pipeline.RawNetEvent
	telem *telemetry.Counters
}

func newNetCollector(out chan<- pipeline.RawNetEvent, telem *telemetry.Counters) Collector {
	return &netCollector{out: out, telem: telem}
}

func (n *netCollector) Name() string { return "net" }

func (n *netCollector) Run(ctx context.Context) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("net: rlimit: %w", err)
	}

	var objs bpfpkg.NetObjects
	if err := bpfpkg.LoadNetObjects(&objs, nil); err != nil {
		return fmt.Errorf("net: load bpf objects: %w", err)
	}
	defer objs.Close()

	var links []link.Link
	defer func() {
		for _, l := range links {
			_ = l.Close()
		}
	}()

	kp := func(symbol string, prog *ebpf.Program) error {
		l, err := link.Kprobe(symbol, prog, nil)
		if err != nil {
			return fmt.Errorf("net: attach kprobe/%s: %w", symbol, err)
		}
		links = append(links, l)
		return nil
	}
	krp := func(symbol string, prog *ebpf.Program) error {
		l, err := link.Kretprobe(symbol, prog, nil)
		if err != nil {
			return fmt.Errorf("net: attach kretprobe/%s: %w", symbol, err)
		}
		links = append(links, l)
		return nil
	}

	if err := kp("tcp_connect", objs.HandleTcpConnect); err != nil {
		return err
	}
	if err := krp("inet_csk_accept", objs.HandleInetCskAccept); err != nil {
		return err
	}
	if err := kp("udp_sendmsg", objs.HandleUdpSendmsg); err != nil {
		return err
	}

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return fmt.Errorf("net: open ringbuf: %w", err)
	}
	defer rd.Close()

	go func() {
		<-ctx.Done()
		_ = rd.Close()
	}()

	return n.drain(ctx, rd)
}

func (n *netCollector) drain(ctx context.Context, rd *ringbuf.Reader) error {
	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return ctx.Err()
			}
			return fmt.Errorf("net: ringbuf read: %w", err)
		}

		var raw bpfpkg.NetNetEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &raw); err != nil {
			n.telem.IncDrops()
			continue
		}
		n.telem.IncEvents()

		select {
		case n.out <- decodeNetEvent(raw):
		case <-ctx.Done():
			return ctx.Err()
		default:
			n.telem.IncDrops()
		}
	}
}

func decodeNetEvent(r bpfpkg.NetNetEvent) pipeline.RawNetEvent {
	ev := pipeline.RawNetEvent{
		Kind:      decodeNetKind(r.Kind),
		PID:       r.Pid,
		Proto:     r.Proto,
		SrcAddr:   formatAddr(r.Family, r.Saddr),
		SrcPort:   r.Sport,
		DstAddr:   formatAddr(r.Family, r.Daddr),
		DstPort:   r.Dport,
		Timestamp: time.Now(),
	}
	return ev
}

func decodeNetKind(k uint32) pipeline.RawNetKind {
	// Values mirror SL_NET_* in net.bpf.c.
	switch k {
	case 1:
		return pipeline.NetTCPConnect
	case 2:
		return pipeline.NetTCPAccept
	case 3:
		return pipeline.NetUDPSend
	default:
		return pipeline.NetUnknown
	}
}

// formatAddr renders raw sock address bytes as a printable string keyed on
// the protocol family. AF_INET = 2; AF_INET6 = 10. Anything else returns ""
// so the enricher can skip it cleanly.
func formatAddr(family uint16, raw [16]uint8) string {
	switch family {
	case 2: // AF_INET
		return fmt.Sprintf("%d.%d.%d.%d", raw[0], raw[1], raw[2], raw[3])
	case 10: // AF_INET6
		return formatIPv6(raw)
	}
	return ""
}

// formatIPv6 prints the 16-byte big-endian IPv6 address in canonical
// colon-hex form. This is a plain printer — no RFC 5952 zero-run compression;
// downstream consumers parse without trouble and the stringified form is
// unambiguous.
func formatIPv6(b [16]uint8) string {
	hex := []byte("0123456789abcdef")
	out := make([]byte, 0, 39)
	for i := 0; i < 16; i += 2 {
		if i > 0 {
			out = append(out, ':')
		}
		w := uint16(b[i])<<8 | uint16(b[i+1])
		// Emit 4 hex digits without leading-zero trimming. RFC 5952-correct
		// compression happens in the enricher only if we need it later.
		out = append(out,
			hex[(w>>12)&0xf],
			hex[(w>>8)&0xf],
			hex[(w>>4)&0xf],
			hex[w&0xf],
		)
	}
	return string(out)
}
