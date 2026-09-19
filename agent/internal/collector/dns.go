//go:build linux

package collector

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	bpfpkg "github.com/t3rmit3/slither/agent/internal/bpf"
	"github.com/t3rmit3/slither/agent/internal/pipeline"
	"github.com/t3rmit3/slither/agent/internal/telemetry"
)

// dnsCollector loads dns.bpf.c: UDP/53 datagrams read from the socket
// buffer on the IP send path (queries) and the UDP receive path
// (responses), attributed to the sending / receiving process. Parsing
// happens in the enricher.
type dnsCollector struct {
	out   chan<- pipeline.RawDNSEvent
	telem *telemetry.Counters
}

func newDNSCollector(out chan<- pipeline.RawDNSEvent, telem *telemetry.Counters) Collector {
	return &dnsCollector{out: out, telem: telem}
}

func (d *dnsCollector) Name() string { return "dns" }

func (d *dnsCollector) Run(ctx context.Context) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("dns: rlimit: %w", err)
	}

	var objs bpfpkg.DnsObjects
	if lerr := bpfpkg.LoadDnsObjects(&objs, nil); lerr != nil {
		return fmt.Errorf("dns: load bpf objects: %w", lerr)
	}
	defer objs.Close()

	var links []link.Link
	defer func() {
		for _, l := range links {
			_ = l.Close()
		}
	}()

	v4, err := link.Kprobe("ip_send_skb", objs.HandleIpSendSkb, nil)
	if err != nil {
		return fmt.Errorf("dns: attach kprobe/ip_send_skb: %w", err)
	}
	links = append(links, v4)
	// ip6_send_skb lives in the ipv6 module; absent when IPv6 is
	// compiled out or blacklisted, which is a configuration, not a
	// failure.
	if v6, v6err := link.Kprobe("ip6_send_skb", objs.HandleIp6SendSkb, nil); v6err != nil {
		if !errors.Is(v6err, os.ErrNotExist) {
			return fmt.Errorf("dns: attach kprobe/ip6_send_skb: %w", v6err)
		}
		slog.Warn("dns: ip6_send_skb not present; IPv6 DNS queries will not be seen")
	} else {
		links = append(links, v6)
	}
	rx, err := link.Kretprobe("__skb_recv_udp", objs.HandleSkbRecvUdp, nil)
	if err != nil {
		return fmt.Errorf("dns: attach kretprobe/__skb_recv_udp: %w", err)
	}
	links = append(links, rx)

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return fmt.Errorf("dns: open ringbuf: %w", err)
	}
	defer rd.Close()

	go func() {
		<-ctx.Done()
		_ = rd.Close()
	}()

	return d.drain(ctx, rd)
}

func (d *dnsCollector) drain(ctx context.Context, rd *ringbuf.Reader) error {
	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return ctx.Err()
			}
			return fmt.Errorf("dns: ringbuf read: %w", err)
		}

		if len(rec.RawSample) < int(unsafe.Sizeof(bpfpkg.DnsDnsEvent{})) {
			d.telem.IncDrops()
			continue
		}
		raw := (*bpfpkg.DnsDnsEvent)(unsafe.Pointer(&rec.RawSample[0])) //nolint:gosec // G103: deliberate zero-copy decode of BPF-emitted fixed-layout record
		d.telem.IncEvents()

		select {
		case d.out <- decodeDNSEvent(raw):
		case <-ctx.Done():
			return ctx.Err()
		default:
			d.telem.IncDropCollector()
		}
	}
}

// decodeDNSEvent copies the payload out of the ring record — the record
// memory is released back to the ring as soon as Read returns, so the
// slice cannot alias it.
func decodeDNSEvent(r *bpfpkg.DnsDnsEvent) pipeline.RawDNSEvent {
	n := int(r.PayloadLen)
	if n > len(r.Payload) {
		n = len(r.Payload)
	}
	payload := make([]byte, n)
	copy(payload, r.Payload[:n])
	family := uint16(2) // AF_INET for formatAddr
	if r.Family == 6 {
		family = 10
	}
	return pipeline.RawDNSEvent{
		Kind:      decodeDNSKind(r.Kind),
		PID:       r.Tgid,
		UID:       r.Uid,
		SrcAddr:   formatAddr(family, r.Saddr),
		SrcPort:   r.Sport,
		DstAddr:   formatAddr(family, r.Daddr),
		DstPort:   r.Dport,
		Payload:   payload,
		Comm:      cstr(r.Comm[:]),
		Timestamp: time.Now(),
	}
}

func decodeDNSKind(k uint32) pipeline.RawDNSKind {
	// Values mirror SL_DNS_* in dns.bpf.c.
	switch k {
	case 1:
		return pipeline.DNSQuery
	case 2:
		return pipeline.DNSResponse
	default:
		return pipeline.DNSUnknown
	}
}
