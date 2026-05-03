package extsdk

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"

	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
)

func TestRoundTrip_AgentToExtension_LiveQueryRequest(t *testing.T) {
	in := &pb.AgentToExtension{
		Payload: &pb.AgentToExtension_LiveQueryRequest{
			LiveQueryRequest: &pb.LiveQueryRequest{
				QueryId:     "q-123",
				Sql:         "SELECT pid, name FROM processes",
				MaxRows:     5000,
				TimeoutSecs: 30,
			},
		},
	}
	var buf bytes.Buffer
	if err := WriteAgentToExtension(&buf, in); err != nil {
		t.Fatalf("write: %v", err)
	}
	out, err := ReadAgentToExtension(&buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	got := out.GetLiveQueryRequest()
	if got == nil {
		t.Fatalf("payload not LiveQueryRequest: %T", out.Payload)
	}
	if got.QueryId != "q-123" || got.Sql != "SELECT pid, name FROM processes" || got.MaxRows != 5000 || got.TimeoutSecs != 30 {
		t.Errorf("round-trip mismatch: %+v", got)
	}
}

func TestRoundTrip_ExtensionToAgent_Hello(t *testing.T) {
	in := &pb.ExtensionToAgent{
		Payload: &pb.ExtensionToAgent_Hello{
			Hello: &pb.Hello{
				Name:    "osquery",
				Version: "0.1.0",
				Capabilities: []pb.Capability{
					pb.Capability_CAPABILITY_OCSF_EMIT,
					pb.Capability_CAPABILITY_LIVE_QUERY_RESPOND,
				},
			},
		},
	}
	var buf bytes.Buffer
	if err := WriteExtensionToAgent(&buf, in); err != nil {
		t.Fatalf("write: %v", err)
	}
	out, err := ReadExtensionToAgent(&buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	hello := out.GetHello()
	if hello == nil {
		t.Fatalf("payload not Hello: %T", out.Payload)
	}
	if hello.Name != "osquery" || hello.Version != "0.1.0" {
		t.Errorf("hello identity mismatch: %+v", hello)
	}
	if len(hello.Capabilities) != 2 {
		t.Fatalf("capabilities len = %d, want 2", len(hello.Capabilities))
	}
}

func TestRoundTrip_MultipleFramesBackToBack(t *testing.T) {
	// Mirrors the steady-state shape: agent writes several
	// AgentToExtension envelopes onto the socket; extension reads
	// them sequentially.
	var buf bytes.Buffer
	for i := 0; i < 5; i++ {
		req := &pb.AgentToExtension{
			Payload: &pb.AgentToExtension_LiveQueryRequest{
				LiveQueryRequest: &pb.LiveQueryRequest{QueryId: "q", MaxRows: uint32(i)},
			},
		}
		if err := WriteAgentToExtension(&buf, req); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	for i := 0; i < 5; i++ {
		out, err := ReadAgentToExtension(&buf)
		if err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		if out.GetLiveQueryRequest().MaxRows != uint32(i) {
			t.Errorf("read %d: MaxRows = %d, want %d", i, out.GetLiveQueryRequest().MaxRows, i)
		}
	}
	// Sixth read should return EOF cleanly.
	if _, err := ReadAgentToExtension(&buf); !errors.Is(err, io.EOF) {
		t.Errorf("post-stream read = %v, want io.EOF", err)
	}
}

func TestReadFrame_OversizedClaim(t *testing.T) {
	// Hand-craft a varint claiming 17 MiB — over MaxMessageSize.
	var lenBuf [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(lenBuf[:], uint64(MaxMessageSize+1))
	r := bytes.NewReader(lenBuf[:n])
	if _, err := ReadAgentToExtension(r); err == nil || !strings.Contains(err.Error(), "MaxMessageSize") {
		t.Errorf("oversized frame should be rejected; got %v", err)
	}
}

func TestReadFrame_TruncatedPayload(t *testing.T) {
	// Varint claims 100 bytes; we supply 10. Read should fail with a
	// non-nil error mentioning the payload read.
	var lenBuf [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(lenBuf[:], 100)
	frame := append(lenBuf[:n], make([]byte, 10)...)
	r := bytes.NewReader(frame)
	_, err := ReadAgentToExtension(r)
	if err == nil {
		t.Fatal("truncated payload should fail")
	}
	if !strings.Contains(err.Error(), "read payload") {
		t.Errorf("error should mention payload read; got %v", err)
	}
}

func TestReadFrame_EmptyReaderReturnsEOF(t *testing.T) {
	r := bytes.NewReader(nil)
	_, err := ReadAgentToExtension(r)
	if !errors.Is(err, io.EOF) {
		t.Errorf("empty reader = %v, want io.EOF", err)
	}
}

func TestReadFrame_VarintTooLong(t *testing.T) {
	// All-continuation-bit-set stream: ten 0xff bytes, every byte
	// claims "more bytes follow". Loop exhausts MaxVarintLen64 without
	// finding a terminator and rejects.
	r := bytes.NewReader(bytes.Repeat([]byte{0xff}, 10))
	_, err := ReadAgentToExtension(r)
	if err == nil || !strings.Contains(err.Error(), "too long") {
		t.Errorf("over-long varint should be rejected; got %v", err)
	}
}

func TestReadFrame_VarintOverflowOn10thByte(t *testing.T) {
	// Nine continuation bytes followed by 0x02 — the 10th byte fits
	// the varint, but the high bits would push the result past uint64.
	// Must reject via the overflow guard, not silently truncate.
	frame := append(bytes.Repeat([]byte{0xff}, 9), 0x02)
	r := bytes.NewReader(frame)
	_, err := ReadAgentToExtension(r)
	if err == nil || !strings.Contains(err.Error(), "overflow") {
		t.Errorf("uint64-overflow varint should be rejected; got %v", err)
	}
}

func TestRoundTrip_SnapshotChunkPreservesBinaryPayload(t *testing.T) {
	// Snapshot chunks are arbitrary bytes — make sure marshal/unmarshal
	// preserves a payload with embedded NULs and high bits set.
	payload := []byte{0x00, 0x01, 0xff, 0x7f, 0x80, 0xfe, 0x00, 0xc0}
	in := &pb.ExtensionToAgent{
		Payload: &pb.ExtensionToAgent_SnapshotChunk{
			SnapshotChunk: &pb.SnapshotChunk{
				SnapshotId: "snap-1",
				Sha256:     "deadbeef",
				Bytes:      payload,
			},
		},
	}
	var buf bytes.Buffer
	if err := WriteExtensionToAgent(&buf, in); err != nil {
		t.Fatalf("write: %v", err)
	}
	out, err := ReadExtensionToAgent(&buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	got := out.GetSnapshotChunk()
	if got == nil {
		t.Fatalf("payload not SnapshotChunk: %T", out.Payload)
	}
	if !bytes.Equal(got.Bytes, payload) {
		t.Errorf("payload bytes diverged: got %v, want %v", got.Bytes, payload)
	}
}
