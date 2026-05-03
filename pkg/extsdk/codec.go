// Package extsdk holds the agent↔extension wire-format helpers shared
// by the agent's supervisor (Phase 6 #107) and the in-tree first-party
// extensions (e.g. extensions/osquery, Phase 6 #109).
//
// Per ADR-0037: framing is varint-length-prefixed protobuf over a unix
// domain socket. Each direction is an independent message stream — the
// agent reads ExtensionToAgent envelopes from the extension's stdout-
// equivalent (the socket), and writes AgentToExtension envelopes back.
package extsdk

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
	"google.golang.org/protobuf/proto"
)

// MaxMessageSize bounds an individual length-delimited frame. 16 MiB
// matches gRPC's default ceiling; a runaway extension claiming a
// gigabyte-shaped varint length cannot drag the agent into OOM.
//
// Snapshot chunks (Phase 6 #111) are deliberately split into multiple
// frames rather than relying on a larger MaxMessageSize — see
// SnapshotChunk on extension.proto.
const MaxMessageSize = 16 << 20

// WriteAgentToExtension serialises m and writes it as one
// varint-length-prefixed protobuf frame to w.
func WriteAgentToExtension(w io.Writer, m *pb.AgentToExtension) error {
	return writeFrame(w, m)
}

// ReadAgentToExtension reads one length-delimited frame from r and
// parses it as an AgentToExtension envelope.
func ReadAgentToExtension(r io.Reader) (*pb.AgentToExtension, error) {
	var m pb.AgentToExtension
	if err := readFrame(r, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// WriteExtensionToAgent serialises m and writes it as one
// varint-length-prefixed protobuf frame to w.
func WriteExtensionToAgent(w io.Writer, m *pb.ExtensionToAgent) error {
	return writeFrame(w, m)
}

// ReadExtensionToAgent reads one length-delimited frame from r and
// parses it as an ExtensionToAgent envelope.
func ReadExtensionToAgent(r io.Reader) (*pb.ExtensionToAgent, error) {
	var m pb.ExtensionToAgent
	if err := readFrame(r, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

func writeFrame(w io.Writer, m proto.Message) error {
	payload, err := proto.Marshal(m)
	if err != nil {
		return fmt.Errorf("extsdk: marshal: %w", err)
	}
	if len(payload) > MaxMessageSize {
		return fmt.Errorf("extsdk: frame %d bytes exceeds MaxMessageSize %d", len(payload), MaxMessageSize)
	}
	var lenBuf [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(lenBuf[:], uint64(len(payload)))
	if _, err := w.Write(lenBuf[:n]); err != nil {
		return err
	}
	if _, err := w.Write(payload); err != nil {
		return err
	}
	return nil
}

func readFrame(r io.Reader, m proto.Message) error {
	length, err := readUvarint(r)
	if err != nil {
		return err
	}
	if length > MaxMessageSize {
		return fmt.Errorf("extsdk: frame length %d exceeds MaxMessageSize %d", length, MaxMessageSize)
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(r, buf); err != nil {
		return fmt.Errorf("extsdk: read payload: %w", err)
	}
	if err := proto.Unmarshal(buf, m); err != nil {
		return fmt.Errorf("extsdk: unmarshal: %w", err)
	}
	return nil
}

// readUvarint reads one byte at a time so a partial frame at EOF is
// distinguishable from a malformed varint. Behaviour matches
// binary.ReadUvarint but avoids requiring an io.ByteReader on the
// caller's reader (unix-socket conn doesn't implement ByteReader).
func readUvarint(r io.Reader) (uint64, error) {
	var b [1]byte
	var x uint64
	var s uint
	for i := 0; i < binary.MaxVarintLen64; i++ {
		n, err := r.Read(b[:])
		if n == 0 {
			if err == nil {
				err = io.ErrNoProgress
			}
			if i == 0 {
				return 0, err
			}
			return 0, fmt.Errorf("extsdk: varint truncated after %d bytes: %w", i, err)
		}
		if b[0] < 0x80 {
			if i == binary.MaxVarintLen64-1 && b[0] > 1 {
				return 0, errors.New("extsdk: varint overflow")
			}
			return x | uint64(b[0])<<s, nil
		}
		x |= uint64(b[0]&0x7f) << s
		s += 7
	}
	return 0, errors.New("extsdk: varint too long")
}
