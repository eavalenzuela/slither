package ocsf

import (
	"crypto/rand"
	"encoding/hex"
	"sync/atomic"
	"time"
)

// fallbackSeq disambiguates fallback UIDs generated within the same
// nanosecond tick so the degraded path can't collide back-to-back.
var fallbackSeq atomic.Uint64

// NewUID returns a 128-bit random hex string suitable for OCSF *.uid fields.
// Collisions are astronomically unlikely; server-side ingest re-keys anyway.
// On the practically-never path where crypto/rand returns an error (/dev/urandom
// unavailable), falls back to a time-based value so we still produce a
// non-empty id that passes validation. The fallback fills all 16 bytes —
// the low 8 from the nanosecond clock, the high 8 from a monotonic
// counter — so the degraded id keeps its full width rather than leaving
// half the value a constant zero.
func NewUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		b = fallbackUID()
	}
	return hex.EncodeToString(b[:])
}

// fallbackUID builds the 16-byte time+counter value used when crypto/rand
// is unavailable. Split out so the degraded path is unit-testable without
// stubbing the RNG.
func fallbackUID() [16]byte {
	var b [16]byte
	ns := uint64(time.Now().UnixNano())
	seq := fallbackSeq.Add(1)
	for i := 0; i < 8; i++ {
		b[i] = byte(ns >> (8 * i))
		b[8+i] = byte(seq >> (8 * i))
	}
	return b
}
