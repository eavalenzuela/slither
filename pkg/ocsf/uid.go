package ocsf

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

// NewUID returns a 128-bit random hex string suitable for OCSF *.uid fields.
// Collisions are astronomically unlikely; server-side ingest re-keys anyway.
// On the practically-never path where crypto/rand returns an error (/dev/urandom
// unavailable), falls back to a time-based value so we still produce a
// non-empty id that passes validation.
func NewUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		ns := time.Now().UnixNano()
		for i := 0; i < 8; i++ {
			b[i] = byte(ns >> (8 * i))
		}
	}
	return hex.EncodeToString(b[:])
}
