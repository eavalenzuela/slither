package ocsf

import (
	"encoding/hex"
	"testing"
)

func TestNewUIDShape(t *testing.T) {
	id := NewUID()
	if len(id) != 32 {
		t.Fatalf("NewUID length = %d, want 32", len(id))
	}
	if _, err := hex.DecodeString(id); err != nil {
		t.Fatalf("NewUID not valid hex: %v", err)
	}
	if NewUID() == id {
		t.Errorf("two NewUID calls collided: %q", id)
	}
}

func TestFallbackUIDFillsAllBytesAndDiffers(t *testing.T) {
	a := fallbackUID()
	b := fallbackUID()
	// The high 8 bytes are the monotonic counter; two consecutive
	// fallbacks must differ there even within the same nanosecond tick.
	if a == b {
		t.Fatalf("consecutive fallbackUID values collided")
	}
	// The high half must not be a constant zero (the pre-fix bug).
	allZeroHigh := true
	for i := 8; i < 16; i++ {
		if a[i] != 0 {
			allZeroHigh = false
			break
		}
	}
	if allZeroHigh {
		t.Errorf("fallbackUID left the high 8 bytes zero")
	}
}
