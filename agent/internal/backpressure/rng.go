package backpressure

import (
	"math/rand/v2"
)

// defaultRng returns a pseudo-random float in [0,1). math/rand/v2 is
// goroutine-safe by default and seeds itself; the sampling decision
// doesn't need crypto-strength randomness — uniform-enough is the
// only contract.
func defaultRng() float32 {
	return rand.Float32() //nolint:gosec // G404: sampling decision; predictability is not exploitable. See SECURITY.md "Risk dispositioning".
}
