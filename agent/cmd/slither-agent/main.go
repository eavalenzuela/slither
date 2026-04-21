// Command slither-agent runs the Linux endpoint agent.
//
// Phase 0: skeleton that prints build identification and exits.
// Phase 1 will wire the eBPF collector, enricher, edge rule engine, and stdout sink.
package main

import (
	"fmt"
	"os"

	"github.com/t3rmit3/slither/pkg/version"
)

func main() {
	dirty := ""
	if version.Modified() {
		dirty = "+dirty"
	}
	fmt.Printf("slither-agent %s (%s%s)\n", version.Version, version.Revision(), dirty)
	os.Exit(0)
}
