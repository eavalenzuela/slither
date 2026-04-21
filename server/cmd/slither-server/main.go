// Command slither-server runs the ingest, detection, and console server.
//
// Phase 0: skeleton that prints build identification and exits.
// Phase 2 will wire ingest, ClickHouse, Postgres, and the HTMX console.
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
	fmt.Printf("slither-server %s (%s%s)\n", version.Version, version.Revision(), dirty)
	os.Exit(0)
}
