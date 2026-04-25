// Package static embeds the console's hand-written CSS so the server
// binary ships self-contained. Phase 2 #41 ships a minimal stylesheet;
// IMPLEMENTATION.md §4.1 leaves a Tailwind pipeline as a polish task —
// `make gen-css` is wired but a no-op until the pinned tailwindcss
// binary lands under tools/tailwind/.
package static

import "embed"

//go:embed *.css
var FS embed.FS
