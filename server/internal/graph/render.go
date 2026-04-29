// Package graph wraps the D2 SVG renderer behind a single Render entry point.
//
// All D2-specific imports stay within this package so swapping for a different
// graph engine (graphviz CLI, etc.) is a one-package change. See ADR-0024.
package graph

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"oss.terrastruct.com/d2/d2graph"
	"oss.terrastruct.com/d2/d2layouts/d2dagrelayout"
	"oss.terrastruct.com/d2/d2lib"
	"oss.terrastruct.com/d2/d2renderers/d2svg"
	"oss.terrastruct.com/d2/d2themes/d2themescatalog"
	"oss.terrastruct.com/d2/lib/textmeasure"
	"oss.terrastruct.com/util-go/go2"
)

// renderMu serialises calls into d2lib.Compile + d2svg.Render. The
// upstream textmeasure.Ruler caches glyph metrics in non-locked maps,
// and the dagre layout's embedded JS runtime is single-threaded — both
// race when invoked concurrently. Serialising here is acceptable
// because rendered graphs are heavily cached (see Cache); the
// serial-ised path only runs on miss.
var renderMu sync.Mutex

var (
	rulerOnce sync.Once
	rulerVal  *textmeasure.Ruler
	rulerErr  error
)

func sharedRuler() (*textmeasure.Ruler, error) {
	rulerOnce.Do(func() {
		rulerVal, rulerErr = textmeasure.NewRuler()
	})
	return rulerVal, rulerErr
}

// Render compiles the given D2 source and returns the rendered SVG bytes.
//
// Empty source is rejected — the caller should decide what to show when there
// is nothing to graph rather than embed a blank SVG.
func Render(ctx context.Context, source string) ([]byte, error) {
	if source == "" {
		return nil, errors.New("graph: empty source")
	}

	renderMu.Lock()
	defer renderMu.Unlock()

	ruler, err := sharedRuler()
	if err != nil {
		return nil, fmt.Errorf("graph: text ruler init: %w", err)
	}

	renderOpts := &d2svg.RenderOpts{
		Pad:     go2.Pointer(int64(20)),
		ThemeID: &d2themescatalog.NeutralDefault.ID,
	}
	compileOpts := &d2lib.CompileOptions{
		LayoutResolver: func(string) (d2graph.LayoutGraph, error) {
			return d2dagrelayout.DefaultLayout, nil
		},
		Ruler: ruler,
	}

	diagram, _, err := d2lib.Compile(ctx, source, compileOpts, renderOpts)
	if err != nil {
		return nil, fmt.Errorf("graph: compile: %w", err)
	}

	svg, err := d2svg.Render(diagram, renderOpts)
	if err != nil {
		return nil, fmt.Errorf("graph: render: %w", err)
	}
	return svg, nil
}
