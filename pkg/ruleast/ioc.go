package ruleast

// IOCRegistry resolves `ioc:<feed_id>` references at compile time. The
// compiler asks the registry for the size + kind of each referenced
// feed; if any feed exceeds MaxIOCFeedEntries (ADR-0018 predicate 3),
// the rule classifies ServerOnly. The agent supplies an in-memory
// implementation backed by the IOC feed map (#67); the server hub
// supplies a Postgres-backed implementation.
//
// A nil IOCRegistry is treated as "no feeds available": rules
// containing `|ioc:<feed_id>` references fail compile with a clear
// error, rather than silently slipping past the gate.
type IOCRegistry interface {
	// Lookup returns the entry count + kind for feedID. Returns
	// (0, "", false) when the feed is unknown — the compiler treats
	// unknown feeds as a compile-time error rather than guessing.
	Lookup(feedID string) (entryCount int, kind string, ok bool)
}

// MaxIOCFeedEntries mirrors pg.MaxIOCFeedEntries / agent's IOC store
// cap. Pulled into ruleast so the classifier doesn't depend on either
// concrete store. Authority lives in ADR-0018 predicate 3.
const MaxIOCFeedEntries = 100_000

// CompileOptions carries optional knobs for the compiler. Today the
// only knob is the IOCRegistry; the struct exists so future additions
// (e.g., baseline subsystem for ADR-0018 predicate 4) extend cleanly.
type CompileOptions struct {
	// IOCRegistry resolves `ioc:<feed_id>` references at compile time.
	// nil disables ioc references — rules containing them fail compile.
	IOCRegistry IOCRegistry
}

// CompileOption is the functional-options entry point. Compile keeps
// its zero-arg signature stable; callers supply registries via
// WithIOCRegistry.
type CompileOption func(*CompileOptions)

// WithIOCRegistry returns a CompileOption that wires the registry into
// the compiler's classification gate.
func WithIOCRegistry(r IOCRegistry) CompileOption {
	return func(o *CompileOptions) { o.IOCRegistry = r }
}

func applyOptions(opts []CompileOption) CompileOptions {
	var out CompileOptions
	for _, fn := range opts {
		if fn != nil {
			fn(&out)
		}
	}
	return out
}
