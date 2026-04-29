package graph

import "time"

// nowFn is overridable for tests that want deterministic mtime updates.
var nowFn = time.Now
