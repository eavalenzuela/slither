# Planned Improvements & Features

Scope for this pass: the detection core (`pkg/ruleast`, `pkg/ruleeval`,
`pkg/ocsf`, `pkg/log`, `pkg/version`) and the agent-side IOC store
(`agent/internal/ioc`). These are the fast-building, well-tested modules
where correctness/perf work has the highest leverage on the Sigma match
path that both the agent edge engine and the server detection engine run.

## Improvements (existing behavior / correctness / perf / robustness / docs / tests)

1. **UTF-16 encoding emits real surrogate pairs.**
   `encodeUTF16LE/BE`/`encodeUTF16WithBOM` used `byte(r), byte(r>>8)`,
   which silently drops the high surrogate for any rune >= U+10000 (emoji,
   astral-plane CJK). A `Field|utf16le|base64` value over such text
   compiled to the wrong bytes and never matched. Switch to
   `unicode/utf16.Encode`. ASCII/BMP output is byte-identical, so existing
   rules are unaffected.

2. **Detection hot-path: precompute case-folded predicate values.**
   `FieldPredicate.matchOne` re-lowercased the constant Sigma *want* value
   on every event for `contains`/`startswith`/`endswith`. Fold once at
   compile time into `foldValues` and reuse. Semantics are unchanged.

3. **CIDR matching handles IPv4-mapped IPv6.**
   A dual-stack socket surfaces `::ffff:a.b.c.d`; `netip.Prefix.Contains`
   returns false against an IPv4 prefix because the families differ.
   `Unmap()` the parsed address first so v4-in-v6 traffic still matches v4
   CIDR rules. No-op for genuine v6 addresses.

4. **Timeframe parse rejects decimal overflow.**
   `parseUintStrict` accumulated `n*10 + d` with no overflow check, so a
   pathological `timeframe:` could wrap to a tiny window and ship an
   effectively-unbounded stateful rule. Detect the wrap and error loud.

5. **`version.String()` build-identity helper.**
   Both binaries hand-built the same `"%s (%s%s)"` banner with duplicated
   dirty-flag logic. Add `version.String()` (and route both banners
   through it) plus the package's first unit test.

6. **`log.ParseLevel` tolerance + first test.**
   Trim and lowercase the input and accept the `warning` alias so a
   slightly-off config value degrades to the intended level instead of
   silently falling back to info. Add the package's first unit test.

7. **`ocsf.NewUID` fallback keeps full width.**
   The crypto/rand failure path filled only the low 8 of 16 bytes, leaving
   the high half a constant zero. Fill all 16 from the nanosecond clock so
   the degraded id keeps its width and variability. Add a focused test.

8. **IOC domain feeds normalize a trailing FQDN dot.**
   `evil.com.` (a fully-qualified name) now matches an `evil.com`
   indicator for `FEED_KIND_DOMAIN`. Filenames and other kinds are
   untouched.

9. **IOC `Apply` load/drop observability.**
   Add `Store.Stats()`, correct the stale `Apply` doc comment (it claimed a
   structured warning it never emitted), and log dropped IOC entries from
   `compileRuleSet` so operators can see feed-parse loss.

10. **IOC IPv4 feeds match IPv4-mapped IPv6 (symmetry with #3).**
    An IPv4 indicator now fires against a `::ffff:a.b.c.d` connection.

## New Features

1. **Numeric comparison operators `|lt |lte |gt |gte`.**
   First-class Sigma numeric predicates for ports, PIDs, sizes, etc.
   Values are validated as numbers at compile time and compared
   numerically at runtime.

2. **`|exists` modifier.**
   `Field|exists: true|false` — the presence/absence check that
   complements `|null`.

3. **`|cased` modifier (case-sensitive matching).**
   Previously rejected outright; now a real modifier that switches
   `equals`/`contains`/`startswith`/`endswith` to case-sensitive.

4. **Regex flag sub-modifiers `|re|i`, `|re|m`, `|re|s`.**
   Case-insensitive, multiline, and dot-all regex compilation, matching
   pySigma's `re` sub-modifiers.

5. **New Linux detection rules.**
   Ship three edge-eligible Sigma rules into `rules/linux/`:
   `proc-memfd-fileless-exec`, `proc-ld-preload-inline-exec`, and
   `file-git-config-exfil-read`.

## Deferred / noted, not implemented here

- **CI govulncheck gate** — a `make ci`-invoked `govulncheck ./...` step
  belongs in the GitHub Actions workflow, but the push token lacks the
  `workflow` scope, so the YAML is intentionally *not* added in this pass.
  It is recorded here as the next CI improvement.
