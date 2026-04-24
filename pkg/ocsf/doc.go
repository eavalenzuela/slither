// Package ocsf defines Go types for the curated subset of OCSF 1.3 event
// classes that slither emits.
//
// # Scope
//
// Rather than pull the entire OCSF schema, we maintain a hand-curated subset
// matching the event classes listed in PROJECT.md §5.1:
//
//   - ProcessActivity      (class_uid 1007)
//   - FileSystemActivity   (class_uid 1001)
//   - NetworkActivity      (class_uid 4001)
//   - DnsActivity          (class_uid 4003)
//   - Authentication       (class_uid 3002)
//   - KernelActivity       (class_uid 1003)
//   - ContainerLifecycle   (class_uid 6000)
//   - DetectionFinding     (class_uid 2004)
//
// # Invariants
//
//   - All types serialise to canonical JSON matching OCSF 1.3 field names.
//   - Each event type implements Event (ClassID + Validate + metadata).
//   - No cross-type inheritance; shared field groups live as embeddable structs.
//
// # Drift detection
//
// scripts/ocsf-check.sh downloads the OCSF 1.3 reference schema and a test
// in schema_test.go asserts every field we use exists upstream with the
// expected type. OCSF version bumps are deliberate, not automatic.
//
// # Versioning
//
// slither pins OCSF 1.3. Moving to a later OCSF version requires:
//  1. An ADR documenting the motivation.
//  2. Regenerating the drift-check fixtures.
//  3. A protobuf Envelope version bump if breaking field renames occurred.
package ocsf

// Version is the OCSF schema version this package targets.
const Version = "1.3.0"
