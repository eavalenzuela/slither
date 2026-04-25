# Phase 2 validation raw outputs

This directory holds the raw artefacts captured during the Phase 2
exit validation run. Mirrors the [Phase 1 layout](../debian_13_phase1_validation)
where each top-level file is one of the runbook's capture points.

The runbook itself lives at [../docs/phase2-validation.md](../docs/phase2-validation.md);
filenames in this directory correspond to the §-numbered capture
steps there:

| File                     | Step                                          |
|--------------------------|-----------------------------------------------|
| `00-stack-up.txt`        | `docker compose ps`, bootstrap creds          |
| `01-enroll.txt`          | `slither-agent enroll` stderr per agent VM    |
| `02-hosts.txt`           | `/hosts` page showing the online agent        |
| `03-events.txt`          | `/events` rows + per-class detail views       |
| `04-rule-push.txt`       | server-pushed rule fires; DetectionFinding    |
| `05-load-test.txt`       | per-agent + server telemetry from 3-agent run |

The directory will be empty until an operator runs the validation;
this README is the only committed file ahead of that. Once the run
is complete the operator commits the artefacts in one go alongside
the IMPLEMENTATION.md ✅ that closes Phase 2.
