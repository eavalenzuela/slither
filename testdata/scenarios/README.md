# Scenario scripts

Each script here represents one attack pattern. The scenario test harness
(`agent/internal/app/scenario_test.go`, build tag `integration`) starts the
agent with the bundled `rules/linux/` pack, runs one of these scripts, and
asserts the matching detection finding is emitted on stdout within a
deadline.

Scripts must:

- Stay harmless. Use loopback-to-unused-ports, tempdir paths, and synthetic
  shell patterns. No real exfil, no real modification of system paths, no
  real privilege escalation.
- Take a single argument: a workspace directory the script can scribble
  inside. Clean up on exit is not required (harness uses `t.TempDir()`).
- Exit 0 on a successful trigger. A non-zero exit fails the test.
- Trigger the rule pattern in a way that survives normal process caching —
  the pattern must appear in `CommandLine` / `TargetFilename` etc. as the
  collector will see it.

See `IMPLEMENTATION.md §3.9` ("Scenario tests").
