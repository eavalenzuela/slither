# Contributing to Slither

Thanks for your interest. Slither is pre-alpha; expectations and process may change as the project matures. The rules below are the ones we intend to keep.

## Before you start

- Read [PROJECT.md](./PROJECT.md) for the design record and [IMPLEMENTATION.md](./IMPLEMENTATION.md) for the build plan. A PR that contradicts a locked decision in PROJECT.md §9.1 needs an accompanying ADR proposing the change.
- For non-trivial work, open an issue first to sanity-check direction before you spend real time.

## Developer Certificate of Origin (DCO)

Every commit must carry a `Signed-off-by:` trailer. This is the [Developer Certificate of Origin](https://developercertificate.org/) — your statement that you have the right to submit the change.

Use `git commit -s` to add the trailer automatically. CI rejects unsigned commits.

No CLA. Just DCO.

## Development setup

```bash
make tools          # installs pinned Go tools
make ci             # runs the full local pipeline
```

System package prerequisites per distro: [docs/dev-setup.md](./docs/dev-setup.md).

## PR expectations

- **Small PRs.** A PR is easier to review if it does one thing. Series of small PRs beat one large PR.
- **Tests.** New behavior needs test coverage. Bug fixes need a regression test that fails before the fix.
- **`make ci` passes locally** before you push. CI will re-run; local first saves iteration time.
- **Generated code.** If you touch `.proto` files or `.templ` components, run `make gen` and commit the result. `make verify-gen` fails CI if you forget.
- **No scope creep.** If you spot an unrelated issue, file it separately — don't bundle it.
- **Commits tell a story.** Squash fixup/WIP commits before requesting review. Each commit should build and test cleanly on its own.

## Commit messages

```
subject line — imperative mood, no period, <= 72 chars

Body explains *why*, not *what*. The diff shows what. Reference
issue numbers if applicable.

Signed-off-by: Your Name <you@example.com>
```

## Adding a Sigma rule

1. Drop the rule under `rules/linux/<category>/<rule-name>.yml`.
2. Include a comment block at the top: one-line description, MITRE ATT&CK tag(s), expected false-positive rate (low/medium/high), test reference.
3. Add a scenario test under `testdata/scenarios/` that reliably triggers it.
4. Verify the rule compiles cleanly: `go test ./pkg/ruleast -run TestCompileBundled`.

## Reporting security issues

Do **not** open a public issue. Use GitHub's private vulnerability reporting — see [SECURITY.md](./SECURITY.md).

## Code of conduct

Deferred. Be decent to each other.
