# Repository working instructions

## Before pushing a branch

Review the complete PR diff against its base, not just the latest commit. Verify
review findings against the code and address valid issues before pushing.

- Document every new or modified named Go function with a useful Go doc comment,
  including unexported helpers, tests, and existing functions whose bodies change.
  Start the comment with the function name and explain its contract or purpose.
  CodeRabbit checks touched functions and requires at least 80% documentation
  coverage; aim for all touched functions rather than waiting for that warning.
- Check documentation commands from the deployment user's perspective. Distinguish
  source checkout/release tarball paths (`deploy/`), installed deb/rpm paths
  (`/usr/share/doc/meshpanel/`), and bare-binary installations, which do not include
  helper files. Cross-check source/destination paths against `.goreleaser.yaml`.
  Walk setup instructions from an empty installation: create required parent
  directories before installing files, with the ownership and modes the helper
  requires. Do not assume package-created directories exist for binary users.
- Inspect `go.mod`/`go.sum` after dependency changes or merges. Use `go mod tidy`
  when needed and review the result; do not leave duplicate requirements.
- Run `git diff --check`. For Go/runtime changes, run `make lint` and
  `go test -race ./...`; for binary/dependency/packaging changes, also run
  `make size`. Check `.github/workflows/ci.yml` for additional current requirements.
  Documentation/comment-only follow-ups need formatting and documentation review,
  not an unchanged full test suite rerun.
- For UI changes, verify affected interactions and responsive rendering. For
  privileged/service changes, check permissions, fixed command arguments, path
  validation, backup coverage, concurrent execution, and failure recovery. State
  explicitly when real systemd behavior has not been exercised.
- Confirm only intended files are staged. Report the validation performed and any
  remaining limitations accurately; local checks do not imply remote CI passed.

These instructions do not authorize merging, releasing, or deploying beyond the
user's requested scope. Do not add tests that merely repeat documentation text.
