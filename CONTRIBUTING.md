# Contributing

Thanks for helping. A few ground rules keep meshpanel small and dependable.

## Principles

- **One binary, no build step.** Templates, CSS, JS and fonts are embedded
  with `go:embed`. No Node toolchain, no CDNs.
- **headscale is reached only through `internal/hs`.** Version differences
  live there and nowhere else.
- **Colors come from tokens.** Components use the CSS variables in
  `internal/web/static/css/tokens.css`, so all three themes and company
  accents keep working.
- **Members see only their own devices.** Every new list, page, search result
  or live event must go through `perm.Scope`.
- **Every state change is audited** (`Server.audit` in the web layer).

## Workflow

```sh
make check    # gofmt, vet, tests
make run
```

- Write the test first. Security-relevant behavior (permissions, scope,
  approvals, CSRF) needs a test that fails without the fix.
- Commit messages: `package: imperative summary`, for example
  `telegram: retry on flood control`.
- Keep pull requests focused, and describe user-visible changes.
