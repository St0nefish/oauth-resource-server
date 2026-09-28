---
name: Bug report
about: Something doesn't behave the way the docs say it should
title: ""
labels: bug
assignees: ""
---

**Do not include real issuer URLs, client IDs/secrets, JWKS contents, or
production tokens anywhere in this report.** Use `https://idp.example.test/`
or similar placeholders, or reproduce with the crate's `testing` feature
fixtures. If the bug can only be shown with real values, use GitHub's
private vulnerability reporting instead (see `SECURITY.md`) rather than a
public issue.

## What happened

A clear description of the behavior you saw.

## What you expected

What the docs (README, rustdoc, `docs/providers.md`) led you to expect
instead, with a link or quote if you can.

## Minimal reproduction

Ideally a small snippet using the crate's `testing` module (enable the
`testing` feature; see its rustdoc, or functions like `mint`, `valid_token`,
`jwks_body` and `resolved_config` in `src/testing.rs`) that shows the problem
without any real credentials. If that's not practical, describe the
exact configuration (feature flags, `OAuthConfig` fields — with placeholder
values) and the request/response you saw.

## Environment

- `oauth-resource-server` version:
- Features enabled:
- Rust version (`rustc --version`):
- OS:
