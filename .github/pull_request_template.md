## What this changes and why

<!-- The "why" matters more than the "what" for a diff a reviewer can already read. -->

## Checklist

- [ ] The full check matrix in [CONTRIBUTING.md](../CONTRIBUTING.md#before-you-open-a-pr) passes locally (fmt, every clippy feature set, both test runs, the `rustls-tls,mcp` doctests, examples, `-D warnings` docs, `cargo audit`, `cargo deny check`, `cargo package --list`, `cargo publish --dry-run`); the msrv, semver, feature-powerset and minimal-versions jobs listed there run in `ci-slow` regardless, once the PR is armed for auto-merge
- [ ] Every new/changed public item has a doc comment (`# Errors`/`# Security` where relevant)
- [ ] Docs updated in the same PR: rustdoc, `examples/` (if it demonstrates the changed surface), `README.md`, `docs/providers.md` (if provider-specific), `CHANGELOG.md` (under `[Unreleased]`; the version is not bumped here unless a deliberate breaking change needs the `0.x` minor — releases are cut by the maintainer)
- [ ] If this touches token/key validation: the security invariant it affects is named below, and no invariant in `CLAUDE.md` is weakened
- [ ] If this adds/changes provider-specific handling: it's config, not a branch, and a fixture test with an accurate `docs/providers.md` label ("verified in production" / "verified in a sandbox" / "documented-shape fixture, not live-tested") was added or updated

## Security-relevant changes (if any)

<!-- Name the specific invariant(s) from CLAUDE.md / SECURITY.md this touches, or write "none". -->
