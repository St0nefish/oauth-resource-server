## What this changes and why

<!-- The "why" matters more than the "what" for a diff a reviewer can already read. -->

## Checklist

- [ ] `cargo fmt --all -- --check` passes
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` passes
- [ ] `cargo clippy --all-targets -- -D warnings` (default features) passes
- [ ] `cargo clippy --all-targets --no-default-features --features native-tls -- -D warnings` passes
- [ ] `cargo test --all-features` and `cargo test` pass
- [ ] `cargo build --examples --all-features` passes
- [ ] `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features` passes
- [ ] Every new/changed public item has a doc comment (`# Errors`/`# Security` where relevant)
- [ ] Docs updated in the same PR: rustdoc, `examples/` (if it demonstrates the changed surface), `README.md`, `docs/providers.md` (if provider-specific), `CHANGELOG.md`
- [ ] If this touches token/key validation: the security invariant it affects is named below, and no invariant in `CLAUDE.md` is weakened
- [ ] If this adds/changes provider-specific handling: it's config, not a branch, and a fixture test with an accurate `docs/providers.md` label ("verified in production" / "verified in a sandbox" / "documented-shape fixture, not live-tested") was added or updated

## Security-relevant changes (if any)

<!-- Name the specific invariant(s) from CLAUDE.md / SECURITY.md this touches, or write "none". -->
