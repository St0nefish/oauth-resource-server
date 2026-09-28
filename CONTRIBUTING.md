# Contributing to oauth-resource-server

Thanks for considering a contribution. This crate sits in front of real
authentication decisions, so the bar for changes to the validation logic is
higher than for most libraries — see the security invariants in
[`CLAUDE.md`](CLAUDE.md) before touching `src/validator.rs`, `src/jwks.rs`,
`src/algorithms.rs`, `src/token.rs`, `src/authenticate.rs`, or `src/axum.rs`.

## Before you open a PR

Run the same checks CI runs, locally, before opening a PR:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo clippy --all-targets -- -D warnings
cargo clippy --all-targets --no-default-features --features native-tls -- -D warnings
cargo clippy --all-targets --no-default-features --features rustls-tls-native-roots -- -D warnings
cargo test --all-features
cargo test
cargo build --examples --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features
cargo audit
cargo package --list
cargo publish --dry-run
```

`cargo publish --dry-run` refuses a working tree with uncommitted changes;
pass `--allow-dirty` when running it locally mid-change (`ci.yml` runs it
against a clean checkout, so it never needs the flag there). `cargo audit`
needs `cargo-audit` installed (`cargo install cargo-audit` or
`cargo binstall cargo-audit`).

This list isn't quite everything CI runs: the `msrv` job also builds with
the pinned MSRV toolchain (`cargo "+1.89" build --all-features --locked`,
reading `rust-version` from `Cargo.toml`), which most contributors won't
have installed locally and CI will catch regardless.

## Ground rules

- **A provider quirk is configuration, never a code branch.** Authorization
  servers disagree on where scopes live, what audience they stamp, which
  algorithms they sign with, and whether the subject claim is even present.
  Every one of those differences is a field on `OAuthConfig` (or a value a
  caller passes), read the same way for every provider. If you're adding
  support for a new provider's shape and find yourself writing
  `if provider == "..."`, that's the sign the config surface is missing a
  knob, not that the branch belongs here.
- **A new provider needs a documented-shape fixture test, not a live
  integration.** Add a test in the relevant module (`src/config.rs` for
  config shape, `src/validator.rs`/`src/jwks.rs` for token/key shape) that
  builds the claims or JWKS shape that provider's documentation describes,
  using the `testing` feature's fixtures — never a real token, key, or
  issuer URL. Say in the test's doc comment whether the shape is
  provider-documentation-only, or something you've actually verified against
  a running instance, and update `docs/providers.md`'s label accordingly,
  using its exact wording (`verified in production` / `verified in a
  sandbox` / `documented-shape fixture, not live-tested`). Never upgrade an
  existing label yourself unless you did the verification it claims.
- **`jsonwebtoken` stays pinned to `9.x`.** The pin and its rationale are in
  `Cargo.toml`'s dependency comment; read it before proposing a bump to
  `11.x` or later. If the tradeoff it describes has genuinely changed (a new
  backend that is neither unpatched nor a new build-tooling requirement),
  say so in the PR and update that comment as part of the same change.
- **Docs move with the code, in the same PR.** A change to a config field, a
  default, a public API's behavior, or a 401/403 response updates every
  place that describes it in the same commit: the item's rustdoc, `examples/`
  if it demonstrates the changed surface, the relevant section of
  `README.md`, `docs/providers.md` if it's provider-specific, and
  `CHANGELOG.md`'s `[Unreleased]` section. A reviewer checks the claim
  against the code, not against the PR description.
- **Every public item needs a doc comment.** `#![warn(missing_docs)]` plus
  `-D warnings` in CI means this isn't optional; a fallible public function
  needs an `# Errors` section, and anything with a non-obvious security
  implication gets a `# Security` note.
- **Every README code block that looks like Rust must actually compile.**
  Check the top of `src/lib.rs` for whether the crate-level rustdoc includes
  `README.md` verbatim (`#![doc = include_str!("../README.md")]`) — if it
  does, every fenced ` ```rust ` block in `README.md` is a doctest CI runs
  directly. Either way, treat every such block as if it were: it must
  compile against the crate's current public API. Mark a block that is
  deliberately not standalone Rust (a config snippet, a shell command, a
  fragment) ` ```toml `, ` ```yaml `, ` ```text `, or similar instead of
  ` ```rust `.

## Opening a pull request

This repository follows a simple trunk-based flow on `master`:

1. Branch from `master` (or fork), make your change, and make sure the check
   suite above passes locally.
2. Open a PR against `master`. `ci.yml` runs on the project's self-hosted
   runner; for a PR from a fork, a maintainer approves the workflow run
   first, so expect a short wait before checks start. `ci-pass` is the one
   required status check.
3. Once `ci-pass` is green and the change has been reviewed, a maintainer
   squash-merges it. The branch is deleted after merge. (The maintainer's
   own PRs merge automatically once `ci-pass` is green.)

You don't need to keep your branch up to date with `master` — CI re-runs on
`master` after every merge. Rebase only if GitHub reports a conflict.

Merging a PR never publishes anything. A release happens in two steps: a
merged PR bumps `version` in `Cargo.toml` and adds the matching
`CHANGELOG.md` section, and then the maintainer publishes a GitHub release
`vX.Y.Z` for that commit on `master`. Publishing the release is what runs
`release.yml`, which verifies the tagged commit, publishes it to crates.io,
and sets the release notes from `CHANGELOG.md`. Publishing uses crates.io
trusted publishing, bound to this repository's `release` GitHub
environment, which only `v*` release tags can deploy to; only repository
admins can create those tags, and no crates.io token is stored anywhere in
the repository.
Contributors don't bump the version or push tags — put your entry under
`CHANGELOG.md`'s `[Unreleased]` section. See
`.github/workflows/release.yml`'s header comment for the details.

## Reporting a security issue

Please don't open a public issue for a security problem — see
[`SECURITY.md`](SECURITY.md) for private reporting instructions.
