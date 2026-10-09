# Contributing to oauth-resource-server

Thanks for considering a contribution. This crate sits in front of real
authentication decisions, so the bar for changes to the validation logic is
higher than for most libraries — see the security invariants in
[`CLAUDE.md`](CLAUDE.md) before touching `src/validator.rs`, `src/jwks.rs`,
`src/builder.rs`, `src/algorithms.rs`, `src/token.rs`, `src/config.rs`,
`src/authenticate.rs`, `src/refusal.rs`, `src/http_layer.rs`, `src/axum.rs`,
`src/mcp.rs` or `src/env.rs`.

## Before you open a PR

Run the same checks CI runs, locally, before opening a PR:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo clippy --all-targets -- -D warnings
cargo clippy --all-targets --no-default-features --features native-tls -- -D warnings
cargo clippy --all-targets --no-default-features --features rustls-tls-native-roots -- -D warnings
cargo clippy --all-targets --no-default-features --features rustls-tls,tower -- -D warnings
cargo clippy --all-targets --no-default-features --features rustls-tls,metrics,mcp -- -D warnings
cargo test --all-features
cargo test
cargo test --doc --no-default-features --features rustls-tls,mcp   # doc examples without axum
cargo build --examples --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features
cargo audit
cargo deny check
cargo package --list
cargo publish --dry-run
```

`cargo publish --dry-run` refuses a working tree with uncommitted changes;
pass `--allow-dirty` when running it locally mid-change (CI runs it
against a clean checkout, so it never needs the flag there). `cargo audit`
and `cargo deny check` need `cargo-audit` and `cargo-deny` installed
(`cargo install --locked cargo-audit cargo-deny`, or `cargo binstall`).
`cargo deny check` reads `deny.toml`: a dependency with a licence that is
not on its allowlist, a git or non-crates.io source, or a yanked or
vulnerable crate fails it; two versions of one crate is only a warning.

This list isn't quite everything CI runs. Four more jobs run in the slow tier
(`ci-slow`), and CI will catch them regardless if you skip them locally:

```sh
# msrv: the pinned MSRV toolchain, reading rust-version from Cargo.toml
cargo "+1.89" build --all-features --locked

# semver: fails on an accidental breaking change (needs cargo-semver-checks
# 0.50.0 and rustc 1.93+ -- CI pins both and they move together; compares
# with the latest release on crates.io)
cargo +1.93 semver-checks check-release --all-features

# feature-powerset: every feature combination builds (needs cargo-hack;
# `metrics` is toggled together with `testing`, see checks.yml)
cargo hack check --feature-powerset --no-dev-deps \
  --mutually-exclusive-features rustls-tls,native-tls,rustls-tls-native-roots \
  --at-least-one-of rustls-tls,native-tls,rustls-tls-native-roots \
  --group-features metrics,testing

# minimal-versions: every dependency lower bound in Cargo.toml really builds.
# It rewrites Cargo.toml and Cargo.lock, so run it in a throwaway copy of the
# tree (needs cargo-hack and a nightly toolchain)
cargo hack --remove-dev-deps
cargo +nightly update -Z direct-minimal-versions
cargo update -p time
cargo build --all-features
```

`semver` compares against the newest release on crates.io. `master`'s
`Cargo.toml` always names the *next* release, one patch above the last one,
so a PR that deliberately breaks the public API must also bump the `0.x`
minor (`cargo release version minor --execute --no-confirm`; see the semver
policy in `CLAUDE.md`); that bump is what marks the break as intended. If `minimal-versions` fails, raise the
named lower bound in `Cargo.toml` to a release that builds and say in the
comment above `[dependencies]` whether it is a compile floor or only what the
resolver needs.

Fuzz targets for the crate's own parsers live in `fuzz/` and run after each merge to `master` (and on demand) in
`fuzz.yml`, not on PRs. To run one locally
(`cargo install --locked cargo-fuzz`, nightly toolchain):

```sh
cargo +nightly fuzz run check_header -- -max_total_time=30
```

The targets reach internals through `src/__fuzz.rs`, which exists only under
`--cfg fuzzing`. Do not make an internal `pub` to fuzz it; widen it to
`pub(crate)` and add a function to that module.

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
  The crate-level rustdoc is `README.md` itself, included verbatim by
  `#![cfg_attr(all(feature = "serde", feature = "env", feature = "axum"),
  doc = include_str!("../README.md"))]` at the top of `src/lib.rs` — so every
  fenced ` ```rust ` block in it is a doctest whenever those three features
  are on: `cargo test --all-features` (as CI runs it) tests them, while a
  plain `cargo test` (default features) does not, and a narrower build gets
  a short pointer doc instead. Treat every such block as a doctest: it must
  compile against the crate's current public API. Mark a block that is
  deliberately not standalone Rust (a config snippet, a shell command, a
  fragment) ` ```toml `, ` ```yaml `, ` ```text `, or similar instead of
  ` ```rust `.

## Opening a pull request

This repository follows a simple trunk-based flow on `master`:

1. Branch from `master` (or fork), make your change, and make sure the check
   suite above passes locally.
2. Open a PR against `master`. Two checks are required:
   - **`ci-fast`** runs on every push to the PR, on GitHub-hosted runners:
     workflow lint, then — when the PR touches code — fmt, clippy, unit
     tests, the doc build, `cargo audit`/`cargo deny` and the publish dry run.
     For a PR from a fork, a maintainer approves the workflow run first.
   - **`ci-slow`** runs once a maintainer arms the PR for auto-merge (the
     approval to run its code on the project's self-hosted runner): the
     integration tests, `msrv`, `semver`, `feature-powerset` and
     `minimal-versions`, on your branch merged onto the current `master`.
3. When both are green, GitHub merge-commits the PR and deletes the branch.
   (The maintainer's own PRs are armed when they open.)

You don't need to keep your branch up to date with `master` — `ci-slow`
tests the merge onto the current `master`, and `master` re-checks any merge
whose combination nobody tested. Rebase or merge `master` only if GitHub
reports a conflict.

A merge publishes nothing. **Releases are made by the maintainer by hand**:
`gh release create vX.Y.Z --target <commit> --title vX.Y.Z --generate-notes`
on a merged commit whose `Cargo.toml` names `X.Y.Z`. That runs `release.yml`,
which checks the release, publishes the crate to crates.io through trusted
publishing (bound to this repository's `release` environment, which only
`v*` tags can deploy to; only repository admins can create those tags, and
no crates.io token is stored anywhere), and then opens a PR rolling `master`
to the next patch version. Contributors don't bump the version or push tags
(unless a deliberate breaking change needs the minor bump above) — put your
entry under `CHANGELOG.md`'s `[Unreleased]` section. See
`.github/workflows/release.yml`'s header comment for the details.

## Reporting a security issue

Please don't open a public issue for a security problem — see
[`SECURITY.md`](SECURITY.md) for private reporting instructions.
