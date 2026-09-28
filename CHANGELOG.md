# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Before 1.0, a breaking change increments the minor version.

## [Unreleased]

## [0.1.0] - 2026-09-28

The first release. The validator was extracted from mcp-md-wiki's OAuth
support
([mcp-md-wiki#308](https://github.com/St0nefish/mcp-md-wiki/issues/308)) into
a standalone, provider-agnostic crate. Every security behavior moved over
unchanged: the algorithm allowlist checked from the unverified header before
any key fetch, per-key algorithm narrowing, `iss`/`aud`/`exp`/`nbf` validated
inside one `jsonwebtoken::decode` call, JWKS discovery with an exact-issuer
match, an hourly background refresh with a 60-second cooldown on unknown-`kid`
refetches, and fail-closed handling throughout. The deliberate differences are
listed under "Changed" below.

MSRV: Rust 1.89. License: MIT.

### Added

- `OAuthConfig`, `OAuthConfig::resolve` and `ResolvedOAuthConfig`:
  all-or-nothing validation that reports every problem at once, with
  `KeyNaming` so problem messages and log lines use the application's own
  config-file keys or environment-variable names. `required_scope` (one) and
  `required_scopes` (a list) are combined, and every one is required. There
  is no default required scope, since the crate is not specific to any one
  application.
- No required scope with `require_at_jwt` off is refused by `resolve` unless
  `allow_unscoped_tokens: true` is set (the original always required a
  scope), because that combination accepts OIDC ID tokens issued to the same
  client as access tokens. A validator built that way still logs a `warn` at
  startup; an unscoped one with `require_at_jwt` on logs an `info` line.
- `allow_insecure_http`: a plain-`http` `issuer`, `jwks_uri` or `resource` on a
  non-loopback host is refused by `resolve` without it (RFC 8414 §2, RFC 9728
  §1.2). Loopback hosts are always allowed.
- `Algorithm` and `AlgorithmError`: a crate-owned algorithm enum with no HMAC
  or `none` variant, and a typed error from `parse_algorithm`.
- `TokenRejection` implements `std::error::Error`; its `Display` is the
  category only (`missing credential`, `invalid token`, `insufficient
  scope`), never the log-only reason.
- `OAuthValidator`: JWT access-token validation against a JWKS (RFC 9068),
  the RFC 9728 protected-resource metadata document, and the RFC 6750
  `WWW-Authenticate` challenges for `invalid_token` and `insufficient_scope`.
- `authenticate` and `static_token_policy`: the framework-free credential
  check and startup policy, usable without the `axum` feature. `authenticate`
  checks every candidate credential against every configured mechanism, so a
  bad credential in one header cannot hide a good one in another, and it
  decides from the signing keys already held before letting any candidate's
  unknown `kid` trigger a JWKS refetch.
- `axum` feature: `AuthLayer`, fail-closed by construction (the only
  pass-throughs are `AuthLayer::allow_unauthenticated()` and a
  `StaticTokenDecision::Unauthenticated` handed to `from_decision` or
  `build_with_decision`, both asked for by name), usable
  directly as a `tower::Layer` or as state for the `require_auth` middleware
  function; `AuthLayer::from_decision` and
  `AuthLayerBuilder::build_with_decision`, which turn a `static_token_policy`
  decision into a layer; `CredentialSource`, for reading credentials from
  more than one header; an `on_reject` callback for the refusal body, given a
  `RejectContext` with the rejection, the status and the request's parts; and
  `metadata_router` for the RFC 9728 well-known routes.
- `env` feature: `secret_from_env` and `secret_from_lookup` (with `VAR_FILE`
  support), and `oauth_config_from_env` and `unresolved_oauth_config_from_env`,
  which read `<PREFIX><FIELD>` variables with the same all-or-nothing
  validation as the `serde` path.
- `serde` feature: `Deserialize` and `Serialize` for `OAuthConfig`.
- `testing` feature: throwaway signing keys, JWK and token-minting helpers,
  and a fake JWKS server, for consumers' own tests.
- `rustls-tls` (default; trusts only the compiled-in Mozilla roots),
  `rustls-tls-native-roots` (rustls with the OS trust store) and `native-tls`
  features selecting the TLS backend for JWKS and discovery fetches. Enabling
  none is a compile error.
- `axum::AuthLayerBuilder::static_challenge` and `DEFAULT_STATIC_CHALLENGE`:
  without OAuth, every 401 carries `WWW-Authenticate: Bearer
  error="invalid_token"` (RFC 9110 §15.5.2) unless the application sets its
  own or opts out with `None`.
- Documentation: the README (also the crate-level rustdoc, so its examples
  are doctests), a provider guide with tested-level labels
  (`docs/providers.md`), and four runnable examples (`axum_basic`,
  `multiple_sources`, `standalone_validator`, `env_config`) that need no
  network access.

### Changed (relative to the mcp-md-wiki original)

- `AuthorizedToken::subject` and `principal` hold the verified claim
  verbatim; only this crate's log lines truncate them (to 128 characters).
  The original truncated the stored value, which made two long identities
  sharing a prefix compare equal.
- A token whose header does not parse is refused with its reason truncated
  like every other token-derived log value; the parser's error can echo an
  attacker-supplied `alg` string of up to the 16 KiB credential cap.
- `OAuthValidator::new` re-checks `leeway_secs` against `MAX_LEEWAY_SECS`
  (`ValidatorError::LeewayTooLarge`), since `ResolvedOAuthConfig`'s fields are
  public and may be changed after resolving.
- A plain-`http` `issuer`, `jwks_uri` or `resource` on a non-loopback host is
  refused at startup unless `allow_insecure_http` is set (the original
  accepted an `http` issuer with a warning); with the opt-in, each such URL
  is warned about. The same opt-in governs URLs reached at run time: a
  `jwks_uri` discovered from a loopback `http` issuer, and a redirect
  followed during a metadata or JWKS fetch, may not land on plain `http` on
  a non-loopback host without it (the original followed any redirect that
  did not leave `https`, and took any `http` `jwks_uri` from an `http`
  issuer).
- A token whose header lists critical extensions (`crit`, even an empty
  list) is refused (RFC 7515 §4.1.11). The original ignored `crit`.
- A token whose `nbf` is present but not a NumericDate (a string, a negative
  or out-of-range number) is refused. The original let `jsonwebtoken` skip
  such an `nbf`, which disabled the not-before check.
- A sender-constrained token (a `cnf` claim: DPoP, mTLS) is refused rather
  than accepted as a bearer token (RFC 9449 §7.2, RFC 8705 §3).
- A JWK whose `key_ops` is present without `verify` is never used to verify a
  signature, like a `use: enc` key.
- A JWK with no `alg` that could verify more than one allowlisted algorithm
  is still used, and now logged at `warn` (naming its `kid`) when it first
  appears (RFC 8725 §3.1).
- Every required and advertised scope must be an RFC 6749 §3.3 scope-token,
  and `issuer`, `resource` and `jwks_uri` may not contain a space, control or
  non-ASCII character. The original accepted both, and such a value could
  make every 401 go out without a `WWW-Authenticate` header.
- An omitted `scopes_supported` resolves to the required scopes, on the
  `serde` and `env` paths alike. The original defaulted it to an
  application-specific list; the crate has no application default. An
  explicitly empty `scopes_supported` is omitted from the metadata document
  (RFC 9728 §3.2: the original published `"scopes_supported": []`), the 401
  challenge then names the required scopes instead of leaving `scope` out,
  and the startup warning about required scopes missing from
  `scopes_supported` is not logged for it.
- The metadata URL keeps the resource path verbatim, trailing slash included
  (RFC 9728 §3.1): `https://api.example.com/v1/` is described at
  `.../oauth-protected-resource/v1/`. The original trimmed that slash.
- A JWKS refetch runs in a task of its own, so a request dropped mid-fetch
  (client disconnect, timeout layer) no longer spends the unknown-`kid`
  cooldown without loading keys. The background task retries a failed pass
  after a minute, backing off to an hour, instead of waiting a full hour, and
  stops when the validator is dropped.
- `axum::RejectContext`'s `Debug` prints header names only, and the layer
  marks the configured credential headers sensitive, so a logged request or
  context never shows the token.
- `AuthLayerBuilder::build` fails with `AuthLayerError::InvalidChallenge`
  when the validator's challenge is not a valid header value; the original
  logged a warning and sent 401s without `WWW-Authenticate`.
- `OAuthValidator::metadata` returns `&serde_json::Value` rather than a clone.

### Compatibility notes

- No `jsonwebtoken` type is part of the public API: `Algorithm` is this
  crate's own enum. Moving to a later `jsonwebtoken` major version (the
  reason for the 9.x pin is in `Cargo.toml`) is therefore not a breaking
  change here.
- The `testing` feature's `mint` and `mint_with` take claims as
  `&impl Serialize`, and `jwks_of` takes `&[serde_json::Value]`.
- Moving an existing deployment onto this crate: a configuration with no
  required scope and `require_at_jwt` off, which code built on "no required
  scope means any validated token" used to start, now fails `resolve` at
  startup. With the `env` loader, set `<PREFIX>REQUIRED_SCOPE` (the
  recommended fix), `<PREFIX>REQUIRE_AT_JWT=true`, or
  `<PREFIX>ALLOW_UNSCOPED_TOKENS=true` to keep that posture deliberately;
  with `serde`, the matching `required_scope`, `require_at_jwt` or
  `allow_unscoped_tokens` key. Likewise, a plain-`http` issuer, `jwks_uri` or
  resource on a non-loopback host needs `<PREFIX>ALLOW_INSECURE_HTTP=true`
  (`allow_insecure_http`).

[Unreleased]: https://github.com/St0nefish/oauth-resource-server/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/St0nefish/oauth-resource-server/releases/tag/v0.1.0
