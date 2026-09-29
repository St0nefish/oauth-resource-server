# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Before 1.0, a breaking change increments the minor version.

## [Unreleased]

### Added

- Several static tokens at once, for rotating a static API key with no
  downtime or for one key per client, with the matched key reported. All
  additive: every existing signature (`authenticate`, `static_token_policy`,
  `StaticTokenDecision`, both builders' `static_token`, the unit
  `Credential::StaticToken`) is unchanged, and a layer or `authenticate` call
  that uses one static token answers exactly as before.
  - `StaticTokens`: an opaque set of secrets, each with an optional label
    (`single`, `new().with(label, secret)`, `len`, `is_empty`, `labels`,
    `MAX_LABEL_LEN`). `with` refuses (`StaticTokensError`) a blank secret, a
    secret already in the set, a repeated label, and a label that is not 1 to
    64 visible ASCII characters. Its `Debug` prints the count and labels only,
    and it wipes its copies of the secrets on drop (`zeroize`, already in
    every build through `rustls-pki-types`, is now a direct dependency). So
    do the layer builders' single `static_token` and the `env` loaders'
    intermediate copies (`secret_from_env`'s untrimmed value, now also
    wiped, with its return type unchanged). Not wiped: strings the caller
    passes in or keeps, `secret_from_env`'s returned `String`,
    `StaticTokenDecision`'s `String` payload, and the process environment.
  - `authenticate_with_static_tokens(candidates, Option<&StaticTokens>,
    oauth)`, returning `(Credential, Option<StaticTokenMatch>)` with the same
    candidate and refusal rules as `authenticate`, which now runs the same
    code over a one-entry set. Every candidate is compared with every entry
    in constant time, with no early exit once one matches.
  - `StaticTokenMatch` (`label()`): inserted into request extensions by both
    layers next to every `Credential::StaticToken` (unlabeled for a single
    `static_token`), removed when a layer accepts an OAuth token and by an
    `optional()` layer, and an axum extractor (plain and `Option`) with the
    same fail-closed rules as the `AuthorizedToken` extractor.
  - `AuthLayerBuilder::static_tokens`/`optional_static_tokens` and the same
    on `HttpAuthLayerBuilder`. With `static_token` the two are merged (a
    secret given both ways counts once, under the set's label); an empty set
    is no credential. `build_with_decision` keeps the set, merged with the
    decision's token, for `StaticOnly`/`StaticAndOAuth`, drops it on
    `StaticIgnored`, and refuses it alongside `OAuthOnly`/`Unauthenticated`
    with the new `AuthLayerError::DecisionWithoutStaticToken`.
  - `env::static_tokens_from_env`/`static_tokens_from_lookup`: `<VAR>`
    (labeled `env::CURRENT_KEY_LABEL`, `"current"`) plus `<VAR>_NEXT`
    (`env::NEXT_KEY_LABEL`, `"next"`), each also as `_FILE`, with
    `secret_from_env`'s rules; equal values are one entry, and `<VAR>_NEXT`
    without `<VAR>` is the new `EnvError::NextWithoutCurrent`. Both keys
    failing is the new `EnvError::Several`, so both are reported at once.
  - README: "Rotating a static API key with zero downtime", and the security
    model's constant-time and log-safety notes for several keys.
  Closes oauth-resource-server#3.
- A general-purpose consumer test harness in the `testing` feature.
  `testing::TestAuthority::start().await` runs a loopback fake authorization
  server with OpenID Connect and RFC 8414 discovery and a JWKS, and exposes
  `issuer()`, `jwks_uri()`, `jwks_fetches()`, `discovery_fetches()`,
  `set_response_delay(Duration)`, `rotate_key()` (publishes the other
  throwaway RSA key beside the old one), `withdraw_old_key()`,
  `config(|c: &mut OAuthConfig| ..)` (a `ResolvedOAuthConfig` for that
  authority with neutral defaults: resource `https://api.example.test/`,
  audience `https://api.example.test/audience`, required scope `api:read`,
  `KeyNaming::Dotted("oauth")`; it panics with the `ConfigError` text if the
  adjusted config does not resolve) and `token()`. Dropping the authority stops
  its server. `testing::TokenBuilder` (`subject`, `scopes`, `audience`,
  `audiences`, `issuer`, `expires_in`, `expired`, `not_before_in`,
  `issued_ago`, `typ`, `without_typ`, `alg`, `kid`, `claim`, `without_claim`,
  `sign`) builds a token the `config` validator accepts by default and signs
  RS*/PS*/ES256/EdDSA with the matching published throwaway key. The served
  JWKS holds one labelled JWK per algorithm (`test-key-a` for RS256,
  `test-key-a-rs384`, `-rs512`, `-ps256`, `-ps384`, `-ps512`, the same for
  `test-key-b`, plus the P-256 and Ed25519 keys), so no key is alg-less and
  no validator logs the ambiguous-key warning. Also `testing::KID_B`, `N_B`
  and `jwk_rsa_b()` (the public half of the existing `KEY_B_PEM`). Every
  existing `testing` item is unchanged. Documented: `testing` follows semver
  like the rest of the crate, and a handler test that skips validation can
  build an `AuthorizedToken` with `AuthorizedToken::new(..).with_claims(..)`.
  Closes oauth-resource-server#12.
- `AuthorizedToken` now carries the verified claims and token metadata, so a
  handler no longer decodes the JWT a second time: `issuer`, `audiences` (a
  string `aud` normalized to a list), `expires_at`, `issued_at`, `client_id`
  (`client_id`, else `azp`) and `jti`, plus `claims()` (the raw claim map) and
  `claims_as::<T>()` (deserialize it into your own type). They are filled from
  the claims the single signature-verifying decode already produced; no
  validation check changed. The struct is `#[non_exhaustive]`, so this is not
  a breaking change. `AuthorizedToken::new` is unchanged and defaults the new
  fields (empty issuer, audiences and claims; `expires_at` 2100-01-01), and
  `with_claims`, `with_issuer`, `with_audiences`, `with_expires_at`,
  `with_issued_at`, `with_client_id` and `with_jti` set them for handler tests.
  A fractional `exp`/`iat` is rounded as `jsonwebtoken` rounds it, and one beyond
  9999-12-31T23:59:59Z saturates to that instant.
  Closes oauth-resource-server#6.
- axum extractors (feature `axum`): `AuthorizedToken` and `Credential`
  implement `FromRequestParts`, and `Option<AuthorizedToken>` /
  `Option<Credential>` work through `OptionalFromRequestParts`. A handler can
  take `credential: Credential` instead of `Extension<Credential>`. When the
  `AuthLayer` inserted nothing, the extractor refuses with that layer's own
  401 and `WWW-Authenticate` challenge (built by the same code as the layer's
  refusals, `on_reject` body included); the `Option` forms return `None`. On
  a route no `AuthLayer` covers, all four answer 500 and log at `error`
  instead of reading the request as anonymous. `Extension<..>` extraction
  keeps working unchanged.
- `AuthLayerBuilder::optional()`: a request that presents no credential
  passes through with nothing inserted (logged at `debug`). A presented but
  refused credential (invalid, expired, unknown, wrong static token, or
  valid without the required scopes) gets the same 401/403 and challenge as
  without `optional()`. "No credential" means every value of every configured
  source header is absent or blank, as `authenticate()` classifies `Missing`;
  a header value that is not visible ASCII, a non-blank later value of a
  repeated header, any `DPoP`-scheme value and a `Bearer` value followed by a
  tab and a token count as presented and are refused. An optional layer
  removes any `Credential`/`AuthorizedToken` an outer layer inserted, so a
  pass-through always extracts as `None`; strict layers are unchanged (their
  extensions accumulate, now documented under "Nested layers"). `build()`
  still refuses a layer with no static token and no validator.
- A typed per-handler scope extractor is not included; it waits on
  per-request 403 challenges (oauth-resource-server#4).
- `OAuthValidator::key_set_status()` returns a `KeySetStatus`
  (`#[non_exhaustive]`): the number of usable signing keys held, the JWKS URL
  in use (configured or discovered), when a refresh was last attempted and
  last succeeded, and the last refresh error. `OAuthValidator::is_ready()` is
  true once at least one key is held. Both are synchronous and passive — no
  I/O, and they never wait on a refresh in flight — so a readiness probe, a
  status page or a metrics scrape can poll them; `refresh_now()` fetches
  every time and does not belong in a probe. The README has a
  readiness/liveness probe recipe
  (oauth-resource-server#9).
- `RefreshError::kind()` and the `#[non_exhaustive]` `RefreshErrorKind`
  (`Discovery`, `Fetch`, `Parse`, `NoUsableKeys`, with `as_str()` labels): the
  stage a key refresh failed at, safe to show where the full error message
  (which names URLs and repeats upstream error text) is not.
- `refusal()` and `refusal_with_static_challenge()`, with the `Refusal`
  result (`status: u16`, `www_authenticate: Option<String>`,
  `#[non_exhaustive]`): the framework-free mapping from a `TokenRejection` to
  its status (401, or 403 for insufficient scope) and `WWW-Authenticate`
  challenge (the validator's with OAuth; otherwise `DEFAULT_STATIC_CHALLENGE`,
  another of the caller's choosing, or none). The axum layer now makes its
  refusal decision through the same private function, so a non-axum
  integration built on `authenticate()` + `refusal()` sends exactly what the
  layer sends; the axum layer's responses are unchanged.
  `DEFAULT_STATIC_CHALLENGE` is now also exported at the crate root
  (`axum::DEFAULT_STATIC_CHALLENGE` is the same constant). The challenge
  returned is always a valid header value: a caller's static challenge with
  any byte outside visible ASCII, SP and HTAB (a CR or LF, say) is replaced by
  `DEFAULT_STATIC_CHALLENGE`.
- A `tower` feature with `http_layer::HttpAuthLayer` (built with
  `HttpAuthLayerBuilder`, wrapping into `HttpAuthService`): the axum layer's
  check for any `tower` service over `http::Request<ReqBody>` /
  `http::Response<ResBody>`, whatever the body types (hyper, tonic, ...). Same
  builder settings, fail-closed build, sensitive credential headers,
  `WWW-Authenticate` on every 401/403, log levels (target
  `oauth_resource_server::http_layer`) and `Credential`/`AuthorizedToken` request
  extensions. A refusal's body is `ResBody::default()` unless an `on_reject`
  closure builds the response; the layer then sets its status and challenge.
  (`RefusalResponse`, the bound both satisfy, is sealed: it can be named, not
  implemented.) The module is `http_layer`, not `tower`, so a downstream
  `use oauth_resource_server::*;` next to the `tower` crate stays unambiguous. Both layers share one
  implementation of the credential check. The `axum` feature now implies
  `tower`, and `CredentialSource`, `RejectContext` and `AuthLayerError` are
  defined in the `http_layer` module and re-exported, unchanged, from `axum`.
- `examples/hyper.rs`: a plain hyper 1.x server built on `authenticate()` and
  `refusal()`. The README's new "Using with other frameworks" section covers
  the tower layer, any other stack, and an actix-web middleware sketch.
  Closes #14.
- `OAuthValidator::invalid_token_challenge()` and
  `insufficient_scope_challenge()` (and so `refusal()`) always return a
  valid header value. A hand-edited `ResolvedOAuthConfig` whose challenge
  would not be one (a CR, LF or other control or non-ASCII character in
  `resource` or a scope; `resolve` refuses every such config) still builds a
  validator, as before, but it logs that once at `error` (the setting named,
  the URL redacted) and uses a fallback: `Bearer error="invalid_token"` /
  `Bearer error="insufficient_scope"`, with `scope` only when that is valid.
  Before, those strings could split a header in a hand-built integration.
  Both layers still refuse to build with such a validator
  (`AuthLayerError::InvalidChallenge`), exactly as the axum layer did.
- Structured configuration problems (oauth-resource-server#2), with no
  breaking change. `ConfigError::problem_details()` and
  `EnvOAuthConfig::problem_details()` return `ConfigProblem`s
  (`#[non_exhaustive]`): `kind()` (a `#[non_exhaustive]` `ProblemKind` with a
  stable `as_str()` label: `MissingRequired`, `InvalidUrl`, `InsecureHttp`,
  `BlankRequiredScope`, `MultiWordScope`, `InvalidScopeToken`,
  `EmptyListEntry`, `NoRequiredScope`, `EmptyScopeClaims`, `BadAlgorithm`,
  `NoAlgorithms`, `LeewayTooLarge`, `EnvLoad`, `EnvParse`, `Other`), `keys()`
  (the settings named, spelled through the `KeyNaming`), `message()` and
  `Display`. Match on the kind instead of the message text. Also added:
  `ConfigError::from_problems`, and `From<String> for ConfigProblem` (kind
  `Other`) so an application's own loader can mix problems in. The public
  `problems: Vec<String>` fields and `ConfigError::new` are unchanged and
  message text is byte-identical; `problems` is now rendered from the same
  list, and editing it in place does not update `problem_details()`. The
  `EnvError` variants were already `#[non_exhaustive]`.

### Security

- Log lines and key-refresh errors (`RefreshError`'s `Display`/`Debug`) now
  redact any userinfo (`https://user:pass@…` → `https://***@…`), query
  (`?***`) and fragment (`#***`) in the issuer, JWKS and discovery URLs they
  name, and quote upstream HTTP errors without the URL they would otherwise
  repeat. `resolve` accepts userinfo in `issuer`/`jwks_uri`, and the fetch
  sends it as HTTP Basic auth, so earlier releases could write that
  credential (or a secret query parameter) to the log. The fetch still uses
  the URL unchanged. The new `KeySetStatus::jwks_uri` is redacted the same
  way.

### Changed

- `AuthorizedToken`'s `Debug` no longer derives: it prints every field but shows
  the verified claims as names only, since claim values can be personal data.
- The `serde` crate is now always compiled (it was already in every build,
  through `jsonwebtoken` and `reqwest`, and `claims_as` is bounded by
  `serde::de::DeserializeOwned`);
  the `serde` feature still exists and now only enables its derive macros. The
  `testing` feature no longer names `serde`.
- After a failed background key refresh while **no** key is held (the first
  load failed and none has succeeded since), `spawn_background_refresh` now
  retries after 5 s, doubling to at most 5 minutes, instead of after a minute
  doubling to an hour. A keyless validator refuses every token, and a
  readiness probe keeps away the traffic that would otherwise trigger a
  refetch, so it previously could stay keyless for up to an hour after the
  identity provider recovered. Once any key is held the schedule is
  unchanged (an hour between passes; a failed pass retried after a minute,
  doubling to an hour), as is the once-a-minute unknown-`kid` refetch limit.
- Minimum versions of direct dependencies raised, checked with `cargo
  update -Z direct-minimal-versions`: `jsonwebtoken` 9 -> 9.2 and `tokio`
  1 -> 1.15 (the next-older releases tried do not compile), plus `tracing`
  0.1 -> 0.1.29, `serde` 1 -> 1.0.152, `serde_json` 1 -> 1.0.64, `subtle`
  2 -> 2.5, `tower-layer` and `tower-service` 0.3 -> 0.3.3, which are what the
  resolver needs to resolve against `reqwest`'s and `axum`'s own minimums. A
  build that already resolves to current releases is unaffected; only a lock
  file pinning an older release of one of these needs updating. These are
  compile-time floors, not exhaustive searches for the oldest working release
  and not a claim that the test suite was run against them.
- Internal: the per-entry JWK parse in the JWKS fetch path is now its own pure
  function (`parse_jwks_entry`), behavior-identical, so it can be tested and
  fuzzed on its own.

### CI and tooling (maintainer-facing)

- CI now also runs
  `cargo semver-checks` against the latest crates.io release,
  `cargo hack --feature-powerset`, a minimal-versions build and
  `cargo deny check` (new `deny.toml`: licence allowlist, crates.io-only
  sources, duplicate-version warnings, advisories); `release.yml` repeats the
  `cargo deny` and semver checks on the tagged commit. A new `fuzz/` crate
  fuzzes the crate's own parsers, run nightly by `fuzz.yml` (never on pull
  requests); its entry points exist only under `--cfg fuzzing` and are not
  part of the public API or the published package.

## [0.1.2] - 2026-09-28

No library changes: the code, public API and behavior are identical to
0.1.1, and upgrading needs nothing.

### Changed

- Release process (maintainer-facing): a new version is now published to
  crates.io when the maintainer publishes a GitHub release for it, instead
  of automatically when a version bump merges to `master`. Merging to
  `master` now runs CI only. 0.1.2 is the first version released this way.

## [0.1.1] - 2026-09-28

### Documentation

- README: a new "CORS for browser-based clients" section, showing a
  `tower-http` `CorsLayer` on the protected and metadata routes, the
  Streamable HTTP headers/methods (`Mcp-Session-Id`, `Mcp-Protocol-Version`,
  `Last-Event-Id`, `DELETE`) a browser-based MCP client additionally needs
  allowed, and why `Access-Control-Expose-Headers: WWW-Authenticate` and
  `Mcp-Session-Id` are needed for a browser's JavaScript to read them. The
  doctest drives an actual preflight `OPTIONS` request (and a follow-up
  request) through the layered router with `tower::ServiceExt::oneshot` and
  asserts on the response headers, so it is exercised, not just compiled
  (#19).
- README: a new "Embedding `OAuthConfig` in your own config" section
  explaining that `OAuthConfig`'s `#[serde(deny_unknown_fields)]` is
  silently defeated by `#[serde(flatten)]` in an application's own config
  struct (a general serde limitation) and that the field should be nested
  instead (#19).
- README: clarified that an omitted `scopes_supported` resolves to the
  required scopes identically on the `serde` and `env` paths — the only
  path-specific difference is that the `env` loader cannot express an
  explicit empty list, which was already documented separately (#19).
- README: a new "Reading the token inside a tool handler" section under
  "Using with MCP", showing how `AuthorizedToken` reaches an MCP tool
  handler through `http::request::Parts` and describing how the rmcp SDK's
  `Extension<T>` extractor surfaces it (#19).
- No library behavior or public API change.

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

[Unreleased]: https://github.com/St0nefish/oauth-resource-server/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/St0nefish/oauth-resource-server/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/St0nefish/oauth-resource-server/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/St0nefish/oauth-resource-server/releases/tag/v0.1.0
