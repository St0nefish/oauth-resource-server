# oauth-resource-server

Rust library crate (`oauth_resource_server`). OAuth 2.0 bearer-token **resource
server** support for any Rust HTTP service: JWT access-token validation against a
JWKS (RFC 9068), RFC 9728 protected-resource metadata, RFC 6750
`WWW-Authenticate` challenges, an optional static API key alongside OAuth, and
axum integration. This file is for agents working on the crate itself — see
`README.md` for the consumer-facing docs.

This is a **public** crate (GitHub `St0nefish/oauth-resource-server`, published on
crates.io). The leak policy at the end of this file is a standing rule, not a
one-time cleanup: it applies to every commit, not just the first one.

## Architecture

The crate turns a process into an OAuth 2.0 resource server and nothing more: it
verifies JWT access tokens a separate authorization server minted, and never
issues, refreshes, revokes or introspects one. The shape an application builds
is always the same three steps, laid out in `src/lib.rs`'s module docs: resolve
an `OAuthConfig` into a `ResolvedOAuthConfig` (`OAuthConfig::resolve`,
naming settings with a `KeyNaming` so errors read the way the operator wrote
them), build one `OAuthValidator` from it and `Arc`-share it
(`OAuthValidator::spawn_background_refresh` warms and then hourly refreshes the
key cache), then per request call `authenticate()` (framework-free, with
`refusal()` for the 401/403 and its challenge) or run the `axum` feature's
`AuthLayer`/`require_auth` or the `tower` feature's `HttpAuthLayer`. Nothing
here hot-reloads: a changed config takes effect only when a new validator and
a new layer are built,
which in an application means a restart — an application should treat every
setting it resolves through this crate as restart-required, and this crate
never claims otherwise in its docs.

**Provider-agnostic by construction.** Authorization servers agree on the
signature and on `iss`/`aud`/`exp`, and disagree on nearly everything else an
access token carries — where scopes live (`scope_claims`), what audience they
stamp (`audience`/`audiences`), which algorithms they sign with (`algorithms`),
whether `typ` is `at+jwt` (`require_at_jwt`), which claim names the caller
(`principal_claims`). Every one of those differences is an `OAuthConfig` field,
never a code branch. A new provider's shape gets a **documented-shape fixture
test** — built from that provider's own published token/JWKS shape using
`testing`'s fixtures, never a real token or issuer — labeled in its doc comment
and in `docs/providers.md` as `verified in production` / `verified in a
sandbox` / `documented-shape fixture, not live-tested` (never upgrade an
existing label without having done the verification it claims). If you find
yourself writing `if provider == "..."`, the config surface is missing a knob,
not the crate missing a branch.

**Security invariants that must never regress**, each enforced by a named
piece of code so a change to any of them is a deliberate, reviewable act:

- The JWS algorithm allowlist is checked from the **unverified** token header
  before any key fetch: `OAuthValidator::check_header` (`src/validator.rs`)
  runs size/shape/`crit`/`alg`/`typ` checks and returns before `JwksStore` is
  ever touched — junk cannot schedule IdP traffic.
- A header carrying `crit` is refused (`validator::check_crit`, RFC 7515
  §4.1.11): this crate understands no JWS extension, so any `crit` — unknown,
  empty or malformed — makes the token invalid. jsonwebtoken's `Header` drops
  `crit` silently, which is why the protected header is also read raw.
- Each JWKS key is narrowed to only the algorithms its own key type can
  produce: `algorithms::key_algorithms` (RSA/EC/OKP by curve) intersected with
  the key's own declared `alg` (if any) and the configured allowlist, in
  `jwks::cached_key`. `algorithms::parse_algorithm` refuses `HS256`/`384`/`512`
  and `none` outright — no config can turn an HMAC or unsigned algorithm on.
- No HMAC (`oct`), no `use: enc` key, and no key whose `key_ops` lacks `verify`
  is ever usable to verify a signature: `algorithms::key_algorithms` returns
  `None` for `AlgorithmParameters::OctetKey`, and `jwks::cached_key` skips any
  JWK whose `public_key_use` is not `Signature`/absent or whose
  `key_operations` is present without `KeyOperations::Verify` (RFC 7517 §4.3).
  `algorithms::Algorithm` (crate-owned) has no HMAC or `none` variant at all.
- A JWK with no `alg` stays usable for every allowlisted algorithm its type
  can produce (a documented RFC 8725 §3.1 deviation); `jwks::JwksStore::refresh`
  logs a `warn` naming its `kid` the first time such a key appears
  (`CachedKey::ambiguous`). Do not silently bind such a key to one algorithm —
  that would break any provider that signs with a non-first algorithm.
- Signature verification and `iss`/`aud`/`exp`/`nbf` all happen inside **one**
  `jsonwebtoken::decode` call (`OAuthValidator::verify`) — the claim checks can
  never be reordered to run after a signature has already been trusted. This
  depends on two settings `OAuthValidator::build` (`src/validator.rs`) puts on
  the `jsonwebtoken::Validation` before that call, and that must never
  regress: `validation.set_required_spec_claims(&["exp", "iss", "aud"])`
  (`jsonwebtoken` validates `aud`/`exp` only when the claim is *present* —
  without this, a token carrying no `aud` or no `exp` at all would pass) and
  `validation.validate_nbf = true` (off by default in `jsonwebtoken`; RFC 9068
  tokens from some providers carry `nbf`, and this is what makes a
  not-yet-valid token fail). jsonwebtoken skips an `nbf` it cannot read as a
  number, so `verify` refuses one itself (`nbf_is_numeric_date`) — without
  that, a string or out-of-range `nbf` would silently disable the check.
- A token carrying a `cnf` claim (sender-constrained: DPoP `jkt`, mTLS
  `x5t#S256`) is refused (`OAuthValidator::verify`): this crate cannot verify
  the binding, and accepting it as a bearer token would undo it (RFC 9449
  §7.2, RFC 8705 §3).
- `iss` is re-checked as an exact single string **after** decode
  (`OAuthValidator::verify`): `jsonwebtoken` alone would also accept an `iss`
  *array* merely containing the right value, which RFC 7519's single
  `StringOrURI` does not allow and no real authorization server emits.
- Every failure mode fails closed: `jwks::JwksStore::refresh` keeps the keys
  already held on any fetch/parse/discovery failure (an IdP outage never
  revokes keys that are still good — which also means a withdrawn key stays
  trusted until a refresh succeeds; there is deliberately no maximum
  staleness), and every rejection path in `OAuthValidator`/`JwksStore` returns
  `TokenRejection`, never a token.
- A key refetch cannot be cancelled by its caller: `JwksStore::refresh_detached`
  runs it in a spawned task that owns the `refresh_lock` guard
  (`OwnedMutexGuard`) until the fetch completes. Run inline, a dropped request
  future (client disconnect, timeout layer) would stamp `last_attempt` and
  spend the unknown-`kid` cooldown with no keys loaded.
- The JWKS `RwLock` (`jwks::JwksStore::jwks`) is never held across a network
  call — only for the instant it takes to read or swap in-memory state;
  refreshes serialize on a separate `refresh_lock` `Mutex` instead, so a
  request whose key is already cached is never stalled behind a slow IdP.
  `OAuthValidator::key_set_status`/`is_ready` read neither: they copy
  `jwks::JwksStore::status`, a third, synchronous `std::sync::Mutex` that is
  locked only to copy or overwrite a few fields — never across an `.await`,
  never while taking `jwks` or `refresh_lock` — so a probe never does I/O or
  waits on a refresh in flight.
- An unknown `kid` triggers at most one JWKS refetch per
  `jwks::JWKS_MIN_REFETCH_INTERVAL` (60s) — `kid` comes from the unverified
  header, so without this cooldown a stream of junk tokens turns the process
  into an amplifier pointed at the IdP. A separate, unconditional hourly
  refresh (`jwks::JWKS_BACKGROUND_REFRESH_INTERVAL`) is what notices a key the
  authorization server has **withdrawn**, which an unknown-`kid` refetch alone
  would never catch (it only ever adds keys). After a failed background pass
  it retries sooner (`jwks::background_retry_delay`: 60 s doubling to the
  hour) — or, while no key is held at all (a failed first load),
  `jwks::keyless_retry_delay`: 5 s doubling to 5 minutes, because a keyless
  validator refuses everything and a readiness probe keeps away the traffic
  that would trigger an unknown-`kid` refetch. The 5 s floor is the fastest
  any background retry may ever run; both schedules are timer-driven only,
  never shortened by a request, and neither touches the 60 s unknown-`kid`
  cooldown. The task holds only a `Weak` between passes and stops when the
  validator's `alive` watch sender drops with it.
- A JWKS fetch that redirects from `https` to a non-`https` URL is refused
  outright, and one that redirects to plain `http` on a non-loopback host is
  refused without `allow_insecure_http` (`jwks::judge_redirect`, the custom
  `reqwest::redirect::Policy` built by `jwks::http_client`). A `jwks_uri`
  discovered from a plain-`http` (loopback) issuer is held to the same
  opt-in (`jwks::jwks_uri_from_metadata`) — `resolve` only sees configured
  URLs, so everything reached at run time is checked where it is reached. And
  every fetch is bounded: `jwks::MAX_FETCH_BYTES` (256 KiB) caps the response
  body, `jwks::MAX_JWKS_KEYS` (64) caps how many keys are parsed from it, and
  `token::MAX_TOKEN_BYTES` (16 KiB) caps the credential itself before it is
  even decoded — none of the three can be used to exhaust memory or CPU with a
  hostile response or an oversized token. Every key set, fetched or seeded by
  `OAuthValidatorBuilder::initial_jwks`, goes through the one path
  `jwks::keys_from_jwk_set` (key cap, `parse_jwks_entry`/`cached_key`
  narrowing; a seed also through `keys_from_jwk_set_json`'s
  `MAX_FETCH_BYTES` cap). No `OAuthValidatorBuilder` option relaxes any rule
  in this bullet: `add_root_certificate_pem` only *adds* anchors
  (`reqwest::ClientBuilder::add_root_certificate` — rustls merges them with
  the webpki/native roots, native-tls with the OS store), an explicit
  `proxy` tunnels https with `CONNECT`, and `fetch_timeout` is held to
  `MIN_FETCH_TIMEOUT..=MAX_FETCH_TIMEOUT` (1–60 s) because it bounds how
  long a refresh holds `refresh_lock`. No proxy, explicit, environment or
  system, ever carries a fetch of a loopback URL: `jwks::http_clients`
  builds two clients from the same settings and redirect policy, and
  `HttpClients::for_url` (called in `fetch_json` for every discovery URL
  and the configured or discovered `jwks_uri`) gives a URL satisfying
  `is_loopback_url` the `loopback` client (`no_proxy()`) and everything else
  `normal` — reqwest's default proxy handling untouched, or, with an
  explicit proxy, `no_proxy()` + that proxy + `jwks::PROXY_BYPASS`. Do not
  reimplement reqwest's env/system proxy parsing instead: it cannot be
  matched exactly (whitespace, `system-proxy` on macOS/Windows via feature
  unification). The one residual, documented in the README security model
  and on `for_url`: a redirect from a non-loopback URL to a loopback one
  stays in `normal`, so an env/system proxy can carry that hop — https to
  https (TLS end to end) or plain http already gated by `judge_redirect`.
  Refusing such redirects would narrow accepted input.
- `WWW-Authenticate` is set — or overwritten, whatever a caller's `on_reject`
  callback returned — on **every** 401/403 once OAuth is configured
  (`http_layer::Gate::finish`, called by both `axum::Enforce::reject` and
  `http_layer::HttpAuthLayer::check`). The status and which challenge are decided
  in exactly one place, `refusal::select`, which the public `refusal()`/
  `refusal_with_static_challenge()` (over the validator's challenge strings)
  and `http_layer::Gate::status_and_challenge` (over the layers' pre-validated
  `HeaderValue`s) both call — so a hand-built integration on `refusal()` and
  either layer cannot disagree; `axum::shared_refusal_tests` pins that, and
  that the two layers answer every request identically. A missing credential gets the same
  `invalid_token` challenge as a bad one, deliberately: `resource_metadata` is
  how claude.ai (and others) find the authorization server, and it refuses to
  start the flow at all without it. A validator challenge that is not a valid
  header value fails `AuthLayerBuilder::build` and
  `HttpAuthLayerBuilder::build` (`AuthLayerError::InvalidChallenge`, from the
  shared `http_layer::Gate::build`) instead of shipping challenge-less 401s —
  and `OAuthValidator::build` never hands out such a challenge either: it
  still builds (refusing would narrow what builds), but logs once at `error`
  (the settings named via `KeyNaming`, the URL through `redact_url`) and
  stores `challenge::fallback`s (`Bearer error="…"`, `scope` only if valid),
  setting `challenge_fallback`, which `Gate::build` turns into
  `AuthLayerError::InvalidChallenge` so both layers fail exactly where the
  axum layer always did (`tests/challenge_fallback_log.rs` pins the log);
  so `refusal()` can never return a challenge that splits a header; a
  caller's `static_challenge` string that is not a header value is replaced
  by `DEFAULT_STATIC_CHALLENGE` in `refusal_with_static_challenge`.
  Without OAuth, a 401 carries `DEFAULT_STATIC_CHALLENGE` (defined in
  `refusal.rs`, re-exported at the root and as `axum::DEFAULT_STATIC_CHALLENGE`;
  RFC 9110 §15.5.2) unless the application opts out with
  `static_challenge(None)` (`refusal_with_static_challenge(.., None)` for a
  hand-built integration).
- `OAuthConfig::resolve` refuses what would silently weaken the deployment:
  a plain-`http` `issuer`/`jwks_uri`/`resource` on a non-loopback host without
  `allow_insecure_http` (RFC 8414 §2, RFC 9728 §1.2), no required scope with
  `require_at_jwt` off without `allow_unscoped_tokens` (ID tokens would pass),
  a required or advertised scope that is not an RFC 6749 §3.3 scope-token, and
  a URL containing a space, control or non-ASCII character (the raw string
  reaches every challenge header). The opt-ins are explicit fields, never a
  default.
- `AuthLayer` is **fail-closed by construction**: `AuthLayerBuilder::build`
  refuses to build with neither a static token nor an OAuth validator
  (`AuthLayerError::NoCredential`) — the check is `http_layer::Gate::build`, which
  the `tower` feature's `HttpAuthLayerBuilder::build` runs too, and
  `HttpAuthLayer`'s only pass-through is likewise the explicitly named
  `HttpAuthLayer::allow_unauthenticated()` (or an `Unauthenticated` decision);
  the axum layer's only pass-through is the explicitly
  named `AuthLayer::allow_unauthenticated()`, which only
  `policy::StaticTokenDecision::Unauthenticated` (itself produced only by an
  explicit `allow_unauthenticated` at the call site) ever yields via
  `AuthLayer::from_decision`/`build_with_decision`. `AuthLayerBuilder::optional()`
  is not a second pass-through: it still needs a credential mechanism to
  build, and `http_layer::Gate::admit` (behind both `AuthLayer::check` and
  `HttpAuthLayer::check`) passes a request through only when
  `authenticate()` returned `Missing` AND every value of every source header
  is blank (`CredentialSource::presents_nothing` — an unreadable value, a
  non-blank later value of a repeated header, and anything `names_a_token`
  flags (a `DPoP` scheme, a tab-separated `Bearer` token) count as presented,
  without touching the strict `bearer_credential` parsing); every other
  refusal goes through `Enforce::refuse` exactly as without it. An optional
  layer removes any `Credential`/`AuthorizedToken` an outer layer inserted
  before deciding; strict layers never do (their extensions accumulate — a
  documented behavior existing consumers may rely on).
- The `AuthorizedToken`/`Credential` axum extractors (and their
  `OptionalFromRequestParts` forms) fail closed: the layer inserts a private
  `LayerRan` marker into extensions on every request it passes, so an
  extractor with no value refuses through the same `Enforce::refuse` the
  layer uses (identical status, challenge and `on_reject` body), and with no
  marker at all (a route outside every layer) answers 500 with an `error`
  log — never `None`, never access. `refuse_extraction` logs the two
  unsatisfiable-401 wirings (a required extractor behind
  `allow_unauthenticated`, `AuthorizedToken` behind a layer with no
  validator) at `error` too.
- Secrets never reach a log or a `Debug` impl: `AuthLayer`, `AuthLayerBuilder`,
  `http_layer::HttpAuthLayer`, `HttpAuthLayerBuilder`, `HttpAuthService` and
  `policy::StaticTokenDecision` all hand-write `Debug` to redact the static
  token; `RejectContext` (defined in `http_layer.rs`, re-exported from `axum`)
  hand-writes `Debug` to print header names only, and `http_layer::Gate::admit`
  (both layers) marks every configured credential header
  `set_sensitive(true)` before the callback or the inner service sees it;
  `env::EnvError`'s `Display`/`Debug` never include a secret's value (only
  variable names and file paths); and `TokenRejection::Invalid`'s reason
  string is documented as log-only — never put it in a response body
  (`TokenRejection`'s `Display` renders the category only, for that reason);
  `AuthorizedToken`'s hand-written `Debug` prints the names of the verified
  claims, never their values (`email`, group memberships and the like are
  personal data); the axum extractors' refusal and misconfiguration logs
  print the request path (and extractor name) only, never a claim or a token,
  and so do both layers' own refusal logs (`uri.path()`, no query, so no URL
  there needs `redact_url`). `resolve` accepts userinfo in `issuer`/`jwks_uri` (sent as Basic auth) and
  a query in `jwks_uri`, so every URL this crate displays — in a log line,
  a `RefreshError` message, `KeySetStatus::jwks_uri` — goes through
  `jwks::redact_url` (`***@`, `?***`, `#***`; a placeholder for anything
  unparseable), and a quoted `reqwest` error has its URL stripped
  (`without_url`). The URL actually fetched is never altered. The
  `OAuthValidatorBuilder::proxy` URL may carry a credential too: its
  hand-written `Debug` prints only whether one is set,
  `ValidatorError::InvalidProxy` never carries the refused value (only its
  scheme, or `<redacted>`) nor the URL parser's error, and the
  cleartext-credential `warn` redacts it. `redact_url` returns its
  placeholder when an `@` sits in what parsed as the path
  (`http://alice:1234/s3cret@host`).

**`jsonwebtoken` is pinned to `9.x`, not `11.x`.** None of its types appear in
this crate's public API — `algorithms::Algorithm` is crate-owned, converted
privately (`to_jwt`/`from_jwt`) — so a re-pin is an internal change, not a
breaking release. Keep it that way: never expose a `jsonwebtoken` type. The
rationale lives on the
dependency itself in `Cargo.toml` and must move with any future re-pin: `11.x`
dropped `ring` and forces a choice between `rust_crypto` (pulls in the `rsa`
crate and RUSTSEC-2023-0071, with no fixed version `cargo audit` could ever
pass) and `aws_lc_rs` (needs cmake and a C toolchain in every consumer's
builder). `9.x` on `ring` adds no new crypto implementation to an
already-rustls-based stack. Read that comment, not just this paragraph, before
proposing a bump — the tradeoff has to have genuinely changed (a backend that
is neither unpatched nor a new build-tooling requirement), and if it has, the
comment gets rewritten in the same change.

**Feature matrix**: `rustls-tls` (default; the compiled-in Mozilla root set,
ignoring the OS store and `SSL_CERT_FILE`), `rustls-tls-native-roots` (rustls
with the OS store) and `native-tls` (the platform library, OS store) are
additive, not exclusive — a consumer may enable any of them — and choosing the
TLS backend and its roots for `reqwest`'s JWKS/discovery fetches is their only
job; an authorization server behind a private CA needs one of the last two,
or `OAuthValidatorBuilder::add_root_certificate_pem`, which adds a trust
anchor under every one of the three. With `native-tls` and a rustls feature
both on, reqwest 0.12 uses native-tls (the OS store), not the Mozilla roots.
Enabling *none* is a **compile error** (`compile_error!` in `src/lib.rs`, unconditional — no
`cfg(test)` or docs exemption), because every real authorization server serves
its keys over https and a validator with no TLS backend would build cleanly and
then fail closed on every single token. `serde` gates `Deserialize`/`Serialize`
on `OAuthConfig` via `cfg_attr` (never a straight `#[derive]`, so the crate
builds with `serde` off; the `serde` crate itself is always a dependency, since
`AuthorizedToken::claims_as` is bounded by `DeserializeOwned`, and the feature
only turns on its derive macros). `env` gates the `env` module. `tower` gates
the `http_layer` module (`HttpAuthLayer`, and the pieces both layers share:
`CredentialSource`, `RejectContext`, `AuthLayerError`, and the crate-private
`Gate`) and its three extra deps (`http`, `tower-layer`, `tower-service` — the
small traits axum itself builds on, not the whole `tower` crate). `axum`
implies `tower` and adds the `axum` module and the `axum` dep; the `axum`
module re-exports the shared types, so their `axum::` paths are unchanged.
`refusal()` needs neither: it is core, with no `http` dependency. `testing` gates
`src/testing.rs`'s throwaway keys, JWK builders, token minting and fake JWKS
server — for **consumers'** tests, enabled only from `[dev-dependencies]`,
never in a production build (the private keys are public knowledge; anything
that trusts them trusts everyone; its minting helpers take
`&impl Serialize`). CI's four clippy runs (`--all-features`,
default features, and `--no-default-features` with `native-tls` or with
`rustls-tls-native-roots`) exist because `--all-features` alone hides a `cfg`
that only appears with `rustls-tls` off. `tower` needed no fifth run: nothing
in it varies with the TLS backend, `--all-features` lints it, and the
`feature-powerset` job builds it with and without `axum` (96 builds).
Every feature-gated public item (the `env`/`http_layer`/`axum`/`testing` modules in
`src/lib.rs`, and anything added inside them later) carries
`#[cfg_attr(docsrs, doc(cfg(feature = "...")))]` so docs.rs renders its
feature badge; give a new feature-gated item the same attribute.

## Key conventions

- `#![warn(missing_docs)]` + `#![forbid(unsafe_code)]` in `src/lib.rs`; CI runs
  clippy with `-D warnings`, so every public item needs a doc comment, a
  fallible one needs `# Errors`, and anything with a non-obvious security
  implication gets a `# Security` note.
- `OAuthConfig` is deliberately **not** `#[non_exhaustive]`, so applications
  can build it with functional-record update
  (`OAuthConfig { enabled: true, ..OAuthConfig::default() }`), which keeps
  compiling even after a field is added. What a new field breaks instead is an
  exhaustive struct literal or destructuring pattern that names every field —
  possible only because every field is public and the struct carries no
  `#[non_exhaustive]` — so adding a field is still a breaking change, just not
  for the FRU form above, and ships in a new `0.x` minor.
  `ResolvedOAuthConfig`, `Credential`, `TokenRejection`,
  `StaticTokenDecision`, `CredentialSource`, `KeyNaming`/`KeyNamingBuf`, and
  every error enum (`ConfigError`'s shape aside — see below), **are**
  `#[non_exhaustive]`, so a new resolved setting or a new rejection/refusal
  variant is additive. Match on these with a wildcard arm outside this crate.
- `ConfigError`'s `naming` field is private (`ConfigError::naming()` is the
  read accessor). `ConfigError::problems` stays a public `Vec<String>` for
  compatibility, and the structured, matchable form now exists additively
  (oauth-resource-server#2): `ConfigError::problem_details()` /
  `EnvOAuthConfig::problem_details()` return `#[non_exhaustive]`
  `ConfigProblem`s with a `#[non_exhaustive]` `ProblemKind` and `keys()`.
  Privatizing `problems` was deliberately not done (it would be breaking);
  the two views are rendered from one list at construction, so only an
  in-place edit of the public field can make them differ, and that is
  documented. A new problem in `resolve` or the env loader gets a kind (a new
  `ProblemKind` variant is additive) and its keys; never a bare string.
- No `anyhow` in any public signature; internal code prefers `thiserror` types
  over it too.
- Every problem `OAuthConfig::resolve` and the `env` loader can find is
  collected and reported **at once** — never one problem per run — and every
  message names the offending setting via `KeyNaming` so a half-usable config
  fails at startup with the key in the message, not as a wall of 401s later.
- `config.rs`'s test module pins two generic phrases
  (`config::tests::WIKI_REWRITES`) that mcp-md-wiki's `config::resolve_mcp_oauth`
  rewrites back to its own pre-extraction, MCP-flavored wording so its historical
  message text stays byte-identical (mcp-md-wiki#308). It is an early warning,
  not a contract: message text is not a stable API, and what guarantees
  mcp-md-wiki's text is mcp-md-wiki's own test pinning its full output, which
  fails on its dependency bump if the wording here changes. This crate's own
  message text must stay generic (no "MCP" anywhere). Rewording either phrase
  is allowed; when the pin fails, change `WIKI_REWRITES` deliberately and tell
  mcp-md-wiki, whose rewrite then changes with its lock bump.
- Test fixtures (`src/testing.rs`) come in two layers. The older free
  functions and constants (`ISSUER`, `resolved_config`, `valid_token`, …)
  model a plausible Authentik deployment (per-application issuer with a
  trailing slash, client-id audience, `mcp:read`/`mcp:write` scopes) because
  that is the production shape the original regression tests were written
  against — not because the crate is MCP-specific — and they stay for this
  crate's own regression tests and for downstream suites that use them. The
  consumer-facing harness (`TestAuthority`, `TokenBuilder`) uses **neutral**
  defaults (`https://api.example.test/` resource, a distinct `/audience` audience, `api:read`, `KeyNaming::Dotted("oauth")`)
  and is what docs and new tests should reach for. Docs must always present
  the crate as general-purpose; the fixtures' scope names are an
  implementation detail of the test suite, never a code default.
- **`testing` follows semver like the rest of the crate**: downstream test
  suites use it, so removing, renaming or changing the behavior of a public
  item there (a constant, a `kid`, a key the served JWKS holds, a builder
  default) is breaking and ships in a new `0.x` minor; additions are not.
  Only panic-message wording is exempt. Its docs and the README's "Testing
  your integration" section say so, and CI's `cargo-semver-checks` covers it
  (it is compiled with `--all-features`).
- Tests use generated-for-the-suite throwaway keys only (`KEY_A_PEM`,
  `KEY_B_PEM`, `EC_PEM`, `ED_PEM` in `src/testing.rs`) and example domains
  (`*.example.test`, `*.example.com`) — never a real issuer, client ID, or
  secret. New tests follow the same rule.

## Keeping docs in sync

Docs are part of the change, not a follow-up, exactly as much as the code —
more, since this crate's whole value to a consumer is correct documentation of
a security-sensitive surface. A change to a config field, a default, a public
API's behavior, a 401/403 response shape, or anything in the security-invariant
list above updates every place that describes it **in the same commit**:

- `README.md` — the primary consumer doc (feature table, TLS note, quickstarts,
  full config reference with real defaults, security/threat model, design
  rationale, "Using with MCP", restart-required note, FAQ). `src/lib.rs`
  includes it verbatim as the crate-level rustdoc
  (`doc = include_str!("../README.md")`) whenever the `serde`, `env` and
  `axum` features are all on — the configuration CI and docs.rs both build
  with — so every code block fenced with the `rust` language tag in it is a
  doctest compiled in that configuration; fence anything that is not
  standalone, compiling Rust (a config snippet, a shell command, a fragment)
  with `toml`, `yaml`, or `text` instead of `rust`. A narrower build falls
  back to a short pointer doc comment in `src/lib.rs` instead; keep that
  comment's summary in sync with the README's own opening paragraph if you
  reword either.
- `docs/providers.md` — provider recipes, each carrying its exact
  `verified in production` / `verified in a sandbox` /
  `documented-shape fixture, not live-tested` label; never upgrade a label
  without having done the verification it claims.
- rustdoc — module-level docs on every module, doc examples on the main entry
  points (`OAuthValidator::new`/`validate`, `OAuthValidator::builder` and
  each `OAuthValidatorBuilder` option, `authenticate`, `refusal`, the
  `AuthLayer` builder, `require_auth`, `metadata_router`, the
  `HttpAuthLayer` builder and its `on_reject`, `oauth_config_from_env`,
  `secret_from_env`, `static_token_policy`).
- `examples/` — runnable, and built in CI (`cargo build --examples
  --all-features`), so an example that no longer compiles against a changed
  public API is a CI failure, not a stale doc.
- `CHANGELOG.md`'s `[Unreleased]` section (or the next version's section once
  one exists) — including anything a consumer's upgrade needs to know.
- `SECURITY.md`'s "Security invariants this crate maintains" list, if the
  change adds, removes or narrows one of the invariants above.
- `deny.toml` and `.cargo/audit.toml` — keep their vulnerability-advisory
  ignores identical (both empty today), each with the reason and what would
  let it go (`deny.toml` also gates yanked crates and, for direct
  dependencies only, unmaintained ones, which `cargo audit` does not fail
  on, so those are not mirrored); the
  licence allowlist in `deny.toml` follows the dependency tree, so a new
  dependency with a new licence is a deliberate edit there.
- `CONTRIBUTING.md` — duplicates the full check matrix, the MSRV command, the
  `jsonwebtoken` pin rule, and the provider-label wording; a change to the CI
  matrix or to that wording goes here too.
- `.github/pull_request_template.md` and `.github/ISSUE_TEMPLATE/*` — the
  provider-compatibility issue template asks a reporter for the same
  issuer/`typ`/`alg`/claims shape (secrets redacted) that `docs/providers.md`
  asks a new provider recipe to document; keep the two asking for the same
  thing.

Check each claim against the code, not against the plan that preceded it. Code
comments explain the code as it is: cite issues as `oauth-resource-server#N`
for issues in this repo, `mcp-md-wiki#308` for the extraction this crate came
from, and never a local plan/review label ("chunk p2", "round one").

## Module layout

| File | Purpose |
|---|---|
| `lib.rs` | Crate root: the module tree, feature gating, and the no-TLS-backend `compile_error!`. `#![warn(missing_docs)]` + `#![forbid(unsafe_code)]`. Re-exports the core, always-available API at the crate root (`OAuthConfig`, `ConfigError`, `ConfigProblem`/`ProblemKind`, `KeyNaming`/`KeyNamingBuf`, `OAuthValidator`, `OAuthValidatorBuilder`, `AuthorizedToken`, `TokenRejection`, `Credential`, `authenticate`, `refusal`/`refusal_with_static_challenge`/`Refusal`/`DEFAULT_STATIC_CHALLENGE`, `static_token_policy`, `Algorithm`/`AlgorithmError`, …); no `jsonwebtoken` type is re-exported or appears in a public signature. The feature-gated `env`, `http_layer` (feature `tower`), `axum` and `testing` modules stay public submodules a consumer reaches through their own path instead (`oauth_resource_server::axum::AuthLayer`, `oauth_resource_server::http_layer::HttpAuthLayer`, `oauth_resource_server::env::secret_from_env`) — nothing inside them is re-exported at the root. `__fuzz` (`src/__fuzz.rs`, `#[doc(hidden)]`) is declared under `#[cfg(all(fuzzing, feature = "axum", feature = "testing"))]` only: the entry points the `fuzz/` crate uses to reach crate-internal parsers, never compiled in an ordinary build and never public API — a new fuzz target adds a function there and widens the target internal to `pub(crate)`, nothing more |
| `config.rs` | `OAuthConfig` (the unvalidated, serde-deserializable input shape — every field `#[serde(default)]`, `deny_unknown_fields`, not `#[non_exhaustive]`) and `OAuthConfig::resolve` (all-or-nothing validation into `ResolvedOAuthConfig`, every problem collected at once via `check_url` and the scope/algorithm/leeway checks). `KeyNaming`/`KeyNamingBuf` (`Dotted`/`Env`) decide how a problem names a setting, carried onto `ResolvedOAuthConfig::key_naming` and `ConfigError` so log lines and errors produced after resolution name settings the same way the input did. `ConfigError::problems` (`Vec<String>`, kept for compatibility) is public, `naming` is private (`ConfigError::naming()` reads it); the structured form is a private `Vec<ConfigProblem>` (`problem_details()`; `ConfigProblem` and `ProblemKind` are `#[non_exhaustive]`, `keys()` are the settings named, already rendered via `KeyNaming`), and both are filled from one list in `ConfigError::assemble`, so `resolve` builds `ConfigProblem`s with a kind at every push site — a new problem needs a `ProblemKind` (or `Other`), its `keys`, and a row in `config::tests::one_problem_per_kind`. `ConfigError::new(naming, Vec<String>)` is frozen (mcp-md-wiki calls it with `.collect()` inference) and wraps strings as `Other`; `from_problems` is the structured constructor. `required_scopes` (list) and `required_scope` (single) are unioned, trimmed, deduplicated, order-stable; an empty union means no scope check and needs `require_at_jwt` or `allow_unscoped_tokens`; an explicitly blank/whitespace entry in either is always an error, and every required or advertised scope must be a scope-token (`is_scope_token`). An omitted `scopes_supported` resolves to the required scopes. `check_url` refuses space/control/non-ASCII characters; a plain-`http` non-loopback URL needs `allow_insecure_http`. `ResolvedOAuthConfig` is `#[non_exhaustive]`; its `accepted_audiences()` is `audience` ∪ `audiences`. Owns the `WIKI_REWRITES` test-pinned strings — see Key conventions above |
| `algorithms.rs` | The two independent algorithm gates, and the crate-owned `Algorithm` enum (no HMAC/`none` variant; `to_jwt`/`from_jwt` are the only bridge to `jsonwebtoken`). `DEFAULT_ALGORITHMS` (every asymmetric alg `ring`-backed `jsonwebtoken` 9 can verify) and `parse_algorithm` (refuses HMAC/`none` outright with a typed `AlgorithmError` — no config can enable them) bound the configured allowlist; `key_algorithms` (by JWK `kty`/curve) and `signing_algorithm` (a JWK's own declared `alg`, if present) bound what one key may verify. A token's `alg` must pass both, which is what stops an attacker-chosen header from steering an RSA key into an ECDSA verification or any key into HMAC |
| `builder.rs` | `OAuthValidatorBuilder` (from `OAuthValidator::builder`; `OAuthValidator::new` is `builder(..).build()`): `add_root_certificate_pem` (bundles allowed; `parse_root_pem` refuses a PEM with no certificate or with any `PRIVATE KEY` block, and builds a probe client trusting only it, so an unusable certificate is `ValidatorError::InvalidRootCertificate` under every backend — rustls parses DER only at client build), `proxy` (`check_proxy`: absolute `http`/`https` URL, host, no path/query/fragment/space/control/non-ASCII; a refusal shows the scheme only; a plain-http non-loopback proxy URL is fine without userinfo, since https fetches `CONNECT`-tunnel through it, but with userinfo is refused unless `allow_insecure_http`, then a `warn` — decided on the parsed URL, `scheme() == "http"` and `!is_loopback_url`, so `http:/…`, `http:…` and `HTTP:\\…` spellings cannot skip it), `fetch_timeout` (`MIN_FETCH_TIMEOUT..=MAX_FETCH_TIMEOUT`) and `initial_jwks` (`seed_keys` → `jwks::keys_from_jwk_set_json`, then `JwksStore::new`'s `seed`). Options are checked in `build` only, in the order timeout, roots, proxy, seed, after every check `new` makes; `fetch_settings` turns them into `jwks::FetchSettings` (which holds the `reqwest` types — the builder holds bytes and strings only). Hand-written `Debug`: counts and "is set", never the proxy URL or the seed. Its test module holds a throwaway test CA and server certificate (generated for this suite only) and an in-process `tokio-rustls` HTTPS server; `min_refetch_interval` is its `cfg(test)` hook |
| `jwks.rs` | `JwksStore`: JWKS discovery (OIDC Discovery then RFC 8414, exact-issuer-match required), fetch (redirect policy `judge_redirect` refuses an https→http downgrade and, without `allow_insecure_http`, a hop to plain http on a non-loopback host; a discovered `jwks_uri` is held to the same opt-in; response capped at `MAX_FETCH_BYTES`, at most `MAX_JWKS_KEYS` keys parsed), caching, and per-key algorithm binding (`parse_jwks_entry`, the pure per-entry step of `fetch_jwks` — parse one JWK Set entry on its own, then `cached_key`, skipping non-signature — `use` other than `sig`, `key_ops` without `verify` — and unparseable keys one at a time rather than failing the whole set, and flagging an alg-less multi-algorithm key `ambiguous` for a one-time `warn`). `JWKS_MIN_REFETCH_INTERVAL` (60s) throttles an unknown-`kid` refetch; `JWKS_BACKGROUND_REFRESH_INTERVAL` (hourly) is the only thing that notices a withdrawn key, with `background_retry_delay` for a failed pass while keys are held and `keyless_retry_delay` (`KEYLESS_RETRY_FLOOR` 5 s doubling to `KEYLESS_RETRY_CAP` 5 min) while none is. The public status types live here too: `KeySetStatus` (`#[non_exhaustive]`, public fields, `is_ready`), kept in the `status` `std::sync::Mutex<Tracked>` (the public copy, whose `jwks_uri` is redacted; the unredacted `jwks_uri` the fetch uses — configured, or filled in once by discovery; and an `attempts` counter) and updated by `refresh` at the start (`attempts`, `last_attempt`) and end (`keys`/`last_success`, or `last_error`) of every attempt — `refresh_detached` records a panicked task's error only if no newer attempt has started, and none for a cancelled one (runtime shutdown); `redact_url` for every displayed URL; and `RefreshError` (private `kind` + message; `Display` is the cause chain with URLs redacted, log-only because it still names endpoints) with its `#[non_exhaustive]` `RefreshErrorKind` (`Discovery`/`Fetch`/`Parse`/`NoUsableKeys`, `as_str` labels). Every fetch runs detached (`refresh_detached`) so a dropped caller cannot cancel it. `http_clients` builds `HttpClients` (`normal` and `loopback`, chosen per fetch by `for_url` — see the invariant above) from `FetchSettings` (timeout, default `DEFAULT_FETCH_TIMEOUT`; extra roots, added; an explicit proxy, `normal` only). `keys_from_jwk_set` (the key cap, per-entry parsing and the no-usable-keys error) is shared by `fetch_jwks` and `keys_from_jwk_set_json` (the seed path); `JwksStore::new` takes the seeded keys, counting them in `KeySetStatus::keys` without stamping `last_attempt`/`last_success`, so `has_keys` (and the background task's retry schedule) treats them as held. The `RwLock`/`refresh_lock` split and the fail-closed-on-any-failure behavior are covered in the Architecture section above; `decoding_key`'s "exactly one candidate key with no `kid`" fallback (`lookup`) is documented on the function itself — it never tries more than one key per verification attempt |
| `validator.rs` | `OAuthValidator`: built once from a `ResolvedOAuthConfig` via `from_builder` (what `new` and `OAuthValidatorBuilder::build` both run; it re-checks the audience/algorithm/leeway invariants `resolve` already enforced, since `ResolvedOAuthConfig`'s fields are public and may be hand-adjusted), then `validate`/`validate_cached` (the cache-only path `authenticate()`'s two-pass check uses) run header checks (`check_header`: size, JWS shape, `crit` via `check_crit`, `alg` allowlist, `typ` — see `token::check_typ`) before any key fetch, then `verify` (one `jsonwebtoken::decode` for signature + `iss`/`aud`/`exp`/`nbf`, then the exact-`iss`-string recheck, the `nbf` NumericDate check, the `cnf` refusal, then all-of scope matching). Also owns the RFC 9728 metadata document and the two `WWW-Authenticate` challenge strings (`invalid_token_challenge`/`insufficient_scope_challenge`, built from `challenge.rs`), `spawn_background_refresh` (a `Weak`-holding task that stops with the validator; after a failed pass it picks `keyless_retry_delay` when `JwksStore::has_keys` is false, `background_retry_delay` otherwise), the passive `key_set_status`/`is_ready` (a copy of `JwksStore::status` — no I/O, no `refresh_lock`, no async), and startup-only warning checks: a `required_scopes` entry missing from a non-empty `scopes_supported` (`unadvertised_scopes`; an empty one makes the challenge name the required scopes, so it is not warned about) (a guaranteed 403 for a client that only requests the advertised scopes), an unscoped config with `require_at_jwt` off (`unscoped_posture`, an ID token becomes a working bearer credential; `resolve` already refuses it without `allow_unscoped_tokens`), and a plain-`http://` issuer/`jwks_uri`/resource on a non-loopback host (refused by `resolve` without `allow_insecure_http`). `metadata()` returns `&Value`. The `# Runtime` section on `OAuthValidator` is the Tokio requirement. Documents the RFC 7662 opaque-token-introspection extension point in `OAuthValidator`'s own doc comment — not built, but the API is shaped so it could be added as a feature-gated alternative key source without a breaking change |
| `token.rs` | `AuthorizedToken` (subject/principal/scopes plus `issuer`, `audiences`, `expires_at`, `issued_at`, `client_id`, `jti` and a private `Arc<Map>` of the verified claims read by `claims()`/`claims_as()`, all filled once by `from_verified_claims` from the map `verify`'s single `decode` produced; `new` defaults them (empty, `expires_at` 2100-01-01) and `with_*` builders set them for tests; `#[non_exhaustive]`, hand-written `Debug` that prints claim names, never values, since they can be personal data; `has_scope`) and `TokenRejection` (`Missing`/`Invalid(String)`/`InsufficientScope`, `#[non_exhaustive]` — the 401-vs-403 split RFC 6750 requires; a `std::error::Error` whose `Display` is the category only, never the `Invalid` reason). `extract_scopes`/`extract_principal` read every configured claim in every accepted shape (string, space-delimited or not; array); `check_typ` is the RFC 9068 `typ` gate `validator.rs` calls. `MAX_TOKEN_BYTES` (16 KiB) and `MAX_LOGGED_CHARS` (128, via `for_log`) bound, respectively, what a credential may be and what a token-derived string may look like in a log line |
| `challenge.rs` | RFC 9728 metadata (`metadata_document`, which omits an empty `scopes_supported` per §3.2; `PROTECTED_RESOURCE_METADATA_PREFIX`; `resource_metadata_url`/`metadata_path` — the well-known segment goes between authority and path, not at the end, and the path is kept verbatim, trailing slash included, per §3.1) and the two RFC 6750 `WWW-Authenticate` builders (`invalid_token`, `insufficient_scope`), which omit the `scope` attribute entirely rather than sending it empty when there is nothing to name (RFC 6749 §3.3); the validator feeds the 401 the required scopes when `scopes_supported` is empty. `quoted` escapes a config-derived value for an HTTP quoted-string — defence against a typo producing a malformed header, not against an attacker |
| `authenticate.rs` | `Credential` (`StaticToken`/`OAuth(AuthorizedToken)`, `#[non_exhaustive]`) and `authenticate()`: the framework-free credential check every candidate header value goes through — constant-time (`subtle`) static-token comparison first (needs no network), then OAuth in two passes (cache-only, then a pass that may trigger a key fetch, so one candidate's unknown `kid` never queues a request behind a refetch when another candidate's key is already cached). Precedence on refusal: any acceptance wins; otherwise `InsufficientScope` if any candidate was valid-but-unscoped; otherwise `Missing` with no non-blank candidate; otherwise `Invalid` with the first candidate's reason. Every candidate is checked independently — a bad credential in one source never masks a good one in another — no framework dependency, so a non-axum HTTP stack calls this directly |
| `refusal.rs` | Core, no feature gate, no `http` dependency: `refusal()`/`refusal_with_static_challenge()` → `Refusal` (`status: u16`, `www_authenticate: Option<String>`, `#[non_exhaustive]`), the framework-free RFC 6750 mapping from a `TokenRejection` (403 for `InsufficientScope`, 401 for everything else, any future variant included) to a status and challenge (the validator's with OAuth; otherwise `DEFAULT_STATIC_CHALLENGE`, the caller's own, or none). The decision itself is the crate-private generic `select`, which both this public API (over `String`s) and the layers' `http_layer::Gate` (over pre-validated `HeaderValue`s, which may hold bytes a `&str` cannot, so there is no fallible conversion per request) call — the one place a status or challenge is chosen |
| `http_layer.rs` | The `tower` feature (implied by `axum`); the module is `http_layer`, never `tower`, because a crate-root `tower` module makes `tower` ambiguous for a downstream `use oauth_resource_server::*;` next to the `tower` crate (`tests/glob_import.rs` pins that): `HttpAuthLayer<R = EmptyRefusal>`/`HttpAuthLayerBuilder<R>`/`HttpAuthService<S, R>`, a `tower::Layer` for any `Service<http::Request<ReqBody>, Response = http::Response<ResBody>>` — named `Http…` so it cannot be mistaken for `axum::AuthLayer` when both are in scope. A refusal's response comes from `R: RefusalResponse<ResBody>` (sealed by the private `sealed::Sealed`, since only `on_reject` can install one) — `EmptyRefusal` (`ResBody::default()`) or an `on_reject` closure — before `Gate::finish` fixes its status and challenge; the boxed future is `Send` without `ResBody: Send` (the check's result is bound before the inner call). Also the pieces both layers share, defined here and re-exported from `axum`: `CredentialSource` (with `presents_nothing`, `names_a_token`, `bearer_credential`, the `__fuzz` target's parser), `RejectContext`, `AuthLayerError` (re-exported with `#[doc(inline)]`, so docs.rs shows them under `axum::` too), and the crate-private `Gate` (`build` — every fail-closed check —, `check_decision`, `admit` — clear an outer credential for `optional()`, mark sources sensitive, `authenticate`, insert `Credential`/`AuthorizedToken`, decide the optional pass-through —, `status_and_challenge`, `finish`). `Gate` logs nothing: each layer logs the `Admission` itself, so the axum layer's log target stays `oauth_resource_server::axum` and this one's is `oauth_resource_server::http_layer`. No `LayerRan` marker, so the axum extractors answer 500 behind this layer (documented) |
| `policy.rs` | `static_token_policy`: pure decision logic (no logging) for which static token, if any, an `AuthLayer` should hold alongside OAuth — `StaticTokenDecision`'s five variants (`StaticAndOAuth`/`StaticOnly`/`OAuthOnly`/`StaticIgnored`/`Unauthenticated`) cover dual mode, static-only, OAuth-only, `accept_static_bearer: false` ignoring a configured token, and the explicit unauthenticated opt-out. `NoAuthConfigured` is returned when nothing is configured and `allow_unauthenticated` was false. Its hand-written `Debug` redacts the token; an application wraps this with its own log lines and message wording (see mcp-md-wiki's `server::static_bearer_token`) |
| `axum.rs` | The `axum` feature: re-exports `CredentialSource` (`Bearer`/`Raw` header, `#[non_exhaustive]`), `RejectContext` and `AuthLayerError` from `http_layer.rs` and `DEFAULT_STATIC_CHALLENGE` from `refusal.rs`; `AuthLayer` (a `tower::Layer` and the state for the `require_auth` middleware fn — the two behave identically, both routing through `AuthLayer::check`, which runs the shared `Gate::admit` and logs the outcome), `AuthLayerBuilder` (fail-closed `build`/`build_with_decision` through `Gate::build`/`Gate::check_decision` — including `AuthLayerError::InvalidChallenge` —, `static_challenge` for the no-OAuth 401 challenge, default `DEFAULT_STATIC_CHALLENGE`; `on_reject` shapes only the refusal body/extra headers — status and `WWW-Authenticate` are fixed after it runs, in `Enforce::reject` via `Gate::finish`; `RejectContext`'s hand-written `Debug` prints header names only, and `check` marks credential headers sensitive; `optional()` passes a request presenting no credential through, logged at `debug`, and refuses everything else as without it; it clears outer layers' `Credential`/`AuthorizedToken` first, strict layers accumulate them), the `FromRequestParts`/`OptionalFromRequestParts` impls for `AuthorizedToken` and `Credential` (read the extensions `check` inserted; the private `LayerRan` marker `check` inserts on every pass lets a missing value be refused through `Enforce::refuse` with the layer's own 401 and challenge, `refuse_extraction` giving `allow_unauthenticated` layers `DEFAULT_STATIC_CHALLENGE`; no marker means a route outside every layer, answered 500 with an `error` log by `no_layer`; a typed per-handler scope extractor is deferred to oauth-resource-server#4), and `metadata_router` (serves the RFC 9728 document on the bare well-known prefix and, when the resource URL has a path, on the path-suffixed form too, matched by literal string comparison rather than registered as an axum route pattern — a resource URL may legally contain `:`/`*`/`{}` characters axum would read as routing syntax). Logs every outcome itself (module docs list the levels) so an application needs no auth-specific logging of its own |
| `env.rs` | The `env` feature: `secret_from_env`/`secret_from_lookup` (`VAR` or `VAR_FILE`, Docker Compose `secrets:`-mount shape; both set is an error, not a silent preference; a `_FILE` that reads empty is an error, an absent `VAR` is not) and `oauth_config_from_env`/`oauth_config_from_lookup` (one `<PREFIX><FIELD_UPPER>` variable per `OAuthConfig` field, lists whitespace-split, bools strict `"true"`/`"false"`, `<PREFIX>ENABLED` unset inferring on/off from whether any `IdentifyingVars` entry is set). `EnvOAuthConfig`/`unresolved_oauth_config_from_env` is the hook an application uses to layer its own defaults (a default required scope, say) between loading and `resolve` — the same hook a config-file application has between deserializing and calling `OAuthConfig::resolve` directly. `EnvError` never carries a secret's value, only variable names and file paths (every variant is `#[non_exhaustive]`). `EnvOAuthConfig` keeps `problems: Vec<String>` public and a private `Vec<ConfigProblem>` (`problem_details()`), both filled at load time: `env_problem` yields `ProblemKind::EnvLoad` keyed by the variable (`BothSet`: `VAR` and `VAR_FILE`; a failed or empty file: `VAR_FILE`), `bool_problem` and the `leeway_secs` parse yield `EnvParse`; `EnvOAuthConfig::resolve` treats the public `problems` as authoritative (an app may have edited it) and re-pairs each string with its structured form via `reconcile`, else `Other`; its `PartialEq` and `ConfigError`'s ignore `details` (0.1.2 semantics). Every `_lookup`/`_from_lookup` twin exists so tests never call the `unsafe`-as-of-2024-edition `std::env::set_var` |
| `testing.rs` | **Test-only** fixtures (compiled for this crate's own tests, and behind the `testing` feature for consumers'). The primary entry point is `TestAuthority` (`start` runs a `spawn_http_server`-backed loopback authority with OIDC and RFC 8414 discovery plus `/jwks`, issuer = its own base URL; `issuer`/`jwks_uri`/`jwks_fetches`/`discovery_fetches` (private per-path counters on `FakeJwksServer`)/`set_response_delay`; no accessor exposes the inner `FakeJwksServer`, so its layout is not frozen and `publish()` owns the routes; `Drop` aborts the accept loop; `rotate_key` flips the active RSA key between `KEY_A_PEM` and `KEY_B_PEM` and publishes both, `withdraw_old_key` drops the retained one; every JWKS carries one labelled JWK per RSA algorithm (`<kid>` for RS256, `<kid>-rs384`/`-rs512`/`-ps256`/`-ps384`/`-ps512` — frozen `kid`s, never alg-less, so no validator logs the `ambiguous` warning; a test pins that) plus the EC and Ed25519 keys, at most 14 under `MAX_JWKS_KEYS`, so every `TokenBuilder::alg` validates; `config(adjust)` resolves an `OAuthConfig` with neutral defaults — `https://api.example.test/` resource and a distinct `https://api.example.test/audience` audience, `api:read`, `Dotted("oauth")`, loopback http needing no `allow_insecure_http` — and panics with the `ConfigError` text) and `TokenBuilder` (`token()`; the fluent knobs, `sign()` captures the active RSA key when `token()` is called, defaults validate against `config(|_| {})`); its tests use the harness itself. Below it, the older building blocks: throwaway RSA/EC/Ed25519 keypairs (`KEY_A_PEM`/`KEY_B_PEM`/`EC_PEM`/`ED_PEM`, generated for this suite, used nowhere else — see the leak policy; `KID_B`/`N_B`/`jwk_rsa_b` are `KEY_B_PEM`'s public half, no new key material), JWK builders (`jwk_rsa_a`, `jwk_ec`, `jwk_ed`, `jwks_of(&[..])`, `jwks_body`/`jwks_body_all`), token minting (`mint`/`mint_with` take `&impl Serialize` claims; `valid_token`), a `resolved_config` fixture, and `FakeJwksServer` (`Debug`, `#[non_exhaustive]`; its `hold`/`release` gate, `path_hits` and `accept_task` are `pub(crate)`)/`spawn_jwks_server`/`spawn_http_server` (an in-process fake authorization server for discovery/JWKS tests). Models a plausible Authentik deployment — not a code default, see Key conventions |

## Semver and MSRV policy

- The crate is pre-1.0; a `0.x → 0.(x+1)` bump is where a breaking change
  ships (Cargo treats any `0.x` minor bump as incompatible). A patch release
  (`0.x.y → 0.x.(y+1)`) is behavior-preserving only, **with one exception**: a
  fix for a vulnerability — a forged, expired, wrongly-audienced, or otherwise
  out-of-policy token that should never have been accepted — ships as a patch
  release even though it narrows accepted input, together with a
  `CHANGELOG.md` entry and a `SECURITY.md` advisory. Security correctness
  outranks the general narrowing-is-breaking rule below: holding the fix for
  a `0.(x+1)` release would leave every consumer on the common caret range
  (`oauth-resource-server = "0.1"`) unprotected until they manually widen
  their dependency requirement, which is the opposite of what a resource
  server crate exists to do.
- Breaking: removing or renaming a public item; adding a field to `OAuthConfig`
  (not `#[non_exhaustive]`, by design — see Key conventions) or to any other
  struct that is not `#[non_exhaustive]`; adding a variant to an enum that is
  not `#[non_exhaustive]`; narrowing an accepted input or widening a returned
  error type; changing a default that changes accepted/rejected tokens (a
  default algorithm, claim name, or scope-claims list) — unless it is the
  security-fix exception above; **a major-version bump of a dependency whose
  types appear in this crate's public API**, since that breaks a consumer who
  names the same type from their own direct dependency on it. Only these apply today: the `axum`
  feature's `axum`/`http`, and `serde`/`serde_json`, always (`AuthorizedToken::claims_as`
  is bounded by `serde::de::DeserializeOwned` and returns `serde_json::Error`,
  `claims()` returns `serde_json::Map<String, Value>`, and `metadata()` returns
  `&serde_json::Value`, so a `serde` or `serde_json` major bump is breaking).
  The `axum`/`http` ones are (`metadata_router` returns
  `axum::Router<S>`, `require_auth`'s signature takes axum's
  `State`/`Request`/`Next`, `CredentialSource` holds an `http::HeaderName`,
  `static_challenge` takes an `http::HeaderValue`, and the `tower` feature's
  `HttpAuthService` is a `Service<http::Request<_>>` and `on_reject`
  returns an `http::Response`); that ships in a new `0.x` minor. `jsonwebtoken` deliberately does not (see its pin paragraph above),
  and `reqwest` never appears in a public signature either.
- The `testing` feature's public items are covered by the same rules (see Key
  conventions): they are API, not an exempt zone.
- Non-breaking (ships in a `0.x` minor): adding a field to a
  `#[non_exhaustive]` struct or a variant to a `#[non_exhaustive]` enum;
  adding a new public item; adding a new feature; loosening a validation rule
  that only accepts more previously-rejected input (never the reverse — that
  is the "narrowing" case above). Cargo itself treats any `0.x.y → 0.x.z`
  (same minor) as semver-compatible and does not require a minor bump for an
  additive change; shipping additive changes in a new `0.x` minor rather than
  the next patch is this crate's own convention, chosen so a `CHANGELOG.md`
  reader can tell at a glance which releases were bugfix-only.
- `ConfigError::problems`' message text (and any `Display` built from it) is
  **not** part of this crate's semver contract — wording may change in any
  release, including a patch. `config.rs`'s `WIKI_REWRITES` test (see Key
  conventions) is an early warning for the one consumer that string-replaces
  two phrases, not an exception to this rule. A consumer must not
  string-match problem text in general; the durable alternative is
  `ConfigError::problem_details()`: match `ConfigProblem::kind()`
  (`ProblemKind`, `#[non_exhaustive]`, labels from `as_str()` stable) and
  `keys()`. Adding a `ProblemKind` variant is non-breaking; the kind a given
  problem carries is part of the contract, its wording is not.
- MSRV is `1.89`, declared in `Cargo.toml`'s `rust-version` (which is what
  makes a too-old local toolchain fail fast with a clear message) and kept in
  lockstep with `rust-toolchain.toml`'s `channel`. Raising MSRV is a breaking
  change under this crate's policy — bump the minor version and say so in
  `CHANGELOG.md`, and update both files together. 1.89 was chosen to match the
  crate's first consumer (mcp-md-wiki) and because the crate is edition 2024
  and uses let-chains.

## Workflow

**pr-manual-release** (CI-gated PRs, release on demand) on GitHub, `master` as the default branch. The
repository settings below are configured on GitHub, not tracked in this tree,
so they are maintainer-owned configuration rather than something a change in
this repo can alter directly — treat them as always-in-effect policy:

- `master` takes no direct pushes and is protected by a repository **ruleset**
  whose only required status check is `ci-pass` (never `checks`/`msrv`
  individually), which does **not** require a branch to be up to date with
  `master` before merging, which allows squash merges only (no merge or
  rebase commits), and which auto-deletes a branch once its PR merges.
- Workflow runs for a pull request from a fork need a maintainer's approval
  for every external contributor, not just first-time ones, because the
  heavy jobs run on a self-hosted runner. That gate covers forks only:
  Dependabot opens its PRs from branches of this repository, so they run on
  the self-hosted runner without approval, and a dependency bump executes
  the new upstream version's build scripts (and proc macros and tests)
  there. That is accepted even though the runner mounts the host docker
  socket, so such code can reach the host beyond its own ephemeral
  container: nothing secret lives on that runner (CI jobs hold only a
  read-only token), and the job that can mint a crates.io token never runs
  there (see Release process).
- A GitHub App's Client ID (`APP_CLIENT_ID` repo variable) and private key
  (`APP_PRIVATE_KEY` repo secret) are what `auto-merge.yml` authenticates
  with. The App deliberately lacks the `workflows` permission. A PR that
  changes a file under `.github/workflows/` still auto-merges when its
  branch contains master's current version of those files; when master has
  changed one of them since the branch was cut, the auto-merge job fails
  (GitHub treats the squash as the App writing workflow content) and the PR
  is refreshed from `master` or merged by hand once `ci-pass` is green.
- A GitHub environment named `release`, whose deployment policy admits only
  `v*` tags, which `release.yml`'s `publish` job runs in; crates.io trusted
  publishing is bound to it.
- A tag ruleset on `refs/tags/v*` that lets only repository admins (the
  owner) create, move or delete a release tag. `GITHUB_TOKEN` and the
  auto-merge App cannot, so no workflow may ever create a tag.
- Every action in `.github/workflows/` is pinned to a full commit SHA with
  its release in a trailing `# vX.Y.Z` comment (`dtolnay/rust-toolchain`,
  which has no releases, to a commit of its `master` branch). Keep it that
  way when adding or bumping one.

The flow:

- Work on a branch, open a PR against `master`. `.github/workflows/ci.yml`
  fans `checks` (fmt, four clippy runs, tests with all and with default
  features, `cargo build --examples --all-features`, a `-D warnings` doc
  build, `cargo audit`, `cargo deny check`, `cargo package --list`,
  `cargo publish --dry-run`), `msrv` (a separate build on the pinned `1.89`
  toolchain) and three more jobs — `semver` (`cargo semver-checks
  check-release --all-features` against the latest release on crates.io, on
  Rust 1.93 with `cargo-semver-checks@0.50.0`: the tool needs a recent rustc,
  so the toolchain and the pinned tool version move together, and a floating
  `stable` would break every PR when a new rustc changes the rustdoc JSON
  format), `feature-powerset`
  (`cargo hack check --feature-powerset`, one TLS backend per build) and
  `minimal-versions` (`cargo update -Z direct-minimal-versions` with
  dev-dependencies removed, then a build) — into `ci-pass`. All five run on
  the project's self-hosted runner (an ephemeral container, labels
  `self-hosted`, `linux`, `x64`): each installs `pkg-config`/`libssl-dev`, a
  toolchain via `dtolnay/rust-toolchain` (the one named in
  `rust-toolchain.toml`, except `semver`'s stable and `minimal-versions`'
  extra nightly), and restores an `actions/cache` of the cargo registry and
  `target/`; `cargo-audit`, `cargo-deny`, `cargo-hack` and
  `cargo-semver-checks` come from a SHA-pinned `taiki-e/install-action`.
  `ci-pass` runs on a GitHub-hosted runner and lists all five in its `needs`
  and its explicit result check.
- `semver` compares against the newest crates.io release, so while
  `Cargo.toml`'s `version` still equals it, any breaking change fails CI. A
  deliberate breaking change (a `0.x` minor under the policy below) carries
  its `version` bump in the same PR; that bump is what tells the check it is
  intended. `minimal-versions` is why some of `Cargo.toml`'s dependency
  requirements are not bare majors, for two different reasons spelled out in
  the comment above `[dependencies]`: `jsonwebtoken` 9.2 and `tokio` 1.15 are
  where the crate builds (the next-older releases tried fail to compile),
  while `subtle`, `tower-layer`, `tower-service`, `tracing`, `serde` and
  `serde_json` are raised only so `direct-minimal-versions` can resolve
  against `reqwest`'s and `axum`'s own minimums. None is an exhaustive search
  for the oldest working release; a new dependency or bound that regresses
  fails this job.
- `.github/workflows/fuzz.yml` (nightly `schedule` plus `workflow_dispatch`,
  never a PR or push trigger, GitHub-hosted) runs each `fuzz/` cargo-fuzz
  target for a bounded time. The targets call `src/__fuzz.rs`, a
  `#[doc(hidden)] pub mod __fuzz` that exists only under `--cfg fuzzing`
  (which cargo-fuzz sets), so the internals it reaches are never public API;
  `Cargo.toml`'s `[lints.rust] unexpected_cfgs` declares that cfg so
  `clippy -D warnings` stays clean. `fuzz/` is its own package (empty
  `[workspace]`, `publish = false`) and is outside `Cargo.toml`'s `include`
  list, so `cargo package --list` never shows it.
- `ci-pass` uses `if: always()` plus an explicit result check specifically so
  that a failed (or skipped, or cancelled) upstream job fails `ci-pass`
  rather than being skipped and read as passing — see the comment at the top
  of `ci.yml` before touching it.
- `.github/workflows/auto-merge.yml` arms squash auto-merge on every PR
  opened by `St0nefish`, so the owner's PRs land as soon as `ci-pass` is
  green — that is the intended flow, not something to hold back. It must use
  the GitHub App token: a merge made with `GITHUB_TOKEN` starts no workflow
  runs, so the post-merge CI run would not fire. Every
  other contributor's PR runs the same CI and is merged by hand after
  review; a fork PR never receives the App credentials, so it cannot
  auto-merge.
- `ci.yml` also runs on every push to `master`. That is the post-merge
  re-check, catching two PRs that were each green against an older `master`
  but break once combined; there is deliberately no separate
  `post-merge.yml`. It is not a required check (it runs after the merge).
- Don't rebase an open PR just because `master` moved; refresh a branch only
  to resolve a real conflict.

## Release process

- **A merge never publishes.** Publishing happens only when the owner
  publishes a GitHub release: `.github/workflows/release.yml` triggers on
  `release: published` and nothing else (no push or manual trigger). The
  guarantee is that the owner must do both halves: create the `v*` tag (the
  tag ruleset allows only admins) and publish the release (`check` fails
  unless `github.event.sender.login` is `St0nefish` — needed because a
  release published with a GitHub App installation token *does* start
  workflow runs, and the auto-merge App has `contents: write`, so it could
  otherwise publish a release on an existing, unpublished `v*` tag). A
  release created with `GITHUB_TOKEN` starts no workflow run at all. A
  prerelease publishes too (a `X.Y.Z-rc.N` version, which Cargo never
  selects unless asked for). `check` (GitHub-hosted, read-only) checks out
  the tagged commit (the event's `github.sha`, confirmed against the tag)
  and fails closed unless the sender is the owner, the tag is `v<version>`
  for `Cargo.toml`'s version at that commit, the commit is an ancestor of
  `master` (a mistake check, not a security boundary: the run uses the
  workflow file at the tagged commit), crates.io answers `404` for the version
  (`200` fails the first attempt — the release is for an already-published
  version; any other answer always fails), and `CHANGELOG.md` has a
  non-empty `## [X.Y.Z]` section. Then `verify`, `msrv` and `semver`
  (self-hosted, read-only, no OIDC permission) repeat `ci.yml`'s `checks`,
  `msrv` and `semver` jobs step for step — keep the lists in step
  (`feature-powerset` and `minimal-versions` are not repeated: they ran on
  master's post-merge CI and are not re-verified at release, while `semver`
  depends on what crates.io holds and on this release's version bump);
  `publish`
  (GitHub-hosted, in the `release` environment, the only job with
  `id-token: write`, running nothing but checkout, toolchain, auth and
  publish, with no restored cache) re-checks crates.io, then authenticates
  via `rust-lang/crates-io-auth-action` (a short-lived OIDC-exchanged token;
  no long-lived token secret is ever stored in this repo) and runs
  `cargo publish`; and `release-notes` (`contents: write` with
  `GITHUB_TOKEN`) replaces the release's notes with that CHANGELOG section
  via `gh release edit`. No job creates or moves a tag. Keep build
  scripts, proc macros and dev-dependencies out of the job that can mint the
  token, and keep that job off the self-hosted runner, which has its host's
  Docker daemon socket mounted and runs unreviewed Dependabot code.
- **To cut a release**: (1) merge a PR that bumps `version` in `Cargo.toml`
  (and `Cargo.lock`) — unless a breaking PR already bumped it, which the
  `semver` job requires — and moves `CHANGELOG.md`'s `[Unreleased]` entries under
  `## [X.Y.Z] - <date>` (plus the link references at the bottom) — merging
  it publishes nothing; (2) the owner runs
  `gh release create vX.Y.Z --target <sha of the bump commit> --title vX.Y.Z --notes "..."`
  (or uses the web UI), which creates the tag and starts `release.yml`.
  Target the bump commit's SHA, not `master`: with `--target master`,
  anything merged after the bump would ride along into the release without
  a CHANGELOG entry.
- A transient failure (crates.io outage, runner hiccup) is re-run with
  "re-run failed jobs" on that run: `publish` skips the upload and succeeds
  if an earlier attempt already made it, and `release-notes` just writes the
  same notes again. Runs are grouped per release tag and never cancelled.
- A genuine `verify`/`msrv`/`semver` failure (the tagged commit is broken)
  cannot be fixed by a re-run, which repeats the same commit. Merge the fix,
  then as the owner delete the release and its tag
  (`gh release delete vX.Y.Z --cleanup-tag`) and create the release again at
  the new commit. Nothing was uploaded: `publish` needs all of them.
- `release.yml` must keep its filename, and `publish` must keep
  `environment: release`: crates.io trusted publishing is registered for
  this repository + `release.yml` + environment `release`. That
  environment's policy (only `v*` tags), the tag ruleset (only admins create
  `v*` tags) and the sender check together limit minting a publish token to
  an owner-created, owner-published release.
- There is no deploy-hold switch: nothing publishes until the owner
  creates a release, so batching changes is only a matter of when to do
  that.
- **0.1.0 was published manually** with a personal crates.io API token,
  because crates.io only lets a trusted publisher be attached to a crate
  that already exists. Trusted publishing was configured after that (bound
  to environment `release`), and every later release goes through
  `release.yml`. 0.1.1 was published on merge by an earlier version of that
  workflow; releases from 0.1.2 on are published from GitHub releases.
- **Repo setup**: private vulnerability reporting must be enabled —
  `gh api -X PUT repos/St0nefish/oauth-resource-server/private-vulnerability-reporting`
  (Settings → Code security → Private vulnerability reporting). It is off by
  default on a new repo, and `SECURITY.md` and
  `.github/ISSUE_TEMPLATE/config.yml` depend on it: without it there is no
  **Report a vulnerability** button, the issue-chooser's security link fails,
  and (blank issues being disabled) a public bug report is the only channel
  left. Confirm with
  `gh api repos/St0nefish/oauth-resource-server/private-vulnerability-reporting`
  returning `{"enabled":true}`.

## Build & test

The full check matrix CI runs — run all of it locally before opening a PR:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo clippy --all-targets -- -D warnings
cargo clippy --all-targets --no-default-features --features native-tls -- -D warnings
cargo clippy --all-targets --no-default-features --features rustls-tls-native-roots -- -D warnings
cargo test --all-features
cargo test
cargo build --examples --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features
cargo audit                    # needs cargo-audit installed; reads .cargo/audit.toml
cargo deny check               # needs cargo-deny installed; reads deny.toml
cargo package --list
cargo publish --dry-run        # pass --allow-dirty for a local, uncommitted tree
```

Four more CI jobs run alongside `checks`; the last two need a nightly
toolchain and `cargo-hack`/`cargo-semver-checks` installed:

```bash
# msrv job: reads rust-version from Cargo.toml; most contributors won't have 1.89
cargo "+1.89" build --all-features --locked

# semver job: cargo-semver-checks 0.50.0 needs rustc 1.93+; CI pins both, so
# they move together
cargo +1.93 semver-checks check-release --all-features

# feature-powerset job
cargo hack check --feature-powerset --no-dev-deps \
  --mutually-exclusive-features rustls-tls,native-tls,rustls-tls-native-roots \
  --at-least-one-of rustls-tls,native-tls,rustls-tls-native-roots

# minimal-versions job: rewrites Cargo.toml and Cargo.lock, so run it in a
# throwaway copy of the tree, not your working tree
cargo hack --remove-dev-deps
cargo +nightly update -Z direct-minimal-versions
cargo update -p time
cargo build --all-features
```

Fuzzing is not part of the PR matrix (`fuzz.yml` runs it nightly). To run a
target locally: `cargo install --locked cargo-fuzz`, then
`cargo +nightly fuzz run <target> -- -max_total_time=30` (targets:
`bearer_credential`, `check_header`, `extract_claims`, `metadata_urls`,
`discovery_urls`, `jwks_entries`). `cargo +nightly fuzz build` builds them all.

```bash
cargo build   # plain library build (default features)
```

## Leak policy (standing rule, not a one-time check)

This is a public repository. Every commit — not just the first one — must
never introduce (this list intentionally names *categories*, not the specific
banned values themselves, so this file does not itself become the leak):

- any hostname, domain, internal node/machine name, or local filesystem path
  belonging to the maintainer's private infrastructure — including in a code
  comment, a commit message, a test fixture, or an example;
- an IP address other than a documentation range (RFC 5737 / RFC 3849) or
  loopback;
- an email address, other than a generic maintainer contact if one is
  supplied;
- a real issuer URL, client ID, client secret, or any other credential from a
  live authorization-server deployment;
- any reference to the maintainer's other, private repositories — their name,
  their issues, or environment-variable names specific to them. Describe the
  same *behavior* generically instead (e.g. "a second credential header such
  as `X-Api-Key`", a neutral example prefix such as `MYAPP_OAUTH_`);
- a path into any private knowledge base or internal documentation tree;
- a real secret or token of any kind.

Allowed: naming the authorization-server providers this crate is tested
against (Authentik, Authelia, Kanidm, and any documented-shape-only ones)
with their tested/sandbox/documented labels; references to the public
`St0nefish/mcp-md-wiki` repo and its issues (e.g. `mcp-md-wiki#308`); the
GitHub username `St0nefish`; generated-for-the-test-suite fixture keys
(confirm any new one is generated for this purpose, never a real key);
example domains (`example.com`, `example.test`, and similar).

This file deliberately does not enumerate the maintainer's actual private
hostnames, node names, paths or repos — spelling them out here would itself
be the leak. Before a commit, run checks that catch a violation of the
*categories* above without needing that list memorized:

```bash
# Any issue reference, owner/repo#N or a bare repo#N, other than this repo's
# own or the public mcp-md-wiki's (see the "Allowed" list above). `PKCS#`
# is the RSA padding name, not a reference.
grep -rnoE --exclude-dir=target --exclude=Cargo.lock \
    '\b[A-Za-z0-9_.-]*[A-Za-z][A-Za-z0-9_.-]*#[0-9]+' . \
  | grep -v '/\.git/' \
  | grep -vE '(^|[/:])(St0nefish/)?(mcp-md-wiki|oauth-resource-server)#' \
  | grep -v 'PKCS#'

# Env-var names with an _OAUTH_ segment under any prefix, multi-segment ones
# included, other than this crate's neutral examples (MYAPP_/APP_) — a real
# prefix from another project leaking into a doc or fixture.
grep -rnoE --exclude-dir=target '\b[A-Z][A-Z0-9_]*_OAUTH_[A-Z_]+' . \
  | grep -v '/\.git/' \
  | grep -vE ':(MYAPP|APP)_OAUTH_'
```

(`grep -v '/\.git/'` rather than `--exclude-dir=.git`, which some command
sandboxes refuse to run because it names the git directory.) A hit means
something new needs triage before committing. A
private hostname/domain, node name, local path, real IP or email has no
single reliable grep pattern (domain-like text is indistinguishable from an
ordinary Rust field-access chain or a dotted config key like
`mcp.oauth.issuer` by regex alone), so those categories stay a manual read of
the diff against the category list above, not a scripted check. If a hit or a
manual read turns up something that needs a judgment call the categories
above don't resolve, ask the maintainer rather than guessing — they hold the
concrete list this file intentionally omits.
