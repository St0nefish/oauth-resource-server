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
key cache), then per request call `authenticate()` (framework-free) or run the
`axum` feature's `AuthLayer`/`require_auth`. Nothing here hot-reloads: a changed
config takes effect only when a new validator and a new `AuthLayer` are built,
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
- An unknown `kid` triggers at most one JWKS refetch per
  `jwks::JWKS_MIN_REFETCH_INTERVAL` (60s) — `kid` comes from the unverified
  header, so without this cooldown a stream of junk tokens turns the process
  into an amplifier pointed at the IdP. A separate, unconditional hourly
  refresh (`jwks::JWKS_BACKGROUND_REFRESH_INTERVAL`) is what notices a key the
  authorization server has **withdrawn**, which an unknown-`kid` refetch alone
  would never catch (it only ever adds keys). After a failed background pass
  it retries sooner (`jwks::background_retry_delay`: 60 s doubling to the
  hour). The task holds only a `Weak` between passes and stops when the
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
  hostile response or an oversized token.
- `WWW-Authenticate` is set — or overwritten, whatever a caller's `on_reject`
  callback returned — on **every** 401/403 once OAuth is configured
  (`axum::Enforce::reject`). A missing credential gets the same
  `invalid_token` challenge as a bad one, deliberately: `resource_metadata` is
  how claude.ai (and others) find the authorization server, and it refuses to
  start the flow at all without it. A validator challenge that is not a valid
  header value fails `AuthLayerBuilder::build`
  (`AuthLayerError::InvalidChallenge`) instead of shipping challenge-less
  401s. Without OAuth, a 401 carries `axum::DEFAULT_STATIC_CHALLENGE` (RFC 9110
  §15.5.2) unless the application opts out with `static_challenge(None)`.
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
  (`AuthLayerError::NoCredential`); the only pass-through is the explicitly
  named `AuthLayer::allow_unauthenticated()`, which only
  `policy::StaticTokenDecision::Unauthenticated` (itself produced only by an
  explicit `allow_unauthenticated` at the call site) ever yields via
  `AuthLayer::from_decision`/`build_with_decision`.
- Secrets never reach a log or a `Debug` impl: `AuthLayer`, `AuthLayerBuilder`
  and `policy::StaticTokenDecision` all hand-write `Debug` to redact the static
  token; `axum::RejectContext` hand-writes `Debug` to print header names only,
  and `AuthLayer::check` marks every configured credential header
  `set_sensitive(true)` before the callback or the inner service sees it;
  `env::EnvError`'s `Display`/`Debug` never include a secret's value (only
  variable names and file paths); and `TokenRejection::Invalid`'s reason
  string is documented as log-only — never put it in a response body
  (`TokenRejection`'s `Display` renders the category only, for that reason).

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
job; an authorization server behind a private CA needs one of the last two.
Enabling *none* is a **compile error** (`compile_error!` in `src/lib.rs`, unconditional — no
`cfg(test)` or docs exemption), because every real authorization server serves
its keys over https and a validator with no TLS backend would build cleanly and
then fail closed on every single token. `serde` gates `Deserialize`/`Serialize`
on `OAuthConfig` via `cfg_attr` (never a straight `#[derive]`, so the crate
builds with `serde` off). `env` gates the `env` module. `axum` gates the `axum`
module and its four extra deps (`axum`, `http`, `tower-layer`, `tower-service`
— `AuthLayer` implements `tower::Layer` against the same small trait axum
itself builds on, not the whole `tower` crate). `testing` gates
`src/testing.rs`'s throwaway keys, JWK builders, token minting and fake JWKS
server — for **consumers'** tests, enabled only from `[dev-dependencies]`,
never in a production build (the private keys are public knowledge; anything
that trusts them trusts everyone; it also pulls in `serde` for its
`&impl Serialize` minting helpers). CI's four clippy runs (`--all-features`,
default features, and `--no-default-features` with `native-tls` or with
`rustls-tls-native-roots`) exist because `--all-features` alone hides a `cfg`
that only appears with `rustls-tls` off.
Every feature-gated public item (the `env`/`axum`/`testing` modules in
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
  read accessor). `ConfigError::problems` is `Vec<String>`, not a structured,
  matchable shape; a structured problem kind can be added later as a
  non-breaking, additive change, so it is not built speculatively now.
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
- Test fixtures (`src/testing.rs`) model a plausible Authentik deployment
  (per-application issuer with a trailing slash, client-id audience,
  `mcp:read`/`mcp:write` scopes) because that is the production shape the
  original regression tests were written against — not because the crate is
  MCP-specific. Docs must always present the crate as general-purpose; the
  fixtures' scope names are an implementation detail of the test suite, never
  a code default.
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
  points (`OAuthValidator::new`/`validate`, `authenticate`, the `AuthLayer`
  builder, `require_auth`, `metadata_router`, `oauth_config_from_env`,
  `secret_from_env`, `static_token_policy`).
- `examples/` — runnable, and built in CI (`cargo build --examples
  --all-features`), so an example that no longer compiles against a changed
  public API is a CI failure, not a stale doc.
- `CHANGELOG.md`'s `[Unreleased]` section (or the next version's section once
  one exists) — including anything a consumer's upgrade needs to know.
- `SECURITY.md`'s "Security invariants this crate maintains" list, if the
  change adds, removes or narrows one of the invariants above.
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
| `lib.rs` | Crate root: the module tree, feature gating, and the no-TLS-backend `compile_error!`. `#![warn(missing_docs)]` + `#![forbid(unsafe_code)]`. Re-exports the core, always-available API at the crate root (`OAuthConfig`, `ConfigError`, `KeyNaming`/`KeyNamingBuf`, `OAuthValidator`, `AuthorizedToken`, `TokenRejection`, `Credential`, `authenticate`, `static_token_policy`, `Algorithm`/`AlgorithmError`, …); no `jsonwebtoken` type is re-exported or appears in a public signature. The feature-gated `env`, `axum` and `testing` modules stay public submodules a consumer reaches through their own path instead (`oauth_resource_server::axum::AuthLayer`, `oauth_resource_server::env::secret_from_env`) — nothing inside them is re-exported at the root |
| `config.rs` | `OAuthConfig` (the unvalidated, serde-deserializable input shape — every field `#[serde(default)]`, `deny_unknown_fields`, not `#[non_exhaustive]`) and `OAuthConfig::resolve` (all-or-nothing validation into `ResolvedOAuthConfig`, every problem collected at once via `check_url` and the scope/algorithm/leeway checks). `KeyNaming`/`KeyNamingBuf` (`Dotted`/`Env`) decide how a problem names a setting, carried onto `ResolvedOAuthConfig::key_naming` and `ConfigError` so log lines and errors produced after resolution name settings the same way the input did. `ConfigError::problems` is public, `naming` is private (`ConfigError::naming()` reads it). `required_scopes` (list) and `required_scope` (single) are unioned, trimmed, deduplicated, order-stable; an empty union means no scope check and needs `require_at_jwt` or `allow_unscoped_tokens`; an explicitly blank/whitespace entry in either is always an error, and every required or advertised scope must be a scope-token (`is_scope_token`). An omitted `scopes_supported` resolves to the required scopes. `check_url` refuses space/control/non-ASCII characters; a plain-`http` non-loopback URL needs `allow_insecure_http`. `ResolvedOAuthConfig` is `#[non_exhaustive]`; its `accepted_audiences()` is `audience` ∪ `audiences`. Owns the `WIKI_REWRITES` test-pinned strings — see Key conventions above |
| `algorithms.rs` | The two independent algorithm gates, and the crate-owned `Algorithm` enum (no HMAC/`none` variant; `to_jwt`/`from_jwt` are the only bridge to `jsonwebtoken`). `DEFAULT_ALGORITHMS` (every asymmetric alg `ring`-backed `jsonwebtoken` 9 can verify) and `parse_algorithm` (refuses HMAC/`none` outright with a typed `AlgorithmError` — no config can enable them) bound the configured allowlist; `key_algorithms` (by JWK `kty`/curve) and `signing_algorithm` (a JWK's own declared `alg`, if present) bound what one key may verify. A token's `alg` must pass both, which is what stops an attacker-chosen header from steering an RSA key into an ECDSA verification or any key into HMAC |
| `jwks.rs` | `JwksStore`: JWKS discovery (OIDC Discovery then RFC 8414, exact-issuer-match required), fetch (redirect policy `judge_redirect` refuses an https→http downgrade and, without `allow_insecure_http`, a hop to plain http on a non-loopback host; a discovered `jwks_uri` is held to the same opt-in; response capped at `MAX_FETCH_BYTES`, at most `MAX_JWKS_KEYS` keys parsed), caching, and per-key algorithm binding (`cached_key`, skipping non-signature — `use` other than `sig`, `key_ops` without `verify` — and unparseable keys one at a time rather than failing the whole set, and flagging an alg-less multi-algorithm key `ambiguous` for a one-time `warn`). `JWKS_MIN_REFETCH_INTERVAL` (60s) throttles an unknown-`kid` refetch; `JWKS_BACKGROUND_REFRESH_INTERVAL` (hourly) is the only thing that notices a withdrawn key, with `background_retry_delay` for a failed pass. Every fetch runs detached (`refresh_detached`) so a dropped caller cannot cancel it. The `RwLock`/`refresh_lock` split and the fail-closed-on-any-failure behavior are covered in the Architecture section above; `decoding_key`'s "exactly one candidate key with no `kid`" fallback (`lookup`) is documented on the function itself — it never tries more than one key per verification attempt |
| `validator.rs` | `OAuthValidator`: built once from a `ResolvedOAuthConfig` (re-checks the audience/algorithm/leeway invariants `resolve` already enforced, since `ResolvedOAuthConfig`'s fields are public and may be hand-adjusted), then `validate`/`validate_cached` (the cache-only path `authenticate()`'s two-pass check uses) run header checks (`check_header`: size, JWS shape, `crit` via `check_crit`, `alg` allowlist, `typ` — see `token::check_typ`) before any key fetch, then `verify` (one `jsonwebtoken::decode` for signature + `iss`/`aud`/`exp`/`nbf`, then the exact-`iss`-string recheck, the `nbf` NumericDate check, the `cnf` refusal, then all-of scope matching). Also owns the RFC 9728 metadata document and the two `WWW-Authenticate` challenge strings (`invalid_token_challenge`/`insufficient_scope_challenge`, built from `challenge.rs`), `spawn_background_refresh` (a `Weak`-holding task that stops with the validator), and startup-only warning checks: a `required_scopes` entry missing from a non-empty `scopes_supported` (`unadvertised_scopes`; an empty one makes the challenge name the required scopes, so it is not warned about) (a guaranteed 403 for a client that only requests the advertised scopes), an unscoped config with `require_at_jwt` off (`unscoped_posture`, an ID token becomes a working bearer credential; `resolve` already refuses it without `allow_unscoped_tokens`), and a plain-`http://` issuer/`jwks_uri`/resource on a non-loopback host (refused by `resolve` without `allow_insecure_http`). `metadata()` returns `&Value`. The `# Runtime` section on `OAuthValidator` is the Tokio requirement. Documents the RFC 7662 opaque-token-introspection extension point in `OAuthValidator`'s own doc comment — not built, but the API is shaped so it could be added as a feature-gated alternative key source without a breaking change |
| `token.rs` | `AuthorizedToken` (subject/principal/scopes; `#[non_exhaustive]`, `has_scope`) and `TokenRejection` (`Missing`/`Invalid(String)`/`InsufficientScope`, `#[non_exhaustive]` — the 401-vs-403 split RFC 6750 requires; a `std::error::Error` whose `Display` is the category only, never the `Invalid` reason). `extract_scopes`/`extract_principal` read every configured claim in every accepted shape (string, space-delimited or not; array); `check_typ` is the RFC 9068 `typ` gate `validator.rs` calls. `MAX_TOKEN_BYTES` (16 KiB) and `MAX_LOGGED_CHARS` (128, via `for_log`) bound, respectively, what a credential may be and what a token-derived string may look like in a log line |
| `challenge.rs` | RFC 9728 metadata (`metadata_document`, which omits an empty `scopes_supported` per §3.2; `PROTECTED_RESOURCE_METADATA_PREFIX`; `resource_metadata_url`/`metadata_path` — the well-known segment goes between authority and path, not at the end, and the path is kept verbatim, trailing slash included, per §3.1) and the two RFC 6750 `WWW-Authenticate` builders (`invalid_token`, `insufficient_scope`), which omit the `scope` attribute entirely rather than sending it empty when there is nothing to name (RFC 6749 §3.3); the validator feeds the 401 the required scopes when `scopes_supported` is empty. `quoted` escapes a config-derived value for an HTTP quoted-string — defence against a typo producing a malformed header, not against an attacker |
| `authenticate.rs` | `Credential` (`StaticToken`/`OAuth(AuthorizedToken)`, `#[non_exhaustive]`) and `authenticate()`: the framework-free credential check every candidate header value goes through — constant-time (`subtle`) static-token comparison first (needs no network), then OAuth in two passes (cache-only, then a pass that may trigger a key fetch, so one candidate's unknown `kid` never queues a request behind a refetch when another candidate's key is already cached). Precedence on refusal: any acceptance wins; otherwise `InsufficientScope` if any candidate was valid-but-unscoped; otherwise `Missing` with no non-blank candidate; otherwise `Invalid` with the first candidate's reason. Every candidate is checked independently — a bad credential in one source never masks a good one in another — no framework dependency, so a non-axum HTTP stack calls this directly |
| `policy.rs` | `static_token_policy`: pure decision logic (no logging) for which static token, if any, an `AuthLayer` should hold alongside OAuth — `StaticTokenDecision`'s five variants (`StaticAndOAuth`/`StaticOnly`/`OAuthOnly`/`StaticIgnored`/`Unauthenticated`) cover dual mode, static-only, OAuth-only, `accept_static_bearer: false` ignoring a configured token, and the explicit unauthenticated opt-out. `NoAuthConfigured` is returned when nothing is configured and `allow_unauthenticated` was false. Its hand-written `Debug` redacts the token; an application wraps this with its own log lines and message wording (see mcp-md-wiki's `server::static_bearer_token`) |
| `axum.rs` | The `axum` feature: `CredentialSource` (`Bearer`/`Raw` header, `#[non_exhaustive]`), `AuthLayer` (a `tower::Layer` and the state for the `require_auth` middleware fn — the two behave identically, both routing through `AuthLayer::check`), `AuthLayerBuilder` (fail-closed `build`/`build_with_decision` — including `AuthLayerError::InvalidChallenge` —, `static_challenge` for the no-OAuth 401 challenge, default `DEFAULT_STATIC_CHALLENGE`; `on_reject` shapes only the refusal body/extra headers — status and `WWW-Authenticate` are fixed after it runs, in `Enforce::reject`; `RejectContext`'s hand-written `Debug` prints header names only, and `check` marks credential headers sensitive), and `metadata_router` (serves the RFC 9728 document on the bare well-known prefix and, when the resource URL has a path, on the path-suffixed form too, matched by literal string comparison rather than registered as an axum route pattern — a resource URL may legally contain `:`/`*`/`{}` characters axum would read as routing syntax). Logs every outcome itself (module docs list the levels) so an application needs no auth-specific logging of its own |
| `env.rs` | The `env` feature: `secret_from_env`/`secret_from_lookup` (`VAR` or `VAR_FILE`, Docker Compose `secrets:`-mount shape; both set is an error, not a silent preference; a `_FILE` that reads empty is an error, an absent `VAR` is not) and `oauth_config_from_env`/`oauth_config_from_lookup` (one `<PREFIX><FIELD_UPPER>` variable per `OAuthConfig` field, lists whitespace-split, bools strict `"true"`/`"false"`, `<PREFIX>ENABLED` unset inferring on/off from whether any `IdentifyingVars` entry is set). `EnvOAuthConfig`/`unresolved_oauth_config_from_env` is the hook an application uses to layer its own defaults (a default required scope, say) between loading and `resolve` — the same hook a config-file application has between deserializing and calling `OAuthConfig::resolve` directly. `EnvError` never carries a secret's value, only variable names and file paths. Every `_lookup`/`_from_lookup` twin exists so tests never call the `unsafe`-as-of-2024-edition `std::env::set_var` |
| `testing.rs` | **Test-only** fixtures (compiled for this crate's own tests, and behind the `testing` feature for consumers'): throwaway RSA/EC/Ed25519 keypairs (`KEY_A_PEM`/`KEY_B_PEM`/`EC_PEM`/`ED_PEM`, generated for this suite, used nowhere else — see the leak policy), JWK builders (`jwk_rsa_a`, `jwk_ec`, `jwk_ed`, `jwks_of(&[..])`, `jwks_body`/`jwks_body_all`), token minting (`mint`/`mint_with` take `&impl Serialize` claims; `valid_token`), a `resolved_config` fixture, and `FakeJwksServer` (`Debug`, `#[non_exhaustive]`)/`spawn_jwks_server`/`spawn_http_server` (an in-process fake authorization server for discovery/JWKS tests). Models a plausible Authentik deployment — not a code default, see Key conventions |

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
  names the same type from their own direct dependency on it. Only the `axum`
  feature's `axum`/`http` apply today (`metadata_router` returns
  `axum::Router<S>`, `require_auth`'s signature takes axum's
  `State`/`Request`/`Next`, `CredentialSource` holds an `http::HeaderName`,
  `static_challenge` takes an `http::HeaderValue`); that ships in a new `0.x`
  minor. `jsonwebtoken` deliberately does not (see its pin paragraph above),
  and `reqwest` never appears in a public signature either.
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
  string-match problem text in general; the durable fix, if the need recurs,
  is a structured problem kind or a stable hint a consumer can match on
  instead of prose — addable later without a breaking change, since
  `ConfigError` has a private field, and not built now (see Key conventions).
- MSRV is `1.89`, declared in `Cargo.toml`'s `rust-version` (which is what
  makes a too-old local toolchain fail fast with a clear message) and kept in
  lockstep with `rust-toolchain.toml`'s `channel`. Raising MSRV is a breaking
  change under this crate's policy — bump the minor version and say so in
  `CHANGELOG.md`, and update both files together. 1.89 was chosen to match the
  crate's first consumer (mcp-md-wiki) and because the crate is edition 2024
  and uses let-chains.

## Workflow

**Pattern A (CI-gated)** on GitHub, `master` as the default branch. The
repository ruleset below is configured in GitHub's repo settings, not tracked
in this tree, so it is maintainer-owned configuration rather than something a
change in this repo can alter directly — treat it as always-in-effect policy:

- `master` takes no direct pushes and is protected by a repository **ruleset**
  whose only required status check is `ci-pass` (never `checks`/`msrv`
  individually), which requires squash merges (no merge or rebase commits),
  and which auto-deletes a branch once its PR merges.
- Work on a branch, open a PR against `master`. `.github/workflows/ci.yml`
  fans `checks` (fmt, four clippy runs, tests with all and with default
  features, `cargo build --examples --all-features`, a `-D warnings` doc
  build, `cargo audit`, `cargo package --list`, `cargo publish --dry-run`) and
  `msrv` (a separate build on the pinned `1.89` toolchain) into `ci-pass`.
- `ci-pass` uses `if: always()` plus an explicit result check specifically so
  that a failed upstream job fails `ci-pass` rather than being skipped and
  read as passing — see the comment at the top of `ci.yml` before touching it.
- Squash-merge once `ci-pass` is green and the change has been reviewed.
- `post-merge.yml`-style re-checks are not currently configured for this repo
  — if one is added later, it re-runs the cheap checks on `master` after
  every push and is not itself a required check.

## Release process

- **Repo setup, before the manual 0.1.0 publish**: after creating the GitHub
  repo, enable private vulnerability reporting —
  `gh api -X PUT repos/St0nefish/oauth-resource-server/private-vulnerability-reporting`
  (Settings → Code security → Private vulnerability reporting). It is off by
  default on a new repo, and `SECURITY.md` and
  `.github/ISSUE_TEMPLATE/config.yml` depend on it: without it there is no
  **Report a vulnerability** button, the issue-chooser's security link fails,
  and (blank issues being disabled) a public bug report is the only channel
  left. Confirm with
  `gh api repos/St0nefish/oauth-resource-server/private-vulnerability-reporting`
  returning `{"enabled":true}`.
- **0.1.0 is published manually**: `cargo publish` with a personal crates.io
  API token, from a clean checkout of the tagged commit. crates.io requires
  the crate to already exist before a trusted publisher can be attached to it,
  so this first release cannot go through CI.
- **Every release after 0.1.0** is tag-driven trusted publishing:
  `.github/workflows/release.yml` triggers on a pushed `v*` tag. Its `verify`
  job (read-only, no OIDC permission) checks the tag matches `Cargo.toml`'s
  version and re-runs fmt/clippy/tests; only then does the separate `publish`
  job — the only one with `id-token: write`, running nothing but checkout,
  toolchain, auth and publish — authenticate via
  `rust-lang/crates-io-auth-action` (a short-lived OIDC-exchanged token; no
  long-lived token secret is ever stored in this repo) and run
  `cargo publish`. Keep build scripts, proc macros and dev-dependencies out of
  the job that can mint the token. It is **inert** until a
  trusted publisher naming this repo + `release.yml` is configured on
  crates.io, which can only happen after the manual 0.1.0 publish — see the
  workflow file's header comment for the exact steps and for why the `v0.1.0`
  tag itself is expected to fail here either way (don't chase that failure).
- Tag only a commit already on `master`. A version bump is its own commit
  (`Cargo.toml` + `CHANGELOG.md`), reviewed through the normal PR flow before
  the tag is pushed.

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
cargo package --list
cargo publish --dry-run        # pass --allow-dirty for a local, uncommitted tree
```

The `msrv` CI job additionally builds on the pinned MSRV toolchain
(`cargo "+1.89" build --all-features --locked`, reading `rust-version` from
`Cargo.toml`) — most contributors won't have `1.89` installed locally and CI
covers it regardless.

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
