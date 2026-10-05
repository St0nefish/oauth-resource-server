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

Sources of truth this file points at rather than repeats: `Cargo.toml` (features,
dependency floors and their reasons, MSRV), `rust-toolchain.toml` (toolchain pin),
`.github/workflows/*.yml` (every CI step, tool version and runner),
`.github/scripts/*.sh` (release rules), `deny.toml`/`.cargo/audit.toml`
(supply-chain policy), and the code's own doc comments.

## How the pieces fit

```text
OAuthConfig ──resolve()──▶ ResolvedOAuthConfig ──▶ OAuthValidator (Arc, one per process)
 (config.rs, env.rs)        (config.rs)              (validator.rs + builder.rs, owns JwksStore in jwks.rs)
                                                          │
            per request: header values ──▶ authenticate() (authenticate.rs) ──▶ Credential | TokenRejection
                                                          │
                       refusal()/refusal::select (refusal.rs) ──▶ status + WWW-Authenticate (challenge.rs)
                                                          │
   framework glue:  http_layer::Gate (tower)  ◀── axum::AuthLayer / http_layer::HttpAuthLayer
                    route checks: RequireScopes, axum::Scoped, mcp::McpToolScopes (all via http_layer::judge_scopes)
   cross-cutting:   observe.rs (log/metric vocabulary), observability.rs (metric names), policy.rs (static-token decision)
```

- **Core** (always compiled, no `http` dependency): `config`, `algorithms`,
  `builder`, `jwks`, `validator`, `token`, `challenge`, `authenticate`,
  `refusal`, `policy`, `observe`. A non-tower stack uses only these.
- **Shared HTTP layer** (`tower`): `http_layer::Gate` holds every fail-closed
  build check and the per-request admit/refuse logic. Both layers delegate to
  it so they cannot disagree; never put decision logic in one layer only.
- **One decision point per concern**: status and challenge → `refusal::select`;
  scope matching → `token::missing_scopes`; static-token comparison →
  `authenticate::find_static`; key-set ingestion → `jwks::keys_from_jwk_set`;
  "plain http"/"loopback" → the parsed-URL helpers. Add to these, never beside
  them.

## Architecture

The crate turns a process into an OAuth 2.0 resource server and nothing more: it
verifies JWT access tokens a separate authorization server minted, and never
issues, refreshes, revokes or introspects one. The shape an application builds
is always the same three steps, laid out in `src/lib.rs`'s module docs:

1. Resolve an `OAuthConfig` into a `ResolvedOAuthConfig` (`OAuthConfig::resolve`,
   naming settings with a `KeyNaming` so errors read the way the operator wrote
   them).
2. Build one `OAuthValidator` from it and `Arc`-share it
   (`OAuthValidator::spawn_background_refresh` warms and then periodically
   refreshes the key cache).
3. Per request, call `authenticate()` (framework-free, with `refusal()` for the
   401/403 and its challenge) or run the `axum` feature's `AuthLayer`/
   `require_auth` or the `tower` feature's `HttpAuthLayer`.

Scopes a route or operation needs beyond the validator's are checked on the
token that one validator produced — the layers' `require_scopes`, the
`RequireScopes` route layer, the axum `Scoped<S>` extractor, the `mcp` feature's
`McpToolScopes`, or `AuthorizedToken::require_scopes` + `refusal_for_scopes()`
by hand — never with a second validator.

Nothing here hot-reloads: a changed config takes effect only when a new validator
and a new layer are built, which in an application means a restart. An
application should treat every setting it resolves through this crate as
restart-required, and this crate never claims otherwise in its docs.

**Provider-agnostic by construction.** Authorization servers agree on the
signature and on `iss`/`aud`/`exp`, and disagree on nearly everything else an
access token carries — where scopes live (`scope_claims`), what audience they
stamp (`audience`/`audiences`), which algorithms they sign with (`algorithms`),
whether `typ` is `at+jwt` (`require_at_jwt`), which claim names the caller
(`principal_claims`). Every one of those differences is an `OAuthConfig` field,
never a code branch. If you find yourself writing `if provider == "..."`, the
config surface is missing a knob, not the crate missing a branch.

- A new provider's shape gets a **documented-shape fixture test** — built from
  that provider's own published token/JWKS shape using `testing`'s fixtures,
  never a real token or issuer.
- Label it in its doc comment and in `docs/providers.md` as `verified in
  production` / `verified in a sandbox` / `documented-shape fixture, not
  live-tested`. Never upgrade an existing label without having done the
  verification it claims.

### Security invariants that must never regress

Each is enforced by a named piece of code, so a change to any of them is a
deliberate, reviewable act. `SECURITY.md` points here for the full list and the
module each one lives in; keep that true.

#### Token validation

- **Algorithm allowlist before any key fetch.** `OAuthValidator::check_header`
  (`src/validator.rs`) runs size/shape/`crit`/`alg`/`typ` checks on the
  **unverified** header and returns before `JwksStore` is touched — junk cannot
  schedule IdP traffic.
- **`crit` is refused** (`validator::check_crit`, RFC 7515 §4.1.11): this crate
  understands no JWS extension, so any `crit` — unknown, empty or malformed —
  makes the token invalid. jsonwebtoken's `Header` drops `crit` silently, which
  is why the protected header is also read raw.
- **Two independent algorithm gates.** Each JWKS key is narrowed to the
  algorithms its own key type can produce (`algorithms::key_algorithms`,
  RSA/EC/OKP by curve), intersected with the key's own declared `alg` (if any)
  and the configured allowlist, in `jwks::cached_key`. A token's `alg` must pass
  both, which stops an attacker-chosen header from steering an RSA key into an
  ECDSA verification or any key into HMAC.
- **No HMAC, no `none`, ever.** `algorithms::parse_algorithm` refuses
  `HS256`/`384`/`512` and `none` outright — no config can turn them on — and the
  crate-owned `algorithms::Algorithm` has no HMAC or `none` variant at all.
- **Only signature keys verify.** No HMAC (`oct`), no `use: enc` key, and no key
  whose `key_ops` lacks `verify` is ever usable: `key_algorithms` returns `None`
  for `AlgorithmParameters::OctetKey`, and `jwks::cached_key` skips any JWK whose
  `public_key_use` is not `Signature`/absent or whose `key_operations` is present
  without `KeyOperations::Verify` (RFC 7517 §4.3).
- **An alg-less JWK stays multi-algorithm.** It is usable for every allowlisted
  algorithm its type can produce (a documented RFC 8725 §3.1 deviation);
  `JwksStore::refresh` logs a `warn` naming its `kid` the first time it appears
  (`CachedKey::ambiguous`). Do not silently bind such a key to one algorithm —
  that would break any provider that signs with a non-first algorithm.
- **Signature and claims in one `decode`.** Signature verification and
  `iss`/`aud`/`exp`/`nbf` all happen inside **one** `jsonwebtoken::decode` call
  (`OAuthValidator::verify`), so the claim checks can never be reordered to run
  after a signature was trusted. Two settings `OAuthValidator::from_builder` puts
  on the `jsonwebtoken::Validation` make this work and must never regress:
  - `validation.set_required_spec_claims(&["exp", "iss", "aud"])` — jsonwebtoken
    validates `aud`/`exp` only when the claim is *present*; without this a token
    with no `aud` or no `exp` would pass.
  - `validation.validate_nbf = true` — off by default in jsonwebtoken; this is
    what makes a not-yet-valid token fail.
  - jsonwebtoken skips an `nbf` it cannot read as a number, so `verify` refuses
    one itself (`nbf_is_numeric_date`); otherwise a string or out-of-range `nbf`
    would silently disable the check.
- **`cnf` is refused** (`OAuthValidator::verify`): a sender-constrained token
  (DPoP `jkt`, mTLS `x5t#S256`) cannot have its binding verified here, and
  accepting it as a bearer token would undo it (RFC 9449 §7.2, RFC 8705 §3).
- **`iss` is re-checked as an exact single string after decode**
  (`OAuthValidator::verify`): jsonwebtoken alone would accept an `iss` *array*
  merely containing the right value, which RFC 7519 does not allow.
- **The opt-in claim policy** (`allowed_client_ids`, `max_token_age_secs`,
  `required_claims`) runs in `OAuthValidator::check_claim_policy`, called by
  `verify` only, on the claim map the single `decode` produced:
  - after the `iss`/`nbf`/`cnf` rechecks and **before** the scope check, so it
    never reads a claim the signature has not covered;
  - its refusals are 401s (`ClientNotAllowed`, `TokenTooOld`, `NotYetValid`,
    `MissingClaim`, `MalformedClaim`, `ClaimMismatch`), never a 403;
  - each check is off when its field is empty/`None`, so a config setting none
    of them validates exactly as without them (pinned by
    `the_claim_policy_is_off_by_default_and_never_runs_before_the_signature`);
  - the client is read by `token::client_id_of` (`client_id`, else `azp`), the
    function `AuthorizedToken::client_id` uses, except that the allowlist
    refuses a `client_id` that is present but not a non-empty string instead of
    falling through to `azp`;
  - `iat` is read by `token::numeric_date_secs`, so a present-but-unreadable
    `iat` is refused, not skipped, when the age bound is on;
  - `required_claims` naming a scope claim or `azp`/`client_id` is warned about
    at build (`validator::required_claim_footguns`), never refused;
  - `resolve` refuses a `required_claims` name in
    `config::RESERVED_REQUIRED_CLAIMS` (`iss`, `aud`, `exp`, `nbf`, `iat`, `cnf`),
    any non-scalar value, and a `max_token_age_secs` outside
    `1..=MAX_TOKEN_AGE_SECS`.
- **Refusal kinds are precise.** An unknown `kid` inside the refetch cooldown
  is `KeySetUnavailable`, not `KeyNotFound`, when the last refresh failed or no
  key is held (`JwksStore::decoding_key`); jsonwebtoken's `MissingRequiredClaim`
  for a claim the (already signed) payload does carry is `MalformedClaim`
  (`validator::decode_error_kind`).

#### Key set (JWKS)

- **Every failure fails closed.** `JwksStore::refresh` keeps the keys already
  held on any fetch/parse/discovery failure — an IdP outage never revokes keys
  that are still good, which also means a withdrawn key stays trusted until a
  refresh succeeds; there is deliberately no maximum staleness. Every rejection
  path in `OAuthValidator`/`JwksStore` returns `TokenRejection`, never a token.
- **A refetch cannot be cancelled by its caller.** `JwksStore::refresh_detached`
  runs it in a spawned task that owns the `refresh_lock` guard
  (`OwnedMutexGuard`) until the fetch completes. Run inline, a dropped request
  future (client disconnect, timeout layer) would stamp `last_attempt` and spend
  the unknown-`kid` cooldown with no keys loaded.
- **Lock discipline.**
  - The JWKS `RwLock` (`JwksStore::jwks`) is never held across a network call —
    only to read or swap in-memory state.
  - Refreshes serialize on a separate `refresh_lock` `Mutex`, so a request whose
    key is cached never stalls behind a slow IdP.
  - `OAuthValidator::key_set_status`/`is_ready` read neither: they copy
    `JwksStore::status`, a synchronous `std::sync::Mutex` locked only to copy or
    overwrite a few fields — never across an `.await`, never while taking `jwks`
    or `refresh_lock` — so a probe never does I/O or waits on a refresh.
- **Refetch is rate-limited; withdrawal is noticed by a timer.**
  - An unknown `kid` triggers at most one refetch per
    `jwks::JWKS_MIN_REFETCH_INTERVAL`. `kid` comes from the unverified header, so
    without this cooldown junk tokens turn the process into an amplifier pointed
    at the IdP.
  - A separate unconditional background refresh
    (`jwks::JWKS_BACKGROUND_REFRESH_INTERVAL`) is what notices a key the
    authorization server **withdrew**; an unknown-`kid` refetch only ever adds
    keys.
  - After a failed background pass it retries sooner: `background_retry_delay`
    while keys are held, `keyless_retry_delay` (faster, from
    `KEYLESS_RETRY_FLOOR`) while none is — a keyless validator refuses
    everything and a readiness probe keeps away the traffic that would trigger a
    refetch. That floor is the fastest any background retry may run.
  - Both schedules are timer-driven only, never shortened by a request, and
    neither shortens the unknown-`kid` cooldown: every pass stamps
    `last_attempt`, which restarts it.
  - The task holds only a `Weak` between passes and stops when the validator's
    `alive` watch sender drops with it.
- **Fetches are hardened** (`src/jwks.rs`):
  - A redirect from `https` to non-`https` is refused outright; one to plain
    `http` on a non-loopback host is refused without `allow_insecure_http`
    (`jwks::judge_redirect`, the custom `reqwest::redirect::Policy`
    `client_builder` gives both clients). A fetch whose first URL is loopback may
    not be redirected off loopback at all (`judge_redirect` reads `previous[0]`).
  - Only a `2xx` response is read (`fetch_json`; `error_for_status` alone lets a
    `3xx` through).
  - A `jwks_uri` discovered from a plain-`http` (loopback) issuer is held to the
    same opt-in (`jwks::jwks_uri_from_metadata`): `resolve` only sees configured
    URLs, so everything reached at run time is checked where it is reached.
  - Every fetch is bounded: `jwks::MAX_FETCH_BYTES` caps the body,
    `jwks::MAX_JWKS_KEYS` caps keys parsed, `token::MAX_TOKEN_BYTES` caps the
    credential before it is decoded.
  - Every key set, fetched or seeded by `OAuthValidatorBuilder::initial_jwks`,
    goes through the one path `jwks::keys_from_jwk_set` (key cap,
    `parse_jwks_entry`/`cached_key` narrowing; a seed also through
    `keys_from_jwk_set_json`'s `MAX_FETCH_BYTES` cap).
- **No builder option relaxes a fetch rule.** `add_root_certificate_pem` only
  *adds* anchors (rustls merges them with the webpki/native roots, native-tls
  with the OS store); an explicit `proxy` tunnels https with `CONNECT`;
  `fetch_timeout` is held to `MIN_FETCH_TIMEOUT..=MAX_FETCH_TIMEOUT` because it
  bounds how long a refresh holds `refresh_lock`.
- **No proxy ever carries a loopback fetch** — explicit, environment or system.
  - `jwks::http_clients` builds two clients from the same settings and redirect
    policy; `HttpClients::for_url` (called in `fetch_json` for every discovery
    URL and the configured or discovered `jwks_uri`) gives a URL satisfying
    `is_loopback_url` the `loopback` client (`no_proxy()`) and everything else
    `normal` — reqwest's default proxy handling untouched, or, with an explicit
    proxy, `no_proxy()` + that proxy + `jwks::PROXY_BYPASS`.
  - Do not reimplement reqwest's env/system proxy parsing instead: it cannot be
    matched exactly (whitespace, `system-proxy` on macOS/Windows via feature
    unification).
  - The `loopback` client never leaves this host: `judge_redirect` refuses a hop
    off loopback when the first URL was loopback, and its `dns_resolver` is
    `jwks::LoopbackResolver`, which answers every name with `[::1]` and
    `127.0.0.1`. That matters because `localhost`/`*.localhost` are exempted
    from `allow_insecure_http` and every proxy *by name* (`is_loopback_url`), and
    some resolvers (musl, glibc without nss-myhostname, some container DNS) send
    `*.localhost` upstream.
  - The one residual, documented in the README security model and on `for_url`:
    a redirect from a non-loopback URL to a loopback one stays in `normal`, so an
    env/system proxy can carry that hop — https to https (TLS end to end) or
    plain http already gated by `judge_redirect`. Refusing such redirects would
    narrow accepted input.

#### Configuration

- **`OAuthConfig::resolve` refuses what would silently weaken the deployment**,
  and every opt-in is an explicit field, never a default:
  - a plain-`http` `issuer`/`jwks_uri`/`resource` on a non-loopback host without
    `allow_insecure_http` (RFC 8414 §2, RFC 9728 §1.2);
  - no required scope with `require_at_jwt` off without `allow_unscoped_tokens`
    (ID tokens would pass);
  - a required or advertised scope that is not an RFC 6749 §3.3 scope-token;
  - a URL containing a space, control or non-ASCII character (the raw string
    reaches every challenge header).
- **"Plain http" and "loopback" are decided on the parsed URL, never the raw
  text** (`validator::plain_http_non_loopback`/`parsed_plain_http_non_loopback`,
  the private `is_loopback_url(&Url)`). The URL parser normalizes `http:/host`,
  `http:host` and `HTTP:\\host` to `http://host`; a raw-prefix test lets those
  skip the opt-in. The same parsed decision gates a discovered `jwks_uri`, a
  redirect hop, client selection (`HttpClients::for_url` via `url_is_loopback`)
  and the credentialed-proxy check.
- **Non-canonical spellings** that are otherwise acceptable are not refused
  (that would narrow input) but warned about once at startup
  (`non_canonical_warnings`). The `://`-splitting URL builders
  (`discovery_urls`, `resource_metadata_url`, `metadata_path`) split only a
  value that parses and is canonical (`is_canonical_url`), so a non-canonical
  spelling can never move a built URL onto another host.

#### HTTP responses and layers

- **`WWW-Authenticate` is always right.**
  - It is set — or overwritten, whatever a caller's `on_reject` returned — on
    **every** 401/403 once OAuth is configured (`http_layer::Gate::finish`,
    called by both `axum::Enforce::reject` and `HttpAuthLayer::check`).
  - Status and challenge are decided in exactly one place, `refusal::select`,
    which the public `refusal()`/`refusal_with_static_challenge()` (over
    `String`s) and `Gate::status_and_challenge` (over pre-validated
    `HeaderValue`s) both call, so a hand-built integration and either layer
    cannot disagree; `axum::shared_refusal_tests` pins that, and that the two
    layers answer every request identically.
  - A missing credential gets the same `invalid_token` challenge as a bad one,
    deliberately: `resource_metadata` is how clients (claude.ai among them) find
    the authorization server, and some refuse to start the flow without it.
  - A validator challenge that is not a valid header value fails
    `AuthLayerBuilder::build`/`HttpAuthLayerBuilder::build`
    (`AuthLayerError::InvalidChallenge`, from `Gate::build`) instead of shipping
    challenge-less 401s. `OAuthValidator::build` still builds (refusing would
    narrow what builds) but logs once at `error` (settings named via
    `KeyNaming`, URL through `redact_url`), stores `challenge::fallback`s
    (`Bearer error="…"`, `scope` only if valid) and sets `challenge_fallback`,
    which `Gate::build` turns into that error (`tests/challenge_fallback_log.rs`
    pins the log). So `refusal()` never returns a challenge that splits a
    header.
  - A caller's `static_challenge` string that is not a header value is replaced
    by `DEFAULT_STATIC_CHALLENGE` in `refusal_with_static_challenge`.
  - Without OAuth, a 401 carries `DEFAULT_STATIC_CHALLENGE` (`refusal.rs`,
    re-exported at the root and as `axum::DEFAULT_STATIC_CHALLENGE`; RFC 9110
    §15.5.2) unless the application opts out with `static_challenge(None)`
    (`refusal_with_static_challenge(.., None)` by hand).
  - A per-request 403 (a route's own scopes) changes only which
    `insufficient_scope` challenge `select` is handed, never the decision:
    `Gate::status_and_challenge_with`/`finish_with` pass a
    `Gate::scope_challenge`, and the public `refusal_for_scopes` passes the same
    string to the same `select`.
  - That challenge is always `OAuthValidator::insufficient_scope_challenge_for`
    over the validator's `required_scopes`, then the layer's `require_scopes`,
    then the route's (`scopes_with_floor`/`scope_floor`, deduplicated), so the
    layers, `RequireScopes`, `Scoped`, `McpToolScopes` and `refusal_for_scopes`
    send identical bytes for the same scopes (`axum::scope_tests` pins parity).
  - It is always a valid header value by construction
    (`challenge::insufficient_scope_for`): a non-scope-token scope is left out,
    never escaped in; `error_description` is reduced to RFC 6750 §3's
    `%x20-21 / %x23-5B / %x5D-7E` (every other char — `"`, `\`, CR, LF,
    non-ASCII — becomes a space, never escaped or passed through) and cut to
    `MAX_ERROR_DESCRIPTION_BYTES`; a fallback validator's per-request challenge
    omits `resource_metadata`; the `scope_challenge` fuzz target checks all of
    it. With the configured scopes and no description it equals
    `insufficient_scope_challenge()` byte for byte, which is what lets a layer
    with `require_scopes` pre-render its own.
- **Per-route scope checks fail closed and never widen access.**
  - A layer's `require_scopes` runs in `Gate::admit` on the accepted credential
    before anything is inserted (an optional layer's no-credential pass-through
    is unchanged).
  - `RequireScopes`, `McpToolScopes` and `Scoped` read the innermost
    `Credential` (not an `AuthorizedToken`, which an outer layer may have
    inserted) via `http_layer::judge_scopes`. Matching is
    `token::missing_scopes`, the one rule `verify` uses too (exact, all-of).
  - A static token has no scopes: every requirement refuses it with 403 unless
    the application opted in (`static_token_bypasses_scopes` on the builders,
    `RequireScopes`, `McpToolScopes`; `Scoped` has no opt-in — it yields an
    `AuthorizedToken`).
  - `Gate::build` refuses scopes with no validator and no bypass
    (`AuthLayerError::ScopesNeedOAuth`) and a non-scope-token entry
    (`InvalidScope`). `RequireScopes::new`/`McpToolScopes::default`/`tool` panic
    on the latter and are for literals; their `try_` forms return the offending
    scope (`http_layer::InvalidScope`) for configured values. A `ScopeSet` with a
    non-scope-token entry is a compile error (`ValidScopeSet::CHECKED`, a `const`
    assertion over `http_layer::all_scope_tokens`, pinned by a `compile_fail`
    doctest). `build_with_decision(Unauthenticated)` with `require_scopes` is
    `AuthLayerError::ScopesWithoutAuthentication`, never a silent drop.
  - Both layers insert the private `http_layer::GateRan` marker
    (`Some(Arc<Gate>)`, `None` for `allow_unauthenticated`) and a
    `RefusalBody<B>` (their `on_reject`, type-erased, found only for the same
    response body type — else `B::default()`) into every request they pass;
    `http_layer::scope_refusal` builds every route-level refusal from them
    through `Gate::finish_with`, so status, challenge and body match the layer's
    own.
  - No `GateRan` is a 500 (logged at `error`) whatever the requirement; an
    `allow_unauthenticated` layer gives a 401 with `DEFAULT_STATIC_CHALLENGE`; a
    403 from a layer with no validator is logged at `error` (unsatisfiable) and
    carries the bare `BARE_INSUFFICIENT_SCOPE_CHALLENGE`
    (`Bearer error="insufficient_scope"`, RFC 6750 §3.1) —
    `Gate::scope_challenge` returns it without OAuth, `status_and_challenge_with`
    prefers it over the static 401 challenge for a per-request 403, and
    `refusal_for_scopes` does the same without a validator.
  - An `allow_unauthenticated` layer inside an enforcing one does not replace
    the outer `GateRan` (`mark`) nor, inside another axum layer, its `LayerRan`
    (`AuthLayer::check`), so a route check behind both judges the outer
    credential and answers with the outer layer's 401/403.
  - `Scoped` refuses a missing credential through `refuse_absent` (or, behind
    only an `HttpAuthLayer` — a `GateRan` but no `LayerRan` — through
    `scope_refusal`'s `Missing`, the layer's 401), and an insufficient one
    through `Enforce::refuse_scoped` or `scope_refusal`.
  - **Claim clauses** (`http_layer::ClaimClause`, crate-private: a top-level
    claim and its any-of values, matched by `AuthorizedToken::has_claim_value`)
    are passed to `judge_scopes` only by `McpToolScopes` (every other caller
    passes `&[]`). An OAuth token must carry every scope AND satisfy every
    clause; a static token passes only with the bypass; a failed clause is
    `InsufficientScope` like a missing scope. The refusal
    (`scope_refusal_with_claims`; `scope_refusal` is it with `&[]`) is
    byte-identical to the scope-only one: the 403 challenge comes from
    `Gate::scope_challenge` over the scopes alone, so no claim name or value
    ever enters `WWW-Authenticate`; `auth.reason` stays `insufficient_scope`;
    only with clauses does the log line differ, adding `required_claims` (claim
    NAMES, never a configured or presented value).
- **`McpToolScopes` (`src/mcp.rs`) never lets a `tools/call` skip its tool's
  requirement.**
  - Every request's body — under **any** method, whatever its headers or size
    hint claim (a lying hint of exactly 0 must not let a `tools/call` through;
    an empty body just ends at once) — is read by `read_capped` under
    `body_limit` (`DEFAULT_BODY_LIMIT`, bounded by
    `MIN_BODY_LIMIT..=MAX_BODY_LIMIT`).
  - 413 on a `Content-Length` or size hint over the limit before reading, and
    as soon as a data frame would cross it, so at most the limit of data is ever
    held (an announced length is reserved up front; otherwise the buffer grows
    by `extend_from_slice`, so capacity can reach about twice the data read,
    never the data itself past the limit). A body that fails mid-read is a bare
    400, logged at `warn` (documented in the README's MCP table and module
    docs). Body reads have no timeout of their own (documented: set one on the
    server).
  - An empty body needs the default requirement (`Rules::for_body`), whitespace
    alone the strictest set. A request with no credential gets the layer's 401
    via `judge_scopes` when its classified requirement is not empty, and is
    refused before reading only when `Rules::always_scoped` (a non-empty default
    and no tool with an empty requirement, scopes and claim clauses both
    counting).
  - A `Requirement` is scopes plus claim clauses. A tool named by `tool` or
    `tool_claim` is configured and needs its own scopes and clauses only (a
    `tool_claim`-only tool has no scopes, not the default's; `tool("x", [])`
    exempts `x` from the default clauses too). Unions (batch, strictest)
    deduplicate clauses by structural equality and never merge two clauses on
    one claim — merging any-of sets would widen access.
  - `for_each_message` is ONE streaming pass that builds no document: tool names
    reach the matcher as a borrowed `&str` (`NameSeed`), `method` is compared in
    place (`IsToolsCall`), and every value it does not inspect goes through
    `Validate` (`deserialize_any`, so UTF-8 and number range are checked exactly
    as `serde_json::Value` checks them — `IgnoredAny` would skip them).
    `Rules::for_body` folds each message into a flag per configured tool, so a
    batch costs no more than one call. Do not reintroduce a whole-body
    `serde_json::Value` pre-pass (an order of magnitude more expensive).
  - It flags as `Ambiguous`: a repeated `method`/`params`/`params.name` (which
    two parsers can resolve differently); a `tools/call` without a readable
    string name; and a message with a serde_json private token key
    (`RAW_VALUE_TOKEN` `$serde_json::private::RawValue`, `NUMBER_TOKEN`
    `$serde_json::private::Number`; `Key::SerdeJsonToken`, compared in place
    after JSON decoding) at **any** depth — with serde_json's `raw_value` (on via
    axum) or `arbitrary_precision` feature, `Value` reads such an object as the
    JSON in its string, so a wrapped `tools/call`, batch or `method` would
    otherwise pass with the default. Every `Validate`/seed returns a `token_key`
    flag that `read_message` ORs in.
  - Unreadable/`Ambiguous` messages need the strictest set (default ∪ every
    tool); a batch the union of its messages', never the default alone.
  - Tool names match exactly (byte for byte after JSON decoding) — documented
    as a deployment requirement on the dispatcher, since a normalizing one would
    reach a scoped tool under an unconfigured spelling.
  - The body goes on as `ReqBody::from(Bytes)`, byte-identical (trailers
    dropped); no log line carries body content, tool names included.
  - The `mcp_tool_calls` fuzz target checks `for_each_message` against
    `serde_json::Value`, except for a body with a token key (found by
    `__fuzz::token_key_in`, a walk independent of `mcp.rs` and of serde_json's
    features), which must instead classify with at least one `Ambiguous`
    message.
- **`AuthLayer`/`HttpAuthLayer` are fail-closed by construction.**
  - `Gate::build` (behind both builders) refuses to build with neither a static
    token nor an OAuth validator (`AuthLayerError::NoCredential`). An empty or
    whitespace-only `static_token` and an empty `StaticTokens` set count as none
    (`StaticTokens::merged` returns `None`), and `static_token_policy` never reads
    a whitespace-only token as "nothing configured", so it cannot become
    `Unauthenticated`.
  - The only pass-through is the explicitly named `allow_unauthenticated()` on
    either layer, or a `policy::StaticTokenDecision::Unauthenticated` (itself
    produced only by an explicit `allow_unauthenticated` at the call site) via
    `from_decision`/`build_with_decision`.
  - `optional()` is not a second pass-through: it still needs a credential
    mechanism to build, and `Gate::admit` passes a request through only when
    `authenticate()` returned `Missing` AND every value of every source header is
    blank (`CredentialSource::presents_nothing` — an unreadable value, a
    non-blank later value of a repeated header, and anything `names_a_token`
    flags, such as a `DPoP` scheme or a tab-separated `Bearer` token, count as
    presented, without touching the strict `bearer_credential` parsing). Every
    other refusal goes through `Enforce::refuse` exactly as without it.
  - An optional layer removes any `Credential`/`AuthorizedToken`/
    `StaticTokenMatch` an outer layer inserted before deciding. Strict layers
    never remove `Credential`/`AuthorizedToken` (extensions accumulate — a
    documented behavior consumers may rely on), but `StaticTokenMatch` always
    pairs with the innermost `Credential`: `Gate::admit` inserts one with every
    `Credential::StaticToken` and removes an outer one on an OAuth acceptance.
  - `build_with_decision` (`Gate::decision_tokens`, after `check_decision`)
    keeps a builder's `static_tokens` set only for a decision carrying a static
    token, drops it on `StaticIgnored` (`accept_static_bearer: false` wins over
    every static token), and refuses it alongside `OAuthOnly`/`Unauthenticated`
    (`AuthLayerError::DecisionWithoutStaticToken`) — a decision made without any
    static token never silently drops a configured set or opens the routes.
- **The axum extractors fail closed.** `AuthorizedToken`/`Credential`/
  `StaticTokenMatch` (and their `OptionalFromRequestParts` forms):
  - the layer inserts a private `LayerRan` marker on every request it passes, so
    an extractor with no value refuses through the same `Enforce::refuse` the
    layer uses (identical status, challenge and `on_reject` body); with no
    marker at all (a route outside every layer) it answers 500 with an `error`
    log — never `None`, never access;
  - `refuse_extraction` logs the unsatisfiable-401 wirings at `error` (a
    required extractor behind `allow_unauthenticated` with no enforcing layer
    around it, `AuthorizedToken` behind a layer with no validator,
    `StaticTokenMatch` behind a layer with no static token); behind an
    `allow_unauthenticated` axum layer inside an enforcing `HttpAuthLayer` it
    refuses through `http_layer::scope_refusal` instead (that layer's 401);
  - behind an `HttpAuthLayer` alone (no `LayerRan`) they return a value it
    inserted but answer 500 when there is none (documented);
  - `Scoped<S>` follows the same rules and refuses an insufficient credential
    through the `GateRan` gate first — `Enforce::refuse_scoped` only when that
    gate is the `LayerRan` layer's own (`Arc::ptr_eq`) or there is no gate — so
    it answers from the same (innermost) layer as `RequireScopes`.

#### Secrets and logs

- **Static tokens are compared in constant time in exactly one place**,
  `authenticate::find_static`, reached by both `authenticate()` (over a borrowed
  one-entry slice) and `authenticate_with_static_tokens` (over a `StaticTokens`
  set) through `check_candidates`:
  - every candidate against every entry with `subtle`'s `ct_eq`, no early exit
    once one matches, the matching index chosen with `conditional_assign` (no
    branch on a comparison);
  - lengths are not hidden (`ct_eq` on slices of different lengths returns
    early);
  - the test-only `STATIC_COMPARISONS` counter, bumped inside `counted_ct_eq`
    (the loop's only comparison), pins that no comparison is skipped. Keep the
    loop branch-free on secret-derived values — `conditional_assign` → `if`
    would be a timing-only regression no functional test can catch.
- **Static-token hygiene.** `StaticTokens::with` refuses a blank or repeated
  secret and any label that is not 1–64 visible ASCII characters
  (`is_log_safe_label`), so a label is always log-safe. Each secret is held in
  `zeroize::Zeroizing`, as are the builders' private `static_token` fields,
  `merged`'s dropped duplicate and the `env` loaders' intermediate copies
  (`env::secret_zeroizing`, behind `secret_from_lookup`, whose `String` return
  type is unchanged). `StaticTokenDecision`'s public `String` payload and
  caller-owned strings are not wiped, and the docs say so.
- **Secrets never reach a log or a `Debug` impl.**
  - `AuthLayer`, `AuthLayerBuilder`, `HttpAuthLayer`, `HttpAuthLayerBuilder`,
    `HttpAuthService` and `StaticTokenDecision` hand-write `Debug` to redact the
    static token; `StaticTokens` prints its count and labels only (the layers
    print their `Gate`'s set that way) and has no `PartialEq`, which would
    compare secrets in variable time.
  - `RejectContext` (`http_layer.rs`, re-exported from `axum`) prints header
    names only and the request path with any query as `?***`
    (`redacted_request_uri`; RFC 6750 §2.3 lets a client send `access_token`
    there — `tests/redacted_request_uri.rs` pins both layers' callback and logs).
  - `Gate::admit` marks every configured credential header
    `set_sensitive(true)` before the callback or the inner service sees it; an
    `allow_unauthenticated` layer (no sources) marks `Authorization` sensitive
    (`http_layer::mark_authorization_sensitive`).
  - `env::EnvError`'s `Display`/`Debug` never include a secret's value (only
    variable names and file paths).
  - `InvalidToken::detail` (also its `Display`/`Deref`) is log-only — never put
    it in a response body. `TokenRejection`'s `Display` renders the category
    only, and `InvalidToken`'s `Serialize` writes the kind label, for that
    reason.
  - `AuthorizedToken`'s `Debug` prints its identity fields (`subject`,
    `principal` — possibly an email —, `client_id`, `audiences`, `jti`, the
    timestamps, `issuer` redacted) but the verified claim map as names only,
    never values (group memberships and the like are personal data).
  - The extractors' and both layers' refusal/misconfiguration logs print the
    request path (and extractor name) only — `uri.path()`, no query — never a
    claim or a token.
- **Every displayed URL is redacted.** `resolve` accepts userinfo in
  `issuer`/`jwks_uri` (sent as Basic auth) and a query in `jwks_uri`, so every
  URL this crate displays goes through `jwks::redact_url` (`***@`, `?***`,
  `#***`; a placeholder for anything unparseable, including an `@` in what
  parsed as the path, e.g. `http://alice:1234/s3cret@host`): log lines,
  `RefreshError` messages, `KeySetStatus::jwks_uri`, `check_url`/plain-http
  `ConfigError` problems, and the `Debug` of `OAuthConfig`,
  `ResolvedOAuthConfig` (both hand-written, destructuring every field so a new
  one cannot be skipped), `OAuthValidator` (which `EnvOAuthConfig`, both layers
  and their builders print through) and `AuthorizedToken`'s `issuer`
  (`jwks::debug_url`: blank stays blank). `tests/redacted_debug.rs` pins the
  `Debug` and problem sides; `tests/redacted_logs.rs` the log side.
  - A problem message (`config::shown`) quotes `try_redact_url`'s result, marked
    "(shown normalized, credential masked)" when that differs from the raw
    value; where it is `None`, `shown_unparsed` quotes the raw value (truncated
    by `for_log`) only if it has no `@`, `?` or `#` and is all visible ASCII,
    and otherwise names the setting alone.
  - A quoted `reqwest` error has its URL stripped (`without_url`). The URL
    actually fetched is never altered.
  - The `OAuthValidatorBuilder::proxy` URL may carry a credential: its `Debug`
    prints only whether one is set, `ValidatorError::InvalidProxy` never carries
    the refused value (only its scheme, or `<redacted>`) nor the URL parser's
    error, and the cleartext-credential `warn` redacts it.
- **Tracing spans and observability follow the same rules.**
  - The `kid` and `alg` fields of `oauth_rs.validate`/`validate_cached` come
    from the **unverified** header, so `check_header` records them through
    `token::for_log_field` (`for_log`'s character cut, then everything outside
    printable ASCII escaped as `\u{..}` — a JSON or OTel subscriber writes a
    field verbatim, not through `Debug`), and only when the span is enabled.
  - A header jsonwebtoken cannot parse (or an HMAC `alg`, which has no
    `Algorithm`) has its raw `kid`/`alg` read by `validator::raw_header_fields`
    — only after the size cap and the three-segment check, only when the span is
    enabled — through the same `for_log_field`; a known `alg` is recorded as
    `Algorithm::as_str`, never jsonwebtoken's `Debug`.
  - The JWKS spans carry `jwks::jwks_host` (the host alone, via
    `try_redact_url`), never a URL.
  - Every `auth.*` log field and metric label is a `&'static str` from
    `observe.rs`'s closed sets (plus the log-safe `auth.static_label` and the
    `issuer_host` label — the configured issuer's host, one value per
    validator), so none can carry a token, claim value, query or body.
    `tests/observability_logs.rs` pins the fields, that no credential reaches
    the output, and a hostile multi-KB `kid`.

### The `jsonwebtoken` pin

`jsonwebtoken` stays on the major `Cargo.toml` pins. None of its types appear in
this crate's public API — `algorithms::Algorithm` is crate-owned, converted
privately (`to_jwt`/`from_jwt`) — so a re-pin is an internal change, not a
breaking release. Keep it that way: never expose a `jsonwebtoken` type. The
rationale (newer majors force a crypto backend that is either unpatched under
`cargo audit` or a new C/cmake build requirement for every consumer) lives in
the comment on the dependency in `Cargo.toml`. Read that comment before
proposing a bump; the tradeoff has to have genuinely changed, and if it has, the
comment is rewritten in the same change. `CONTRIBUTING.md` states the same rule.

### Features

| Feature | Gates | Notes |
|---|---|---|
| `rustls-tls` (default) | reqwest's TLS for JWKS/discovery | Compiled-in Mozilla roots; ignores the OS store and `SSL_CERT_FILE`. |
| `rustls-tls-native-roots` | same | OS store, *added* to the Mozilla roots while `rustls-tls` is also on (one root store); instead of them only with `default-features = false`. |
| `native-tls` | same | Platform library and OS store. With a rustls feature also on, reqwest uses native-tls. |
| `serde` | `Deserialize`/`Serialize` on `OAuthConfig` (+ `InvalidToken: Serialize`) | Via `cfg_attr`, never a bare `#[derive]`. The `serde` *crate* is always a dependency (`claims_as` is bounded by `DeserializeOwned`); the feature only adds derive macros. |
| `env` | `env` module | |
| `tower` | `http_layer` module (+ `http`, `tower-layer`, `tower-service`) | `HttpAuthLayer` and everything both layers share. |
| `axum` | `axum` module (+ `axum`) | Implies `tower`; re-exports the shared types so their `axum::` paths stay valid. |
| `mcp` | `mcp` module (+ `http-body`, `bytes`) | Implies `tower`. An integration helper — no MCP SDK dependency; the crate stays general-purpose. |
| `metrics` | `observability` module (+ `metrics` facade) | Without it `observe::count_request`/`count_refresh`/`set_keys` are empty, so off costs nothing. |
| `testing` | `testing` module (+ tokio `net`/`io-util`) | For **consumers' tests**, enabled only from `[dev-dependencies]`, never in production: the private keys are public knowledge, so anything that trusts them trusts everyone. Also compiled under `cfg(test)` for this crate's own tests. |

- The TLS features are additive, not exclusive; choosing the backend and roots
  for reqwest is their only job. A private-CA authorization server needs one of
  the last two, or `OAuthValidatorBuilder::add_root_certificate_pem` (which works
  under all three).
- Enabling **no** TLS feature is a `compile_error!` in `src/lib.rs`,
  unconditional (no `cfg(test)`/docs exemption): a validator without TLS would
  build and then fail closed on every token.
- `refusal()`/`refusal_for_scopes()` are core: they need no feature and no
  `http` dependency.
- Every feature-gated public item — the gated modules in `src/lib.rs` and any
  `#[cfg(feature)]` public item or impl outside its feature's own module —
  carries `#[cfg_attr(docsrs, doc(cfg(feature = "...")))]` so docs.rs renders
  its badge. Give a new one the same attribute.
- `__fuzz` (`src/__fuzz.rs`, `#[doc(hidden)]`) exists only under
  `cfg(all(fuzzing, feature = "axum", feature = "testing"))`: never public API.

**Why default features matter for local work.** A plain `cargo build`/`cargo
test` uses only `rustls-tls`, so it compiles none of `env`, `http_layer`,
`axum`, `mcp`, `observability`, skips the README doctests (included only with
`serde` + `env` + `axum`), skips the examples (each has `required-features`) and
compiles most integration tests to nothing (they are `#![cfg(feature =
"testing")]`, some also `axum`/`mcp`). Iterate with `--all-features`; run the
default build too because it is what most consumers compile.

## Key conventions

- `#![warn(missing_docs)]` + `#![forbid(unsafe_code)]` in `src/lib.rs`; CI runs
  clippy and rustdoc with `-D warnings`, so every public item needs a doc
  comment, a fallible one needs `# Errors`, and anything with a non-obvious
  security implication gets a `# Security` note.
- `OAuthConfig` is deliberately **not** `#[non_exhaustive]`, so applications can
  build it with functional-record update
  (`OAuthConfig { enabled: true, ..OAuthConfig::default() }`), which keeps
  compiling after a field is added. What a new field breaks is an exhaustive
  struct literal or destructuring pattern — possible only because every field
  is public — so adding a field is still a breaking change (new `0.x` minor),
  just not for the FRU form.
- `ResolvedOAuthConfig`, `Credential`, `TokenRejection`, `StaticTokenDecision`,
  `StaticTokenMatch`, `MissingScopes`, `CredentialSource`,
  `KeyNaming`/`KeyNamingBuf`, `KeySetStatus`, `Refusal`, `AuthorizedToken`,
  `InvalidToken`, `ConfigProblem`/`ProblemKind` and every error enum **are**
  `#[non_exhaustive]`, so a new resolved setting or rejection/refusal variant is
  additive. Match on these with a wildcard arm outside this crate.
- `ConfigError`: `naming` is private (`naming()` reads it); `problems` stays a
  public `Vec<String>` for compatibility (privatizing it would be breaking), and
  the structured, matchable form is `problem_details()` (on `ConfigError` and
  `EnvOAuthConfig`) returning `ConfigProblem`s with a `ProblemKind` and `keys()`.
  Both views are rendered from one list at construction (`ConfigError::assemble`),
  so only an in-place edit of the public field can make them differ, and that
  is documented. A new problem gets a kind (a new `ProblemKind` is additive) and
  its keys; never a bare string.
- Every problem `OAuthConfig::resolve` and the `env` loader can find is
  collected and reported **at once** — never one per run — and every message
  names the offending setting via `KeyNaming`, so a half-usable config fails at
  startup with the key in the message, not as a wall of 401s later.
- No `anyhow` in any public signature; internal code prefers `thiserror` types.
- `config.rs`'s test module pins two generic phrases
  (`config::tests::WIKI_REWRITES`) that mcp-md-wiki's `config::resolve_mcp_oauth`
  rewrites back to its own MCP-flavored wording so its historical message text
  stays byte-identical (mcp-md-wiki#308). It is an early warning, not a
  contract: message text is not a stable API, and what guarantees mcp-md-wiki's
  text is its own test pinning its full output. This crate's own message text
  must stay generic (no "MCP" anywhere). Rewording either phrase is allowed;
  when the pin fails, change `WIKI_REWRITES` deliberately and tell mcp-md-wiki.
- Test fixtures (`src/testing.rs`) come in two layers:
  - The consumer-facing harness (`TestAuthority`, `TokenBuilder`) uses
    **neutral** defaults (`https://api.example.test/` resource, a distinct
    `/audience` audience, `api:read`, `KeyNaming::Dotted("oauth")`) and is what
    docs and new tests should reach for.
  - The lower-level free functions and constants (`ISSUER`, `resolved_config`,
    `valid_token`, …) model a plausible Authentik deployment (per-application
    issuer with a trailing slash, client-id audience, `mcp:read`/`mcp:write`
    scopes) — a realistic production shape, not because the crate is
    MCP-specific. They stay for regression tests and downstream suites.
  - Docs always present the crate as general-purpose; fixture scope names are a
    test-suite detail, never a code default.
- **`testing` follows semver like the rest of the crate**: downstream test
  suites use it, so removing, renaming or changing the behavior of a public item
  there (a constant, a `kid`, a key the served JWKS holds, a builder default) is
  breaking; additions are not. Only panic-message wording is exempt. Its docs
  and the README's "Testing your integration" section say so, and the `semver`
  job covers it (compiled with `--all-features`).
- Tests use generated-for-the-suite throwaway keys only (`KEY_A_PEM`,
  `KEY_B_PEM`, `EC_PEM`, `ED_PEM` in `src/testing.rs`) and example domains
  (`*.example.test`, `*.example.com`) — never a real issuer, client ID, or
  secret.

## Keeping docs in sync

Docs are part of the change, not a follow-up, exactly as much as the code —
more, since this crate's whole value to a consumer is correct documentation of
a security-sensitive surface. A change to a config field, a default, a public
API's behavior, a 401/403 response shape, or anything in the security-invariant
list above updates every place that describes it **in the same commit**:

- `README.md` — the primary consumer doc (feature table, TLS note, quickstarts,
  configuration reference with real defaults, environment variables,
  observability, security model, design rationale, "Using with MCP",
  restart-required note, troubleshooting, testing, MSRV/semver policy).
  `src/lib.rs` includes it verbatim as the crate-level rustdoc whenever `serde`,
  `env` and `axum` are all on (what CI's `--all-features` and docs.rs build),
  so every ` ```rust ` block in it is a doctest in that configuration. Fence
  anything that is not standalone, compiling Rust (a config snippet, a shell
  command, a fragment) as `toml`, `yaml` or `text`. A narrower build gets a
  short pointer doc comment in `src/lib.rs` instead; keep its summary in sync
  with the README's opening paragraph.
- `docs/providers.md` — provider recipes, each with its exact label (see
  Architecture); never upgrade a label without the verification it claims.
- rustdoc — module-level docs on every module, and a doc example on every main
  entry point (constructors, builders and each builder option, the free
  functions, the layers, extractors and route layers). A new public entry point
  gets one.
- `examples/` — runnable and built in CI (`cargo build --examples
  --all-features`), so an example that no longer compiles against a changed
  public API is a CI failure, not a stale doc. A new example declares
  `required-features` in `Cargo.toml`.
- `CHANGELOG.md`'s `[Unreleased]` section — including anything a consumer's
  upgrade needs to know.
- `SECURITY.md`'s "Security invariants this crate maintains" list, if the change
  adds, removes or narrows an invariant above.
- `deny.toml` and `.cargo/audit.toml` — their vulnerability-advisory ignores
  stay identical, each entry with the reason and what would let it go
  (`deny.toml` also gates yanked crates and, for direct dependencies only,
  unmaintained ones, which `cargo audit` does not fail on, so those are not
  mirrored). The licence allowlist in `deny.toml` follows the dependency tree,
  so a new dependency with a new licence is a deliberate edit there.
- `CONTRIBUTING.md` — duplicates the full check matrix, the MSRV command, the
  `jsonwebtoken` pin rule and the provider-label wording; a change to the CI
  matrix or that wording goes there too.
- `.github/pull_request_template.md` and `.github/ISSUE_TEMPLATE/*` — the
  provider-compatibility template asks a reporter for the same
  issuer/`typ`/`alg`/claims shape (secrets redacted) that `docs/providers.md`
  asks a new recipe to document; keep the two asking for the same thing. The PR
  template asks authors to name the invariant from this file a change touches,
  so keep the invariant headings stable.

Check each claim against the code, not against the plan that preceded it. Code
comments explain the code as it is: cite issues as `oauth-resource-server#N` for
issues in this repo, `mcp-md-wiki#308` for the extraction this crate came from,
and never a local plan/review label ("chunk p2", "round one").

## Module layout

What each module owns and the design decisions the code does not make obvious.
For exact items, read the module docs or `grep` — they are not mirrored here.

**`lib.rs`** — module tree, feature gating, the no-TLS `compile_error!`, crate
lints, README inclusion.

- Re-exports the core, always-available API at the crate root. The
  feature-gated modules (`env`, `http_layer`, `axum`, `mcp`, `observability`,
  `testing`) are reached by their own path; nothing in them is re-exported at
  the root. `config` is also a public module.
- No `jsonwebtoken` type is re-exported or appears in a public signature.
- `__fuzz`: a new fuzz target adds a function there and widens the internal it
  reaches to `pub(crate)`, never `pub`.

**`config.rs`** — `OAuthConfig` (the unvalidated input) and `resolve`
(all-or-nothing validation into `ResolvedOAuthConfig`).

- `OAuthConfig`: every field `#[serde(default)]`, `deny_unknown_fields`, not
  `#[non_exhaustive]` (see Key conventions).
- `KeyNaming`/`KeyNamingBuf` (`Dotted`/`Env`) decide how a problem names a
  setting; carried onto `ResolvedOAuthConfig` and `ConfigError` so later logs
  and errors use the operator's spelling.
- Every push site in `resolve` builds a `ConfigProblem` with a kind; a new
  problem needs a `ProblemKind` (or `Other`), its `keys`, and a row in
  `config::tests::one_problem_per_kind`. `from_problems` is the structured
  constructor; do not change `ConfigError::new`'s signature (downstream callers
  build its `Vec<String>` by inference).
- `required_scopes` (list) and `required_scope` (single) are unioned, trimmed,
  deduplicated, order-stable; an explicitly blank entry is always an error. An
  omitted `scopes_supported` resolves to the required scopes.
  `accepted_audiences()` is `audience` ∪ `audiences`.
- With `serde`, `required_claims` deserializes through
  `required_claims_without_duplicates`: a claim named twice is an error, never
  last-wins.

**`algorithms.rs`** — the crate-owned `Algorithm` and the two independent
algorithm gates (configured allowlist via `parse_algorithm`/
`DEFAULT_ALGORITHMS`; per-key via `key_algorithms`/`signing_algorithm`).
`to_jwt`/`from_jwt` are the only bridge to jsonwebtoken.

**`builder.rs`** — `OAuthValidatorBuilder` (`OAuthValidator::new` is
`builder(..).build()`): root certificates, proxy, fetch timeout, seeded JWKS.

- Options are checked in `build` only, after every check `new` makes. The
  builder holds bytes and strings only; `fetch_settings` turns them into
  `jwks::FetchSettings`, which holds the reqwest types.
- `parse_root_pem` refuses a PEM with no certificate or with any `PRIVATE KEY`
  block, and builds a probe client trusting only it, so an unusable certificate
  fails under every backend (rustls parses DER only at client build).
- `check_proxy`: absolute `http`/`https`, host, nothing else. A plain-http
  non-loopback proxy is fine without userinfo (https is `CONNECT`-tunnelled);
  with userinfo it is refused unless `allow_insecure_http`, then warned —
  decided on the parsed URL.
- Its tests hold a throwaway CA and an in-process `tokio-rustls` HTTPS server;
  `min_refetch_interval` is a `cfg(test)` hook.

**`jwks.rs`** — `JwksStore`: discovery, fetch, cache, per-key algorithm
binding, refresh scheduling, and the public `KeySetStatus`/`RefreshError`/
`redact_url`.

- Discovery tries OIDC Discovery then RFC 8414 and requires an exact issuer
  match.
- Entries are parsed one at a time (`parse_jwks_entry` → `cached_key`):
  non-signature, unparseable, or RSA keys `ring` cannot verify
  (`rsa_components_can_verify`) are skipped individually rather than failing
  the set, so `KeySetStatus::keys` counts keys that can verify.
- A discovered `jwks_uri` is reset after a failed fetch so the next refresh
  re-discovers; the public status copy keeps the last (redacted) one.
- Seeded (`initial_jwks`) keys count in `KeySetStatus::keys` without stamping
  `last_attempt`/`last_success`, and count as held for the retry schedule.
- `decoding_key`'s single-no-`kid`-key fallback (`lookup`) never tries more
  than one key per verification; documented on the function.
- `RefreshError`'s `Display` still names endpoints (redacted), so it is
  log-only; `RefreshErrorKind::as_str` labels are stable.

**`validator.rs`** — `OAuthValidator`: header gate, `verify`, challenges, RFC
9728 metadata document, background refresh, readiness, startup warnings.

- `from_builder` re-checks the invariants `resolve` enforced, because
  `ResolvedOAuthConfig`'s fields are public and may be hand-adjusted.
- `validate_cached` is the cache-only path `authenticate()`'s two-pass check
  uses.
- `check_header` also refuses a `kid` present but not a string (`"kid": null`,
  which jsonwebtoken reads as absent).
- Startup warnings (never refusals): unadvertised required scopes, an unscoped
  posture, plain-http non-loopback URLs, non-canonical URLs.
- The `# Runtime` section on `OAuthValidator` is the Tokio requirement. Its
  doc comment documents the RFC 7662 introspection extension point: not built,
  but the API is shaped so it could be added as a feature-gated key source
  without a breaking change.

**`token.rs`** — `AuthorizedToken`, `TokenRejection`, `InvalidToken`/
`InvalidTokenKind`, `MissingScopes`, scope/principal extraction, the RFC 9068
`typ` gate (`check_typ`), and the log-length bounds (`MAX_TOKEN_BYTES`,
`for_log`).

- `AuthorizedToken` is filled once by `from_verified_claims` from the map
  `verify`'s single `decode` produced; `new` + `with_*` exist for tests.
  `claim_matches` is the equality-or-array-membership rule shared by
  `has_claim_value` and the validator's `required_claims` (a parity test pins
  it).
- `TokenRejection` is the 401-vs-403 split RFC 6750 requires.
- `InvalidToken` keeps the older `Invalid(String)` call sites compiling
  (`From<String>`, `Deref<Target = str>`, `PartialEq` with string types).
  Equality, between two `InvalidToken`s too, is **detail-only**; in-crate tests
  that mean the kind use `token::assert_invalid`, and a `Hash` impl, if ever
  added, must hash the detail only. Pinned by
  `invalid_token_keeps_the_string_uses_compiling` and a `compile_fail` doctest.
- Every refusal goes through `TokenRejection::invalid(kind, detail)`; see the
  "add an error variant or refusal kind" recipe.

**`challenge.rs`** — RFC 9728 metadata document and URL (the well-known segment
goes between authority and path, path kept verbatim, trailing slash included,
§3.1) and the RFC 6750 challenge builders, which omit `scope` entirely rather
than send it empty. `quoted` escapes config-derived values for a quoted-string —
a defence against typos, not attackers.

**`authenticate.rs`** — `Credential`, `StaticTokens`, `StaticTokenMatch`,
`authenticate()`/`authenticate_with_static_tokens()`.

- Every candidate header value is checked independently — a bad credential in
  one source never masks a good one in another.
- Order: constant-time static comparison first (no network), then OAuth in two
  passes (cache-only, then one that may fetch keys), so one candidate's unknown
  `kid` never queues the request behind a refetch when another's key is cached.
- Precedence on refusal: any acceptance wins; else `InsufficientScope` if any
  candidate was valid-but-unscoped; else `Missing` with no non-blank candidate;
  else `Invalid` with the first candidate's reason.

**`refusal.rs`** — core, no feature, no `http`: `refusal()` and friends →
`Refusal`, and the crate-private generic `select`, the one place a status or
challenge is chosen (generic so the layers can pass pre-validated
`HeaderValue`s with no per-request fallible conversion).

**`observe.rs`** — crate-private, always compiled: the stable observability
vocabulary (`Stage`, `Outcome`, `Mechanism`, reasons, status) and the metric
recording helpers, which compile to nothing without `metrics`. The layers'
outcome events are macros in `http_layer.rs` so each keeps its calling layer's
module log target.

**`observability.rs`** — the `metrics` feature's public module: metric-name
constants and `describe_metrics()`. The `oauth_rs_` prefix is fixed, not
configurable: dashboards key on stable names, and an exporter can rename.

**`http_layer.rs`** — the `tower` feature: `HttpAuthLayer`/
`HttpAuthLayerBuilder`/`HttpAuthService`, the types both layers share
(`CredentialSource`, `RejectContext`, `AuthLayerError`), the crate-private
`Gate`, route-level scope checking (`judge_scopes`, `scope_refusal`,
`RequireScopes`), and the markers.

- The module is `http_layer`, never `tower`: a crate-root `tower` module makes
  `tower` ambiguous for a downstream `use oauth_resource_server::*;` next to the
  `tower` crate (`tests/glob_import.rs` pins it). The types are named `Http…` so
  they cannot be mistaken for the axum ones.
- `RefusalResponse` is sealed: only `on_reject` can install one. The boxed
  future is `Send` without `ResBody: Send`.
- `Gate` logs nothing; each layer logs its own `Admission`, so log targets stay
  `oauth_resource_server::axum` / `oauth_resource_server::http_layer`.
- No `LayerRan` marker here (see the extractor invariant).

**`policy.rs`** — `static_token_policy`: pure decision logic (no logging) for
which static token an `AuthLayer` holds alongside OAuth (`StaticTokenDecision`).
Single-token by design: an application with a `StaticTokens` set passes its
current key to the policy and the set to the builder's `static_tokens`, and
`build_with_decision` combines them.

**`axum.rs`** — the `axum` feature: `AuthLayer`/`AuthLayerBuilder` (a
`tower::Layer` and the state for `require_auth`, identical behavior, both via
`AuthLayer::check`), the extractors (`AuthorizedToken`, `Credential`,
`StaticTokenMatch`, `Scoped<S>`), and `metadata_router`.

- `on_reject` shapes only body/extra headers; status and `WWW-Authenticate` are
  fixed after it runs.
- `metadata_router` matches the path-suffixed well-known URL by literal string
  comparison, not an axum route pattern: a resource URL may contain `:`/`*`/`{}`
  that axum would read as routing syntax.
- Logs every outcome itself (module docs list the levels), so an application
  needs no auth-specific logging.

**`mcp.rs`** — the `mcp` feature: `McpToolScopes`/`McpToolScopesService`, the
one module that knows JSON-RPC (see its invariant above). Builder methods panic
on bad literals; the `try_` forms return `McpScopesError`. `claims_for_tool`
returns plain tuples so `ClaimClause` stays crate-private.
`classify`/`Classified` (`cfg(any(test, fuzzing))`) serve tests and the fuzz
target; `service_tests` (`cfg(all(test, feature = "axum"))`) drives it behind
both layers.

**`env.rs`** — the `env` feature: load secrets, config values, static-token
sets and a whole `OAuthConfig` from environment variables.

- Every value has a `VAR` / `VAR_FILE` pair (the Docker/Compose
  `secrets:`-mount shape); both set is an error, never a silent preference.
  - **Secret semantics** (`secret_from_env`, every `oauth_config_from_env`
    field): a blank `VAR` reads as unset; a `_FILE` that reads empty is an
    error.
  - **Config-value semantics** (`config_value_from_env`): a set `VAR` is
    returned exactly as set (empty, untrimmed), so it can replace a plain
    `std::env::var` read; a blank `VAR` beside a `VAR_FILE` yields to the file,
    a non-blank one is `BothSet`.
- Every real `_FILE` read is the one public bounded reader `read_secret_file`:
  regular file only (checked on the path before opening — opening a FIFO blocks
  — and again on the open file), at most `MAX_SECRET_FILE_BYTES`, into a
  `Zeroizing` buffer. Its refusals travel inside the `io::Error` as the typed
  `FileRefused` (so the reader signature stays `Fn(&str) -> io::Result<String>`
  and a direct caller can `downcast_ref` it) and become `EnvError::NotAFile`/
  `FileTooLarge`; an injected reader's result is held to the same cap.
- Every `_from_env` function has a `_from_lookup` twin taking an injected
  variable lookup and file reader. Tests use the twins and never call
  `std::env::set_var` (`unsafe` in edition 2024); an application with its own
  lookup passes `read_secret_file` instead of copying the checks.
- `static_tokens_from_env` reads `VAR` and `VAR_NEXT` into a labelled set
  (rotation); equal values fold into one entry; `VAR_NEXT` alone is an error;
  both failing reports both. Deliberately no whitespace-list form (it could
  carry no labels).
- `oauth_config_from_env(prefix)` reads one `<PREFIX><FIELD_UPPER>` variable per
  `OAuthConfig` field (lists whitespace-split, bools strictly `true`/`false`,
  `REQUIRED_CLAIMS` one JSON object). `<PREFIX>ENABLED` unset infers on/off from
  whether any identifying variable is set. A whitespace-only `REQUIRED_SCOPE` is
  kept blank so `resolve` reports it, as for a config file.
- `unresolved_oauth_config_from_env` → `EnvOAuthConfig` is the hook for an
  application's own defaults between loading and `resolve`. Its public
  `problems` are authoritative at `resolve` (an app may edit them) and are
  re-paired with their structured forms (`reconcile`), else `Other`; its
  `PartialEq` and `ConfigError`'s ignore the structured details.

**`testing.rs`** — test-only fixtures (see Key conventions for the two layers).

- `TestAuthority` runs an in-process loopback authority (OIDC + RFC 8414
  discovery + `/jwks`, issuer = its base URL) with fetch counters, response
  delay, key rotation/withdrawal. It exposes no accessor to the inner
  `FakeJwksServer`, so that layout is not frozen.
- Every served JWKS has one labelled JWK per RSA algorithm (frozen `kid`s,
  never alg-less, so no validator logs the ambiguous-key warning — a test pins
  that) plus EC and Ed25519 keys, under `MAX_JWKS_KEYS`, so every
  `TokenBuilder::alg` validates.
- `config(adjust)` panics with the `ConfigError` text; loopback http needs no
  `allow_insecure_http`.
- Never add new key material without generating it for this suite (see the
  leak policy).

## Recipes for common changes

### Add a public API item

1. Doc comment with an example (it is a doctest), `# Errors` if fallible,
   `# Security` if non-obvious. Feature-gated → `doc(cfg)` attribute.
2. Decide its place: root re-export only for core items; feature items stay in
   their module. Never expose a `jsonwebtoken` or `reqwest` type.
3. New public struct/enum: `#[non_exhaustive]` unless there is a reason (as for
   `OAuthConfig`); hand-write `Debug` if it can hold a secret, URL or claim
   value.
4. README section and `CHANGELOG.md` `[Unreleased]` entry; an example if it is a
   new integration surface.
5. Semver: additive, so it ships in a new `0.x` minor by convention (see
   Semver). If it exposes a third-party type, that dependency joins the
   public-API dependency list below.

### Add an `OAuthConfig` field

- Breaking (new `0.x` minor): see Key conventions.
- `#[serde(default)]`; a default that keeps existing behavior (a security
  check defaults off only if it is an opt-in tightening; an opt-out of a
  safety check defaults to safe).
- Validate in `resolve` and collect a `ConfigProblem` (kind + keys + a row in
  `one_problem_per_kind`), never return early.
- Carry it onto `ResolvedOAuthConfig` (additive there). The hand-written
  `Debug` impls destructure every field, so the compiler makes you add it —
  redact if it can hold a URL.
- `env.rs`'s loader builds with `..OAuthConfig::default()`, so the compiler
  will **not** remind you: add the `<PREFIX><FIELD>` read and its tests by hand.
- `from_builder` re-check if the field carries an invariant.
- README configuration reference (with the real default) and environment
  variables table.

### Add an env-loading function

- Write the `_from_lookup` form first (lookup `Fn(&str) -> Option<String>`,
  reader `Fn(&str) -> io::Result<String>`); the `_from_env` form is a one-line
  wrapper passing `std::env::var` and `read_secret_file`.
- Test only through the `_lookup` form with a map and an in-memory reader.
- Errors name variables and file paths, never values; every new `EnvError`
  variant is `#[non_exhaustive]`; config-loading problems carry
  `ProblemKind::EnvLoad`/`EnvParse` keyed by the variable.

### Add an error variant or refusal kind

- The enum is `#[non_exhaustive]`, so a new variant is additive.
- A new refusal site calls `TokenRejection::invalid(kind, detail)` with a
  specific `InvalidTokenKind`, and gets a row in
  `validator::tests::every_validator_refusal_names_its_kind` (or the equivalent
  test for its path) producing it through the real code.
- `as_str` labels are stable API; never move an existing refusal to a different
  kind (giving an `Other` refusal a specific kind is fine).
- `detail` is log-only text: say what failed, never echo a secret.

### Add a metric, log field or span

- Names and values are API (see Semver). Add the value to `observe.rs`'s closed
  sets as a `&'static str`; never a token-, claim- or URL-derived string
  (hosts via `jwks_host`, unverified header fields via `for_log_field`).
- A new outcome event carries all four `auth.*` fields and a `count_request`.
- Update `tests/observability_logs.rs`/`tests/observability_metrics.rs` (shared
  setup in `tests/support/`) and the README "Observability" section.
- Anything only read under `metrics` needs the matching `cfg`, or the
  narrower clippy runs fail on dead code.

### Add a dependency

- Check its licence against `deny.toml`'s allowlist (`cargo deny check`); a new
  licence is a deliberate edit there.
- Its MSRV must not exceed `rust-version` (the `msrv` job builds with
  `--locked`).
- Choose a lower bound that really builds: `minimal-versions` resolves it to
  its floor. If you raise a floor, say in the comment above `[dependencies]`
  whether it is a compile floor or only what the resolver needs.
- Prefer crates already in the tree (several existing ones are justified that
  way in `Cargo.toml`); gate it behind the feature that needs it
  (`optional = true`, `dep:`).
- If any of its types reach a public signature, its major bumps become breaking
  for this crate; list it under Semver.

### Add a fuzz target

Add `fuzz/fuzz_targets/<name>.rs`, its `[[bin]]` in `fuzz/Cargo.toml`, an entry
point in `src/__fuzz.rs` (widening the internal to `pub(crate)`), and the
matrix entry in `.github/workflows/fuzz.yml`.

## Testing conventions

- **Unit tests** live in a `#[cfg(test)] mod tests` at the bottom of each
  `src/` file (some modules have extra child test modules, e.g.
  `axum::scope_tests`, `mcp::service_tests`). They can reach crate-private
  items and use `testing` (compiled under `cfg(test)`).
- **Integration tests** (`tests/`) use only the public API. A test that needs
  process-global state — a global tracing subscriber, real environment
  variables — gets its own test binary with a single test function, because
  parallel tests in one process race on it (see the module docs of
  `tests/redacted_logs.rs` and `tests/env_proxy_loopback.rs`; the latter is the
  one place real env vars are set, because it tests reqwest's own env-proxy
  handling).
- **No real network, no real environment.** Authorization servers are
  `TestAuthority`/`spawn_jwks_server`/`spawn_http_server` on loopback; env
  loading goes through `_lookup` twins with injected maps and readers; time
  bounds use tokio's `test-util` where needed.
- **Assert kinds, not text**: refusals with `token::assert_invalid` (kind), config
  problems by `ProblemKind` — except where a test deliberately pins wording.
- **Secret-leak tests** assert a known secret string never appears in captured
  logs or `Debug` output; extend them when adding a field that could carry one.
- **Parity tests** pin that two paths answer identically (both layers,
  `refusal_for_scopes` vs the layers, `has_claim_value` vs `claim_matches`).
  When you add a path, add it to the parity test rather than a new one.

## Gotchas

- README ` ```rust ` blocks are doctests (only with `serde`+`env`+`axum`), so a
  plain `cargo test` will not catch a broken one — `cargo test --all-features`
  will.
- Doc comments must pass `RUSTDOCFLAGS="-D warnings"`: a broken intra-doc link
  or a link to an item missing in some feature set fails. Doc examples in the
  `tower`/`mcp` docs must not reach for `oauth_resource_server::axum` (CI
  doctests them with `rustls-tls,mcp` only).
- `--all-features` hides problems: a `cfg` that only appears with `rustls-tls`
  off, or an item only `axum` or `metrics` reads (dead code in a `tower`-only
  build). That is why CI runs the narrow clippy builds; gate crate-private
  helpers with the exact feature set that uses them.
- MSRV (`rust-version` in `Cargo.toml`) and `rust-toolchain.toml`'s `channel`
  move in lockstep; rustup picks the pinned toolchain automatically in this
  tree, so `cargo +<ver>` is needed only for a different one.
- The `semver` job's toolchain and its pinned `cargo-semver-checks` version move
  together (the tool needs a recent rustc for the rustdoc JSON format; a
  floating `stable` would break every PR when the format changes). Both live in
  `ci.yml` and `release.yml`.
- `cargo publish --dry-run` refuses a dirty tree; pass `--allow-dirty` locally.
- The minimal-versions recipe rewrites `Cargo.toml`/`Cargo.lock`: run it in a
  throwaway copy.
- A PR touching only `CLAUDE.md`/`.claude/`/`.claude-plugin/` skips every heavy
  CI job (`ci.yml`'s `changes` job) — nothing compiles, so do not rely on CI to
  validate code snippets edited here.

## Security review checklist

Apply to any change touching `src/validator.rs`, `src/jwks.rs`,
`src/builder.rs`, `src/algorithms.rs`, `src/token.rs`, `src/config.rs`,
`src/authenticate.rs`, `src/refusal.rs`, `src/http_layer.rs`, `src/axum.rs`,
`src/mcp.rs` or `src/env.rs` (the list `CONTRIBUTING.md` gives):

- [ ] No invariant above is weakened; the PR names the ones it touches.
- [ ] Nothing new is read from the unverified header beyond what
      `check_header` already gates, and no key fetch happens before it.
- [ ] Every new failure path fails closed and returns a `TokenRejection` with a
      specific kind; no new path can return a token or pass a request through.
- [ ] No input is narrowed outside a security fix, no default changed that
      alters accepted/rejected tokens.
- [ ] Status and challenge still come from `refusal::select`; both layers and
      `refusal()` still agree (parity tests updated).
- [ ] No secret, claim value, query, body or unredacted URL reaches a log line,
      span field, metric label, `Debug`, `Display` or error message.
- [ ] Secret comparisons stay in `find_static`, branch-free.
- [ ] No lock is held across `.await`/network; no request can cancel or
      trigger more than one refetch per cooldown.
- [ ] Every new size, count or time input is bounded.
- [ ] URL decisions use the parsed URL; new runtime-reached URLs get the
      plain-http and loopback checks.
- [ ] Docs in sync (see above), including `SECURITY.md`.

## Semver and MSRV policy

- The crate is pre-1.0; a `0.x → 0.(x+1)` bump is where a breaking change ships
  (Cargo treats any `0.x` minor bump as incompatible). A patch release is
  behavior-preserving only, **with one exception**: a fix for a vulnerability —
  a forged, expired, wrongly-audienced, or otherwise out-of-policy token that
  should never have been accepted — ships as a patch release even though it
  narrows accepted input, with a `CHANGELOG.md` entry and a `SECURITY.md`
  advisory. Security correctness outranks the narrowing-is-breaking rule:
  holding the fix for a minor release would leave every consumer on the common
  caret range unprotected until they widen their requirement by hand.
- **Breaking**:
  - removing or renaming a public item;
  - adding a field to `OAuthConfig` (not `#[non_exhaustive]`, by design) or to
    any other struct that is not `#[non_exhaustive]`;
  - adding a variant to an enum that is not `#[non_exhaustive]`;
  - narrowing an accepted input or widening a returned error type;
  - changing a default that changes accepted/rejected tokens (a default
    algorithm, claim name, or scope-claims list) — unless it is the
    security-fix exception;
  - raising MSRV;
  - **a major-version bump of a dependency whose types appear in this crate's
    public API**, since that breaks a consumer who names the same type from
    their own direct dependency. These are:
    - `serde`/`serde_json`, always (`AuthorizedToken::claims_as` is bounded by
      `serde::de::DeserializeOwned` and returns `serde_json::Error`, `claims()`
      returns `serde_json::Map<String, Value>`, `metadata()` returns
      `&serde_json::Value`);
    - the `tower` feature's `http`, `tower-layer`, `tower-service` (both layers
      implement `tower_layer::Layer`, their services `tower_service::Service`
      over `http::Request`; `CredentialSource` holds an `http::HeaderName`,
      `static_challenge` takes an `http::HeaderValue`, `on_reject` returns an
      `http::Response`);
    - the `axum` feature's `axum` (`metadata_router` returns `axum::Router<S>`,
      `require_auth` takes axum's `State`/`Request`/`Next`);
    - the `mcp` feature's `http-body` and `bytes` (`McpToolScopesService` is a
      `Service` over a body bounded by `http_body::Body + From<bytes::Bytes>`).

    `jsonwebtoken`, `reqwest`, `metrics` and the other dependencies never appear
    in a public signature. `cargo-semver-checks` cannot see these dependency
    bumps; `SECURITY.md` points here for this list — keep it current when a new
    third-party type reaches the public API.
- The `testing` feature's public items are covered by the same rules (see Key
  conventions): they are API, not an exempt zone.
- **Non-breaking** (ships in a `0.x` minor): adding a field to a
  `#[non_exhaustive]` struct or a variant to a `#[non_exhaustive]` enum; adding
  a public item; adding a feature; loosening a validation rule so it only
  accepts more previously-rejected input (never the reverse). Cargo itself
  would allow additive changes in a patch; shipping them in a new `0.x` minor
  is this crate's convention, so a `CHANGELOG.md` reader can tell at a glance
  which releases were bugfix-only.
- `ConfigError::problems`' message text (and any `Display` built from it) is
  **not** part of the semver contract — wording may change in any release. The
  `WIKI_REWRITES` test is an early warning, not an exception. The durable
  alternative is `problem_details()`: match `ConfigProblem::kind()`
  (`ProblemKind`, `as_str()` labels stable) and `keys()`. The kind a given
  problem carries is part of the contract; its wording is not.
- **Observability names are API**: the `auth.*` log fields (`auth.outcome`,
  `auth.mechanism`, `auth.reason`, `auth.status`, `auth.static_label`), the span
  names (`oauth_rs.validate`, `oauth_rs.validate_cached`,
  `oauth_rs.jwks_refresh`, `oauth_rs.jwks_discovery`) and their fields, the
  metric names and labels (`oauth_rs_requests_total{stage,outcome,mechanism,reason}`,
  `oauth_rs_jwks_refresh_total{issuer_host,result}`,
  `oauth_rs_jwks_keys{issuer_host}`), and every value the README's
  "Observability" section lists. Renaming one, or moving an outcome to another
  value, is breaking; adding a value is not. Event message text and level stay
  unstable.
- The same rule for a refused token: `InvalidToken::detail()` (and `Display`)
  wording may change in any release; the `InvalidTokenKind` a given refusal
  carries, and every `as_str()` label, may not — consumers put them in metrics
  and alerts. Moving a refusal from one specific kind to another is breaking;
  giving an `Other` refusal a specific kind is not, nor is a new kind for a new
  check.
- **The `semver` job is necessary, not sufficient.**
  - `cargo-semver-checks` does not flag a tuple variant's payload type changing
    (e.g. `Invalid(String)` → `Invalid(SomeType)`), so a green job never proves
    that kind of change compatible — review it by hand.
  - It compares against the newest crates.io release. Once a version bump has
    merged and until that version is published, the job sees a new minor and
    reports no break at all: diff any further `pub` change in that window by
    hand against the last published release, and keep breaking changes out of
    a release whose CHANGELOG promises an additive one.
- **MSRV** is `Cargo.toml`'s `rust-version` (which makes a too-old toolchain
  fail fast with a clear message), kept in lockstep with
  `rust-toolchain.toml`'s `channel`. Raising it is breaking under this policy:
  bump the minor, say so in `CHANGELOG.md`, update both files together. The
  crate is edition 2024 and uses let-chains.

## Workflow

**pr-manual-release** (CI-gated PRs; an ordinary merge ships nothing, and a
merged version bump is the release — bump-is-release) on GitHub, `master` as the
default branch. These repository settings live on GitHub, not in this tree;
treat them as always-in-effect policy:

- `master` takes no direct pushes; a repository **ruleset** requires only the
  `ci-pass` status check (never individual jobs), does **not** require branches
  to be up to date, allows squash merges only, and auto-deletes merged branches.
- Workflow runs for a fork PR need a maintainer's approval for every external
  contributor, because the heavy jobs run on a self-hosted runner. That gate
  covers forks only: Dependabot's PRs come from branches of this repository, so
  they run there without approval and a dependency bump executes new upstream
  build scripts, proc macros and tests on it. That is accepted even though the
  runner mounts the host docker socket: nothing secret lives on that runner (CI
  jobs hold only a read-only token), and neither the job that can mint a
  crates.io token nor `release-on-bump` (which holds a `contents: write` App
  token) ever runs there.
- A GitHub App (`stonefish-ci`, bot login `st0nefish-ci[bot]`): Client ID in the
  `APP_CLIENT_ID` repo variable, private key in the `APP_PRIVATE_KEY` repo
  secret; used by `auto-merge.yml` and `release-on-bump`. It deliberately lacks
  the `workflows` permission: a PR changing a file under `.github/workflows/`
  still auto-merges when its branch contains master's current version of those
  files; when master changed one since the branch was cut, auto-merge fails and
  the PR is refreshed from `master` or merged by hand once `ci-pass` is green.
- A GitHub environment `release`, whose deployment policy admits only `v*`
  tags; `release.yml`'s `publish` runs in it and crates.io trusted publishing
  is bound to it.
- A tag ruleset on `refs/tags/v*`: only repository admins (the owner) and the
  App (a bypass actor) may create, move or delete a release tag. `GITHUB_TOKEN`
  cannot, so the only workflow that may ever create a tag is `release-on-bump`,
  with the App token, through `gh release create`.
- Every action in `.github/workflows/` is pinned to a full commit SHA with its
  release in a trailing comment (`dtolnay/rust-toolchain`, which has no
  releases, to a commit of its `master` branch). Keep it that way.

The flow and the constraints the workflow files cannot express on their own
(read the header comments of `ci.yml`, `release.yml`, `fuzz.yml` and
`auto-merge.yml` before editing them):

- Work on a branch, open a PR against `master`. `ci.yml` runs the heavy jobs
  `checks`, `msrv`, `semver`, `feature-powerset` and `minimal-versions` on the
  self-hosted runner and fans them into `ci-pass` (GitHub-hosted). A cheap
  `changes` job skips all heavy jobs when only Claude Code config changed.
- **Adding a CI job**: add it to `ci-pass`'s `needs:` **and** its explicit
  result check (and to the skip condition), and to `release-on-bump`'s `needs:`.
  `ci-pass` uses `if: always()` plus that explicit check because a skipped
  required check counts as passing — see the comment at the top of `ci.yml`.
- **Keep `release.yml` in step**: its `verify`, `msrv` and `semver` jobs repeat
  `ci.yml`'s `checks`, `msrv` and `semver` step for step. `feature-powerset` and
  `minimal-versions` are deliberately not repeated at release (they ran on
  master's post-merge CI); `semver` is, because it depends on crates.io and on
  the release's version bump.
- `semver` compares against the newest crates.io release, so while
  `Cargo.toml`'s `version` equals it, any breaking change fails CI. A deliberate
  breaking change carries its `version` bump in the same PR; that bump is what
  tells the check it is intended.
- `minimal-versions` is why some dependency requirements in `Cargo.toml` are not
  bare majors; the comment above `[dependencies]` says which are compile floors
  and which only let the resolver work. A new dependency or bound that
  regresses fails this job.
- `fuzz.yml` runs each target for a bounded time after a merge to `master`
  touching `src/`, `fuzz/` or the manifests, and on demand — never on a PR or a
  schedule, never self-hosted. `fuzz/` is its own package (empty `[workspace]`,
  `publish = false`) outside `Cargo.toml`'s `include` list; `Cargo.toml`'s
  `[lints.rust] unexpected_cfgs` declares the `fuzzing` cfg so clippy stays
  clean.
- `auto-merge.yml` arms squash auto-merge on every PR opened by `St0nefish`, so
  the owner's PRs land as soon as `ci-pass` is green — that is the intended
  flow. It must use the App token: a merge made with `GITHUB_TOKEN` starts no
  workflow runs, so the post-merge CI (and the release) would never fire. Other
  contributors' PRs are merged by hand after review; a fork PR never receives
  the App credentials.
- `ci.yml` also runs on every push to `master` — the post-merge re-check that
  catches two PRs each green against an older `master`; there is deliberately
  no separate `post-merge.yml`. Its concurrency group is per commit and never
  cancelled: a shared group lets GitHub replace a pending run, and a bump commit
  whose run vanished would never be released. That push run's
  `release-on-bump` job (push only, after all heavy jobs, not in `ci-pass`,
  GitHub-hosted) is where a release starts.
- Don't rebase an open PR just because `master` moved; refresh a branch only to
  resolve a real conflict.

## Release process

- **A merged version bump is the release; any other merge publishes nothing.**
  `ci.yml`'s `release-on-bump` runs `.github/scripts/release-on-bump.sh`, which
  creates release `vX.Y.Z` at the bump commit with the App token only when the
  commit changed the `[package] version`, the version is stable (pre-releases
  stay owner-published by hand), no such tag exists and it would be the highest
  stable `v*` tag. It **fails**, creating nothing, on a non-semver version, a
  missing token, or a bump whose `CHANGELOG.md` has no non-empty `## [X.Y.Z]`
  section — never create a release `check` will refuse. The script header lists
  every rule; `DRY_RUN=1` runs the checks and prints the command. The job's
  `if:` pins `github.repository`, so a fork's push runs never try to release.
- `release.yml` triggers on `release: published` and nothing else. A release
  created with an App installation token starts workflow runs; one created with
  `GITHUB_TOKEN` starts none.
- **The tradeoff, accepted deliberately:** release authority is "can get a
  version bump merged to `master`" — the owner, plus anything that can act as
  the App — not "is the owner". What the App can release is constrained by
  `check`, not by who it is. `check` (GitHub-hosted, read-only) fails closed
  unless the sender is in `RELEASE_SENDERS`, the release is not a draft, a
  pre-release comes from the owner only, the tag is `v<Cargo.toml version>` at
  that commit, the commit is on `master` (a mistake check, not a security
  boundary: the run uses the workflow file at the tagged commit), a stable tag
  is the highest stable `v*` tag (`.github/scripts/require-highest-tag.sh`, so a
  backport release of an older minor line is refused), crates.io does not have
  the version, and `CHANGELOG.md` has the section. The workflow file is the
  source of truth for each check.
- **Job placement is a security property**:
  - `verify`, `msrv`, `semver` run on the self-hosted runner with read-only
    permissions and no OIDC.
  - `publish` is GitHub-hosted, in the `release` environment, the only job with
    `id-token: write`; it runs nothing but checkout, toolchain, the
    highest-tag re-check (plain git/coreutils, placed before authentication so
    a refusal never mints a token), `rust-lang/crates-io-auth-action` (a
    short-lived OIDC-exchanged token; no long-lived crates.io token is ever
    stored) and `cargo publish`, with no restored cache.
  - Keep build scripts, proc macros, dev-dependencies and build tooling out of
    the job that can mint the token, and keep that job — and `release-on-bump`
    — off the self-hosted runner, which mounts its host's Docker socket and runs
    unreviewed Dependabot code.
  - `release-notes` (`contents: write` with `GITHUB_TOKEN`) replaces the notes
    with the CHANGELOG section. No job in `release.yml` creates or moves a tag.
- `release.yml` must keep its filename, and `publish` must keep
  `environment: release`: crates.io trusted publishing is registered for this
  repository + `release.yml` + environment `release`. That environment's policy
  (only `v*` tags), the tag ruleset (only admins and the App create `v*` tags)
  and the sender check together limit minting a publish token to a release
  created by the owner or the App.
- **To cut a release**: open a PR that bumps `version` in `Cargo.toml` and
  `Cargo.lock` (`cargo release version minor --execute --no-confirm`, or
  `patch`/`major`/`X.Y.Z`, or a hand edit of both) — unless a breaking PR
  already bumped it — and moves `CHANGELOG.md`'s `[Unreleased]` entries under
  `## [X.Y.Z] - <date>` (plus the link references at the bottom). Merge it.
  That is the whole release.
- **Manual fallback** (a pre-release, or a bump whose `release-on-bump` could
  not create the release — re-run that job first if the failure was transient),
  as the owner, under exactly the same `check`:
  `gh release create vX.Y.Z --target <full sha of the bump commit> --title vX.Y.Z --generate-notes`
  (add `--prerelease` for `X.Y.Z-pre`). Target the bump commit's full SHA, not
  `master`: anything merged after the bump would ride along without a
  CHANGELOG entry.
- A bump with no CHANGELOG section fails `release-on-bump` and creates nothing.
  Merge a fix adding the section (its version is unchanged, so nothing is
  released for it), then release that fix commit with the manual fallback.
- A transient failure (crates.io outage, runner hiccup) is re-run with "re-run
  failed jobs": `publish` skips the upload and succeeds if an earlier attempt
  already made it, and `release-notes` writes the same notes again. Runs are
  grouped per release tag and never cancelled.
- A genuine `verify`/`msrv`/`semver` failure cannot be fixed by a re-run. Merge
  the fix, then as the owner delete the release and its tag
  (`gh release delete vX.Y.Z --cleanup-tag`) and create the release by hand at
  the fix commit, or merge a fresh bump. Nothing was uploaded: `publish` needs
  all of them.
- There is no deploy-hold switch: nothing publishes until a version bump
  merges, so batching changes is only a matter of when to merge the bump.
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

The `checks` job, which you should run in full before opening a PR (same list
as `CONTRIBUTING.md`; the authoritative copy is `ci.yml`):

```bash
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
cargo audit                    # needs cargo-audit; reads .cargo/audit.toml
cargo deny check               # needs cargo-deny; reads deny.toml
cargo package --list
cargo publish --dry-run        # add --allow-dirty for an uncommitted tree
```

The other CI jobs — slower or needing extra tools; CI runs them regardless:

```bash
# msrv: the toolchain named by rust-version in Cargo.toml (equal to the pinned
# channel while the two are in lockstep, so a plain build already covers it)
cargo +<rust-version> build --all-features --locked

# semver: needs cargo-semver-checks and the toolchain ci.yml's `semver` job pins
# (both versions are in ci.yml); compares against the latest crates.io release
cargo +<semver toolchain> semver-checks check-release --all-features

# feature-powerset: needs cargo-hack; ~160 `cargo check` builds, several minutes
cargo hack check --feature-powerset --no-dev-deps \
  --mutually-exclusive-features rustls-tls,native-tls,rustls-tls-native-roots \
  --at-least-one-of rustls-tls,native-tls,rustls-tls-native-roots \
  --group-features metrics,testing

# minimal-versions: needs cargo-hack and nightly. Rewrites Cargo.toml and
# Cargo.lock, so run it in a throwaway copy of the tree. `time` is lifted
# because a transitive floor no longer compiles (see the step in ci.yml).
cargo hack --remove-dev-deps
cargo +nightly update -Z direct-minimal-versions
cargo update -p time
cargo build --all-features
```

- The powerset makes the TLS backends mutually exclusive and toggles `metrics`
  together with `testing` (no `cfg` of either touches the other). A new feature
  with its own `cfg` interplay gets its own axis, not a group.
- `native-tls` builds need `pkg-config` and OpenSSL headers (`libssl-dev`).

Iterating:

| Goal | Command |
|---|---|
| Plain library build | `cargo build` |
| Everything compiles, every feature | `cargo check --all-targets --all-features` |
| One module's unit tests | `cargo test --all-features --lib config::tests` |
| One test by name | `cargo test --all-features -- <name_substring>` |
| One integration test binary | `cargo test --all-features --test redacted_logs` |
| Doctests only (README included) | `cargo test --all-features --doc` |
| Run an example | `cargo run --all-features --example axum_basic` |
| Docs as docs.rs renders them | `RUSTDOCFLAGS="--cfg docsrs" cargo +nightly doc --no-deps --all-features --open` |

Fuzzing (not in the PR matrix): `cargo install --locked cargo-fuzz`, then
`cargo +nightly fuzz run <target> -- -max_total_time=30`; targets are the files
in `fuzz/fuzz_targets/`, and `cargo +nightly fuzz build` builds them all. A CI
crash uploads its input as an artifact; reproduce with
`cargo +nightly fuzz run <target> fuzz/artifacts/<target>/<crash-file>`.

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
