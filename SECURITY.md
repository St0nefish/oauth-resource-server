# Security Policy

`oauth-resource-server` validates bearer tokens that gate access to real HTTP
APIs. A bug here can mean an attacker gets past authentication or scope
checks entirely, so please report vulnerabilities privately rather than
through a public issue.

## Supported versions

This crate is pre-1.0. Security fixes are made against the **latest published
`0.x` release** only; there is no separate maintenance branch for older minor
versions. Once a fix lands, upgrading to the latest `0.x` is the supported
remediation.

| Version        | Supported          |
| -------------- | ------------------- |
| latest `0.x`   | :white_check_mark:  |
| older `0.x`    | :x:                  |

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting instead of opening a
public issue or pull request:

1. Go to this repository's **Security** tab.
2. Click **Report a vulnerability** to open a private advisory draft.
3. Describe the issue: affected version(s), the security property that
   breaks (e.g. "a rejected token is accepted", "the wrong `WWW-Authenticate`
   challenge is sent", "a key from the wrong provider is trusted"), and, if
   possible, a minimal reproduction using this crate's `testing` feature
   fixtures rather than a real deployment's tokens or keys.

Do not include real issuer URLs, client IDs/secrets, or production tokens in
a report — use the crate's test fixtures or a placeholder like
`https://idp.example.test/`.

You should get an initial response within a few days. If the report is
confirmed, a fix is prepared in the private advisory, a new `0.x` version is
published, and the advisory is disclosed once the fix is out, with credit to
the reporter unless anonymity is requested.

## Security invariants this crate maintains

These are the properties covered by the crate's own test suite and CI, and
the ones a report is most likely to concern:

- the JWT algorithm allowlist is checked from the *unverified* token header
  before any network fetch happens, and a header listing critical extensions
  (`crit`), a `kid` that is present but not a string (`"kid": null`), or —
  with `require_at_jwt` — a `typ` other than `at+jwt` is refused there too;
- a credential over 16 KiB (`MAX_TOKEN_BYTES`) is refused before it is even
  decoded, whatever it holds;
- an unknown `kid` (which comes from the unverified header) triggers at most
  one key refetch per minute, so junk tokens cannot turn the server into an
  amplifier aimed at the authorization server; a separate hourly refresh is
  what notices a key the authorization server has withdrawn;
- a key refetch runs in a task of its own that holds the refresh lock until
  the fetch completes, so a caller that stops waiting (a client disconnect,
  a timeout layer) cannot cancel it halfway and leave the refetch cooldown
  spent with no keys loaded;
- each JWKS key is narrowed to only the algorithms its own key type can
  produce (an HMAC, raw octet, `use: enc` key, or key whose `key_ops` lacks
  `verify` is never usable to verify a signature) — including a key set
  seeded with `OAuthValidatorBuilder::initial_jwks`, which goes through the
  same size cap, key cap and per-key checks as a fetched one. A key the
  verifier could never use — a P-521 or X25519/X448 key, an RSA key whose
  modulus is not 2048 to 8192 bits — is skipped, never counted as held. A key
  that declares no `alg` stays usable for every allowlisted algorithm its
  type can produce (a documented RFC 8725 §3.1 deviation), and a `warn`
  naming its `kid` is logged the first time it appears;
- no `OAuthValidatorBuilder` option relaxes a fetch rule: an added root
  certificate only adds trust anchors (a private key alongside it is
  refused), an explicit proxy tunnels `https` fetches end to end, a
  credential in a plain-`http` non-loopback proxy URL is refused without
  `allow_insecure_http`, and the proxy URL is never logged, displayed or
  `Debug`-printed unredacted (a refused one is not shown at all). Every
  metadata and JWKS request times out after 10 s by default, and
  `fetch_timeout` accepts only 1 to 60 s, since the timeout also bounds how
  long a refresh holds the refresh lock. Only a `2xx` response is read, at
  most 256 KiB of it and 64 keys;
- a credential in the `issuer`, `jwks_uri` or `resource` URL (userinfo, or a
  `jwks_uri` query) never reaches a log line, an error or configuration
  problem message, or the `Debug` output of the config types, the validator,
  `AuthorizedToken` or the layers: every such display masks userinfo, query
  and fragment, and a value that cannot be parsed is shown only when it has
  no `@`, `?` or `#` and only visible ASCII. The exception is where the URL
  *is* the output: `resolve` accepts userinfo in `issuer` and `resource`
  (it refuses only a query or fragment there), and the RFC 9728 metadata
  document publishes the `issuer` verbatim in `authorization_servers` and
  every challenge carries the raw `resource`, so a credential written into
  either is sent to every client. Put none there;
- a refused request's query (which may carry an RFC 6750 §2.3
  `access_token`) never reaches a log line or `RejectContext`'s `Debug`:
  the layers log the path only, and the `Debug` shows the query as `?***`;
- no proxy — explicit, from `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY`, or from
  the system settings — ever carries a fetch of a loopback URL (it uses a
  proxy-free client), so the plain-http loopback exemption never crosses the
  network; non-loopback fetches keep reqwest's own proxy handling, and an
  explicit proxy replaces the environment and system ones. A fetch that
  starts on a loopback URL may not be redirected off loopback, so the
  proxy-free client never carries a hop a proxy should have seen.
  `localhost` and `*.localhost` count as loopback **by name**, so that client
  resolves every name to `::1`/`127.0.0.1` itself, never through DNS (which,
  on some resolvers, forwards `*.localhost` upstream). The one residual — a
  redirect from a non-loopback URL to a loopback one may go through an
  environment or system proxy — is documented in the README's security
  model;
- signature verification and `iss`/`aud`/`exp`/`nbf` claim checks happen
  inside a single `jsonwebtoken::decode` call, so a claim check can never be
  reordered to run after a signature has already been treated as valid;
- `iss` is re-checked as an exact single string after decode, a present
  `nbf` must be a NumericDate, and a sender-constrained (`cnf`) token is
  refused rather than accepted as a bearer token;
- the optional claim policy (`allowed_client_ids`, `max_token_age_secs`,
  `required_claims`) reads only claims the verified signature covers, runs
  after those rechecks and before the scope check (so its refusals are 401,
  never 403), and changes nothing when unset; with `max_token_age_secs` set,
  a token without a readable `iat` is refused, never waved through, and with
  `allowed_client_ids` set a `client_id` that is present but not a non-empty
  string is refused rather than read past to `azp`;
- every failure mode (fetch error, parse error, unknown key) fails closed —
  a failed refresh never discards keys already held, and the validator never
  falls back to accepting a token it cannot verify against the keys it has;
- `WWW-Authenticate` is set (and overwrites whatever a caller-supplied
  rejection handler returned) on every 401/403 once OAuth is configured, and
  a layer whose challenge would not be a valid header refuses to build. The
  status and challenge are decided by one function, shared by the axum layer,
  the `tower` layer and the public `refusal()` a hand-built integration
  calls, and every challenge it returns is a valid header value (a validator
  whose configured challenge would not be one logs at `error` and uses a
  fallback without `resource_metadata`, and the layers refuse to build with
  it);
- which check refused a token (`InvalidToken::kind()`) never changes the
  response: every `TokenRejection::Invalid` is the same 401 with the same
  challenge, and neither the kind nor the log-only detail reaches a response
  the crate builds;
- a configuration that would accept ID tokens as access tokens, or fetch keys
  from (or receive tokens at) a plain-`http` non-loopback URL — configured,
  discovered or reached by a redirect — is refused (at startup, or when the
  fetch is made) unless explicitly opted into. Whether a URL is plain `http`,
  and whether its host is loopback, is decided on the URL as parsed — the
  same reading the fetch uses — never on its raw text, so no spelling of a
  cleartext URL (`http:/host`, `http:host`, `HTTP:\\host`) avoids the opt-in.
  A spelling the parser has to repair is otherwise accepted and logged as a
  startup `warn`, and the discovery and `resource_metadata` URLs built from
  it never leave the host the parser reads in it;
- `AuthLayer` (and the `tower` feature's `HttpAuthLayer`, which runs the
  same check) cannot be constructed in a state that silently passes every
  request through unauthenticated — that requires an explicit,
  clearly-named constructor. An `optional()` layer still needs a credential
  mechanism, and passes through only a request that presents no credential
  at all (a `DPoP`-scheme or tab-separated `Bearer` value counts as
  presented); anything presented is refused exactly as without `optional()`,
  and a credential an outer layer inserted is removed, not passed on;
- the `Credential`/`AuthorizedToken`/`StaticTokenMatch` axum extractors never
  turn a missing credential into access: they answer with the layer's own 401
  and challenge, and with 500 on a route no `AuthLayer` covers (their `Option`
  forms too);
- every configured credential header is marked sensitive
  (`http::HeaderValue::set_sensitive`) before a rejection handler or the
  inner service sees the request, and an `allow_unauthenticated` layer marks
  `Authorization`, so a `Debug` of the request downstream never prints a
  credential;
- per-route and per-operation scope requirements (a layer's
  `require_scopes`, `RequireScopes`, the `Scoped` extractor, the `mcp`
  feature's `McpToolScopes`) are an exact all-of match on the token the
  layer validated, the same matching as the validator's own; a token missing
  one, and a static token (which has no scopes) unless the application opted
  in with `static_token_bypasses_scopes`, get 403 through the layer's own
  refusal path, with a challenge that is always a valid header value (a
  caller-supplied `error_description` is reduced to RFC 6750's character
  set, never escaped in); a route-level check with no authentication layer in
  front answers 500, never access;
- `McpToolScopes` reads a request body under a limit enforced while it
  streams (1 MiB by default; a larger body is refused with 413 without being
  read further), gives a body it cannot classify with certainty (not JSON, no
  readable tool name, a repeated member two parsers could read differently)
  the strictest scope set rather than the default, authorizes every message
  of a JSON-RPC batch, classifies a body under any method (not only
  `POST`, and never trusting a size hint of zero), refuses a request with
  no credential with the layer's 401 whenever what it needs is not empty
  (before reading its body when every request needs a scope),
  parses in one streaming pass that builds no document (memory stays at
  about the body itself), passes a served body on byte-identical, and never
  logs body content. Its tool names are matched exactly — byte for byte on
  the JSON-decoded name — so it relies on the MCP server dispatching tools
  exactly as well: a dispatcher that normalizes names (case, whitespace)
  would let a caller reach a scoped tool under a spelling treated as
  unconfigured, with only the default scopes. That is a documented
  deployment requirement, not something this crate can check; body reads
  have no timeout of their own, so the server must set one;
- static tokens are compared in constant time (`subtle`): with several
  (`StaticTokens`), every candidate is compared with every entry, with no
  early exit once one matches and no branch on which entry matched. A
  secret's length is not hidden. No static token reaches a `Debug` impl or a
  log line; a set prints its count and labels, and labels are restricted to
  1 to 64 visible ASCII characters so they are always log-safe. Each secret
  the crate holds (a set's entries, the builders' single token, the `env`
  loader's intermediate copies) is wiped from memory when dropped
  (`zeroize`); a `StaticTokenDecision`'s `String` and strings the caller owns
  are not. A whitespace-only static token is no credential: a layer built
  with only one fails to build rather than silently admitting nobody;
- the structured observability output (the `auth.*` log fields, the
  `oauth_rs.*` spans and, with the `metrics` feature, the metric labels)
  carries only values from fixed sets, a static token's log-safe label, and
  hosts without scheme, path, credential or query — never a token, secret,
  claim value, URL query or request body. The span fields taken from a
  token's unverified header (`kid`, `alg`) are cut to 128 characters and
  every character outside printable ASCII is escaped, so a hostile header
  cannot inject control characters or terminal escapes into a log.

See `CLAUDE.md` for the full list and the module each one lives in.

## Assurance beyond the test suite

CI checks more than the invariants above, so a regression in them is caught
before a release rather than reported after it:

- **API compatibility.** `cargo semver-checks` compares every pull request,
  and every release commit, with the latest release on crates.io, so an
  accidental breaking change to this crate's own API surface fails CI instead
  of reaching a consumer on a compatible-version range. It cannot see a major
  bump of a dependency whose types appear in the public API (`serde`,
  `serde_json`, `http`, `tower-layer`, `tower-service`, `http-body`, `bytes`,
  `axum`); that stays a manual policy check (see `CLAUDE.md`).
- **Feature combinations and dependency floors.** `cargo hack` builds every
  feature combination that can compile, and a build against the oldest
  release each dependency requirement allows keeps the lower bounds in
  `Cargo.toml` honest.
- **Supply chain.** `cargo audit` and `cargo deny check` (`deny.toml`) fail on
  a known advisory or a yanked crate, on a dependency licence outside an
  explicit allowlist, and on any dependency source other than crates.io. Both
  ignore lists are empty.
- **Fuzzing.** `cargo-fuzz` targets in `fuzz/` run after every merge to `master` that touches the crate's source, against its
  own parsers: the `Bearer` header parser, the validator's pre-fetch header
  checks (`check_header`, `check_crit`, `check_typ`), scope and principal
  extraction, the RFC 9728 metadata URL and path builders, the discovery-URL
  builder, the per-entry JWK parse, the per-request 403 challenge, and the
  `mcp` feature's JSON-RPC tool-call classification (against
  `serde_json::Value` as an oracle). They assert invariants as well as
  looking for panics: for example, a token whose header carries `crit` is
  never accepted, and no parsed key ends up with an empty or out-of-allowlist
  algorithm set. They run after a merge, and on demand, rather than on every pull request or on a schedule.

Fuzzing exercises the parsers, not the full validation path; it complements
the test suite rather than replacing it.
