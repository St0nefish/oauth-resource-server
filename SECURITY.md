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
  (`crit`) is refused there too;
- each JWKS key is narrowed to only the algorithms its own key type can
  produce (an HMAC, raw octet, `use: enc` key, or key whose `key_ops` lacks
  `verify` is never usable to verify a signature) — including a key set
  seeded with `OAuthValidatorBuilder::initial_jwks`, which goes through the
  same size cap, key cap and per-key checks as a fetched one;
- no `OAuthValidatorBuilder` option relaxes a fetch rule: an added root
  certificate only adds trust anchors (a private key alongside it is
  refused), an explicit proxy tunnels `https` fetches end to end, a
  credential in a plain-`http` non-loopback proxy URL is refused without
  `allow_insecure_http`, and the proxy URL is never logged, displayed or
  `Debug`-printed unredacted (a refused one is not shown at all);
- no proxy — explicit, from `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY`, or from
  the system settings — ever carries a fetch of a loopback URL (it uses a
  proxy-free client), so the plain-http loopback exemption never crosses the
  network; non-loopback fetches keep reqwest's own proxy handling, and an
  explicit proxy replaces the environment and system ones;
- signature verification and `iss`/`aud`/`exp`/`nbf` claim checks happen
  inside a single `jsonwebtoken::decode` call, so a claim check can never be
  reordered to run after a signature has already been treated as valid;
- `iss` is re-checked as an exact single string after decode, a present
  `nbf` must be a NumericDate, and a sender-constrained (`cnf`) token is
  refused rather than accepted as a bearer token;
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
- static tokens are compared in constant time (`subtle`): with several
  (`StaticTokens`), every candidate is compared with every entry, with no
  early exit once one matches and no branch on which entry matched. A
  secret's length is not hidden. No static token reaches a `Debug` impl or a
  log line; a set prints its count and labels, and labels are restricted to
  1 to 64 visible ASCII characters so they are always log-safe.

See `CLAUDE.md` for the full list and the module each one lives in.

## Assurance beyond the test suite

CI checks more than the invariants above, so a regression in them is caught
before a release rather than reported after it:

- **API compatibility.** `cargo semver-checks` compares every pull request,
  and every release commit, with the latest release on crates.io, so an
  accidental breaking change to this crate's own API surface fails CI instead
  of reaching a consumer on a compatible-version range. It cannot see a major
  bump of `axum` or `http`, whose types appear in the public API; that stays a
  manual policy check (see `CLAUDE.md`).
- **Feature combinations and dependency floors.** `cargo hack` builds every
  feature combination that can compile, and a build against the oldest
  release each dependency requirement allows keeps the lower bounds in
  `Cargo.toml` honest.
- **Supply chain.** `cargo audit` and `cargo deny check` (`deny.toml`) fail on
  a known advisory or a yanked crate, on a dependency licence outside an
  explicit allowlist, and on any dependency source other than crates.io. Both
  ignore lists are empty.
- **Fuzzing.** `cargo-fuzz` targets in `fuzz/` run nightly against the crate's
  own parsers: the `Bearer` header parser, the validator's pre-fetch header
  checks (`check_header`, `check_crit`, `check_typ`), scope and principal
  extraction, the RFC 9728 metadata URL and path builders, the discovery-URL
  builder, and the per-entry JWK parse. They assert invariants as well as
  looking for panics: for example, a token whose header carries `crit` is
  never accepted, and no parsed key ends up with an empty or out-of-allowlist
  algorithm set. They run nightly rather than on every pull request.

Fuzzing exercises the parsers, not the full validation path; it complements
the test suite rather than replacing it.
