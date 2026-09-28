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
  `verify` is never usable to verify a signature);
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
  a layer whose challenge would not be a valid header refuses to build;
- a configuration that would accept ID tokens as access tokens, or fetch keys
  from (or receive tokens at) a plain-`http` non-loopback URL — configured,
  discovered or reached by a redirect — is refused (at startup, or when the
  fetch is made) unless explicitly opted into;
- `AuthLayer` cannot be constructed in a state that silently passes every
  request through unauthenticated — that requires an explicit,
  clearly-named constructor.

See `CLAUDE.md` for the full list and the module each one lives in.
