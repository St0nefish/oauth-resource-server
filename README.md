# oauth-resource-server

[![crates.io](https://img.shields.io/crates/v/oauth-resource-server.svg)](https://crates.io/crates/oauth-resource-server)
[![docs.rs](https://img.shields.io/docsrs/oauth-resource-server)](https://docs.rs/oauth-resource-server)
[![CI](https://github.com/St0nefish/oauth-resource-server/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/St0nefish/oauth-resource-server/actions/workflows/ci.yml)
[![license: MIT](https://img.shields.io/crates/l/oauth-resource-server.svg)](https://github.com/St0nefish/oauth-resource-server/blob/master/LICENSE)
[![MSRV 1.89](https://img.shields.io/badge/MSRV-1.89-blue.svg)](#msrv-and-semver-policy)

Protect a Rust HTTP API with OAuth 2.0 access tokens. This crate verifies JWT
access tokens (RFC 9068) against your authorization server's published signing
keys, answers refusals with RFC 6750 `WWW-Authenticate` challenges, serves RFC
9728 protected-resource metadata so clients can discover where to get a token,
and can accept a static API key alongside OAuth. It ships an axum/tower
middleware, and the validator underneath works with any framework running on
a Tokio runtime.

## What it is, and what it is not

**It is** the *resource server* half of OAuth: the part in front of your API
that decides whether the bearer token on a request is good enough.

- It validates JWT access tokens locally against a JWKS: signature, `iss`,
  `aud`, `exp`, `nbf`, `typ`, and the scopes you require. There is no
  per-request call to the authorization server.
- It works with any standards-following authorization server. Every provider
  difference (audience value, scope claim name and shape, signing algorithm,
  `typ`, username claim) is a configuration field, never a code path. The
  [provider guide](https://github.com/St0nefish/oauth-resource-server/blob/master/docs/providers.md)
  has recipes, each labeled with exactly how far it has been tested.
- It tells clients where to authenticate: every 401 and 403 carries a
  challenge pointing at the metadata document, which names your authorization
  server.
- It accepts a static API key alongside OAuth, or instead of it, so an
  existing deployment can move to OAuth without an outage — and several keys
  at once, so a key can be rotated without one either.
- It fails closed, down to the middleware refusing to build with no
  credential configured.

**It is not:**

- **An OAuth client or login flow.** It has no redirects, no PKCE and no token
  exchange. Callers get their tokens from the authorization server.
- **An authorization server.** It never issues, refreshes or revokes a token.
- **An opaque-token validator.** It accepts JWT access tokens only; there is
  no RFC 7662 introspection yet. Several servers issue opaque tokens by default
  and need a setting changed to issue JWTs.
- **Sender-constrained.** It accepts plain bearer tokens only, with no DPoP
  and no mTLS binding. A token the authorization server did bind (one with a
  `cnf` claim) is refused rather than accepted as a bearer token.
- **Hot-reloadable.** Configuration takes effect when the validator and layer
  are built, which in practice means at process start.

[Security model](#security-model) draws the boundary precisely.

## Install

```sh
cargo add oauth-resource-server --features axum,serde
```

The [axum quickstart](#quickstart-axum) below also uses `axum`, `tokio` and a
serde format crate (YAML here; any serde format works):

```sh
cargo add axum@0.8 serde_yaml_ng
cargo add tokio --features full
```

or in `Cargo.toml`:

```toml
[dependencies]
oauth-resource-server = { version = "0.3", features = ["axum", "serde"] }
```

### Features

| Feature | Default | What it enables |
|---|---|---|
| `rustls-tls` | yes | The rustls TLS backend for fetching the JWKS and discovery documents, trusting **only the Mozilla root certificates compiled into the binary**. |
| `rustls-tls-native-roots` | no | rustls, trusting the operating system's certificate store (for an authorization server behind a private CA) — **in addition to** the Mozilla roots while the default `rustls-tls` is on too (reqwest merges both into one root store), and **instead of** them only with `default-features = false`. |
| `native-tls` | no | The platform TLS backend (OpenSSL on Linux), trusting the operating system's certificate store. Enabled together with a rustls feature, it is the one used (reqwest's choice), so the OS store applies rather than the Mozilla roots. |
| `serde` | no | `Deserialize`/`Serialize` for `OAuthConfig`, to load it from YAML, TOML, JSON or any other serde format, and `Serialize` for `InvalidToken` (as its kind label, never the log-only detail). |
| `env` | no | The `env` module: load the config and secrets from environment variables, with `VAR_FILE` support. |
| `tower` | no | The `http_layer` module: `HttpAuthLayer`, an authentication layer for any `tower` service over `http::Request<B>` (hyper, tonic, ...), whatever its body types. See [Using with other frameworks](#using-with-other-frameworks). |
| `axum` | no | The `axum` module: the `AuthLayer` middleware, `metadata_router`, axum extractors for `Credential` and `AuthorizedToken`, and per-route scopes (`RequireScopes`, the `Scoped<S>` extractor). Implies `tower`. |
| `mcp` | no | The `mcp` module, an integration helper for [Model Context Protocol](https://modelcontextprotocol.io) servers: `McpToolScopes`, a tower layer that requires scopes (and, optionally, claim values such as a group) per tool by reading the JSON-RPC `tools/call` in the request body. No MCP SDK: it parses with `serde_json` and reads the body with `http-body` and `bytes`, all already in every build. Implies `tower`. See [Per-tool scopes](#per-tool-scopes-mcptoolscopes). |
| `metrics` | no | Counters and a gauge for authentication decisions and JWKS refreshes, through the [`metrics`](https://docs.rs/metrics) facade, and the `observability` module naming them. See [Observability](#observability). Off, it adds no dependency and records nothing. |
| `testing` | no | A fake authorization server (`TestAuthority`), a fluent token builder, and the throwaway signing keys behind them, for **your tests only**. Never enable it in a production build. It follows semver like the rest of the crate. |

The core (config, validator, `authenticate`, `refusal`, `static_token_policy`)
is always available and depends on no web framework.

### Choosing a TLS backend

At least one of `rustls-tls`, `rustls-tls-native-roots` and `native-tls` must
be enabled. Signing keys are fetched over HTTPS, and with no backend the crate
fails to compile rather than failing every fetch at runtime.

**Which certificates are trusted depends on the feature.** `rustls-tls`, the
default, trusts only the Mozilla root set built into the binary
(`webpki-roots`); it ignores the operating system's trust store and
`SSL_CERT_FILE`. That suits an authorization server with a public
certificate, and a minimal container with no CA bundle. A self-hosted server
whose certificate comes from a private CA fails every fetch with a TLS error
under it. Either add the CA in code with
`OAuthValidator::builder(..).add_root_certificate_pem(..)`, which works with
every backend, or use `rustls-tls-native-roots` (rustls plus the OS store) or
`native-tls` (the platform library plus the OS store) and install the CA into
the OS store as usual. `rustls-tls-native-roots` **adds** the OS store to the
Mozilla roots while the default `rustls-tls` feature stays on — reqwest loads
both into one root store — so to trust the OS store *instead*, turn the
defaults off:

```toml
[dependencies]
oauth-resource-server = { version = "0.3", default-features = false, features = ["rustls-tls-native-roots", "axum", "serde"] }
```

(and the same `default-features = false` on any `[dev-dependencies]` entry,
for the reason given below for `native-tls`). With `native-tls` and a rustls feature both enabled,
reqwest uses native-tls, so the OS store is what applies (and what
`add_root_certificate_pem` adds to), not the Mozilla roots.

`add_root_certificate_pem` **adds** trust anchors; it never replaces the
backend's own roots. A PEM file may hold one certificate or a bundle, and a
file with no certificate in it, one the TLS backend cannot use, or any
private-key block fails `build()` rather than being ignored. Pass only real
CA certificates: under rustls a trust anchor keeps only its subject, public
key and name constraints, ignoring `basicConstraints` and `keyUsage`, so a
leaf (`CA:FALSE`) certificate passed here becomes an anchor that can issue
for any host.

```rust,no_run
use std::sync::Arc;

use oauth_resource_server::{KeyNaming, OAuthConfig, OAuthValidator};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let resolved = OAuthConfig {
        enabled: true,
        issuer: "https://idp.internal.example.com/".into(),
        audience: "example-api".into(),
        resource: "https://api.example.com/".into(),
        required_scope: Some("api:read".into()),
        ..OAuthConfig::default()
    }
    .resolve(KeyNaming::Dotted("oauth"))?
    .expect("OAuth is enabled");

    let validator = Arc::new(
        OAuthValidator::builder(&resolved)
            .add_root_certificate_pem(&std::fs::read("/etc/ssl/private-ca.pem")?)
            .build()?,
    );
    assert!(!validator.is_ready()); // no I/O yet: keys load on first use
    Ok(())
}
```

A root added this way can vouch for any host name on this validator's
fetches, so add the CA that issues the authorization server's certificate and
nothing broader. The other fetch options (proxy, timeout, a key set to start
from) are in [Fetch options](#fetch-options-code-not-config).

If your application already uses `reqwest` with `native-tls`, switch this
crate over as well, so the binary carries one TLS stack instead of two:

```toml
[dependencies]
oauth-resource-server = { version = "0.3", default-features = false, features = ["native-tls", "axum", "serde"] }

[dev-dependencies]
oauth-resource-server = { version = "0.3", default-features = false, features = ["native-tls", "testing"] }
```

Repeat `default-features = false` in `[dev-dependencies]`. Cargo merges a
dependency's features across every table it appears in, so a dev-dependency
entry that leaves the defaults on brings `rustls-tls` back into every test
build.

## Quickstart: axum

A complete server: configuration from YAML, one shared validator, the auth
layer on the protected routes, and the discovery document served outside it.

```rust,no_run
use std::sync::Arc;

use axum::{Router, routing::get};
use oauth_resource_server::axum::{AuthLayer, metadata_router};
use oauth_resource_server::{KeyNaming, OAuthConfig, OAuthValidator, static_token_policy};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Configuration, from any serde format (feature `serde`).
    let config: OAuthConfig = serde_yaml_ng::from_str(
        r#"
        enabled: true
        issuer: "https://auth.example.com/"   # byte-exact, trailing slash and all
        audience: "my-api"                    # what your server puts in `aud`
        resource: "https://api.example.com"   # this API's public URL
        required_scope: "api:read"
        scopes_supported: ["api:read"]
        "#,
    )?;
    // `KeyNaming` decides how problems name settings: `oauth.issuer`, ...
    let resolved = config
        .resolve(KeyNaming::Dotted("oauth"))?
        .expect("enabled: true, so resolve returns Some");

    // 2. One validator per process. The background task loads the signing keys
    //    now and re-reads them every hour.
    let oauth = Arc::new(OAuthValidator::new(&resolved)?);
    oauth.spawn_background_refresh();

    // 3. The auth layer. No static API key here; the dual-mode quickstart
    //    below adds one.
    let decision = static_token_policy(None, Some(&resolved), false)?;
    let auth = AuthLayer::from_decision(decision, Some(Arc::clone(&oauth)))?;

    // 4. Protect the API, and serve the metadata document OUTSIDE the layer:
    //    a caller with no token uses it to find out where to get one.
    let app = Router::new()
        .route("/v1/things", get(|| async { "the protected things" }))
        .route_layer(auth)
        .merge(metadata_router(Some(oauth)));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    axum::serve(listener, app).await?;
    Ok(())
}
```

What a client sees (challenge headers wrapped for reading; on the wire each
is one line):

```text
GET /v1/things                           (no token)
401  WWW-Authenticate: Bearer error="invalid_token",
       resource_metadata="https://api.example.com/.well-known/oauth-protected-resource",
       scope="api:read"

GET /.well-known/oauth-protected-resource
200  {"authorization_servers":["https://auth.example.com/"],
      "bearer_methods_supported":["header"],
      "resource":"https://api.example.com",
      "scopes_supported":["api:read"]}

GET /v1/things   Authorization: Bearer <valid token without api:read>
403  WWW-Authenticate: Bearer error="insufficient_scope", scope="api:read",
       resource_metadata="https://api.example.com/.well-known/oauth-protected-resource"

GET /v1/things   Authorization: Bearer <valid token with api:read>
200  the protected things
```

`AuthLayer` is a `tower::Layer`, so `.route_layer(auth)` or `.layer(auth)`
protects routes directly. It is also the state for the `require_auth`
middleware function:
`.route_layer(axum::middleware::from_fn_with_state(auth, require_auth))`
behaves identically, for composing with other `from_fn` middleware.

The runnable version,
[`examples/axum_basic.rs`](https://github.com/St0nefish/oauth-resource-server/blob/master/examples/axum_basic.rs),
starts a fake authorization server on a loopback port, so it needs no network.

### Reading the caller in a handler

On success the layer inserts a `Credential` into the request extensions and,
for an OAuth token, the `AuthorizedToken` as well (for a static key, a
`StaticTokenMatch` naming which key; see
[Rotating a static API key](#rotating-a-static-api-key-with-zero-downtime)).
All three are axum extractors, so a handler takes them as arguments:

```rust
use oauth_resource_server::Credential;

async fn whoami(credential: Credential) -> String {
    match credential {
        Credential::OAuth(token) => format!(
            "subject {:?}, known as {:?}, with scopes {:?}",
            token.subject, token.principal, token.scopes
        ),
        Credential::StaticToken => "the static API key".to_string(),
        // `Credential` is `#[non_exhaustive]`.
        _ => "some other credential".to_string(),
    }
}
```

When the layer inserted nothing, the extractors refuse the request themselves,
and never pass it to the handler:

| The request… | `Credential` / `AuthorizedToken` | `Option<Credential>` / `Option<AuthorizedToken>` |
|---|---|---|
| was accepted by the layer | the value | `Some(value)` |
| passed an `optional()` layer with no credential, or an `allow_unauthenticated()` layer | the layer's own 401 and `WWW-Authenticate` challenge | `None` |
| was accepted with the static token (`AuthorizedToken` only, unless an outer layer inserted one; see below) | the layer's own 401 and challenge | `None` |
| was accepted with an OAuth token (`StaticTokenMatch` only) | the layer's own 401 and challenge | `None` |
| is on a route no `AuthLayer` covers | 500, logged at `error` | 500, logged at `error` |

"The layer's own 401" comes from the same code as the layer's refusals, so it
has the same status, challenge and `on_reject` body. A route outside every
layer is a mistake in the server's wiring, not something a caller can fix by
authenticating. It gets a 500 rather than a 401, because a 401 would send an
OAuth client into an authorization flow that can never succeed there. Even
`Option<..>` refuses in that case, so a wiring mistake can never read as an
anonymous caller. `Extension<Credential>` and `Extension<AuthorizedToken>`
still work as before.

Nested layers: an `optional()` layer first removes any `Credential` and
`AuthorizedToken` an outer layer inserted, so its handlers only ever see what
it accepted itself. Strict layers never remove anything, so the extensions
accumulate. `Credential` is the innermost layer's decision, but an
`AuthorizedToken` may come from an outer layer. For example, an inner
static-key layer under an outer OAuth layer leaves the outer layer's token in
place. Read `Credential` when the innermost decision is what matters.

When a static token is also configured, extract `Credential` rather than
`AuthorizedToken`: a static-token request has no `AuthorizedToken`, so an
`AuthorizedToken` extractor refuses it with a 401. Key per-user decisions on
`subject`, the verbatim signed `sub`; `principal` comes from a configurable
claim list and is meant for logs.

### Per-route and per-handler scopes

The validator's required scopes are the floor every token must meet. For more
on some routes — a write scope on the routes that write — require it where it
applies, on top of that floor. Every way below checks the token the layer
already validated (one validator, one key cache; no second validator), and
refuses a token without the scopes with **403 and a challenge naming the
scopes this request needs**: the validator's required scopes followed by the
route's, `Bearer error="insufficient_scope", scope="api:read api:write",
resource_metadata="…"`. A client re-authorizes for exactly that set and
passes both checks (this is the per-request challenge MCP's scope step-up
expects).

| For | Use |
|---|---|
| everything behind a layer | `AuthLayer::builder().require_scopes([..])` (or `HttpAuthLayerBuilder::require_scopes`) |
| some routes | the `RequireScopes::new([..])` route layer, behind the auth layer |
| one handler | the `Scoped<S>` extractor, with `S` a `ScopeSet` type of yours |
| one MCP tool | [`McpToolScopes`](#per-tool-scopes-mcptoolscopes) (feature `mcp`) |
| any other code | `AuthorizedToken::require_scopes(&[..])`, and `refusal_for_scopes()` for the 403 |

```rust
use axum::{Router, routing::{get, post}};
use oauth_resource_server::axum::{AuthLayer, RequireScopes, ScopeSet, Scoped};

struct DocsAdmin;
impl ScopeSet for DocsAdmin {
    const SCOPES: &'static [&'static str] = &["docs:admin"];
}

async fn purge(token: Scoped<DocsAdmin>) -> String {
    format!("purged by {:?}", token.subject)
}

fn app(auth: AuthLayer) -> Router {
    Router::new()
        .route("/docs/new", post(|| async { "written" }))
        // Applies to the routes added above it.
        .route_layer(RequireScopes::new(["docs:write"]))
        .route("/docs/purge", post(purge))
        .route("/docs", get(|| async { "listed" }))
        // Added last, so it runs first: everything above is behind it.
        .route_layer(auth)
}
```

They refuse through the layer's own refusal path: its status, challenge and
`on_reject` body. A request with no credential (an `optional()` layer passed
it through) gets the layer's own 401; a route no layer covers gets 500,
logged at `error`, never access. Scopes are matched exactly, all-of, the same
way the validator matches its own.

**A static token has no scopes**, so wherever scopes are required it is
refused with the same 403 — fail-safe, even though in dual mode it was never
held to the validator's scopes: a route that names a scope asks it of every
credential. Where the static key is meant to be a full-access key, say so
with `static_token_bypasses_scopes()` (on the layer builders,
`RequireScopes` and `McpToolScopes`). A layer with required scopes, no OAuth
validator and no bypass refuses to build (`AuthLayerError::ScopesNeedOAuth`):
nothing could ever pass it; so does `build_with_decision` with an
`Unauthenticated` decision and required scopes
(`AuthLayerError::ScopesWithoutAuthentication`), rather than drop them. Behind
a static-only layer a route check's 403 carries the bare
`Bearer error="insufficient_scope"` challenge. `Scoped<S>` extracts an OAuth
token, so it always refuses a static token. A request presenting both a
static token and an OAuth token (in two sources) is judged by the static
token, which the layer checks first.

Scopes written in code go to `RequireScopes::new` (and `McpToolScopes`'
`default`/`tool`), which panic on a value that is not a valid scope-token;
scopes read from configuration go to `RequireScopes::try_new` (and
`try_default`/`try_tool`/`try_body_limit`), which return an error naming
the bad value. A `ScopeSet` with an invalid scope does not compile.

A check of your own in the handler works too; decide it **fail-closed**:
allow only a credential you positively recognize.

```rust
use axum::http::StatusCode;
use oauth_resource_server::Credential;

async fn delete_thing(credential: Option<Credential>) -> StatusCode {
    let allowed = match &credential {
        Some(Credential::OAuth(token)) => token.has_scope("api:write"),
        // The static API key has no scopes. Whether it may write is your
        // decision; say so explicitly rather than falling through.
        Some(Credential::StaticToken) => false,
        // No credential at all (an `optional()` or `allow_unauthenticated()`
        // layer passed the request through), or a kind this code does not
        // know: deny.
        _ => false,
    };
    if !allowed {
        return StatusCode::FORBIDDEN;
    }
    // ... do the write ...
    StatusCode::NO_CONTENT
}
```

Avoid `Option<AuthorizedToken>` with an
`if let Some(token) = .. { if !token.has_scope(..) { deny } }` check: `None`
covers a static-token request and every request that an `optional()` or
`allow_unauthenticated()` layer passed through, so that shape lets all of them
through the write check. Scopes are matched exactly, with no hierarchy: if
your authorization server means `api:write` to imply `api:read`, check for
either here.

### Optional authentication

For routes that serve everyone but personalize for an authenticated caller,
or an API that is open for reads but authenticated for writes,
`AuthLayerBuilder::optional()` lets a request that presents **no** credential
through with nothing inserted. A credential that is presented but not accepted
is still refused, exactly as without `optional()`:

```rust
use std::sync::Arc;

use axum::{Router, routing::get};
use oauth_resource_server::axum::{AuthLayer, AuthLayerError};
use oauth_resource_server::{AuthorizedToken, OAuthValidator};

async fn front_page(token: Option<AuthorizedToken>) -> String {
    match token {
        Some(token) => format!("welcome back, {:?}", token.principal),
        None => "welcome, visitor".to_string(),
    }
}

fn app(oauth: Arc<OAuthValidator>) -> Result<Router, AuthLayerError> {
    let optional = AuthLayer::builder().oauth(oauth).optional().build()?;
    Ok(Router::new()
        .route("/", get(front_page))
        .route_layer(optional))
}
```

| The request carries… | An `optional()` layer |
|---|---|
| no credential: every configured header absent or blank | passes it through; the handler sees `None` |
| a valid credential with the required scopes | inserts it, as without `optional()` |
| an invalid, expired or unknown credential, or the wrong static token | the same 401 and challenge as without `optional()` |
| a valid token without the required scopes | the same 403 and challenge as without `optional()` |

"Blank" is what `authenticate()` reports as `Missing`: an empty or
whitespace-only value, `Bearer` followed by nothing, or an `Authorization`
value that uses some other scheme (`Basic ...`), which carries no bearer
credential. Some values count as a presented credential even so, and get
exactly the refusal a non-optional layer sends:

- a header value that is not visible ASCII;
- a non-blank later value of a repeated header;
- any `DPoP ...` value, because a sender-constrained token must be refused,
  not served as anonymous;
- `Bearer` followed by a tab and a token.

`optional()` still requires a static token or a validator to build. See the
security model below.

### Reading the verified claims

Beyond `subject`, `principal` and `scopes`, an `AuthorizedToken` carries what
the signature covered, so a handler never decodes the JWT a second time:
`issuer`, `audiences` (a single-string `aud` normalized to a list),
`expires_at`, `issued_at`, `client_id` (RFC 9068 `client_id`, else `azp`) and
`jti`. Everything else, such as `groups`, `roles`, `email` or a tenant id, is
in the claim set: `claims()` returns it raw, and `claims_as::<T>()`
deserializes it into your own type.

```rust
use std::time::SystemTime;

use oauth_resource_server::AuthorizedToken;

async fn admin_only(token: AuthorizedToken) -> String {
    if !token.has_claim_value("groups", "admins") {
        return "not an admin".to_string();
    }
    // Close a long-lived stream when the token behind it expires.
    let left = token.expires_at.duration_since(SystemTime::now()).unwrap_or_default();
    format!(
        "client {:?}, token valid for another {}s",
        token.client_id,
        left.as_secs()
    )
}
```

For a role or group claim, `has_claim_value("groups", "admins")` is an exact,
case-sensitive membership test, and `claim_values("groups")` returns the
strings: a string claim is one value (not split on whitespace, unlike scopes),
an array yields its string elements, anything else is empty. A claim nested in
objects, such as Keycloak's `realm_access.roles`, is read by explicit segments:
`claim_values_at(&["realm_access", "roles"])` and `has_claim_value_at(..)`.
Segments, not a dotted string, because claim names can contain dots
(`claim_values("https://example.com/roles")` looks up that literal key). These
read the signature-verified claims for a per-request decision; the global
`required_claims` setting is the gate every token must pass.

The `AuthorizedToken` extractor behaves as the table in [Reading the caller in
a handler](#reading-the-caller-in-a-handler) describes: a request the layer
inserted no token into, such as a static-key request or an `optional()`
pass-through, is refused before the handler runs. Take `Option<AuthorizedToken>`
to serve those requests too.

The claims are exactly what the signature covered, and they are bounded by the
16 KiB credential cap. They can hold personal data, so `Debug` on an
`AuthorizedToken` prints claim *names* only, never values. In a test, build a
token with `AuthorizedToken::new(..)` and the `with_claims` / `with_client_id`
/ `with_expires_at` (and so on) builders; `new` leaves `expires_at` at the year
2100 so a fixture is never already expired.

## More quickstarts

### Configuration from environment variables

With the `env` feature, every setting is read from `<PREFIX><FIELD>` or, for a
file mounted by Docker or Kubernetes secrets, from the path in
`<PREFIX><FIELD>_FILE`.

```rust,no_run
use std::sync::Arc;

use oauth_resource_server::OAuthValidator;
use oauth_resource_server::env::{oauth_config_from_env, secret_from_env};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Reads MYAPP_OAUTH_ISSUER (or MYAPP_OAUTH_ISSUER_FILE), MYAPP_OAUTH_AUDIENCE,
    // MYAPP_OAUTH_RESOURCE, MYAPP_OAUTH_REQUIRED_SCOPE, ... and returns Ok(None)
    // when none of the identifying variables is set.
    if let Some(resolved) = oauth_config_from_env("MYAPP_OAUTH_")? {
        let oauth = Arc::new(OAuthValidator::new(&resolved)?);
        oauth.spawn_background_refresh();
    }

    // Any other secret the same way: MYAPP_API_KEY, or MYAPP_API_KEY_FILE.
    // Setting both is an error, not a silent preference.
    let _api_key: Option<String> = secret_from_env("MYAPP_API_KEY")?;
    Ok(())
}
```

```sh
MYAPP_OAUTH_ISSUER=https://auth.example.com/
MYAPP_OAUTH_AUDIENCE=my-api
MYAPP_OAUTH_RESOURCE=https://api.example.com
MYAPP_OAUTH_REQUIRED_SCOPE=api:read
MYAPP_API_KEY_FILE=/run/secrets/api_key
```

OAuth is on when any of `ISSUER`, `JWKS_URI`, `AUDIENCE`, `AUDIENCES` or
`RESOURCE` is set, so a partial set fails at startup naming what is missing
instead of silently starting unauthenticated. `<PREFIX>ENABLED=false` turns it
off with the other variables left in place. [Environment
variables](#environment-variables) describes how values are parsed, and
[`examples/env_config.rs`](https://github.com/St0nefish/oauth-resource-server/blob/master/examples/env_config.rs)
applies an application default (a required scope) before the config is
resolved.

### A static API key alongside OAuth, and moving off it

A static token (an API key you manage yourself) and OAuth can run side by side.
That lets a deployment already running on a static token turn OAuth on without
an outage:

1. **Before:** static token only. `static_token_policy(Some(key), None, false)`
   returns `StaticOnly`.
2. **Turn OAuth on and keep the key.** `static_token_policy` returns
   `StaticAndOAuth`: both credentials work, existing clients carry on, and new
   clients use OAuth.
3. **Once every client has moved,** set `accept_static_bearer: false`, which
   makes it return `StaticIgnored` (the key stops working although it is still
   configured), or remove the key, which makes it return `OAuthOnly`.

Each step is a config change and a restart, and no step locks anyone out.

```rust
use oauth_resource_server::{
    NoAuthConfigured, ResolvedOAuthConfig, StaticTokenDecision, static_token_policy,
};

fn decide(
    api_key: Option<String>,
    oauth: Option<&ResolvedOAuthConfig>,
) -> Result<StaticTokenDecision, NoAuthConfigured> {
    let decision = static_token_policy(api_key, oauth, /* allow_unauthenticated */ false)?;
    match &decision {
        StaticTokenDecision::StaticAndOAuth(_) => println!("API key and OAuth both accepted"),
        StaticTokenDecision::StaticOnly(_) => println!("API key only; consider enabling OAuth"),
        StaticTokenDecision::OAuthOnly => println!("OAuth only"),
        StaticTokenDecision::StaticIgnored => {
            println!("OAuth only; the API key is ignored (accept_static_bearer: false)")
        }
        StaticTokenDecision::Unauthenticated => println!("WARNING: no authentication"),
        // `#[non_exhaustive]`: refuse to start on a decision this code does not know.
        _ => panic!("unrecognized decision {decision:?}"),
    }
    Ok(decision)
}

// Nothing configured and no explicit opt-out: refuse to start.
assert!(decide(None, None).is_err());
assert_eq!(
    decide(Some("k3y".into()), None).unwrap(),
    StaticTokenDecision::StaticOnly("k3y".into())
);
```

Then build the layer from the decision, which applies `accept_static_bearer`
for you:

```rust
use std::sync::Arc;

use oauth_resource_server::axum::{AuthLayer, AuthLayerError};
use oauth_resource_server::{OAuthValidator, StaticTokenDecision};

fn layer(
    decision: StaticTokenDecision,
    oauth: Option<Arc<OAuthValidator>>,
) -> Result<AuthLayer, AuthLayerError> {
    AuthLayer::from_decision(decision, oauth)
}
```

Always go through `static_token_policy`. It is the only thing that reads
`accept_static_bearer`, so handing the key straight to
`AuthLayer::builder().static_token(..)` would make that setting do nothing. It
contains no logging and no message text, so your application can explain the
decision at startup in its own words.

### Rotating a static API key with zero downtime

A layer can hold several static keys at once, as a `StaticTokens` set, and
tells the handler which one a request used. Rotating a key then needs no
window in which clients are locked out:

1. **Add the new key next to the old one.** With the `env` feature,
   `static_tokens_from_env("MYAPP_API_KEY")` reads `MYAPP_API_KEY` (the
   current key, labeled `"current"`) and `MYAPP_API_KEY_NEXT` (the new one,
   labeled `"next"`), each also as a `_FILE`. Restart: both keys work.
2. **Move every client to the new key.** The `StaticTokenMatch` label shows
   which clients still send the old one.
3. **Promote the new key.** Set `MYAPP_API_KEY` to it and unset
   `MYAPP_API_KEY_NEXT` (a restart with both holding the same value is fine:
   it is one key). Restart: only the new key works.

`<VAR>_NEXT` without `<VAR>` is an error (a half-done rotation), as is setting
both a variable and its `_FILE`. There is deliberately no whitespace-separated
list form: it could not carry labels.

`accept_static_bearer` still applies, through `static_token_policy`, which
decides on the current key. The layer's `static_tokens` set follows that
decision: kept when it carries a static token, dropped with it on
`StaticIgnored`, and refused (`AuthLayerError::DecisionWithoutStaticToken`)
alongside a decision the policy made without any static token.

```rust
use std::sync::Arc;

use oauth_resource_server::axum::AuthLayer;
use oauth_resource_server::env::{secret_from_env, static_tokens_from_env};
use oauth_resource_server::{
    OAuthValidator, ResolvedOAuthConfig, StaticTokenMatch, static_token_policy,
};

fn auth_layer(
    oauth_config: Option<&ResolvedOAuthConfig>,
    oauth: Option<Arc<OAuthValidator>>,
) -> Result<AuthLayer, Box<dyn std::error::Error>> {
    // The current key alone is what the policy decides on...
    let current = secret_from_env("MYAPP_API_KEY")?;
    // ...and the layer accepts it plus MYAPP_API_KEY_NEXT during a rotation.
    let keys = static_tokens_from_env("MYAPP_API_KEY")?;
    let decision = static_token_policy(current, oauth_config, false)?;
    Ok(AuthLayer::builder()
        .optional_oauth(oauth)
        .optional_static_tokens(keys)
        .build_with_decision(decision)?)
}

// `None` for an OAuth request; `Some` with the key's label for a static one.
async fn audit(matched: Option<StaticTokenMatch>) -> String {
    match matched.as_ref().map(StaticTokenMatch::label) {
        Some(Some(label)) => format!("static key {label}"),
        Some(None) => "static key".to_string(),
        None => "not a static key".to_string(),
    }
}
```

For one key per client, build the set yourself and label each entry:
`StaticTokens::new().with(Some("ci"), ci_key)?.with(Some("backup-job"), backup_key)?`.
`with` refuses a blank secret, a secret already in the set, a repeated label,
and a label that is not 1 to 64 visible ASCII characters, so every label is
safe to log. `AuthLayerBuilder::static_tokens` (and `HttpAuthLayerBuilder`'s)
takes the set; `static_token(..)` alongside it adds that key too. Outside the
layers, `authenticate_with_static_tokens` returns the `StaticTokenMatch` next
to the `Credential`.

### Several credential sources

Accept a credential from more than one header, such as `Authorization: Bearer`
for OAuth clients and a raw `X-Api-Key` header for scripts:

```rust
use std::sync::Arc;

use axum::http::HeaderName;
use oauth_resource_server::axum::{AuthLayer, AuthLayerError, CredentialSource};
use oauth_resource_server::{OAuthValidator, StaticTokenDecision};

fn layer(
    decision: StaticTokenDecision,
    oauth: Arc<OAuthValidator>,
) -> Result<AuthLayer, AuthLayerError> {
    AuthLayer::builder()
        .oauth(oauth)
        .sources([
            CredentialSource::authorization_bearer(),
            CredentialSource::Raw(HeaderName::from_static("x-api-key")),
        ])
        .build_with_decision(decision)
}
```

Every source is read, and every candidate is checked against every mechanism
(static token and OAuth), so a bad credential in one header never hides a good
one in another. All candidates are first checked against the signing keys
already held. Only if none is accepted may an unknown `kid` trigger a key
refetch, so a foreign JWT in one header (a proxy's own token, say) does not
make the request wait on the authorization server.

### Custom rejection bodies

By default a refusal has an empty body. `on_reject` supplies the body and any
extra headers, for an API whose errors are JSON, say:

```rust
use std::sync::Arc;

use axum::Json;
use axum::response::IntoResponse;
use oauth_resource_server::axum::{AuthLayer, AuthLayerError, RejectContext};
use oauth_resource_server::{OAuthValidator, TokenRejection};

fn layer(oauth: Arc<OAuthValidator>) -> Result<AuthLayer, AuthLayerError> {
    AuthLayer::builder()
        .oauth(oauth)
        .on_reject(|cx: RejectContext<'_>| {
            let error = match cx.rejection {
                TokenRejection::InsufficientScope => "insufficient_scope",
                _ => "unauthorized",
            };
            (cx.status, Json(serde_json::json!({ "error": error }))).into_response()
        })
        .build()
}
```

The callback shapes the response but cannot change the outcome. Whatever it
returns, the crate sets the status (401 for a missing or invalid credential,
403 for insufficient scope) and sets `WWW-Authenticate`, replacing any value
the callback set: to the validator's challenge when OAuth is configured, and
otherwise to the static challenge described below. `RejectContext` also
carries the request's method, URI and headers, so the body can follow
`Accept`. Never put the detail inside `TokenRejection::Invalid` in the body:
it says which check failed, which is an oracle for an attacker. The layer
logs it instead. (Its `kind()` is coarser, but this crate's own responses
never carry it either; whether to expose it is your decision.)
`RejectContext`'s `Debug` prints header names but no header
values, and the URI's path with any query shown as `?***` (a client may put
an `access_token` there), and the credential headers are marked sensitive, so
`tracing::warn!(?cx)` in the callback does not log the token.

### Metrics: counting refusals by kind

`TokenRejection::Invalid` holds an `InvalidToken`, whose `kind()` is an
`InvalidTokenKind`: which check refused the token (`Expired`, `BadSignature`,
`WrongAudience`, `KeySetUnavailable`, ...). `kind().as_str()` is a stable,
low-cardinality `snake_case` label, so it can go straight into a metrics
label; the human-readable `detail()` cannot (it is unbounded, and for logs
only). `on_reject` sees every refusal, so it is one place to count them:

```rust
use std::sync::Arc;

use axum::response::IntoResponse;
use oauth_resource_server::axum::{AuthLayer, AuthLayerError, RejectContext};
use oauth_resource_server::{InvalidTokenKind, OAuthValidator, TokenRejection};

/// Stand-in for your metrics library's counter.
fn count_refusal(reason: &'static str) {
    let _ = reason;
}

fn layer(oauth: Arc<OAuthValidator>) -> Result<AuthLayer, AuthLayerError> {
    AuthLayer::builder()
        .oauth(oauth)
        .on_reject(|cx: RejectContext<'_>| {
            let reason = match cx.rejection {
                TokenRejection::Missing => "missing",
                TokenRejection::InsufficientScope => "insufficient_scope",
                TokenRejection::Invalid(invalid) => {
                    if invalid.kind() == InvalidTokenKind::KeySetUnavailable {
                        // The authorization server is unreachable: an outage to
                        // alert on, not junk traffic.
                        tracing::error!(detail = %invalid, "signing keys unavailable");
                    }
                    invalid.kind().as_str()
                }
                _ => "other",
            };
            count_refusal(reason);
            cx.status.into_response()
        })
        .build()
}
```

The same `TokenRejection` comes back from `authenticate` and
`OAuthValidator::validate` on any other stack. Every kind is a 401
`invalid_token`: the kind never changes the response. The labels, and which
kind a given refusal carries, are stable across releases (a new kind may be
added in a minor release, so match with a wildcard arm); the detail text is
not.

With the `metrics` feature the crate counts every decision itself, with the
same labels (`oauth_rs_requests_total{stage, outcome, mechanism, reason}`), so a
callback like this one is needed only for a metrics library the facade does
not reach; see [Observability](#observability).

**Without OAuth**, a 401 carries `WWW-Authenticate: Bearer error="invalid_token"`
(`axum::DEFAULT_STATIC_CHALLENGE`), because RFC 9110 §15.5.2 requires every 401
to carry a challenge. `AuthLayerBuilder::static_challenge` sets another value,
such as `Bearer realm="my-api"`, or `None` to send no challenge at all and keep
whatever your callback set. `None` departs from RFC 9110; use it only to keep
an existing API's responses unchanged.
[`examples/multiple_sources.rs`](https://github.com/St0nefish/oauth-resource-server/blob/master/examples/multiple_sources.rs)
combines this with several sources and runs without network.

### CORS for browser-based clients

A browser-based client — a web app calling your API directly with `fetch`, or
an MCP client running in a browser — needs two things this crate does not add
for you:

1. **CORS on every route the browser calls**, including the metadata route,
   or the browser's preflight `OPTIONS` request fails before your handler
   ever runs.
2. **`Access-Control-Expose-Headers: WWW-Authenticate`**, or the browser
   receives the header on the wire but hides it from JavaScript:
   `Response.headers.get('WWW-Authenticate')` returns `null`, and the client
   cannot read `resource_metadata` off a 401 to start its authorization flow.

Add [`tower-http`](https://docs.rs/tower-http)'s `CorsLayer` as the outermost
layer, so it also covers the metadata route and preflight requests to routes
behind `AuthLayer`. A browser-based **MCP** client additionally needs the
Streamable HTTP transport's own headers and methods allowed, not just
`Authorization`:

```rust
use axum::Router;
use axum::body::Body;
use axum::http::header::{
    AUTHORIZATION, CONTENT_TYPE, HeaderName, InvalidHeaderValue, WWW_AUTHENTICATE,
};
use axum::http::{HeaderValue, Method, Request};
use tower::ServiceExt;
use tower_http::cors::CorsLayer;

// Streamable HTTP headers a browser-based MCP client's requests and
// responses need CORS to cover, beyond `Authorization`/`Content-Type`:
static MCP_SESSION_ID: HeaderName = HeaderName::from_static("mcp-session-id");
static MCP_PROTOCOL_VERSION: HeaderName = HeaderName::from_static("mcp-protocol-version");
static LAST_EVENT_ID: HeaderName = HeaderName::from_static("last-event-id");

fn cors_for(client_origin: &str) -> Result<CorsLayer, InvalidHeaderValue> {
    Ok(CorsLayer::new()
        .allow_origin(HeaderValue::from_str(client_origin)?)
        // `DELETE` is how an MCP client ends a session.
        .allow_methods([Method::GET, Method::POST, Method::DELETE, Method::OPTIONS])
        .allow_headers([
            AUTHORIZATION,
            CONTENT_TYPE,
            // The MCP protocol version the client negotiated.
            MCP_PROTOCOL_VERSION.clone(),
            // The session id the client must echo back on every request.
            MCP_SESSION_ID.clone(),
            // SSE stream resumption after a dropped connection.
            LAST_EVENT_ID.clone(),
        ])
        // `WWW-Authenticate` so the client's JavaScript can read a
        // challenge; `Mcp-Session-Id` so it can read the session id the
        // server assigned on `initialize` (both are otherwise invisible to
        // `fetch`, per the CORS-safelisted response header list).
        .expose_headers([WWW_AUTHENTICATE, MCP_SESSION_ID.clone()]))
}

fn with_cors(app: Router, client_origin: &str) -> Result<Router, InvalidHeaderValue> {
    Ok(app.layer(cors_for(client_origin)?))
}

fn header<'a>(headers: &'a axum::http::HeaderMap, name: &str) -> &'a str {
    headers.get(name).unwrap().to_str().unwrap()
}

#[tokio::main]
async fn main() {
    let app = with_cors(Router::new(), "https://client.example.com").unwrap();

    // Drive an actual preflight `OPTIONS` request through the layered
    // router, so this snippet is exercised rather than only compiled.
    let preflight = Request::builder()
        .method(Method::OPTIONS)
        .uri("/mcp")
        .header("origin", "https://client.example.com")
        .header("access-control-request-method", "POST")
        .header(
            "access-control-request-headers",
            "authorization,content-type,mcp-protocol-version,mcp-session-id,last-event-id",
        )
        .body(Body::empty())
        .unwrap();
    let response = app.clone().oneshot(preflight).await.unwrap();
    assert!(response.status().is_success());

    let allow_headers =
        header(response.headers(), "access-control-allow-headers").to_ascii_lowercase();
    for h in [
        "authorization",
        "content-type",
        "mcp-protocol-version",
        "mcp-session-id",
        "last-event-id",
    ] {
        assert!(allow_headers.contains(h), "missing {h}");
    }
    let allow_methods = header(response.headers(), "access-control-allow-methods");
    for m in ["GET", "POST", "DELETE", "OPTIONS"] {
        assert!(allow_methods.contains(m), "missing {m}");
    }

    // `Access-Control-Expose-Headers` is sent on the actual response, not
    // the preflight.
    let actual = Request::builder()
        .method(Method::POST)
        .uri("/mcp")
        .header("origin", "https://client.example.com")
        .body(Body::empty())
        .unwrap();
    let response = app.oneshot(actual).await.unwrap();
    let expose_headers =
        header(response.headers(), "access-control-expose-headers").to_ascii_lowercase();
    assert!(expose_headers.contains("www-authenticate"));
    assert!(expose_headers.contains("mcp-session-id"));
}
```

No `allow_credentials` is needed here: a bearer token your JavaScript sets in
the `Authorization` header is not a CORS credential (a cookie or
browser-managed HTTP auth would be). Use an explicit origin, as above, rather
than a wildcard — and never combine a wildcard `allow_origin` with
`allow_credentials(true)` at all; the Fetch spec forbids it.

### Readiness and liveness probes

`OAuthValidator::is_ready()` is true once at least one signing key is held;
`OAuthValidator::key_set_status()` returns the detail (key count, the JWKS URL
in use, when a refresh was last attempted and last succeeded, and the last
refresh error). Neither does any I/O or waits on a refresh in flight, so a
probe can poll them as often as it likes. `refresh_now()`, by contrast,
fetches every time: keep it out of probes.

```rust
use std::sync::Arc;

use axum::{Router, extract::State, http::StatusCode, routing::get};
use oauth_resource_server::OAuthValidator;

/// Readiness: this process can validate a token, because it holds at least
/// one signing key.
async fn ready(State(oauth): State<Arc<OAuthValidator>>) -> StatusCode {
    if oauth.is_ready() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

/// Liveness: the process is up and answering. Nothing about the
/// authorization server belongs here.
async fn live() -> StatusCode {
    StatusCode::OK
}

/// Merge these OUTSIDE the auth layer, like `metadata_router`: a probe
/// carries no token. For the same reason the handlers take no `Credential`
/// or `AuthorizedToken` extractor, which answers 500 on a route no
/// `AuthLayer` covers.
fn probes(oauth: Arc<OAuthValidator>) -> Router {
    Router::new()
        .route("/readyz", get(ready))
        .route("/livez", get(live))
        .with_state(oauth)
}
```

- **Readiness means keys are held.** A process with no key refuses every token
  with a 401, so it should not be sent traffic yet. Once ready, it stays
  ready: a failed refresh keeps the keys already held, so an identity-provider
  outage after startup does not flip it back (tokens signed by those keys
  still validate). If the first load fails, the background task retries after
  5 s, doubling to at most 5 minutes, until keys load; that schedule, not
  request traffic, is what makes the process ready once the identity provider
  is reachable.
- **A seeded validator is ready before it has talked to anyone.** With
  `initial_jwks`, `is_ready()` is true from the moment the validator is
  built, before any contact with the authorization server
  (`key_set_status().last_success` stays `None` until a fetch succeeds). The
  seeded keys are withdrawn only by a successful fetch that yields at least
  one usable key; a failed or empty fetch keeps them.
- **Gating on `/readyz` needs `spawn_background_refresh()`** (or at the very
  least a `refresh_now()` at startup). Without it keys are loaded only when a
  request brings a token, and a process that is not ready receives no
  requests: it would stay not-ready forever.
- **Liveness must not depend on the identity provider.** A liveness failure
  restarts the process, and a restart cannot fix an unreachable identity
  provider: it throws away keys that were still good, and every replica
  restarting at once during an outage turns the provider's problem into a
  full outage of your service too, followed by a burst of key fetches as they
  all come back.
- `KeySetStatus::last_error`'s `Display` names the issuer and JWKS URLs
  (with any userinfo or query redacted, as in `KeySetStatus::jwks_uri`) and
  repeats upstream error text: fine for logs and an internal status page. On
  a public endpoint, report `RefreshError::kind()` (`discovery`, `fetch`,
  `parse`, `no_usable_keys`) instead.

## Observability

Every authentication decision is logged with a fixed set of structured
fields, validation and key refreshes run in tracing spans, and the optional
`metrics` feature counts both. The field names, span names, metric names and
every value listed below are **stable: covered by semver** like the public
API. Renaming one, or moving an outcome from one value to another, is a
breaking change; adding a value (a new `InvalidTokenKind` label, say) is not.
Message text stays unstable (see [MSRV and semver policy](#msrv-and-semver-policy)),
so build dashboards and alerts on these fields, never on the sentence.

No field, span or label ever carries a token, a secret, a claim value, a URL
query or a request body: every value comes from a closed set, except the
bounded ones called out below.

The log fields and `oauth_rs_requests_total` come from the layers,
`RequireScopes`, `McpToolScopes` and the axum extractors. An application
that calls the framework-free `authenticate()` or `OAuthValidator::validate`
itself gets the spans and the key-set metrics, but no `auth.*` fields and no
request counts: it logs and counts its own decisions.

### Log fields

Each auth-outcome event of both layers, `RequireScopes`, `McpToolScopes`
and the axum extractors (`AuthorizedToken`, `Credential`,
`StaticTokenMatch`, `Scoped`) carries these fields next to its existing ones
(`path`, `reason`, `required`, ...), which are unchanged:

| Field | Values | Present on |
|---|---|---|
| `auth.outcome` | `accepted`, `rejected`, `passed_through` | every auth-outcome event |
| `auth.mechanism` | `static`, `oauth`, `none` | every auth-outcome event |
| `auth.reason` | an `InvalidTokenKind::as_str()` label (`too_large`, `not_jwt`, `malformed_header`, `critical_header`, `algorithm_not_allowed`, `type_not_allowed`, `key_not_found`, `key_set_unavailable`, `malformed_token`, `bad_signature`, `expired`, `not_yet_valid`, `wrong_issuer`, `wrong_audience`, `missing_claim`, `malformed_claim`, `sender_constrained`, `client_not_allowed`, `token_too_old`, `claim_mismatch`, `static_token_mismatch`, `no_mechanism`, `oauth_token_required`, `static_token_required`, `other`), `missing`, `insufficient_scope`, or `misconfigured` | `rejected` only |
| `auth.status` | `401`, `403`, `500` (an integer) | `rejected` only |
| `auth.static_label` | the matched static token's label (1–64 visible ASCII characters, validated by `StaticTokens::with`) | an accepted static token with a label |

`auth.mechanism` names the credential that was judged: `static` for a static
token (accepted, refused by a scope requirement, or not matching on a
static-only layer), `oauth` for an OAuth access token (including a
credential that was neither, when OAuth is configured: the refusal comes from
the validator), and `none` when no credential was presented or none could be
checked. `misconfigured` marks the `error`-level "Server misconfiguration"
events: wirings no request can satisfy, such as a route no layer covers, a
required extractor or scope behind `allow_unauthenticated` (with no enforcing
layer around it), an `AuthorizedToken` or `Scoped` extractor or scopes behind
a layer with no validator, and a `StaticTokenMatch` extractor behind a layer
with no static token.

The events, at the levels the module docs list (targets
`oauth_resource_server::axum` and `oauth_resource_server::http_layer`):

| Message | Level | `auth.outcome` |
|---|---|---|
| `OAuth bearer auth accepted` | `debug` | `accepted` |
| `Static bearer auth accepted` | `debug` | `accepted` |
| `No credential presented; optional auth passes the request through` | `debug` | `passed_through` |
| `No bearer credential presented` | `debug` | `rejected` (`missing`, with OAuth configured) |
| `OAuth bearer auth rejected` / `Bearer auth rejected` | `warn` | `rejected` (including a layer's 403 `insufficient_scope` for the validator's own required scopes, which the validator also logs at `info`: `OAuth token is valid but lacks the required scope`) |
| `The credential lacks the scopes this route requires` / `… this handler requires` | `info` | `rejected` (`insufficient_scope`, 403) |
| `Server misconfiguration: …` | `error` | `rejected` (`misconfigured`) |

An `allow_unauthenticated` layer logs nothing per request (the `metrics`
feature counts it as `passed_through`). A refusal now reads:

```text
WARN oauth_resource_server::axum: OAuth bearer auth rejected path=/v1/things reason=Invalid(InvalidToken { kind: Expired, detail: "token rejected: ExpiredSignature" }) auth.outcome="rejected" auth.mechanism="oauth" auth.reason="expired" auth.status=401
```

### Spans

| Span | Level, target | Fields |
|---|---|---|
| `oauth_rs.validate` | `debug`, `oauth_resource_server::validator` | `kid`, `alg`, `auth.outcome` (`accepted`, `rejected`), `auth.reason` |
| `oauth_rs.validate_cached` | `debug`, `oauth_resource_server::validator` | as above; `auth.outcome` is also `needs_key_fetch` (the cache-only first pass found no key, and `oauth_rs.validate` follows) |
| `oauth_rs.jwks_refresh` | `info`, `oauth_resource_server::jwks` | `jwks.host`, `result` (`success`, `discovery`, `fetch`, `parse`, `no_usable_keys`), `keys` (held afterwards) |
| `oauth_rs.jwks_discovery` | `info`, `oauth_resource_server::jwks` | `issuer.host`, `jwks.host`, `result` (`success`, `discovery`) |

`kid` and `alg` come from the token's **unverified** header, so they are
attacker-chosen: they are cut to 128 characters and every character outside
printable ASCII is escaped (`\u{1b}`), so no control character, ANSI escape
or bidi override reaches a terminal or a log store raw, whatever the
subscriber. They are recorded only for a credential under the 16 KiB cap
that has three segments. `alg` is the crate's own label (`RS256`, `EdDSA`,
...) when it names an algorithm this crate knows; otherwise, and whenever
the header cannot be parsed at all (`alg: none`, `HS256`, an unknown name),
both are the raw strings from the header's JSON, bounded and escaped the
same way — absent only when the header is not base64url JSON or the member
is not a string. The hosts are the host alone, never a scheme, port, path,
credential or query. A refresh a request triggers is a child of that
request's `oauth_rs.validate` span, so a trace shows a request waiting on a
slow authorization server. When a span's level is disabled nothing is
formatted or allocated for it: the validation path makes the same
allocations as without the spans.

### Metrics (feature `metrics`)

With the `metrics` feature, this crate reports through the
[`metrics`](https://docs.rs/metrics) facade; install any recorder or exporter
(`metrics-exporter-prometheus`, say) in your application. Without the
feature there is no `metrics` dependency and nothing is recorded.

| Metric | Type | Labels |
|---|---|---|
| `oauth_rs_requests_total` | counter | `stage` (`layer`, `route`, `handler`), and `outcome`, `mechanism`, `reason` with the log fields' values; `reason` is `none` for `accepted` and `passed_through` |
| `oauth_rs_jwks_refresh_total` | counter | `issuer_host`, and `result`: `success`, `discovery`, `fetch`, `parse`, `no_usable_keys` |
| `oauth_rs_jwks_keys` | gauge | `issuer_host`: the usable keys that validator holds, set when it is built (so keys seeded with `initial_jwks` show at once) and after every refresh |

**`oauth_rs_requests_total` counts decisions, not requests.** `stage` says
which check decided: `layer` is either authentication layer's admission
(`AuthLayer`, `HttpAuthLayer`, an `allow_unauthenticated` one included),
exactly one per request per layer, so `stage="layer"` is the request count;
`route` is a refusal by `RequireScopes` or `McpToolScopes`; `handler` is a
refusal by an axum extractor (`AuthorizedToken`, `Credential`,
`StaticTokenMatch`, `Scoped`). A request a layer accepts and a route then
refuses counts once under `layer` (`accepted`) and once under `route`
(`rejected`). Route and handler checks count only refusals.

`issuer_host` is the configured issuer's host alone (no scheme, port, path,
credential or query): one value per validator, bounded by your
configuration, never by traffic. Two validators for the same host share a
series. The names are also constants in the `observability` module, whose
`describe_metrics()` registers HELP text and units with the installed
recorder. The `oauth_rs_` prefix is
fixed rather than configurable: a stable name is what dashboards and alerts
key on, and an exporter or Prometheus' `metric_relabel_configs` can still
rename it.

Some queries (Prometheus):

```text
# Refusals per second by stage and reason, leaving out first-contact 401s.
sum by (stage, reason) (rate(oauth_rs_requests_total{outcome="rejected", reason!="missing"}[5m]))

# Share of requests the layer refused because the signing keys could not be
# loaded. Both sides are `stage="layer"`: counts are per decision, and only
# the layer stage sees every request exactly once.
sum(rate(oauth_rs_requests_total{stage="layer", reason="key_set_unavailable"}[5m]))
  / sum(rate(oauth_rs_requests_total{stage="layer"}[5m]))

# Alert: a key refresh failing, or no signing key held at all, per issuer.
sum by (issuer_host) (increase(oauth_rs_jwks_refresh_total{result!="success"}[1h])) > 0
oauth_rs_jwks_keys == 0
```

## Configuration reference

`OAuthConfig` is the unvalidated input. `OAuthConfig::resolve` checks it and
returns a `ResolvedOAuthConfig`, which is what the validator is built from.
With the `serde` feature every field is optional in the input and unknown keys
are refused. The names below are bare field names; `KeyNaming` decides how
error messages spell them (`KeyNaming::Dotted("oauth")` gives `oauth.issuer`,
`KeyNaming::Env("MYAPP_OAUTH_")` gives `MYAPP_OAUTH_ISSUER`).

| Field | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | `bool` | `false` | Master switch. While `false`, `resolve` returns `Ok(None)` and checks nothing else. |
| `issuer` | `String` | required | The authorization server's issuer identifier. Compared byte for byte with each token's `iss` and published in the metadata document. Copy it from the server's discovery document, including any trailing slash. Must be an absolute URL with no query, fragment, space, control or non-ASCII character, and `https` (RFC 8414 §2) unless its host is loopback or `allow_insecure_http` is set, however it is spelled (`http:/host` is plain `http` too). Write it `https://host/…`: a spelling the URL parser has to repair (`https:/host`, a `\` in the host) is accepted but logged as a startup `warn`, and can never match a token's `iss`. |
| `jwks_uri` | `Option<String>` | `None` | Where to fetch the signing keys. When absent or blank, it is discovered from the issuer's metadata (OpenID Connect Discovery, then RFC 8414), and the discovered document's `issuer` must equal `issuer` exactly. Same URL rules as `issuer`, except that a query is allowed. |
| `audience` | `String` | required, unless `audiences` is set | A value the token's `aud` must contain. There is no default; see [Audience](#audience-which-value-to-configure). |
| `audiences` | `Vec<String>` | `[]` | More accepted audiences. A token matching any configured value passes. Useful while migrating from one audience to another. |
| `resource` | `String` | required | This API's public URL, e.g. `https://api.example.com/v1`. Published as `resource` in the metadata and used to build the metadata URL. Not compared with `aud` unless you also list it in `audience` or `audiences`. Same URL rules as `issuer` (`https` per RFC 9728 §1.2: clients send their bearer tokens to it). |
| `required_scope` | `Option<String>` | `None` | A scope every token must carry, or it gets 403. One RFC 6749 §3.3 scope-token (printable ASCII, no space, `"` or `\`), matched exactly and case-sensitively. An explicit empty value is an error, not "no scope". |
| `required_scopes` | `Vec<String>` | `[]` | More scopes every token must carry: all of them, together with `required_scope`. With neither set there is no scope check at all, which `resolve` accepts only with `require_at_jwt` or `allow_unscoped_tokens`; see [ID tokens](#id-tokens-and-the-lenient-typ-default). |
| `scopes_supported` | `Option<Vec<String>>` | `None`, which resolves to the required scopes | The scopes advertised in the metadata document and in the 401 challenge. Declarative only; each entry a scope-token. **List every required scope here** if you set it: clients request what is advertised, and a required scope they are not told about means 403 on every call. An explicit `[]` advertises nothing: the metadata omits `scopes_supported` (RFC 9728 §3.2) and the 401 names the required scopes instead. **This default is identical on the `serde` and `env` paths** — `resolve` applies it either way, so a serde user who sets only `required_scope` gets the same advertised scopes an env user does. The one path-specific difference is in [Environment variables](#environment-variables): the `env` loader cannot express an explicit empty list. |
| `scope_claims` | `Vec<String>` | `["scope", "scp"]` | The claims scopes are read from. Each is read as a space-delimited string or an array of strings, and the results are combined. Must not be empty. |
| `principal_claims` | `Vec<String>` | `["preferred_username", "sub"]` | Claims tried in order to name the caller in logs (`AuthorizedToken::principal`). `email` is left out so addresses do not reach logs unless you add it. |
| `algorithms` | `Vec<String>` | `RS256 RS384 RS512 PS256 PS384 PS512 ES256 ES384 EdDSA` | The signature algorithms a token may use, as case-sensitive JWS names. `HS256`, `HS384`, `HS512` and `none` are always refused. A JWKS key on a curve the verifier cannot use (P-521, whose `ES512` `ring` does not verify) or not meant for signatures (X25519, X448) is skipped whatever this lists, as is an RSA key whose modulus is not 2048 to 8192 bits. |
| `leeway_secs` | `u64` | `60` | Clock-skew allowance for `exp` and `nbf`, and for `max_token_age_secs`' `iat` checks. At most `MAX_LEEWAY_SECS` (`300`); a larger value is an error, not clamped. |
| `require_at_jwt` | `bool` | `false` | Require the token header's `typ` to be `at+jwt` (or `application/at+jwt`), as RFC 9068 §4 requires. Off is a deliberate, documented deviation; see [ID tokens](#id-tokens-and-the-lenient-typ-default). Turn it on if your server emits it. |
| `allow_unscoped_tokens` | `bool` | `false` | Accept a config with no required scope and `require_at_jwt` off. Without it, `resolve` refuses that combination, because it would accept OIDC ID tokens as access tokens. |
| `allow_insecure_http` | `bool` | `false` | Accept a plain-`http` `issuer`, `jwks_uri` or `resource` on a non-loopback host, for an in-cluster address on a trusted network. Also governs a `jwks_uri` discovered from a plain-`http` issuer and every redirect followed while fetching keys. Loopback hosts never need it. |
| `accept_static_bearer` | `bool` | `true` | Whether a separately configured static token keeps working while OAuth is on. Read only by `static_token_policy`. |
| `allowed_client_ids` | `Vec<String>` | `[]` (no check) | The OAuth clients whose tokens are accepted. A token's client is its `client_id` claim (RFC 9068 §2.2), else its `azp` (the first that is a non-empty string, as `AuthorizedToken::client_id` reads it), and it must equal an entry byte for byte; `client_id` wins, so a listed `azp` does not rescue an unlisted `client_id`, and a `client_id` that is present but empty or not a string is refused rather than read past. No client, or another one, is a 401 (`ClientNotAllowed`). Use it where the audience is shared by several clients (see [Client identity](#what-is-not-covered)). No blank entries. |
| `max_token_age_secs` | `Option<u64>` | `None` (no check) | Refuse a token issued more than this many seconds ago (`now - iat`, plus `leeway_secs` of slack): `TokenTooOld`. With it set, `iat` is required (`MissingClaim`) and must be a NumericDate (`MalformedClaim`), and an `iat` more than `leeway_secs` in the future is `NotYetValid`. `1` to `MAX_TOKEN_AGE_SECS` (2 592 000, 30 days); `0`, or more than that, is an error. All 401. |
| `required_claims` | map of claim name to value | `{}` (no check) | Claims every token must carry with a value: the token's claim must equal it (JSON equality, so `"1"` is not `1`), or be an array containing it (for `groups`, `roles` and the like). A missing claim is `MissingClaim`; any other value (including `null`, an object, or an array without it) is `ClaimMismatch`; both 401. Values must be a string, number or boolean (an array may later mean "any of", additively); naming a scope claim or `azp`/`client_id` logs a startup `warn`; top-level claims only (no paths into nested objects); names must not be blank nor one of `iss`, `aud`, `exp`, `nbf`, `iat` and `cnf`, which this crate already checks. |

`resolve` is all-or-nothing. An enabled config either resolves completely or
fails with a `ConfigError` listing **every** problem, each naming its setting:

```text
oauth.enabled is true but the OAuth config is not usable:
  - these required settings are empty: oauth.issuer, oauth.resource, oauth.audience (or oauth.audiences). Set issuer to ...
  - oauth.leeway_secs 3600 is over the 300-second cap — leeway is for clock drift, not for extending token lifetimes
Fix these, or set oauth.enabled: false.
```

The same problems are available structured, so code can react to them without
reading the sentences. `ConfigError::problem_details()` returns
`ConfigProblem`s, each with a `kind()` (a `#[non_exhaustive]` `ProblemKind`,
with a stable `as_str()` label), the `keys()` it names (already spelled through
your `KeyNaming`) and its `message()`:

```rust
use oauth_resource_server::{KeyNaming, OAuthConfig, ProblemKind};

let err = OAuthConfig { enabled: true, leeway_secs: 3600, ..OAuthConfig::default() }
    .resolve(KeyNaming::Env("MYAPP_OAUTH_"))
    .unwrap_err();
for problem in err.problem_details() {
    match problem.kind() {
        ProblemKind::MissingRequired => eprintln!("set one of {:?}", problem.keys()),
        ProblemKind::LeewayTooLarge => eprintln!("lower {}", problem.keys()[0]),
        _ => eprintln!("{problem}"), // keep a wildcard arm: the enum grows
    }
}
```

`ConfigError::problems` (plain strings) stays for compatibility and is filled
from the same list, in the same order. Editing that field in place does not
update `problem_details()`. `ConfigError::from_problems` builds an error from
`ConfigProblem`s, and `ConfigProblem::from(String)` (kind `Other`) lets your own
loader mix its problems in; `ConfigError::new` still takes plain strings.

`ResolvedOAuthConfig` has one setting you may want to set by hand that
`OAuthConfig` does not: `resource_name`, a human-readable name published in the
metadata document. Set it on the resolved value if you want one. (It also
carries `key_naming`, the owned copy of the `KeyNaming` it was resolved with,
which the validator's log lines use; and its `required_scopes` holds the union
of `required_scope` and `required_scopes`.)

### Fetch options (code, not config)

How the validator reaches the authorization server is set on
`OAuthValidator::builder(&resolved)`, not in `OAuthConfig` (whose fields are a
config format; these are wired in code). `OAuthValidator::new(&resolved)` is
the builder with nothing set. Every option is checked by `build()`, and a
refused one is a `ValidatorError`, never silently dropped.

| Builder method                    | Default                                                                                                                                          | Meaning                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `add_root_certificate_pem(&[u8])` | none                                                                                                                                             | Adds the certificate(s) in a PEM file (one, or a bundle) as TLS trust anchors, on top of the TLS feature's own roots. Works with every TLS feature. Pass CA certificates only. Error: `ValidatorError::InvalidRootCertificate` (no certificate in it, one the backend cannot use, or a private-key block).                                                                                                                                                                 |
| `proxy(url)`                      | reqwest's own proxy handling (environment variables, and system settings where reqwest's `system-proxy` feature is on), for non-loopback fetches | An explicit `http://` or `https://` proxy for every non-loopback metadata and JWKS fetch, `user:password@` sent as proxy Basic auth. Setting it turns the environment and system proxies off, `NO_PROXY` included. No path, query, fragment, SOCKS scheme, space, control or non-ASCII character, and no credential in a plain-`http` proxy URL on a non-loopback host unless `allow_insecure_http` is set. Error: `ValidatorError::InvalidProxy` (never showing the URL). |
| `fetch_timeout(Duration)`         | `DEFAULT_FETCH_TIMEOUT`, 10 s                                                                                                                    | Timeout for one metadata or JWKS request, connect through last body byte. `MIN_FETCH_TIMEOUT` (1 s) to `MAX_FETCH_TIMEOUT` (60 s); zero or anything outside is `ValidatorError::FetchTimeoutOutOfRange`.                                                                                                                                                                                                                                                                   |
| `initial_jwks(&str)`              | none                                                                                                                                             | A JWK Set (`{"keys": [...]}`) the key cache starts with, parsed and narrowed exactly like a fetched one (256 KiB and 64-key caps, no `oct`/`use: enc`/non-`verify` key, each key limited to the configured algorithms). Refreshed normally: the first successful refresh replaces it, a failed one keeps it. Error: `ValidatorError::InvalidInitialJwks`.                                                                                                                  |

Every fetch whose URL is on a loopback host (`localhost`, `*.localhost`,
`127.0.0.0/8`, `::1`) uses a separate client with no proxy of any kind, so a
loopback fetch never goes through a proxy, explicit or from the environment.
`localhost` and `*.localhost` are recognized **by name**, so that client also
resolves every name itself, to `::1` and `127.0.0.1` (keeping the URL's
port), never through DNS: some resolvers (musl, glibc without
nss-myhostname, some container DNS servers) forward `*.localhost` upstream,
where whoever controls that DNS could otherwise receive a cleartext,
proxy-free key fetch. A fetch that starts on a loopback URL may not be
redirected off loopback at all.
Every other fetch uses reqwest's own proxy handling untouched: the
`HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY`/`NO_PROXY` environment variables (and,
on macOS and Windows, the system proxy settings when reqwest's `system-proxy`
feature is on in your build) exactly as a plain reqwest client applies them —
unless `proxy(url)` is set, which turns all of those off.

With `initial_jwks`, `is_ready()` is true from the start and
`key_set_status()` reports the seeded keys in `keys`, while `last_attempt` and
`last_success` stay `None` until a real fetch (`keys > 0` with no
`last_success` means "seeded, not yet confirmed by the authorization
server"). Seeded keys count as held, so a failed background pass retries on
the held-keys schedule (a minute, backing off to an hour), not the keyless
5-second one. To seed from a file, pass `std::fs::read_to_string(path)?`.

```rust
use std::time::Duration;

use oauth_resource_server::{OAuthValidator, ResolvedOAuthConfig, ValidatorError};

fn build_validator(resolved: &ResolvedOAuthConfig) -> Result<OAuthValidator, ValidatorError> {
    OAuthValidator::builder(resolved)
        .proxy("http://proxy.example.com:3128")
        .fetch_timeout(Duration::from_secs(5))
        .build()
}
```

### Embedding `OAuthConfig` in your own config

`OAuthConfig` derives `#[serde(deny_unknown_fields)]` (feature `serde`) so a
typo'd or renamed setting fails at startup instead of being silently
ignored. **Nest it under its own field in your application's config struct;
do not `#[serde(flatten)]` it.**

`#[serde(flatten)]` buffers the input through a generic value first, and
that buffering is what makes `deny_unknown_fields` stop firing for the
struct it is applied to: a field neither struct recognizes is silently
dropped instead of failing to deserialize at all, defeating the whole point
of the attribute. (This happens before `OAuthConfig::resolve` ever runs, so
it is a plain serde deserialization error from your format crate, not this
crate's own `ConfigError`.) This is a general serde limitation, not specific
to this crate — see [serde's own `flatten`
docs](https://serde.rs/attr-flatten.html).

```rust
use oauth_resource_server::OAuthConfig;
use serde::Deserialize;

#[derive(Deserialize, Default)]
struct FlattenedConfig {
    #[serde(flatten)]
    oauth: OAuthConfig,
}

#[derive(Debug, Deserialize, Default)]
struct NestedConfig {
    #[serde(default)]
    oauth: OAuthConfig,
}

// Flattened: a typo'd field (`isuer` for `issuer`) is silently accepted.
// `deny_unknown_fields` does not fire through `#[serde(flatten)]`.
assert!(serde_yaml_ng::from_str::<FlattenedConfig>("isuer: x\n").is_ok());

// Nested instead of flattened: the same typo is refused, as intended.
let err = serde_yaml_ng::from_str::<NestedConfig>("oauth:\n  isuer: x\n").unwrap_err();
assert!(err.to_string().contains("unknown field `isuer`"));
```

### Environment variables

The `env` feature's `oauth_config_from_env(prefix)` reads each field from
`<PREFIX><FIELD>` in upper case (`MYAPP_OAUTH_REQUIRED_SCOPES`), and every one
of them also accepts the `_FILE` form. It differs from the serde path in these
ways:

- **Whether OAuth is on is inferred.** `<PREFIX>ENABLED` may be `true` or
  `false`. When it is unset, OAuth is on if any of `ISSUER`, `JWKS_URI`,
  `AUDIENCE`, `AUDIENCES` or `RESOURCE` is set, and off (`Ok(None)`)
  otherwise.
- **`SCOPES_SUPPORTED` cannot be explicitly empty.** An empty value reads as
  unset, so it always resolves to the required scopes, exactly as an omitted
  `scopes_supported` does on the serde path — `OAuthConfig::resolve` applies
  that default the same way regardless of which path produced the config.
  This is the only behavioral difference between the two paths for this
  setting: neither defaults it to the required scopes "instead of" the
  other leaving it empty.
- **Lists** (`AUDIENCES`, `REQUIRED_SCOPES`, `SCOPES_SUPPORTED`,
  `SCOPE_CLAIMS`, `PRINCIPAL_CLAIMS`, `ALGORITHMS`, `ALLOWED_CLIENT_IDS`) are
  split on whitespace.
- **Booleans** accept exactly `true` or `false`. Anything else is an error, so
  a typo cannot silently read as `false`.
- **`LEEWAY_SECS`** and **`MAX_TOKEN_AGE_SECS`** are decimal integers
  (`MAX_TOKEN_AGE_SECS` unset means no age check).
- **`REQUIRED_CLAIMS`** is one JSON object:
  `MYAPP_OAUTH_REQUIRED_CLAIMS='{"tid": "<tenant id>", "groups": "api-users"}'`.
  Anything but a JSON object is an `EnvParse` problem; an object naming one
  claim twice is `InvalidRequiredClaim`, never "the last one wins" (a config
  file naming one twice fails to deserialize, for the same reason).
- **Values are trimmed.** A variable that is empty after trimming counts as
  unset — except `REQUIRED_SCOPE`: set to whitespace only, it is
  `BlankRequiredScope`, as a blank `required_scope` in a config file is, never
  "no scope". A `_FILE` whose contents are empty after trimming is an error.
  Setting both `VAR` and `VAR_FILE` is an error.
- **A `_FILE` must be a regular file of at most 64 KiB**
  (`env::MAX_SECRET_FILE_BYTES`). A directory, FIFO or device (`/dev/zero`)
  is refused before it is opened (`EnvError::NotAFile`), and a bigger file
  after reading one byte past the limit (`EnvError::FileTooLarge`), so a
  wrong path can neither block startup nor exhaust memory.
- **Every problem is reported at once.** Load and parse problems are listed in
  one `ConfigError` together with the problems `resolve` finds. Loader
  problems have kind `ProblemKind::EnvLoad` (a variable or `_FILE` that could
  not be read) or `ProblemKind::EnvParse` (a value that did not parse), and
  `keys()` names the variables to look at (`VAR` and `VAR_FILE` when both were
  set, `VAR_FILE` when its file could not be used, the variable
  itself for a parse problem); `EnvOAuthConfig::problem_details()` lists them
  before `resolve`. A `problems` entry you edit or add on the loaded value
  reaches the `ConfigError` as `ProblemKind::Other`.

To apply your own defaults before validation, call
`unresolved_oauth_config_from_env`, change the returned `config`, then call
`resolve()` on it.

A static API key is not an `OAuthConfig` field; it is read on its own:

| Function | Variables | Returns |
|---|---|---|
| `secret_from_env(var)` | `<VAR>` or `<VAR>_FILE` | the one key, or `None` |
| `static_tokens_from_env(var)` | the above, plus `<VAR>_NEXT` or `<VAR>_NEXT_FILE` | a `StaticTokens` set: `"current"`, and `"next"` while a rotation is under way (one entry when the two are equal), or `None`; `<VAR>_NEXT` without `<VAR>` is an error |

Both trim values, treat a blank variable as unset, refuse an empty,
oversized or not-a-regular `_FILE`, and refuse a variable set together with
its `_FILE`. See
[Rotating a static API key](#rotating-a-static-api-key-with-zero-downtime).

## Security model

### What is checked, in order

For each candidate credential, `OAuthValidator::validate`:

1. **Refuses what it can from the unverified header, before any key lookup:**
   an empty credential (`Missing`), one over 16 KiB, one that is not three
   dot-separated segments (not a JWT), a header that does not parse (a `kid`
   that is present but not a string, `"kid": null` included, is one), a header
   that lists critical extensions in `crit` (RFC 7515 §4.1.11: this crate
   understands none, so any `crit`, even an empty one, is refused), an `alg`
   not in `algorithms`, and a `typ` that is not an access-token type. Junk
   never causes a request to the authorization server.
2. **Finds the key:** the JWKS entry whose `kid` matches and whose key type can
   produce the token's `alg`. A token with no `kid` uses the only compatible
   key, and is refused if there are several. An unknown `kid` triggers a key
   refetch at most once a minute.
3. **Verifies the signature, `iss`, `aud`, `exp` and `nbf` in one
   `jsonwebtoken::decode` call,** so no claim check can run apart from the
   signature check. `exp`, `iss` and `aud` must be present; `nbf` is checked
   when present; `leeway_secs` applies to both times (and to the `iat` checks
   of `max_token_age_secs`).
4. **Re-checks the claims the decoder does not police:** `iss` must be a
   single string equal to `issuer`, byte for byte (the decoder alone would
   accept an array containing it); a present `nbf` must be a NumericDate, a
   non-negative number (the decoder silently skips anything else, which would
   let a not-yet-valid token through); and a token carrying a `cnf`
   confirmation claim is refused, since it is bound to a DPoP key (RFC 9449)
   or an mTLS certificate (RFC 8705) whose proof this crate cannot check, and
   those RFCs forbid accepting it as a plain bearer token.
5. **Applies the optional claim policy**, each check off unless configured,
   in this order: the client (`client_id`, else `azp`) must be in
   `allowed_client_ids`; `iat` must be no older than `max_token_age_secs`
   (and not in the future); every `required_claims` entry must match. These
   read only claims the signature already covered, and each refusal is a 401
   with its own kind (`ClientNotAllowed`, `TokenTooOld`, `NotYetValid`,
   `MissingClaim`, `MalformedClaim`, `ClaimMismatch`).
6. **Checks scopes.** The token must carry every required scope, or it is
   refused with `InsufficientScope` (403), not 401. A token that fails step 5
   is a 401 whatever its scopes.

The result is an `AuthorizedToken` (`subject`, `principal`, `scopes`, plus the
verified claims and token metadata) or a
`TokenRejection` (`Missing`, `Invalid(InvalidToken)` or `InsufficientScope`;
an `InvalidToken`'s `kind()` names the check that failed).

### Guarantees

- **Algorithm confusion is closed twice.** No configuration can enable HMAC or
  `none`; `Algorithm` has no variant for either. Independently, each key is
  limited to the algorithms its own type, and its declared `alg` if it has
  one, can produce. A token cannot steer an RSA key into an ECDSA check, or
  any key into HMAC. Symmetric (`oct`) keys, `use: enc` keys, and keys whose
  `key_ops` do not include `verify` are never used.
- **Every failure fails closed.** An unreachable server, a malformed key set,
  an unknown `kid` during the refetch cooldown and a TLS failure all mean
  "refuse", never "skip the check". A failed refresh keeps the keys already
  held, so an outage at the authorization server does not also revoke keys
  that are still good. A refetch runs in a task of its own, so a caller that
  disconnects or times out mid-fetch cannot cancel it and leave the cooldown
  spent with no keys loaded.
- **The middleware fails closed by construction.**
  `AuthLayer::builder().build()` (and the tower layer's
  `HttpAuthLayer::builder().build()`, which runs the same check) returns an
  error with neither a static token nor a validator. The only pass-throughs are `AuthLayer::allow_unauthenticated()`
  and a `StaticTokenDecision::Unauthenticated` handed to `AuthLayer::from_decision`
  or `build_with_decision` (which `static_token_policy` returns only with
  `allow_unauthenticated = true`); both must be asked for by name.
- **Optional authentication only skips what was never presented.** An
  `optional()` layer passes a request through only when every value of every
  configured credential header is absent or blank. Blank means empty or
  whitespace, `Bearer` followed by nothing, or another scheme in a `Bearer`
  source. A header value that is not visible ASCII, a non-blank later value
  of a repeated header, any `DPoP`-scheme value, and `Bearer` followed by a
  tab and a token all count as presented. Anything presented gets exactly
  the refusal a non-optional layer sends (401 for an invalid, expired or
  unknown credential, 403 for insufficient scope, with the same challenge and
  `on_reject` body). A caller gains nothing it could not get by leaving its
  credential headers off, so a handler behind an optional layer must treat
  `None` as unauthenticated. `optional()` still needs a static token or a
  validator to build. It also removes any credential an outer layer inserted,
  so `None` after its pass-through is never replaced by an outer layer's
  token.
- **Per-route scopes fail closed.** A layer's `require_scopes`,
  `RequireScopes`, `Scoped` and `McpToolScopes` refuse a token without the
  scopes with 403 and a challenge naming them, and a static token (it has
  none) the same way unless `static_token_bypasses_scopes()` says otherwise.
  `RequireScopes`, `Scoped` and `McpToolScopes` answer 500 (logged at
  `error`) on a route no authentication layer covers, even when they require
  nothing. `McpToolScopes` classifies the body of a request under any
  method, reads at most its body limit (1 MiB by default) and refuses a
  larger body with 413; a body it cannot classify with certainty (not JSON,
  a `tools/call` with no readable tool name, a repeated member, a
  serde_json `$serde_json::private::RawValue`/`Number` token key) needs every
  scope any tool requires, never fewer; a JSON-RPC batch needs every scope
  any of its calls needs; it never logs body content. Its claim clauses
  (`default_claim`, `tool_claim`) follow the same rules — an unclassifiable
  body needs every clause any tool has, a batch every clause any of its
  calls needs, clauses are never merged by claim name — and are refused
  with the same 403 and a challenge naming scopes only (no claim name or
  value in a header; the log names the claim, never a value); a static
  token meets them only with `static_token_bypasses_scopes()`. Its tool names are
  matched **exactly** (see [Per-tool scopes](#per-tool-scopes-mcptoolscopes)):
  an MCP server whose dispatcher normalizes names (case, whitespace) must not
  be put behind it with scopes on some tools and not others.
- **The extractors fail closed.** `Credential` and `AuthorizedToken` refuse a
  request the layer inserted nothing into with that layer's own 401 and
  challenge, built by the same code as its other refusals. On a route no
  `AuthLayer` covers, they and their `Option<..>` forms answer 500 and log at
  `error`. They never read that case as anonymous. A required extractor behind
  `allow_unauthenticated()`, or an `AuthorizedToken` extractor behind a layer
  with no validator, is a 401 no credential can satisfy, and is also logged at
  `error`.
- **Every refusal carries a challenge.** With OAuth configured, every 401 and
  403 carries `WWW-Authenticate` with `resource_metadata`, including a request
  that failed with a static token, since the server cannot tell which
  credential the caller meant. A custom `on_reject` cannot remove it, and a
  config whose challenge would not be a valid header makes
  `AuthLayerBuilder::build` fail rather than send challenge-less 401s (the
  validator itself then logs at `error` and falls back to a minimal
  `Bearer error="…"` challenge — its `scope` only when that is valid, no
  `resource_metadata` — so `refusal()` never returns a header a line break
  could split). With
  only a static token, 401s carry `Bearer error="invalid_token"` unless the
  application opts out with `static_challenge(None)`. The status and the
  challenge are decided in one place: the crate-private decision behind the
  public `refusal()` is the same one the axum layer and the tower layer call,
  so a hand-built integration on `refusal()` and either layer cannot
  disagree about a refusal.
- **Weak configurations are refused, not just logged.** `resolve` refuses a
  plain-`http` `issuer`, `jwks_uri` or `resource` on a non-loopback host, a
  config that would accept ID tokens (no required scope and no `typ` check),
  a scope that is not a valid scope-token, and a URL with a space, control or
  non-ASCII character. Whether a URL is plain `http` is decided on the URL as
  parsed, so `http:/host` or `HTTP:\\host` needs the opt-in exactly as
  `http://host` does. The first two have explicit opt-ins
  (`allow_insecure_http`, `allow_unscoped_tokens`).
- **Network use is bounded.** Only the configured `jwks_uri`, the discovery
  URLs derived from the configured `issuer`, or (with no `jwks_uri` configured)
  the `jwks_uri` that the issuer's own metadata document names are ever
  fetched, plus any redirects from those; nothing in a token influences where
  a request goes. A discovered `jwks_uri` may be on any host the issuer's
  metadata names, but that document is used only when its `issuer` equals the
  configured one byte-for-byte, and it may not downgrade an `https` issuer to
  `http`. Responses are capped at 256 KiB and 64 keys, fetches time out after
  10 seconds (1 to 60 s with `fetch_timeout`), only a `2xx` answer is read,
  at most three redirects are followed, a redirect from `https` to `http` is
  refused, one to plain `http` on a non-loopback host is refused without
  `allow_insecure_http`, and a fetch that starts on a loopback URL may not be
  redirected off loopback (it runs on the proxy-free client). A discovered
  `jwks_uri` whose fetch fails is discovered again on the next refresh, so an
  authorization server that moves its key set is followed without a
  restart.
  None of the [fetch options](#fetch-options-code-not-config) loosens any of
  this, and a key set passed to `initial_jwks` gets the same size cap, key cap
  and per-key checks as a fetched one.
- **Proxies and extra roots do not weaken key integrity.** An `https` fetch
  through a proxy (explicit, or from `HTTPS_PROXY`) is a `CONNECT` tunnel:
  TLS runs end to end to the authorization server and its certificate is
  checked against its host name, so the proxy can neither read nor replace
  the keys. That is why a plain-`http` proxy on a non-loopback host needs no
  opt-in; a plain-`http` fetch through it already needed
  `allow_insecure_http` for its own URL, and a fetch of a loopback URL never
  goes through any proxy, explicit or from the environment. The proxy-free
  client is chosen from the URL a fetch starts at; a redirect from a loopback
  URL to a non-loopback one is refused, so that client never carries a hop
  the operator's proxy should have seen, and it resolves every name to
  loopback itself, so `localhost`/`*.localhost` — exempted by name — never
  reach DNS. One residual: a
  redirect from a non-loopback URL to a loopback one is followed by the
  normal client and, with an environment or system proxy (never an explicit
  one, which skips loopback hosts), can go through it, as it always has.
  Such a hop is either `https` to `https`, where TLS stays end to end and the
  certificate is still checked, or plain `http`, which the redirect policy
  follows only when no `https` URL came before it and which already needed
  `allow_insecure_http` for any non-loopback hop. A credential in a
  plain-`http` proxy URL on a non-loopback host would cross the network in
  cleartext, so `build()` refuses it without `allow_insecure_http` (and logs a
  `warn` with it). The proxy URL never appears unredacted in a log line or
  `Debug`, and a refused one never appears in the error at all.
  A root certificate added with `add_root_certificate_pem` is trusted for any
  host name on these fetches, so whoever holds that CA's private key can
  serve signing keys: add only the CA that issues the authorization server's
  certificate.
- **Secrets stay out of logs.** Tokens and the static tokens are never logged,
  and the `Debug` output of the layer, its builder and the policy decision
  redacts the static token; a `StaticTokens` set prints its count and labels
  only. Labels are not secrets: `StaticTokens::with` accepts only 1 to 64
  visible ASCII characters, so a label is always safe in a log line. `RejectContext`'s `Debug` prints no header
  values, and the layer marks the configured credential headers sensitive on
  the request, so a tracing layer or a handler's `Debug` of the headers shows
  `Sensitive` instead of the token. The token-derived `kid`, `typ`, subject and
  principal are truncated to 128 characters when logged, and the `kid` and
  `alg` span fields (from the unverified header) additionally have every
  character outside printable ASCII escaped; scope values are
  logged in full (on an insufficient-scope refusal at `info`, and on an
  accepted token at `debug`), bounded only by the 16 KiB credential cap.
  Rejection reasons go to the log, never to the client. A credential in the
  `issuer`, `jwks_uri` or `resource` URL (userinfo, or a query) is masked
  (`***@`, `?***`) wherever this crate shows it: every log line, error and
  configuration problem, and the `Debug` output of `OAuthConfig`,
  `ResolvedOAuthConfig`, `EnvOAuthConfig`, `AuthorizedToken`, the validator,
  the layers and their builders. The refused request's URI in a
  `RejectContext` `Debug` is its path, with any query shown as `?***` (a
  client may send its token there, RFC 6750 §2.3); the layers log the path
  only. The RFC 9728 metadata document and the challenges publish
  `issuer` and `resource` as configured.
- **The static token is compared in constant time** (with `subtle`). Its
  length is not hidden. With several static tokens, every candidate is
  compared with every entry, with no early exit once one matches, and the
  matching entry is selected without a data-dependent branch, so the time
  does not depend on which entry matched. It does depend on how many entries
  have the candidate's length (each comparison ends early on a length
  mismatch, as with one token); keys of one fixed length reveal nothing by it.
  A `StaticTokens` set, the layer builders' single static token and the
  `env` loaders' intermediate copies are wiped (`zeroize`) when dropped.
  Strings your code passes in or keeps, `secret_from_env`'s returned
  `String`, a `StaticTokenDecision`'s payload and the process environment
  are not.
- **Configuration is validated at startup,** all of it at once, so a broken
  deployment refuses to start rather than answering 401 to everyone.

### What is not covered

- **Revocation.** A JWT stays valid until `exp`. Revoking it at the
  authorization server does not stop this crate from accepting it, so keep
  access-token lifetimes short.
- **Opaque tokens and introspection.** Only JWT access tokens are accepted;
  there is no RFC 7662 introspection. `OAuthValidator`'s documentation
  describes where it would plug in.
- **Sender constraint.** There is no DPoP (RFC 9449) and no mTLS token binding
  (RFC 8705): whoever holds a bearer token can use it, so protect tokens in
  transit with TLS. A token the authorization server did sender-constrain
  (one carrying `cnf`) is refused, not downgraded to a bearer token. Tokens
  are accepted from headers only (`bearer_methods_supported` is
  `["header"]`), never from query strings or form bodies.
- **Replay.** There is no `jti` tracking: a token is usable until `exp` by
  whoever holds it. Token *age* can be bounded independently of `exp` with
  `max_token_age_secs` (off by default), which limits how long a stolen token
  stays useful when the authorization server issues long-lived ones.
- **Client identity, unless you list the clients.** By default `azp` and
  `client_id` are not checked: any client of the authorization server whose
  tokens carry an accepted `aud` and the required scopes is accepted. That is
  the whole story when the audience identifies this API alone, but not when
  the authorization server stamps an audience shared by many clients (an
  Auth0 API identifier, an Okta custom authorization server's audience, an
  Entra ID app ID URI): then every client granted that API gets in. Set
  `allowed_client_ids` to the clients you mean to serve (it reads
  `client_id`, else `azp`; for a client named in another claim, such as
  Okta's `cid`, require that claim with `required_claims`; see the [provider
  guide](https://github.com/St0nefish/oauth-resource-server/blob/master/docs/providers.md#shared-audiences-restrict-the-clients)), and see
  [Audience](#audience-which-value-to-configure) for what a client_id
  audience means. Any further claim policy (a tenant, a group) can be
  required with `required_claims`.
- **Scope hierarchies.** Every scope check — the validator's, a layer's
  `require_scopes`, `RequireScopes`, `Scoped`, `McpToolScopes` — is an exact,
  all-of match: there is no way to say "`api:write` implies `api:read`".
  Hierarchy-aware checks are the application's (`AuthorizedToken::has_scope`);
  see [Per-route and per-handler
  scopes](#per-route-and-per-handler-scopes).
- **Malformed requests get 401, not 400.** RFC 6750 §3.1 suggests 400
  `invalid_request` for a malformed request; this crate treats anything it
  cannot read as no credential. A request that repeats a credential header
  has only its first value read; the rest are ignored, not refused.
- **Request rate limiting.** Only key refetches are rate-limited. Put your own
  limiter in front if you need one.
- **Live reconfiguration.** Nothing hot-reloads; see [Configuration changes
  need a restart](#configuration-changes-need-a-restart).
- **The trust anchor.** The keys are exactly as trustworthy as the connection
  they arrive over. A plain-`http` issuer or `jwks_uri` (or resource) on a
  non-loopback host is refused at startup, as RFC 8414 §2 and RFC 9728 §1.2
  require `https`, unless you set `allow_insecure_http` for an in-cluster
  address on a network you trust; the validator then still logs a `warn` for
  each such URL. The same rule holds for URLs you did not configure: a
  `jwks_uri` discovered from a (loopback) `http` issuer, or a redirect
  followed while fetching keys, may land on plain `http` on a non-loopback
  host only with `allow_insecure_http`, and is warned about when it does. An
  `https` issuer's `http` `jwks_uri` and an `https`→`http` redirect are
  always refused.
- **One algorithm per key.** RFC 8725 §3.1 says each key is used with exactly
  one algorithm. A JWK that declares its `alg` is held to it. One that does
  not (`alg` is optional in RFC 7517) can verify any allowlisted algorithm
  its type produces; an RSA key without `alg` accepts RS256 through PS512
  under the default allowlist. That is accepted because such a key set gives
  no other way to know the signing algorithm, and no practical attack mixing
  those algorithms on one key is known. The validator logs a `warn` naming the
  `kid` when such a key first appears; narrow `algorithms` to the algorithm
  your server signs with to bind it.
- **A withdrawn key while the key set is unreachable.** Keys are dropped when
  a refresh succeeds without them. If every refresh fails (an outage, or
  someone blocking the fetches), the keys already held stay trusted, with no
  upper bound. That is the price of not turning an authorization-server
  outage into an outage of your API.

### ID tokens and the lenient `typ` default

With `require_at_jwt` off (the default), a token whose header `typ` is
`at+jwt`, `JWT`, or absent passes, and any other type (`dpop+jwt`,
`logout+jwt`, ...) is refused. That departs from RFC 9068 §4, under which a
resource server MUST reject any `typ` other than `at+jwt` or
`application/at+jwt` (RFC 8725 §3.11 recommends the same explicit typing).
The default is lenient because Authentik, Keycloak (by default), Microsoft
Entra ID and Okta emit `JWT` or no `typ` at all, and a strict default would
reject every one of their tokens.

The cost: on servers that put the client_id in `aud` (Authentik and Kanidm,
for example), an OIDC **ID token** issued to the same client also has the
right `iss` and `aud`. Two things keep it out:

- **A required scope.** ID tokens carry no `scope` or `scp` claim, so with the
  default `scope_claims` any required scope refuses them. This is why every
  recipe in the provider guide sets one. If you point `scope_claims` at a
  claim ID tokens do carry, such as `groups`, a required value no longer keeps
  them out.
- **`require_at_jwt: true`**, on servers that emit `typ: at+jwt` (Authelia and
  Kanidm, for example). It is the one check that tells an access token from an
  ID token.

With neither, any token the issuer signs for the audience would be accepted,
ID tokens included, so `resolve` refuses that configuration. If it really is
what you want (an application may need no more than "signed by this issuer
for this audience"), set `allow_unscoped_tokens: true`; the validator still
logs a `warn` when it is built.

### Audience: which value to configure

There is no default and no guessing, because a wrong guess either rejects
every real token or accepts tokens meant for another service. Decode one real
access token (its middle segment is base64url JSON) and look at `aud`. Servers
fall into two groups:

- **Servers that honour RFC 8707 resource indicators or let you configure an
  access-token audience** put the resource URL or an API identifier there.
  Usually that is the same value as `resource`. Authelia with a client
  `audience` behaves this way (verified in a sandbox), as do, according to
  their documentation, Auth0 API identifiers, Okta custom authorization
  servers, Ory Hydra and Logto API resources.
- **Servers that ignore the `resource` parameter and stamp the OAuth
  client_id** need the client_id. Authentik (verified in production) and
  Kanidm (token shape verified) behave this way, as do, according to their
  documentation, Keycloak, Casdoor, Rauthy and Dex. Microsoft Entra ID stamps
  the API application's own client id.

**A client_id audience is weaker, and departs from the specs.** RFC 9068 §4
says the resource server MUST check that `aud` contains an identifier it
expects *for itself*; the MCP authorization spec (2026-07-28, "Token
Handling" and "Access Token Privilege Restriction") says an MCP server MUST
accept only tokens issued specifically for it as the audience (RFC 8707 §2).
A client_id identifies the client, not this API: every token that client
obtains from the authorization server, for any resource, carries the same
`aud`, and all of them pass here. It is sound only when that OAuth client is
**dedicated to this one resource server** and shared with no other API or MCP
server. Wherever your authorization server can stamp a resource URL or API
identifier instead, use that.

To switch from one audience to another without downtime, list both in
`audiences` while you migrate.

## Design rationale

- **Provider differences are configuration, never code.** Authorization
  servers agree on signatures and on `iss`, `aud` and `exp`, and disagree on
  almost everything else: scopes as a `scope` string or an `scp` array, `aud`
  as the client_id or the resource, RS256 or ES256 or EdDSA, `typ: JWT` or
  `at+jwt`, a username or only a UUID `sub`. Each is a config field, and each
  supported shape has a test modeling it. There is no `if provider == ...`
  anywhere.
- **Scopes come from `scope` and `scp` by default, in every shape, combined.**
  That default covers every shape seen in practice, and a claim a token does
  not carry adds nothing, so reading both cannot widen access.
- **`iss` is compared byte for byte, never normalized.** Matching "equivalent"
  URLs would let a near-miss issuer start matching silently.
- **The algorithm allowlist is wide, and each key is bound to its own type.**
  Kanidm signs ES256 by default and some servers use EdDSA, so an RS256-only
  default would force per-provider configuration. Binding keys to their type
  is what makes the wide list safe. HMAC stays refused outright.
- **Keys load in the background, not before startup.** If startup waited for
  the authorization server, its outage would take this service down too. Keys
  are loaded as soon as the refresh task starts and re-read hourly; a re-read
  that succeeds is what drops a key the server has withdrawn. A failed pass
  is retried after a minute, backing off to an hour — or, while no key is
  held at all, after 5 s, backing off to 5 minutes, since a keyless process
  refuses every token and a readiness probe keeps away the traffic that would
  otherwise trigger a refetch. These retries are timer-driven; no request can
  schedule one. The task stops when the last `Arc` of the validator is
  dropped.
- **An unknown `kid` refetches at most once a minute.** `kid` comes from an
  unverified header, so without a limit a stream of junk tokens would turn
  your service into an amplifier aimed at your identity provider.
- **The key lock is never held across a network call.** A slow identity
  provider delays only requests whose key is not already cached.
- **A missing credential gets the same `invalid_token` challenge as a bad
  one.** RFC 6750 §3.1 says a server should omit the error code there, but
  clients in use start their authorization flow from this challenge, and the
  `resource_metadata` they depend on is present either way. The difference is
  kept in the log level instead.
- **401 and 403 are different answers.** A client that gets 401 for a missing
  scope re-authorizes, gets the same token, and loops. 403
  `insufficient_scope` names the scope it needs.

## Using with other frameworks

The validator and the credential logic have no web-framework dependency. They
do need a **Tokio 1.x runtime**: key fetches use `reqwest` with a Tokio timer
and run in a spawned task, and the first fetch panics outside one. On
`async-std`, `smol` or another executor, drive `validate` and `authenticate`
from a Tokio runtime handle.

Whatever the stack, the 401/403 decision is one function, `refusal()`: the
axum layer, the tower layer and a hand-built integration all get the status and
`WWW-Authenticate` challenge from the same code, so they cannot disagree. For
a request that needed more scopes than the validator's (checked with
`AuthorizedToken::require_scopes`), `refusal_for_scopes()` is the same
decision with a 403 challenge naming them — the bytes the layers'
per-route scope checks send.

### A tower stack (hyper, tonic, ...): `HttpAuthLayer`

With the `tower` feature, `oauth_resource_server::http_layer::HttpAuthLayer` wraps
any `tower` service over `http::Request<ReqBody>` / `http::Response<ResBody>`,
for any body types. It is the axum layer's check without axum: the same
builder (`static_token`, `static_tokens`, `oauth`, `sources`, `static_challenge`, `optional`,
`require_scopes`, `static_token_bypasses_scopes`, `build_with_decision`), the
same fail-closed build, the same refusals, and the
same `Credential`/`AuthorizedToken`/`StaticTokenMatch` request extensions; the
`http_layer::RequireScopes` route layer (and `McpToolScopes`) work behind it
exactly as behind the axum layer. A refusal's body is
`ResBody::default()` unless `on_reject` builds a response, whose status and
challenge the layer then sets:

```rust,no_run
use std::convert::Infallible;
use std::sync::Arc;

use http::{Request, Response, header::CONTENT_TYPE};
use oauth_resource_server::http_layer::{HttpAuthLayer, RejectContext};
use oauth_resource_server::{Credential, OAuthValidator};
use tower::{ServiceBuilder, service_fn};

async fn handler(request: Request<String>) -> Result<Response<String>, Infallible> {
    let who = match request.extensions().get::<Credential>() {
        Some(Credential::OAuth(token)) => format!("{:?}", token.subject),
        _ => "someone".to_string(),
    };
    Ok(Response::new(format!("hello, {who}")))
}

fn service(oauth: Arc<OAuthValidator>) {
    let auth = HttpAuthLayer::builder()
        .oauth(oauth)
        .on_reject(|cx: RejectContext<'_>| {
            Response::builder()
                .header(CONTENT_TYPE, "application/json")
                .body(format!(r#"{{"status":{}}}"#, cx.status.as_u16()))
                .unwrap()
        })
        .build()
        .expect("a validator is configured");
    let _service = ServiceBuilder::new().layer(auth).service(service_fn(handler));
}
```

On hyper, adapt the tower service with `hyper_util::service::TowerToHyperService`.
On an axum app, use `axum::AuthLayer`: the axum extractors answer 500 behind
`HttpAuthLayer`, which they cannot tell ran.

### Any other stack: `authenticate` + `refusal`

Collect the candidate credentials yourself, call `authenticate`, and answer a
refusal with what `refusal` returns — the status, and `WWW-Authenticate` set
(not appended) to its value:

```rust,no_run
use oauth_resource_server::{Credential, OAuthValidator, authenticate, refusal};

/// On refusal: the status and the `WWW-Authenticate` value to send.
async fn check(
    bearer: Option<&str>,
    api_key: Option<&str>,
    static_token: Option<&str>,
    oauth: &OAuthValidator,
) -> Result<Credential, (u16, Option<String>)> {
    let candidates = bearer.into_iter().chain(api_key);
    authenticate(candidates, static_token, Some(oauth))
        .await
        .map_err(|rejection| {
            // Log `rejection` (an `Invalid` carries its kind and detail);
            // never send it.
            let r = refusal(&rejection, Some(oauth));
            (r.status, r.www_authenticate)
        })
}
```

With only a static token, `refusal(&rejection, None)` gives the same
`Bearer error="invalid_token"` challenge the layers send (RFC 9110 §15.5.2
requires one on every 401); `refusal_with_static_challenge` picks another, or
none (a challenge that is not a valid header value, such as one containing a
line break, is replaced by the default). For a single token, call `OAuthValidator::validate` directly. Serve
`OAuthValidator::metadata()` (a `&serde_json::Value`) as JSON, without
authentication, on `OAuthValidator::metadata_path()` and, if you like, on the
bare `/.well-known/oauth-protected-resource` (see [Using with
MCP](#using-with-mcp) for what that bare copy is and is not). A readiness
probe is framework-free too: answer it from `OAuthValidator::is_ready()`,
outside authentication, as in [Readiness and liveness
probes](#readiness-and-liveness-probes) (never from `refresh_now()`, which
fetches every time). `TokenRejection` is a `std::error::Error` whose `Display` is only its category
(`invalid token`), so `?` and `{e}` never expose the reason; the reason is in
the variant (an `InvalidToken`: `kind()` for code and metrics, `detail()` for
your log) and in `Debug`.
[`examples/hyper.rs`](https://github.com/St0nefish/oauth-resource-server/blob/master/examples/hyper.rs)
is a complete hyper 1.x server built this way, and
[`examples/standalone_validator.rs`](https://github.com/St0nefish/oauth-resource-server/blob/master/examples/standalone_validator.rs)
walks through accepted and refused tokens against a fake authorization server.

### actix-web

actix-web runs on Tokio, so the same two functions work in an actix-web
middleware. This sketch is not compiled by this crate's CI (actix-web is not
one of its dev-dependencies); it uses `actix_web::middleware::from_fn`
(actix-web 4.9 or later):

```text
use std::sync::Arc;

use actix_web::body::MessageBody;
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::http::{StatusCode, header};
use actix_web::middleware::{Next, from_fn};
use actix_web::{App, Error, HttpMessage, HttpResponse, web};
use oauth_resource_server::{OAuthValidator, authenticate, refusal};

async fn require_auth(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<impl MessageBody>, Error> {
    let oauth = req
        .app_data::<web::Data<OAuthValidator>>()
        .expect("the validator is registered as app data")
        .clone();
    let bearer = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split_once(' '))
        .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("bearer"))
        .map(|(_, token)| token.trim().to_owned());
    match authenticate(bearer.as_deref(), None, Some(&oauth)).await {
        Ok(credential) => {
            req.extensions_mut().insert(credential);
            Ok(next.call(req).await?.map_into_left_body())
        }
        Err(rejection) => {
            let r = refusal(&rejection, Some(&oauth));
            let mut response = HttpResponse::build(StatusCode::from_u16(r.status).unwrap());
            if let Some(challenge) = r.www_authenticate {
                response.insert_header((header::WWW_AUTHENTICATE, challenge));
            }
            Ok(req.into_response(response.finish()).map_into_right_body())
        }
    }
}

// let oauth: Arc<OAuthValidator> = ...;
// App::new()
//     .app_data(web::Data::from(Arc::clone(&oauth)))
//     .service(web::scope("/api").wrap(from_fn(require_auth)) /* .route(...) */)
```

## Using with MCP

The crate is not specific to the Model Context Protocol, but it was extracted
from an MCP server
([mcp-md-wiki#308](https://github.com/St0nefish/mcp-md-wiki/issues/308)) and
fits MCP's authorization model:

- **Hosted clients need the challenge.** claude.ai, Claude Desktop and the
  mobile apps cannot send a static bearer token or a custom header to a remote
  MCP server, so OAuth (an authorization-code flow) is the only way they can
  authenticate to a protected one. claude.ai has been observed not starting
  that flow at all when a 401 lacks `resource_metadata` in `WWW-Authenticate`.
  Claude Code tolerates its absence, which is why a missing header is easy to
  ship and hard to notice. This crate sends it on every 401 and 403.
- **Set `resource` to the MCP endpoint's URL,** e.g.
  `https://mcp.example.com/mcp`. The metadata is then served at
  `/.well-known/oauth-protected-resource/mcp`, where MCP clients look first,
  and at the bare `/.well-known/oauth-protected-resource`. A trailing slash
  is part of the path (`.../mcp/` is described at
  `.../oauth-protected-resource/mcp/`, per RFC 9728 §3.1).
- **The bare-path copy is a compatibility deviation.** The document served at
  the bare `/.well-known/oauth-protected-resource` still names
  `https://mcp.example.com/mcp` as its `resource`, and RFC 9728 §3.3 tells a
  client that derived the bare URL from `https://mcp.example.com` to discard
  a document whose `resource` differs. It is served because some clients fall
  back to the bare path and accept it; a compliant client uses the
  `resource_metadata` URL every challenge carries, so it costs nothing.
- **Use a resource-URL audience if you can.** MCP requires a server to accept
  only tokens issued for it as the audience (RFC 8707 §2). With a client_id
  audience that holds only if the OAuth client is used for this one MCP
  server and no other; see [Audience](#audience-which-value-to-configure).
- **The scope is yours to choose.** The crate has no default scope. Pick one,
  such as `mcp:read`, set it as `required_scope`, and advertise it (an
  omitted `scopes_supported` advertises the required scopes; if you list
  `scopes_supported` yourself, include it): claude.ai requests exactly what
  the metadata advertises, so an unadvertised required scope is a 403 on
  every call.
- **Mind scope hierarchies.** MCP (2026-07-28, "Scope Challenge Handling")
  says a server MUST account for a broader scope implying narrower ones. This
  crate's check is an exact all-of match, so require only a scope **every**
  client token carries (if a write-only token is possible, `mcp:read` as the
  layer's requirement would refuse it), and make hierarchy-aware decisions
  in the application with `AuthorizedToken::has_scope`.
- **Merge `metadata_router` outside the auth layer,** on the same origin as
  the MCP endpoint.
- **Per-tool scopes need the request body.** The auth layer sees HTTP
  requests, not the JSON-RPC method inside a POST to `/mcp`, so on its own
  any accepted token can call every tool. The `mcp` feature's
  `McpToolScopes` reads the tool name and requires that tool's scopes (and
  any claim values, such as a group) before the MCP server sees the request
  (below); a tool handler can also check
  scopes itself ([Reading the token inside a tool
  handler](#reading-the-token-inside-a-tool-handler)).

### Per-tool scopes: `McpToolScopes`

With the `mcp` feature, `oauth_resource_server::mcp::McpToolScopes` is a tower
layer for the MCP endpoint, placed behind the auth layer. It gives every
request a default requirement and each named tool its own, reading the tool
name from a `tools/call` in the POST body (the `mcp` module's documentation
compiles the same layering behind an `HttpAuthLayer`):

```text
use axum::Router;
use oauth_resource_server::axum::AuthLayer;
use oauth_resource_server::mcp::McpToolScopes;

fn app(mcp_service: Router, auth: AuthLayer) -> Router {
    let tool_scopes = McpToolScopes::new()
        .default(["mcp:read"])
        .tool("write_document", ["mcp:write"]);
    Router::new()
        .nest_service("/mcp", mcp_service)
        .route_layer(tool_scopes)
        .route_layer(auth)
}
```

A token without the scopes is refused with 403 before the MCP server parses
anything, with a challenge naming the layer's scopes followed by that tool's
(`scope="mcp:read mcp:write"`), which is how a client knows to step up; a
request with no credential gets the auth layer's 401. What each request
needs:

| Request | Requires |
|---|---|
| an empty body (the event stream `GET`, `DELETE`, `Content-Length: 0`) | the default |
| a body, under **any** method, with a `tools/call` for a listed tool | that tool's scopes |
| `tools/call` for another tool, or any other method | the default |
| a JSON-RPC batch | every scope any of its messages needs |
| a body that is not JSON, a `tools/call` with no readable `params.name`, or a message repeating `method`, `params` or `params.name` | every scope in the configuration (default and all tools) |
| a message with an object key `$serde_json::private::RawValue` or `$serde_json::private::Number` at any depth | every scope in the configuration: with serde_json's `raw_value` (on in any build with axum) or `arbitrary_precision` feature, `serde_json::Value` reads such an object as the JSON inside the key's string, so a dispatcher could see a different call there |
| a body over the limit (`body_limit`, 1 MiB by default, 4 KiB to 64 MiB) | refused with 413, unread past the limit |
| a body that fails while it is being read (the client disconnects, a transport error) | refused with a bare 400, logged at `warn` (no challenge: nothing about the credential was wrong) |

Anything it cannot classify with certainty gets the strictest set rather
than the default, because the MCP server's parser might read that body as a
tool call; a caller holding every scope loses nothing, and the server answers
a malformed body itself. A static token is refused wherever scopes are
required, unless `static_token_bypasses_scopes()`. A served request reaches
the MCP server with its body byte-identical (trailers are not passed on). The
body type must be buildable from bytes (`axum::body::Body`, `Full<Bytes>`);
nothing from the body is ever logged. The body is parsed in one streaming
pass that builds no document, so memory stays at about the body itself
however many messages a batch holds. A request with no credential (behind
an `optional()` layer) gets the auth layer's 401 when what it needs is not
empty and is served when it needs nothing (an anonymous `initialize`, a
public tool behind an empty default); only when every request needs a scope
is it refused before its body is read. Every request's body is read whatever
its method or size hint (an empty one ends at once); whitespace alone is not
empty, so it needs every scope.

**Tool names are matched exactly** — byte for byte on the JSON-decoded
`params.name`, with no case folding, trimming or normalization — and a name
with no entry gets the default. Register every tool under exactly the name
your MCP server dispatches on, and make sure its dispatcher is exact too: one
that would also run `Write_Document` or `write_document` as `write_document`
lets a caller reach that tool under a spelling this layer treats as
unconfigured, with only the default's scopes.

**Set a read timeout on the server.** Reading the body has no timeout of its
own, so a client that sends it slowly (slow-loris) holds the request open
for as long as your server allows: configure a header/body read or request
timeout (hyper's, a `tower_http::timeout` layer, or your proxy's), as for
any endpoint that reads a body.

**Claim requirements per tool.** Next to scopes, a tool (or the default) can
require a verified claim value — a group or role a token carries as a claim
rather than a scope:

```text
let tool_scopes = McpToolScopes::new()
    .default(["mcp:read"])
    .tool("purge", ["mcp:write"])
    // `purge` also needs `groups` to hold `admins` or `ops`.
    .tool_claim("purge", "groups", ["admins", "ops"])
    // `approve` needs `role` = `approver`, and no scope of its own.
    .tool_claim("approve", "role", ["approver"]);
```

- Each `tool_claim` / `default_claim` call adds one clause: the top-level
  claim must hold **at least one** of the values (a string equal to it, or
  an array with that string element; exact and case-sensitive, a
  space-delimited string is one value), and **every** clause must hold.
  Two clauses on the same claim are two requirements, never merged.
- A tool is configured once it appears in `tool` **or** `tool_claim`; it then
  needs its own scopes and its own clauses only, never the default's. A tool
  given only `tool_claim` has no scopes of its own (add them with `tool`),
  and `tool("x", [])` exempts `x` from the default clauses as well as the
  default scopes. Everything else needs the default scopes and the
  `default_claim` clauses.
- A batch needs the union of its calls' clauses; a body it cannot classify
  needs every clause in the configuration (so two tools needing
  `role = a` and `role = b` make such a body need both).
- A missing claim value is the same 403 as a missing scope, with a challenge
  naming the scopes only (byte-identical to a scope-only refusal for the same
  scopes): RFC 6750 has no claim error, and no claim name or value ever
  enters `WWW-Authenticate`. The refusal is logged with `auth.reason =
  insufficient_scope` and a `required_claims` field holding the claim
  **names** only, never a configured or presented value.
- A static token has no claims: it is refused wherever a clause applies,
  unless `static_token_bypasses_scopes()`, which covers claims too. A request
  with no credential gets the auth layer's 401 as for scopes.

Scopes, claim requirements and limits read from configuration go through
`try_default`, `try_tool`, `try_default_claim`, `try_tool_claim` and
`try_body_limit`, which return an `McpScopesError` naming the bad value (a
blank claim name, no values or a blank value is `InvalidClaimRequirement`);
the plain forms panic and are for literals in code.

### Reading the token inside a tool handler

`AuthLayer` inserts `AuthorizedToken` (and `Credential`) into the HTTP
request's `http::Extensions` — the same place [Reading the caller in a
handler](#reading-the-caller-in-a-handler) reads `Credential` from in a plain
axum handler. A tool handler runs one layer further in, inside the MCP SDK's
JSON-RPC dispatch, so it has no axum extractor of its own; it
needs the original `http::request::Parts` (extensions included), which is
what carries the value here:

```rust
use http::request::Parts;
use oauth_resource_server::AuthorizedToken;

/// Read back what `AuthLayer` put on the request, given the `Parts` a tool
/// handler's own extractor hands it.
fn token_from_parts(parts: &Parts) -> Option<&AuthorizedToken> {
    parts.extensions.get::<AuthorizedToken>()
}
```

Once you hold the token, `token.has_claim_value("groups", "admins")` checks a
group or role claim in the handler.

With the [rmcp](https://docs.rs/rmcp) SDK, `StreamableHttpService` carries
those `Parts` onto the request context a `#[tool]` handler receives (its own
docs, "Accessing HTTP request data from tool handlers"): a handler taking
`rmcp::handler::server::tool::Extension<http::request::Parts>` as a
parameter gets exactly the `Parts` value `token_from_parts` above
expects, and `parts.extensions.get::<AuthorizedToken>()` inside the handler
reaches the token this crate validated. `Extension<AuthorizedToken>` on its
own does not do this: rmcp's `Extension<T>` extractor reads from its own
request-scoped extension map, which holds the whole `Parts` value as one
entry, not the individual values inside `Parts.extensions` — extract
`Parts` first, as shown above, then read `AuthorizedToken` out of it.

A scope check there is `token.require_scopes(&["mcp:write"])`. It answers
inside the protocol (a tool error), not with the 403 and challenge a client
can re-authorize from; `McpToolScopes` does the latter.

## Provider guide

[`docs/providers.md`](https://github.com/St0nefish/oauth-resource-server/blob/master/docs/providers.md)
has setup recipes and a checklist for any other server. Each recipe states how
far it has been tested, and none claims more:

| Provider | Status |
|---|---|
| Authentik | verified in production |
| Authelia 4.39 | verified in a sandbox, end to end |
| Kanidm | token shape verified in a sandbox; not tested end to end |
| Keycloak, Okta, Microsoft Entra ID, Auth0, Ory Hydra, Logto, Casdoor, Rauthy, Dex, Zitadel | documented-shape fixture, not live-tested |

The Authentik, Authelia and Kanidm results were obtained with the
[mcp-md-wiki](https://github.com/St0nefish/mcp-md-wiki) implementation this
crate was extracted from, whose validation logic moved here unchanged; no
token from those servers has been sent to this crate's validator itself.

## Configuration changes need a restart

Nothing hot-reloads. A changed `OAuthConfig`, static token or credential
source — or a changed [fetch option](#fetch-options-code-not-config) (root
certificate, proxy, timeout, initial key set), which is code rather than
config but is read at the same moment — takes effect only when a new
`OAuthValidator` and `AuthLayer` are built, which in practice means
restarting the process. If your application reloads
other settings live, treat all of these as restart-required and say so.
Signing keys are the exception: they are refreshed in the background, so a key
rotation at the authorization server needs no restart.

## Troubleshooting

The layer logs refusals under the target `oauth_resource_server::axum`: `warn`
for a refused credential, and `debug` for an accepted OAuth token and, when
OAuth is configured, for a request with no credential at all (every OAuth
client's first request looks like that). An accepted static token is logged
at `debug` too (`Static bearer auth accepted`, with its label), and with only
a static token configured a request with no credential is logged at `warn`
like any other refusal. Every one of these lines also carries the stable
`auth.*` fields described under [Observability](#observability); filter on
those rather than on the message. Enable `debug` for that target while setting up. A refusal looks like
this:

```text
WARN oauth_resource_server::axum: OAuth bearer auth rejected path=/v1/things reason=Invalid(InvalidToken { kind: WrongAudience, detail: "token rejected: InvalidAudience" }) auth.outcome="rejected" auth.mechanism="oauth" auth.reason="wrong_audience" auth.status=401
```

With only a static token configured, the line is `Bearer auth rejected`, with
no reason. A per-route scope refusal (`RequireScopes`, `McpToolScopes`) is
logged under `oauth_resource_server::http_layer` at `info`, as `The credential
lacks the scopes this route requires` with the required and present scopes
(`The credential lacks the scopes or claim values this route requires`, with
a `required_claims` field naming the claims, never their values, for an
`McpToolScopes` requirement with claim clauses; and a `Scoped` extractor's under `oauth_resource_server::axum`); a layer's
own `require_scopes` refusal is its usual `warn` line with
`reason=InsufficientScope`. The table below is keyed on the detail text, which is for reading
logs; in code, match `InvalidToken::kind()` instead. The validator and key-set messages come from the targets
`oauth_resource_server::validator` and `oauth_resource_server::jwks`.

| Reason or log line | Cause and fix |
|---|---|
| `token header lists critical extensions (crit), ...` | The authorization server marked the token with a JWS extension this crate cannot process (RFC 7515 §4.1.11). Configure it not to. |
| `token nbf is not a NumericDate ...` | The token's `nbf` is a string or out-of-range number. The authorization server is emitting a malformed token. |
| `token is sender-constrained (cnf); ...` | The token is DPoP- or mTLS-bound, which this crate cannot verify. Configure the client or server to issue plain bearer tokens for this API. |
| `token client "..." is not in ...allowed_client_ids`, or `token names no client (client_id or azp) ...` | The token was issued to a client you did not list, or names its client in another claim (Okta: `cid`; require that with `required_claims` instead). |
| `token was issued ...s ago, over ...max_token_age_secs`, or `token has no iat and ...max_token_age_secs is set` | The token is older than you allow, or carries no `iat`. Lower the authorization server's token lifetime, or unset `max_token_age_secs` if it cannot emit `iat`. |
| `token has no "..." claim, which ...required_claims requires`, or `token claim "..." does not match ...required_claims` | A `required_claims` entry failed. Decode a real token and compare the claim's name, type and value (`"1"` is not `1`). |
| `credential is not a JWT (...)` | The token is opaque, or it is a mistyped static token. Configure the authorization server to issue JWT access tokens (Authelia: `access_token_signed_response_alg`; Ory Hydra: `strategies.access_token: jwt`; Zitadel: the JWT token type). |
| `token rejected: InvalidAudience` | `aud` contains none of the configured audiences. Decode a real token and copy its `aud` into `audience`; see [Audience](#audience-which-value-to-configure). |
| `token rejected: InvalidIssuer`, or `token iss is not a single string equal to ...` | `issuer` differs from the token's `iss`, most often by a trailing slash. Copy it from the discovery document exactly. |
| `token rejected: ExpiredSignature` or `ImmatureSignature` | The token has expired, or its `nbf` is in the future. Check both machines' clocks; `leeway_secs` absorbs up to 300 seconds of skew. |
| `token rejected: InvalidSignature` | The token was signed by a key other than the one with that `kid` in your JWKS: the wrong `jwks_uri`, or a token from a different server. |
| `token rejected: Missing required claim: aud` (or `iss`, `exp`) | The token lacks a claim this crate requires. It is usually not an access token. |
| `token algorithm HS256 is not in ...algorithms` | The server signs with a shared secret, which a resource server cannot verify. Give it an asymmetric signing key (Authentik: set a signing key on the provider). For an asymmetric algorithm, add it to `algorithms`. |
| `token typ "JWT" is not accepted as an access token (...require_at_jwt is on)` | Your server does not emit `at+jwt`. Turn `require_at_jwt` off and rely on a required scope. |
| `no RS256 key for kid "..." and the JWKS was refetched less than 60s ago` | The `kid` is not in the key set, and the once-a-minute refetch was already used. A key rotation resolves itself within a minute; if it persists, the token comes from a different issuer or key set. |
| `JWKS refresh failed: ...` | The key set could not be fetched or had no usable keys. The rest of the message says why: a DNS or TLS error, a non-success status, `metadata issuer ... does not match`, or `the JWK Set contained no usable signature keys for ...algorithms`. A certificate error against a server with a private CA means the default `rustls-tls` feature, which trusts only its built-in Mozilla roots: add the CA with `add_root_certificate_pem`, or see [Choosing a TLS backend](#choosing-a-tls-backend). |
| 403, with `OAuth token is valid but lacks the required scope` at `info` | The line lists `required`, `present` and `scope_claims`. `present=[]` usually means the scopes are in a claim missing from `scope_claims`, or the server did not grant the scope (Authentik needs a scope mapping, Kanidm a scope map). |
| Startup `warn`: `required scope(s) ... not in ...scopes_supported` | Clients request what is advertised and will get 403. Add the scope to `scopes_supported`. (An empty `scopes_supported` never logs this: the 401 challenge then names the required scopes.) |
| Startup error: `no required scope is configured ...` | With no scope and no `require_at_jwt`, ID tokens would be accepted too. Set a required scope (or `require_at_jwt`, or `allow_unscoped_tokens` if that is really intended, which then logs a startup `warn`: `no required scope configured ... ANY token this issuer signs ...`). |
| Startup error: `... uses plain http on a non-loopback host` | Use `https`, or set `allow_insecure_http` for an address on a trusted network (which then logs the same line as a startup `warn`). |
| `JWKS refresh failed: ... jwks_uri "http://..." uses plain http on a non-loopback host` or `redirect to plain http on a non-loopback host ... refused` | A loopback `http` issuer's metadata, or a redirect during a key fetch, points at a cleartext non-loopback URL. Serve it over `https`, or set `allow_insecure_http` if that network is trusted (each use is then logged at `warn`). |
| Startup error: `... is not a valid scope` | A scope with a space, `"`, `\` or non-printable character. Scopes are RFC 6749 scope-tokens. |
| Startup `warn`: `OAuth: could not load the authorization server's signing keys` | The first background key load failed (unreachable issuer, discovery mismatch, TLS). Requests fail closed until a later attempt succeeds; with no key held the task retries after 5 s, backing off to 5 minutes (`retry_in_secs` in the log line). `key_set_status()` shows the last error; see [Readiness and liveness probes](#readiness-and-liveness-probes). |
| `warn`: `JWKS key declares no alg, so it may verify any of ...` | A key in the set has no `alg`. Narrow `algorithms` to the algorithm your server signs with. |
| A client never starts the login flow | The 401 lacks `WWW-Authenticate`, or the metadata is unreachable. Check that `metadata_router` is merged outside the auth layer, that no proxy strips the header, and that `resource` is the URL clients actually use. |
| The metadata document is 404 | OAuth is off (`metadata_router(None)` answers 404), or the path does not match the path of `resource`. `OAuthValidator::metadata_path()` returns the path served. |
| A static token that used to work is refused | With OAuth on, `accept_static_bearer: false` makes `static_token_policy` return `StaticIgnored`. |
| `AuthLayerError::NoCredential` or `NoAuthConfigured` | Neither a static token nor OAuth is configured. Configure one, or opt out explicitly with `allow_unauthenticated`. |

## Testing your integration

Enable the `testing` feature **from `[dev-dependencies]` only** (its signing
keys are public, so anything that trusts them trusts everyone):

```toml
[dev-dependencies]
oauth-resource-server = { version = "0.3", features = ["testing"] }
```

That keeps it out of a production build under Cargo's feature resolver
version 2, the default since edition 2021. A package on edition 2018 or
earlier without `resolver = "2"` uses version 1, which unifies
dev-dependency features into `cargo build` too, so `testing` (its module and
its public keys, though no validator path changes) would be compiled into
the binary: set `resolver = "2"` there.

`testing::TestAuthority` is a fake authorization server on a loopback port. It
serves discovery (OpenID Connect and RFC 8414) and a JWKS, and hands you a
config and tokens that agree with it, with neutral defaults: resource
`https://api.example.test/`, a distinct audience `https://api.example.test/audience`,
required scope `api:read`, settings named `oauth.*`. Each thing a test wants
wrong is one builder call.

```text
use std::sync::Arc;

use axum::{Router, body::Body, http::{Request, StatusCode}, routing::get};
use oauth_resource_server::axum::AuthLayer;
use oauth_resource_server::testing::TestAuthority;
use oauth_resource_server::{AuthorizedToken, OAuthValidator};
use tower::ServiceExt; // for `oneshot`

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let authority = TestAuthority::start().await;
    // Adjust anything before the config is resolved; it panics with the
    // `ConfigError` text if the result is invalid.
    let config = authority.config(|c| c.require_at_jwt = true);
    let validator = Arc::new(OAuthValidator::new(&config).unwrap());

    let app = Router::new()
        .route(
            "/whoami",
            get(|token: AuthorizedToken| async move { token.subject.unwrap_or_default() }),
        )
        .route_layer(AuthLayer::builder().oauth(validator).build().unwrap());
    let request = |bearer: String| {
        Request::builder()
            .uri("/whoami")
            .header("authorization", format!("Bearer {bearer}"))
            .body(Body::empty())
            .unwrap()
    };

    let ok = app.clone().oneshot(request(authority.token().subject("ada").sign())).await.unwrap();
    assert_eq!(ok.status(), StatusCode::OK);

    let expired = app.clone().oneshot(request(authority.token().expired().sign())).await.unwrap();
    assert_eq!(expired.status(), StatusCode::UNAUTHORIZED);

    let no_scope = app.oneshot(request(authority.token().scopes(["other:scope"]).sign())).await.unwrap();
    assert_eq!(no_scope.status(), StatusCode::FORBIDDEN);
}
```

(This block is fenced `text` because the README is compiled without the
`testing` feature; its body is identical to the doctest in the
[`testing`](https://docs.rs/oauth-resource-server/latest/oauth_resource_server/testing/)
module docs, which is compiled and run. Use `#[tokio::test]` instead of
`#[tokio::main]` in a real test.) The example needs `tower` with the `util`
feature (for `ServiceExt::oneshot`) as a dev-dependency.

The token builder covers what an access-token test needs to get wrong:
`.subject()`, `.scopes()`, `.audience()`/`.audiences()`, `.issuer()`,
`.expires_in(secs)`, `.expired()`, `.not_before_in(secs)`, `.issued_ago(secs)`,
`.typ()`, `.without_typ()`, `.alg()` (RS*, PS*, ES256, EdDSA, each signed with
the matching published throwaway key), `.kid()`, `.claim()` (also the way to
set an absolute or malformed `exp`/`nbf`/`iat`), `.without_claim()` and
`.sign()`. Key rotation is `authority.rotate_key()` (publishes the new key next
to the old) followed, if you want the old key gone, by
`authority.withdraw_old_key()` (its tokens then fail once the validator
refreshes). `authority.jwks_fetches()` and `authority.discovery_fetches()`
count what the authority served, and `authority.set_response_delay(..)`
simulates a slow one. For a handler test that needs no validation at all,
build the verified value directly with `AuthorizedToken::new(..)` and
`with_claims(..)`.

`testing` follows semver like the rest of the crate: a breaking change to it
ships in a new `0.x` minor, so your test suite is not broken by a patch or
additive release.

## Examples

Every example runs locally without network access. The ones that validate
tokens start the `testing` feature's fake authorization server on a loopback
port and mint tokens with its throwaway keys.

```sh
cargo run --example axum_basic --features axum,serde,testing
cargo run --example multiple_sources --features axum,testing
cargo run --example standalone_validator --features testing
cargo run --example env_config --features env,axum
cargo run --example hyper --features testing
```

| Example | What it shows |
|---|---|
| `axum_basic` | YAML config, the middleware and the metadata router, with requests sent through the router and each response printed. |
| `multiple_sources` | `Authorization: Bearer` plus an `X-Api-Key` header, a static key in dual mode, and JSON rejection bodies. |
| `standalone_validator` | The validator without axum: discovery, `validate`, `authenticate` and the challenge headers. |
| `env_config` | Loading everything from `MYAPP_OAUTH_*` variables, an application default for the required scope, and `static_token_policy`. |
| `hyper` | A plain hyper 1.x server with no framework: `authenticate`, `refusal` for the 401/403 and challenge, and the metadata document, driven by hyper's client. |

## MSRV and semver policy

The minimum supported Rust version is **1.89** (edition 2024). It is declared
as `rust-version` and checked in CI.

The crate follows semantic versioning as Cargo applies it before 1.0: a release
that breaks the public API increments the minor version (0.1 to 0.2). A patch
release (0.1.0 to 0.1.1) preserves behavior, with **one exception**: a fix for
a vulnerability, where a forged, expired, wrongly-audienced or otherwise
out-of-policy token was being accepted, ships as a patch release even though
it refuses tokens that were accepted before. It comes with a `CHANGELOG.md`
entry and a security advisory. Holding such a fix for the next minor release
would leave everyone on the usual `"0.3"` requirement unprotected. If you pin
an exact version (`=0.3.x`), expect a patch to narrow what is accepted when it
fixes a vulnerability.

A new minor release is required for:

- Raising the MSRV.
- A major-version bump of a dependency whose types appear in the public API:
  `serde` and `serde_json`, always (`AuthorizedToken::claims_as` is bounded
  by `DeserializeOwned`, `claims()` and `metadata()` return `serde_json`
  types); `http`, `tower-layer` and `tower-service` under the `tower`
  feature (`CredentialSource` holds an `http::HeaderName`, `static_challenge`
  takes an `http::HeaderValue`, and both layers implement `tower_layer::Layer`
  and their services `tower_service::Service` over `http::Request`);
  `http-body` and `bytes` under the `mcp` feature (`McpToolScopesService`'s
  request body is bounded by `http_body::Body + From<bytes::Bytes>`); and
  `axum` under the `axum` feature (`metadata_router` returns an
  `axum::Router<S>`, `require_auth` takes axum's `State`, `Request` and
  `Next`). The JWT library is not part of the API (`Algorithm` is this
  crate's own type), so replacing it is not a breaking change.
- A new configuration field. Types that may grow are `#[non_exhaustive]`, but
  `OAuthConfig` deliberately is not, so it can be built with struct-literal
  syntax.

**Log field, span and metric names are a stable API.** The `auth.*` log
fields, the `oauth_rs.*` span names and fields, the `oauth_rs_*` metric
names and labels, and every value [Observability](#observability) lists are
covered by semver: renaming one, or moving an outcome to another value, is a
breaking change; adding a value is not.

**Message text is not a stable API.** The wording of `ConfigError::problems`
(and the `Display` built from it), of rejection reasons, and of log lines may
change in any release, a patch included. The troubleshooting table above is
for reading logs; do not string-match these messages in code. Match on the
types instead (`TokenRejection`, `ValidatorError`, `AuthLayerError`, and so
on): for a refused token, on `InvalidToken::kind()` (`InvalidTokenKind`,
with `as_str()` labels for metrics), and for configuration problems, on
`ConfigProblem::kind()` (`ProblemKind`) and `keys()`. These are the durable
alternative to matching the sentence. The kind a given refusal or problem
carries, and each kind's `as_str()` label, are part of the contract
(reclassifying one is a breaking change; adding a variant is not), while the
message text (`InvalidToken::detail()`, `ConfigProblem::message()`) is not.

## License

MIT. See [LICENSE](https://github.com/St0nefish/oauth-resource-server/blob/master/LICENSE).
