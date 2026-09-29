# Provider guide

Setup recipes for specific authorization servers, a checklist for any other
server, and how to add a provider to this guide.

Only providers with actual evidence behind them are listed, and each recipe is
labeled with exactly how much evidence that is. Never read a recipe as more
tested than its label says, and never cite one as a stronger compatibility
claim than its label.

- **verified in production**: running against the real product in a live
  deployment.
- **verified in a sandbox**: an end-to-end run against a real instance of the
  product, not a production deployment, or, where the status line says so, a
  token shape captured from a real instance and re-created in a unit test.
- **documented-shape fixture, not live-tested**: a unit test in this crate
  (`src/validator.rs`) models the access-token shape that the provider's own
  documentation (or, where noted, its source code) describes, proving the
  validator covers it with configuration alone. **The real product has never
  been run against this crate.** Treat these as a starting point, not a
  guarantee, and check your own server's tokens with the
  [checklist](#any-other-provider-checklist).

Each bullet inside a recipe carries its own marker:

- **[verified]**: checked against the real product, at the level the recipe's
  status line states.
- **[docs]**: taken from the provider's own documentation and not
  independently tested.

The recipes whose status line names mcp-md-wiki were verified before this
crate was extracted from it
([mcp-md-wiki#308](https://github.com/St0nefish/mcp-md-wiki/issues/308); see
`CHANGELOG.md`). No token from those providers has been sent to *this crate's*
validator, only to the implementation it was ported from, whose
security-relevant behavior moved over unchanged.

## Reading the recipes

Each recipe is the `OAuthConfig` block as YAML, for the `serde` feature. The
same keys work in any serde format, and with the `env` feature each one is an
environment variable (`issuer` becomes `<PREFIX>ISSUER`; lists are
space-separated). Placeholders throughout: `auth.example.com` and
`idm.example.com` for the authorization server, `api.example.com` for the
protected API, and `api:read`/`api:write` as scope names. Use the scopes your
application actually checks.

Every recipe sets a required scope and lists it in `scopes_supported`. Keep
both:

- **Without a required scope** the crate checks no scope at all, and unless
  `require_at_jwt` is on, an OIDC ID token issued to the same client would be
  accepted as well, so `resolve` refuses that configuration unless you set
  `allow_unscoped_tokens: true`.
- **Without the scope in `scopes_supported`**, clients that request what the
  metadata advertises (claude.ai does) never ask for it, and every call is 403
  `insufficient_scope`. The validator logs a `warn` at startup for that. (An
  omitted `scopes_supported` advertises the required scopes; the recipes list
  it to show a menu wider than what is required.)

Every issuer and `jwks_uri` below is `https`. A plain-`http` one on a
non-loopback host (an in-cluster address, say) is refused unless you set
`allow_insecure_http: true`.

The recipes that set `audience` to a client_id (Authentik, Kanidm) rely on
that OAuth client being **dedicated to this one API**: every token the client
obtains, for any resource, carries the same `aud`. That departs from RFC 9068
§4 and MCP's audience requirement; the README's
[Audience](https://github.com/St0nefish/oauth-resource-server#audience-which-value-to-configure)
section explains when it is sound.

## Authentik

Status: **verified in production**, the deployment this crate's validator was
originally built for (mcp-md-wiki, before extraction; see `CHANGELOG.md`),
running OAuth alongside a static bearer token.

- [verified] Use an OAuth2/OpenID provider. The per-application issuer has a
  trailing slash: `https://auth.example.com/application/o/<slug>/`.
- [verified] The JWKS is at `<issuer>jwks/`. Discovery also finds it.
- [verified] `aud` is the provider's **client_id**, as a string. The
  `resource` parameter is ignored.
- [verified] `scope` is a space-delimited string. Tokens are signed RS256 with
  header `typ: JWT`, so leave `require_at_jwt` off.
- [docs] The provider needs a **signing key**. Without one, Authentik signs
  with HS256 using the client secret, which no resource server can verify
  (and this crate refuses HS256 unconditionally).
- [docs] Only scopes backed by a scope mapping on the provider end up in
  `scope`. Create mappings for the scopes your application requires.

```yaml
enabled: true
issuer: "https://auth.example.com/application/o/example-app/"
jwks_uri: "https://auth.example.com/application/o/example-app/jwks/"   # optional
audience: "example-client-id"
resource: "https://api.example.com"
required_scope: "api:read"                  # whatever your application checks
scopes_supported: ["api:read", "api:write"] # must include every required scope
```

## Authelia (4.39)

Status: **verified in a sandbox**, end to end. Real Authelia 4.39.4 tokens
were accepted and rejected as expected by mcp-md-wiki's validator, before it
was extracted into this crate, including discovery, the `scp` claim, a
resource-URL audience, `require_at_jwt`, a 403 for a token missing a required
scope, and a 401 when the audience is configured as the client_id instead.

- [verified] Access tokens are **opaque by default**. Set
  `access_token_signed_response_alg: 'RS256'` on the client to get JWTs. The
  header is then `{"alg":"RS256","typ":"at+jwt"}`.
- [verified] Scopes arrive as `scp` (a JSON array), with no `scope` claim.
  Authelia refuses to add one through a claims policy. The default
  `scope_claims` reads `scp`.
- [verified] `aud` never contains the client_id. It holds only the client's
  configured `audience` values, and the `resource` parameter is ignored.
  Configure the client with `audience: ['https://api.example.com']` and
  `requested_audience_mode: 'implicit'`, and set this crate's `audience` to
  the same URL.
- [verified] `iss` has no trailing slash. `sub` is an opaque UUID and the
  access token carries no username, so logs show the `sub`.
- [verified] There is no dynamic client registration, so pre-register a
  client. A public client (`public: true`, `token_endpoint_auth_method:
  'none'`, PKCE S256) works. Custom scope names cause only a validation
  warning.
- [verified] For redirect URIs, `http://127.0.0.1/callback` matches
  127.0.0.1 on any port. `localhost` matches only exactly registered ports.

Authelia client (excerpt):

```yaml
identity_providers:
  oidc:
    clients:
      - client_id: 'example-client'
        public: true
        token_endpoint_auth_method: 'none'
        authorization_policy: 'one_factor'      # or two_factor
        consent_mode: 'implicit'
        require_pkce: true
        pkce_challenge_method: 'S256'
        redirect_uris:
          - 'http://127.0.0.1/callback'         # matches 127.0.0.1 on any port
          - 'http://localhost:38765/callback'   # exact port
        scopes: ['openid', 'offline_access', 'api:read', 'api:write']
        response_types: ['code']
        grant_types: ['authorization_code', 'refresh_token']
        access_token_signed_response_alg: 'RS256'   # without this, tokens are opaque
        audience: ['https://api.example.com']
        requested_audience_mode: 'implicit'
```

This crate's config:

```yaml
enabled: true
issuer: "https://auth.example.com"          # no trailing slash
audience: "https://api.example.com"         # the resource URL, not the client id
resource: "https://api.example.com"
require_at_jwt: true
required_scope: "api:read"                  # whatever your application checks
scopes_supported: ["api:read", "api:write"] # must include every required scope
```

## Kanidm

Status: **token shape verified in a sandbox; not tested end to end with any
server built on this crate (or on mcp-md-wiki before the extraction).** A
real Kanidm access token was verified with an independent JWT tool. A unit
test (`observed_shape_kanidm_es256_per_client_issuer_and_client_audience` in
`src/validator.rs`) replays that exact shape through this crate's validator,
but no live Kanidm token has been sent to a running server built on this
crate.

- [verified] Each client has its own issuer:
  `https://idm.example.com/oauth2/openid/<client>`. The trailing-slash
  variant does not match. Discovery works at
  `<issuer>/.well-known/openid-configuration`, and the JWKS is per client.
- [verified] Tokens are signed **ES256** with header `typ: at+jwt`. `aud` is
  the **client name** (a string). `scope` is a space-delimited string. `sub`
  is a UUID, with no username or groups in the access token. Tokens live
  900 s.
- [verified] The `resource` parameter is accepted and ignored. There is no
  dynamic client registration. Public clients require PKCE S256.
- [docs] Grant scopes to users with a scope map on the client, for a group.
  Whether Kanidm accepts a scope name containing `:` was not tested. If it
  refuses one, use an underscore instead (e.g. `api_read`) and use that same
  name in all three places: this crate's `required_scope` and
  `scopes_supported`, and the scope map on Kanidm.

```yaml
enabled: true
issuer: "https://idm.example.com/oauth2/openid/example-client"
audience: "example-client"
resource: "https://api.example.com"
require_at_jwt: true
required_scope: "api:read"                  # whatever your application checks
scopes_supported: ["api:read", "api:write"] # must include every required scope
```

## Documented-shape fixtures, not live-tested

Each of these is a unit test in `src/validator.rs`
(`documented_shape_fixture_not_live_tested_<provider>`) modeling the
access-token shape the provider's documentation (or source, where noted)
describes. **None of these products has been run against this crate.** The
shape notes tell you which settings to reach for; confirm them against a real
token with the checklist below.

| Provider | Test | Shape notes |
|---|---|---|
| Keycloak | `documented_shape_fixture_not_live_tested_keycloak` | Realm issuer; `typ: JWT` (`at+jwt` is an opt-in client switch since 26.2); `scope` string; `aud` includes the client (set `audience` to it); `azp` names the client; `preferred_username` present. |
| Okta (custom authorization server) | `documented_shape_fixture_not_live_tested_okta_custom_as` | No `typ` header at all; `scp` array; `aud` is the configured API audience, shared by every client granted it; `cid` names the client, which `allowed_client_ids` does not read, so restrict clients with `required_claims: {cid: "<client id>"}` (see [Shared audiences](#shared-audiences-restrict-the-clients)). |
| Microsoft Entra ID (v2.0) | `documented_shape_fixture_not_live_tested_entra_id_v2` | `typ: JWT`; `scp` a space-delimited string; `aud` is the API's own client id. |
| Auth0 | `documented_shape_fixture_not_live_tested_auth0` | Issuer with a trailing slash; `aud` an array (API identifier plus `/userinfo`); `scope` string; both the classic (`typ: JWT`) and RFC 9068 (`at+jwt`) profiles work. The API identifier is shared by every client granted the API; `azp` names the client, so list yours in `allowed_client_ids` (see [Shared audiences](#shared-audiences-restrict-the-clients)). |
| Ory Hydra (JWT strategy) | `documented_shape_fixture_not_live_tested_ory_hydra_jwt_strategy` | Only with `strategies.access_token: jwt` set (opaque is Hydra's default); `scp` is a list by default, a string with `oauth2.jwt.scope_claim: string`. |
| Logto | `documented_shape_fixture_not_live_tested_logto_resource_indicator` | `aud` is the registered API resource indicator (RFC 8707); `scope` string; ES256 among its allowed signing algorithms. |
| Casdoor | `documented_shape_fixture_not_live_tested_casdoor_jwt_standard` | Source-derived. No `typ` beyond the library default; `aud` is `[client_id]` (or `[resource]` under RFC 8707); `scope` string; `preferred_username` present with the JWT-Standard token format. |
| Rauthy | `documented_shape_fixture_not_live_tested_rauthy_eddsa_at_jwt` | Source-derived. `typ: at+jwt`; `scope` string; EdDSA available per client; no `preferred_username` (the principal chain falls to `sub`). |
| Dex | `documented_shape_fixture_not_live_tested_dex_needs_a_group_claim_as_scope` | Source-derived. Dex's "access token" is really an ID token: `aud` is the client_id, and there is no `scope`/`scp` claim at all. The only generic way to gate it is to point `scope_claims` at a group claim (`scope_claims: ["groups"]`, `required_scopes: ["<group>"]`; the group name must be a valid scope-token, so no spaces), a deliberate compromise: configuration can approximate a scope check this way, and this crate adds no Dex-specific code path to do better. Set `scopes_supported` to the scopes a client must request for Dex to emit that claim (`["openid", "groups"]`), not to the group: a group is not a requestable scope. The startup `warn` that the required "scope" is not in `scopes_supported` is then expected, and harmless here. Because the tokens are ID tokens, the required group is the only gate: any token Dex signs for the client whose `groups` contains it is accepted. |
| Zitadel (JWT mode) | `documented_shape_fixture_not_live_tested_zitadel_jwt_mode` | Only with the application's token type switched to JWT (opaque is the alternative). `aud` holds the client ids and the project id. Zitadel's scope-claim shape was not documented where this fixture's author looked, so it exercises only the `aud` array and project id. |

### Shared audiences: restrict the clients

Where the authorization server stamps an audience that names the API rather
than one client — an Auth0 API identifier, an Okta custom authorization
server's audience, an Entra ID app ID URI — every client granted that API
gets a token this crate accepts. Restrict it to the clients you mean to serve:

- **`allowed_client_ids`** when the token names its client in `client_id`
  (RFC 9068) or `azp` (Auth0, Keycloak): `allowed_client_ids: ["<client id>"]`.
- **`required_claims`** when the client is in some other claim, such as
  Okta's `cid`: `required_claims: {cid: "<client id>"}`. A single value only;
  for several clients there, check `AuthorizedToken::claims()` in the
  application.

`documented_shape_fixture_not_live_tested_shared_audience_client_restriction`
exercises both on the Auth0 and Okta shapes above. It is a documented-shape
fixture, not live-tested.

## Any other provider: checklist

1. **Issue JWT access tokens.** This crate cannot verify opaque tokens; there
   is no RFC 7662 introspection. Many servers issue opaque tokens by default
   and have a per-client or global switch for JWTs. A token without two `.`
   characters is opaque, and validation fails with `credential is not a JWT`.
   Every server verified above can issue JWT access tokens.
2. **Sign asymmetrically.** Use RS256, RS384, RS512, PS256, PS384, PS512,
   ES256, ES384 or EdDSA. HS256 cannot be verified by a resource server
   holding no shared secret, and is refused unconditionally. ES512 is not
   supported.
3. **Copy the issuer exactly** from the `issuer` field of
   `<issuer>/.well-known/openid-configuration`, trailing slash included. It is
   compared byte for byte.
4. **Decode a real access token** (the middle segment is base64url JSON) and
   read three things:
   - `aud`: put it in `audience`, or in `audiences` to accept more than one
     while migrating. There is no safe default: the right value depends on
     whether your server honours RFC 8707 (the resource URL) or stamps the
     client_id. Prefer a resource URL where the server offers one; a
     client_id audience is sound only for a client used by this API alone.
     If `aud` names the API and several clients can obtain it, also read
     which claim names the client (`client_id`, `azp`, or something like
     Okta's `cid`) and restrict it (see [Shared
     audiences](#shared-audiences-restrict-the-clients)).
   - Where the scopes are: `scope` or `scp`, as a string or an array, all
     work by default. Any other claim goes in `scope_claims`.
   - `typ` in the header: if it is `at+jwt`, turn on `require_at_jwt`.
5. **Set the scope(s) your application requires** (`required_scope` or
   `required_scopes`; the crate has no default), **list every one of them in
   `scopes_supported`** if you set that list (left out, it advertises exactly
   the required scopes), and grant them to the users who should get in. Each
   must be an RFC 6749 scope-token: no spaces, `"` or `\`.
6. **Register a client.** Most self-hosted servers have no dynamic client
   registration, so create a public client with PKCE and give its client id
   to whatever is connecting. The redirect URI must be registered exactly.
7. **Check the logs.** With `spawn_background_refresh` running, the startup
   log should say `OAuth: authorization server signing keys loaded`. For a
   refused request, the `warn` line `OAuth bearer auth rejected` (target
   `oauth_resource_server::axum`) carries the reason; the README's
   [troubleshooting table](https://github.com/St0nefish/oauth-resource-server#troubleshooting)
   maps each reason to a fix.

## Adding a provider to this guide

Contributions of recipes are welcome, at whatever level of evidence you have,
as long as the label says exactly that.

1. **Collect the shape, not the secrets.** From a real token (or the
   provider's documentation), note the issuer format, `aud`, where the scopes
   are and in what shape, `alg`, header `typ`, and which username claims are
   present. Replace hostnames, client ids and subjects with placeholders
   before sharing anything. The "Provider compatibility report" issue
   template asks for exactly this.
2. **Add a fixture test** in `src/validator.rs`, using the `testing` feature's
   keys and `mint_with`, never a real token, key or issuer URL. Name it by its
   evidence:
   - `documented_shape_fixture_not_live_tested_<provider>` for a shape taken
     from documentation or source code;
   - `observed_shape_<provider>_...` for a shape captured from a real
     instance.

   The test's comment says where the shape came from.
3. **Use configuration only.** If the provider cannot be covered by
   `OAuthConfig` fields, open an issue describing the missing knob. A
   provider-specific code path will not be accepted.
4. **Add or update the recipe here** with the label your evidence supports,
   using the exact wording above: `verified in production`, `verified in a
   sandbox`, or `documented-shape fixture, not live-tested`. Mark each bullet
   `[verified]` or `[docs]`. A recipe that sets a required scope also lists it
   in `scopes_supported`.
5. **Never upgrade someone else's label** without doing the verification it
   claims yourself, and say in the pull request what you ran.
