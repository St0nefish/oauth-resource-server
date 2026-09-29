//! [`OAuthValidator`]: JWT access-token validation against the authorization
//! server's published keys, plus the metadata document and challenge headers
//! derived from the same config.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{DecodingKey, Validation, decode, decode_header};
use serde_json::{Map, Value};
use tracing::{debug, error, info, warn};

use crate::algorithms::Algorithm;
use crate::challenge;
use crate::config::ResolvedOAuthConfig;
use crate::jwks::{
    JWKS_BACKGROUND_REFRESH_INTERVAL, JWKS_MIN_REFETCH_INTERVAL, JwksStore, KeySetStatus,
    RefreshError, background_retry_delay, http_client, keyless_retry_delay, redact_url,
};
use crate::token::{
    AuthorizedToken, MAX_TOKEN_BYTES, TokenRejection, check_typ, extract_principal, extract_scopes,
    for_log,
};

/// Why an [`OAuthValidator`] could not be built.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ValidatorError {
    /// Neither `audience` nor `audiences` holds a value. [`crate::OAuthConfig::resolve`]
    /// refuses this; only a hand-edited [`ResolvedOAuthConfig`] reaches it.
    #[error("{section}: no accepted audience configured")]
    #[non_exhaustive]
    NoAudience {
        /// The config block, named per its [`crate::KeyNaming`].
        section: String,
    },
    /// The algorithm allowlist is empty. Refused by `resolve` as well.
    #[error("{key} is empty")]
    #[non_exhaustive]
    NoAlgorithms {
        /// The `algorithms` setting, named per its [`crate::KeyNaming`].
        key: String,
    },
    /// `leeway_secs` is over [`crate::MAX_LEEWAY_SECS`]. Refused by `resolve`
    /// as well; re-checked because a larger leeway silently extends every
    /// token's life (and past the current Unix time, overflows the expiry
    /// arithmetic).
    #[error("{key} {leeway_secs} is over the {max}-second cap")]
    #[non_exhaustive]
    LeewayTooLarge {
        /// The `leeway_secs` setting, named per its [`crate::KeyNaming`].
        key: String,
        /// The configured value.
        leeway_secs: u64,
        /// [`crate::MAX_LEEWAY_SECS`].
        max: u64,
    },
    /// The HTTP client for metadata/JWKS fetches could not be built (in
    /// practice: the TLS backend failed to initialize).
    ///
    /// The underlying error is boxed rather than named, so the HTTP client
    /// library's version is not part of this crate's public API; it is still
    /// reachable through [`std::error::Error::source`].
    #[error("Failed to build the HTTP client for OAuth metadata/JWKS fetches")]
    HttpClient(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
}

/// The outcome of a cache-only validation attempt (`OAuthValidator::validate_cached`).
// One value per request, moved straight out: boxing the token buys nothing.
#[allow(clippy::large_enum_variant)]
pub(crate) enum CachedAttempt {
    /// Decided without any key fetch: accepted, or refused for a reason a
    /// fetch could not change.
    Decided(Result<AuthorizedToken, TokenRejection>),
    /// The header checks passed but no key already held fits `kid`/`alg`;
    /// only a full `validate` (which may refetch the JWKS) can decide it.
    NeedsKeyFetch,
}

/// Validates bearer credentials as JWT access tokens (RFC 9068) for one resource.
///
/// Built once from a [`ResolvedOAuthConfig`] and shared (`Arc`) for the life of
/// the process; nothing about it hot-reloads. It never issues, refreshes, revokes
/// or introspects tokens, and it only talks to the authorization server to fetch
/// its metadata (when no `jwks_uri` is configured) and its public signing keys.
///
/// Every check that can be made from the unverified header (size, JWS shape,
/// `crit`, `alg` allowlist, `typ`) runs before any key is fetched, so junk
/// cannot schedule IdP traffic. Signature, `iss`, `aud`, `exp` and `nbf` are all
/// checked inside one `jsonwebtoken::decode`, so the claim checks can never be
/// reordered ahead of the signature. Every failure fails closed.
///
/// # Runtime
///
/// Validation, [`OAuthValidator::refresh_now`] and
/// [`OAuthValidator::spawn_background_refresh`] need a Tokio 1.x runtime: key
/// fetches use `reqwest` (with a Tokio timer) and run in a spawned task. Called
/// outside one, the first key fetch panics. On `async-std`, `smol` or another
/// executor, drive them from a Tokio runtime handle.
///
/// # Extension point: opaque tokens
///
/// Opaque (non-JWT) access tokens are refused today. RFC 7662 introspection would
/// cover them but needs a client credential and per-request AS round trips, so it
/// is deliberately not built. An introspection backend would be a feature-gated
/// alternative to the JWKS key source, chosen at construction, and
/// [`OAuthValidator::validate`] would dispatch to it where it now refuses a
/// non-JWT credential. Its result is the same [`AuthorizedToken`] (and
/// [`TokenRejection`]), both `#[non_exhaustive]`, so code consuming a validation
/// result is unaffected; [`ResolvedOAuthConfig`] is `#[non_exhaustive]` too, so a
/// new resolved setting is an additive change.
///
/// [`crate::OAuthConfig`] is deliberately NOT `#[non_exhaustive]`: applications
/// build it with a functional-record update (`OAuthConfig { enabled: true,
/// ..OAuthConfig::default() }`), which that attribute would forbid outside
/// this crate, and which keeps compiling even after a field is added. Adding
/// introspection keys to it (endpoint, client credential) would instead break
/// only an exhaustive struct literal or destructuring pattern that names
/// every field — possible today because every field is public — and would
/// still ship in a new `0.x` minor release, which Cargo already treats as
/// incompatible — unless those settings are passed to a separate constructor
/// instead, which leaves `OAuthConfig` untouched.
pub struct OAuthValidator {
    /// Everything below is derived from this once; it is kept for scope and
    /// claim policy and for logging.
    config: ResolvedOAuthConfig,
    /// Pre-rendered so the 401/403 paths are a string clone, not a `format!` per
    /// rejected request.
    resource_metadata_url: String,
    /// The route the metadata document must be served on (the path of
    /// `resource_metadata_url`).
    metadata_path: String,
    /// `required_scopes`, space-joined, for the 403 challenge and the log line.
    required_scopes: String,
    /// The two `WWW-Authenticate` values, rendered once. Always valid header
    /// values: when the configured ones would not be (a control or non-ASCII
    /// character in a hand-edited `resource` or scope), `build` logs at
    /// `error` and stores `challenge::fallback`s instead.
    invalid_token_challenge: String,
    insufficient_scope_challenge: String,
    /// Whether `build` fell back. The layers refuse to build with such a
    /// validator (`AuthLayerError::InvalidChallenge`), as they always have.
    #[cfg_attr(not(any(feature = "tower", test)), allow(dead_code))] // read by the layers only
    challenge_fallback: bool,
    /// The RFC 9728 document, rendered once.
    metadata: Value,
    /// Allowlisted algorithms in the JWT library's form, for the header check.
    jwt_algorithms: Vec<jsonwebtoken::Algorithm>,
    /// Issuer/audience/expiry/not-before policy, built once. Each token gets a
    /// clone with `algorithms` narrowed to its own (already allowlisted and
    /// key-compatible) `alg`, because `jsonwebtoken` refuses a `Validation` whose
    /// algorithms span more than one key family. The claim checks all run inside
    /// `decode`, which is what keeps signature verification and claim validation
    /// from being two separately-forgettable steps.
    validation: Validation,
    /// The signing keys: cache, discovery, refresh and rate limiting. Shared
    /// with the detached tasks that run its fetches.
    keys: Arc<JwksStore>,
    /// Dropped with the validator, which is how the background refresh task
    /// learns to stop: it waits on a receiver whose `changed()` resolves once
    /// this sender is gone.
    alive: tokio::sync::watch::Sender<()>,
}

impl std::fmt::Debug for OAuthValidator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthValidator")
            .field("issuer", &self.config.issuer)
            .field("resource", &self.config.resource)
            .field("required_scopes", &self.config.required_scopes)
            .finish_non_exhaustive()
    }
}

impl OAuthValidator {
    /// Build a validator. Does no I/O: keys are fetched on first use, or earlier
    /// by [`OAuthValidator::spawn_background_refresh`] /
    /// [`OAuthValidator::refresh_now`].
    ///
    /// Build one per process and share it (`Arc`): it owns the key cache, so
    /// separate validators would each fetch and refresh their own keys.
    ///
    /// Logs a `warn` for a configuration that works but is weaker than it
    /// probably should be: a required scope missing from `scopes_supported`
    /// (clients that request the advertised scopes will get 403), no required
    /// scope with `require_at_jwt` off (ID tokens for the same client are
    /// accepted), and a plain-`http` issuer, `jwks_uri` or resource on a
    /// non-loopback host. [`crate::OAuthConfig::resolve`] refuses the last two
    /// unless the config opts in explicitly; the warning is for the deployments
    /// that did.
    ///
    /// # Errors
    ///
    /// [`ValidatorError`] when the config has no accepted audience, no
    /// algorithm, or a `leeway_secs` over [`crate::MAX_LEEWAY_SECS`] (none of
    /// which a config from [`crate::OAuthConfig::resolve`] can have, but the
    /// fields of [`ResolvedOAuthConfig`] are public), or when the HTTP client
    /// for key fetches cannot be built (the TLS backend failed to initialize).
    ///
    /// # Examples
    ///
    /// ```
    /// use std::sync::Arc;
    ///
    /// use oauth_resource_server::{KeyNaming, OAuthConfig, OAuthValidator};
    ///
    /// let resolved = OAuthConfig {
    ///     enabled: true,
    ///     issuer: "https://auth.example.com/".into(),
    ///     audience: "example-api".into(),
    ///     resource: "https://api.example.com/v1".into(),
    ///     required_scope: Some("api:read".into()),
    ///     scopes_supported: Some(vec!["api:read".into()]),
    ///     ..OAuthConfig::default()
    /// }
    /// .resolve(KeyNaming::Dotted("oauth"))
    /// .unwrap()
    /// .unwrap();
    ///
    /// let validator = Arc::new(OAuthValidator::new(&resolved).unwrap());
    /// assert_eq!(
    ///     validator.metadata_path(),
    ///     "/.well-known/oauth-protected-resource/v1"
    /// );
    /// assert_eq!(
    ///     validator.insufficient_scope_challenge(),
    ///     "Bearer error=\"insufficient_scope\", scope=\"api:read\", \
    ///      resource_metadata=\"https://api.example.com/.well-known/oauth-protected-resource/v1\""
    /// );
    /// // In a server, inside the tokio runtime:
    /// // validator.spawn_background_refresh();
    /// ```
    pub fn new(config: &ResolvedOAuthConfig) -> Result<Self, ValidatorError> {
        Self::build(config, JWKS_MIN_REFETCH_INTERVAL)
    }

    pub(crate) fn build(
        config: &ResolvedOAuthConfig,
        jwks_min_refetch_interval: Duration,
    ) -> Result<Self, ValidatorError> {
        let naming = &config.key_naming;
        // `OAuthConfig::resolve` already refuses all three of these; re-checked
        // here because `ResolvedOAuthConfig`'s fields are public and may be
        // adjusted after resolving. An empty audience set or algorithm list is
        // the construction mistake that would fail OPEN-adjacent (an empty `aud`
        // set in jsonwebtoken means "reject everything", but an empty allowlist
        // is a panic-free foot-gun nobody should have to reason about), and an
        // oversized leeway silently extends every token's life — jsonwebtoken
        // computes `now - leeway` unchecked, so past `now` it also overflows.
        let audiences = config.accepted_audiences();
        if audiences.is_empty() {
            return Err(ValidatorError::NoAudience {
                section: naming.section(),
            });
        }
        let Some(&first_alg) = config.algorithms.first() else {
            return Err(ValidatorError::NoAlgorithms {
                key: naming.key("algorithms"),
            });
        };
        if config.leeway_secs > crate::config::MAX_LEEWAY_SECS {
            return Err(ValidatorError::LeewayTooLarge {
                key: naming.key("leeway_secs"),
                leeway_secs: config.leeway_secs,
                max: crate::config::MAX_LEEWAY_SECS,
            });
        }

        let mut validation = Validation::new(first_alg.to_jwt());
        // Byte-exact issuer match. Authentik's issuer ends in a slash and the
        // difference matters — `.../example-app/` and `.../example-app` are
        // different strings and only one of them is in the tokens.
        validation.set_issuer(&[&config.issuer]);
        // Membership, per RFC 7519 §4.1.3: `aud` may be a string or an array, and
        // the token is accepted if ANY element is one of the configured audiences.
        // What those audiences should be is provider-specific and deliberately
        // config, never guessed — the client_id on servers that ignore RFC 8707
        // (Authentik, Kanidm), the resource URL on servers configured to stamp it
        // (Authelia with a client `audience`). See `OAuthConfig::audience`.
        validation.set_audience(&audiences);
        // `jsonwebtoken` only validates `iss`/`aud` when the claim is *present*, so
        // requiring them here is what turns "wrong issuer" and "no issuer at all"
        // into the same refusal. Without this a token carrying neither claim would
        // sail through both checks.
        validation.set_required_spec_claims(&["exp", "iss", "aud"]);
        validation.leeway = config.leeway_secs;
        validation.validate_exp = true;
        // Off by default in jsonwebtoken. RFC 9068 tokens (Authelia, Kanidm) carry
        // `nbf`; a token presented before it is not yet valid. jsonwebtoken skips
        // an `nbf` it cannot read as a number, so `verify` refuses one of those
        // itself (`nbf_is_numeric_date`).
        validation.validate_nbf = true;
        validation.validate_aud = true;

        let resource_metadata_url = challenge::resource_metadata_url(&config.resource);
        let metadata_path = challenge::metadata_path(&resource_metadata_url);
        let required_scopes = config.required_scopes.join(" ");
        // The 401's `scope` names what to ask for: the advertised menu, or —
        // when the config advertises none — what is required, so a client is
        // never left to request nothing and be refused with 403.
        let supported_scopes = if config.scopes_supported.is_empty() {
            required_scopes.clone()
        } else {
            config.scopes_supported.join(" ")
        };
        // Every challenge this validator (and so `refusal()`) hands out must be
        // a valid header value. `resolve` refuses every config that would break
        // one; a hand-edited resolved config still builds (refusing it here
        // would narrow what builds), but gets a safe fallback and a loud log
        // line, and the layers refuse it (`challenge_fallback`).
        let mut invalid_token_challenge =
            challenge::invalid_token(&resource_metadata_url, &supported_scopes);
        let mut insufficient_scope_challenge =
            challenge::insufficient_scope(&required_scopes, &resource_metadata_url);
        let challenge_fallback = !challenge::is_header_value(&invalid_token_challenge)
            || !challenge::is_header_value(&insufficient_scope_challenge);
        if challenge_fallback {
            invalid_token_challenge = challenge::fallback("invalid_token", &supported_scopes);
            insufficient_scope_challenge =
                challenge::fallback("insufficient_scope", &required_scopes);
            error!(
                resource = %redact_url(&config.resource),
                "the WWW-Authenticate challenge built from {}, {} and {} is not a valid HTTP \
                 header value (a control or non-ASCII character); sending a fallback \
                 challenge without resource_metadata, which clients need to find the \
                 authorization server. Fix the configuration (resolve refuses it).",
                naming.key("resource"),
                naming.key("scopes_supported"),
                naming.key("required_scopes"),
            );
        }

        // A required scope nobody is told to ask for is a guaranteed 403 for every
        // client that requests exactly `scopes_supported`. Not fatal — an operator
        // may be advertising a narrower menu on purpose — but never silent. An
        // empty `scopes_supported` is not that case: the challenge then names
        // the required scopes itself (`supported_scopes` above), so a client is
        // told exactly what to request.
        let unadvertised = unadvertised_scopes(config);
        if !unadvertised.is_empty() {
            // Names the scopes rather than a setting: `required_scopes` is the union
            // of `required_scope` and `required_scopes`, and which of the two an
            // unadvertised scope came from is not known here.
            warn!(
                unadvertised_scopes = %unadvertised.join(" "),
                scopes_supported = ?config.scopes_supported,
                "required scope(s) {} not in {} — clients that request the advertised \
                 scopes will get 403 insufficient_scope",
                unadvertised.join(" "),
                naming.key("scopes_supported")
            );
        }
        // Valid by design (an application may need only "signed by this issuer for
        // this audience"), but a weaker posture than a scoped deployment, so it is
        // said once at construction rather than left implicit. With `typ` not
        // enforced either, nothing tells an access token from an ID token minted
        // for the same client: on servers that stamp the client_id as `aud`
        // (Authentik, Kanidm) the ID token a front end got from an OIDC login is
        // then a working bearer credential. That combination is a warning.
        match unscoped_posture(config) {
            UnscopedPosture::Scoped => {}
            UnscopedPosture::UnscopedButTypEnforced => info!(
                "no required scope configured ({} and {} unset) — every valid access \
                 token (typ at+jwt) for the audience is accepted",
                naming.key("required_scope"),
                naming.key("required_scopes")
            ),
            UnscopedPosture::IdTokensAccepted => warn!(
                "no required scope configured ({} and {} unset) and {} is off — ANY token \
                 this issuer signs for the audience is accepted, including an OIDC ID token \
                 minted for the same client. Set {} (a scope only access tokens carry) or \
                 turn on {} if the authorization server emits typ at+jwt.",
                naming.key("required_scope"),
                naming.key("required_scopes"),
                naming.key("require_at_jwt"),
                naming.key("required_scope"),
                naming.key("require_at_jwt")
            ),
        }
        if plain_http_non_loopback(&config.issuer) {
            warn!(
                issuer = %redact_url(&config.issuer),
                "{} uses plain http on a non-loopback host — signing keys fetched over it \
                 can be substituted by anyone on the path. Use https.",
                naming.key("issuer")
            );
        }
        if plain_http_non_loopback(&config.resource) {
            warn!(
                resource = %redact_url(&config.resource),
                "{} uses plain http on a non-loopback host — bearer tokens sent to it can \
                 be read in transit. Use https.",
                naming.key("resource")
            );
        }
        if let Some(jwks_uri) = config.jwks_uri.as_deref().map(str::trim)
            && plain_http_non_loopback(jwks_uri)
        {
            // The discovered-URI path refuses this outright when the issuer is
            // https, and without `allow_insecure_http` otherwise
            // (`jwks_uri_from_metadata`; `refresh` warns when the opt-in lets
            // one through). A configured one reaches here only
            // with `allow_insecure_http` (or a hand-edited resolved config) — an
            // in-cluster `http://idp:9000/...` behind a private network is a real
            // deployment shape — so it is warned about, never silent.
            warn!(
                jwks_uri = %redact_url(jwks_uri),
                "{} uses plain http on a non-loopback host — signing keys fetched over it \
                 can be substituted by anyone on the path. Use https.",
                naming.key("jwks_uri")
            );
        }

        let metadata = challenge::metadata_document(config);
        let http = http_client(
            config.allow_insecure_http,
            naming.key("allow_insecure_http"),
        )
        .map_err(|e| ValidatorError::HttpClient(Box::new(e)))?;

        Ok(Self {
            config: config.clone(),
            resource_metadata_url,
            metadata_path,
            required_scopes,
            invalid_token_challenge,
            insufficient_scope_challenge,
            challenge_fallback,
            metadata,
            jwt_algorithms: config.algorithms.iter().map(|a| a.to_jwt()).collect(),
            validation,
            keys: Arc::new(JwksStore::new(config, http, jwks_min_refetch_interval)),
            alive: tokio::sync::watch::channel(()).0,
        })
    }

    /// The config this validator was built from.
    pub fn config(&self) -> &ResolvedOAuthConfig {
        &self.config
    }

    /// The protected resource's identifier ([`crate::OAuthConfig::resource`]).
    pub fn resource(&self) -> &str {
        &self.config.resource
    }

    /// The protected-resource metadata URL advertised in every challenge's
    /// `resource_metadata` parameter (RFC 9728 §3: the well-known segment spliced
    /// between the resource's authority and path).
    pub fn resource_metadata_url(&self) -> &str {
        &self.resource_metadata_url
    }

    /// The path of [`OAuthValidator::resource_metadata_url`] — the route the
    /// metadata document must be served on, e.g.
    /// `/.well-known/oauth-protected-resource/mcp` for a resource at `/mcp`, or
    /// the bare [`crate::PROTECTED_RESOURCE_METADATA_PREFIX`] for a resource at
    /// the root.
    ///
    /// It comes from config and may contain characters a router reads as
    /// pattern syntax (`{…}`, or a segment starting with `:` or `*`, which axum
    /// refuses with a panic), so an app serving it itself should compare the
    /// request path against it literally rather than register it as a route.
    /// The `axum` feature's `metadata_router` does exactly that.
    pub fn metadata_path(&self) -> &str {
        &self.metadata_path
    }

    /// The RFC 9728 protected-resource metadata document, rendered once at
    /// construction. `scopes_supported` is left out when the list is empty
    /// (RFC 9728 §3.2: a parameter with zero values is omitted).
    pub fn metadata(&self) -> &Value {
        &self.metadata
    }

    /// The `WWW-Authenticate` value for every 401 — a refused credential and, by
    /// deliberate choice, a missing one too:
    /// `Bearer error="invalid_token", resource_metadata="…", scope="…"`.
    /// `scope` lists `scopes_supported`, or the required scopes when nothing is
    /// advertised (the MCP authorization spec asks servers to name the scopes
    /// needed here). With neither, the parameter is omitted, not sent empty:
    /// RFC 6749 §3.3 requires at least one scope-token.
    ///
    /// Load-bearing, not cosmetic: claude.ai has been observed refusing to start
    /// the authorization flow at all when a 401 arrives without it, because
    /// `resource_metadata` is how the client finds the authorization server in the
    /// first place. Claude Code tolerates its absence, which is exactly why it is
    /// easy to drop and hard to notice. Emit it on EVERY 401 once OAuth is
    /// configured — including a failed static-token request, since the server
    /// cannot tell which credential the caller meant to present.
    ///
    /// Always a valid header value: with a hand-edited config that would break
    /// it (a control or non-ASCII character in `resource` or a scope), this is
    /// the fallback `Bearer error="invalid_token"` (plus `scope` when that is
    /// valid), logged at `error` when the validator is built.
    pub fn invalid_token_challenge(&self) -> String {
        self.invalid_token_challenge.clone()
    }

    /// The `WWW-Authenticate` value for a 403:
    /// `Bearer error="insufficient_scope", scope="…", resource_metadata="…"`.
    ///
    /// The token was genuinely valid, so `scope` names what is *required* —
    /// every required scope, space-delimited (RFC 6750 §3) — rather than
    /// everything on offer. That is the difference that lets a client
    /// re-authorize for the right thing instead of replaying the same request.
    /// With no required scope (no token is ever refused for scope) the `scope`
    /// parameter is omitted.
    ///
    /// Always a valid header value, falling back as
    /// [`OAuthValidator::invalid_token_challenge`] does.
    pub fn insufficient_scope_challenge(&self) -> String {
        self.insufficient_scope_challenge.clone()
    }

    /// Whether the configured challenges were not valid header values and the
    /// fallbacks are in use; the layers refuse to build with such a validator.
    #[cfg_attr(not(any(feature = "tower", test)), allow(dead_code))] // read by the layers only
    pub(crate) fn challenge_fell_back(&self) -> bool {
        self.challenge_fallback
    }

    /// Validate a bearer credential as a JWT access token.
    ///
    /// Order matters and is RFC 9068 §4's: everything that can be refused from the
    /// unverified header alone (size, shape, `alg` allowlist, `typ`) is refused
    /// before any key is fetched, so junk cannot schedule IdP traffic; then the
    /// signature; then issuer / audience / expiry / not-before — all inside
    /// `jsonwebtoken::decode`, so they cannot be reordered ahead of the signature by
    /// accident — then scope: the token must carry EVERY required scope.
    ///
    /// `token` is the credential alone, without the `Bearer ` prefix. When the
    /// signing key is not cached this fetches the JWKS (at most once a minute
    /// for an unknown `kid`), so the call can wait on a fetch, each bounded by
    /// a 10-second timeout. The fetch runs in a task of its own, so dropping
    /// this future does not cancel it. Logs an insufficient scope at `info` and
    /// a failed key refresh at `warn`; logging the outcome is the caller's job.
    ///
    /// # Errors
    ///
    /// - [`TokenRejection::Missing`] for an empty `token`.
    /// - [`TokenRejection::Invalid`] for everything that makes the token no
    ///   good: over 16 KiB, not a JWT, an unparsable header, a header listing
    ///   critical extensions (`crit`, RFC 7515 §4.1.11: this crate supports
    ///   none), an `alg` outside the allowlist, a refused `typ`, no usable key,
    ///   a bad signature, a wrong or missing `iss`/`aud`, an expired or
    ///   not-yet-valid token, an `nbf` that is not a NumericDate, or a
    ///   sender-constrained token (a `cnf` claim: DPoP, RFC 9449 §7.2, or
    ///   mTLS, RFC 8705 §3), which this crate cannot verify the binding of and
    ///   so will not accept as a plain bearer token.
    /// - [`TokenRejection::InsufficientScope`] for a valid token that lacks a
    ///   required scope.
    ///
    /// # Panics
    ///
    /// Outside a Tokio 1.x runtime, when a key has to be fetched (see
    /// [Runtime](OAuthValidator#runtime)).
    ///
    /// # Security
    ///
    /// The reason inside `Invalid` names the check that failed. Log it; never
    /// send it to the caller, for whom it would be an oracle. Answer with
    /// [`OAuthValidator::invalid_token_challenge`] or
    /// [`OAuthValidator::insufficient_scope_challenge`] instead.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use oauth_resource_server::{OAuthValidator, TokenRejection};
    ///
    /// /// The status and `WWW-Authenticate` value for a request.
    /// async fn check(validator: &OAuthValidator, bearer: &str) -> (u16, Option<String>) {
    ///     match validator.validate(bearer).await {
    ///         Ok(token) => {
    ///             println!("accepted {:?} with scopes {:?}", token.subject, token.scopes);
    ///             (200, None)
    ///         }
    ///         Err(TokenRejection::InsufficientScope) => {
    ///             (403, Some(validator.insufficient_scope_challenge()))
    ///         }
    ///         Err(rejection) => {
    ///             eprintln!("refused: {rejection:?}"); // for the log only
    ///             (401, Some(validator.invalid_token_challenge()))
    ///         }
    ///     }
    /// }
    /// ```
    pub async fn validate(&self, token: &str) -> Result<AuthorizedToken, TokenRejection> {
        let header = self.check_header(token)?;
        let key = self
            .keys
            .decoding_key(header.kid.as_deref(), header.alg)
            .await?;
        self.verify(token, header.alg, &key)
    }

    /// [`OAuthValidator::validate`] against the keys already held, never
    /// fetching: [`CachedAttempt::NeedsKeyFetch`] when every header check passed
    /// but no cached key fits. Everything else — header refusals, signature and
    /// claim checks, scope — is exactly `validate`'s, in the same order.
    ///
    /// [`crate::authenticate()`] runs this over every candidate first, so a
    /// candidate whose key is cached is decided before any other candidate's
    /// unknown `kid` can queue the request behind a JWKS refetch.
    pub(crate) async fn validate_cached(&self, token: &str) -> CachedAttempt {
        let header = match self.check_header(token) {
            Ok(header) => header,
            Err(rejection) => return CachedAttempt::Decided(Err(rejection)),
        };
        match self
            .keys
            .cached_decoding_key(header.kid.as_deref(), header.alg)
            .await
        {
            Some(key) => CachedAttempt::Decided(self.verify(token, header.alg, &key)),
            None => CachedAttempt::NeedsKeyFetch,
        }
    }

    /// Everything that can be refused from the unverified header alone (size,
    /// shape, `crit`, `alg` allowlist, `typ`), before any key is looked up.
    pub(crate) fn check_header(&self, token: &str) -> Result<CheckedHeader, TokenRejection> {
        if token.is_empty() {
            return Err(TokenRejection::Missing);
        }
        if token.len() > MAX_TOKEN_BYTES {
            return Err(TokenRejection::Invalid(format!(
                "credential is {} bytes, over the {MAX_TOKEN_BYTES}-byte cap",
                token.len()
            )));
        }
        if token.split('.').count() != 3 {
            // The single most useful hint in this crate for a new deployment:
            // Authelia (by default), Ory Hydra (by default) and others issue OPAQUE
            // access tokens, which no amount of JWKS can verify. (This is where an
            // RFC 7662 introspection backend would take over; see the type docs.)
            return Err(TokenRejection::Invalid(
                "credential is not a JWT (a mistyped static token, or an opaque access \
                 token — this server validates JWT access tokens only; configure the \
                 authorization server to issue JWT access tokens)"
                    .into(),
            ));
        }

        // The header is unverified data. It is read only to pick which key to
        // verify WITH; nothing from it is trusted afterwards, and `alg` is checked
        // against our allowlist (and later against the key) rather than obeyed.
        // `alg: none` does not even get this far: jsonwebtoken's `Algorithm` has no
        // `none` variant, so the header fails to parse.
        // The error text can echo attacker-supplied header content (an unknown
        // `alg` string, verbatim), so it is truncated like every other
        // token-derived string that reaches a log line.
        let header = decode_header(token).map_err(|e| {
            TokenRejection::Invalid(format!(
                "malformed token header: {}",
                for_log(&e.to_string())
            ))
        })?;
        check_crit(token)?;
        let alg = Algorithm::from_jwt(header.alg)
            .filter(|_| self.jwt_algorithms.contains(&header.alg))
            .ok_or_else(|| {
                TokenRejection::Invalid(format!(
                    "token algorithm {:?} is not in {}",
                    header.alg,
                    self.config.key_naming.key("algorithms")
                ))
            })?;
        check_typ(
            header.typ.as_deref(),
            self.config.require_at_jwt,
            &self.config.key_naming,
        )?;
        Ok(CheckedHeader {
            kid: header.kid,
            alg,
        })
    }

    /// Signature, then issuer / audience / expiry / not-before, then the
    /// claims the decoder does not police (`iss` shape, `nbf` type, `cnf`),
    /// then scope, against `key` — which [`OAuthValidator::check_header`]'s
    /// output selected.
    fn verify(
        &self,
        token: &str,
        alg: Algorithm,
        key: &DecodingKey,
    ) -> Result<AuthorizedToken, TokenRejection> {
        let mut validation = self.validation.clone();
        validation.algorithms = vec![alg.to_jwt()];
        let data = decode::<Map<String, Value>>(token, key, &validation).map_err(|e| {
            // `jsonwebtoken`'s error kinds already distinguish bad signature from
            // bad issuer/audience/expiry; all of them are 401 `invalid_token` to the
            // caller, and only the log gets to know which.
            TokenRejection::Invalid(format!("token rejected: {e}"))
        })?;
        let claims = data.claims;

        // Belt and braces on `iss`: jsonwebtoken also accepts an `iss` ARRAY that
        // merely contains the configured issuer. RFC 7519 makes `iss` a single
        // StringOrURI, and "one of several issuers" is not a shape any real AS
        // emits, so anything but the exact string is refused.
        if claims.get("iss").and_then(Value::as_str) != Some(self.config.issuer.as_str()) {
            return Err(TokenRejection::Invalid(format!(
                "token iss is not a single string equal to {}",
                self.config.key_naming.key("issuer")
            )));
        }

        // RFC 7519 §4.1.5: `nbf` is a NumericDate, and the token MUST NOT be
        // accepted before it. jsonwebtoken checks it only when it reads as a
        // number and silently skips anything else (a string, a negative or
        // out-of-range value), which would turn a not-yet-valid token into a
        // valid one. Anything it could not have checked is refused here.
        if let Some(nbf) = claims.get("nbf")
            && !nbf_is_numeric_date(nbf)
        {
            return Err(TokenRejection::Invalid(
                "token nbf is not a NumericDate (a non-negative number of seconds)".into(),
            ));
        }

        // A `cnf` (confirmation) claim binds the token to a key the client must
        // prove it holds: DPoP (RFC 9449, `jkt`) or an mTLS certificate (RFC
        // 8705, `x5t#S256`). This crate verifies neither proof, so accepting the
        // token as a plain bearer token would undo the binding the
        // authorization server set up — exactly what RFC 9449 §7.2 and RFC 8705
        // §3 forbid a resource server to do.
        if claims.contains_key("cnf") {
            return Err(TokenRejection::Invalid(
                "token is sender-constrained (cnf); this server accepts bearer tokens only".into(),
            ));
        }

        let scopes = extract_scopes(&claims, &self.config.scope_claims);
        let principal = extract_principal(&claims, &self.config.principal_claims);
        let subject = claims
            .get("sub")
            .and_then(Value::as_str)
            .map(str::to_string);

        // All-of: every required scope must be present. An empty requirement
        // passes every token.
        if !self
            .config
            .required_scopes
            .iter()
            .all(|required| scopes.contains(required))
        {
            // Info, not debug: this is the refusal an operator wiring up a new
            // authorization server hits first (Authelia's `scp`-only tokens were
            // exactly this), and `present=[]` next to the claims that were
            // read is most of the diagnosis. Scopes are not secret.
            info!(
                principal = ?principal.as_deref().map(for_log),
                required = %self.required_scopes,
                present = ?scopes,
                scope_claims = ?self.config.scope_claims,
                "OAuth token is valid but lacks the required scope"
            );
            return Err(TokenRejection::InsufficientScope);
        }

        Ok(AuthorizedToken::from_verified_claims(
            claims, subject, principal, scopes,
        ))
    }

    /// Load (or reload) the key set now, discovering the JWKS URI first if needed.
    /// Returns how many usable keys it holds. On failure the previous keys are
    /// kept — a transient IdP outage must not invalidate keys that are still good.
    ///
    /// Useful for a startup step that waits for the keys, or a test. It fetches
    /// every time, so a probe should call [`OAuthValidator::is_ready`] or
    /// [`OAuthValidator::key_set_status`] instead, which do no I/O.
    /// [`OAuthValidator::spawn_background_refresh`] already calls it
    /// once at startup and then hourly. The fetch runs in a task of its own,
    /// so dropping this future does not cancel it.
    ///
    /// # Errors
    ///
    /// [`RefreshError`] when discovery fails (no metadata document, or one for
    /// a different issuer), the JWKS cannot be fetched (network, TLS, status,
    /// size cap, not JSON), or the key set holds no key usable with the
    /// configured algorithms. Its `Display` includes the whole cause chain.
    ///
    /// # Panics
    ///
    /// Outside a Tokio 1.x runtime (see [Runtime](OAuthValidator#runtime)).
    pub async fn refresh_now(&self) -> Result<usize, RefreshError> {
        self.keys.refresh_now().await
    }

    /// A snapshot of the signing keys this validator holds: how many, the
    /// JWKS URL in use, when a refresh was last attempted and last succeeded,
    /// and why the last one failed, if it did.
    ///
    /// Passive: it does no I/O, never takes the refresh lock and never waits
    /// on a refresh in flight — it copies a few fields under a lock that is
    /// only ever held for such a copy. Unlike [`OAuthValidator::refresh_now`]
    /// it is cheap enough for a readiness probe, a status page or a metrics
    /// scrape to call on every request, and needs no Tokio runtime. It only
    /// reports: nothing loads keys unless
    /// [`OAuthValidator::spawn_background_refresh`] runs (or a request or
    /// [`OAuthValidator::refresh_now`] triggers a fetch), so a probe gating on
    /// it needs that task. The `jwks_uri` and any error message in it are
    /// redacted (see [`RefreshError`]).
    ///
    /// # Examples
    ///
    /// A status report for an operator-facing page:
    ///
    /// ```
    /// use std::time::SystemTime;
    ///
    /// use oauth_resource_server::OAuthValidator;
    ///
    /// fn key_report(validator: &OAuthValidator) -> String {
    ///     let status = validator.key_set_status();
    ///     let age = status
    ///         .last_success
    ///         .and_then(|t| SystemTime::now().duration_since(t).ok())
    ///         .map_or("never".to_string(), |d| format!("{}s ago", d.as_secs()));
    ///     let error = match &status.last_error {
    ///         // `kind()` is safe to show anyone; the full `Display` (URLs and
    ///         // upstream error text) is for logs and operators.
    ///         Some(e) => e.kind().as_str(),
    ///         None => "none",
    ///     };
    ///     format!(
    ///         "{} key(s) from {}, loaded {age}, last error: {error}",
    ///         status.keys,
    ///         status.jwks_uri.as_deref().unwrap_or("(not yet discovered)"),
    ///     )
    /// }
    /// # let resolved = oauth_resource_server::OAuthConfig {
    /// #     enabled: true,
    /// #     issuer: "https://auth.example.com/".into(),
    /// #     jwks_uri: Some("https://auth.example.com/jwks".into()),
    /// #     audience: "example-api".into(),
    /// #     resource: "https://api.example.com/".into(),
    /// #     required_scope: Some("api:read".into()),
    /// #     ..Default::default()
    /// # }
    /// # .resolve(oauth_resource_server::KeyNaming::Dotted("oauth"))
    /// # .unwrap()
    /// # .unwrap();
    /// # let validator = OAuthValidator::new(&resolved).unwrap();
    /// // Before any key load:
    /// assert_eq!(
    ///     key_report(&validator),
    ///     "0 key(s) from https://auth.example.com/jwks, loaded never, last error: none"
    /// );
    /// ```
    pub fn key_set_status(&self) -> KeySetStatus {
        self.keys.status()
    }

    /// At least one usable signing key is held, so a token signed by it can be
    /// validated. Passive, like [`OAuthValidator::key_set_status`]: no I/O, no
    /// waiting on a refresh.
    ///
    /// It never goes back to `false` once `true`: a failed refresh keeps the
    /// keys already held (see [`OAuthValidator::refresh_now`]). That makes it
    /// the right readiness signal, and the wrong liveness one — see the
    /// README's "Readiness and liveness probes".
    ///
    /// Gate readiness on it only with [`OAuthValidator::spawn_background_refresh`]
    /// running (or at least a startup [`OAuthValidator::refresh_now`]).
    /// Otherwise keys load only when a request brings a token — and a
    /// not-ready process gets no requests, so it would never become ready.
    ///
    /// # Examples
    ///
    /// ```
    /// use oauth_resource_server::OAuthValidator;
    ///
    /// /// The status code for a readiness endpoint.
    /// fn readiness(validator: &OAuthValidator) -> u16 {
    ///     if validator.is_ready() { 200 } else { 503 }
    /// }
    /// # let resolved = oauth_resource_server::OAuthConfig {
    /// #     enabled: true,
    /// #     issuer: "https://auth.example.com/".into(),
    /// #     audience: "example-api".into(),
    /// #     resource: "https://api.example.com/".into(),
    /// #     required_scope: Some("api:read".into()),
    /// #     ..Default::default()
    /// # }
    /// # .resolve(oauth_resource_server::KeyNaming::Dotted("oauth"))
    /// # .unwrap()
    /// # .unwrap();
    /// # let validator = OAuthValidator::new(&resolved).unwrap();
    /// assert_eq!(readiness(&validator), 503); // no key loaded yet
    /// ```
    pub fn is_ready(&self) -> bool {
        self.keys.has_keys()
    }

    /// Warm the key cache at startup and keep it fresh; returns the task's handle.
    ///
    /// The first pass turns a misconfigured issuer, an unreachable JWKS or a
    /// discovery mismatch into one clear log line at boot instead of a wall of
    /// 401s on the first real request — without making startup itself depend on
    /// the authorization server being up (a restart during an IdP outage must not
    /// take this service down too). Later passes, hourly, are what drop a key the
    /// AS has withdrawn — once one succeeds: a failed pass keeps every key held,
    /// and is retried after a minute, backing off to an hour.
    ///
    /// While no key is held at all (the first load failed and nothing has
    /// succeeded since), a failed pass is retried sooner: after 5 s, doubling
    /// to at most 5 minutes. A keyless validator refuses every token, and a
    /// readiness probe on [`OAuthValidator::is_ready`] keeps the traffic that
    /// would otherwise trigger a refetch away from it, so this schedule is
    /// what brings it back once the authorization server recovers. These
    /// retries are timer-driven only; nothing in a request can schedule one.
    ///
    /// The first load logs `OAuth: authorization server signing keys loaded` at
    /// `info`, or `OAuth: could not load the authorization server's signing
    /// keys` at `warn`. The task holds only a weak reference between passes: it
    /// stops once the last `Arc` of this validator is dropped (or when the
    /// returned handle is aborted), so rebuilding a validator does not leave the
    /// old one polling. Dropping the handle alone does not stop it.
    ///
    /// # Panics
    ///
    /// When called outside a Tokio 1.x runtime (it uses `tokio::spawn`).
    pub fn spawn_background_refresh(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let weak = Arc::downgrade(self);
        let mut alive = self.alive.subscribe();
        tokio::spawn(async move {
            let mut first = true;
            let mut failures: u32 = 0;
            loop {
                let Some(this) = weak.upgrade() else {
                    return;
                };
                let wait = match this.refresh_now().await {
                    Ok(count) => {
                        if first {
                            info!(
                                issuer = %redact_url(&this.config.issuer),
                                keys = count,
                                "OAuth: authorization server signing keys loaded"
                            );
                        } else {
                            debug!(keys = count, "OAuth: signing keys refreshed");
                        }
                        failures = 0;
                        JWKS_BACKGROUND_REFRESH_INTERVAL
                    }
                    Err(e) => {
                        failures = failures.saturating_add(1);
                        let wait = if this.keys.has_keys() {
                            background_retry_delay(failures)
                        } else {
                            keyless_retry_delay(failures)
                        };
                        warn!(
                            issuer = %redact_url(&this.config.issuer),
                            error = %e,
                            retry_in_secs = wait.as_secs(),
                            "OAuth: could not load the authorization server's signing keys — \
                             tokens signed by a key this server does not already hold will be \
                             rejected (401) until a later attempt succeeds. Check {} / {} and \
                             that this host can reach them.",
                            this.config.key_naming.key("issuer"),
                            this.config.key_naming.key("jwks_uri")
                        );
                        wait
                    }
                };
                first = false;
                // Only the weak reference survives the wait, so the validator
                // can be dropped meanwhile — which drops `alive`'s sender and
                // ends the wait at once.
                drop(this);
                if tokio::time::timeout(wait, alive.changed()).await.is_ok() {
                    return;
                }
            }
        })
    }
}

/// The header fields a validation carries forward: the `kid` to look the key
/// up by, and the allowlisted algorithm.
pub(crate) struct CheckedHeader {
    kid: Option<String>,
    alg: Algorithm,
}

/// RFC 7515 §4.1.11: a recipient that does not understand every extension a
/// JWS lists in `crit` MUST treat it as invalid. This crate understands none,
/// so any `crit` — including an empty or malformed one — is refused.
/// jsonwebtoken's `Header` has no `crit` field and drops it silently, so the
/// protected header is read raw here. Called after `decode_header` succeeded,
/// so the segment is known to be base64url JSON; it is at most the 16 KiB
/// credential cap.
pub(crate) fn check_crit(token: &str) -> Result<(), TokenRejection> {
    let segment = token.split('.').next().unwrap_or_default();
    let header: Map<String, Value> = URL_SAFE_NO_PAD
        .decode(segment)
        .ok()
        .and_then(|raw| serde_json::from_slice(&raw).ok())
        .ok_or_else(|| {
            TokenRejection::Invalid("malformed token header: not a base64url JSON object".into())
        })?;
    if header.contains_key("crit") {
        return Err(TokenRejection::Invalid(
            "token header lists critical extensions (crit), none of which this server supports"
                .into(),
        ));
    }
    Ok(())
}

/// Whether `nbf` is a NumericDate jsonwebtoken actually checks: a non-negative
/// number it can read as whole seconds.
fn nbf_is_numeric_date(nbf: &Value) -> bool {
    nbf.as_u64().is_some()
        || nbf
            .as_f64()
            .is_some_and(|f| f.is_finite() && f >= 0.0 && f < u64::MAX as f64)
}

/// The scope/`typ` posture a validator was built with; see the warning it
/// drives in [`OAuthValidator::build`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnscopedPosture {
    /// At least one required scope: an ID token (which carries no scope claim
    /// on any mainstream server) is refused with 403.
    Scoped,
    /// No required scope, but `require_at_jwt` refuses anything not typed as
    /// an access token.
    UnscopedButTypEnforced,
    /// No required scope and no `typ` enforcement: an ID token for the same
    /// client (`aud` = client_id) is indistinguishable from an access token.
    IdTokensAccepted,
}

fn unscoped_posture(config: &ResolvedOAuthConfig) -> UnscopedPosture {
    match (config.required_scopes.is_empty(), config.require_at_jwt) {
        (false, _) => UnscopedPosture::Scoped,
        (true, true) => UnscopedPosture::UnscopedButTypEnforced,
        (true, false) => UnscopedPosture::IdTokensAccepted,
    }
}

/// Required scopes a client is never told to request: those missing from a
/// non-empty `scopes_supported`. Empty when `scopes_supported` is empty, since
/// the challenge then advertises the required scopes themselves.
fn unadvertised_scopes(config: &ResolvedOAuthConfig) -> Vec<&str> {
    if config.scopes_supported.is_empty() {
        return Vec::new();
    }
    config
        .required_scopes
        .iter()
        .filter(|s| !config.scopes_supported.contains(s))
        .map(String::as_str)
        .collect()
}

/// Whether `url` is plain `http://` to a host other than loopback/`localhost`.
pub(crate) fn plain_http_non_loopback(url: &str) -> bool {
    url.get(..7)
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("http://"))
        && !is_loopback_url(url)
}

/// Whether `url`'s host is a loopback address or `localhost`.
pub(crate) fn is_loopback_url(url: &str) -> bool {
    let Ok(parsed) = reqwest::Url::parse(url) else {
        return false;
    };
    let Some(host) = parsed.host_str() else {
        return false;
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host == "localhost"
        || host.ends_with(".localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::KeyNamingBuf;
    use crate::jwks::{MAX_FETCH_BYTES, RefreshErrorKind};
    use crate::testing::*;
    use std::collections::HashMap;
    use std::sync::atomic::Ordering;

    fn oauth_config(jwks_uri: &str) -> ResolvedOAuthConfig {
        resolved_config(jwks_uri)
    }

    /// Zero cooldown: a test that wants to observe a refetch should not have to
    /// sleep out `JWKS_MIN_REFETCH_INTERVAL`.
    fn validator_no_cooldown(jwks_uri: &str) -> OAuthValidator {
        OAuthValidator::build(&oauth_config(jwks_uri), Duration::ZERO).unwrap()
    }

    fn validator(jwks_uri: &str) -> OAuthValidator {
        OAuthValidator::new(&oauth_config(jwks_uri)).unwrap()
    }

    fn validator_with(cfg: ResolvedOAuthConfig) -> OAuthValidator {
        OAuthValidator::new(&cfg).unwrap()
    }

    fn claims(extra: serde_json::Value) -> serde_json::Value {
        let mut base = serde_json::json!({
            "iss": ISSUER, "aud": AUDIENCE, "sub": "user-1", "exp": now() + 3600,
        });
        for (k, v) in extra.as_object().unwrap() {
            base[k] = v.clone();
        }
        base
    }

    fn is_invalid<T: std::fmt::Debug>(r: &Result<T, TokenRejection>) -> bool {
        matches!(r, Err(TokenRejection::Invalid(_)))
    }

    // ── construction ─────────────────────────────────────────────────────────

    #[test]
    fn construction_refuses_an_empty_audience_set_or_algorithm_list() {
        let mut cfg = oauth_config("http://127.0.0.1:1/jwks");
        cfg.audience = String::new();
        let err = OAuthValidator::new(&cfg).unwrap_err();
        assert!(matches!(err, ValidatorError::NoAudience { .. }));
        assert_eq!(
            err.to_string(),
            "mcp.oauth: no accepted audience configured"
        );

        // OAuth fields at the root of the config: the block still gets a name.
        let mut cfg = oauth_config("http://127.0.0.1:1/jwks");
        cfg.audience = String::new();
        cfg.key_naming = KeyNamingBuf::Dotted(String::new());
        let err = OAuthValidator::new(&cfg).unwrap_err();
        assert_eq!(
            err.to_string(),
            "OAuth config: no accepted audience configured"
        );

        let mut cfg = oauth_config("http://127.0.0.1:1/jwks");
        cfg.algorithms.clear();
        let err = OAuthValidator::new(&cfg).unwrap_err();
        assert_eq!(err.to_string(), "mcp.oauth.algorithms is empty");

        cfg.key_naming = KeyNamingBuf::Env("APP_OAUTH_".into());
        let err = OAuthValidator::new(&cfg).unwrap_err();
        assert_eq!(err.to_string(), "APP_OAUTH_ALGORITHMS is empty");
    }

    #[test]
    fn construction_refuses_a_leeway_over_the_cap_set_after_resolving() {
        let mut cfg = oauth_config("http://127.0.0.1:1/jwks");
        cfg.leeway_secs = crate::MAX_LEEWAY_SECS;
        OAuthValidator::new(&cfg).expect("the cap itself is allowed");

        for leeway in [crate::MAX_LEEWAY_SECS + 1, 86_400, u64::MAX] {
            cfg.leeway_secs = leeway;
            let err = OAuthValidator::new(&cfg).unwrap_err();
            assert!(
                matches!(err, ValidatorError::LeewayTooLarge { .. }),
                "{err}"
            );
            assert_eq!(
                err.to_string(),
                format!("mcp.oauth.leeway_secs {leeway} is over the 300-second cap")
            );
        }
    }

    #[test]
    fn the_unscoped_posture_is_classified_for_the_startup_log() {
        let mut cfg = oauth_config("http://127.0.0.1:1/jwks");
        assert!(!cfg.required_scopes.is_empty());
        assert_eq!(unscoped_posture(&cfg), UnscopedPosture::Scoped);
        cfg.require_at_jwt = true;
        assert_eq!(unscoped_posture(&cfg), UnscopedPosture::Scoped);

        // No scope: only `typ` enforcement keeps an ID token out.
        cfg.required_scopes.clear();
        assert_eq!(
            unscoped_posture(&cfg),
            UnscopedPosture::UnscopedButTypEnforced
        );
        cfg.require_at_jwt = false;
        assert_eq!(unscoped_posture(&cfg), UnscopedPosture::IdTokensAccepted);
    }

    /// The combination the startup warning is about: with no required scope and
    /// `require_at_jwt` off, an ID token (typ `JWT`, no scope claim) signed for
    /// the same client is accepted; either setting turns it away.
    #[tokio::test]
    async fn an_id_token_is_accepted_only_when_unscoped_and_typ_is_not_enforced() {
        let jwks = spawn_jwks_server("200 OK", jwks_body()).await;
        let id_token = mint_with(
            Algorithm::RS256,
            Some(KID_A),
            Some("JWT"),
            &claims(serde_json::json!({ "nonce": "n-1", "auth_time": now() })),
        );

        let mut cfg = oauth_config(&jwks.url);
        cfg.required_scopes.clear();
        assert!(
            validator_with(cfg.clone())
                .validate(&id_token)
                .await
                .is_ok()
        );

        let mut scoped = cfg.clone();
        scoped.required_scopes = vec!["mcp:read".into()];
        assert_eq!(
            validator_with(scoped).validate(&id_token).await,
            Err(TokenRejection::InsufficientScope)
        );

        cfg.require_at_jwt = true;
        assert!(is_invalid(&validator_with(cfg).validate(&id_token).await));
    }

    #[test]
    fn plain_http_detection_exempts_loopback_only() {
        assert!(plain_http_non_loopback("http://idp.example.com/jwks"));
        assert!(plain_http_non_loopback("HTTP://idp.example.com/jwks"));
        assert!(!plain_http_non_loopback("https://idp.example.com/jwks"));
        assert!(!plain_http_non_loopback("http://127.0.0.1:9000/jwks"));
        assert!(!plain_http_non_loopback("http://localhost/jwks"));
    }

    #[test]
    fn accessors_expose_the_resource_and_where_its_metadata_lives() {
        let v = validator("http://127.0.0.1:1/jwks");
        assert_eq!(v.resource(), RESOURCE);
        assert_eq!(
            v.resource_metadata_url(),
            "https://kb.example.test/.well-known/oauth-protected-resource/mcp"
        );
        assert_eq!(
            v.metadata_path(),
            "/.well-known/oauth-protected-resource/mcp"
        );
        assert_eq!(v.config().issuer, ISSUER);
    }

    // ── the metadata document and the challenge headers ──────────────────────

    #[test]
    fn metadata_document_has_the_rfc_9728_shape() {
        let v = validator("http://127.0.0.1:1/jwks");
        let doc = v.metadata();
        assert_eq!(doc["resource"], RESOURCE);
        // Byte-identical, trailing slash and all — a client matches this against
        // the `iss` of the tokens it receives.
        assert_eq!(doc["authorization_servers"][0], ISSUER);
        assert_eq!(doc["scopes_supported"][0], "mcp:read");
        assert_eq!(doc["scopes_supported"][1], "mcp:write");
        assert_eq!(doc["bearer_methods_supported"][0], "header");
        // `resource_name` names the application, so the crate sets none of its
        // own; it is published exactly when the application supplies one.
        assert!(doc.get("resource_name").is_none());

        let mut cfg = oauth_config("http://127.0.0.1:1/jwks");
        cfg.resource_name = Some("mcp-md-wiki knowledge base (MCP)".into());
        let v = validator_with(cfg);
        let doc = v.metadata();
        assert_eq!(doc["resource_name"], "mcp-md-wiki knowledge base (MCP)");
        assert_eq!(
            doc.to_string(),
            "{\"authorization_servers\":[\"https://authentik.example.test/application/o/example-app/\"],\
             \"bearer_methods_supported\":[\"header\"],\
             \"resource\":\"https://kb.example.test/mcp\",\
             \"resource_name\":\"mcp-md-wiki knowledge base (MCP)\",\
             \"scopes_supported\":[\"mcp:read\",\"mcp:write\"]}"
        );
    }

    #[test]
    fn invalid_token_challenge_is_well_formed() {
        let v = validator("http://127.0.0.1:1/jwks");
        assert_eq!(
            v.invalid_token_challenge(),
            "Bearer error=\"invalid_token\", \
             resource_metadata=\"https://kb.example.test/.well-known/oauth-protected-resource/mcp\", \
             scope=\"mcp:read mcp:write\""
        );
    }

    #[test]
    fn invalid_token_challenge_names_the_required_scopes_when_none_is_advertised() {
        // An explicitly empty `scopes_supported`: the 401 still tells a client
        // what to ask for, rather than leaving it to request nothing and hit 403.
        let mut cfg = oauth_config("http://127.0.0.1:1/jwks");
        cfg.scopes_supported = Vec::new();
        let v = validator_with(cfg.clone());
        assert_eq!(
            v.invalid_token_challenge(),
            "Bearer error=\"invalid_token\", \
             resource_metadata=\"https://kb.example.test/.well-known/oauth-protected-resource/mcp\", \
             scope=\"mcp:read\""
        );
        // RFC 9728 §3.2: a parameter with zero values is omitted.
        assert!(
            v.metadata().get("scopes_supported").is_none(),
            "{}",
            v.metadata()
        );

        // RFC 6749 §3.3: `scope` holds at least one scope-token, so with nothing
        // advertised AND nothing required the parameter is left out.
        cfg.required_scopes.clear();
        assert_eq!(
            validator_with(cfg).invalid_token_challenge(),
            "Bearer error=\"invalid_token\", \
             resource_metadata=\"https://kb.example.test/.well-known/oauth-protected-resource/mcp\""
        );
    }

    #[test]
    fn insufficient_scope_challenge_names_the_missing_scope_not_the_menu() {
        // With a single required scope this is byte-identical to what
        // mcp-md-wiki sent before mcp-md-wiki#308.
        let v = validator("http://127.0.0.1:1/jwks");
        assert_eq!(
            v.insufficient_scope_challenge(),
            "Bearer error=\"insufficient_scope\", scope=\"mcp:read\", \
             resource_metadata=\"https://kb.example.test/.well-known/oauth-protected-resource/mcp\""
        );
    }

    #[test]
    fn insufficient_scope_challenge_lists_every_required_scope_space_delimited() {
        let mut cfg = oauth_config("http://127.0.0.1:1/jwks");
        cfg.required_scopes = vec!["mcp:read".into(), "mcp:write".into()];
        assert_eq!(
            validator_with(cfg).insufficient_scope_challenge(),
            "Bearer error=\"insufficient_scope\", scope=\"mcp:read mcp:write\", \
             resource_metadata=\"https://kb.example.test/.well-known/oauth-protected-resource/mcp\""
        );
    }

    // ── token validation: the happy path and the original checks ─────────────

    #[tokio::test]
    async fn a_well_formed_token_is_accepted_and_yields_its_scopes() {
        let jwks = spawn_jwks_server("200 OK", jwks_body()).await;
        let v = validator(&jwks.url);
        let token = v.validate(&valid_token()).await.unwrap();
        assert_eq!(token.subject.as_deref(), Some("user-1"));
        assert_eq!(token.scopes, vec!["mcp:read", "mcp:write"]);
        assert!(token.has_scope("mcp:write"));
    }

    #[tokio::test]
    async fn an_empty_credential_is_missing_not_invalid() {
        let jwks = spawn_jwks_server("200 OK", jwks_body()).await;
        let v = validator(&jwks.url);
        assert_eq!(v.validate("").await.unwrap_err(), TokenRejection::Missing);
        assert_eq!(jwks.hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_wrong_issuer_is_rejected() {
        let jwks = spawn_jwks_server("200 OK", jwks_body()).await;
        let v = validator(&jwks.url);
        // Same issuer minus the trailing slash: the near-miss that actually happens
        // in practice, not an obviously foreign string.
        let token = mint(
            KEY_A_PEM,
            KID_A,
            &claims(serde_json::json!({
                "iss": ISSUER.trim_end_matches('/'), "scope": "mcp:read",
            })),
        );
        assert!(is_invalid(&v.validate(&token).await));
    }

    #[tokio::test]
    async fn an_issuer_array_containing_the_right_issuer_is_rejected() {
        // jsonwebtoken on its own accepts this; `iss` is a single StringOrURI.
        let jwks = spawn_jwks_server("200 OK", jwks_body()).await;
        let v = validator(&jwks.url);
        let token = mint(
            KEY_A_PEM,
            KID_A,
            &claims(serde_json::json!({
                "iss": ["https://evil.example.test/", ISSUER], "scope": "mcp:read",
            })),
        );
        assert!(is_invalid(&v.validate(&token).await));
    }

    #[tokio::test]
    async fn a_missing_issuer_or_audience_is_rejected() {
        let jwks = spawn_jwks_server("200 OK", jwks_body()).await;
        let v = validator(&jwks.url);
        // jsonwebtoken only checks iss/aud when the claim is present, so omitting
        // them entirely is the way a token would sneak past a validator that had
        // not set `required_spec_claims`.
        for claims in [
            serde_json::json!({"aud": AUDIENCE, "exp": now() + 3600, "scope": "mcp:read"}),
            serde_json::json!({"iss": ISSUER, "exp": now() + 3600, "scope": "mcp:read"}),
        ] {
            let token = mint(KEY_A_PEM, KID_A, &claims);
            assert!(is_invalid(&v.validate(&token).await));
        }
    }

    // ── audience ─────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn aud_is_accepted_as_a_string_and_as_an_array() {
        let jwks = spawn_jwks_server("200 OK", jwks_body()).await;
        let v = validator(&jwks.url);
        for aud in [
            serde_json::json!(AUDIENCE),
            serde_json::json!(["some-other-client", AUDIENCE]),
        ] {
            let token = mint(
                KEY_A_PEM,
                KID_A,
                &claims(serde_json::json!({"aud": aud, "scope": "mcp:read"})),
            );
            assert!(
                v.validate(&token).await.is_ok(),
                "aud must be accepted in both RFC 7519 §4.1.3 shapes"
            );
        }
    }

    #[tokio::test]
    async fn a_wrong_empty_or_malformed_audience_is_rejected() {
        let jwks = spawn_jwks_server("200 OK", jwks_body()).await;
        let v = validator(&jwks.url);
        for aud in [
            serde_json::json!("some-other-client"),
            serde_json::json!([]),
            serde_json::json!(["some-other-client"]),
            serde_json::json!(42),
            serde_json::json!([AUDIENCE, 42]),
            serde_json::json!(""),
        ] {
            let token = mint(
                KEY_A_PEM,
                KID_A,
                &claims(serde_json::json!({"aud": aud, "scope": "mcp:read"})),
            );
            assert!(
                is_invalid(&v.validate(&token).await),
                "aud {aud} must never be accepted"
            );
        }
    }

    #[tokio::test]
    async fn every_configured_audience_is_accepted_and_nothing_else() {
        // `audience` (single key) + `audiences` (list) are unioned: the migration
        // from client_id to resource-URL audience can run with both.
        let jwks = spawn_jwks_server("200 OK", jwks_body()).await;
        let mut cfg = oauth_config(&jwks.url);
        cfg.audiences = vec![RESOURCE.to_string()];
        let v = validator_with(cfg);
        for aud in [AUDIENCE, RESOURCE] {
            let token = mint(
                KEY_A_PEM,
                KID_A,
                &claims(serde_json::json!({"aud": aud, "scope": "mcp:read"})),
            );
            assert!(v.validate(&token).await.is_ok(), "{aud} is configured");
        }
        let token = mint(
            KEY_A_PEM,
            KID_A,
            &claims(
                serde_json::json!({"aud": "https://other.example.test/mcp", "scope": "mcp:read"}),
            ),
        );
        assert!(is_invalid(&v.validate(&token).await));
    }

    // ── expiry, not-before and clock skew ────────────────────────────────────

    #[tokio::test]
    async fn an_expired_token_is_rejected_beyond_the_leeway() {
        let jwks = spawn_jwks_server("200 OK", jwks_body()).await;
        let v = validator(&jwks.url);
        let token = mint(
            KEY_A_PEM,
            KID_A,
            &claims(serde_json::json!({
                "exp": now() - (crate::DEFAULT_LEEWAY_SECS + 60), "scope": "mcp:read",
            })),
        );
        assert!(is_invalid(&v.validate(&token).await));
    }

    #[tokio::test]
    async fn skew_within_the_leeway_is_tolerated_and_zero_leeway_is_strict() {
        let jwks = spawn_jwks_server("200 OK", jwks_body()).await;
        let just_expired = mint(
            KEY_A_PEM,
            KID_A,
            &claims(serde_json::json!({"exp": now() - 10, "scope": "mcp:read"})),
        );
        let not_yet_valid = mint(
            KEY_A_PEM,
            KID_A,
            &claims(serde_json::json!({"nbf": now() + 10, "scope": "mcp:read"})),
        );

        let lenient = validator(&jwks.url);
        assert!(lenient.validate(&just_expired).await.is_ok());
        assert!(lenient.validate(&not_yet_valid).await.is_ok());

        let mut cfg = oauth_config(&jwks.url);
        cfg.leeway_secs = 0;
        let strict = validator_with(cfg);
        assert!(is_invalid(&strict.validate(&just_expired).await));
        assert!(is_invalid(&strict.validate(&not_yet_valid).await));
    }

    #[tokio::test]
    async fn a_token_used_before_nbf_is_rejected_beyond_the_leeway() {
        let jwks = spawn_jwks_server("200 OK", jwks_body()).await;
        let v = validator(&jwks.url);
        let token = mint(
            KEY_A_PEM,
            KID_A,
            &claims(serde_json::json!({
                "nbf": now() + crate::DEFAULT_LEEWAY_SECS + 120, "scope": "mcp:read",
            })),
        );
        assert!(is_invalid(&v.validate(&token).await));
    }

    #[tokio::test]
    async fn a_token_signed_by_the_wrong_key_is_rejected() {
        let jwks = spawn_jwks_server("200 OK", jwks_body()).await;
        let v = validator(&jwks.url);
        // Signed by B but LABELLED as A, so the lookup succeeds and the failure is
        // genuinely a signature failure rather than an unknown-kid failure.
        let token = mint(
            KEY_B_PEM,
            KID_A,
            &claims(serde_json::json!({"scope": "mcp:read"})),
        );
        assert!(is_invalid(&v.validate(&token).await));
    }

    // ── scope extraction: every shape ────────────────────────────────────────

    async fn scopes_of(extra: serde_json::Value) -> Result<AuthorizedToken, TokenRejection> {
        let jwks = spawn_jwks_server("200 OK", jwks_body()).await;
        let v = validator(&jwks.url);
        v.validate(&mint(KEY_A_PEM, KID_A, &claims(extra))).await
    }

    #[tokio::test]
    async fn scope_as_a_space_delimited_string_is_read() {
        let t = scopes_of(serde_json::json!({"scope": "openid  mcp:read\tmcp:write"}))
            .await
            .unwrap();
        assert_eq!(t.scopes, ["openid", "mcp:read", "mcp:write"]);
    }

    #[tokio::test]
    async fn scp_as_an_array_is_read() {
        // Authelia's shape — the incompatibility the `scp` fallback fixes.
        let t = scopes_of(serde_json::json!({"scp": ["mcp:read", "mcp:write"]}))
            .await
            .unwrap();
        assert_eq!(t.scopes, ["mcp:read", "mcp:write"]);
    }

    #[tokio::test]
    async fn scp_as_a_space_delimited_string_is_read() {
        // Entra ID's (and Ory Hydra's `scope_claim: string`) shape.
        let t = scopes_of(serde_json::json!({"scp": "mcp:read mcp:write"}))
            .await
            .unwrap();
        assert_eq!(t.scopes, ["mcp:read", "mcp:write"]);
    }

    #[tokio::test]
    async fn scope_and_scp_together_are_unioned_without_duplicates() {
        let t = scopes_of(serde_json::json!({
            "scope": "openid mcp:read", "scp": ["mcp:read", "mcp:write"],
        }))
        .await
        .unwrap();
        assert_eq!(t.scopes, ["openid", "mcp:read", "mcp:write"]);
    }

    #[tokio::test]
    async fn the_required_scope_in_scp_alone_satisfies_the_check() {
        let t = scopes_of(serde_json::json!({"scope": "openid", "scp": ["mcp:read"]}))
            .await
            .unwrap();
        assert!(t.has_scope("mcp:read"));
    }

    #[tokio::test]
    async fn neither_claim_or_non_string_shapes_are_insufficient_not_invalid() {
        for extra in [
            serde_json::json!({}),
            serde_json::json!({"scope": ""}),
            serde_json::json!({"scope": "openid profile"}),
            serde_json::json!({"scp": []}),
            serde_json::json!({"scp": [1, {"mcp:read": true}]}),
            serde_json::json!({"scope": {"mcp:read": true}}),
            // Scope matching is exact and case-sensitive (RFC 6749 §3.3).
            serde_json::json!({"scope": "MCP:READ mcp:read:extra"}),
        ] {
            assert_eq!(
                scopes_of(extra.clone()).await.unwrap_err(),
                TokenRejection::InsufficientScope,
                "{extra} — the token itself is fine; conflating this with \
                 invalid_token sends the client round the authorization flow to the \
                 same refusal"
            );
        }
    }

    #[tokio::test]
    async fn only_the_configured_scope_claims_are_read() {
        let jwks = spawn_jwks_server("200 OK", jwks_body()).await;
        let mut cfg = oauth_config(&jwks.url);
        cfg.scope_claims = vec!["scope".to_string()];
        let v = validator_with(cfg);
        let token = mint(
            KEY_A_PEM,
            KID_A,
            &claims(serde_json::json!({"scp": ["mcp:read"]})),
        );
        assert_eq!(
            v.validate(&token).await.unwrap_err(),
            TokenRejection::InsufficientScope
        );
    }

    // ── required scopes: all-of ──────────────────────────────────────────────

    #[tokio::test]
    async fn every_required_scope_must_be_present() {
        let jwks = spawn_jwks_server("200 OK", jwks_body()).await;
        let mut cfg = oauth_config(&jwks.url);
        cfg.required_scopes = vec!["mcp:read".into(), "mcp:write".into()];
        let v = validator_with(cfg);
        for (scope, ok) in [
            ("mcp:read", false),
            ("mcp:write", false),
            ("openid", false),
            ("mcp:read mcp:write", true),
            ("mcp:write openid mcp:read", true),
        ] {
            let token = mint(
                KEY_A_PEM,
                KID_A,
                &claims(serde_json::json!({ "scope": scope })),
            );
            let result = v.validate(&token).await;
            if ok {
                assert!(result.is_ok(), "{scope:?} carries every required scope");
            } else {
                assert_eq!(
                    result.unwrap_err(),
                    TokenRejection::InsufficientScope,
                    "{scope:?} lacks one"
                );
            }
        }
    }

    #[tokio::test]
    async fn an_empty_required_scope_set_passes_the_scope_check() {
        let jwks = spawn_jwks_server("200 OK", jwks_body()).await;
        let mut cfg = oauth_config(&jwks.url);
        cfg.required_scopes.clear();
        let v = validator_with(cfg);
        // No scope claim at all: still a valid token, just an unscoped one.
        let t = v
            .validate(&mint(KEY_A_PEM, KID_A, &claims(serde_json::json!({}))))
            .await
            .unwrap();
        assert!(t.scopes.is_empty());
        // Every other check still applies.
        let expired = mint(
            KEY_A_PEM,
            KID_A,
            &claims(serde_json::json!({"exp": now() - 3600})),
        );
        assert!(is_invalid(&v.validate(&expired).await));
    }

    // ── principal ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn the_principal_is_the_first_present_claim_of_the_chain() {
        let jwks = spawn_jwks_server("200 OK", jwks_body()).await;
        let mut cfg = oauth_config(&jwks.url);
        cfg.principal_claims = vec!["preferred_username".into(), "email".into(), "sub".into()];
        let v = validator_with(cfg);
        for (extra, expected) in [
            (
                serde_json::json!({"preferred_username": "alice", "email": "a@example.com"}),
                "alice",
            ),
            (
                serde_json::json!({"preferred_username": "", "email": "a@example.com"}),
                "a@example.com",
            ),
            (serde_json::json!({"preferred_username": 7}), "user-1"),
        ] {
            let mut c = claims(extra);
            c["scope"] = "mcp:read".into();
            let t = v.validate(&mint(KEY_A_PEM, KID_A, &c)).await.unwrap();
            assert_eq!(t.principal.as_deref(), Some(expected));
        }
    }

    /// `subject` and `principal` are identity values a handler may key on, so
    /// two signed values sharing a long prefix must stay distinct: truncation
    /// happens at log call sites only.
    #[tokio::test]
    async fn long_subjects_and_principals_are_kept_verbatim() {
        let jwks = spawn_jwks_server("200 OK", jwks_body()).await;
        let mut cfg = oauth_config(&jwks.url);
        cfg.principal_claims = vec!["email".into()];
        let v = validator_with(cfg);
        let prefix = "u".repeat(200);
        let mut seen = Vec::new();
        for suffix in ["-a", "-b"] {
            let sub = format!("{prefix}{suffix}");
            let email = format!("{prefix}{suffix}@example.com");
            let c = claims(serde_json::json!({"sub": sub, "email": email, "scope": "mcp:read"}));
            let t = v.validate(&mint(KEY_A_PEM, KID_A, &c)).await.unwrap();
            assert_eq!(t.subject.as_deref(), Some(sub.as_str()));
            assert_eq!(t.principal.as_deref(), Some(email.as_str()));
            seen.push(t.subject);
        }
        assert_ne!(seen[0], seen[1]);
    }

    // ── algorithm and key confusion ──────────────────────────────────────────

    #[tokio::test]
    async fn alg_none_is_rejected_before_any_jwks_fetch() {
        let jwks = spawn_jwks_server("200 OK", jwks_body()).await;
        let v = validator(&jwks.url);
        // Hand-assembled (no crate will sign `none`): base64url of
        // `{"alg":"none","typ":"JWT"}` / `{"alg":"None"}`, a payload with a
        // plausible claim set, and an empty signature.
        let payload = "eyJpc3MiOiJ4IiwiYXVkIjoidGVzdC1jbGllbnQtaWQiLCJzY29wZSI6Im1jcDpyZWFkIiwiZXhwIjo5OTk5OTk5OTk5fQ";
        for header in ["eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0", "eyJhbGciOiJOb25lIn0"] {
            let token = format!("{header}.{payload}.");
            assert!(is_invalid(&v.validate(&token).await), "{header}");
        }
        assert_eq!(jwks.hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn hs256_signed_with_the_public_key_is_rejected_before_any_jwks_fetch() {
        // The classic confusion: an attacker HMACs a token with the server's
        // PUBLIC key bytes and hopes the verifier treats them as the HMAC secret.
        let jwks = spawn_jwks_server("200 OK", jwks_body()).await;
        let v = validator(&jwks.url);
        let published = jwks_body();
        for secret in [N_A.as_bytes(), published.as_bytes()] {
            let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
            header.kid = Some(KID_A.to_string());
            let token = jsonwebtoken::encode(
                &header,
                &claims(serde_json::json!({"scope": "mcp:read"})),
                &jsonwebtoken::EncodingKey::from_secret(secret),
            )
            .unwrap();
            assert!(is_invalid(&v.validate(&token).await));
        }
        assert_eq!(
            jwks.hits.load(Ordering::SeqCst),
            0,
            "a junk algorithm must not be able to schedule IdP traffic"
        );
    }

    #[tokio::test]
    async fn a_symmetric_key_in_the_jwks_is_never_used() {
        // Even a key set that (wrongly) publishes an `oct` key cannot make HMAC
        // verification reachable: the key is dropped at load, and HS* is not
        // configurable anyway.
        let body = jwks_of(&[serde_json::json!({"kty": "oct", "kid": KID_A, "k": "c2VjcmV0"})]);
        let jwks = spawn_jwks_server("200 OK", body).await;
        let v = validator(&jwks.url);
        assert!(is_invalid(&v.validate(&valid_token()).await));
    }

    #[tokio::test]
    async fn a_token_alg_the_named_key_cannot_produce_is_rejected() {
        // Header says ES256 but names the RSA key: the key's type pins it to
        // RS*/PS*, so there is no key to verify with. Also the reverse.
        let jwks = spawn_jwks_server("200 OK", jwks_body_all()).await;
        let v = validator(&jwks.url);
        let c = claims(serde_json::json!({"scope": "mcp:read"}));
        let es_labelled_rsa = mint_with(Algorithm::ES256, Some(KID_A), None, &c.clone());
        assert!(is_invalid(&v.validate(&es_labelled_rsa).await));
        let rs_labelled_ec = mint_with(Algorithm::RS256, Some(KID_EC), None, &c.clone());
        assert!(is_invalid(&v.validate(&rs_labelled_ec).await));
        // KID_A declares `alg: RS256`, so it must refuse PS256 even though an RSA
        // key could technically verify it.
        let ps_on_rs_only_key = mint_with(Algorithm::PS256, Some(KID_A), None, &c);
        assert!(is_invalid(&v.validate(&ps_on_rs_only_key).await));
    }

    #[tokio::test]
    async fn es256_ps256_and_eddsa_tokens_are_accepted() {
        let jwks = spawn_jwks_server("200 OK", jwks_body_all()).await;
        let v = validator(&jwks.url);
        let c = claims(serde_json::json!({"scope": "mcp:read"}));
        for (alg, kid) in [
            (Algorithm::ES256, KID_EC),
            (Algorithm::PS256, "test-key-a-pss"),
            (Algorithm::RS384, "test-key-a-pss"),
            (Algorithm::EdDSA, KID_ED),
            (Algorithm::RS256, KID_A),
        ] {
            let token = mint_with(alg, Some(kid), Some("at+jwt"), &c.clone());
            assert!(v.validate(&token).await.is_ok(), "{alg:?} must verify");
        }
    }

    #[tokio::test]
    async fn an_algorithm_outside_the_allowlist_is_rejected_before_any_jwks_fetch() {
        let jwks = spawn_jwks_server("200 OK", jwks_body_all()).await;
        let mut cfg = oauth_config(&jwks.url);
        cfg.algorithms = vec![Algorithm::RS256];
        let v = validator_with(cfg);
        let token = mint_with(
            Algorithm::ES256,
            Some(KID_EC),
            None,
            &claims(serde_json::json!({"scope": "mcp:read"})),
        );
        assert!(is_invalid(&v.validate(&token).await));
        assert_eq!(jwks.hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn rejection_reasons_name_settings_per_key_naming() {
        let jwks = spawn_jwks_server("200 OK", jwks_body_all()).await;
        let token = mint_with(
            Algorithm::ES256,
            Some(KID_EC),
            None,
            &claims(serde_json::json!({"scope": "mcp:read"})),
        );
        for (naming, expected) in [
            (
                KeyNamingBuf::Dotted("mcp.oauth".into()),
                "token algorithm ES256 is not in mcp.oauth.algorithms",
            ),
            (
                KeyNamingBuf::Env("APP_OAUTH_".into()),
                "token algorithm ES256 is not in APP_OAUTH_ALGORITHMS",
            ),
        ] {
            let mut cfg = oauth_config(&jwks.url);
            cfg.algorithms = vec![Algorithm::RS256];
            cfg.key_naming = naming;
            assert_eq!(
                validator_with(cfg).validate(&token).await.unwrap_err(),
                TokenRejection::Invalid(expected.into())
            );
        }
    }

    // ── typ ──────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn typ_access_token_types_pass_and_other_jwt_types_fail() {
        let jwks = spawn_jwks_server("200 OK", jwks_body()).await;
        let v = validator(&jwks.url);
        let c = claims(serde_json::json!({"scope": "mcp:read"}));
        for typ in [
            None,
            Some("JWT"),
            Some("jwt"),
            Some("at+jwt"),
            Some("AT+JWT"),
            Some("application/at+jwt"),
        ] {
            let token = mint_with(Algorithm::RS256, Some(KID_A), typ, &c.clone());
            assert!(v.validate(&token).await.is_ok(), "typ {typ:?} must pass");
        }
        for typ in ["dpop+jwt", "logout+jwt", "secevent+jwt", "JOSE"] {
            let token = mint_with(Algorithm::RS256, Some(KID_A), Some(typ), &c.clone());
            assert!(is_invalid(&v.validate(&token).await), "typ {typ} must fail");
        }
    }

    #[tokio::test]
    async fn require_at_jwt_refuses_plain_jwt_and_a_missing_typ() {
        let jwks = spawn_jwks_server("200 OK", jwks_body()).await;
        let mut cfg = oauth_config(&jwks.url);
        cfg.require_at_jwt = true;
        let v = validator_with(cfg);
        let c = claims(serde_json::json!({"scope": "mcp:read"}));
        for typ in [None, Some("JWT")] {
            let token = mint_with(Algorithm::RS256, Some(KID_A), typ, &c.clone());
            assert!(is_invalid(&v.validate(&token).await), "typ {typ:?}");
        }
        let token = mint_with(Algorithm::RS256, Some(KID_A), Some("at+jwt"), &c);
        assert!(v.validate(&token).await.is_ok());
    }

    // ── credential shape ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn garbage_opaque_and_oversized_credentials_are_rejected_without_a_fetch() {
        let jwks = spawn_jwks_server("200 OK", jwks_body()).await;
        let v = validator(&jwks.url);
        let oversized = format!("{}.{}.{}", "a".repeat(MAX_TOKEN_BYTES), "b", "c");
        for junk in [
            "not-a-jwt",
            "a.b.c",
            "a.b",
            // An Authelia-style opaque access token.
            "authelia_at_Xy9vQ3c2bG9uZ3JhbmRvbXN0cmluZw.abc",
            oversized.as_str(),
        ] {
            assert!(is_invalid(&v.validate(junk).await), "{junk:.40}");
        }
        assert_eq!(jwks.hits.load(Ordering::SeqCst), 0);
    }

    /// Unpadded base64url, for hand-built token headers.
    fn b64url(bytes: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let n = chunk
                .iter()
                .enumerate()
                .fold(0u32, |acc, (i, &b)| acc | (u32::from(b) << (16 - 8 * i)));
            for i in 0..=chunk.len() {
                out.push(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize] as char);
            }
        }
        out
    }

    /// An unknown `alg` string is echoed verbatim by the header parser's error;
    /// the rejection reason (which reaches a warn-level log line) must not carry
    /// all of it.
    #[tokio::test]
    async fn a_malformed_header_reason_is_truncated() {
        let v = validator("http://127.0.0.1:1/jwks");
        let header = format!(r#"{{"alg":"{}","typ":"JWT"}}"#, "A".repeat(8 * 1024));
        let token = format!("{}.e30.sig", b64url(header.as_bytes()));
        match v.validate(&token).await {
            Err(TokenRejection::Invalid(reason)) => {
                assert!(
                    reason.starts_with("malformed token header: "),
                    "{reason:.80}"
                );
                assert!(
                    reason.chars().count() <= "malformed token header: ".len() + 129,
                    "{} chars",
                    reason.chars().count()
                );
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    /// A token signed with [`KEY_A_PEM`] whose protected header is exactly
    /// `header` — for header members jsonwebtoken's `Header` cannot express.
    fn mint_raw_header(header: serde_json::Value, claims: serde_json::Value) -> String {
        let input = format!(
            "{}.{}",
            b64url(header.to_string().as_bytes()),
            b64url(claims.to_string().as_bytes())
        );
        let key = jsonwebtoken::EncodingKey::from_rsa_pem(KEY_A_PEM.as_bytes()).unwrap();
        let signature =
            jsonwebtoken::crypto::sign(input.as_bytes(), &key, jsonwebtoken::Algorithm::RS256)
                .unwrap();
        format!("{input}.{signature}")
    }

    /// RFC 7515 §4.1.11: a `crit` header naming an extension the recipient does
    /// not understand makes the JWS invalid. This crate understands none, so
    /// every `crit` — unknown, empty or malformed — is refused, before any key
    /// is fetched.
    #[tokio::test]
    async fn a_crit_header_is_refused_before_any_jwks_fetch() {
        let jwks = spawn_jwks_server("200 OK", jwks_body()).await;
        let v = validator(&jwks.url);
        let c = claims(serde_json::json!({"scope": "mcp:read"}));
        for crit in [
            serde_json::json!(["urn:example:must-understand"]),
            serde_json::json!([]),
            serde_json::json!("not-an-array"),
        ] {
            let token = mint_raw_header(
                serde_json::json!({
                    "alg": "RS256", "kid": KID_A, "crit": crit,
                    "urn:example:must-understand": true,
                }),
                c.clone(),
            );
            assert_eq!(
                v.validate(&token).await,
                Err(TokenRejection::Invalid(
                    "token header lists critical extensions (crit), none of which this \
                     server supports"
                        .into()
                )),
                "crit {crit}"
            );
        }
        assert_eq!(jwks.hits.load(Ordering::SeqCst), 0);
        // The same hand-built header without `crit` is accepted, so it is the
        // `crit` being refused, not the construction.
        let token = mint_raw_header(serde_json::json!({"alg": "RS256", "kid": KID_A}), c);
        assert!(v.validate(&token).await.is_ok());
    }

    /// RFC 7519 §4.1.5: `nbf` is a NumericDate. jsonwebtoken silently skips one
    /// it cannot read as a number, which would make a not-yet-valid token valid.
    #[tokio::test]
    async fn an_nbf_that_is_not_a_numeric_date_is_refused() {
        let jwks = spawn_jwks_server("200 OK", jwks_body()).await;
        let v = validator(&jwks.url);
        let later = now() + 365 * 24 * 3600;
        for nbf in [
            serde_json::json!(later.to_string()),
            serde_json::json!("later"),
            serde_json::json!(1e30),
            serde_json::json!(-5),
            serde_json::json!(null),
        ] {
            let token = mint(
                KEY_A_PEM,
                KID_A,
                &claims(serde_json::json!({"nbf": nbf, "scope": "mcp:read"})),
            );
            assert_eq!(
                v.validate(&token).await,
                Err(TokenRejection::Invalid(
                    "token nbf is not a NumericDate (a non-negative number of seconds)".into()
                )),
                "nbf {nbf}"
            );
        }
        // An array fails jsonwebtoken's own claim parsing: refused either way.
        let token = mint(
            KEY_A_PEM,
            KID_A,
            &claims(serde_json::json!({"nbf": [later], "scope": "mcp:read"})),
        );
        assert!(is_invalid(&v.validate(&token).await));
        // Numbers, integral or not, are checked normally.
        let past = mint(
            KEY_A_PEM,
            KID_A,
            &claims(serde_json::json!({"nbf": now() as f64 - 10.5, "scope": "mcp:read"})),
        );
        assert!(v.validate(&past).await.is_ok());
        let future = mint(
            KEY_A_PEM,
            KID_A,
            &claims(serde_json::json!({"nbf": later, "scope": "mcp:read"})),
        );
        match v.validate(&future).await {
            Err(TokenRejection::Invalid(reason)) => {
                assert!(reason.contains("ImmatureSignature"), "{reason}");
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    /// RFC 9449 §7.2 / RFC 8705 §3: a sender-constrained token must not be
    /// accepted as a bearer token by a server that cannot check the binding.
    #[tokio::test]
    async fn a_sender_constrained_token_is_refused() {
        let jwks = spawn_jwks_server("200 OK", jwks_body()).await;
        let v = validator(&jwks.url);
        for cnf in [
            serde_json::json!({"jkt": "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"}),
            serde_json::json!({"x5t#S256": "bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2"}),
            serde_json::json!(null),
        ] {
            let token = mint_with(
                crate::Algorithm::RS256,
                Some(KID_A),
                Some("at+jwt"),
                &claims(serde_json::json!({"cnf": cnf, "scope": "mcp:read"})),
            );
            assert_eq!(
                v.validate(&token).await,
                Err(TokenRejection::Invalid(
                    "token is sender-constrained (cnf); this server accepts bearer tokens only"
                        .into()
                )),
                "cnf {cnf}"
            );
        }
    }

    // ── JWKS fetching, rotation and rate limiting ────────────────────────────

    #[tokio::test]
    async fn the_jwks_is_fetched_once_and_cached() {
        let jwks = spawn_jwks_server("200 OK", jwks_body()).await;
        let v = validator(&jwks.url);
        for _ in 0..3 {
            v.validate(&valid_token()).await.unwrap();
        }
        assert_eq!(
            jwks.hits.load(Ordering::SeqCst),
            1,
            "a cached key must not be re-fetched per request"
        );
    }

    #[tokio::test]
    async fn an_unknown_kid_does_not_refetch_during_the_cooldown() {
        let jwks = spawn_jwks_server("200 OK", jwks_body()).await;
        let v = validator(&jwks.url); // real 60s cooldown
        // First call populates the cache (one fetch); the unknown kid is then NOT
        // worth a second fetch, because we just fetched.
        let token = mint(
            KEY_A_PEM,
            "rotated-key",
            &claims(serde_json::json!({"scope": "mcp:read"})),
        );
        for _ in 0..5 {
            assert!(is_invalid(&v.validate(&token).await));
        }
        assert_eq!(
            jwks.hits.load(Ordering::SeqCst),
            1,
            "kid is attacker-controlled — five junk tokens must not mean five IdP hits"
        );
    }

    #[tokio::test]
    async fn concurrent_unknown_kids_cost_one_fetch() {
        let jwks = spawn_jwks_server("200 OK", jwks_body()).await;
        let v = Arc::new(validator(&jwks.url));
        let mut tasks = Vec::new();
        for i in 0..20 {
            let v = Arc::clone(&v);
            tasks.push(tokio::spawn(async move {
                let token = mint(
                    KEY_A_PEM,
                    &format!("junk-{i}"),
                    &claims(serde_json::json!({"scope": "mcp:read"})),
                );
                v.validate(&token).await
            }));
        }
        for t in tasks {
            assert!(is_invalid(&t.await.unwrap()));
        }
        assert_eq!(jwks.hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn an_unknown_kid_refetches_once_the_cooldown_has_passed() {
        let jwks = spawn_jwks_server("200 OK", jwks_body()).await;
        let v = validator_no_cooldown(&jwks.url);
        let token = mint(
            KEY_A_PEM,
            "rotated-key",
            &claims(serde_json::json!({"scope": "mcp:read"})),
        );
        assert!(is_invalid(&v.validate(&token).await));
        assert!(is_invalid(&v.validate(&token).await));
        assert_eq!(
            jwks.hits.load(Ordering::SeqCst),
            2,
            "with the cooldown elapsed, an unknown kid must trigger a refresh — this \
             is how a rotated signing key is picked up without a restart"
        );
    }

    #[tokio::test]
    async fn a_rotated_key_is_picked_up_and_a_withdrawn_key_is_dropped() {
        let jwks = spawn_http_server(HashMap::new(), None).await;
        let set = |body: String| {
            jwks.routes
                .lock()
                .unwrap()
                .insert("/jwks".to_string(), ("200 OK", body));
        };
        set(jwks_body());
        let v = validator_no_cooldown(&jwks.url);
        let c = claims(serde_json::json!({"scope": "mcp:read"}));
        let old = mint(KEY_A_PEM, KID_A, &c.clone());
        let new = mint_with(Algorithm::ES256, Some(KID_EC), None, &c);

        assert!(v.validate(&old).await.is_ok());
        // The AS publishes the new key alongside the old one: the unknown kid
        // triggers a refetch and both verify.
        set(jwks_of(&[jwk_rsa_a(), jwk_ec()]));
        assert!(v.validate(&new).await.is_ok());
        assert!(v.validate(&old).await.is_ok());
        // The AS withdraws the old key; the next refresh (the background task's
        // job) must stop trusting it.
        set(jwks_of(&[jwk_ec()]));
        assert_eq!(v.refresh_now().await.unwrap(), 1);
        assert!(is_invalid(&v.validate(&old).await));
        assert!(v.validate(&new).await.is_ok());
    }

    #[tokio::test]
    async fn a_slow_refresh_does_not_stall_requests_whose_key_is_cached() {
        // Holding the key lock across the fetch would, with tokio's
        // writer-preferring RwLock, park every request behind a slow IdP.
        let jwks = spawn_jwks_server("200 OK", jwks_body()).await;
        let v = Arc::new(validator_no_cooldown(&jwks.url));
        v.validate(&valid_token()).await.unwrap();

        jwks.delay_ms.store(1500, Ordering::SeqCst);
        let background = Arc::clone(&v);
        let refresh = tokio::spawn(async move { background.refresh_now().await });
        // And an unknown-kid request that also wants a refresh, queued behind it.
        let junk = Arc::clone(&v);
        let queued = tokio::spawn(async move {
            junk.validate(&mint(
                KEY_A_PEM,
                "unknown",
                &claims(serde_json::json!({"scope": "mcp:read"})),
            ))
            .await
        });
        tokio::time::sleep(Duration::from_millis(200)).await;

        let fast = tokio::time::timeout(Duration::from_millis(500), v.validate(&valid_token()))
            .await
            .expect("a cached-key validation must not wait for the in-flight refresh");
        assert!(fast.is_ok());
        assert!(refresh.await.unwrap().is_ok());
        assert!(is_invalid(&queued.await.unwrap()));
    }

    /// A caller that stops waiting mid-refetch (client disconnect, timeout
    /// layer) must not cancel the fetch: run inline, the drop would spend the
    /// unknown-`kid` cooldown with no keys loaded, and a legitimate token would
    /// then be refused for a minute.
    #[tokio::test]
    async fn a_dropped_validation_does_not_spend_the_refetch_cooldown() {
        let jwks = spawn_jwks_server("200 OK", jwks_body()).await;
        jwks.delay_ms.store(500, Ordering::SeqCst);
        let v = validator(&jwks.url); // the real 60s cooldown
        assert!(
            tokio::time::timeout(Duration::from_millis(50), v.validate(&valid_token()))
                .await
                .is_err(),
            "the slow fetch outlives the caller"
        );
        jwks.delay_ms.store(0, Ordering::SeqCst);
        // The fetch the dropped call started finishes in its own task and loads
        // the key; this request waits for it rather than being refused.
        assert!(v.validate(&valid_token()).await.is_ok());
        assert_eq!(jwks.hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn the_background_task_stops_when_the_validator_is_dropped() {
        let jwks = spawn_jwks_server("200 OK", jwks_body()).await;
        let v = Arc::new(validator(&jwks.url));
        let task = v.spawn_background_refresh();
        for _ in 0..200 {
            if jwks.hits.load(Ordering::SeqCst) > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(jwks.hits.load(Ordering::SeqCst), 1);
        let weak = Arc::downgrade(&v);
        drop(v);
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("the task ends with the validator, not after its hour-long sleep")
            .unwrap();
        assert!(
            weak.upgrade().is_none(),
            "the task held no strong reference"
        );
    }

    #[tokio::test]
    async fn a_failed_refresh_keeps_the_keys_already_held() {
        let jwks = spawn_http_server(HashMap::new(), None).await;
        jwks.routes
            .lock()
            .unwrap()
            .insert("/jwks".to_string(), ("200 OK", jwks_body()));
        let v = validator_no_cooldown(&jwks.url);
        assert!(v.validate(&valid_token()).await.is_ok());
        jwks.routes.lock().unwrap().insert(
            "/jwks".to_string(),
            ("503 Service Unavailable", "{}".into()),
        );
        assert!(v.refresh_now().await.is_err());
        assert!(
            v.validate(&valid_token()).await.is_ok(),
            "an IdP outage must not revoke keys that are still good"
        );
    }

    // ── key-set status and readiness ─────────────────────────────────────────

    #[tokio::test]
    async fn the_status_before_any_load_is_empty_and_does_no_io() {
        let jwks = spawn_jwks_server("200 OK", jwks_body()).await;
        let v = validator(&jwks.url);
        for _ in 0..10 {
            let status = v.key_set_status();
            assert_eq!(status.keys, 0);
            assert_eq!(status.jwks_uri.as_deref(), Some(jwks.url.as_str()));
            assert_eq!(status.last_attempt, None);
            assert_eq!(status.last_success, None);
            assert_eq!(status.last_error, None);
            assert!(!status.is_ready());
            assert!(!v.is_ready());
        }
        assert_eq!(
            jwks.hits.load(Ordering::SeqCst),
            0,
            "reading the status must never fetch"
        );
    }

    #[tokio::test]
    async fn the_status_tracks_a_success_and_a_failure_keeps_the_keys() {
        let jwks = spawn_http_server(HashMap::new(), None).await;
        let set = |status: &'static str, body: String| {
            jwks.routes
                .lock()
                .unwrap()
                .insert("/jwks".to_string(), (status, body));
        };
        set("200 OK", jwks_of(&[jwk_rsa_a(), jwk_ec()]));
        let v = validator_no_cooldown(&jwks.url);

        let before = std::time::SystemTime::now();
        assert_eq!(v.refresh_now().await.unwrap(), 2);
        let ok = v.key_set_status();
        assert_eq!(ok.keys, 2);
        assert!(ok.is_ready() && v.is_ready());
        assert_eq!(ok.jwks_uri.as_deref(), Some(jwks.url.as_str()));
        let success = ok.last_success.expect("a success is recorded");
        let attempt = ok.last_attempt.expect("the attempt is recorded");
        assert!(before <= attempt && attempt <= success);
        assert_eq!(ok.last_error, None);

        set("503 Service Unavailable", "{}".into());
        let err = v.refresh_now().await.unwrap_err();
        let failed = v.key_set_status();
        assert_eq!(failed.last_error.as_ref(), Some(&err));
        assert_eq!(err.kind(), RefreshErrorKind::Fetch);
        assert_eq!(failed.keys, 2, "a failed refresh keeps the keys held");
        assert!(failed.is_ready() && v.is_ready());
        assert_eq!(failed.last_success, Some(success), "unchanged by a failure");
        assert!(failed.last_attempt.unwrap() >= success);

        // Reading the status, however often, costs the IdP nothing.
        let hits = jwks.hits.load(Ordering::SeqCst);
        for _ in 0..10 {
            let _ = v.key_set_status();
            let _ = v.is_ready();
        }
        assert_eq!(jwks.hits.load(Ordering::SeqCst), hits);

        // A later success clears the error.
        set("200 OK", jwks_body());
        assert_eq!(v.refresh_now().await.unwrap(), 1);
        let recovered = v.key_set_status();
        assert_eq!(recovered.last_error, None);
        assert_eq!(recovered.keys, 1);
        assert!(recovered.last_success.unwrap() >= success);
    }

    #[tokio::test]
    async fn a_failed_first_load_leaves_the_validator_not_ready_with_the_error_kind() {
        let no_usable_keys = jwks_of(&[serde_json::json!({"kty": "oct", "k": "c2VjcmV0"})]);
        for (status_line, body, kind) in [
            (
                "503 Service Unavailable",
                "{}".to_string(),
                RefreshErrorKind::Fetch,
            ),
            ("200 OK", "not json".to_string(), RefreshErrorKind::Parse),
            (
                "200 OK",
                "{\"no\": \"keys\"}".to_string(),
                RefreshErrorKind::Parse,
            ),
            ("200 OK", no_usable_keys, RefreshErrorKind::NoUsableKeys),
        ] {
            let jwks = spawn_jwks_server(status_line, body).await;
            let v = validator(&jwks.url);
            let err = v.refresh_now().await.unwrap_err();
            let status = v.key_set_status();
            assert_eq!(err.kind(), kind, "{err}");
            assert_eq!(status.last_error, Some(err));
            assert_eq!(status.keys, 0);
            assert!(status.last_attempt.is_some());
            assert_eq!(status.last_success, None);
            assert!(!v.is_ready());
        }
    }

    #[tokio::test]
    async fn the_status_reports_the_discovered_jwks_uri_and_discovery_failures() {
        let (server, issuer) =
            discovery_server("/application/o/wiki/", |i| i.to_string(), false).await;
        let v = discovering_validator(&issuer);
        assert_eq!(v.key_set_status().jwks_uri, None, "not yet discovered");
        v.refresh_now().await.unwrap();
        let status = v.key_set_status();
        assert_eq!(
            status.jwks_uri.as_deref(),
            Some(format!("{}/keys", server.base).as_str())
        );
        assert!(status.is_ready());

        let (_server, issuer) =
            discovery_server("/app/", |_| "https://other.test/".into(), false).await;
        let v = discovering_validator(&issuer);
        let err = v.refresh_now().await.unwrap_err();
        assert_eq!(err.kind(), RefreshErrorKind::Discovery);
        let status = v.key_set_status();
        assert_eq!(status.jwks_uri, None);
        assert_eq!(status.last_error, Some(err));
    }

    /// A `jwks_uri` carrying a credential two ways (userinfo, which the fetch
    /// sends as Basic auth, and a query): neither may surface in the status or
    /// the refresh error (`Display` or `Debug`), or in the rejection reason a
    /// request-driven refetch produces. Log lines are covered by
    /// `tests/redacted_logs.rs`, which needs a process-global subscriber.
    #[tokio::test]
    async fn a_credential_in_the_jwks_uri_never_reaches_the_status_or_errors() {
        let jwks = spawn_jwks_server("503 Service Unavailable", "{}".into()).await;
        let uri = format!(
            "{}?key=t0ken",
            jwks.url.replacen("http://", "http://alice:s3cret@", 1)
        );
        let shown = format!("{}?***", jwks.url.replacen("http://", "http://***@", 1));
        let v = validator_no_cooldown(&uri);

        assert_eq!(v.key_set_status().jwks_uri.as_deref(), Some(shown.as_str()));
        let err = v.refresh_now().await.unwrap_err();
        let Err(TokenRejection::Invalid(reason)) = v.validate(&valid_token()).await else {
            panic!("no key can be loaded");
        };
        assert_eq!(jwks.hits.load(Ordering::SeqCst), 2, "both fetches went out");

        let status = v.key_set_status();
        assert_eq!(status.jwks_uri.as_deref(), Some(shown.as_str()));
        assert!(err.to_string().contains(&shown), "{err}");
        for text in [
            err.to_string(),
            format!("{err:?}"),
            status.last_error.as_ref().unwrap().to_string(),
            format!("{status:?}"),
            reason,
        ] {
            for secret in ["alice", "s3cret", "t0ken"] {
                assert!(!text.contains(secret), "{secret} leaked into: {text}");
            }
        }
    }

    /// The fake server holds the JWKS response until the test releases it, so
    /// the status is read while the refresh lock is certainly held. On this
    /// single-threaded runtime a status read that waited on the refresh could
    /// never return (the refresh cannot progress while the test's task
    /// blocks), so a regression hangs — which the CI job timeout catches —
    /// rather than racing a wall-clock deadline.
    #[tokio::test]
    async fn the_status_does_not_wait_on_a_slow_refresh_in_flight() {
        let jwks = spawn_jwks_server("200 OK", jwks_body()).await;
        let v = Arc::new(validator_no_cooldown(&jwks.url));
        v.refresh_now().await.unwrap();
        let loaded = v.key_set_status();

        jwks.hold.store(true, Ordering::SeqCst);
        let background = Arc::clone(&v);
        let refresh = tokio::spawn(async move { background.refresh_now().await });
        // Wait until the request has reached the server, which is holding it.
        while !(v.keys.refresh_in_flight() && jwks.hits.load(Ordering::SeqCst) == 2) {
            tokio::task::yield_now().await;
        }

        let status = v.key_set_status();
        let ready = v.is_ready();
        assert!(
            v.keys.refresh_in_flight(),
            "read while the fetch was in flight"
        );
        assert!(!refresh.is_finished());
        assert_eq!(
            jwks.hits.load(Ordering::SeqCst),
            2,
            "reading the status fetched nothing"
        );
        assert!(ready);
        assert_eq!(status.keys, 1);
        assert_eq!(status.last_success, loaded.last_success);
        assert!(status.last_attempt > loaded.last_attempt);
        assert_eq!(status.last_error, None);

        jwks.release.notify_one();
        assert!(refresh.await.unwrap().is_ok());
        assert_eq!(jwks.hits.load(Ordering::SeqCst), 2);
        assert!(v.key_set_status().last_success > loaded.last_success);
    }

    /// Run every ready task and let pending loopback I/O complete WITHOUT
    /// moving the paused clock: `yield_now` parks the runtime with a zero
    /// timeout, which never auto-advances time (a `sleep` would, jumping past
    /// timers while a fetch is still in flight). Returns once no refresh is in
    /// flight and the background task has re-armed its timer.
    async fn settle(v: &OAuthValidator) {
        for _ in 0..100 {
            tokio::task::yield_now().await;
        }
        for _ in 0..100_000 {
            if !v.keys.refresh_in_flight() {
                break;
            }
            tokio::task::yield_now().await;
        }
        for _ in 0..100 {
            tokio::task::yield_now().await;
        }
    }

    /// Move the paused clock forward by `secs`, settle, and return the
    /// server's hit count.
    async fn hits_after(v: &OAuthValidator, jwks: &FakeJwksServer, secs: f64) -> usize {
        tokio::time::advance(Duration::from_secs_f64(secs)).await;
        settle(v).await;
        jwks.hits.load(Ordering::SeqCst)
    }

    /// Assert that the background task's next attempt comes exactly `gap`
    /// seconds after the previous one (which ran at the current clock): none
    /// half a second before, one half a second after. The clock ends at that
    /// attempt, ready for the next call.
    async fn next_attempt_after(v: &OAuthValidator, jwks: &FakeJwksServer, gap: f64) {
        let before = jwks.hits.load(Ordering::SeqCst);
        assert_eq!(
            hits_after(v, jwks, gap - 0.5).await,
            before,
            "no attempt before {gap}s"
        );
        assert_eq!(
            hits_after(v, jwks, 1.0).await,
            before + 1,
            "an attempt at {gap}s"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_first_load_is_retried_quickly_until_keys_are_held() {
        let jwks = spawn_http_server(HashMap::new(), None).await;
        let set = |status: &'static str, body: String| {
            jwks.routes
                .lock()
                .unwrap()
                .insert("/jwks".to_string(), (status, body));
        };
        set("503 Service Unavailable", "{}".into());
        let v = Arc::new(validator(&jwks.url)); // the real 60 s cooldown
        let task = v.spawn_background_refresh();
        settle(&v).await;
        assert_eq!(jwks.hits.load(Ordering::SeqCst), 1, "the first load");
        assert!(!v.is_ready());

        // Keyless: 5 s, doubling, capped at 5 minutes.
        for gap in [5.0, 10.0, 20.0, 40.0, 80.0, 160.0, 300.0, 300.0] {
            next_attempt_after(&v, &jwks, gap).await;
        }
        assert!(!v.is_ready());
        assert_eq!(
            v.key_set_status().last_error.map(|e| e.kind()),
            Some(RefreshErrorKind::Fetch)
        );

        // The authorization server recovers: the next keyless retry loads the
        // keys.
        set("200 OK", jwks_body());
        next_attempt_after(&v, &jwks, 300.0).await;
        assert!(v.is_ready());
        assert_eq!(v.key_set_status().last_error, None);

        // With keys held the schedule is the pre-existing one: the hourly
        // pass, then — once it fails — a minute, not the 5 s keyless retry.
        set("503 Service Unavailable", "{}".into());
        next_attempt_after(&v, &jwks, 3600.0).await;
        next_attempt_after(&v, &jwks, 60.0).await;
        next_attempt_after(&v, &jwks, 120.0).await;
        assert!(v.is_ready(), "the failures kept the keys");

        task.abort();
    }

    #[tokio::test]
    async fn an_unreachable_jwks_endpoint_fails_closed() {
        // Port 1 refuses instantly.
        let v = validator("http://127.0.0.1:1/jwks");
        assert!(
            is_invalid(&v.validate(&valid_token()).await),
            "an IdP we cannot reach must mean 'no', never 'sure'"
        );
    }

    #[tokio::test]
    async fn a_jwks_error_response_fails_closed() {
        let jwks = spawn_jwks_server("500 Internal Server Error", "{}".into()).await;
        let v = validator(&jwks.url);
        assert!(is_invalid(&v.validate(&valid_token()).await));
        // The refresh error carries the whole cause chain, outermost first.
        let err = v.refresh_now().await.unwrap_err().to_string();
        assert!(
            err.starts_with(&format!(
                "fetching the JWKS from {}: non-success status: ",
                jwks.url
            )),
            "{err}"
        );
        assert!(err.contains("500 Internal Server Error"), "{err}");
    }

    #[tokio::test]
    async fn an_oversized_jwks_response_fails_closed() {
        let padding = "x".repeat(MAX_FETCH_BYTES);
        let body = format!("{{\"keys\":[{}],\"padding\":\"{padding}\"}}", jwk_rsa_a());
        let jwks = spawn_jwks_server("200 OK", body).await;
        let v = validator(&jwks.url);
        assert!(is_invalid(&v.validate(&valid_token()).await));
    }

    #[tokio::test]
    async fn a_key_set_with_no_usable_keys_fails_closed() {
        let body = jwks_of(&[
            // Encryption key, symmetric key, a P-521 key ring cannot verify, and
            // an RSA key whose declared alg contradicts its type: none may verify.
            serde_json::json!({"kty": "RSA", "use": "enc", "kid": KID_A, "n": N_A, "e": "AQAB"}),
            serde_json::json!({"kty": "oct", "kid": "hmac", "k": "c2VjcmV0"}),
            serde_json::json!({"kty": "EC", "crv": "P-521", "kid": "p521", "x": "AA", "y": "AA"}),
            serde_json::json!({"kty": "RSA", "alg": "ES256", "kid": KID_A, "n": N_A, "e": "AQAB"}),
        ]);
        let jwks = spawn_jwks_server("200 OK", body).await;
        let v = validator(&jwks.url);
        assert!(is_invalid(&v.validate(&valid_token()).await));
        assert!(
            v.refresh_now()
                .await
                .unwrap_err()
                .to_string()
                .contains("fetching the JWKS")
        );
    }

    #[tokio::test]
    async fn one_unparseable_key_does_not_take_the_usable_ones_down() {
        let body = jwks_of(&[
            serde_json::json!({"kty": "OKP", "crv": "X25519", "kid": "x", "x": "AA"}),
            serde_json::json!({"kty": "weird", "kid": "w"}),
            jwk_rsa_a(),
        ]);
        let jwks = spawn_jwks_server("200 OK", body).await;
        let v = validator(&jwks.url);
        assert!(v.validate(&valid_token()).await.is_ok());
    }

    #[tokio::test]
    async fn a_kid_less_header_uses_the_single_compatible_key() {
        let jwks = spawn_jwks_server("200 OK", jwks_body()).await;
        let v = validator(&jwks.url);
        let c = claims(serde_json::json!({"scope": "mcp:read"}));
        let token = mint_with(Algorithm::RS256, None, None, &c.clone());
        assert!(v.validate(&token).await.is_ok());

        // Two RSA keys that could both verify RS256: refuse rather than try each.
        let jwks = spawn_jwks_server(
            "200 OK",
            jwks_of(&[jwk_rsa_a(), jwk_rsa_a_any_alg("second")]),
        )
        .await;
        let v = validator(&jwks.url);
        assert!(is_invalid(&v.validate(&token).await));
    }

    // ── discovery ────────────────────────────────────────────────────────────

    /// Serve OIDC discovery for `issuer_path` on a fake server whose document
    /// claims `doc_issuer`, plus the JWKS.
    async fn discovery_server(
        issuer_path: &str,
        doc_issuer: impl Fn(&str) -> String,
        via_rfc8414: bool,
    ) -> (FakeJwksServer, String) {
        let server = spawn_http_server(HashMap::new(), None).await;
        let issuer = format!("{}{issuer_path}", server.base);
        let doc = serde_json::json!({
            "issuer": doc_issuer(&issuer),
            "jwks_uri": format!("{}/keys", server.base),
        })
        .to_string();
        let well_known = if via_rfc8414 {
            format!(
                "/.well-known/oauth-authorization-server{}",
                issuer_path.trim_end_matches('/')
            )
        } else {
            format!(
                "{}/.well-known/openid-configuration",
                issuer_path.trim_end_matches('/')
            )
        };
        {
            let mut routes = server.routes.lock().unwrap();
            routes.insert(well_known, ("200 OK", doc));
            routes.insert("/keys".to_string(), ("200 OK", jwks_body()));
        }
        (server, issuer)
    }

    fn discovering_validator(issuer: &str) -> OAuthValidator {
        let mut cfg = oauth_config("");
        cfg.issuer = issuer.to_string();
        validator_with(cfg)
    }

    fn token_from(issuer: &str) -> String {
        mint(
            KEY_A_PEM,
            KID_A,
            &claims(serde_json::json!({"iss": issuer, "scope": "mcp:read"})),
        )
    }

    #[tokio::test]
    async fn an_omitted_jwks_uri_is_discovered_once_from_oidc_metadata() {
        // Per-application issuer with a trailing slash — Authentik's shape.
        let (server, issuer) =
            discovery_server("/application/o/wiki/", |i| i.to_string(), false).await;
        let v = discovering_validator(&issuer);
        for _ in 0..3 {
            assert!(v.validate(&token_from(&issuer)).await.is_ok());
        }
        assert_eq!(
            server.hits.load(Ordering::SeqCst),
            2,
            "one discovery fetch and one JWKS fetch, then cached"
        );
    }

    #[tokio::test]
    async fn discovery_falls_back_to_rfc_8414_metadata() {
        let (_server, issuer) = discovery_server("/tenant", |i| i.to_string(), true).await;
        let v = discovering_validator(&issuer);
        assert!(v.validate(&token_from(&issuer)).await.is_ok());
    }

    #[tokio::test]
    async fn a_discovery_document_for_a_different_issuer_is_refused() {
        // The near miss again: the document drops the trailing slash.
        let (server, issuer) = discovery_server(
            "/application/o/wiki/",
            |i| i.trim_end_matches('/').to_string(),
            false,
        )
        .await;
        let v = discovering_validator(&issuer);
        assert!(is_invalid(&v.validate(&token_from(&issuer)).await));
        let err = v.refresh_now().await.unwrap_err().to_string();
        assert!(err.contains("does not match mcp.oauth.issuer"), "{err}");
        assert!(
            err.starts_with("could not discover a jwks_uri for mcp.oauth.issuer "),
            "{err}"
        );
        assert!(err.contains("set mcp.oauth.jwks_uri explicitly"), "{err}");
        // Two candidate URLs per attempt, two attempts, and the mismatching
        // document's jwks_uri was never followed.
        assert_eq!(server.hits.load(Ordering::SeqCst), 4);
    }

    #[test]
    fn loopback_detection() {
        assert!(is_loopback_url("http://127.0.0.1:8080/x"));
        assert!(is_loopback_url("http://[::1]:8080/x"));
        assert!(is_loopback_url("http://localhost/x"));
        assert!(!is_loopback_url("http://auth.example.com/x"));
        assert!(!is_loopback_url("not a url"));
    }

    #[tokio::test]
    async fn a_loopback_issuer_cannot_discover_a_cleartext_non_loopback_jwks_uri() {
        // A loopback issuer needs no opt-in; the key URL its metadata names
        // is still held to `allow_insecure_http`.
        let server = spawn_http_server(HashMap::new(), None).await;
        let issuer = format!("{}/app/", server.base);
        let doc =
            serde_json::json!({"issuer": issuer, "jwks_uri": "http://idp.example.invalid/keys"})
                .to_string();
        server.routes.lock().unwrap().insert(
            "/app/.well-known/openid-configuration".to_string(),
            ("200 OK", doc),
        );
        let v = discovering_validator(&issuer);
        let err = v.refresh_now().await.unwrap_err().to_string();
        assert!(err.contains("plain http on a non-loopback host"), "{err}");
        assert!(err.contains("mcp.oauth.allow_insecure_http"), "{err}");
    }

    #[tokio::test]
    async fn a_redirect_to_cleartext_on_a_non_loopback_host_is_refused() {
        // The status line carries a Location header: the fake server writes it
        // verbatim after `HTTP/1.1 `.
        let server = spawn_http_server(
            HashMap::from([(
                "/jwks".to_string(),
                (
                    "302 Found\r\nLocation: http://idp.example.invalid/keys",
                    String::new(),
                ),
            )]),
            None,
        )
        .await;
        let v = validator(&server.url);
        let err = v.refresh_now().await.unwrap_err().to_string();
        assert!(
            err.contains("redirect to plain http on a non-loopback host"),
            "{err}"
        );
        assert!(err.contains("mcp.oauth.allow_insecure_http"), "{err}");
        assert_eq!(server.hits.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn required_scopes_are_unadvertised_only_against_a_non_empty_menu() {
        let mut cfg = oauth_config("http://127.0.0.1/jwks");
        cfg.required_scopes = vec!["mcp:read".to_string()];
        cfg.scopes_supported = vec!["mcp:write".to_string()];
        assert_eq!(unadvertised_scopes(&cfg), ["mcp:read"]);
        cfg.scopes_supported = vec!["mcp:read".to_string(), "mcp:write".to_string()];
        assert!(unadvertised_scopes(&cfg).is_empty());
        // An empty menu makes the challenge name the required scopes, so nothing
        // is unadvertised.
        cfg.scopes_supported = Vec::new();
        assert!(unadvertised_scopes(&cfg).is_empty());
        let challenge = OAuthValidator::new(&cfg).unwrap().invalid_token_challenge();
        assert!(challenge.contains(r#"scope="mcp:read""#), "{challenge}");
    }

    // ── regression: the production Authentik shape, unchanged ────────────────

    /// The config block of the original production deployment (mcp-md-wiki),
    /// using ONLY the keys it had before provider-agnostic validation. Parsed from
    /// YAML when the `serde` feature is on, built literally otherwise.
    fn production_authentik_config(issuer: &str) -> crate::OAuthConfig {
        #[cfg(feature = "serde")]
        {
            let yaml = format!(
                "enabled: true\n\
                 issuer: \"{issuer}\"\n\
                 jwks_uri: \"{issuer}jwks/\"\n\
                 audience: \"example-client-id\"\n\
                 resource: \"https://kb.example.com/mcp\"\n\
                 required_scope: \"mcp:read\"\n\
                 scopes_supported: [\"mcp:read\", \"mcp:write\"]\n"
            );
            serde_yaml_ng::from_str(&yaml).unwrap()
        }
        #[cfg(not(feature = "serde"))]
        {
            crate::OAuthConfig {
                enabled: true,
                issuer: issuer.to_string(),
                jwks_uri: Some(format!("{issuer}jwks/")),
                audience: "example-client-id".into(),
                resource: "https://kb.example.com/mcp".into(),
                required_scope: Some("mcp:read".into()),
                scopes_supported: Some(vec!["mcp:read".into(), "mcp:write".into()]),
                ..crate::OAuthConfig::default()
            }
        }
    }

    /// The exact config and token shape of the original production deployment
    /// (Authentik, per-application issuer with a trailing slash, JWKS at
    /// `<issuer>jwks/`, `aud` = the OAuth client_id as a string, `scope` a
    /// space-delimited string, RS256, header `typ: JWT`). It must validate with
    /// every newer key at its default. Hostnames are placeholders; the fake server
    /// stands in for the AS.
    #[tokio::test]
    async fn production_authentik_config_and_token_still_pass_unchanged() {
        let server = spawn_http_server(HashMap::new(), None).await;
        let issuer = format!("{}/application/o/example-app/", server.base);
        server.routes.lock().unwrap().insert(
            "/application/o/example-app/jwks/".to_string(),
            ("200 OK", jwks_body()),
        );
        let parsed = production_authentik_config(&issuer);
        let cfg = parsed
            .resolve(crate::KeyNaming::Dotted("mcp.oauth"))
            .unwrap()
            .expect("enabled");
        assert!(
            cfg.accept_static_bearer,
            "dual mode must stay on by default"
        );
        assert_eq!(cfg.required_scopes, ["mcp:read"]);
        let v = validator_with(cfg);

        let token = mint_with(
            Algorithm::RS256,
            Some(KID_A),
            Some("JWT"),
            &serde_json::json!({
                "iss": issuer,
                "sub": "0000000000000000example",
                "aud": "example-client-id",
                "azp": "example-client-id",
                "exp": now() + 300,
                "iat": now(),
                "auth_time": now(),
                "acr": "goauthentik.io/providers/oauth2/default",
                "email": "user@example.com",
                "email_verified": true,
                "name": "Example User",
                "given_name": "Example User",
                "preferred_username": "example",
                "nickname": "example",
                "groups": ["wiki-users"],
                "scope": "openid email profile mcp:read mcp:write",
            }),
        );
        let t = v.validate(&token).await.unwrap();
        assert_eq!(t.principal.as_deref(), Some("example"));
        assert_eq!(
            t.scopes,
            ["openid", "email", "profile", "mcp:read", "mcp:write"]
        );
        // And the metadata and challenges are what they were before
        // provider-agnostic validation.
        assert_eq!(v.metadata()["authorization_servers"][0], issuer.as_str());
        assert!(
            v.invalid_token_challenge()
                .starts_with("Bearer error=\"invalid_token\", resource_metadata=")
        );
        assert_eq!(
            v.insufficient_scope_challenge(),
            "Bearer error=\"insufficient_scope\", scope=\"mcp:read\", \
             resource_metadata=\"https://kb.example.com/.well-known/oauth-protected-resource/mcp\""
        );
    }

    // ── observed shapes: sandbox-tested authorization servers ────────────────
    //
    // These mirror token shapes captured from real Authelia 4.39.4 and Kanidm
    // sandboxes. Hostnames and ids are placeholders.

    async fn accepts(
        cfg_edit: impl FnOnce(&mut ResolvedOAuthConfig),
        alg: Algorithm,
        kid: &str,
        typ: Option<&str>,
        token_claims: serde_json::Value,
    ) -> AuthorizedToken {
        let jwks = spawn_jwks_server("200 OK", jwks_body_all()).await;
        let mut cfg = oauth_config(&jwks.url);
        cfg_edit(&mut cfg);
        let v = validator_with(cfg);
        v.validate(&mint_with(alg, Some(kid), typ, &token_claims))
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn observed_shape_authelia_4_39_scp_array_and_resource_url_audience() {
        let issuer = "https://auth.example.com";
        let resource = "https://kb.example.com/mcp";
        let t = accepts(
            |c| {
                c.issuer = issuer.into();
                c.audience = resource.into();
                c.require_at_jwt = true;
            },
            Algorithm::RS256,
            "test-key-a-pss",
            Some("at+jwt"),
            serde_json::json!({
                "iss": issuer, "aud": [resource], "client_id": "example-client",
                "sub": "44726d41-0000-4000-8000-000000000000",
                "exp": now() + 3600, "iat": now(), "nbf": now(),
                "jti": "x", "scp": ["mcp:read", "mcp:write"],
            }),
        )
        .await;
        assert_eq!(t.scopes, ["mcp:read", "mcp:write"]);
        // No username claim in Authelia access tokens: the chain lands on `sub`.
        assert_eq!(
            t.principal.as_deref(),
            Some("44726d41-0000-4000-8000-000000000000")
        );
    }

    #[tokio::test]
    async fn observed_shape_kanidm_es256_per_client_issuer_and_client_audience() {
        let issuer = "https://idm.example.com/oauth2/openid/example-client";
        let t = accepts(
            |c| {
                c.issuer = issuer.into();
                c.audience = "example-client".into();
                c.require_at_jwt = true;
            },
            Algorithm::ES256,
            KID_EC,
            Some("at+jwt"),
            serde_json::json!({
                "iss": issuer, "aud": "example-client", "client_id": "example-client",
                "sub": "00000000-0000-4000-8000-000000000001",
                "exp": now() + 900, "iat": now(), "nbf": now(), "jti": "x",
                "scope": "mcp:read openid profile",
            }),
        )
        .await;
        assert!(t.has_scope("mcp:read"));
    }

    // ── documented-shape fixtures, NOT live-tested ───────────────────────────
    //
    // Each models the access-token shape the named authorization server
    // documents (or, where noted, its source code shows), to prove the generic
    // validator covers it with config alone. None of these has been run against
    // the real product; they are "documented-shape fixture, not live-tested" and
    // must not be cited as compatibility claims.

    #[tokio::test]
    async fn documented_shape_fixture_not_live_tested_keycloak() {
        // Realm issuer, `typ` JWT (at+jwt is an opt-in client switch since 26.2),
        // `scope` string, `azp` = client, `preferred_username` present.
        let issuer = "https://sso.example.com/realms/home";
        let t = accepts(
            |c| {
                c.issuer = issuer.into();
                c.audience = "wiki".into();
            },
            Algorithm::RS256,
            KID_A,
            Some("JWT"),
            serde_json::json!({
                "iss": issuer, "aud": ["wiki", "account"], "azp": "wiki",
                "sub": "u", "exp": now() + 300, "typ": "Bearer",
                "preferred_username": "alice", "scope": "openid profile mcp:read",
            }),
        )
        .await;
        assert_eq!(t.principal.as_deref(), Some("alice"));
    }

    #[tokio::test]
    async fn documented_shape_fixture_not_live_tested_okta_custom_as() {
        // Custom authorization server: no `typ` header at all, `scp` array,
        // `aud` = the configured API audience, `cid` = client.
        let issuer = "https://example.okta.com/oauth2/default";
        let t = accepts(
            |c| {
                c.issuer = issuer.into();
                c.audience = "api://default".into();
            },
            Algorithm::RS256,
            KID_A,
            None,
            serde_json::json!({
                "iss": issuer, "aud": "api://default", "cid": "client", "sub": "a@example.com",
                "exp": now() + 3600, "scp": ["openid", "mcp:read"],
            }),
        )
        .await;
        assert!(t.has_scope("mcp:read"));
    }

    #[tokio::test]
    async fn documented_shape_fixture_not_live_tested_entra_id_v2() {
        // v2.0 tenant issuer, `typ` JWT, `scp` space-delimited string, `aud` = the
        // API's client id.
        let issuer = "https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/v2.0";
        let t = accepts(
            |c| {
                c.issuer = issuer.into();
                c.audience = "11111111-1111-1111-1111-111111111111".into();
            },
            Algorithm::RS256,
            KID_A,
            Some("JWT"),
            serde_json::json!({
                "iss": issuer, "aud": "11111111-1111-1111-1111-111111111111",
                "sub": "pairwise", "oid": "o", "exp": now() + 3600,
                "preferred_username": "alice@example.com", "scp": "mcp.read mcp:read",
            }),
        )
        .await;
        assert!(t.has_scope("mcp:read"));
    }

    #[tokio::test]
    async fn documented_shape_fixture_not_live_tested_auth0() {
        // Issuer with a trailing slash, `aud` array (API identifier + userinfo),
        // `scope` string, both the Auth0 (`typ` JWT) and RFC 9068 (`at+jwt`)
        // profiles.
        let issuer = "https://tenant.example.auth0.com/";
        for typ in ["JWT", "at+jwt"] {
            let t = accepts(
                |c| {
                    c.issuer = issuer.into();
                    c.audience = "https://kb.example.com/mcp".into();
                },
                Algorithm::RS256,
                KID_A,
                Some(typ),
                serde_json::json!({
                    "iss": issuer,
                    "aud": ["https://kb.example.com/mcp", "https://tenant.example.auth0.com/userinfo"],
                    "azp": "client", "sub": "auth0|1", "exp": now() + 3600,
                    "scope": "openid mcp:read",
                }),
            )
            .await;
            assert!(t.has_scope("mcp:read"));
        }
    }

    #[tokio::test]
    async fn documented_shape_fixture_not_live_tested_ory_hydra_jwt_strategy() {
        // Only with `strategies.access_token: jwt` (the default is opaque);
        // `scp` is a list by default, a string with `oauth2.jwt.scope_claim: string`.
        let issuer = "https://hydra.example.com/";
        for scp in [
            serde_json::json!(["mcp:read"]),
            serde_json::json!("offline mcp:read"),
        ] {
            let t = accepts(
                |c| {
                    c.issuer = issuer.into();
                    c.audience = "https://kb.example.com/mcp".into();
                },
                Algorithm::RS256,
                KID_A,
                Some("JWT"),
                serde_json::json!({
                    "iss": issuer, "aud": ["https://kb.example.com/mcp"], "sub": "u",
                    "client_id": "c", "exp": now() + 3600, "scp": scp, "ext": {},
                }),
            )
            .await;
            assert!(t.has_scope("mcp:read"));
        }
    }

    #[tokio::test]
    async fn documented_shape_fixture_not_live_tested_logto_resource_indicator() {
        // `aud` = the registered API resource indicator (RFC 8707), `scope`
        // string, ES256 among its allowed signing algorithms.
        let issuer = "https://logto.example.com/oidc";
        let t = accepts(
            |c| {
                c.issuer = issuer.into();
                c.audience = "https://kb.example.com/mcp".into();
            },
            Algorithm::ES256,
            KID_EC,
            None,
            serde_json::json!({
                "iss": issuer, "aud": "https://kb.example.com/mcp", "sub": "u",
                "client_id": "c", "exp": now() + 3600, "scope": "mcp:read",
            }),
        )
        .await;
        assert!(t.has_scope("mcp:read"));
    }

    #[tokio::test]
    async fn documented_shape_fixture_not_live_tested_casdoor_jwt_standard() {
        // Source-derived: no `typ` beyond jsonwebtoken's default, `aud` =
        // [client_id] (or [resource] when RFC 8707 is used), `scope` string,
        // `preferred_username` with the JWT-Standard token format.
        let issuer = "https://casdoor.example.com";
        let t = accepts(
            |c| {
                c.issuer = issuer.into();
                c.audience = "example-client-id".into();
            },
            Algorithm::RS256,
            KID_A,
            Some("JWT"),
            serde_json::json!({
                "iss": issuer, "aud": ["example-client-id"], "sub": "u",
                "exp": now() + 3600, "preferred_username": "alice",
                "scope": "openid mcp:read",
            }),
        )
        .await;
        assert_eq!(t.principal.as_deref(), Some("alice"));
    }

    #[tokio::test]
    async fn documented_shape_fixture_not_live_tested_rauthy_eddsa_at_jwt() {
        // Source-derived: `typ` at+jwt, `scope` string, EdDSA available per
        // client, no `preferred_username` (the principal chain falls to `sub`).
        let issuer = "https://rauthy.example.com/auth/v1";
        let t = accepts(
            |c| {
                c.issuer = issuer.into();
                c.audience = "example-client".into();
                c.require_at_jwt = true;
            },
            Algorithm::EdDSA,
            KID_ED,
            Some("at+jwt"),
            serde_json::json!({
                "iss": issuer, "aud": "example-client", "azp": "example-client",
                "sub": "user-id", "exp": now() + 1800, "scope": "openid mcp:read",
            }),
        )
        .await;
        assert_eq!(t.principal.as_deref(), Some("user-id"));
    }

    #[tokio::test]
    async fn documented_shape_fixture_not_live_tested_dex_needs_a_group_claim_as_scope() {
        // Source-derived: Dex's access token is an ID token (`aud` = client_id, no
        // `scope`/`scp` claim at all). The only generic way to gate it is to read
        // a group claim as the scope source — a compromise, see the design notes.
        let issuer = "https://dex.example.com";
        let t = accepts(
            |c| {
                c.issuer = issuer.into();
                c.audience = "example-client".into();
                c.scope_claims = vec!["groups".into()];
                c.required_scopes = vec!["wiki-users".into()];
            },
            Algorithm::RS256,
            KID_A,
            None,
            serde_json::json!({
                "iss": issuer, "aud": "example-client", "sub": "u",
                "exp": now() + 3600, "email": "a@example.com",
                "groups": ["wiki-users", "admins"],
            }),
        )
        .await;
        assert!(t.has_scope("wiki-users"));
    }

    #[tokio::test]
    async fn documented_shape_fixture_not_live_tested_zitadel_jwt_mode() {
        // Only with the application's token type switched to JWT (opaque is the
        // alternative). `aud` holds the client ids and the project id.
        // Zitadel's scope claim shape is not documented where we looked; this
        // fixture exercises the aud-array/project-id part only.
        let issuer = "https://zitadel.example.com";
        let t = accepts(
            |c| {
                c.issuer = issuer.into();
                c.audience = "123456789012345678".into();
            },
            Algorithm::RS256,
            KID_A,
            None,
            serde_json::json!({
                "iss": issuer,
                "aud": ["234567890123456789@wiki", "123456789012345678"],
                "client_id": "234567890123456789@wiki", "sub": "u",
                "exp": now() + 3600, "scope": "openid mcp:read",
            }),
        )
        .await;
        assert!(t.has_scope("mcp:read"));
    }

    // ── verified claims and token metadata ───────────────────────────────────

    fn at(secs: u64) -> std::time::SystemTime {
        std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs)
    }

    #[tokio::test]
    async fn issuer_expiry_and_audience_string_are_filled_from_the_token() {
        let exp = now() + 1800;
        let t = scopes_of(serde_json::json!({"scope": "mcp:read", "exp": exp}))
            .await
            .unwrap();
        assert_eq!(t.issuer, ISSUER);
        assert_eq!(t.audiences, [AUDIENCE]);
        assert_eq!(t.expires_at, at(exp));
    }

    #[tokio::test]
    async fn audience_array_is_normalized_to_a_list() {
        let t = scopes_of(serde_json::json!({
            "scope": "mcp:read", "aud": ["https://other.example.test", AUDIENCE],
        }))
        .await
        .unwrap();
        assert_eq!(t.audiences, ["https://other.example.test", AUDIENCE]);
    }

    #[tokio::test]
    async fn client_id_claim_wins_over_azp() {
        let t = scopes_of(serde_json::json!({
            "scope": "mcp:read", "client_id": "client-1", "azp": "client-2",
        }))
        .await
        .unwrap();
        assert_eq!(t.client_id.as_deref(), Some("client-1"));
    }

    #[tokio::test]
    async fn client_id_falls_back_to_azp() {
        let t = scopes_of(serde_json::json!({"scope": "mcp:read", "azp": "client-2"}))
            .await
            .unwrap();
        assert_eq!(t.client_id.as_deref(), Some("client-2"));
    }

    #[tokio::test]
    async fn client_id_is_none_without_client_id_or_azp() {
        let t = scopes_of(serde_json::json!({"scope": "mcp:read"}))
            .await
            .unwrap();
        assert_eq!(t.client_id, None);
        // An empty or non-string value is not a client id either.
        let t = scopes_of(serde_json::json!({"scope": "mcp:read", "client_id": "", "azp": 7}))
            .await
            .unwrap();
        assert_eq!(t.client_id, None);
    }

    #[tokio::test]
    async fn issued_at_is_read_when_present_and_none_when_absent() {
        let iat = now() - 60;
        let t = scopes_of(serde_json::json!({"scope": "mcp:read", "iat": iat}))
            .await
            .unwrap();
        assert_eq!(t.issued_at, Some(at(iat)));
        let t = scopes_of(serde_json::json!({"scope": "mcp:read"}))
            .await
            .unwrap();
        assert_eq!(t.issued_at, None);
    }

    #[tokio::test]
    async fn jti_is_read_when_present_and_none_when_absent() {
        let t = scopes_of(serde_json::json!({"scope": "mcp:read", "jti": "id-42"}))
            .await
            .unwrap();
        assert_eq!(t.jti.as_deref(), Some("id-42"));
        let t = scopes_of(serde_json::json!({"scope": "mcp:read"}))
            .await
            .unwrap();
        assert_eq!(t.jti, None);
    }

    #[tokio::test]
    async fn claims_returns_custom_claims_and_claims_as_round_trips() {
        #[derive(serde::Deserialize, Debug, PartialEq)]
        struct AppClaims {
            sub: String,
            email: String,
            groups: Vec<String>,
            #[serde(default)]
            tenant: Option<String>,
        }
        let t = scopes_of(serde_json::json!({
            "scope": "mcp:read",
            "email": "ada@example.com",
            "groups": ["admins", "dev"],
        }))
        .await
        .unwrap();
        assert_eq!(t.claims()["groups"], serde_json::json!(["admins", "dev"]));
        assert_eq!(t.claims()["iss"], ISSUER);
        let typed: AppClaims = t.claims_as().unwrap();
        assert_eq!(
            typed,
            AppClaims {
                sub: "user-1".into(),
                email: "ada@example.com".into(),
                groups: vec!["admins".into(), "dev".into()],
                tenant: None,
            }
        );
        // A shape mismatch is an error, not a panic.
        #[derive(serde::Deserialize, Debug)]
        struct NeedsTenant {
            #[allow(dead_code)]
            tenant: String,
        }
        assert!(t.claims_as::<NeedsTenant>().is_err());
    }

    #[tokio::test]
    async fn debug_shows_claim_names_but_never_claim_values() {
        let t = scopes_of(serde_json::json!({
            "scope": "mcp:read", "email": "private-address@example.com",
        }))
        .await
        .unwrap();
        let shown = format!("{t:?}");
        assert!(shown.contains("\"email\""));
        assert!(!shown.contains("private-address@example.com"));
    }

    #[tokio::test]
    async fn an_out_of_range_exp_and_iat_saturate_instead_of_reading_as_expired() {
        // jsonwebtoken accepts an `exp` up to u64::MAX; SystemTime cannot hold it.
        let t = scopes_of(serde_json::json!({
            "scope": "mcp:read",
            "exp": 10_000_000_000_000_000_000u64,
            "iat": 10_000_000_000_000_000_000u64,
        }))
        .await
        .unwrap();
        let max = at(253_402_300_799);
        assert_eq!(t.expires_at, max);
        assert_eq!(t.issued_at, Some(max));
    }

    #[tokio::test]
    async fn fractional_exp_and_iat_are_rounded_like_jsonwebtoken_rounds_them() {
        // jsonwebtoken (`numeric_type`) does `value.round() as u64` before it
        // checks `exp`, so `base + 0.5` reads as `base + 1` (half away from zero).
        let base = now() + 1000;
        let iat = now() - 100;
        let t = scopes_of(serde_json::json!({
            "scope": "mcp:read",
            "exp": base as f64 + 0.5,
            "iat": iat as f64 + 0.4,
        }))
        .await
        .unwrap();
        assert_eq!(t.expires_at, at(base + 1));
        assert_eq!(t.issued_at, Some(at(iat)));
    }

    #[tokio::test]
    async fn a_string_iat_is_ignored_and_the_token_is_still_accepted() {
        // jsonwebtoken never reads `iat`, so a token with a junk one validates
        // today; issued_at is just None.
        let t = scopes_of(serde_json::json!({"scope": "mcp:read", "iat": "yesterday"}))
            .await
            .unwrap();
        assert_eq!(t.issued_at, None);
    }
}
