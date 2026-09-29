//! axum integration: the authentication layer ([`AuthLayer`], a
//! `tower::Layer`, also usable as state for the [`require_auth`] middleware
//! function) and the RFC 9728 metadata routes ([`metadata_router`]).
//!
//! ```no_run
//! use std::sync::Arc;
//!
//! use axum::{Router, routing::get};
//! use oauth_resource_server::axum::{AuthLayer, metadata_router};
//! use oauth_resource_server::{OAuthValidator, ResolvedOAuthConfig, static_token_policy};
//!
//! # fn app(config: &ResolvedOAuthConfig, static_token: Option<String>) -> Router {
//! let oauth = Arc::new(OAuthValidator::new(config).expect("validator"));
//! oauth.spawn_background_refresh();
//!
//! // `accept_static_bearer` only takes effect through `static_token_policy`, the
//! // one thing that reads the setting. Handing `static_token` straight to the
//! // builder instead would make `accept_static_bearer: false` silently do nothing.
//! let decision = static_token_policy(static_token, Some(config), false)
//!     .expect("oauth is configured here, so a credential always exists");
//! let auth = AuthLayer::from_decision(decision, Some(Arc::clone(&oauth)))
//!     .expect("the decision was made with OAuth on, and a validator is given");
//!
//! Router::new()
//!     .route("/api", get(|| async { "protected" }))
//!     .route_layer(auth)
//!     // Outside the auth layer: discovery must work for a caller that has no
//!     // credential yet.
//!     .merge(metadata_router(Some(oauth)))
//! # }
//! ```
//!
//! `.route_layer(auth)` and
//! `.route_layer(axum::middleware::from_fn_with_state(auth, require_auth))`
//! behave identically; the second form is for composing with other `from_fn`
//! middleware.
//!
//! # Refusals
//!
//! 401 for a missing or invalid credential, 403 for a valid token without the
//! required scopes, each with a `WWW-Authenticate` challenge: the validator's
//! when OAuth is configured, otherwise [`DEFAULT_STATIC_CHALLENGE`] (see
//! [`AuthLayerBuilder::static_challenge`]). There is no 400 `invalid_request`
//! (RFC 6750 §3.1's SHOULD for a malformed request): a request is authenticated
//! or it is not, and anything unreadable is simply no credential.
//!
//! # Logging
//!
//! The layer logs every outcome itself, so applications need not (target
//! `oauth_resource_server::axum`): an accepted OAuth token at `debug` (principal,
//! subject, scopes — never the token); a request with no credential at `debug`
//! when OAuth is configured, since every OAuth client's first request looks like
//! that; any other refusal at `warn`, with the reason when OAuth is configured.
//! The reason goes to the log only, never to the caller.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use ::axum::Json;
use ::axum::Router;
use ::axum::body::Body;
use ::axum::extract::{Request, State};
use ::axum::middleware::Next;
use ::axum::response::{IntoResponse, Response};
use ::axum::routing::{any, get};
use http::header::{AUTHORIZATION, WWW_AUTHENTICATE};
use http::request::Parts;
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use tracing::{debug, warn};

use crate::authenticate::{Credential, authenticate};
use crate::challenge::PROTECTED_RESOURCE_METADATA_PREFIX;
use crate::policy::StaticTokenDecision;
use crate::token::{TokenRejection, for_log};
use crate::validator::OAuthValidator;

/// Where a request may carry a credential. Each configured source contributes
/// at most one candidate — the header's FIRST value; a request that repeats the
/// header has the later values ignored, not refused — and every candidate is
/// checked independently (see [`crate::authenticate()`]): a bad credential in
/// one source never masks a good one in another.
///
/// A header value that is not visible ASCII contributes no candidate. Every
/// configured source header is marked sensitive
/// (`http::HeaderValue::set_sensitive`) on the request, before the callback and
/// the inner service see it, so `Debug` output and tracing layers print it as
/// `Sensitive`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CredentialSource {
    /// `<header>: Bearer <token>` (RFC 6750 §2.1). The scheme is matched
    /// case-insensitively (RFC 9110 §11.1): `bearer x` is the same credential as
    /// `Bearer x`. The token is the rest of the value after the first space,
    /// trimmed. Any other scheme contributes no candidate.
    Bearer(HeaderName),
    /// `<header>: <token>`: the whole value, verbatim — for an API-key header
    /// such as `X-Api-Key`.
    Raw(HeaderName),
}

impl CredentialSource {
    /// `Authorization: Bearer <token>`, the default and only source unless
    /// [`AuthLayerBuilder::sources`] says otherwise.
    pub fn authorization_bearer() -> Self {
        Self::Bearer(AUTHORIZATION)
    }

    /// This source's candidate in `headers`, if the header is present, valid
    /// visible ASCII and (for [`CredentialSource::Bearer`]) uses the `Bearer`
    /// scheme. May be blank; [`crate::authenticate()`] treats blank as absent.
    fn candidate<'h>(&self, headers: &'h HeaderMap) -> Option<&'h str> {
        match self {
            Self::Bearer(name) => headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(bearer_credential),
            Self::Raw(name) => headers.get(name).and_then(|v| v.to_str().ok()),
        }
    }

    /// The header this source reads.
    fn header_name(&self) -> &HeaderName {
        match self {
            Self::Bearer(name) | Self::Raw(name) => name,
        }
    }
}

/// The credential from a `Bearer <token>` header value, or `""`.
///
/// The auth-scheme is matched case-insensitively (RFC 9110 §11.1, RFC 6750 §2.1
/// examples notwithstanding) — `bearer x` is the same credential as `Bearer x`,
/// and refusing it would be a spurious 401 for a client that lower-cases scheme
/// names. The token itself is taken verbatim, minus surrounding spaces.
pub(crate) fn bearer_credential(header: &str) -> &str {
    match header.split_once(' ') {
        Some((scheme, token)) if scheme.eq_ignore_ascii_case("bearer") => token.trim(),
        _ => "",
    }
}

/// What an [`AuthLayerBuilder::on_reject`] callback is told about a refusal.
///
/// `#[non_exhaustive]`: read its fields; more may be added without a breaking
/// change.
///
/// Its `Debug` prints the rejection, the status, the method, URI and version,
/// and the request's header NAMES — never a header value, so
/// `tracing::warn!(?cx, "refused")` cannot log the presented credential (which,
/// for an insufficient-scope refusal, is a validly signed, unexpired token).
#[non_exhaustive]
pub struct RejectContext<'a> {
    /// Why the request was refused. [`TokenRejection::Invalid`]'s reason is for
    /// logs only — never put it in the response.
    pub rejection: &'a TokenRejection,
    /// The status the response will carry (401, or 403 for insufficient scope),
    /// whatever the callback sets.
    pub status: StatusCode,
    /// The refused request's method, URI, version, headers and extensions — for
    /// content negotiation (`Accept`), or a per-path error shape.
    pub request: &'a Parts,
}

impl std::fmt::Debug for RejectContext<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let header_names: Vec<&str> = self
            .request
            .headers
            .keys()
            .map(HeaderName::as_str)
            .collect();
        f.debug_struct("RejectContext")
            .field("rejection", self.rejection)
            .field("status", &self.status)
            .field("method", &self.request.method)
            .field("uri", &self.request.uri)
            .field("version", &self.request.version)
            .field("header_names", &header_names)
            .finish_non_exhaustive()
    }
}

/// Builds a refusal's body and extra headers; see [`AuthLayerBuilder::on_reject`].
pub type RejectFn = Arc<dyn Fn(RejectContext<'_>) -> Response + Send + Sync>;

/// The `WWW-Authenticate` value a layer with no OAuth validator sends on every
/// 401, unless [`AuthLayerBuilder::static_challenge`] says otherwise.
///
/// RFC 9110 §15.5.2 requires a 401 to carry at least one challenge, and RFC
/// 6750 §3 a `Bearer` challenge with at least one parameter. This is the same
/// `invalid_token` challenge an OAuth layer sends (without the
/// `resource_metadata` there is nothing to point at), for a missing credential
/// as well as a wrong one — see the [module docs](self).
pub const DEFAULT_STATIC_CHALLENGE: &str = "Bearer error=\"invalid_token\"";

/// Why an [`AuthLayerBuilder`] refused to build.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AuthLayerError {
    /// Neither a (non-empty) static token nor an OAuth validator was given. A
    /// layer that could accept nothing would lock every route; one that
    /// accepted everything must be asked for by name.
    #[error(
        "no credential is configured: give a static token and/or an OAuth validator \
         (AuthLayer::allow_unauthenticated is the explicit opt-out)"
    )]
    NoCredential,
    /// [`AuthLayerBuilder::sources`] was given an empty list, so no request could
    /// ever present a credential.
    #[error("no credential source is configured: a request could never present a credential")]
    NoSources,
    /// [`AuthLayerBuilder::build_with_decision`]: the decision was made with
    /// OAuth on, but no OAuth validator was given.
    #[error(
        "the static-token decision was made with OAuth enabled, but no OAuth validator \
         was given"
    )]
    DecisionNeedsOAuth,
    /// [`AuthLayerBuilder::build_with_decision`]: the decision was made with
    /// OAuth off, but an OAuth validator was given.
    #[error(
        "the static-token decision was made with OAuth disabled, but an OAuth validator \
         was given"
    )]
    DecisionWithoutOAuth,
    /// The OAuth validator's challenge is not a valid HTTP header value, so
    /// refusals could not carry `WWW-Authenticate`. [`crate::OAuthConfig::resolve`]
    /// refuses every config that would cause this (a control or non-ASCII
    /// character in `resource`, a scope that is not a scope-token); only a
    /// hand-edited [`crate::ResolvedOAuthConfig`] reaches it.
    #[error(
        "the OAuth WWW-Authenticate challenge is not a valid HTTP header value — check \
         the resource URL and scopes for control or non-ASCII characters"
    )]
    InvalidChallenge,
}

/// Which credentials are accepted, where they are read from, and how a refusal
/// looks. Cheap to clone (one `Arc`).
///
/// It is a `tower::Layer`, so `router.route_layer(auth)` (or `.layer(auth)`)
/// protects routes directly; it is also the state for the [`require_auth`]
/// middleware function (`axum::middleware::from_fn_with_state(auth,
/// require_auth)`), which behaves identically.
///
/// **Fail-closed by construction.** [`AuthLayer::builder`] refuses to build
/// without at least one credential; the only way to get a layer that lets
/// requests through unauthenticated is to call
/// [`AuthLayer::allow_unauthenticated`] by name (or to hand
/// [`AuthLayer::from_decision`] or [`AuthLayerBuilder::build_with_decision`] a
/// [`StaticTokenDecision::Unauthenticated`], which [`crate::static_token_policy`]
/// returns only when its `allow_unauthenticated` argument is `true`, and which
/// can otherwise only be named directly).
///
/// Built once at startup. Nothing in it hot-reloads: a changed static token or
/// OAuth config takes effect when a new layer is built, which in practice means
/// a restart.
#[derive(Clone)]
pub struct AuthLayer {
    inner: Arc<Mode>,
}

enum Mode {
    Enforce(Enforce),
    AllowUnauthenticated,
}

struct Enforce {
    static_token: Option<String>,
    oauth: Option<Arc<OAuthValidator>>,
    sources: Vec<CredentialSource>,
    on_reject: Option<RejectFn>,
    /// The validator's pre-rendered challenges, `(invalid_token,
    /// insufficient_scope)`; `Some` exactly when OAuth is configured (a
    /// challenge that is not a valid header value fails the build instead).
    oauth_challenges: Option<(HeaderValue, HeaderValue)>,
    /// The challenge for a 401 when OAuth is off; `None` when the application
    /// opted out with `static_challenge(None)`.
    static_challenge: Option<HeaderValue>,
}

/// Hand-written so the static token never reaches a log line through `{:?}`.
impl std::fmt::Debug for AuthLayer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &*self.inner {
            Mode::AllowUnauthenticated => f
                .debug_struct("AuthLayer")
                .field("allow_unauthenticated", &true)
                .finish(),
            Mode::Enforce(e) => f
                .debug_struct("AuthLayer")
                .field(
                    "static_token",
                    &e.static_token.as_ref().map(|_| "<redacted>"),
                )
                .field("oauth", &e.oauth)
                .field("sources", &e.sources)
                .field("on_reject", &e.on_reject.as_ref().map(|_| "<fn>"))
                .field("static_challenge", &e.static_challenge)
                .finish(),
        }
    }
}

impl AuthLayer {
    /// Start building an enforcing layer.
    ///
    /// Give it a static token, an OAuth validator, or both; optionally the
    /// credential sources (default: `Authorization: Bearer`) and an
    /// [`on_reject`](AuthLayerBuilder::on_reject) callback. To honour
    /// `accept_static_bearer`, finish with
    /// [`build_with_decision`](AuthLayerBuilder::build_with_decision) and a
    /// [`crate::static_token_policy`] decision rather than setting the static
    /// token directly.
    ///
    /// # Examples
    ///
    /// ```
    /// use axum::{Router, http::HeaderName, routing::get};
    /// use oauth_resource_server::axum::{AuthLayer, AuthLayerError, CredentialSource};
    ///
    /// // A static API key accepted from either header. (With OAuth, add
    /// // `.oauth(validator)` as well.)
    /// let auth = AuthLayer::builder()
    ///     .static_token("example-static-key")
    ///     .sources([
    ///         CredentialSource::authorization_bearer(),
    ///         CredentialSource::Raw(HeaderName::from_static("x-api-key")),
    ///     ])
    ///     .build()
    ///     .unwrap();
    /// let app: Router = Router::new()
    ///     .route("/api", get(|| async { "protected" }))
    ///     .route_layer(auth);
    ///
    /// // Fail closed: no credential configured is an error, not a pass-through.
    /// assert_eq!(AuthLayer::builder().build().unwrap_err(), AuthLayerError::NoCredential);
    /// # let _ = app;
    /// ```
    pub fn builder() -> AuthLayerBuilder {
        AuthLayerBuilder::default()
    }

    /// A layer that lets EVERY request through, unauthenticated, and inserts
    /// nothing into request extensions.
    ///
    /// The explicit opt-out. The only other pass-through is a
    /// [`crate::StaticTokenDecision::Unauthenticated`] handed to
    /// [`AuthLayer::from_decision`] or [`AuthLayerBuilder::build_with_decision`],
    /// which builds this same layer. Pair it with a loud startup warning. [`crate::static_token_policy`]
    /// returns [`crate::StaticTokenDecision::Unauthenticated`] exactly
    /// when an application has chosen this.
    ///
    /// # Security
    ///
    /// Every request reaches the protected routes. Use it only where something
    /// else (a trusted network, a proxy that authenticates) stands in front.
    pub fn allow_unauthenticated() -> Self {
        Self {
            inner: Arc::new(Mode::AllowUnauthenticated),
        }
    }

    /// The layer a [`crate::static_token_policy`] decision calls for, with the
    /// default source (`Authorization: Bearer`) and refusal shape — the whole
    /// startup mapping in one call. Shorthand for
    /// `AuthLayer::builder().optional_oauth(oauth).build_with_decision(decision)`;
    /// use that form to set sources or `on_reject` as well.
    ///
    /// # Errors
    ///
    /// See [`AuthLayerBuilder::build_with_decision`].
    pub fn from_decision(
        decision: StaticTokenDecision,
        oauth: Option<Arc<OAuthValidator>>,
    ) -> Result<Self, AuthLayerError> {
        Self::builder()
            .optional_oauth(oauth)
            .build_with_decision(decision)
    }

    /// Whether this is the [`AuthLayer::allow_unauthenticated`] pass-through.
    pub fn allows_unauthenticated(&self) -> bool {
        matches!(*self.inner, Mode::AllowUnauthenticated)
    }

    /// The OAuth validator, when one is configured.
    pub fn oauth(&self) -> Option<&Arc<OAuthValidator>> {
        match &*self.inner {
            Mode::Enforce(e) => e.oauth.as_ref(),
            Mode::AllowUnauthenticated => None,
        }
    }
}

/// Builder for an enforcing [`AuthLayer`]; see [`AuthLayer::builder`].
#[derive(Default)]
pub struct AuthLayerBuilder {
    static_token: Option<String>,
    oauth: Option<Arc<OAuthValidator>>,
    sources: Option<Vec<CredentialSource>>,
    on_reject: Option<RejectFn>,
    /// `None`: not set, so [`DEFAULT_STATIC_CHALLENGE`].
    static_challenge: Option<Option<HeaderValue>>,
}

impl std::fmt::Debug for AuthLayerBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthLayerBuilder")
            .field(
                "static_token",
                &self.static_token.as_ref().map(|_| "<redacted>"),
            )
            .field("oauth", &self.oauth)
            .field("sources", &self.sources)
            .field("on_reject", &self.on_reject.as_ref().map(|_| "<fn>"))
            .field("static_challenge", &self.static_challenge)
            .finish()
    }
}

impl AuthLayerBuilder {
    /// Accept this static token (compared in constant time). An empty string
    /// counts as no token.
    ///
    /// # Security
    ///
    /// Setting the token here bypasses `accept_static_bearer`, which only
    /// [`crate::static_token_policy`] reads; with OAuth configured, prefer
    /// [`AuthLayerBuilder::build_with_decision`]. The token's length is not
    /// hidden by the comparison, and `Debug` output shows it as `<redacted>`.
    pub fn static_token(mut self, token: impl Into<String>) -> Self {
        self.static_token = Some(token.into());
        self
    }

    /// [`AuthLayerBuilder::static_token`] when `Some`; for threading through the
    /// output of [`crate::static_token_policy`] or a secret loader.
    pub fn optional_static_token(mut self, token: Option<String>) -> Self {
        self.static_token = token;
        self
    }

    /// Accept OAuth access tokens this validator accepts.
    pub fn oauth(mut self, validator: Arc<OAuthValidator>) -> Self {
        self.oauth = Some(validator);
        self
    }

    /// [`AuthLayerBuilder::oauth`] when `Some`.
    pub fn optional_oauth(mut self, validator: Option<Arc<OAuthValidator>>) -> Self {
        self.oauth = validator;
        self
    }

    /// Where to read credentials from, replacing the default
    /// `[CredentialSource::authorization_bearer()]`. Every source is checked,
    /// whatever the others hold.
    pub fn sources(mut self, sources: impl IntoIterator<Item = CredentialSource>) -> Self {
        self.sources = Some(sources.into_iter().collect());
        self
    }

    /// The `WWW-Authenticate` challenge every 401 carries when NO OAuth
    /// validator is configured; with one, the validator's challenges are used
    /// and this is ignored. Default: [`DEFAULT_STATIC_CHALLENGE`].
    ///
    /// `Some(value)` sends `value` instead — `Bearer realm="my-api"`, say, or
    /// your own scheme for an API-key header. `None` sends no challenge at all
    /// and leaves any `WWW-Authenticate` an [`on_reject`](Self::on_reject)
    /// callback set untouched. That departs from RFC 9110 §15.5.2 (a 401 MUST
    /// carry a challenge); use it only to keep an existing API's responses
    /// unchanged.
    ///
    /// ```
    /// use axum::http::HeaderValue;
    /// use oauth_resource_server::axum::AuthLayer;
    ///
    /// let auth = AuthLayer::builder()
    ///     .static_token("example-static-key")
    ///     .static_challenge(Some(HeaderValue::from_static("Bearer realm=\"my-api\"")))
    ///     .build()
    ///     .unwrap();
    /// # let _ = auth;
    /// ```
    pub fn static_challenge(mut self, challenge: Option<HeaderValue>) -> Self {
        self.static_challenge = Some(challenge);
        self
    }

    /// Build the body and any extra headers of a refusal — for an API whose
    /// errors are, say, JSON. Without it a refusal has an empty body. The
    /// [`RejectContext`] carries the rejection, the status and the request's
    /// parts (method, URI, headers), so the shape can depend on, say, `Accept`.
    ///
    /// The callback shapes the response only; it cannot change the outcome.
    /// Whatever it returns, the status is set to [`RejectContext::status`] (401
    /// for a missing or invalid credential, 403 for insufficient scope), and
    /// `WWW-Authenticate` is set to the layer's challenge, replacing any the
    /// callback set: the validator's when OAuth is configured — every 401/403
    /// must carry it, or claude.ai (among others) never starts the
    /// authorization flow — and otherwise the
    /// [`static_challenge`](Self::static_challenge). Only with
    /// `static_challenge(None)` and no OAuth are the callback's headers left
    /// as they are.
    ///
    /// Never put [`TokenRejection::Invalid`]'s reason in the body: telling an
    /// unauthenticated caller exactly which check failed is a free oracle. The
    /// credential headers in [`RejectContext::request`] are marked sensitive,
    /// and `RejectContext`'s `Debug` prints no header values.
    pub fn on_reject(
        mut self,
        f: impl Fn(RejectContext<'_>) -> Response + Send + Sync + 'static,
    ) -> Self {
        self.on_reject = Some(Arc::new(f));
        self
    }

    /// Build the layer a [`crate::static_token_policy`] decision calls for,
    /// keeping this builder's sources and `on_reject`.
    ///
    /// The decision's static token (if any) replaces one set on this builder.
    /// [`StaticTokenDecision::Unauthenticated`] yields
    /// [`AuthLayer::allow_unauthenticated`] — the decision is itself the
    /// application's explicit opt-out, since `static_token_policy` returns it
    /// only when asked to allow unauthenticated access. Every other decision
    /// builds an enforcing layer exactly as [`AuthLayerBuilder::build`] does.
    ///
    /// # Errors
    ///
    /// The decision must agree with the validator given via
    /// [`AuthLayerBuilder::oauth`]: [`AuthLayerError::DecisionNeedsOAuth`] when
    /// it was made with OAuth on and no validator was given,
    /// [`AuthLayerError::DecisionWithoutOAuth`] when it was made with OAuth off
    /// (including `Unauthenticated`) and one was given. Otherwise as
    /// [`AuthLayerBuilder::build`].
    pub fn build_with_decision(
        mut self,
        decision: StaticTokenDecision,
    ) -> Result<AuthLayer, AuthLayerError> {
        match (decision.oauth_enabled(), self.oauth.is_some()) {
            (true, false) => return Err(AuthLayerError::DecisionNeedsOAuth),
            (false, true) => return Err(AuthLayerError::DecisionWithoutOAuth),
            _ => {}
        }
        if decision == StaticTokenDecision::Unauthenticated {
            return Ok(AuthLayer::allow_unauthenticated());
        }
        self.static_token = decision.into_static_token();
        self.build()
    }

    /// Build the layer.
    ///
    /// # Errors
    ///
    /// [`AuthLayerError::NoCredential`] with neither a non-empty static token
    /// nor an OAuth validator; [`AuthLayerError::NoSources`] with an empty
    /// source list; [`AuthLayerError::InvalidChallenge`] when the validator's
    /// challenge is not a valid header value (only reachable from a
    /// hand-edited resolved config).
    pub fn build(self) -> Result<AuthLayer, AuthLayerError> {
        let static_token = self.static_token.filter(|t| !t.is_empty());
        if static_token.is_none() && self.oauth.is_none() {
            return Err(AuthLayerError::NoCredential);
        }
        let sources = self
            .sources
            .unwrap_or_else(|| vec![CredentialSource::authorization_bearer()]);
        if sources.is_empty() {
            return Err(AuthLayerError::NoSources);
        }
        // Fail closed here too: an OAuth layer whose 401s could not carry
        // `resource_metadata` would leave hosted clients unable to start the
        // authorization flow, which is worse than refusing to start.
        let header = |challenge: String| {
            HeaderValue::from_str(&challenge).map_err(|_| AuthLayerError::InvalidChallenge)
        };
        let oauth_challenges = match &self.oauth {
            Some(v) => Some((
                header(v.invalid_token_challenge())?,
                header(v.insufficient_scope_challenge())?,
            )),
            None => None,
        };
        let static_challenge = self
            .static_challenge
            .unwrap_or_else(|| Some(HeaderValue::from_static(DEFAULT_STATIC_CHALLENGE)));
        Ok(AuthLayer {
            inner: Arc::new(Mode::Enforce(Enforce {
                static_token,
                oauth: self.oauth,
                sources,
                on_reject: self.on_reject,
                oauth_challenges,
                static_challenge,
            })),
        })
    }
}

impl Enforce {
    /// The response for a refusal. The status and (with OAuth) the
    /// `WWW-Authenticate` challenge are fixed here, after `on_reject`, so no
    /// callback can drop or contradict them.
    ///
    /// A request with NO credential gets the same `invalid_token` challenge as a
    /// bad one. RFC 6750 §3.1 says a server SHOULD NOT send an error code then,
    /// but this is the challenge claude.ai and Claude Code start the flow from,
    /// and the part they depend on — `resource_metadata` — is present either
    /// way. The distinction lives in the log level only.
    ///
    /// Without OAuth the challenge is the builder's `static_challenge`
    /// ([`DEFAULT_STATIC_CHALLENGE`] unless set), which RFC 9110 §15.5.2
    /// requires on every 401. An application that opted out with
    /// `static_challenge(None)` gets none (a deliberate deviation, for keeping
    /// an existing API's responses byte-identical) and keeps whatever its
    /// callback set.
    fn reject(&self, rejection: &TokenRejection, request: &Parts) -> Response {
        let status = match rejection {
            TokenRejection::InsufficientScope => StatusCode::FORBIDDEN,
            TokenRejection::Invalid(_) | TokenRejection::Missing => StatusCode::UNAUTHORIZED,
        };
        let challenge = match (&self.oauth_challenges, rejection) {
            (Some((_, insufficient)), TokenRejection::InsufficientScope) => Some(insufficient),
            (Some((invalid, _)), _) => Some(invalid),
            (None, _) => self.static_challenge.as_ref(),
        };
        let mut response = match &self.on_reject {
            Some(f) => f(RejectContext {
                rejection,
                status,
                request,
            }),
            None => {
                let mut response = Response::new(Body::empty());
                *response.status_mut() = status;
                response
            }
        };
        *response.status_mut() = status;
        if let Some(value) = challenge {
            // `insert` replaces every value the callback set.
            response
                .headers_mut()
                .insert(WWW_AUTHENTICATE, value.clone());
        }
        response
    }
}

impl AuthLayer {
    /// Authenticate `request`: the request to pass on (with the credential in
    /// its extensions), or the refusal to answer with. The one implementation
    /// behind both [`require_auth`] and the `tower::Layer` service, so the two
    /// cannot drift apart.
    async fn check(&self, request: Request) -> Result<Request, Response> {
        let enforce = match &*self.inner {
            Mode::AllowUnauthenticated => return Ok(request),
            Mode::Enforce(enforce) => enforce,
        };

        let (mut parts, body) = request.into_parts();
        // The credential must not reach a `Debug` of the request — ours
        // (`RejectContext`), a tracing layer's, or a handler's.
        for (name, value) in parts.headers.iter_mut() {
            if enforce.sources.iter().any(|s| s.header_name() == name) {
                value.set_sensitive(true);
            }
        }
        let result = {
            let headers = &parts.headers;
            let candidates = enforce.sources.iter().filter_map(|s| s.candidate(headers));
            authenticate(
                candidates,
                enforce.static_token.as_deref(),
                enforce.oauth.as_deref(),
            )
            .await
        };

        match result {
            Ok(Credential::StaticToken) => {
                parts.extensions.insert(Credential::StaticToken);
            }
            Ok(Credential::OAuth(token)) => {
                debug!(
                    path = %parts.uri.path(),
                    principal = ?token.principal.as_deref().map(for_log),
                    subject = ?token.subject.as_deref().map(for_log),
                    scopes = ?token.scopes,
                    "OAuth bearer auth accepted"
                );
                parts.extensions.insert(token.clone());
                parts.extensions.insert(Credential::OAuth(token));
            }
            Err(rejection) => {
                let path = parts.uri.path();
                match (&enforce.oauth, &rejection) {
                    (None, _) => warn!(path = %path, "Bearer auth rejected"),
                    // Every OAuth client's first request carries no credential
                    // (401 → read `resource_metadata` → authorize), so it is not
                    // worth a warning.
                    (Some(_), TokenRejection::Missing) => {
                        debug!(path = %path, "No bearer credential presented");
                    }
                    (Some(_), _) => {
                        warn!(path = %path, reason = ?rejection, "OAuth bearer auth rejected");
                    }
                }
                return Err(enforce.reject(&rejection, &parts));
            }
        }
        Ok(Request::from_parts(parts, body))
    }
}

/// The authentication middleware, for [`axum::middleware::from_fn_with_state`]
/// with an [`AuthLayer`] as state. Equivalent to using the [`AuthLayer`] as a
/// `tower::Layer` directly.
///
/// Collects one candidate per configured [`CredentialSource`] and runs
/// [`crate::authenticate()`] over them: any candidate matching the static token
/// or validating as an OAuth token with every required scope is accepted.
///
/// On success it inserts the [`Credential`] into request extensions and, for an
/// OAuth token, the [`AuthorizedToken`](crate::AuthorizedToken) too, so a
/// handler can enforce a finer-grained scope or attribute the request. On
/// refusal it answers 401 (missing or invalid credential) or 403 (valid token,
/// insufficient scope) itself; see [`AuthLayerBuilder::on_reject`] for the
/// response shape. See the [module docs](self) for what it logs.
///
/// # Examples
///
/// ```
/// use axum::{Router, middleware, routing::get};
/// use oauth_resource_server::axum::{AuthLayer, require_auth};
///
/// let auth = AuthLayer::builder().static_token("example-static-key").build().unwrap();
/// let app: Router = Router::new()
///     .route("/api", get(|| async { "protected" }))
///     .route_layer(middleware::from_fn_with_state(auth, require_auth));
/// # let _ = app;
/// ```
pub async fn require_auth(State(auth): State<AuthLayer>, request: Request, next: Next) -> Response {
    match auth.check(request).await {
        Ok(request) => next.run(request).await,
        Err(refusal) => refusal,
    }
}

impl<S> tower_layer::Layer<S> for AuthLayer {
    type Service = AuthService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthService {
            auth: self.clone(),
            inner,
        }
    }
}

/// The service [`AuthLayer`] wraps a route (or router) in, as a
/// `tower::Layer`. Behaves exactly like [`require_auth`].
#[derive(Clone)]
pub struct AuthService<S> {
    auth: AuthLayer,
    inner: S,
}

impl<S: std::fmt::Debug> std::fmt::Debug for AuthService<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthService")
            .field("auth", &self.auth)
            .field("inner", &self.inner)
            .finish()
    }
}

impl<S> tower_service::Service<Request> for AuthService<S>
where
    S: tower_service::Service<Request, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Response, S::Error>> + Send + 'static>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request) -> Self::Future {
        // Call the instance `poll_ready` was driven on and leave a fresh clone in
        // its place (the usual tower pattern for a service moved into a future).
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let auth = self.auth.clone();
        Box::pin(async move {
            match auth.check(request).await {
                Ok(request) => inner.call(request).await,
                Err(refusal) => Ok(refusal),
            }
        })
    }
}

/// The RFC 9728 protected-resource metadata routes, to be merged into the app
/// **outside** the auth layer: this document is how a caller with no credential
/// discovers where to get one, so gating it behind that credential makes the
/// OAuth flow unstartable. It contains nothing secret.
///
/// With a validator, `GET` (and `HEAD`) answer with
/// [`OAuthValidator::metadata`] as JSON on:
///
/// - `/.well-known/oauth-protected-resource`, always, and
/// - [`OAuthValidator::metadata_path`] when the resource URL has a path (RFC
///   9728 §3.1: `https://api.example.com/v1` is described at
///   `/.well-known/oauth-protected-resource/v1`, and
///   `https://api.example.com/v1/` at `.../oauth-protected-resource/v1/`).
///
/// Serving the bare path for a resource that HAS a path is a deliberate
/// compatibility deviation: the document there still says
/// `"resource": "https://api.example.com/v1"`, and under RFC 9728 §3.3 a
/// client that derived the bare URL from `https://api.example.com` must
/// discard a document whose `resource` differs. Some MCP clients fall back to
/// the bare path and accept it anyway, and it costs a compliant client nothing
/// (it uses the `resource_metadata` URL every challenge carries, or the
/// path-suffixed form).
///
/// A served path answers any method other than `GET`/`HEAD` with 405. Every
/// other path under the well-known prefix answers 404 for every method. With
/// no validator, a `GET` on the bare path answers 404 too, as does any request
/// under the prefix, rather than an empty document being served: a client that
/// finds metadata will act on it, and metadata pointing at no authorization
/// server is worse than none. The router claims that prefix, so an app with a
/// fallback route still answers 404 there.
///
/// # Examples
///
/// ```no_run
/// use std::sync::Arc;
///
/// use axum::{Router, routing::get};
/// use oauth_resource_server::OAuthValidator;
/// use oauth_resource_server::axum::{AuthLayer, metadata_router};
///
/// fn app(oauth: Arc<OAuthValidator>) -> Router {
///     let auth = AuthLayer::builder().oauth(Arc::clone(&oauth)).build().unwrap();
///     Router::new()
///         .route("/v1/things", get(|| async { "protected" }))
///         .route_layer(auth)
///         // Merged after `route_layer`, so the auth layer does not cover it.
///         .merge(metadata_router(Some(oauth)))
/// }
/// ```
pub fn metadata_router<S>(oauth: Option<Arc<OAuthValidator>>) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    async fn not_found() -> StatusCode {
        StatusCode::NOT_FOUND
    }
    let catch_all = format!("{PROTECTED_RESOURCE_METADATA_PREFIX}/{{*rest}}");

    let Some(validator) = oauth else {
        // `any`, not `get`: an unserved suffix is 404 for every method.
        return Router::new()
            .route(&catch_all, any(not_found))
            .route(PROTECTED_RESOURCE_METADATA_PREFIX, get(not_found));
    };

    let serve = {
        let validator = Arc::clone(&validator);
        move || {
            let validator = Arc::clone(&validator);
            async move { Json(validator.metadata()).into_response() }
        }
    };
    // The resource's own metadata path comes from config, so it is never
    // registered as a route pattern: axum gives `{…}`, `:…` and `*…` segments
    // route meaning and panics at registration on a `:` or `*` segment, which
    // an absolute http(s) resource URL may legally contain. The catch-all under
    // the prefix compares the request path against it literally instead.
    let path: Arc<str> = validator.metadata_path().into();
    let suffix = move |request: Request| {
        let validator = Arc::clone(&validator);
        let path = Arc::clone(&path);
        async move {
            if request.uri().path() != &*path {
                return StatusCode::NOT_FOUND.into_response();
            }
            match *request.method() {
                Method::GET | Method::HEAD => Json(validator.metadata()).into_response(),
                _ => method_not_allowed(),
            }
        }
    };
    Router::new()
        .route(&catch_all, any(suffix))
        .route(PROTECTED_RESOURCE_METADATA_PREFIX, get(serve))
}

/// The 405 an axum `get` route answers any other method with, reproduced for
/// the metadata path the catch-all serves by hand.
fn method_not_allowed() -> Response {
    (
        StatusCode::METHOD_NOT_ALLOWED,
        [(http::header::ALLOW, HeaderValue::from_static("GET,HEAD"))],
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use ::axum::Extension;
    use ::axum::middleware;
    use tower::ServiceExt;

    use super::*;
    use crate::AuthorizedToken;
    use crate::testing;

    const STATIC: &str = "secret";

    fn validator(jwks_uri: &str) -> Arc<OAuthValidator> {
        Arc::new(OAuthValidator::new(&testing::resolved_config(jwks_uri)).unwrap())
    }

    fn unreachable_validator() -> Arc<OAuthValidator> {
        validator("http://127.0.0.1:1/jwks")
    }

    fn app(auth: AuthLayer) -> Router {
        Router::new()
            .route("/test", get(|| async { "ok" }))
            .route_layer(middleware::from_fn_with_state(auth, require_auth))
    }

    /// mcp-md-wiki's pre-extraction `AuthState` constructor shape, with the one
    /// option it sets to keep its static-only refusals unchanged
    /// (`static_challenge(None)`).
    fn wiki_app(static_token: Option<&str>, oauth: Option<Arc<OAuthValidator>>) -> Router {
        app(AuthLayer::builder()
            .optional_static_token(static_token.map(str::to_string))
            .optional_oauth(oauth)
            .static_challenge(None)
            .build()
            .unwrap())
    }

    async fn send(app: &Router, headers: &[(&str, &str)]) -> Response {
        let mut req = Request::builder().uri("/test");
        for (name, value) in headers {
            req = req.header(*name, *value);
        }
        app.clone()
            .oneshot(req.body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    async fn get_with_auth(app: &Router, header: Option<&str>) -> Response {
        match header {
            Some(h) => send(app, &[("authorization", h)]).await,
            None => send(app, &[]).await,
        }
    }

    fn www_authenticate(resp: &Response) -> String {
        resp.headers()
            .get(WWW_AUTHENTICATE)
            .expect("a refusal with OAuth configured must carry WWW-Authenticate")
            .to_str()
            .unwrap()
            .to_string()
    }

    async fn body_bytes(resp: Response) -> Vec<u8> {
        ::axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap()
            .to_vec()
    }

    fn unscoped_token() -> String {
        testing::mint(
            testing::KEY_A_PEM,
            testing::KID_A,
            &serde_json::json!({
                "iss": testing::ISSUER, "aud": testing::AUDIENCE,
                "exp": testing::now() + 3600, "scope": "openid profile",
            }),
        )
    }

    fn expired_token() -> String {
        testing::mint(
            testing::KEY_A_PEM,
            testing::KID_A,
            &serde_json::json!({
                "iss": testing::ISSUER, "aud": testing::AUDIENCE,
                "exp": testing::now() - 3600, "scope": "mcp:read",
            }),
        )
    }

    // --- Fail-closed construction ---

    #[test]
    fn the_builder_refuses_to_build_a_pass_through() {
        assert_eq!(
            AuthLayer::builder().build().unwrap_err(),
            AuthLayerError::NoCredential
        );
        assert_eq!(
            AuthLayer::builder().static_token("").build().unwrap_err(),
            AuthLayerError::NoCredential
        );
        assert_eq!(
            AuthLayer::builder()
                .optional_static_token(None)
                .optional_oauth(None)
                .build()
                .unwrap_err(),
            AuthLayerError::NoCredential
        );
        assert_eq!(
            AuthLayer::builder()
                .static_token(STATIC)
                .sources([])
                .build()
                .unwrap_err(),
            AuthLayerError::NoSources
        );
        let built = AuthLayer::builder().static_token(STATIC).build().unwrap();
        assert!(!built.allows_unauthenticated());
        assert!(built.oauth().is_none());
    }

    #[tokio::test]
    async fn only_the_explicit_opt_out_passes_requests_through() {
        let layer = AuthLayer::allow_unauthenticated();
        assert!(layer.allows_unauthenticated());
        let app =
            Router::new()
                .route(
                    "/test",
                    get(
                        |c: Option<Extension<Credential>>,
                         t: Option<Extension<AuthorizedToken>>| async move {
                            assert!(c.is_none() && t.is_none(), "a pass-through inserts nothing");
                            "ok"
                        },
                    ),
                )
                .route_layer(middleware::from_fn_with_state(layer, require_auth));
        assert_eq!(get_with_auth(&app, None).await.status(), StatusCode::OK);
        assert_eq!(
            get_with_auth(&app, Some("Bearer anything")).await.status(),
            StatusCode::OK
        );
    }

    #[test]
    fn debug_never_prints_the_static_token() {
        let layer = AuthLayer::builder()
            .static_token("hunter2")
            .build()
            .unwrap();
        let rendered = format!("{layer:?}");
        assert!(!rendered.contains("hunter2"), "{rendered}");
        let builder = AuthLayer::builder().static_token("hunter2");
        let rendered = format!("{builder:?}");
        assert!(!rendered.contains("hunter2"), "{rendered}");
    }

    // --- Ported from mcp-md-wiki's static-token middleware tests ---

    #[tokio::test]
    async fn static_token_only() {
        let app = wiki_app(Some(STATIC), None);
        for (header, status) in [
            (Some("Bearer secret"), StatusCode::OK),
            (Some("Bearer wrong-token"), StatusCode::UNAUTHORIZED),
            (None, StatusCode::UNAUTHORIZED),
            (Some("Basic c2VjcmV0LXRva2Vu"), StatusCode::UNAUTHORIZED),
        ] {
            let resp = get_with_auth(&app, header).await;
            assert_eq!(resp.status(), status, "{header:?}");
            // Static-only with `static_challenge(None)`: no challenge, ever.
            assert!(resp.headers().get(WWW_AUTHENTICATE).is_none(), "{header:?}");
        }
    }

    #[tokio::test]
    async fn a_static_only_401_carries_a_bearer_challenge_by_default() {
        // RFC 9110 §15.5.2: a 401 MUST carry a challenge.
        let app = app(AuthLayer::builder().static_token(STATIC).build().unwrap());
        for header in [None, Some("Bearer wrong-token"), Some("Basic abc")] {
            let resp = get_with_auth(&app, header).await;
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{header:?}");
            assert_eq!(
                resp.headers()[WWW_AUTHENTICATE],
                DEFAULT_STATIC_CHALLENGE,
                "{header:?}"
            );
        }
        assert_eq!(
            get_with_auth(&app, Some("Bearer secret")).await.status(),
            StatusCode::OK
        );
        // `from_decision` uses the same default.
        let app = super::tests::app(
            AuthLayer::from_decision(StaticTokenDecision::StaticOnly(STATIC.into()), None).unwrap(),
        );
        assert_eq!(
            get_with_auth(&app, None).await.headers()[WWW_AUTHENTICATE],
            DEFAULT_STATIC_CHALLENGE
        );
        // An application's own challenge replaces it.
        let custom = HeaderValue::from_static("Bearer realm=\"my-api\"");
        let app = super::tests::app(
            AuthLayer::builder()
                .static_token(STATIC)
                .static_challenge(Some(custom.clone()))
                .build()
                .unwrap(),
        );
        assert_eq!(
            get_with_auth(&app, None).await.headers()[WWW_AUTHENTICATE],
            custom
        );
    }

    #[tokio::test]
    async fn the_static_challenge_is_ignored_when_oauth_is_configured() {
        let v = unreachable_validator();
        let layer = AuthLayer::builder()
            .static_token(STATIC)
            .oauth(Arc::clone(&v))
            .static_challenge(Some(HeaderValue::from_static("Bearer realm=\"x\"")))
            .build()
            .unwrap();
        let resp = get_with_auth(&app(layer), None).await;
        assert_eq!(www_authenticate(&resp), v.invalid_token_challenge());
    }

    #[test]
    fn an_oauth_challenge_that_is_not_a_header_value_fails_the_build() {
        // `resolve` refuses such a resource; a hand-edited resolved config is
        // the only way in, and it must not yield 401s without a challenge.
        let mut cfg = testing::resolved_config("http://127.0.0.1:1/jwks");
        cfg.resource = "https://kb.example.test/m\ncp".into();
        let v = Arc::new(OAuthValidator::new(&cfg).unwrap());
        assert_eq!(
            AuthLayer::builder().oauth(v).build().unwrap_err(),
            AuthLayerError::InvalidChallenge
        );
        let mut cfg = testing::resolved_config("http://127.0.0.1:1/jwks");
        cfg.required_scopes = vec!["a\u{1}b".into()];
        let v = Arc::new(OAuthValidator::new(&cfg).unwrap());
        assert_eq!(
            AuthLayer::builder()
                .static_token(STATIC)
                .oauth(v)
                .build()
                .unwrap_err(),
            AuthLayerError::InvalidChallenge
        );
    }

    #[tokio::test]
    async fn static_bearer_token_still_works_with_oauth_enabled() {
        // The JWKS endpoint is unreachable on purpose: a static-token request
        // must never reach the OAuth validator, let alone depend on the IdP.
        let app = wiki_app(Some(STATIC), Some(unreachable_validator()));
        assert_eq!(
            get_with_auth(&app, Some("Bearer secret")).await.status(),
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn an_oauth_token_is_accepted_alongside_the_static_token() {
        let jwks = testing::spawn_jwks_server("200 OK", testing::jwks_body()).await;
        let app = wiki_app(Some(STATIC), Some(validator(&jwks.url)));
        let header = format!("Bearer {}", testing::valid_token());
        assert_eq!(
            get_with_auth(&app, Some(&header)).await.status(),
            StatusCode::OK
        );
        assert_eq!(
            get_with_auth(&app, Some("Bearer secret")).await.status(),
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn a_missing_credential_gets_401_with_a_well_formed_challenge() {
        let jwks = testing::spawn_jwks_server("200 OK", testing::jwks_body()).await;
        let app = wiki_app(Some(STATIC), Some(validator(&jwks.url)));
        // No header, a wrong STATIC token, and a non-bearer scheme: all carry
        // the challenge — the server cannot tell which credential the caller
        // meant to present.
        for header in [None, Some("Bearer not-the-secret"), Some("Basic abc")] {
            let resp = get_with_auth(&app, header).await;
            assert_eq!(
                resp.status(),
                StatusCode::UNAUTHORIZED,
                "header: {header:?}"
            );
            assert_eq!(
                www_authenticate(&resp),
                "Bearer error=\"invalid_token\", \
                 resource_metadata=\"https://kb.example.test\
                 /.well-known/oauth-protected-resource/mcp\", \
                 scope=\"mcp:read mcp:write\""
            );
        }
    }

    #[tokio::test]
    async fn an_invalid_token_gets_401_and_an_insufficient_scope_token_gets_403() {
        let jwks = testing::spawn_jwks_server("200 OK", testing::jwks_body()).await;
        let app = wiki_app(None, Some(validator(&jwks.url)));

        let resp = get_with_auth(&app, Some(&format!("Bearer {}", expired_token()))).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(www_authenticate(&resp).contains("error=\"invalid_token\""));

        let resp = get_with_auth(&app, Some(&format!("Bearer {}", unscoped_token()))).await;
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "a valid token missing the scope is 403, not 401"
        );
        assert_eq!(
            www_authenticate(&resp),
            "Bearer error=\"insufficient_scope\", scope=\"mcp:read\", \
             resource_metadata=\"https://kb.example.test\
             /.well-known/oauth-protected-resource/mcp\""
        );
    }

    #[tokio::test]
    async fn an_authelia_style_scp_token_is_accepted_through_the_middleware() {
        let jwks = testing::spawn_jwks_server("200 OK", testing::jwks_body()).await;
        let app = wiki_app(None, Some(validator(&jwks.url)));
        let token = testing::mint_with(
            crate::Algorithm::RS256,
            Some(testing::KID_A),
            Some("at+jwt"),
            &serde_json::json!({
                "iss": testing::ISSUER, "aud": [testing::AUDIENCE],
                "exp": testing::now() + 3600, "nbf": testing::now(),
                "sub": "44726d41-0000-4000-8000-000000000000",
                "scp": ["mcp:read", "mcp:write"],
            }),
        );
        let resp = get_with_auth(&app, Some(&format!("Bearer {token}"))).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn the_bearer_scheme_is_case_insensitive_for_both_credentials() {
        let jwks = testing::spawn_jwks_server("200 OK", testing::jwks_body()).await;
        let app = wiki_app(Some(STATIC), Some(validator(&jwks.url)));
        for header in [
            "bearer secret".to_string(),
            "BEARER secret".to_string(),
            "Bearer   secret  ".to_string(),
            format!("bearer {}", testing::valid_token()),
        ] {
            assert_eq!(
                get_with_auth(&app, Some(&header)).await.status(),
                StatusCode::OK,
                "{header:.20}"
            );
        }
        for header in ["Basic secret", "Bearersecret", "secret", "Bearer\tsecret"] {
            assert_eq!(
                get_with_auth(&app, Some(header)).await.status(),
                StatusCode::UNAUTHORIZED,
                "{header}"
            );
        }
    }

    #[test]
    fn bearer_credential_parsing() {
        assert_eq!(bearer_credential("Bearer abc"), "abc");
        assert_eq!(bearer_credential("bEaReR  abc "), "abc");
        assert_eq!(bearer_credential("Bearer "), "");
        assert_eq!(bearer_credential("Bearer"), "");
        assert_eq!(bearer_credential("Basic abc"), "");
        assert_eq!(bearer_credential(""), "");
    }

    // --- Byte-identical default responses ---

    /// mcp-md-wiki's pre-extraction `AuthState`, `challenge`, `auth_rejection`,
    /// `bearer_auth` and `bearer_credential`, verbatim but for the log lines: the
    /// oracle the crate's default behaviour must match byte for byte, run
    /// through the same axum plumbing (which is what adds `content-length`).
    mod wiki {
        use subtle::ConstantTimeEq;

        use super::super::*;

        #[derive(Clone)]
        pub(super) struct AuthState {
            pub(super) bearer_token: Option<String>,
            pub(super) oauth: Option<Arc<OAuthValidator>>,
        }

        impl AuthState {
            fn challenge(&self, rejection: &TokenRejection) -> Option<String> {
                let oauth = self.oauth.as_ref()?;
                Some(match rejection {
                    TokenRejection::InsufficientScope => oauth.insufficient_scope_challenge(),
                    TokenRejection::Invalid(_) | TokenRejection::Missing => {
                        oauth.invalid_token_challenge()
                    }
                })
            }
        }

        fn auth_rejection(auth: &AuthState, rejection: TokenRejection) -> Response {
            let status = match rejection {
                TokenRejection::InsufficientScope => StatusCode::FORBIDDEN,
                TokenRejection::Invalid(_) | TokenRejection::Missing => StatusCode::UNAUTHORIZED,
            };
            let mut response = Response::builder().status(status);
            if let Some(challenge) = auth.challenge(&rejection)
                && let Ok(value) = HeaderValue::from_str(&challenge)
            {
                response = response.header(WWW_AUTHENTICATE, value);
            }
            response
                .body(Body::empty())
                .expect("a status-and-header-only response is always constructible")
        }

        pub(super) async fn bearer_auth(
            State(auth): State<AuthState>,
            headers: HeaderMap,
            request: Request,
            next: Next,
        ) -> Response {
            if auth.bearer_token.is_none() && auth.oauth.is_none() {
                return next.run(request).await;
            }
            let auth_header = headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            let token = bearer_credential(auth_header);
            if let Some(ref expected_token) = auth.bearer_token
                && !token.is_empty()
                && token.as_bytes().ct_eq(expected_token.as_bytes()).into()
            {
                return next.run(request).await;
            }
            let Some(ref oauth) = auth.oauth else {
                return auth_rejection(
                    &auth,
                    TokenRejection::Invalid("static token mismatch".into()),
                );
            };
            match oauth.validate(token).await {
                Ok(claims) => {
                    let mut request = request;
                    request.extensions_mut().insert(claims);
                    next.run(request).await
                }
                Err(TokenRejection::Missing) => auth_rejection(&auth, TokenRejection::Missing),
                Err(rejection) => auth_rejection(&auth, rejection),
            }
        }

        fn bearer_credential(header: &str) -> &str {
            match header.split_once(' ') {
                Some((scheme, token)) if scheme.eq_ignore_ascii_case("bearer") => token.trim(),
                _ => "",
            }
        }
    }

    fn wiki_oracle_app(static_token: Option<&str>, oauth: Option<Arc<OAuthValidator>>) -> Router {
        let auth_state = wiki::AuthState {
            bearer_token: static_token.map(str::to_string),
            oauth,
        };
        Router::new()
            .route("/test", get(|| async { "ok" }))
            .route_layer(middleware::from_fn_with_state(
                auth_state,
                wiki::bearer_auth,
            ))
    }

    async fn assert_same_response(actual: Response, expected: Response, what: &str) {
        assert_eq!(actual.status(), expected.status(), "{what}");
        assert_eq!(actual.version(), expected.version(), "{what}");
        assert_eq!(actual.headers(), expected.headers(), "{what}");
        assert_eq!(
            body_bytes(actual).await,
            body_bytes(expected).await,
            "{what}"
        );
    }

    #[tokio::test]
    async fn default_responses_are_byte_identical_to_the_wiki_middleware() {
        let jwks = testing::spawn_jwks_server("200 OK", testing::jwks_body()).await;
        let v = validator(&jwks.url);
        let valid = format!("Bearer {}", testing::valid_token());
        let lower = format!("bearer {}", testing::valid_token());
        let expired = format!("Bearer {}", expired_token());
        let unscoped = format!("Bearer {}", unscoped_token());
        let headers: Vec<Option<&str>> = vec![
            None,
            Some(""),
            Some("Bearer"),
            Some("Bearer "),
            Some("Bearer secret"),
            Some("bearer secret"),
            Some("Bearer  secret "),
            Some("Bearer wrong"),
            Some("Bearersecret"),
            Some("Bearer\tsecret"),
            Some("Basic c2VjcmV0"),
            Some("secret"),
            Some(&valid),
            Some(&lower),
            Some(&expired),
            Some(&unscoped),
        ];

        // Static-only (no challenge on any refusal), dual mode, OAuth-only.
        for (static_token, oauth) in [
            (Some(STATIC), None),
            (Some(STATIC), Some(Arc::clone(&v))),
            (None, Some(Arc::clone(&v))),
        ] {
            let ours = wiki_app(static_token, oauth.clone());
            let theirs = wiki_oracle_app(static_token, oauth.clone());
            for header in &headers {
                assert_same_response(
                    get_with_auth(&ours, *header).await,
                    get_with_auth(&theirs, *header).await,
                    &format!(
                        "static={static_token:?} oauth={} header={header:.30?}",
                        oauth.is_some()
                    ),
                )
                .await;
            }
        }
    }

    // --- on_reject ---

    #[tokio::test]
    async fn on_reject_shapes_the_body_but_not_the_status_or_challenge() {
        let jwks = testing::spawn_jwks_server("200 OK", testing::jwks_body()).await;
        let v = validator(&jwks.url);
        let layer = AuthLayer::builder()
            .static_token(STATIC)
            .oauth(Arc::clone(&v))
            .on_reject(|cx: RejectContext<'_>| {
                assert_eq!(cx.request.uri.path(), "/test");
                let status = cx.status;
                let body = match cx.rejection {
                    TokenRejection::InsufficientScope => r#"{"error":"insufficient_scope"}"#,
                    _ => r#"{"error":"unauthorized"}"#,
                };
                Response::builder()
                    // A callback that gets the status wrong, and tries to
                    // replace the challenge, is corrected on both counts.
                    .status(StatusCode::OK)
                    .header("content-type", "application/json")
                    .header("x-seen-status", status.as_str())
                    .header(WWW_AUTHENTICATE, "Basic realm=\"nope\"")
                    .header(WWW_AUTHENTICATE, "Bearer realm=\"also-nope\"")
                    .body(Body::from(body))
                    .unwrap()
            })
            .build()
            .unwrap();
        let app = app(layer);

        let resp = get_with_auth(&app, None).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(resp.headers()["x-seen-status"], "401");
        assert_eq!(resp.headers()["content-type"], "application/json");
        assert_eq!(
            resp.headers().get_all(WWW_AUTHENTICATE).iter().count(),
            1,
            "the callback's challenges are replaced, not added to"
        );
        assert_eq!(www_authenticate(&resp), v.invalid_token_challenge());
        assert_eq!(body_bytes(resp).await, br#"{"error":"unauthorized"}"#);

        let resp = get_with_auth(&app, Some(&format!("Bearer {}", unscoped_token()))).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(resp.headers()["x-seen-status"], "403");
        assert_eq!(www_authenticate(&resp), v.insufficient_scope_challenge());
        assert_eq!(body_bytes(resp).await, br#"{"error":"insufficient_scope"}"#);
    }

    #[tokio::test]
    async fn on_reject_without_oauth_or_a_static_challenge_keeps_its_own_headers() {
        let builder = || {
            AuthLayer::builder()
                .static_token(STATIC)
                .on_reject(|cx: RejectContext<'_>| {
                    Response::builder()
                        .status(cx.status)
                        .header(WWW_AUTHENTICATE, "ApiKey")
                        .body(Body::from("nope"))
                        .unwrap()
                })
        };
        let layer = builder().static_challenge(None).build().unwrap();
        let resp = get_with_auth(&app(layer), Some("Bearer wrong")).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(resp.headers()[WWW_AUTHENTICATE], "ApiKey");
        assert_eq!(body_bytes(resp).await, b"nope");

        // With the default static challenge, the layer's challenge wins, as
        // it does with OAuth.
        let resp = get_with_auth(&app(builder().build().unwrap()), Some("Bearer wrong")).await;
        assert_eq!(resp.headers().get_all(WWW_AUTHENTICATE).iter().count(), 1);
        assert_eq!(resp.headers()[WWW_AUTHENTICATE], DEFAULT_STATIC_CHALLENGE);
        assert_eq!(body_bytes(resp).await, b"nope");
    }

    #[tokio::test]
    async fn the_presented_credential_never_reaches_a_debug_rendering() {
        let jwks = testing::spawn_jwks_server("200 OK", testing::jwks_body()).await;
        let v = validator(&jwks.url);
        let token = unscoped_token(); // valid and signed: a 403, not a 401
        let seen: Arc<std::sync::Mutex<Vec<String>>> = Arc::default();
        let log = Arc::clone(&seen);
        let layer = AuthLayer::builder()
            .oauth(v)
            .sources([
                CredentialSource::authorization_bearer(),
                CredentialSource::Raw(HeaderName::from_static("x-api-key")),
            ])
            .on_reject(move |cx: RejectContext<'_>| {
                log.lock().unwrap().push(format!("{cx:?}"));
                log.lock().unwrap().push(format!("{:?}", cx.request));
                Response::new(Body::empty())
            })
            .build()
            .unwrap();
        let bearer = format!("Bearer {token}");
        let resp = send(
            &app(layer),
            &[
                ("authorization", bearer.as_str()),
                ("x-api-key", "raw-api-key-value"),
                ("accept", "application/json"),
            ],
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 2);
        for rendered in seen.iter() {
            assert!(!rendered.contains(&token), "{rendered}");
            assert!(!rendered.contains("raw-api-key-value"), "{rendered}");
        }
        // The context still says what happened.
        assert!(seen[0].contains("InsufficientScope"), "{}", seen[0]);
        assert!(seen[0].contains("403"), "{}", seen[0]);
        assert!(seen[0].contains("authorization"), "{}", seen[0]);
        assert!(!seen[0].contains("application/json"), "{}", seen[0]);
    }

    #[tokio::test]
    async fn the_inner_service_sees_the_credential_headers_marked_sensitive() {
        let layer = AuthLayer::builder().static_token(STATIC).build().unwrap();
        let app = Router::new()
            .route(
                "/test",
                get(|headers: HeaderMap| async move {
                    assert!(headers["authorization"].is_sensitive());
                    assert!(!format!("{headers:?}").contains(STATIC));
                    assert!(!headers["accept"].is_sensitive());
                    "ok"
                }),
            )
            .route_layer(layer);
        let resp = send(
            &app,
            &[("authorization", "Bearer secret"), ("accept", "text/plain")],
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // --- Multiple sources: a second credential header beside Authorization ---

    fn multi_source_app(v: Arc<OAuthValidator>) -> Router {
        app(AuthLayer::builder()
            .static_token(STATIC)
            .oauth(v)
            .sources([
                CredentialSource::authorization_bearer(),
                CredentialSource::Raw(HeaderName::from_static("x-api-key")),
            ])
            .build()
            .unwrap())
    }

    #[tokio::test]
    async fn a_bad_authorization_header_does_not_mask_a_good_raw_header() {
        let jwks = testing::spawn_jwks_server("200 OK", testing::jwks_body()).await;
        let app = multi_source_app(validator(&jwks.url));
        let foreign = format!("Bearer {}", expired_token());
        for authorization in [foreign.as_str(), "Bearer garbage", "Basic abc"] {
            let resp = send(
                &app,
                &[("authorization", authorization), ("x-api-key", STATIC)],
            )
            .await;
            assert_eq!(resp.status(), StatusCode::OK, "{authorization:.30}");
        }
    }

    #[tokio::test]
    async fn a_bad_raw_header_does_not_mask_a_good_authorization_header() {
        let jwks = testing::spawn_jwks_server("200 OK", testing::jwks_body()).await;
        let app = multi_source_app(validator(&jwks.url));
        let valid = format!("Bearer {}", testing::valid_token());
        for authorization in ["Bearer secret", valid.as_str()] {
            let resp = send(
                &app,
                &[("authorization", authorization), ("x-api-key", "garbage")],
            )
            .await;
            assert_eq!(resp.status(), StatusCode::OK, "{authorization:.30}");
        }
        // An OAuth token in the raw header works too.
        let resp = send(&app, &[("x-api-key", &testing::valid_token())]).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn multi_source_refusals() {
        let jwks = testing::spawn_jwks_server("200 OK", testing::jwks_body()).await;
        let v = validator(&jwks.url);
        let app = multi_source_app(Arc::clone(&v));

        let resp = send(
            &app,
            &[
                ("authorization", "Bearer garbage"),
                ("x-api-key", "also-garbage"),
            ],
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(www_authenticate(&resp), v.invalid_token_challenge());

        // A scope-lacking valid token in either place outranks garbage elsewhere.
        let unscoped = unscoped_token();
        let resp = send(
            &app,
            &[
                ("authorization", "Bearer garbage"),
                ("x-api-key", &unscoped),
            ],
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(www_authenticate(&resp), v.insufficient_scope_challenge());

        // The raw header is taken verbatim: a `Bearer ` prefix there is part of
        // the value, not a scheme.
        let resp = send(&app, &[("x-api-key", "Bearer secret")]).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let resp = send(&app, &[]).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn a_raw_only_layer_ignores_the_authorization_header() {
        let layer = AuthLayer::builder()
            .static_token(STATIC)
            .sources([CredentialSource::Raw(HeaderName::from_static("x-api-key"))])
            .build()
            .unwrap();
        let app = app(layer);
        assert_eq!(
            send(&app, &[("authorization", "Bearer secret")])
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            send(&app, &[("x-api-key", STATIC)]).await.status(),
            StatusCode::OK
        );
    }

    // --- Extensions ---

    #[tokio::test]
    async fn the_credential_and_oauth_token_are_inserted_into_extensions() {
        let jwks = testing::spawn_jwks_server("200 OK", testing::jwks_body()).await;
        let layer = AuthLayer::builder()
            .static_token(STATIC)
            .oauth(validator(&jwks.url))
            .build()
            .unwrap();
        let app = Router::new()
            .route(
                "/test",
                get(
                    |Extension(credential): Extension<Credential>,
                     token: Option<Extension<AuthorizedToken>>| async move {
                        match (credential, token) {
                            (Credential::StaticToken, None) => "static".to_string(),
                            (Credential::OAuth(c), Some(Extension(t))) => {
                                assert_eq!(c, t);
                                format!(
                                    "oauth {} {}",
                                    t.subject.as_deref().unwrap_or_default(),
                                    t.has_scope("mcp:write")
                                )
                            }
                            other => panic!("inconsistent extensions: {other:?}"),
                        }
                    },
                ),
            )
            .route_layer(middleware::from_fn_with_state(layer, require_auth));

        let resp = get_with_auth(&app, Some("Bearer secret")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_bytes(resp).await, b"static");

        let header = format!("Bearer {}", testing::valid_token());
        let resp = get_with_auth(&app, Some(&header)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_bytes(resp).await, b"oauth user-1 true");
    }

    // --- tower::Layer ---

    /// `.route_layer(auth)` / `.layer(auth)` and `from_fn_with_state(auth,
    /// require_auth)` are one implementation: same statuses, challenges, bodies
    /// and extensions.
    #[tokio::test]
    async fn the_layer_behaves_exactly_like_the_middleware_function() {
        let jwks = testing::spawn_jwks_server("200 OK", testing::jwks_body()).await;
        let layer = AuthLayer::builder()
            .static_token(STATIC)
            .oauth(validator(&jwks.url))
            .on_reject(|cx: RejectContext<'_>| Response::new(Body::from(cx.status.to_string())))
            .build()
            .unwrap();
        let handler = get(|c: Option<Extension<Credential>>| async move {
            match c {
                Some(Extension(Credential::StaticToken)) => "static",
                Some(Extension(Credential::OAuth(_))) => "oauth",
                None => "none",
            }
        });
        let via_fn = Router::new()
            .route("/test", handler.clone())
            .route_layer(middleware::from_fn_with_state(layer.clone(), require_auth));
        let via_route_layer = Router::new()
            .route("/test", handler.clone())
            .route_layer(layer.clone());
        let via_layer = Router::new().route("/test", handler).layer(layer);

        let valid = format!("Bearer {}", testing::valid_token());
        let unscoped = format!("Bearer {}", unscoped_token());
        for header in [
            None,
            Some("Bearer secret"),
            Some("Bearer wrong"),
            Some(valid.as_str()),
            Some(unscoped.as_str()),
        ] {
            let expected = get_with_auth(&via_fn, header).await;
            let (status, challenge) = (
                expected.status(),
                expected.headers().get(WWW_AUTHENTICATE).cloned(),
            );
            let expected_body = body_bytes(expected).await;
            for app in [&via_route_layer, &via_layer] {
                let resp = get_with_auth(app, header).await;
                assert_eq!(resp.status(), status, "{header:?}");
                assert_eq!(
                    resp.headers().get(WWW_AUTHENTICATE),
                    challenge.as_ref(),
                    "{header:?}"
                );
                assert_eq!(body_bytes(resp).await, expected_body, "{header:?}");
            }
        }
    }

    // --- from_decision ---

    #[tokio::test]
    async fn from_decision_maps_every_decision_and_refuses_a_mismatch() {
        use StaticTokenDecision::*;

        let jwks = testing::spawn_jwks_server("200 OK", testing::jwks_body()).await;
        let v = validator(&jwks.url);
        let valid = format!("Bearer {}", testing::valid_token());
        let status = |layer: AuthLayer, header: &'static str| async move {
            get_with_auth(&app(layer), Some(header)).await.status()
        };
        let valid: &'static str = Box::leak(valid.into_boxed_str());

        // The explicit opt-out.
        let open = AuthLayer::from_decision(Unauthenticated, None).unwrap();
        assert!(open.allows_unauthenticated());

        // Static only.
        let layer = AuthLayer::from_decision(StaticOnly(STATIC.into()), None).unwrap();
        assert!(!layer.allows_unauthenticated());
        assert_eq!(status(layer.clone(), "Bearer secret").await, StatusCode::OK);
        assert_eq!(status(layer, valid).await, StatusCode::UNAUTHORIZED);

        // Dual mode.
        let layer =
            AuthLayer::from_decision(StaticAndOAuth(STATIC.into()), Some(Arc::clone(&v))).unwrap();
        assert_eq!(status(layer.clone(), "Bearer secret").await, StatusCode::OK);
        assert_eq!(status(layer, valid).await, StatusCode::OK);

        // OAuth only, and a static token dropped by `accept_static_bearer: false`.
        for decision in [OAuthOnly, StaticIgnored] {
            let layer = AuthLayer::from_decision(decision, Some(Arc::clone(&v))).unwrap();
            assert_eq!(
                status(layer.clone(), "Bearer secret").await,
                StatusCode::UNAUTHORIZED
            );
            assert_eq!(status(layer, valid).await, StatusCode::OK);
        }

        // The decision and the validator must agree.
        for decision in [StaticAndOAuth(STATIC.into()), OAuthOnly, StaticIgnored] {
            assert_eq!(
                AuthLayer::from_decision(decision, None).unwrap_err(),
                AuthLayerError::DecisionNeedsOAuth
            );
        }
        for decision in [StaticOnly(STATIC.into()), Unauthenticated] {
            assert_eq!(
                AuthLayer::from_decision(decision, Some(Arc::clone(&v))).unwrap_err(),
                AuthLayerError::DecisionWithoutOAuth
            );
        }
    }

    #[tokio::test]
    async fn build_with_decision_keeps_the_builders_sources_and_replaces_its_token() {
        let layer = AuthLayer::builder()
            .static_token("builder-token")
            .sources([CredentialSource::Raw(HeaderName::from_static("x-api-key"))])
            .build_with_decision(StaticTokenDecision::StaticOnly(STATIC.into()))
            .unwrap();
        let app = app(layer);
        assert_eq!(
            send(&app, &[("x-api-key", STATIC)]).await.status(),
            StatusCode::OK
        );
        assert_eq!(
            send(&app, &[("x-api-key", "builder-token")]).await.status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            send(&app, &[("authorization", "Bearer secret")])
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }

    // --- Metadata routes ---

    async fn get_path(app: &Router, path: &str) -> Response {
        app.clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    const MCP_METADATA_PATH: &str = "/.well-known/oauth-protected-resource/mcp";

    #[tokio::test]
    async fn metadata_routes_for_a_resource_with_a_path() {
        let v = unreachable_validator();
        assert_eq!(v.metadata_path(), MCP_METADATA_PATH);
        let app: Router = metadata_router(Some(Arc::clone(&v)));
        for path in [MCP_METADATA_PATH, PROTECTED_RESOURCE_METADATA_PREFIX] {
            let resp = get_path(&app, path).await;
            assert_eq!(resp.status(), StatusCode::OK, "{path}");
            assert_eq!(resp.headers()["content-type"], "application/json", "{path}");
            let body = body_bytes(resp).await;
            // Byte-identical to what `Json(v.metadata())` serialized before.
            assert_eq!(body, serde_json::to_vec(&v.metadata()).unwrap(), "{path}");
            let doc: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(doc["resource"], testing::RESOURCE);
            assert_eq!(doc["authorization_servers"][0], testing::ISSUER);
            assert_eq!(
                doc["scopes_supported"],
                serde_json::json!(["mcp:read", "mcp:write"])
            );
            assert_eq!(
                doc["bearer_methods_supported"],
                serde_json::json!(["header"])
            );
        }
        for path in [
            "/.well-known/oauth-protected-resource/other",
            "/.well-known/oauth-protected-resource/mcp/deeper",
        ] {
            assert_eq!(
                get_path(&app, path).await.status(),
                StatusCode::NOT_FOUND,
                "{path}"
            );
        }
    }

    async fn post_path(app: &Router, path: &str) -> Response {
        app.clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(path)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn metadata_routes_answer_other_methods_by_whether_the_path_is_served() {
        // A served path is GET-only (405 for anything else); an unserved suffix
        // is 404 for every method, as it would be with no route at all.
        let app: Router = metadata_router(Some(unreachable_validator()));
        for path in [MCP_METADATA_PATH, PROTECTED_RESOURCE_METADATA_PREFIX] {
            assert_eq!(
                post_path(&app, path).await.status(),
                StatusCode::METHOD_NOT_ALLOWED,
                "{path}"
            );
        }
        for path in [
            "/.well-known/oauth-protected-resource/other",
            "/.well-known/oauth-protected-resource/mcp/deeper",
        ] {
            let resp = post_path(&app, path).await;
            assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{path}");
            assert!(!resp.headers().contains_key("allow"), "{path}");
        }
        let app: Router = metadata_router(None);
        assert_eq!(
            post_path(&app, MCP_METADATA_PATH).await.status(),
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn metadata_routes_for_a_root_resource() {
        let mut cfg = testing::resolved_config("http://127.0.0.1:1/jwks");
        cfg.resource = "https://api.example.test/".to_string();
        let v = Arc::new(OAuthValidator::new(&cfg).unwrap());
        assert_eq!(v.metadata_path(), PROTECTED_RESOURCE_METADATA_PREFIX);
        let app: Router = metadata_router(Some(v));
        let resp = get_path(&app, PROTECTED_RESOURCE_METADATA_PREFIX).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let doc: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
        assert_eq!(doc["resource"], "https://api.example.test/");
        assert_eq!(
            get_path(&app, MCP_METADATA_PATH).await.status(),
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn metadata_routes_with_a_nested_and_a_brace_bearing_path() {
        for (resource, path) in [
            (
                "https://api.example.test/v1/things",
                "/.well-known/oauth-protected-resource/v1/things",
            ),
            // RFC 9728 §3.1: a path's own trailing slash is kept.
            (
                "https://api.example.test/v1/",
                "/.well-known/oauth-protected-resource/v1/",
            ),
            (
                "https://api.example.test/a{b}",
                "/.well-known/oauth-protected-resource/a{b}",
            ),
        ] {
            let mut cfg = testing::resolved_config("http://127.0.0.1:1/jwks");
            cfg.resource = resource.to_string();
            let v = Arc::new(OAuthValidator::new(&cfg).unwrap());
            assert_eq!(v.metadata_path(), path);
            let app: Router = metadata_router(Some(v));
            let resp = get_path(&app, path).await;
            assert_eq!(resp.status(), StatusCode::OK, "{resource}");
        }
    }

    /// A resource path whose segments axum would read as route syntax — `:x`
    /// and `*x` panic at registration if used as a route pattern — is accepted
    /// by `resolve`, so the router must serve it without ever registering it.
    #[tokio::test]
    async fn metadata_routes_for_a_path_axum_would_read_as_route_syntax() {
        for (resource, path) in [
            (
                "https://api.example.test/a/:id",
                "/.well-known/oauth-protected-resource/a/:id",
            ),
            (
                "https://api.example.test/a/*x",
                "/.well-known/oauth-protected-resource/a/*x",
            ),
            (
                "https://api.example.test/:id",
                "/.well-known/oauth-protected-resource/:id",
            ),
            (
                "https://api.example.test/*",
                "/.well-known/oauth-protected-resource/*",
            ),
            (
                "https://api.example.test/{x}",
                "/.well-known/oauth-protected-resource/{x}",
            ),
            (
                "https://api.example.test/%7Bx%7D",
                "/.well-known/oauth-protected-resource/%7Bx%7D",
            ),
            (
                "https://api.example.test//mcp",
                "/.well-known/oauth-protected-resource//mcp",
            ),
        ] {
            let resolved = crate::OAuthConfig {
                enabled: true,
                issuer: testing::ISSUER.to_string(),
                jwks_uri: Some("http://127.0.0.1:1/jwks".to_string()),
                audience: testing::AUDIENCE.to_string(),
                resource: resource.to_string(),
                required_scope: Some("mcp:read".to_string()),
                ..crate::OAuthConfig::default()
            }
            .resolve(crate::KeyNaming::Dotted("oauth"))
            .unwrap_or_else(|e| panic!("{resource}: {e}"))
            .expect("enabled");
            let v = Arc::new(OAuthValidator::new(&resolved).unwrap());
            assert_eq!(v.metadata_path(), path, "{resource}");
            let app: Router = metadata_router(Some(Arc::clone(&v)));
            for served in [path, PROTECTED_RESOURCE_METADATA_PREFIX] {
                let resp = get_path(&app, served).await;
                assert_eq!(resp.status(), StatusCode::OK, "{resource} {served}");
                assert_eq!(
                    body_bytes(resp).await,
                    serde_json::to_vec(&v.metadata()).unwrap(),
                    "{resource} {served}"
                );
            }
            // Route syntax in the configured path matches only itself.
            for other in [
                "/.well-known/oauth-protected-resource/a/other",
                "/.well-known/oauth-protected-resource/a/:id/x",
                "/.well-known/oauth-protected-resource/other",
                "/.well-known/oauth-protected-resource/mcp",
            ] {
                assert_eq!(
                    get_path(&app, other).await.status(),
                    StatusCode::NOT_FOUND,
                    "{resource} {other}"
                );
            }
        }
    }

    /// The catch-all serves the resource's path by hand, so it must answer
    /// exactly as the axum `get` route serving the bare prefix does: same 405
    /// and `Allow` for another method, same headers and an empty body for HEAD.
    #[tokio::test]
    async fn metadata_path_answers_methods_exactly_like_the_bare_prefix_route() {
        let app: Router = metadata_router(Some(unreachable_validator()));
        let send = |method: &'static str, path: &'static str| {
            app.clone().oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .body(Body::empty())
                    .unwrap(),
            )
        };
        for method in ["GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"] {
            let bare = send(method, PROTECTED_RESOURCE_METADATA_PREFIX)
                .await
                .unwrap();
            let suffixed = send(method, MCP_METADATA_PATH).await.unwrap();
            assert_eq!(bare.status(), suffixed.status(), "{method}");
            assert_eq!(bare.headers(), suffixed.headers(), "{method}");
            let (bare, suffixed) = (body_bytes(bare).await, body_bytes(suffixed).await);
            assert_eq!(bare, suffixed, "{method}");
            if method == "HEAD" {
                assert!(suffixed.is_empty());
            }
        }
    }

    #[tokio::test]
    async fn metadata_routes_404_when_oauth_is_not_configured() {
        // A catch-all fallback in the app must not answer for them either.
        let app: Router = metadata_router(None).fallback(|| async { "spa shell" });
        for path in [MCP_METADATA_PATH, PROTECTED_RESOURCE_METADATA_PREFIX] {
            let resp = get_path(&app, path).await;
            assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{path}");
            assert!(body_bytes(resp).await.is_empty(), "{path}");
        }
    }

    #[tokio::test]
    async fn metadata_routes_are_reachable_outside_the_auth_layer() {
        let v = unreachable_validator();
        let layer = AuthLayer::builder().oauth(Arc::clone(&v)).build().unwrap();
        let app = Router::new()
            .route("/mcp", get(|| async { "ok" }))
            .route_layer(middleware::from_fn_with_state(layer, require_auth))
            .merge(metadata_router(Some(v)));
        assert_eq!(
            get_path(&app, "/mcp").await.status(),
            StatusCode::UNAUTHORIZED
        );
        for path in [MCP_METADATA_PATH, PROTECTED_RESOURCE_METADATA_PREFIX] {
            assert_eq!(
                get_path(&app, path).await.status(),
                StatusCode::OK,
                "{path}"
            );
        }
    }

    #[tokio::test]
    async fn metadata_router_works_with_app_state() {
        #[derive(Clone)]
        struct AppState;
        let app: Router = Router::new()
            .route("/x", get(|State(_): State<AppState>| async { "x" }))
            .merge(metadata_router(Some(unreachable_validator())))
            .with_state(AppState);
        assert_eq!(
            get_path(&app, MCP_METADATA_PATH).await.status(),
            StatusCode::OK
        );
    }
}
