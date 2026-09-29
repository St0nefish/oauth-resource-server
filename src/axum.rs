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
//! [`AuthLayerBuilder::static_challenge`]). The status and the challenge are
//! the ones [`crate::refusal()`] gives — the same decision, made by the same
//! code — so an integration outside axum built on it, and the `tower`
//! feature's [`HttpAuthLayer`](crate::http_layer::HttpAuthLayer), refuse exactly
//! as this layer does. There is no 400 `invalid_request`
//! (RFC 6750 §3.1's SHOULD for a malformed request): a request is authenticated
//! or it is not, and anything unreadable is simply no credential.
//!
//! # Extractors
//!
//! [`AuthorizedToken`] and [`Credential`] are axum extractors (`FromRequestParts`),
//! and so are `Option<AuthorizedToken>` and `Option<Credential>`
//! (`OptionalFromRequestParts`). They read what the layer inserted, and refuse
//! fail-closed when it is not there:
//!
//! | The request… | `T` | `Option<T>` |
//! |---|---|---|
//! | carries the value (the layer accepted it) | the value | `Some(value)` |
//! | passed an [`optional`](AuthLayerBuilder::optional) layer with no credential, or an [`allow_unauthenticated`](AuthLayer::allow_unauthenticated) layer | the layer's own 401 and challenge | `None` |
//! | was accepted with the static token (`T` = [`AuthorizedToken`] only, and no outer layer inserted one — see [nested layers](self#nested-layers)) | the layer's own 401 and challenge | `None` |
//! | never went through an [`AuthLayer`] (a route mounted outside it) | 500, logged at `error` | 500, logged at `error` |
//!
//! "The layer's own 401" is built by the same code that builds the layer's
//! refusals ([`AuthLayerBuilder::on_reject`] included), so its status and
//! `WWW-Authenticate` challenge are exactly the ones the layer would have sent
//! for a request with no credential. An [`allow_unauthenticated`](AuthLayer::allow_unauthenticated)
//! layer has no challenge of its own and answers with
//! [`DEFAULT_STATIC_CHALLENGE`].
//!
//! A route outside every layer is a wiring mistake in the server, not something
//! the caller can fix by authenticating, so it gets 500 (empty body) rather than
//! a 401 that would send an OAuth client into an authorization flow that can
//! never succeed there. It never grants access, and it never reads as "anonymous":
//! `Option<T>` fails the same way.
//!
//! ```
//! use axum::{Router, routing::get};
//! use oauth_resource_server::axum::AuthLayer;
//! use oauth_resource_server::{AuthorizedToken, Credential};
//!
//! async fn whoami(credential: Credential) -> String {
//!     match credential {
//!         Credential::OAuth(token) => format!("subject {:?}", token.subject),
//!         Credential::StaticToken => "the static API key".to_string(),
//!         // `Credential` is `#[non_exhaustive]`.
//!         _ => "some other credential".to_string(),
//!     }
//! }
//!
//! // Needs an OAuth token: a static-token request is refused with the
//! // layer's 401.
//! async fn subject(token: AuthorizedToken) -> String {
//!     token.subject.unwrap_or_default()
//! }
//!
//! let auth = AuthLayer::builder().static_token("example-static-key").build().unwrap();
//! let app: Router = Router::new()
//!     .route("/whoami", get(whoami))
//!     .route("/subject", get(subject))
//!     .route_layer(auth);
//! # let _ = app;
//! ```
//!
//! # Optional authentication
//!
//! [`AuthLayerBuilder::optional`] builds a layer for routes that serve everyone
//! but personalize for (or unlock more to) an authenticated caller: a valid
//! credential is inserted as usual, a request that presents NO credential
//! passes through with nothing inserted, and a credential that is presented
//! but refused — invalid, expired, or valid without the required scopes — is
//! refused exactly as by a non-optional layer. See that method for what counts
//! as "no credential". A `DPoP`-scheme `Authorization` value (a
//! sender-constrained token this crate cannot accept) and a `Bearer` value
//! separated from its token by a tab are counted as presented, and refused
//! exactly as a non-optional layer refuses them, never passed through.
//!
//! # Nested layers
//!
//! An optional layer first removes any [`Credential`] and [`AuthorizedToken`]
//! an outer layer inserted, so what its handlers extract is only ever what IT
//! accepted: `None` after its pass-through, even when an outer layer accepted
//! a token.
//!
//! Strict (non-optional) layers never remove anything; the extensions
//! accumulate, as they always have. [`Credential`] reflects the innermost
//! layer that accepted the request, while an [`AuthorizedToken`] may have been
//! inserted by an OUTER layer: behind an outer OAuth layer, an inner
//! static-only layer that accepts its static token leaves the outer layer's
//! [`AuthorizedToken`] in place, and an `AuthorizedToken` extractor returns it.
//! When that matters, read [`Credential`] (the innermost decision) instead.
//!
//! # Logging
//!
//! The layer logs every outcome itself, so applications need not (target
//! `oauth_resource_server::axum`): an accepted OAuth token at `debug` (principal,
//! subject, scopes — never the token); a request with no credential at `debug`
//! when OAuth is configured, since every OAuth client's first request looks like
//! that; a request with no credential passed through by an
//! [`optional`](AuthLayerBuilder::optional) layer at `debug`; any other refusal
//! at `warn`, with the reason when OAuth is configured. The reason goes to the
//! log only, never to the caller. The extractors log their refusals the same
//! way. Three wiring mistakes are logged at `error`: an extractor on a route no
//! [`AuthLayer`] covers (500), a required extractor behind an
//! [`allow_unauthenticated`](AuthLayer::allow_unauthenticated) layer, and an
//! [`AuthorizedToken`] extractor behind a layer with no OAuth validator (both
//! a 401 no credential can ever satisfy).

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use ::axum::Json;
use ::axum::Router;
use ::axum::body::Body;
use ::axum::extract::{FromRequestParts, OptionalFromRequestParts, Request, State};
use ::axum::middleware::Next;
use ::axum::response::{IntoResponse, Response};
use ::axum::routing::{any, get};
use http::header::WWW_AUTHENTICATE;
use http::request::Parts;
use http::{HeaderValue, Method, StatusCode};
use tracing::{debug, error, warn};

use crate::authenticate::Credential;
use crate::challenge::PROTECTED_RESOURCE_METADATA_PREFIX;
use crate::policy::StaticTokenDecision;
use crate::token::{AuthorizedToken, InvalidTokenKind, TokenRejection, for_log};
use crate::validator::OAuthValidator;

use crate::http_layer::{Admission, Gate};
#[doc(inline)]
pub use crate::http_layer::{AuthLayerError, CredentialSource, RejectContext};
pub use crate::refusal::DEFAULT_STATIC_CHALLENGE;
// What the test module (`use super::*`) used from here before these moved to
// `crate::http_layer`.
#[cfg(test)]
use crate::http_layer::{bearer_credential, names_a_token};
#[cfg(test)]
use http::{HeaderMap, HeaderName};

/// Builds a refusal's body and extra headers; see [`AuthLayerBuilder::on_reject`].
pub type RejectFn = Arc<dyn Fn(RejectContext<'_>) -> Response + Send + Sync>;

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

/// An enforcing layer: the credential check shared with the `tower`
/// feature's `HttpAuthLayer` (`Gate`, which also holds the static token, the
/// validator, the sources, the pre-rendered challenges and
/// [`AuthLayerBuilder::optional`]), plus this layer's axum-typed `on_reject`.
struct Enforce {
    gate: Gate,
    on_reject: Option<RejectFn>,
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
                    &e.gate.static_token.as_ref().map(|_| "<redacted>"),
                )
                .field("oauth", &e.gate.oauth)
                .field("sources", &e.gate.sources)
                .field("on_reject", &e.on_reject.as_ref().map(|_| "<fn>"))
                .field("static_challenge", &e.gate.static_challenge)
                .field("optional", &e.gate.optional)
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

    /// A layer that lets EVERY request through, unauthenticated, and inserts no
    /// credential into request extensions (so `Option<Credential>` and
    /// `Option<AuthorizedToken>` extract `None`, and the non-`Option`
    /// extractors refuse with a 401 carrying [`DEFAULT_STATIC_CHALLENGE`]; see
    /// the [module docs](self#extractors)).
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
            Mode::Enforce(e) => e.gate.oauth.as_ref(),
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
    optional: bool,
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
            .field("optional", &self.optional)
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

    /// Let a request that presents NO credential through, unauthenticated, with
    /// nothing inserted into its extensions; everything else is decided exactly
    /// as without this. For routes that serve everyone but personalize for an
    /// authenticated caller, or read-open/write-authenticated APIs.
    ///
    /// - A credential that is accepted is inserted as usual.
    /// - A credential that is presented but refused — invalid, expired, signed
    ///   by an unknown key, not the static token, or a valid token without the
    ///   required scopes — gets the same 401 or 403, with the same
    ///   `WWW-Authenticate` challenge and [`on_reject`](Self::on_reject) body,
    ///   as without `optional()`. A client with a bad token learns so, rather
    ///   than being served silently as anonymous.
    /// - A request presents no credential when EVERY value of EVERY configured
    ///   [`CredentialSource`] header is absent or blank: empty or whitespace
    ///   for a [`CredentialSource::Raw`] header; for a
    ///   [`CredentialSource::Bearer`] header, empty or whitespace after
    ///   `Bearer`, or a value using some other scheme (which carries no bearer
    ///   credential to check). This is the same classification
    ///   [`crate::authenticate()`] reports as [`TokenRejection::Missing`],
    ///   with two stricter edges: a header value that is not visible ASCII
    ///   counts as a presented credential, not as a blank one, and so does a
    ///   non-blank LATER value of a repeated header (only the first is ever
    ///   authenticated). Both are refused with the layer's 401. So are a
    ///   `Bearer` value that uses a tab instead of a space before a non-blank
    ///   token, and any `DPoP`-scheme value (RFC 9449; a sender-constrained
    ///   token this crate cannot verify must be refused, not served as
    ///   anonymous). The strict parsing of those values is unchanged: they get
    ///   exactly the refusal a non-optional layer sends.
    /// - Any [`Credential`]/[`AuthorizedToken`] an outer layer inserted is
    ///   removed first, so a pass-through always extracts as `None` (see
    ///   [nested layers](self#nested-layers)).
    ///
    /// Handlers read the outcome with `Option<Credential>` or
    /// `Option<AuthorizedToken>` (see the [module docs](self#extractors)); a
    /// handler that takes a plain `Credential` or `AuthorizedToken` refuses a
    /// passed-through request with the layer's own 401 and challenge.
    ///
    /// # Security
    ///
    /// This is not a way around the fail-closed build: [`build`](Self::build)
    /// still requires a static token or an OAuth validator, and a credential
    /// the layer cannot accept is still refused. What passes through is only
    /// what any caller could send by leaving the credential headers off, so
    /// every handler behind an optional layer must treat `None` as
    /// unauthenticated. The pass-through is logged at `debug`.
    ///
    /// # Examples
    ///
    /// ```
    /// use axum::{Router, routing::get};
    /// use oauth_resource_server::Credential;
    /// use oauth_resource_server::axum::AuthLayer;
    ///
    /// async fn greeting(credential: Option<Credential>) -> &'static str {
    ///     match credential {
    ///         Some(_) => "hello, authenticated caller",
    ///         None => "hello, anonymous caller",
    ///     }
    /// }
    ///
    /// let auth = AuthLayer::builder()
    ///     .static_token("example-static-key")
    ///     .optional()
    ///     .build()
    ///     .unwrap();
    /// let app: Router = Router::new().route("/", get(greeting)).route_layer(auth);
    /// # let _ = app;
    /// ```
    pub fn optional(mut self) -> Self {
        self.optional = true;
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
        Gate::check_decision(&decision, self.oauth.is_some())?;
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
        // The fail-closed checks, shared with the `tower` feature's
        // `HttpAuthLayerBuilder::build`.
        let gate = Gate::build(
            self.static_token,
            self.oauth,
            self.sources,
            self.static_challenge,
            self.optional,
        )?;
        Ok(AuthLayer {
            inner: Arc::new(Mode::Enforce(Enforce {
                gate,
                on_reject: self.on_reject,
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
    ///
    /// The status and the challenge come from the same decision as the public
    /// [`crate::refusal()`] (`refusal::select`, through `Gate`), so an
    /// integration built on `refusal()` sends exactly what this layer sends.
    fn reject(&self, rejection: &TokenRejection, request: &Parts) -> Response {
        let (status, _) = self.gate.status_and_challenge(rejection);
        let response = match &self.on_reject {
            Some(f) => f(RejectContext {
                rejection,
                status,
                request,
            }),
            None => Response::new(Body::empty()),
        };
        // `finish` sets the status and `insert`s the challenge, replacing every
        // value the callback set.
        self.gate.finish(rejection, response)
    }

    /// Log a refusal at the level the [module docs](self#logging) give, then
    /// build its response with [`Enforce::reject`]. Every refusal — the
    /// layer's own and an extractor's — goes through here.
    fn refuse(&self, rejection: &TokenRejection, request: &Parts) -> Response {
        let path = request.uri.path();
        match (&self.gate.oauth, rejection) {
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
        self.reject(rejection, request)
    }
}

/// Inserted into a request's extensions by every [`AuthLayer`] it passes, so
/// the extractors can tell "the layer ran and inserted no credential" (answer
/// with that layer's own refusal) from "no layer ran" (a server
/// misconfiguration). The type is private, so nothing outside this module can
/// insert, read or forge it.
#[derive(Clone)]
struct LayerRan(AuthLayer);

impl AuthLayer {
    /// Authenticate `request`: the request to pass on (with the credential in
    /// its extensions), or the refusal to answer with. The one implementation
    /// behind both [`require_auth`] and the `tower::Layer` service, so the two
    /// cannot drift apart.
    async fn check(&self, mut request: Request) -> Result<Request, Response> {
        let enforce = match &*self.inner {
            Mode::AllowUnauthenticated => {
                request.extensions_mut().insert(LayerRan(self.clone()));
                return Ok(request);
            }
            Mode::Enforce(enforce) => enforce,
        };

        let (mut parts, body) = request.into_parts();
        // `Gate::admit` (shared with the `tower` feature's `HttpAuthLayer`):
        // clear an outer layer's credential for an optional layer, mark the
        // source headers sensitive, `authenticate`, insert what was accepted,
        // and decide an optional layer's pass-through. Logging stays here, so
        // its target stays `oauth_resource_server::axum`.
        match enforce.gate.admit(&mut parts).await {
            Admission::Static => {}
            Admission::OAuth(token) => {
                debug!(
                    path = %parts.uri.path(),
                    principal = ?token.principal.as_deref().map(for_log),
                    subject = ?token.subject.as_deref().map(for_log),
                    scopes = ?token.scopes,
                    "OAuth bearer auth accepted"
                );
            }
            Admission::PassedThrough => {
                debug!(
                    path = %parts.uri.path(),
                    "No credential presented; optional auth passes the request through"
                );
            }
            Admission::Refused(rejection) => return Err(enforce.refuse(&rejection, &parts)),
        }
        parts.extensions.insert(LayerRan(self.clone()));
        Ok(Request::from_parts(parts, body))
    }

    /// The refusal for an extractor whose value the layer did not insert: the
    /// same response the layer itself gives a request with no acceptable
    /// credential, built by the same [`Enforce::reject`]. `wants_oauth_token`
    /// is set for an [`AuthorizedToken`] extractor.
    ///
    /// Two wirings give a 401 no credential can ever satisfy — a required
    /// extractor behind [`AuthLayer::allow_unauthenticated`], and an
    /// [`AuthorizedToken`] extractor behind a layer with no OAuth validator —
    /// so, like the no-layer 500, they are logged at `error` rather than as an
    /// ordinary refusal.
    fn refuse_extraction(
        &self,
        rejection: &TokenRejection,
        parts: &Parts,
        wants_oauth_token: bool,
    ) -> Response {
        match &*self.inner {
            Mode::Enforce(enforce) if wants_oauth_token && enforce.gate.oauth.is_none() => {
                error!(
                    path = %parts.uri.path(),
                    "Server misconfiguration: the handler requires an OAuth access token, but \
                     its AuthLayer has no OAuth validator; refusing the request"
                );
                enforce.reject(rejection, parts)
            }
            Mode::Enforce(enforce) => enforce.refuse(rejection, parts),
            // No challenge of its own to send: the default one, as a
            // static-only layer would (RFC 9110 §15.5.2).
            Mode::AllowUnauthenticated => {
                error!(
                    path = %parts.uri.path(),
                    "Server misconfiguration: the handler requires a credential, but its \
                     AuthLayer allows unauthenticated requests; refusing the request"
                );
                (
                    StatusCode::UNAUTHORIZED,
                    [(
                        WWW_AUTHENTICATE,
                        HeaderValue::from_static(DEFAULT_STATIC_CHALLENGE),
                    )],
                )
                    .into_response()
            }
        }
    }
}

/// What the extractors find on a request.
enum Found<T> {
    /// The layer inserted it.
    Present(T),
    /// An [`AuthLayer`] ran but inserted no `T`.
    Absent(AuthLayer),
    /// No [`AuthLayer`] ran.
    NoLayer,
}

fn find<T: Clone + Send + Sync + 'static>(parts: &Parts) -> Found<T> {
    match (
        parts.extensions.get::<T>(),
        parts.extensions.get::<LayerRan>(),
    ) {
        (Some(value), _) => Found::Present(value.clone()),
        (None, Some(LayerRan(layer))) => Found::Absent(layer.clone()),
        (None, None) => Found::NoLayer,
    }
}

/// The response for an extractor on a route no [`AuthLayer`] covers: 500, and
/// an `error` log naming the mistake. Never access, never "anonymous".
fn no_layer(parts: &Parts, extractor: &'static str) -> Response {
    error!(
        path = %parts.uri.path(),
        extractor,
        "Server misconfiguration: an authentication extractor ran on a route no AuthLayer \
         covers; refusing the request"
    );
    StatusCode::INTERNAL_SERVER_ERROR.into_response()
}

/// The [`AuthLayer`]'s refusal for a required extractor with nothing to
/// extract. A static-token request asking for an [`AuthorizedToken`] is a
/// presented credential of the wrong kind, so it is `Invalid`, not `Missing`.
fn refuse_absent(layer: &AuthLayer, parts: &Parts, wants_oauth_token: bool) -> Response {
    let rejection = match parts.extensions.get::<Credential>() {
        Some(_) => TokenRejection::invalid(
            InvalidTokenKind::OAuthTokenRequired,
            "a credential was accepted, but the handler requires an OAuth access token",
        ),
        None => TokenRejection::Missing,
    };
    layer.refuse_extraction(&rejection, parts, wants_oauth_token)
}

/// Extracts the OAuth token an [`AuthLayer`] accepted.
///
/// Refuses with the layer's own 401 and `WWW-Authenticate` challenge when no
/// token is in the extensions — an [`optional`](AuthLayerBuilder::optional) or
/// [`allow_unauthenticated`](AuthLayer::allow_unauthenticated) layer passed the
/// request through, or the static token was accepted — and with 500 (logged at
/// `error`) on a route no [`AuthLayer`] covers. Behind nested strict layers the
/// token may have been inserted by an OUTER layer even when the innermost one
/// accepted the static token; see the [module docs](self#nested-layers).
///
/// # Examples
///
/// ```
/// use axum::{Router, routing::get};
/// use oauth_resource_server::AuthorizedToken;
///
/// async fn subject(token: AuthorizedToken) -> String {
///     token.subject.unwrap_or_default()
/// }
/// # let _: Router = Router::new().route("/", get(subject));
/// ```
#[cfg_attr(docsrs, doc(cfg(feature = "axum")))]
impl<S: Send + Sync> FromRequestParts<S> for AuthorizedToken {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Response> {
        match find::<AuthorizedToken>(parts) {
            Found::Present(token) => Ok(token),
            Found::Absent(layer) => Err(refuse_absent(&layer, parts, true)),
            Found::NoLayer => Err(no_layer(parts, "AuthorizedToken")),
        }
    }
}

/// `Option<AuthorizedToken>`: `None` when an [`AuthLayer`] ran and no OAuth
/// token is in the extensions (no credential under an
/// [`optional`](AuthLayerBuilder::optional) or
/// [`allow_unauthenticated`](AuthLayer::allow_unauthenticated) layer, or the
/// static token was accepted and no outer strict layer inserted a token — see
/// [nested layers](self#nested-layers)). On a route no [`AuthLayer`] covers it
/// still refuses with 500, logged at `error`, rather than reading as anonymous.
#[cfg_attr(docsrs, doc(cfg(feature = "axum")))]
impl<S: Send + Sync> OptionalFromRequestParts<S> for AuthorizedToken {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Option<Self>, Response> {
        match find::<AuthorizedToken>(parts) {
            Found::Present(token) => Ok(Some(token)),
            Found::Absent(_) => Ok(None),
            Found::NoLayer => Err(no_layer(parts, "Option<AuthorizedToken>")),
        }
    }
}

/// Extracts the credential an [`AuthLayer`] accepted.
///
/// Refuses with the layer's own 401 and `WWW-Authenticate` challenge when the
/// layer inserted none (an [`optional`](AuthLayerBuilder::optional) or
/// [`allow_unauthenticated`](AuthLayer::allow_unauthenticated) layer passed the
/// request through), and with 500 (logged at `error`) on a route no
/// [`AuthLayer`] covers. See the [module docs](self#extractors).
///
/// # Examples
///
/// ```
/// use axum::{Router, routing::get};
/// use oauth_resource_server::Credential;
///
/// async fn whoami(credential: Credential) -> String {
///     match credential {
///         Credential::OAuth(token) => format!("subject {:?}", token.subject),
///         Credential::StaticToken => "the static API key".to_string(),
///         _ => "some other credential".to_string(),
///     }
/// }
/// # let _: Router = Router::new().route("/", get(whoami));
/// ```
#[cfg_attr(docsrs, doc(cfg(feature = "axum")))]
impl<S: Send + Sync> FromRequestParts<S> for Credential {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Response> {
        match find::<Credential>(parts) {
            Found::Present(credential) => Ok(credential),
            Found::Absent(layer) => Err(refuse_absent(&layer, parts, false)),
            Found::NoLayer => Err(no_layer(parts, "Credential")),
        }
    }
}

/// `Option<Credential>`: `None` when an [`AuthLayer`] ran and inserted no
/// credential (no credential under an [`optional`](AuthLayerBuilder::optional)
/// or [`allow_unauthenticated`](AuthLayer::allow_unauthenticated) layer). On a
/// route no [`AuthLayer`] covers it still refuses with 500, logged at `error`,
/// rather than reading as anonymous.
#[cfg_attr(docsrs, doc(cfg(feature = "axum")))]
impl<S: Send + Sync> OptionalFromRequestParts<S> for Credential {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Option<Self>, Response> {
        match find::<Credential>(parts) {
            Found::Present(credential) => Ok(Some(credential)),
            Found::Absent(_) => Ok(None),
            Found::NoLayer => Err(no_layer(parts, "Option<Credential>")),
        }
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
/// OAuth token, the [`AuthorizedToken`] too, so a
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

    // --- Extractors and optional authentication ---

    /// Everything about a response a caller can observe, for byte-for-byte
    /// comparisons: status, every header (in order), body.
    async fn observed(resp: Response) -> (StatusCode, Vec<(String, Vec<u8>)>, Vec<u8>) {
        let status = resp.status();
        let headers = resp
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.as_bytes().to_vec()))
            .collect();
        (status, headers, body_bytes(resp).await)
    }

    fn json_reject(cx: RejectContext<'_>) -> Response {
        Response::new(Body::from(format!("refused {}", cx.status.as_u16())))
    }

    /// A router whose one handler reads `Option<Credential>` and
    /// `Option<AuthorizedToken>` through the extractors, counting its runs.
    fn optional_extractor_app(
        layer: AuthLayer,
        runs: Arc<std::sync::atomic::AtomicUsize>,
    ) -> Router {
        let handler = move |credential: Option<Credential>, token: Option<AuthorizedToken>| {
            let runs = Arc::clone(&runs);
            async move {
                runs.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                match (credential, token) {
                    (None, None) => "none".to_string(),
                    (Some(Credential::StaticToken), None) => "static".to_string(),
                    (Some(Credential::OAuth(c)), Some(t)) => {
                        assert_eq!(c, t);
                        format!("oauth {}", t.subject.as_deref().unwrap_or_default())
                    }
                    other => panic!("inconsistent extraction: {other:?}"),
                }
            }
        };
        Router::new()
            .route("/test", get(handler))
            .route_layer(layer)
    }

    /// Request headers as raw bytes, so a test can send a non-ASCII value.
    type Headers<'a> = Vec<(&'a str, &'a [u8])>;

    async fn send_raw(app: &Router, headers: &[(&str, &[u8])]) -> Response {
        let mut req = Request::builder().uri("/test");
        for (name, value) in headers {
            req = req.header(*name, HeaderValue::from_bytes(value).unwrap());
        }
        app.clone()
            .oneshot(req.body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    /// The kind an extractor's refusal carries reaches `on_reject`: a static
    /// token where a handler needs an OAuth token is `OAuthTokenRequired`,
    /// and the status stays 401.
    #[tokio::test]
    async fn an_oauth_extractor_refusing_a_static_token_names_its_kind() {
        let jwks = testing::spawn_jwks_server("200 OK", testing::jwks_body()).await;
        let v = validator(&jwks.url);
        let layer = AuthLayer::builder()
            .static_token(STATIC)
            .oauth(Arc::clone(&v))
            .on_reject(|cx: RejectContext<'_>| {
                let label = match cx.rejection {
                    TokenRejection::Invalid(invalid) => invalid.kind().as_str(),
                    _ => "not invalid",
                };
                Response::new(Body::from(label))
            })
            .build()
            .unwrap();
        let app = Router::new()
            .route("/test", get(|_: AuthorizedToken| async { "ok" }))
            .route_layer(layer);
        let resp = get_with_auth(&app, Some("Bearer secret")).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(www_authenticate(&resp), v.invalid_token_challenge());
        assert_eq!(body_bytes(resp).await, b"oauth_token_required");
        let resp = get_with_auth(&app, Some("Bearer wrong")).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(body_bytes(resp).await, b"not_jwt");
    }

    #[tokio::test]
    async fn the_extractors_read_a_valid_token_and_the_static_token() {
        let jwks = testing::spawn_jwks_server("200 OK", testing::jwks_body()).await;
        let v = validator(&jwks.url);
        let layer = AuthLayer::builder()
            .static_token(STATIC)
            .oauth(Arc::clone(&v))
            .build()
            .unwrap();
        let app = Router::new()
            .route(
                "/credential",
                get(|credential: Credential| async move {
                    match credential {
                        Credential::StaticToken => "static".to_string(),
                        Credential::OAuth(t) => format!("oauth {}", t.subject.unwrap_or_default()),
                    }
                }),
            )
            .route(
                "/token",
                get(|token: AuthorizedToken| async move {
                    format!(
                        "{} {}",
                        token.subject.as_deref().unwrap_or_default(),
                        token.has_scope("mcp:read")
                    )
                }),
            )
            .route_layer(layer);
        let get_at = |path: &'static str, header: String| {
            let app = app.clone();
            async move {
                app.oneshot(
                    Request::builder()
                        .uri(path)
                        .header("authorization", header)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap()
            }
        };

        let valid = format!("Bearer {}", testing::valid_token());
        let resp = get_at("/credential", valid.clone()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_bytes(resp).await, b"oauth user-1");
        let resp = get_at("/token", valid).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_bytes(resp).await, b"user-1 true");

        let resp = get_at("/credential", "Bearer secret".into()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_bytes(resp).await, b"static");
        // A static-token request has no OAuth token: the layer's own 401 and
        // challenge, never a 500 or a pass.
        let resp = get_at("/token", "Bearer secret".into()).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(www_authenticate(&resp), v.invalid_token_challenge());
    }

    #[tokio::test]
    async fn an_extractor_outside_every_layer_fails_closed_with_500() {
        let runs = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count = |runs: &Arc<std::sync::atomic::AtomicUsize>| {
            runs.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        };
        let (r1, r2, r3, r4) = (
            Arc::clone(&runs),
            Arc::clone(&runs),
            Arc::clone(&runs),
            Arc::clone(&runs),
        );
        let app = Router::new()
            .route(
                "/credential",
                get(move |_: Credential| async move { count(&r1) }),
            )
            .route(
                "/token",
                get(move |_: AuthorizedToken| async move { count(&r2) }),
            )
            .route(
                "/opt-credential",
                get(move |_: Option<Credential>| async move { count(&r3) }),
            )
            .route(
                "/opt-token",
                get(move |_: Option<AuthorizedToken>| async move { count(&r4) }),
            );
        for path in ["/credential", "/token", "/opt-credential", "/opt-token"] {
            for header in [None, Some("Bearer secret")] {
                let mut req = Request::builder().uri(path);
                if let Some(h) = header {
                    req = req.header("authorization", h);
                }
                let resp = app
                    .clone()
                    .oneshot(req.body(Body::empty()).unwrap())
                    .await
                    .unwrap();
                assert_eq!(
                    resp.status(),
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "{path} {header:?}"
                );
                assert!(resp.headers().get(WWW_AUTHENTICATE).is_none());
                assert!(body_bytes(resp).await.is_empty(), "{path}");
            }
        }
        assert_eq!(runs.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[test]
    fn optional_still_needs_a_credential_to_build() {
        assert_eq!(
            AuthLayer::builder().optional().build().unwrap_err(),
            AuthLayerError::NoCredential
        );
        assert_eq!(
            AuthLayer::builder()
                .static_token("")
                .optional()
                .build()
                .unwrap_err(),
            AuthLayerError::NoCredential
        );
        assert_eq!(
            AuthLayer::builder()
                .static_token(STATIC)
                .optional()
                .sources([])
                .build()
                .unwrap_err(),
            AuthLayerError::NoSources
        );
        let layer = AuthLayer::builder()
            .static_token("hunter2")
            .optional()
            .build()
            .unwrap();
        assert!(!layer.allows_unauthenticated());
        let rendered = format!("{layer:?}");
        assert!(!rendered.contains("hunter2") && rendered.contains("optional: true"));
    }

    /// Every refusal an `optional()` layer sends is byte-identical to the one
    /// the same layer without `optional()` sends, and the handler never runs;
    /// only a request presenting nothing passes, as `None`.
    #[tokio::test]
    async fn an_optional_layer_passes_only_a_request_with_no_credential() {
        let jwks = testing::spawn_jwks_server("200 OK", testing::jwks_body()).await;
        let v = validator(&jwks.url);
        let builder = || {
            AuthLayer::builder()
                .static_token(STATIC)
                .oauth(Arc::clone(&v))
                .sources([
                    CredentialSource::authorization_bearer(),
                    CredentialSource::Raw(HeaderName::from_static("x-api-key")),
                ])
                .on_reject(json_reject)
        };
        let runs = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let optional =
            optional_extractor_app(builder().optional().build().unwrap(), Arc::clone(&runs));
        let strict =
            optional_extractor_app(builder().build().unwrap(), Arc::new(Default::default()));
        let ran = || runs.load(std::sync::atomic::Ordering::SeqCst);

        // No credential, and blank ones: the handler runs with `None`.
        let blanks: &[&[(&str, &[u8])]] = &[
            &[],
            &[("authorization", b"")],
            &[("authorization", b"Bearer ")],
            &[("authorization", b"bearer    ")],
            // Another scheme carries no bearer credential at all.
            &[("authorization", b"Basic c2VjcmV0")],
            &[("x-api-key", b"   ")],
            &[("authorization", b"Bearer "), ("x-api-key", b"")],
            &[("authorization", b"Bearer "), ("authorization", b" ")],
        ];
        for headers in blanks {
            let before = ran();
            let resp = send_raw(&optional, headers).await;
            assert_eq!(resp.status(), StatusCode::OK, "{headers:?}");
            assert!(resp.headers().get(WWW_AUTHENTICATE).is_none());
            assert_eq!(body_bytes(resp).await, b"none", "{headers:?}");
            assert_eq!(ran(), before + 1);
            // The same request is refused by the non-optional layer.
            let resp = send_raw(&strict, headers).await;
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{headers:?}");
            assert_eq!(www_authenticate(&resp), v.invalid_token_challenge());
        }

        // Anything presented but not accepted: refused exactly as without
        // `optional()`, and the handler never runs.
        let invalid = format!("Bearer {}", testing::valid_token().replace('.', "x."));
        let expired = format!("Bearer {}", expired_token());
        let unscoped = format!("Bearer {}", unscoped_token());
        let refused: Vec<(Headers<'_>, StatusCode, String)> = vec![
            (
                vec![("authorization", b"Bearer not-a-jwt")],
                StatusCode::UNAUTHORIZED,
                v.invalid_token_challenge(),
            ),
            (
                vec![("authorization", invalid.as_bytes())],
                StatusCode::UNAUTHORIZED,
                v.invalid_token_challenge(),
            ),
            (
                vec![("authorization", expired.as_bytes())],
                StatusCode::UNAUTHORIZED,
                v.invalid_token_challenge(),
            ),
            (
                vec![("x-api-key", b"wrong-key")],
                StatusCode::UNAUTHORIZED,
                v.invalid_token_challenge(),
            ),
            // A blank source never hides a bad one.
            (
                vec![("authorization", b"Bearer "), ("x-api-key", b"wrong-key")],
                StatusCode::UNAUTHORIZED,
                v.invalid_token_challenge(),
            ),
            // Only the first value is authenticated, but a non-blank later one
            // is still something presented, not nothing.
            (
                vec![
                    ("authorization", b"Bearer "),
                    ("authorization", b"Bearer junk"),
                ],
                StatusCode::UNAUTHORIZED,
                v.invalid_token_challenge(),
            ),
            // Not visible ASCII: unreadable, so not provably blank.
            (
                vec![("authorization", b"Bearer \xff")],
                StatusCode::UNAUTHORIZED,
                v.invalid_token_challenge(),
            ),
            (
                vec![("authorization", unscoped.as_bytes())],
                StatusCode::FORBIDDEN,
                v.insufficient_scope_challenge(),
            ),
        ];
        for (headers, status, challenge) in &refused {
            let before = ran();
            let resp = send_raw(&optional, headers).await;
            assert_eq!(resp.status(), *status, "{headers:?}");
            assert_eq!(&www_authenticate(&resp), challenge, "{headers:?}");
            let got = observed(resp).await;
            assert_eq!(got.2, format!("refused {}", status.as_u16()).as_bytes());
            assert_eq!(
                got,
                observed(send_raw(&strict, headers).await).await,
                "{headers:?}"
            );
            assert_eq!(ran(), before, "the handler ran for {headers:?}");
        }

        // Accepted credentials are inserted as usual.
        let valid = format!("Bearer {}", testing::valid_token());
        let resp = send_raw(&optional, &[("authorization", valid.as_bytes())]).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_bytes(resp).await, b"oauth user-1");
        let resp = send_raw(&optional, &[("x-api-key", STATIC.as_bytes())]).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_bytes(resp).await, b"static");
    }

    /// The marker path: a required extractor behind an `optional()` layer that
    /// passed a request through answers with the response the non-optional
    /// layer gives the same request, byte for byte (`on_reject` body included).
    #[tokio::test]
    async fn a_required_extractor_behind_an_optional_layer_gets_the_layers_own_refusal() {
        let v = unreachable_validator();
        let builder = || {
            AuthLayer::builder()
                .static_token(STATIC)
                .oauth(Arc::clone(&v))
                .on_reject(json_reject)
        };
        let runs = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let make = |layer: AuthLayer| {
            let (r1, r2) = (Arc::clone(&runs), Arc::clone(&runs));
            Router::new()
                .route(
                    "/test",
                    get(move |_: Credential| async move {
                        r1.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    }),
                )
                .route(
                    "/token",
                    get(move |_: AuthorizedToken| async move {
                        r2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    }),
                )
                .route_layer(layer)
        };
        let optional = make(builder().optional().build().unwrap());
        let strict = make(builder().build().unwrap());
        for path in ["/test", "/token"] {
            let request = || Request::builder().uri(path).body(Body::empty()).unwrap();
            let got = observed(optional.clone().oneshot(request()).await.unwrap()).await;
            let want = observed(strict.clone().oneshot(request()).await.unwrap()).await;
            assert_eq!(got.0, StatusCode::UNAUTHORIZED, "{path}");
            assert_eq!(got, want, "{path}");
            assert!(
                got.1.iter().any(|(k, val)| k == "www-authenticate"
                    && val == v.invalid_token_challenge().as_bytes()),
                "{path}"
            );
        }
        assert_eq!(runs.load(std::sync::atomic::Ordering::SeqCst), 0);

        // Without OAuth, the static challenge — the same code path again.
        let optional = make(
            AuthLayer::builder()
                .static_token(STATIC)
                .optional()
                .build()
                .unwrap(),
        );
        let resp = optional
            .oneshot(Request::builder().uri("/test").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(resp.headers()[WWW_AUTHENTICATE], DEFAULT_STATIC_CHALLENGE);
    }

    #[tokio::test]
    async fn the_extractors_under_allow_unauthenticated() {
        let app = Router::new()
            .route(
                "/test",
                get(
                    |c: Option<Credential>, t: Option<AuthorizedToken>| async move {
                        assert!(c.is_none() && t.is_none());
                        "none"
                    },
                ),
            )
            .route("/required", get(|_: Credential| async { "unreachable" }))
            .route_layer(AuthLayer::allow_unauthenticated());
        let resp = get_with_auth(&app, Some("Bearer anything")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_bytes(resp).await, b"none");
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/required")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(resp.headers()[WWW_AUTHENTICATE], DEFAULT_STATIC_CHALLENGE);
    }

    /// A non-optional layer with the extractors answers exactly as with
    /// `Extension<..>`: the extractor only ever sees what the layer passed.
    #[tokio::test]
    async fn a_non_optional_layer_with_extractors_matches_extension_handlers() {
        let jwks = testing::spawn_jwks_server("200 OK", testing::jwks_body()).await;
        let layer = AuthLayer::builder()
            .static_token(STATIC)
            .oauth(validator(&jwks.url))
            .build()
            .unwrap();
        let via_extension = Router::new()
            .route(
                "/test",
                get(|Extension(c): Extension<Credential>| async move { format!("{c:?}") }),
            )
            .route_layer(layer.clone());
        let via_extractor = Router::new()
            .route(
                "/test",
                get(|c: Credential| async move { format!("{c:?}") }),
            )
            .route_layer(layer);
        let valid = format!("Bearer {}", testing::valid_token());
        let unscoped = format!("Bearer {}", unscoped_token());
        let expired = format!("Bearer {}", expired_token());
        for header in [
            None,
            Some("Bearer "),
            Some("Bearer secret"),
            Some("Bearer wrong"),
            Some(valid.as_str()),
            Some(unscoped.as_str()),
            Some(expired.as_str()),
        ] {
            assert_eq!(
                observed(get_with_auth(&via_extractor, header).await).await,
                observed(get_with_auth(&via_extension, header).await).await,
                "{header:?}"
            );
        }
    }

    fn claims_with(extra: serde_json::Value) -> serde_json::Value {
        let mut claims = serde_json::json!({
            "iss": testing::ISSUER, "aud": testing::AUDIENCE,
            "exp": testing::now() + 3600, "scope": "mcp:read mcp:write", "sub": "user-1",
        });
        for (k, v) in extra.as_object().unwrap() {
            claims[k] = v.clone();
        }
        claims
    }

    #[test]
    fn names_a_token_only_for_dpop_and_tab_separated_bearer() {
        for value in [
            "DPoP x",
            "dpop x",
            "DPoP",
            "Bearer\tx",
            "bearer\t x",
            " Bearer x",
            "\tBEARER\tx",
        ] {
            assert!(names_a_token(value), "{value:?}");
        }
        for value in [
            "",
            "Bearer",
            "Bearer ",
            "Bearer\t",
            "Bearer \t ",
            "Basic x",
            "x",
        ] {
            assert!(!names_a_token(value), "{value:?}");
        }
        // The strict parsing is untouched.
        assert_eq!(bearer_credential("Bearer\tx"), "");
        assert_eq!(bearer_credential("DPoP x"), "");
    }

    /// Every presented-but-unacceptable shape the security review listed is
    /// refused by an `optional()` layer exactly as by the same layer without
    /// it — status, every header and body, byte for byte — and the handler
    /// never runs.
    #[tokio::test]
    async fn an_optional_layer_refuses_every_presented_shape_like_the_strict_layer() {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let jwks = testing::spawn_jwks_server("200 OK", testing::jwks_body()).await;
        let v = validator(&jwks.url);
        let builder = || {
            AuthLayer::builder()
                .static_token(STATIC)
                .oauth(Arc::clone(&v))
                .sources([
                    CredentialSource::authorization_bearer(),
                    CredentialSource::Raw(HeaderName::from_static("x-api-key")),
                ])
                .on_reject(json_reject)
        };
        let runs = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let optional =
            optional_extractor_app(builder().optional().build().unwrap(), Arc::clone(&runs));
        let strict =
            optional_extractor_app(builder().build().unwrap(), Arc::new(Default::default()));

        let forged = testing::mint(
            testing::KEY_B_PEM,
            testing::KID_A,
            &claims_with(serde_json::json!({})),
        );
        let wrong_aud = testing::mint(
            testing::KEY_A_PEM,
            testing::KID_A,
            &claims_with(serde_json::json!({ "aud": "some-other-client" })),
        );
        let cnf = testing::mint(
            testing::KEY_A_PEM,
            testing::KID_A,
            &claims_with(serde_json::json!({ "cnf": { "jkt": "abc" } })),
        );
        let valid = testing::valid_token();
        let crit = {
            let mut parts: Vec<String> = valid.split('.').map(str::to_string).collect();
            parts[0] =
                URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","kid":"test-key-a","crit":["exp"]}"#);
            parts.join(".")
        };

        let cases: Vec<(&str, Vec<(&str, String)>)> = vec![
            (
                "forged",
                vec![("authorization", format!("Bearer {forged}"))],
            ),
            (
                "wrong aud",
                vec![("authorization", format!("Bearer {wrong_aud}"))],
            ),
            (
                "cnf bearer",
                vec![("authorization", format!("Bearer {cnf}"))],
            ),
            ("crit", vec![("authorization", format!("Bearer {crit}"))]),
            (
                "BEARER forged",
                vec![("authorization", format!("BEARER {forged}"))],
            ),
            (
                "bearer bad",
                vec![("authorization", "bearer not-a-jwt".to_string())],
            ),
            (
                "Bearer<TAB>forged",
                vec![("authorization", format!("Bearer\t{forged}"))],
            ),
            (
                "Bearer<TAB>valid",
                vec![("authorization", format!("Bearer\t{valid}"))],
            ),
            (
                " Bearer forged",
                vec![("authorization", format!(" Bearer {forged}"))],
            ),
            ("DPoP cnf", vec![("authorization", format!("DPoP {cnf}"))]),
            (
                "DPoP forged",
                vec![("authorization", format!("DPoP {forged}"))],
            ),
            (
                "Basic, then Bearer forged",
                vec![
                    ("authorization", "Basic x".to_string()),
                    ("authorization", format!("Bearer {forged}")),
                ],
            ),
            (
                "blank Bearer, then Bearer forged",
                vec![
                    ("authorization", "Bearer ".to_string()),
                    ("authorization", format!("Bearer {forged}")),
                ],
            ),
        ];
        for (name, headers) in &cases {
            let headers: Vec<(&str, &[u8])> =
                headers.iter().map(|(n, v)| (*n, v.as_bytes())).collect();
            let before = runs.load(std::sync::atomic::Ordering::SeqCst);
            let got = observed(send_raw(&optional, &headers).await).await;
            let want = observed(send_raw(&strict, &headers).await).await;
            assert_eq!(got.0, StatusCode::UNAUTHORIZED, "{name}");
            assert!(
                got.1.iter().any(|(k, val)| k == "www-authenticate"
                    && val == v.invalid_token_challenge().as_bytes()),
                "{name}"
            );
            assert_eq!(got, want, "{name}");
            assert_eq!(
                runs.load(std::sync::atomic::Ordering::SeqCst),
                before,
                "the handler ran for {name}"
            );
        }
    }

    /// An inner `optional()` layer extracts only what IT accepted: the outer
    /// strict OAuth layer's token and credential are not visible behind it.
    #[tokio::test]
    async fn an_inner_optional_layer_does_not_leak_an_outer_layers_credential() {
        let jwks = testing::spawn_jwks_server("200 OK", testing::jwks_body()).await;
        let outer = AuthLayer::builder()
            .oauth(validator(&jwks.url))
            .build()
            .unwrap();
        let inner = AuthLayer::builder()
            .static_token("inner-key")
            .sources([CredentialSource::Raw(HeaderName::from_static("x-inner"))])
            .optional()
            .build()
            .unwrap();
        let runs = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let app = optional_extractor_app(inner, Arc::clone(&runs)).layer(outer);
        let valid = format!("Bearer {}", testing::valid_token());

        let resp = send_raw(&app, &[("authorization", valid.as_bytes())]).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_bytes(resp).await, b"none");

        // The inner layer's own acceptance is all the handler sees.
        let resp = send_raw(
            &app,
            &[
                ("authorization", valid.as_bytes()),
                ("x-inner", b"inner-key"),
            ],
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_bytes(resp).await, b"static");
        assert_eq!(runs.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    /// Strict nested layers keep accumulating, as documented: `Credential` is
    /// the innermost acceptance, `AuthorizedToken` the outer layer's.
    #[tokio::test]
    async fn strict_nested_layers_accumulate_extensions_as_documented() {
        let jwks = testing::spawn_jwks_server("200 OK", testing::jwks_body()).await;
        let outer = AuthLayer::builder()
            .oauth(validator(&jwks.url))
            .build()
            .unwrap();
        let inner = AuthLayer::builder()
            .static_token("inner-key")
            .sources([CredentialSource::Raw(HeaderName::from_static("x-inner"))])
            .build()
            .unwrap();
        let app = Router::new()
            .route(
                "/test",
                get(|c: Credential, t: AuthorizedToken| async move {
                    format!(
                        "{} {}",
                        matches!(c, Credential::StaticToken),
                        t.subject.unwrap_or_default()
                    )
                }),
            )
            .route_layer(inner)
            .layer(outer);
        let valid = format!("Bearer {}", testing::valid_token());

        let resp = send_raw(
            &app,
            &[
                ("authorization", valid.as_bytes()),
                ("x-inner", b"inner-key"),
            ],
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_bytes(resp).await, b"true user-1");

        // The inner strict layer still refuses on its own terms.
        let resp = send_raw(&app, &[("authorization", valid.as_bytes())]).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(resp.headers()[WWW_AUTHENTICATE], DEFAULT_STATIC_CHALLENGE);
    }
}

/// The shared refusal mapping: [`crate::refusal()`] against this layer's own
/// [`Enforce::reject`], and this layer against the `tower` feature's
/// `HttpAuthLayer`, request for request.
#[cfg(test)]
mod shared_refusal_tests {
    use ::tower::{ServiceExt, service_fn};

    use super::*;
    use crate::http_layer::HttpAuthLayer;
    use crate::testing;
    use crate::{Refusal, refusal, refusal_with_static_challenge};

    const STATIC: &str = "secret";
    const CUSTOM: &str = "ApiKey realm=\"example\"";

    fn validator(jwks_uri: &str) -> Arc<OAuthValidator> {
        Arc::new(OAuthValidator::new(&testing::resolved_config(jwks_uri)).unwrap())
    }

    /// The layer's `static_challenge` setting, and the `&str` form
    /// `refusal_with_static_challenge` takes for it.
    #[derive(Clone, Copy, Debug)]
    enum Static {
        Unset,
        Custom,
        Off,
    }

    fn what_the_axum_layer_sends(
        oauth: Option<Arc<OAuthValidator>>,
        setting: Static,
        rejection: &TokenRejection,
    ) -> (u16, Vec<String>) {
        let mut builder = AuthLayer::builder()
            .static_token(STATIC)
            .optional_oauth(oauth)
            // A callback that sets its own challenge, to show it is replaced
            // exactly when `refusal()` names one.
            .on_reject(|_| {
                (StatusCode::IM_A_TEAPOT, [(WWW_AUTHENTICATE, "Callback x")]).into_response()
            });
        builder = match setting {
            Static::Unset => builder,
            Static::Custom => builder.static_challenge(Some(HeaderValue::from_static(CUSTOM))),
            Static::Off => builder.static_challenge(None),
        };
        let layer = builder.build().unwrap();
        let Mode::Enforce(enforce) = &*layer.inner else {
            unreachable!("an enforcing layer was built")
        };
        let (parts, ()) = Request::builder()
            .uri("/test")
            .body(())
            .unwrap()
            .into_parts();
        let response = enforce.reject(rejection, &parts);
        let challenges = response
            .headers()
            .get_all(WWW_AUTHENTICATE)
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect();
        (response.status().as_u16(), challenges)
    }

    #[test]
    fn refusal_gives_exactly_what_enforce_reject_gives() {
        let v = validator("http://127.0.0.1:1/jwks");
        let rejections = [
            TokenRejection::Missing,
            TokenRejection::Invalid("any reason".into()),
            TokenRejection::InsufficientScope,
        ];
        let mut rows = 0;
        for oauth in [None, Some(Arc::clone(&v))] {
            for setting in [Static::Unset, Static::Custom, Static::Off] {
                for rejection in &rejections {
                    let static_str = match setting {
                        Static::Unset => Some(DEFAULT_STATIC_CHALLENGE),
                        Static::Custom => Some(CUSTOM),
                        Static::Off => None,
                    };
                    let ours =
                        refusal_with_static_challenge(rejection, oauth.as_deref(), static_str);
                    if let Static::Unset = setting {
                        assert_eq!(ours, refusal(rejection, oauth.as_deref()));
                    }
                    let (status, challenges) =
                        what_the_axum_layer_sends(oauth.clone(), setting, rejection);
                    let context = format!("oauth={} {setting:?} {rejection:?}", oauth.is_some());
                    assert_eq!(ours.status, status, "{context}");
                    // `None` leaves the callback's own header in place, as the
                    // layer documents; `Some` replaces it.
                    let expected = match &ours {
                        Refusal {
                            www_authenticate: Some(c),
                            ..
                        } => vec![c.clone()],
                        _ => vec!["Callback x".to_string()],
                    };
                    assert_eq!(challenges, expected, "{context}");
                    rows += 1;
                }
            }
        }
        assert_eq!(rows, 18);
    }

    #[test]
    fn the_status_and_challenge_are_what_rfc_6750_asks_for() {
        let v = validator("http://127.0.0.1:1/jwks");
        let r = refusal(&TokenRejection::Missing, Some(&v));
        assert_eq!(r.status, 401);
        assert_eq!(r.www_authenticate, Some(v.invalid_token_challenge()));
        let r = refusal(&TokenRejection::Invalid("x".into()), Some(&v));
        assert_eq!(r.status, 401);
        assert_eq!(r.www_authenticate, Some(v.invalid_token_challenge()));
        let r = refusal(&TokenRejection::InsufficientScope, Some(&v));
        assert_eq!(r.status, 403);
        assert_eq!(r.www_authenticate, Some(v.insufficient_scope_challenge()));
        // With OAuth, the static setting is ignored.
        assert_eq!(
            refusal_with_static_challenge(&TokenRejection::Missing, Some(&v), None),
            refusal(&TokenRejection::Missing, Some(&v))
        );
    }

    /// Status, every `WWW-Authenticate` value, and the handler's body.
    type Seen = (u16, Vec<String>, String);

    async fn through_axum(layer: AuthLayer, headers: &[(&str, &str)]) -> Seen {
        let app: Router = Router::new()
            .route(
                "/test",
                get(|credential: Option<Credential>| async move { format!("{credential:?}") }),
            )
            .route_layer(layer);
        let mut request = Request::builder().uri("/test");
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let response = app
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status().as_u16();
        let challenges = response
            .headers()
            .get_all(WWW_AUTHENTICATE)
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect();
        let body = ::axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        (
            status,
            challenges,
            String::from_utf8(body.to_vec()).unwrap(),
        )
    }

    async fn through_tower(layer: HttpAuthLayer, headers: &[(&str, &str)]) -> Seen {
        let service = tower_layer::Layer::layer(
            &layer,
            service_fn(|request: http::Request<String>| async move {
                let credential = request.extensions().get::<Credential>().cloned();
                Ok::<_, std::convert::Infallible>(http::Response::new(format!("{credential:?}")))
            }),
        );
        let mut request = http::Request::builder().uri("/test");
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let response = service
            .oneshot(request.body(String::new()).unwrap())
            .await
            .unwrap();
        let challenges = response
            .headers()
            .get_all(WWW_AUTHENTICATE)
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect();
        (response.status().as_u16(), challenges, response.into_body())
    }

    #[tokio::test]
    async fn the_axum_and_tower_layers_answer_every_request_identically() {
        let jwks = testing::spawn_jwks_server("200 OK", testing::jwks_body()).await;
        let v = validator(&jwks.url);
        let mint = |scope: &str, exp_offset: i64| {
            testing::mint(
                testing::KEY_A_PEM,
                testing::KID_A,
                &serde_json::json!({
                    "iss": testing::ISSUER, "aud": testing::AUDIENCE, "sub": "user-1",
                    "exp": testing::now() as i64 + exp_offset, "scope": scope,
                }),
            )
        };
        let valid = format!("Bearer {}", mint("mcp:read", 3600));
        let expired = format!("Bearer {}", mint("mcp:read", -3600));
        let unscoped = format!("Bearer {}", mint("openid", 3600));
        let requests: Vec<Vec<(&str, &str)>> = vec![
            vec![],
            vec![("authorization", valid.as_str())],
            vec![("authorization", expired.as_str())],
            vec![("authorization", unscoped.as_str())],
            vec![("authorization", "Bearer not-a-jwt")],
            vec![("authorization", "Bearer secret")],
            vec![("authorization", "bearer secret")],
            vec![("authorization", "Bearer ")],
            vec![("authorization", "Basic abc")],
            vec![("authorization", "DPoP abc")],
            vec![("x-api-key", "secret")],
            vec![("authorization", "Bearer wrong"), ("x-api-key", "secret")],
        ];

        // (static token, oauth, static_challenge, optional, x-api-key source)
        type Config = (
            Option<&'static str>,
            bool,
            Option<Option<&'static str>>,
            bool,
            bool,
        );
        let configs: [Config; 7] = [
            (None, true, None, false, false),
            (Some(STATIC), true, None, false, true),
            (Some(STATIC), false, None, false, false),
            (Some(STATIC), false, Some(None), false, false),
            (Some(STATIC), false, Some(Some(CUSTOM)), false, true),
            (Some(STATIC), true, None, true, false),
            (Some(STATIC), false, None, true, true),
        ];
        for (static_token, with_oauth, static_challenge, optional, api_key) in configs {
            let oauth = with_oauth.then(|| Arc::clone(&v));
            let sources = if api_key {
                vec![
                    CredentialSource::authorization_bearer(),
                    CredentialSource::Raw(HeaderName::from_static("x-api-key")),
                ]
            } else {
                vec![CredentialSource::authorization_bearer()]
            };
            let challenge = static_challenge.map(|c| c.map(HeaderValue::from_static));
            let mut axum_builder = AuthLayer::builder()
                .optional_static_token(static_token.map(str::to_string))
                .optional_oauth(oauth.clone())
                .sources(sources.clone());
            let mut tower_builder = HttpAuthLayer::builder()
                .optional_static_token(static_token.map(str::to_string))
                .optional_oauth(oauth.clone())
                .sources(sources);
            if let Some(c) = challenge {
                axum_builder = axum_builder.static_challenge(c.clone());
                tower_builder = tower_builder.static_challenge(c);
            }
            if optional {
                axum_builder = axum_builder.optional();
                tower_builder = tower_builder.optional();
            }
            let axum_layer = axum_builder.build().unwrap();
            let tower_layer = tower_builder.build().unwrap();
            for headers in &requests {
                let a = through_axum(axum_layer.clone(), headers).await;
                let t = through_tower(tower_layer.clone(), headers).await;
                assert_eq!(
                    a, t,
                    "config {static_token:?} oauth={with_oauth} {static_challenge:?} \
                     optional={optional} api_key={api_key}, request {headers:?}"
                );
            }
        }
    }

    /// Status, every `WWW-Authenticate` value, `Content-Type`, and the body.
    type SeenFull = (u16, Vec<String>, Option<String>, String);

    fn seen_parts(headers: &HeaderMap, status: u16, body: String) -> SeenFull {
        let challenges = headers
            .get_all(WWW_AUTHENTICATE)
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect();
        let content_type = headers
            .get(http::header::CONTENT_TYPE)
            .map(|v| v.to_str().unwrap().to_string());
        (status, challenges, content_type, body)
    }

    /// What the handler behind both stacks reports: the credential and the
    /// token the layers left in the extensions.
    fn describe(extensions: &http::Extensions) -> String {
        format!(
            "{:?} token={}",
            extensions.get::<Credential>(),
            extensions.get::<AuthorizedToken>().is_some()
        )
    }

    /// Headers as raw `HeaderValue`s, so a test can send a repeated header or
    /// bytes that are not visible ASCII.
    type RawHeaders = Vec<(&'static str, HeaderValue)>;

    async fn axum_full(app: Router, headers: &RawHeaders) -> SeenFull {
        let mut request = Request::builder().uri("/test");
        for (name, value) in headers {
            request = request.header(*name, value.clone());
        }
        let response = app
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let (parts, body) = response.into_parts();
        let body = ::axum::body::to_bytes(body, 64 * 1024).await.unwrap();
        seen_parts(
            &parts.headers,
            parts.status.as_u16(),
            String::from_utf8(body.to_vec()).unwrap(),
        )
    }

    async fn tower_full<S>(service: S, headers: &RawHeaders) -> SeenFull
    where
        S: tower_service::Service<
                http::Request<String>,
                Response = http::Response<String>,
                Error = std::convert::Infallible,
            >,
    {
        let mut request = http::Request::builder().uri("/test");
        for (name, value) in headers {
            request = request.header(*name, value.clone());
        }
        let response = service
            .oneshot(request.body(String::new()).unwrap())
            .await
            .unwrap();
        let (parts, body) = response.into_parts();
        seen_parts(&parts.headers, parts.status.as_u16(), body)
    }

    fn axum_app(layer: AuthLayer) -> Router {
        Router::new()
            .route(
                "/test",
                get(|request: Request| async move { describe(request.extensions()) }),
            )
            .route_layer(layer)
    }

    fn tower_handler(
        request: http::Request<String>,
    ) -> std::future::Ready<Result<http::Response<String>, std::convert::Infallible>> {
        // The content type axum gives a `String` handler response, so only
        // the layers' own differences could make the two stacks disagree.
        let mut response = http::Response::new(describe(request.extensions()));
        response.headers_mut().insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        );
        std::future::ready(Ok(response))
    }

    #[tokio::test]
    async fn the_layers_agree_on_callbacks_repeated_and_unreadable_headers() {
        let jwks = testing::spawn_jwks_server("200 OK", testing::jwks_body()).await;
        let v = validator(&jwks.url);
        let valid = HeaderValue::from_str(&format!("Bearer {}", testing::valid_token())).unwrap();
        let requests: Vec<RawHeaders> = vec![
            vec![],
            vec![("authorization", valid.clone())],
            vec![("authorization", HeaderValue::from_static("Bearer wrong"))],
            // Repeated: only the first value is authenticated, and an optional
            // layer counts a non-blank later value as presented.
            vec![
                ("authorization", valid.clone()),
                ("authorization", HeaderValue::from_static("Bearer wrong")),
            ],
            vec![
                ("authorization", HeaderValue::from_static("Bearer ")),
                ("authorization", HeaderValue::from_static("Bearer secret")),
            ],
            vec![
                ("x-api-key", HeaderValue::from_static("wrong")),
                ("x-api-key", HeaderValue::from_static("secret")),
            ],
            // Not visible ASCII: no candidate, but presented.
            vec![(
                "authorization",
                HeaderValue::from_bytes(b"Bearer s\xe9cret").unwrap(),
            )],
            vec![("x-api-key", HeaderValue::from_bytes(b"\xff").unwrap())],
        ];
        for with_oauth in [false, true] {
            for optional in [false, true] {
                for static_challenge in [None, Some(None)] {
                    let sources = [
                        CredentialSource::authorization_bearer(),
                        CredentialSource::Raw(HeaderName::from_static("x-api-key")),
                    ];
                    let oauth = with_oauth.then(|| Arc::clone(&v));
                    // Both callbacks set their own challenge, content type and
                    // body; the layers must treat them identically.
                    let mut a = AuthLayer::builder()
                        .static_token(STATIC)
                        .optional_oauth(oauth.clone())
                        .sources(sources.clone())
                        .on_reject(|cx| {
                            (
                                StatusCode::IM_A_TEAPOT,
                                [
                                    (WWW_AUTHENTICATE, "Callback x"),
                                    (http::header::CONTENT_TYPE, "application/json"),
                                ],
                                format!("{{\"status\":{}}}", cx.status.as_u16()),
                            )
                                .into_response()
                        });
                    let mut t = HttpAuthLayer::builder()
                        .static_token(STATIC)
                        .optional_oauth(oauth)
                        .sources(sources)
                        .on_reject(|cx: RejectContext<'_>| {
                            http::Response::builder()
                                .status(StatusCode::IM_A_TEAPOT)
                                .header(WWW_AUTHENTICATE, "Callback x")
                                .header(http::header::CONTENT_TYPE, "application/json")
                                .body(format!("{{\"status\":{}}}", cx.status.as_u16()))
                                .unwrap()
                        });
                    if let Some(c) = &static_challenge {
                        a = a.static_challenge(c.clone());
                        t = t.static_challenge(c.clone());
                    }
                    if optional {
                        a = a.optional();
                        t = t.optional();
                    }
                    let (a, t) = (a.build().unwrap(), t.build().unwrap());
                    for headers in &requests {
                        let service = tower_layer::Layer::layer(&t, service_fn(tower_handler));
                        assert_eq!(
                            axum_full(axum_app(a.clone()), headers).await,
                            tower_full(service, headers).await,
                            "oauth={with_oauth} optional={optional} \
                             static_challenge={static_challenge:?} {headers:?}"
                        );
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn the_layers_agree_that_optional_clears_an_outer_layers_credential() {
        let jwks = testing::spawn_jwks_server("200 OK", testing::jwks_body()).await;
        let v = validator(&jwks.url);
        let bearer = HeaderValue::from_str(&format!("Bearer {}", testing::valid_token())).unwrap();
        // An outer strict layer accepts an OAuth token from `X-Outer`; the
        // inner optional layer reads only `Authorization`.
        let outer_sources = [CredentialSource::Bearer(HeaderName::from_static("x-outer"))];
        let requests: Vec<RawHeaders> = vec![
            vec![("x-outer", bearer.clone())],
            vec![
                ("x-outer", bearer.clone()),
                ("authorization", HeaderValue::from_static("Bearer secret")),
            ],
            vec![
                ("x-outer", bearer.clone()),
                ("authorization", HeaderValue::from_static("Bearer wrong")),
            ],
        ];
        let axum_outer = AuthLayer::builder()
            .oauth(Arc::clone(&v))
            .sources(outer_sources.clone())
            .build()
            .unwrap();
        let axum_inner = AuthLayer::builder()
            .static_token(STATIC)
            .optional()
            .build()
            .unwrap();
        let tower_outer = HttpAuthLayer::builder()
            .oauth(Arc::clone(&v))
            .sources(outer_sources)
            .build()
            .unwrap();
        let tower_inner = HttpAuthLayer::builder()
            .static_token(STATIC)
            .optional()
            .build()
            .unwrap();
        let mut outcomes = Vec::new();
        for headers in &requests {
            let app = axum_app(axum_inner.clone()).layer(axum_outer.clone());
            let service = ::tower::ServiceBuilder::new()
                .layer(tower_outer.clone())
                .layer(tower_inner.clone())
                .service(service_fn(tower_handler));
            let a = axum_full(app, headers).await;
            assert_eq!(a, tower_full(service, headers).await, "{headers:?}");
            outcomes.push(a);
        }
        // The pass-through left nothing of the outer layer's token.
        assert_eq!(outcomes[0].3, "None token=false");
        assert_eq!(outcomes[1].3, "Some(StaticToken) token=false");
        assert_eq!(outcomes[2].0, 401);
    }
}
