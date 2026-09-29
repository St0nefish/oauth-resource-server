//! A `tower` authentication layer for any HTTP stack built on the `http` crate's
//! types — hyper, tonic, or a `tower` service of your own — whatever its body
//! types: [`HttpAuthLayer`] (built with [`HttpAuthLayerBuilder`]) wraps a
//! `Service<http::Request<ReqBody>, Response = http::Response<ResBody>>` for any
//! `ReqBody` and any `ResBody`.
//!
//! ```
//! use http::{Request, Response};
//! use oauth_resource_server::http_layer::HttpAuthLayer;
//! use tower::{ServiceBuilder, service_fn};
//!
//! let auth = HttpAuthLayer::builder()
//!     .static_token("example-static-key")
//!     .build()
//!     .unwrap();
//! let service = ServiceBuilder::new().layer(auth).service(service_fn(
//!     |_request: Request<String>| async { Ok::<_, std::convert::Infallible>(Response::new(String::from("ok"))) },
//! ));
//! # let _ = service;
//! ```
//!
//! On an axum app use [`crate::axum::AuthLayer`] instead (feature `axum`, which
//! turns this feature on): it is the same check, with axum's `Response`, the
//! `require_auth` middleware form, and the axum extractors, which answer 500
//! behind an [`HttpAuthLayer`] because they cannot tell it ran.
//!
//! # Behavior
//!
//! Identical to the axum layer, because both run the same code: every
//! configured [`CredentialSource`] contributes one candidate to
//! [`crate::authenticate()`]; an accepted request gets the [`Credential`] (and,
//! for an OAuth token, the [`AuthorizedToken`]) inserted into its extensions;
//! a refused one gets the status and `WWW-Authenticate` challenge
//! [`crate::refusal()`] describes — the validator's challenge on every 401 and
//! 403 when OAuth is configured, otherwise the
//! [`static_challenge`](HttpAuthLayerBuilder::static_challenge)
//! ([`crate::DEFAULT_STATIC_CHALLENGE`] unless set). The refusal's body is
//! `ResBody::default()` (empty, for the usual body types) unless
//! [`on_reject`](HttpAuthLayerBuilder::on_reject) builds one; its status and
//! challenge are set after that callback runs, so it cannot drop or contradict
//! them. [`optional`](HttpAuthLayerBuilder::optional) passes a request that
//! presents no credential through, exactly as the axum layer's does.
//!
//! **Fail-closed by construction.** [`HttpAuthLayerBuilder::build`] refuses to
//! build without a static token or an OAuth validator
//! ([`AuthLayerError::NoCredential`]); the only layer that lets every request
//! through is [`HttpAuthLayer::allow_unauthenticated`], asked for by name (or a
//! [`StaticTokenDecision::Unauthenticated`] handed to
//! [`HttpAuthLayerBuilder::build_with_decision`]). Every configured source
//! header is marked sensitive (`http::HeaderValue::set_sensitive`) on the
//! request before the callback and the inner service see it, and the layer's
//! `Debug` prints the static token as `<redacted>`.
//!
//! # Logging
//!
//! The same outcomes at the same levels as the axum layer, with target
//! `oauth_resource_server::http_layer`: an accepted OAuth token at `debug`
//! (principal, subject, scopes — never the token); a request with no credential
//! at `debug` when OAuth is configured; a request with no credential passed
//! through by an [`optional`](HttpAuthLayerBuilder::optional) layer at `debug`;
//! any other refusal at `warn`, with the reason when OAuth is configured. The
//! reason goes to the log only, never to the caller.
//!
//! # Naming
//!
//! `HttpAuthLayer`, not `AuthLayer`: with the `axum` feature on, both layers
//! are in scope in one application, and two `AuthLayer`s would read as the
//! same type under two paths. The `Http` prefix names what it is generic over
//! — `http::Request<B>` for any `B`. The module is `http_layer`, not `tower`
//! (the feature is still `tower`): a crate-root module named `tower` would
//! make `tower` ambiguous in a downstream module that glob-imports this
//! crate's root and also uses the `tower` crate.
//! [`CredentialSource`], [`RejectContext`] and [`AuthLayerError`] are shared by
//! both layers and are also reachable under `oauth_resource_server::axum`.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use http::header::{AUTHORIZATION, WWW_AUTHENTICATE};
use http::request::Parts;
use http::{HeaderMap, HeaderName, HeaderValue, Request, Response, StatusCode};
use tracing::{debug, warn};

use crate::authenticate::{Credential, authenticate};
use crate::policy::StaticTokenDecision;
use crate::refusal::{DEFAULT_STATIC_CHALLENGE, select};
use crate::token::{AuthorizedToken, TokenRejection, for_log};
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
///
/// Used by both layers: [`HttpAuthLayerBuilder::sources`] here, and the axum
/// layer's `AuthLayerBuilder::sources` (also reachable as
/// `oauth_resource_server::axum::CredentialSource`).
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
    /// `Authorization: Bearer <token>`, the default and only source unless the
    /// layer's builder is given `sources`.
    pub fn authorization_bearer() -> Self {
        Self::Bearer(AUTHORIZATION)
    }

    /// This source's candidate in `headers`, if the header is present, valid
    /// visible ASCII and (for [`CredentialSource::Bearer`]) uses the `Bearer`
    /// scheme. May be blank; [`crate::authenticate()`] treats blank as absent.
    pub(crate) fn candidate<'h>(&self, headers: &'h HeaderMap) -> Option<&'h str> {
        headers.get(self.header_name()).and_then(|v| self.parse(v))
    }

    /// The candidate one value of this source's header carries: `None` when
    /// the value is not visible ASCII, otherwise the (possibly blank) token.
    fn parse<'h>(&self, value: &'h HeaderValue) -> Option<&'h str> {
        let value = value.to_str().ok()?;
        Some(match self {
            Self::Bearer(_) => bearer_credential(value),
            Self::Raw(_) => value,
        })
    }

    /// Whether EVERY value of this source's header — not just the first, which
    /// is the only one ever authenticated — is readable and blank. Used only by
    /// an `optional()` layer, and deliberately stricter than the candidate
    /// parsing ([`bearer_credential`], unchanged): an unreadable
    /// (non-visible-ASCII) value, and for a [`CredentialSource::Bearer`] source
    /// any value [`names_a_token`] says carries a token, count as presented.
    pub(crate) fn presents_nothing(&self, headers: &HeaderMap) -> bool {
        headers.get_all(self.header_name()).iter().all(|v| {
            let Ok(value) = v.to_str() else {
                return false;
            };
            match self {
                Self::Raw(_) => value.trim().is_empty(),
                Self::Bearer(_) => {
                    !names_a_token(value) && bearer_credential(value).trim().is_empty()
                }
            }
        })
    }

    /// The header this source reads.
    pub(crate) fn header_name(&self) -> &HeaderName {
        match self {
            Self::Bearer(name) | Self::Raw(name) => name,
        }
    }
}

/// Whether a `Bearer`-source header value carries a token that an `optional()`
/// layer must not read as "no credential", even though [`bearer_credential`]
/// yields no candidate from it:
///
/// - any value whose auth-scheme is `DPoP` (case-insensitive) — a
///   sender-constrained token this crate cannot accept (RFC 9449), which must
///   be refused rather than served as anonymous;
/// - a `Bearer` scheme separated from a non-blank rest by SP **or HTAB** (RFC
///   9110 §11.4 allows only SP; the strict parsing is not widened, the value
///   is only counted as presented).
///
/// Leading SP/HTAB is skipped. Every other scheme (`Basic`, …) still counts as
/// no bearer credential.
pub(crate) fn names_a_token(value: &str) -> bool {
    let value = value.trim_start_matches([' ', '\t']);
    let (scheme, rest) = value
        .find([' ', '\t'])
        .map_or((value, ""), |i| value.split_at(i));
    scheme.eq_ignore_ascii_case("dpop")
        || (scheme.eq_ignore_ascii_case("bearer") && !rest.trim().is_empty())
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

/// What an `on_reject` callback ([`HttpAuthLayerBuilder::on_reject`], or the
/// axum layer's `AuthLayerBuilder::on_reject`) is told about a refusal.
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

/// Why a layer's builder refused to build ([`HttpAuthLayerBuilder`], or the
/// axum layer's `AuthLayerBuilder`, which reaches this type as
/// `oauth_resource_server::axum::AuthLayerError`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AuthLayerError {
    /// Neither a (non-empty) static token nor an OAuth validator was given. A
    /// layer that could accept nothing would lock every route; one that
    /// accepted everything must be asked for by name.
    #[error(
        "no credential is configured: give a static token and/or an OAuth validator \
         (the layer's allow_unauthenticated constructor is the explicit opt-out)"
    )]
    NoCredential,
    /// The builder's `sources` was given an empty list, so no request could
    /// ever present a credential.
    #[error("no credential source is configured: a request could never present a credential")]
    NoSources,
    /// `build_with_decision`: the decision was made with OAuth on, but no
    /// OAuth validator was given.
    #[error(
        "the static-token decision was made with OAuth enabled, but no OAuth validator \
         was given"
    )]
    DecisionNeedsOAuth,
    /// `build_with_decision`: the decision was made with OAuth off, but an
    /// OAuth validator was given.
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

/// The enforcing part of a layer, shared by [`HttpAuthLayer`] and the axum
/// `AuthLayer`: which credentials are accepted, where they are read from, and
/// the pre-rendered challenges. Built only by [`Gate::build`], so the
/// fail-closed checks cannot be skipped by either layer.
pub(crate) struct Gate {
    pub(crate) static_token: Option<String>,
    pub(crate) oauth: Option<Arc<OAuthValidator>>,
    pub(crate) sources: Vec<CredentialSource>,
    /// The validator's pre-rendered challenges, `(invalid_token,
    /// insufficient_scope)`; `Some` exactly when OAuth is configured (a
    /// challenge that is not a valid header value fails the build instead).
    oauth_challenges: Option<(HeaderValue, HeaderValue)>,
    /// The challenge for a 401 when OAuth is off; `None` when the application
    /// opted out with `static_challenge(None)`.
    pub(crate) static_challenge: Option<HeaderValue>,
    /// `optional()`: pass a request that presents no credential through
    /// instead of refusing it.
    pub(crate) optional: bool,
}

/// What [`Gate::admit`] decided about a request.
pub(crate) enum Admission {
    /// The static token was accepted (and inserted).
    Static,
    /// An OAuth token was accepted (and inserted); returned for the caller's
    /// log line.
    OAuth(AuthorizedToken),
    /// `optional()`: no credential was presented; nothing was inserted.
    PassedThrough,
    /// Refused.
    Refused(TokenRejection),
}

impl Gate {
    /// The fail-closed build both layers' builders end in.
    pub(crate) fn build(
        static_token: Option<String>,
        oauth: Option<Arc<OAuthValidator>>,
        sources: Option<Vec<CredentialSource>>,
        static_challenge: Option<Option<HeaderValue>>,
        optional: bool,
    ) -> Result<Self, AuthLayerError> {
        let static_token = static_token.filter(|t| !t.is_empty());
        if static_token.is_none() && oauth.is_none() {
            return Err(AuthLayerError::NoCredential);
        }
        let sources = sources.unwrap_or_else(|| vec![CredentialSource::authorization_bearer()]);
        if sources.is_empty() {
            return Err(AuthLayerError::NoSources);
        }
        // Fail closed here too: an OAuth layer whose 401s could not carry
        // `resource_metadata` would leave hosted clients unable to start the
        // authorization flow, which is worse than refusing to start.
        let header = |challenge: String| {
            HeaderValue::from_str(&challenge).map_err(|_| AuthLayerError::InvalidChallenge)
        };
        // A validator that fell back to its safe challenges was built from a
        // config whose challenges are not header values: exactly the configs
        // this check refused before the fallback existed, so it still does.
        if oauth.as_ref().is_some_and(|v| v.challenge_fell_back()) {
            return Err(AuthLayerError::InvalidChallenge);
        }
        let oauth_challenges = match &oauth {
            Some(v) => Some((
                header(v.invalid_token_challenge())?,
                header(v.insufficient_scope_challenge())?,
            )),
            None => None,
        };
        let static_challenge = static_challenge
            .unwrap_or_else(|| Some(HeaderValue::from_static(DEFAULT_STATIC_CHALLENGE)));
        Ok(Self {
            static_token,
            oauth,
            sources,
            oauth_challenges,
            static_challenge,
            optional,
        })
    }

    /// The agreement `build_with_decision` requires between a decision and
    /// whether a validator was given.
    pub(crate) fn check_decision(
        decision: &StaticTokenDecision,
        has_oauth: bool,
    ) -> Result<(), AuthLayerError> {
        match (decision.oauth_enabled(), has_oauth) {
            (true, false) => Err(AuthLayerError::DecisionNeedsOAuth),
            (false, true) => Err(AuthLayerError::DecisionWithoutOAuth),
            _ => Ok(()),
        }
    }

    /// Authenticate the request whose `parts` these are: mark the source
    /// headers sensitive, run [`authenticate`] over one candidate per source,
    /// and insert what was accepted into the extensions. Logs nothing; each
    /// layer logs the outcome under its own target.
    pub(crate) async fn admit(&self, parts: &mut Parts) -> Admission {
        // An optional layer's pass-through must mean "this layer accepted
        // nothing": drop whatever an outer layer inserted, so `Option<..>`
        // never hands the handler a credential this layer did not validate.
        // Strict layers keep accumulating, as they always have.
        if self.optional {
            parts.extensions.remove::<Credential>();
            parts.extensions.remove::<AuthorizedToken>();
        }
        // The credential must not reach a `Debug` of the request — ours
        // (`RejectContext`), a tracing layer's, or a handler's.
        for (name, value) in parts.headers.iter_mut() {
            if self.sources.iter().any(|s| s.header_name() == name) {
                value.set_sensitive(true);
            }
        }
        let result = {
            let headers = &parts.headers;
            let candidates = self.sources.iter().filter_map(|s| s.candidate(headers));
            authenticate(
                candidates,
                self.static_token.as_deref(),
                self.oauth.as_deref(),
            )
            .await
        };
        match result {
            Ok(Credential::StaticToken) => {
                parts.extensions.insert(Credential::StaticToken);
                Admission::Static
            }
            Ok(Credential::OAuth(token)) => {
                parts.extensions.insert(token.clone());
                parts.extensions.insert(Credential::OAuth(token.clone()));
                Admission::OAuth(token)
            }
            // `optional()`: pass through only what `authenticate` found no
            // credential in AND where no source header holds anything at all
            // beyond blanks — an unreadable value, or a non-blank later value
            // of a repeated header, is refused like any other `Missing`. An
            // invalid or insufficient credential never reaches this arm:
            // `authenticate` reports `Missing` only with no non-blank candidate.
            Err(TokenRejection::Missing)
                if self.optional
                    && self
                        .sources
                        .iter()
                        .all(|s| s.presents_nothing(&parts.headers)) =>
            {
                Admission::PassedThrough
            }
            Err(rejection) => Admission::Refused(rejection),
        }
    }

    /// The status and challenge for `rejection`: [`crate::refusal()`]'s
    /// decision ([`select`]), over this layer's pre-validated header values.
    pub(crate) fn status_and_challenge(
        &self,
        rejection: &TokenRejection,
    ) -> (StatusCode, Option<&HeaderValue>) {
        let (status, challenge) = select(
            rejection,
            self.oauth_challenges.as_ref().map(|(i, s)| (i, s)),
            self.static_challenge.as_ref(),
        );
        // `select` only ever yields 401 or 403, both valid.
        let status = StatusCode::from_u16(status).unwrap_or(StatusCode::UNAUTHORIZED);
        (status, challenge)
    }

    /// Fix a refusal's status and `WWW-Authenticate` on `response`, whatever an
    /// `on_reject` callback put there. With a challenge, `insert` replaces every
    /// `WWW-Authenticate` value the callback set; with none (no OAuth and
    /// `static_challenge(None)`), the callback's headers are left as they are.
    pub(crate) fn finish<B>(
        &self,
        rejection: &TokenRejection,
        mut response: Response<B>,
    ) -> Response<B> {
        let (status, challenge) = self.status_and_challenge(rejection);
        *response.status_mut() = status;
        if let Some(value) = challenge {
            response
                .headers_mut()
                .insert(WWW_AUTHENTICATE, value.clone());
        }
        response
    }
}

/// Builds the response for a refusal (its body and any extra headers); see
/// [`HttpAuthLayerBuilder::on_reject`]. Implemented for [`EmptyRefusal`] (the
/// default) and for every `Fn(RejectContext<'_>) -> http::Response<B>`.
///
/// Sealed: it can be named in bounds, but not implemented outside this crate,
/// since only [`HttpAuthLayerBuilder::on_reject`] (which takes a closure) can
/// install a refusal builder.
pub trait RefusalResponse<B>: sealed::Sealed<B> {
    /// The response for this refusal, before the layer sets its status and
    /// `WWW-Authenticate` challenge.
    fn refusal_response(&self, cx: RejectContext<'_>) -> Response<B>;
}

/// The default refusal: `B::default()` as the body (empty for the usual body
/// types), no extra headers.
#[derive(Debug, Clone, Copy, Default)]
pub struct EmptyRefusal;

mod sealed {
    /// The private supertrait that seals [`super::RefusalResponse`].
    pub trait Sealed<B> {}

    impl<B: Default> Sealed<B> for super::EmptyRefusal {}

    impl<B, F> Sealed<B> for F where F: Fn(super::RejectContext<'_>) -> http::Response<B> {}
}

impl<B: Default> RefusalResponse<B> for EmptyRefusal {
    fn refusal_response(&self, _cx: RejectContext<'_>) -> Response<B> {
        Response::new(B::default())
    }
}

impl<B, F> RefusalResponse<B> for F
where
    F: Fn(RejectContext<'_>) -> Response<B>,
{
    fn refusal_response(&self, cx: RejectContext<'_>) -> Response<B> {
        self(cx)
    }
}

/// A `tower::Layer` that authenticates every request to the service it wraps,
/// for any `http::Request<ReqBody>` / `http::Response<ResBody>` service; see
/// the [module docs](self). Cheap to clone (two `Arc`s).
///
/// `R` is what builds a refusal's response: [`EmptyRefusal`] unless
/// [`HttpAuthLayerBuilder::on_reject`] set a callback.
///
/// Built once at startup. Nothing in it hot-reloads: a changed static token or
/// OAuth config takes effect when a new layer is built, which in practice means
/// a restart.
pub struct HttpAuthLayer<R = EmptyRefusal> {
    mode: Arc<HttpMode>,
    on_reject: Arc<R>,
}

enum HttpMode {
    Enforce(Gate),
    AllowUnauthenticated,
}

impl<R> Clone for HttpAuthLayer<R> {
    fn clone(&self) -> Self {
        Self {
            mode: Arc::clone(&self.mode),
            on_reject: Arc::clone(&self.on_reject),
        }
    }
}

/// Hand-written so the static token never reaches a log line through `{:?}`.
impl<R> std::fmt::Debug for HttpAuthLayer<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &*self.mode {
            HttpMode::AllowUnauthenticated => f
                .debug_struct("HttpAuthLayer")
                .field("allow_unauthenticated", &true)
                .finish(),
            HttpMode::Enforce(g) => f
                .debug_struct("HttpAuthLayer")
                .field(
                    "static_token",
                    &g.static_token.as_ref().map(|_| "<redacted>"),
                )
                .field("oauth", &g.oauth)
                .field("sources", &g.sources)
                .field("on_reject", &std::any::type_name::<R>())
                .field("static_challenge", &g.static_challenge)
                .field("optional", &g.optional)
                .finish(),
        }
    }
}

impl HttpAuthLayer {
    /// Start building an enforcing layer. Give it a static token, an OAuth
    /// validator, or both; optionally the credential sources (default:
    /// `Authorization: Bearer`), the refusal body
    /// ([`on_reject`](HttpAuthLayerBuilder::on_reject)), and
    /// [`optional`](HttpAuthLayerBuilder::optional). To honour
    /// `accept_static_bearer`, finish with
    /// [`build_with_decision`](HttpAuthLayerBuilder::build_with_decision) and a
    /// [`crate::static_token_policy`] decision.
    ///
    /// # Examples
    ///
    /// ```
    /// use http::HeaderName;
    /// use oauth_resource_server::http_layer::{AuthLayerError, CredentialSource, HttpAuthLayer};
    ///
    /// let auth = HttpAuthLayer::builder()
    ///     .static_token("example-static-key")
    ///     .sources([
    ///         CredentialSource::authorization_bearer(),
    ///         CredentialSource::Raw(HeaderName::from_static("x-api-key")),
    ///     ])
    ///     .build()
    ///     .unwrap();
    /// # let _ = auth;
    ///
    /// // Fail closed: no credential configured is an error, not a pass-through.
    /// assert_eq!(
    ///     HttpAuthLayer::builder().build().unwrap_err(),
    ///     AuthLayerError::NoCredential
    /// );
    /// ```
    pub fn builder() -> HttpAuthLayerBuilder {
        HttpAuthLayerBuilder::default()
    }

    /// A layer that lets EVERY request through, unauthenticated, and inserts no
    /// credential into request extensions. The explicit opt-out; the only
    /// other way to get it is a [`StaticTokenDecision::Unauthenticated`] handed
    /// to [`HttpAuthLayer::from_decision`] or
    /// [`HttpAuthLayerBuilder::build_with_decision`].
    ///
    /// # Security
    ///
    /// Every request reaches the wrapped service. Use it only where something
    /// else (a trusted network, a proxy that authenticates) stands in front.
    pub fn allow_unauthenticated() -> Self {
        Self {
            mode: Arc::new(HttpMode::AllowUnauthenticated),
            on_reject: Arc::new(EmptyRefusal),
        }
    }

    /// The layer a [`crate::static_token_policy`] decision calls for, with the
    /// default source and refusal body. Shorthand for
    /// `HttpAuthLayer::builder().optional_oauth(oauth).build_with_decision(decision)`.
    ///
    /// # Errors
    ///
    /// See [`HttpAuthLayerBuilder::build_with_decision`].
    pub fn from_decision(
        decision: StaticTokenDecision,
        oauth: Option<Arc<OAuthValidator>>,
    ) -> Result<Self, AuthLayerError> {
        Self::builder()
            .optional_oauth(oauth)
            .build_with_decision(decision)
    }
}

impl<R> HttpAuthLayer<R> {
    /// Whether this is the [`HttpAuthLayer::allow_unauthenticated`] pass-through.
    pub fn allows_unauthenticated(&self) -> bool {
        matches!(*self.mode, HttpMode::AllowUnauthenticated)
    }

    /// The OAuth validator, when one is configured.
    pub fn oauth(&self) -> Option<&Arc<OAuthValidator>> {
        match &*self.mode {
            HttpMode::Enforce(g) => g.oauth.as_ref(),
            HttpMode::AllowUnauthenticated => None,
        }
    }

    /// Authenticate `request`: the request to pass on (with the credential in
    /// its extensions), or the refusal to answer with.
    async fn check<ReqBody, ResBody>(
        &self,
        request: Request<ReqBody>,
    ) -> Result<Request<ReqBody>, Response<ResBody>>
    where
        R: RefusalResponse<ResBody>,
    {
        let gate = match &*self.mode {
            HttpMode::AllowUnauthenticated => return Ok(request),
            HttpMode::Enforce(gate) => gate,
        };
        let (mut parts, body) = request.into_parts();
        match gate.admit(&mut parts).await {
            Admission::Static => {}
            Admission::OAuth(token) => debug!(
                path = %parts.uri.path(),
                principal = ?token.principal.as_deref().map(for_log),
                subject = ?token.subject.as_deref().map(for_log),
                scopes = ?token.scopes,
                "OAuth bearer auth accepted"
            ),
            Admission::PassedThrough => debug!(
                path = %parts.uri.path(),
                "No credential presented; optional auth passes the request through"
            ),
            Admission::Refused(rejection) => {
                let path = parts.uri.path();
                match (&gate.oauth, &rejection) {
                    (None, _) => warn!(path = %path, "Bearer auth rejected"),
                    // Every OAuth client's first request carries no credential
                    // (401 → read `resource_metadata` → authorize), so it is
                    // not worth a warning.
                    (Some(_), TokenRejection::Missing) => {
                        debug!(path = %path, "No bearer credential presented");
                    }
                    (Some(_), _) => {
                        warn!(path = %path, reason = ?rejection, "OAuth bearer auth rejected");
                    }
                }
                let (status, _) = gate.status_and_challenge(&rejection);
                let response = self.on_reject.refusal_response(RejectContext {
                    rejection: &rejection,
                    status,
                    request: &parts,
                });
                return Err(gate.finish(&rejection, response));
            }
        }
        Ok(Request::from_parts(parts, body))
    }
}

/// Builder for an enforcing [`HttpAuthLayer`]; see [`HttpAuthLayer::builder`].
pub struct HttpAuthLayerBuilder<R = EmptyRefusal> {
    static_token: Option<String>,
    oauth: Option<Arc<OAuthValidator>>,
    sources: Option<Vec<CredentialSource>>,
    /// `None`: not set, so [`DEFAULT_STATIC_CHALLENGE`].
    static_challenge: Option<Option<HeaderValue>>,
    optional: bool,
    on_reject: R,
}

impl Default for HttpAuthLayerBuilder {
    fn default() -> Self {
        Self {
            static_token: None,
            oauth: None,
            sources: None,
            static_challenge: None,
            optional: false,
            on_reject: EmptyRefusal,
        }
    }
}

/// Hand-written so the static token never reaches a log line through `{:?}`.
impl<R> std::fmt::Debug for HttpAuthLayerBuilder<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpAuthLayerBuilder")
            .field(
                "static_token",
                &self.static_token.as_ref().map(|_| "<redacted>"),
            )
            .field("oauth", &self.oauth)
            .field("sources", &self.sources)
            .field("on_reject", &std::any::type_name::<R>())
            .field("static_challenge", &self.static_challenge)
            .field("optional", &self.optional)
            .finish()
    }
}

impl<R> HttpAuthLayerBuilder<R> {
    /// Accept this static token (compared in constant time). An empty string
    /// counts as no token.
    ///
    /// # Security
    ///
    /// Setting the token here bypasses `accept_static_bearer`, which only
    /// [`crate::static_token_policy`] reads; with OAuth configured, prefer
    /// [`HttpAuthLayerBuilder::build_with_decision`]. The token's length is not
    /// hidden by the comparison, and `Debug` output shows it as `<redacted>`.
    pub fn static_token(mut self, token: impl Into<String>) -> Self {
        self.static_token = Some(token.into());
        self
    }

    /// [`HttpAuthLayerBuilder::static_token`] when `Some`.
    pub fn optional_static_token(mut self, token: Option<String>) -> Self {
        self.static_token = token;
        self
    }

    /// Accept OAuth access tokens this validator accepts.
    pub fn oauth(mut self, validator: Arc<OAuthValidator>) -> Self {
        self.oauth = Some(validator);
        self
    }

    /// [`HttpAuthLayerBuilder::oauth`] when `Some`.
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
    /// and this is ignored. Default: [`crate::DEFAULT_STATIC_CHALLENGE`].
    ///
    /// `None` sends no challenge at all and leaves any `WWW-Authenticate` an
    /// [`on_reject`](Self::on_reject) callback set untouched. That departs from
    /// RFC 9110 §15.5.2 (a 401 MUST carry a challenge); use it only to keep an
    /// existing API's responses unchanged.
    pub fn static_challenge(mut self, challenge: Option<HeaderValue>) -> Self {
        self.static_challenge = Some(challenge);
        self
    }

    /// Let a request that presents NO credential through, unauthenticated, with
    /// nothing inserted into its extensions; a credential that is presented but
    /// refused is refused exactly as without this. "No credential" is decided
    /// exactly as by the axum layer's `optional()` (see its documentation): every
    /// value of every configured source header absent or blank, where a value
    /// that is not visible ASCII, a non-blank later value of a repeated header,
    /// a `DPoP`-scheme value and a tab-separated `Bearer` token all count as
    /// presented. Any [`Credential`]/[`AuthorizedToken`] an outer layer
    /// inserted is removed first.
    ///
    /// # Security
    ///
    /// Not a way around the fail-closed build: [`build`](Self::build) still
    /// requires a static token or an OAuth validator. Every handler behind an
    /// optional layer must treat a request with no [`Credential`] in its
    /// extensions as unauthenticated.
    pub fn optional(mut self) -> Self {
        self.optional = true;
        self
    }

    /// Build a refusal's response (its body and any extra headers, such as
    /// `Content-Type`) — for an API whose errors are, say, JSON. Without it a
    /// refusal's body is `ResBody::default()`.
    ///
    /// The callback shapes the response only; it cannot change the outcome.
    /// Whatever it returns, the status is set to [`RejectContext::status`] and
    /// `WWW-Authenticate` to the layer's challenge, replacing any the callback
    /// set (only with `static_challenge(None)` and no OAuth are the callback's
    /// headers left as they are). Never put [`TokenRejection::Invalid`]'s
    /// reason in the body.
    ///
    /// # Examples
    ///
    /// ```
    /// use http::{Response, header::CONTENT_TYPE};
    /// use oauth_resource_server::http_layer::{HttpAuthLayer, RejectContext};
    ///
    /// let auth = HttpAuthLayer::builder()
    ///     .static_token("example-static-key")
    ///     .on_reject(|cx: RejectContext<'_>| {
    ///         Response::builder()
    ///             .header(CONTENT_TYPE, "application/json")
    ///             .body(format!(r#"{{"error":"{}"}}"#, cx.status.as_u16()))
    ///             .unwrap()
    ///     })
    ///     .build()
    ///     .unwrap();
    /// # let _ = auth;
    /// ```
    pub fn on_reject<B, F>(self, f: F) -> HttpAuthLayerBuilder<F>
    where
        F: Fn(RejectContext<'_>) -> Response<B> + Send + Sync + 'static,
    {
        HttpAuthLayerBuilder {
            static_token: self.static_token,
            oauth: self.oauth,
            sources: self.sources,
            static_challenge: self.static_challenge,
            optional: self.optional,
            on_reject: f,
        }
    }

    /// Build the layer a [`crate::static_token_policy`] decision calls for,
    /// keeping this builder's other settings. The decision's static token (if
    /// any) replaces one set on this builder;
    /// [`StaticTokenDecision::Unauthenticated`] yields the
    /// [`allow_unauthenticated`](HttpAuthLayer::allow_unauthenticated)
    /// pass-through.
    ///
    /// # Errors
    ///
    /// [`AuthLayerError::DecisionNeedsOAuth`] when the decision was made with
    /// OAuth on and no validator was given,
    /// [`AuthLayerError::DecisionWithoutOAuth`] when it was made with OAuth off
    /// (including `Unauthenticated`) and one was given. Otherwise as
    /// [`HttpAuthLayerBuilder::build`].
    pub fn build_with_decision(
        mut self,
        decision: StaticTokenDecision,
    ) -> Result<HttpAuthLayer<R>, AuthLayerError> {
        Gate::check_decision(&decision, self.oauth.is_some())?;
        if decision == StaticTokenDecision::Unauthenticated {
            return Ok(HttpAuthLayer {
                mode: Arc::new(HttpMode::AllowUnauthenticated),
                on_reject: Arc::new(self.on_reject),
            });
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
    pub fn build(self) -> Result<HttpAuthLayer<R>, AuthLayerError> {
        let gate = Gate::build(
            self.static_token,
            self.oauth,
            self.sources,
            self.static_challenge,
            self.optional,
        )?;
        Ok(HttpAuthLayer {
            mode: Arc::new(HttpMode::Enforce(gate)),
            on_reject: Arc::new(self.on_reject),
        })
    }
}

impl<S, R> tower_layer::Layer<S> for HttpAuthLayer<R> {
    type Service = HttpAuthService<S, R>;

    fn layer(&self, inner: S) -> Self::Service {
        HttpAuthService {
            layer: self.clone(),
            inner,
        }
    }
}

/// The service an [`HttpAuthLayer`] wraps another in.
pub struct HttpAuthService<S, R = EmptyRefusal> {
    layer: HttpAuthLayer<R>,
    inner: S,
}

impl<S: Clone, R> Clone for HttpAuthService<S, R> {
    fn clone(&self) -> Self {
        Self {
            layer: self.layer.clone(),
            inner: self.inner.clone(),
        }
    }
}

impl<S: std::fmt::Debug, R> std::fmt::Debug for HttpAuthService<S, R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpAuthService")
            .field("layer", &self.layer)
            .field("inner", &self.inner)
            .finish()
    }
}

impl<S, R, ReqBody, ResBody> tower_service::Service<Request<ReqBody>> for HttpAuthService<S, R>
where
    S: tower_service::Service<Request<ReqBody>, Response = Response<ResBody>>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
    R: RefusalResponse<ResBody> + Send + Sync + 'static,
    ReqBody: Send + 'static,
    ResBody: 'static,
{
    type Response = Response<ResBody>;
    type Error = S::Error;
    type Future =
        Pin<Box<dyn Future<Output = Result<Response<ResBody>, S::Error>> + Send + 'static>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<ReqBody>) -> Self::Future {
        // Call the instance `poll_ready` was driven on and leave a fresh clone in
        // its place (the usual tower pattern for a service moved into a future).
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let layer = self.layer.clone();
        Box::pin(async move {
            // Bound first, so no `ResBody` is held across the inner call and
            // the future is `Send` without requiring `ResBody: Send`.
            let request = match layer.check(request).await {
                Ok(request) => request,
                Err(refusal) => return Ok(refusal),
            };
            inner.call(request).await
        })
    }
}

#[cfg(test)]
mod tests {
    use ::tower::{ServiceExt, service_fn};

    use super::*;
    use crate::testing;

    const STATIC: &str = "secret";

    fn validator(jwks_uri: &str) -> Arc<OAuthValidator> {
        Arc::new(OAuthValidator::new(&testing::resolved_config(jwks_uri)).unwrap())
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

    /// A plain (non-axum) inner service over `String` bodies: 200 with a
    /// description of what the layer inserted, after asserting every
    /// credential header reached it marked sensitive.
    async fn inner(request: Request<String>) -> Result<Response<String>, std::convert::Infallible> {
        for name in ["authorization", "x-api-key"] {
            for value in request.headers().get_all(name) {
                assert!(
                    value.is_sensitive(),
                    "{name} must reach the service sensitive"
                );
            }
        }
        let token = request.extensions().get::<AuthorizedToken>();
        let credential = request.extensions().get::<Credential>();
        let body = match (credential, token) {
            (Some(Credential::OAuth(_)), Some(t)) => format!("oauth {:?}", t.subject),
            (Some(Credential::StaticToken), None) => "static".to_string(),
            (None, None) => "anonymous".to_string(),
            other => panic!("unexpected extensions: {other:?}"),
        };
        Ok(Response::new(body))
    }

    async fn send<R>(layer: &HttpAuthLayer<R>, headers: &[(&str, &str)]) -> Response<String>
    where
        R: RefusalResponse<String> + Send + Sync + 'static,
    {
        let mut request = Request::builder().uri("/test");
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let service = tower_layer::Layer::layer(layer, service_fn(inner));
        service
            .oneshot(request.body(String::new()).unwrap())
            .await
            .unwrap()
    }

    fn challenge<B>(response: &Response<B>) -> Option<&str> {
        response
            .headers()
            .get(WWW_AUTHENTICATE)
            .map(|v| v.to_str().unwrap())
    }

    #[test]
    fn the_builder_fails_closed() {
        assert_eq!(
            HttpAuthLayer::builder().build().unwrap_err(),
            AuthLayerError::NoCredential
        );
        assert_eq!(
            HttpAuthLayer::builder()
                .static_token("")
                .build()
                .unwrap_err(),
            AuthLayerError::NoCredential
        );
        assert_eq!(
            HttpAuthLayer::builder().optional().build().unwrap_err(),
            AuthLayerError::NoCredential
        );
        assert_eq!(
            HttpAuthLayer::builder()
                .static_token(STATIC)
                .sources([])
                .build()
                .unwrap_err(),
            AuthLayerError::NoSources
        );
        assert_eq!(
            HttpAuthLayer::builder()
                .build_with_decision(StaticTokenDecision::OAuthOnly)
                .unwrap_err(),
            AuthLayerError::DecisionNeedsOAuth
        );
        let built = HttpAuthLayer::builder()
            .static_token(STATIC)
            .optional()
            .build()
            .unwrap();
        assert!(!built.allows_unauthenticated() && built.oauth().is_none());
        assert!(
            HttpAuthLayer::builder()
                .build_with_decision(StaticTokenDecision::Unauthenticated)
                .unwrap()
                .allows_unauthenticated()
        );
    }

    #[test]
    fn a_validator_on_its_fallback_challenges_fails_the_build_as_for_axum() {
        let mut cfg = testing::resolved_config("http://127.0.0.1:1/jwks");
        cfg.resource = "https://api.example.test/v1\r\nX-Injected: 1".into();
        let v = Arc::new(OAuthValidator::new(&cfg).unwrap());
        assert_eq!(
            HttpAuthLayer::builder()
                .static_token(STATIC)
                .oauth(Arc::clone(&v))
                .build()
                .unwrap_err(),
            AuthLayerError::InvalidChallenge
        );
        #[cfg(feature = "axum")]
        assert_eq!(
            crate::axum::AuthLayer::builder()
                .oauth(v)
                .build()
                .unwrap_err(),
            AuthLayerError::InvalidChallenge
        );
    }

    #[tokio::test]
    async fn only_the_explicit_opt_out_passes_everything() {
        // Like the axum layer's pass-through, it reads (and marks) no header,
        // so this test's service does not use `inner`'s sensitivity check.
        let layer = HttpAuthLayer::allow_unauthenticated();
        let service = tower_layer::Layer::layer(
            &layer,
            service_fn(|request: Request<String>| async move {
                let inserted = request.extensions().get::<Credential>().is_some()
                    || request.extensions().get::<AuthorizedToken>().is_some();
                assert!(!inserted, "a pass-through inserts nothing");
                Ok::<_, std::convert::Infallible>(Response::new(String::from("anonymous")))
            }),
        );
        for authorization in [None, Some("Bearer junk")] {
            let mut request = Request::builder().uri("/test");
            if let Some(value) = authorization {
                request = request.header("authorization", value);
            }
            let response = service
                .clone()
                .oneshot(request.body(String::new()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response.body(), "anonymous");
        }
    }

    #[tokio::test]
    async fn oauth_accepts_a_valid_token_and_refuses_the_rest_with_the_validators_challenge() {
        let jwks = testing::spawn_jwks_server("200 OK", testing::jwks_body()).await;
        let v = validator(&jwks.url);
        let layer = HttpAuthLayer::builder()
            .oauth(Arc::clone(&v))
            .build()
            .unwrap();

        let bearer = format!("Bearer {}", testing::valid_token());
        let ok = send(&layer, &[("authorization", &bearer)]).await;
        assert_eq!(ok.status(), StatusCode::OK);
        assert!(ok.body().starts_with("oauth "), "{}", ok.body());
        assert_eq!(challenge(&ok), None);

        let cases = [
            (None, 401, v.invalid_token_challenge()),
            (
                Some(format!("Bearer {}", expired_token())),
                401,
                v.invalid_token_challenge(),
            ),
            (
                Some("Bearer not-a-jwt".to_string()),
                401,
                v.invalid_token_challenge(),
            ),
            (
                Some(format!("Bearer {}", unscoped_token())),
                403,
                v.insufficient_scope_challenge(),
            ),
        ];
        for (header, status, expected) in cases {
            let headers: Vec<(&str, &str)> = header
                .iter()
                .map(|h| ("authorization", h.as_str()))
                .collect();
            let response = send(&layer, &headers).await;
            assert_eq!(response.status().as_u16(), status, "{header:?}");
            assert_eq!(challenge(&response), Some(expected.as_str()), "{header:?}");
            assert_eq!(
                response.body(),
                "",
                "the default body is ResBody::default()"
            );
        }
    }

    #[tokio::test]
    async fn static_only_sends_the_static_challenge_unless_opted_out() {
        let default = HttpAuthLayer::builder()
            .static_token(STATIC)
            .build()
            .unwrap();
        let ok = send(&default, &[("authorization", "Bearer secret")]).await;
        assert_eq!(
            (ok.status(), ok.body().as_str()),
            (StatusCode::OK, "static")
        );
        for headers in [&[][..], &[("authorization", "Bearer wrong")][..]] {
            let refused = send(&default, headers).await;
            assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(challenge(&refused), Some(DEFAULT_STATIC_CHALLENGE));
        }

        let custom = HttpAuthLayer::builder()
            .static_token(STATIC)
            .static_challenge(Some(HeaderValue::from_static("ApiKey realm=\"x\"")))
            .build()
            .unwrap();
        assert_eq!(
            challenge(&send(&custom, &[]).await),
            Some("ApiKey realm=\"x\"")
        );

        let none = HttpAuthLayer::builder()
            .static_token(STATIC)
            .static_challenge(None)
            .build()
            .unwrap();
        let refused = send(&none, &[]).await;
        assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(challenge(&refused), None);
    }

    #[tokio::test]
    async fn every_source_header_is_sensitive_for_the_callback_and_the_service() {
        let layer = HttpAuthLayer::builder()
            .static_token(STATIC)
            .sources([
                CredentialSource::authorization_bearer(),
                CredentialSource::Raw(HeaderName::from_static("x-api-key")),
            ])
            .on_reject(|cx: RejectContext<'_>| {
                for name in ["authorization", "x-api-key"] {
                    assert!(cx.request.headers[name].is_sensitive(), "{name}");
                }
                assert!(!format!("{cx:?}").contains("wrong"));
                Response::new(String::from("refused"))
            })
            .build()
            .unwrap();
        // `inner` asserts sensitivity on the accepted path.
        let ok = send(
            &layer,
            &[("authorization", "Bearer wrong"), ("x-api-key", STATIC)],
        )
        .await;
        assert_eq!(ok.status(), StatusCode::OK);
        let refused = send(
            &layer,
            &[("authorization", "Bearer wrong"), ("x-api-key", "wrong")],
        )
        .await;
        assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(refused.body(), "refused");
    }

    #[tokio::test]
    async fn on_reject_shapes_the_body_but_not_the_status_or_the_challenge() {
        let jwks = testing::spawn_jwks_server("200 OK", testing::jwks_body()).await;
        let v = validator(&jwks.url);
        let layer = HttpAuthLayer::builder()
            .oauth(Arc::clone(&v))
            .on_reject(|cx: RejectContext<'_>| {
                Response::builder()
                    .status(StatusCode::IM_A_TEAPOT)
                    .header(WWW_AUTHENTICATE, "Basic realm=\"nope\"")
                    .header("content-type", "application/json")
                    .body(format!("{{\"status\":{}}}", cx.status.as_u16()))
                    .unwrap()
            })
            .build()
            .unwrap();
        let bearer = format!("Bearer {}", unscoped_token());
        let refused = send(&layer, &[("authorization", &bearer)]).await;
        assert_eq!(refused.status(), StatusCode::FORBIDDEN);
        let challenges: Vec<_> = refused.headers().get_all(WWW_AUTHENTICATE).iter().collect();
        assert_eq!(challenges, [v.insufficient_scope_challenge().as_str()]);
        assert_eq!(refused.headers()["content-type"], "application/json");
        assert_eq!(refused.body(), "{\"status\":403}");
    }

    #[tokio::test]
    async fn an_optional_layer_passes_only_a_request_presenting_nothing() {
        let layer = HttpAuthLayer::builder()
            .static_token(STATIC)
            .optional()
            .build()
            .unwrap();
        for headers in [
            &[][..],
            &[("authorization", "Bearer ")][..],
            &[("authorization", "Basic x")][..],
        ] {
            let response = send(&layer, headers).await;
            assert_eq!(
                (response.status(), response.body().as_str()),
                (StatusCode::OK, "anonymous")
            );
        }
        for value in ["Bearer wrong", "DPoP x", "Bearer\tx"] {
            let response = send(&layer, &[("authorization", value)]).await;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{value:?}");
            assert_eq!(challenge(&response), Some(DEFAULT_STATIC_CHALLENGE));
        }
    }

    #[test]
    fn debug_never_prints_the_static_token() {
        let builder = HttpAuthLayer::builder().static_token("hunter2");
        assert!(!format!("{builder:?}").contains("hunter2"));
        let layer = builder.build().unwrap();
        let rendered = format!("{layer:?}");
        assert!(
            !rendered.contains("hunter2") && rendered.contains("<redacted>"),
            "{rendered}"
        );
        let service = tower_layer::Layer::layer(&layer, "inner");
        assert!(!format!("{service:?}").contains("hunter2"));
    }
}
