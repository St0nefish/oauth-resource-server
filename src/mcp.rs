//! An integration helper for [Model Context Protocol](https://modelcontextprotocol.io)
//! servers (feature `mcp`): per-tool scope requirements, enforced before the
//! MCP server sees the request. The rest of this crate is protocol-agnostic;
//! this module is the one place that knows what a JSON-RPC `tools/call` looks
//! like, and it depends on nothing MCP-specific (no MCP SDK — `serde_json`
//! only).
//!
//! An MCP server exposes every tool on one endpoint, so a route-level scope
//! ([`crate::http_layer::RequireScopes`]) cannot tell a read tool from a write
//! tool. [`McpToolScopes`] reads the tool name from the request body instead.
//! Behind the `tower` feature's `HttpAuthLayer`:
//!
//! ```
//! use std::sync::Arc;
//!
//! use bytes::Bytes;
//! use http::{Request, Response};
//! use http_body_util::Full;
//! use oauth_resource_server::OAuthValidator;
//! use oauth_resource_server::http_layer::HttpAuthLayer;
//! use oauth_resource_server::mcp::McpToolScopes;
//! use tower::{ServiceBuilder, service_fn};
//!
//! # fn service(oauth: Arc<OAuthValidator>) {
//! let tool_scopes = McpToolScopes::new()
//!     .default(["mcp:read"])
//!     .tool("write_document", ["mcp:write"])
//!     .tool("delete_document", ["mcp:write", "mcp:admin"]);
//! let mcp = ServiceBuilder::new()
//!     // Outermost first: authenticate, then require each tool's scopes.
//!     .layer(HttpAuthLayer::builder().oauth(oauth).build().unwrap())
//!     .layer(tool_scopes)
//!     .service(service_fn(|_request: Request<Full<Bytes>>| async {
//!         // Your MCP server here.
//!         Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::new())))
//!     }));
//! # let _ = mcp;
//! # }
//! ```
//!
//! Under axum (feature `axum`) it is a `route_layer` on the MCP endpoint,
//! added before (so inside) the `AuthLayer`:
//! `Router::new().nest_service("/mcp", mcp).route_layer(tool_scopes).route_layer(auth)`.
//!
//! # What it enforces
//!
//! For every request the authentication layer in front of it let through
//! (it must sit behind the axum `AuthLayer` or the `tower` feature's
//! `HttpAuthLayer`; without one it answers 500):
//!
//! | Request | Scopes required (all-of, on top of the layer's) |
//! |---|---|
//! | no body (no `Content-Length` above 0, no `Transfer-Encoding`, and a body whose size hint is exactly 0) — the `GET` event stream, `DELETE`, … | the default |
//! | a body, **whatever the method**, whose JSON-RPC message is `tools/call` for a configured tool | that tool's (not the default's) |
//! | a body whose message is `tools/call` for any other tool | the default |
//! | a body whose message is anything else (`initialize`, `tools/list`, a notification, a response) | the default |
//! | a JSON-RPC **batch** (an array) | every scope any of its messages requires: all of them must be authorized, or none is served |
//! | a body that is not JSON, or a `tools/call` without a readable string `params.name`, or a message with a repeated `method`, `params` or `params.name` | the **strictest** set: the default and every tool's scopes together |
//! | a body larger than the [limit](McpToolScopes::body_limit) | refused with 413, unread beyond the limit |
//!
//! Every method is classified, not just `POST`: MCP's own transport sends
//! JSON-RPC in `POST`s only, but another JSON-RPC server may read a
//! `tools/call` from any request with a body.
//!
//! A request whose credential lacks the scopes is refused with 403 and the
//! authentication layer's own refusal (its `on_reject` body), with a
//! `WWW-Authenticate` challenge naming the layer's scopes followed by the
//! ones this request needed — the MCP authorization spec's per-operation
//! challenge. A static token has no scopes, so it is refused the same way
//! whenever scopes are required, unless
//! [`static_token_bypasses_scopes`](McpToolScopes::static_token_bypasses_scopes).
//! A request with no credential (an `optional` layer passed it through) gets
//! the layer's own 401 — before its body is read, whenever any tool or the
//! default requires a scope — and is served when nothing is required.
//! Anything served reaches the MCP server with its body byte-identical.
//!
//! # Tool names are matched exactly
//!
//! A `tools/call` is matched to a [`tool`](McpToolScopes::tool) entry byte
//! for byte on its JSON-decoded `params.name`: no case folding, trimming or
//! Unicode normalization, and any name without an entry gets the default.
//! That is only safe if the MCP server dispatches exactly as well. Register
//! every tool under exactly the name the server dispatches on, and make sure
//! the dispatcher does not normalize: one that also runs `Write_Document`
//! or `write_document ` as `write_document` turns "an unconfigured tool gets
//! the default" into a way around that tool's scopes.
//!
//! # Why fail closed on what it cannot read
//!
//! A body this layer cannot parse is still handed to the MCP server, whose
//! parser may read it differently — and a `tools/call` that slipped past as
//! "not a tool call" would skip its tool's requirement. So nothing this
//! layer cannot classify with certainty is ever given less than the
//! strictest set: an unreadable body, a `tools/call` with no readable tool
//! name, and a message with a repeated member (which two JSON parsers can
//! resolve to different values). A caller holding every scope loses nothing
//! (the server answers a malformed body with its own error); everyone else
//! is refused before it is parsed a second time. An over-limit body is
//! refused rather than passed on, because it could only be passed unread.
//!
//! # Resource use
//!
//! The body is held once (reserved up front when its length is announced),
//! and parsed in a single streaming pass that validates it fully but builds
//! no document: memory beyond the body itself stays small and does not grow
//! with the number of messages in a batch.
//!
//! Reading the body has **no timeout of its own**: a client that trickles
//! a body in slowly (slow-loris) holds the request open for as long as the
//! server lets it. Set a read or request timeout on the server (hyper's
//! `header_read_timeout`, a `tower_http::timeout` layer, or your proxy's),
//! as for any endpoint that reads a body.
//!
//! # Privacy
//!
//! Nothing from the body — tool name, arguments, identifiers — is ever
//! logged; refusals are logged (target `oauth_resource_server::http_layer`,
//! as for [`crate::http_layer::RequireScopes`], with the same stable
//! `auth.*` fields) with the request path and the configured scopes only.
//! Oversized and unreadable bodies are logged at `warn` with the path and
//! the limit; those are not authentication decisions, so they carry no
//! `auth.*` field and are not counted by the `metrics` feature.
//!
//! # Checking scopes in the tool handler instead
//!
//! The layers insert the validated [`crate::AuthorizedToken`] into the
//! request's extensions. An MCP server framework that hands a tool handler
//! the HTTP request parts (rmcp does, as an `Extension<http::request::Parts>`
//! in the tool call's context) can check a scope there, per call:
//!
//! ```
//! use http::request::Parts;
//! use oauth_resource_server::AuthorizedToken;
//!
//! fn may_write(parts: &Parts) -> bool {
//!     parts
//!         .extensions
//!         .get::<AuthorizedToken>()
//!         .is_some_and(|token| token.require_scopes(&["mcp:write"]).is_ok())
//! }
//! ```
//!
//! That answers inside the protocol (a tool error), not with the 403 and
//! challenge a client can re-authorize from; [`McpToolScopes`] does the
//! latter.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::{Buf, Bytes};
use http::{Request, Response, StatusCode};
use http_body::Body;
use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use tracing::warn;

use crate::http_layer::{InvalidScope, ScopeVerdict, checked_scopes, judge_scopes, scope_refusal};
use crate::token::TokenRejection;

/// The default [`McpToolScopes::body_limit`]: 1 MiB.
pub const DEFAULT_BODY_LIMIT: usize = 1024 * 1024;
/// The smallest [`McpToolScopes::body_limit`] allowed: 4 KiB.
pub const MIN_BODY_LIMIT: usize = 4 * 1024;
/// The largest [`McpToolScopes::body_limit`] allowed: 64 MiB.
pub const MAX_BODY_LIMIT: usize = 64 * 1024 * 1024;

/// Per-tool scope requirements for an MCP server's JSON-RPC endpoint, as a
/// `tower::Layer`; see the [module docs](self) for what it enforces.
///
/// Built once at startup, with a builder-style API: every method takes and
/// returns the value.
///
/// Tool names are matched **exactly** (byte for byte, after JSON
/// decoding); see [`tool`](Self::tool)'s `# Security` section before
/// relying on it.
///
/// # Panics
///
/// [`default`](Self::default) and [`tool`](Self::tool) panic on a scope that
/// is not an RFC 6749 §3.3 scope-token (empty, or holding a space, `"`,
/// `\`, a control or non-ASCII character) — no token can carry one — and
/// [`body_limit`](Self::body_limit) outside
/// [`MIN_BODY_LIMIT`]`..=`[`MAX_BODY_LIMIT`]. They are for literals in code;
/// the `try_` forms ([`try_default`](Self::try_default),
/// [`try_tool`](Self::try_tool), [`try_body_limit`](Self::try_body_limit))
/// return a [`McpScopesError`] instead, for settings read from
/// configuration.
#[derive(Clone, Debug)]
pub struct McpToolScopes {
    rules: Arc<Rules>,
}

#[derive(Clone, Debug)]
struct Rules {
    default: Vec<String>,
    /// In the order configured; a repeated name replaces the earlier entry.
    tools: Vec<(String, Vec<String>)>,
    /// `default` followed by every tool's scopes, deduplicated.
    strictest: Vec<String>,
    body_limit: usize,
    static_bypasses: bool,
}

impl Rules {
    fn with_strictest(mut self) -> Self {
        let mut all: Vec<String> = Vec::new();
        for scope in self
            .default
            .iter()
            .chain(self.tools.iter().flat_map(|(_, scopes)| scopes))
        {
            if !all.contains(scope) {
                all.push(scope.clone());
            }
        }
        self.strictest = all;
        self
    }

    fn for_tool(&self, name: &str) -> &[String] {
        self.tools
            .iter()
            .find(|(tool, _)| tool == name)
            .map_or(&self.default, |(_, scopes)| scopes)
    }

    /// The scopes a request body requires (see the module docs' table),
    /// folded message by message as the body is parsed: what is kept is one
    /// flag per configured tool, never the messages themselves, so a batch of
    /// any length costs no more memory than one call.
    fn for_body(&self, body: &[u8]) -> Vec<String> {
        let mut needs_default = false;
        let mut needs_strictest = false;
        let mut needs_tool = vec![false; self.tools.len()];
        let mut seen_any = false;
        let readable = for_each_message(body, &mut |message| {
            seen_any = true;
            match message {
                Message::NotToolCall => needs_default = true,
                Message::ToolCall(name) => {
                    match self.tools.iter().position(|(tool, _)| *tool == name) {
                        Some(i) => needs_tool[i] = true,
                        None => needs_default = true,
                    }
                }
                Message::Ambiguous => needs_strictest = true,
            }
        });
        if !readable || needs_strictest {
            return self.strictest.clone();
        }
        if !seen_any {
            // An empty batch: nothing to call.
            return self.default.clone();
        }
        // The default first, then each needed tool's, in configuration order.
        let mut all: Vec<String> = Vec::new();
        let needed = needs_default
            .then_some(&self.default[..])
            .into_iter()
            .chain(
                self.tools
                    .iter()
                    .zip(&needs_tool)
                    .filter(|(_, needed)| **needed)
                    .map(|((_, scopes), _)| &scopes[..]),
            );
        for scopes in needed {
            for scope in scopes {
                if !all.contains(scope) {
                    all.push(scope.clone());
                }
            }
        }
        all
    }
}

/// Why [`McpToolScopes`]' fallible constructors ([`try_default`](McpToolScopes::try_default),
/// [`try_tool`](McpToolScopes::try_tool), [`try_body_limit`](McpToolScopes::try_body_limit))
/// refused a setting. `#[non_exhaustive]`: match with a wildcard arm.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum McpScopesError {
    /// A scope is not an RFC 6749 §3.3 scope-token; the error names it.
    #[error(transparent)]
    InvalidScope(#[from] InvalidScope),
    /// A body limit outside [`MIN_BODY_LIMIT`]`..=`[`MAX_BODY_LIMIT`].
    #[error("body limit {0} is outside {MIN_BODY_LIMIT}..={MAX_BODY_LIMIT}")]
    BodyLimitOutOfRange(usize),
}

// `default` is the name the requirement reads best under; this type has no
// meaningful `Default` (`new` is it), and a `Default` impl would make
// `McpToolScopes::default()` resolve to the inherent method anyway.
#[allow(clippy::new_without_default)]
impl McpToolScopes {
    /// No requirement at all: every tool, and every other request, needs
    /// only what the authentication layer requires, until
    /// [`default`](Self::default) and [`tool`](Self::tool) add some.
    pub fn new() -> Self {
        Self {
            rules: Arc::new(Rules {
                default: Vec::new(),
                tools: Vec::new(),
                strictest: Vec::new(),
                body_limit: DEFAULT_BODY_LIMIT,
                static_bypasses: false,
            }),
        }
    }

    fn update(self, f: impl FnOnce(&mut Rules)) -> Self {
        let mut rules = Arc::unwrap_or_clone(self.rules);
        f(&mut rules);
        Self {
            rules: Arc::new(rules.with_strictest()),
        }
    }

    /// The scopes every request needs unless a [`tool`](Self::tool) entry
    /// says otherwise: every request without a body, every JSON-RPC message
    /// other than `tools/call`, and a `tools/call` for a tool with no entry.
    /// Replaces a default given earlier. For literals in code; see
    /// [`try_default`](Self::try_default) for scopes from configuration.
    ///
    /// # Panics
    ///
    /// On a scope that is not a scope-token; see the type's docs.
    pub fn default(self, scopes: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.try_default(scopes)
            .unwrap_or_else(|e| panic!("McpToolScopes::default: {e}"))
    }

    /// [`default`](Self::default) for scopes read from configuration.
    ///
    /// # Errors
    ///
    /// [`McpScopesError::InvalidScope`], naming the first scope that is not
    /// a scope-token.
    pub fn try_default(
        self,
        scopes: impl IntoIterator<Item = impl Into<String>>,
    ) -> Result<Self, McpScopesError> {
        let scopes = checked_scopes(scopes)?;
        Ok(self.update(|rules| rules.default = scopes))
    }

    /// The scopes a `tools/call` for the tool named `name` needs, instead of
    /// the [`default`](Self::default). An empty list means that tool needs
    /// nothing beyond the authentication layer's own scopes. Replaces an
    /// entry for the same name. For literals in code; see
    /// [`try_tool`](Self::try_tool) for a map read from configuration.
    ///
    /// # Security
    ///
    /// `name` is matched **exactly**: byte for byte against the tool name
    /// the request carries, after JSON decoding (`\u0041` is `A`), with no
    /// case folding, trimming or Unicode normalization. A `tools/call` for
    /// any other name gets the default. So register each tool under exactly
    /// the name your MCP server dispatches on, and make that dispatch exact
    /// too: a server that also runs `Write_Document` or `write_document `
    /// as `write_document` would let a caller reach it under a spelling
    /// this layer treats as unconfigured, with only the default's scopes.
    ///
    /// # Panics
    ///
    /// On a scope that is not a scope-token; see the type's docs.
    pub fn tool(
        self,
        name: impl Into<String>,
        scopes: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.try_tool(name, scopes)
            .unwrap_or_else(|e| panic!("McpToolScopes::tool: {e}"))
    }

    /// [`tool`](Self::tool) for a tool-to-scopes map read from
    /// configuration. The same exact name matching applies.
    ///
    /// # Errors
    ///
    /// [`McpScopesError::InvalidScope`], naming the first scope that is not
    /// a scope-token.
    ///
    /// # Examples
    ///
    /// ```
    /// use oauth_resource_server::mcp::{McpScopesError, McpToolScopes};
    ///
    /// // As read from a config file.
    /// let configured = [("write_document", vec!["docs:write"]), ("purge", vec!["docs admin"])];
    /// let mut layer = McpToolScopes::new().try_default(["docs:read"]).unwrap();
    /// let mut refused = None;
    /// for (tool, scopes) in configured {
    ///     match layer.clone().try_tool(tool, scopes) {
    ///         Ok(next) => layer = next,
    ///         Err(McpScopesError::InvalidScope(e)) => refused = Some(e.scope().to_string()),
    ///         Err(other) => panic!("{other}"),
    ///     }
    /// }
    /// assert_eq!(refused.as_deref(), Some("docs admin"));
    /// # let _ = layer;
    /// ```
    pub fn try_tool(
        self,
        name: impl Into<String>,
        scopes: impl IntoIterator<Item = impl Into<String>>,
    ) -> Result<Self, McpScopesError> {
        let name = name.into();
        let scopes = checked_scopes(scopes)?;
        Ok(self.update(|rules| {
            rules.tools.retain(|(tool, _)| *tool != name);
            rules.tools.push((name, scopes));
        }))
    }

    /// The largest request body read, in bytes ([`DEFAULT_BODY_LIMIT`]
    /// unless set). A body announced larger (`Content-Length`, or the
    /// body's own size hint) is refused with 413 before any of it is read;
    /// one that turns out larger is refused as soon as a chunk would cross
    /// the limit, so no more than the limit is ever held. For a literal in
    /// code; see [`try_body_limit`](Self::try_body_limit) for a configured
    /// value.
    ///
    /// # Panics
    ///
    /// Outside [`MIN_BODY_LIMIT`]`..=`[`MAX_BODY_LIMIT`].
    pub fn body_limit(self, bytes: usize) -> Self {
        self.try_body_limit(bytes)
            .unwrap_or_else(|e| panic!("McpToolScopes::body_limit: {e}"))
    }

    /// [`body_limit`](Self::body_limit) for a configured value.
    ///
    /// # Errors
    ///
    /// [`McpScopesError::BodyLimitOutOfRange`] outside
    /// [`MIN_BODY_LIMIT`]`..=`[`MAX_BODY_LIMIT`].
    pub fn try_body_limit(self, bytes: usize) -> Result<Self, McpScopesError> {
        if !(MIN_BODY_LIMIT..=MAX_BODY_LIMIT).contains(&bytes) {
            return Err(McpScopesError::BodyLimitOutOfRange(bytes));
        }
        Ok(self.update(|rules| rules.body_limit = bytes))
    }

    /// Let a static token through whatever the request requires, instead
    /// of refusing it with 403.
    ///
    /// # Security
    ///
    /// The static token then reaches every tool. Opt in only where it is
    /// meant to be a full-access key.
    pub fn static_token_bypasses_scopes(self) -> Self {
        self.update(|rules| rules.static_bypasses = true)
    }

    /// The scopes `tool` requires: its own entry, or the default.
    pub fn scopes_for_tool(&self, tool: &str) -> &[String] {
        self.rules.for_tool(tool)
    }
}

impl<S> tower_layer::Layer<S> for McpToolScopes {
    type Service = McpToolScopesService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        McpToolScopesService {
            rules: Arc::clone(&self.rules),
            inner,
        }
    }
}

/// The service a [`McpToolScopes`] layer wraps another in.
///
/// Generic over the request body, which it must be able to rebuild from the
/// bytes it read (`ReqBody: From<Bytes>`, as `axum::body::Body` and
/// `http_body_util::Full<Bytes>` are); a server on a body type that is not
/// (hyper's `Incoming`) maps it to one first. Trailers of a `POST` body are
/// not passed on.
#[derive(Clone, Debug)]
pub struct McpToolScopesService<S> {
    rules: Arc<Rules>,
    inner: S,
}

/// Why a `POST` body could not be read.
enum ReadError {
    TooLarge,
    Failed,
}

/// Read `body` whole, refusing it as soon as it is known to exceed `limit`.
/// `announced` (the larger of `Content-Length` and the size hint's lower
/// bound, already checked against `limit`) is reserved up front, so a body
/// that arrives as announced is held once, never in a doubling buffer.
async fn read_capped<B: Body + Unpin>(
    mut body: B,
    limit: usize,
    announced: u64,
) -> Result<Bytes, ReadError> {
    if body.size_hint().lower() > limit as u64 {
        return Err(ReadError::TooLarge);
    }
    let reserve = usize::try_from(announced).map_or(limit, |n| n.min(limit));
    let mut buf: Vec<u8> = Vec::with_capacity(reserve);
    loop {
        let frame = std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await;
        match frame {
            None => return Ok(Bytes::from(buf)),
            Some(Err(_)) => return Err(ReadError::Failed),
            Some(Ok(frame)) => {
                // Trailers carry no JSON-RPC and are dropped.
                let Ok(mut data) = frame.into_data() else {
                    continue;
                };
                if buf.len().saturating_add(data.remaining()) > limit {
                    return Err(ReadError::TooLarge);
                }
                while data.has_remaining() {
                    let chunk = data.chunk();
                    let n = chunk.len();
                    buf.extend_from_slice(chunk);
                    data.advance(n);
                }
            }
        }
    }
}

/// A response with `status` and an empty (default) body.
fn plain<B: Default>(status: StatusCode) -> Response<B> {
    let mut response = Response::new(B::default());
    *response.status_mut() = status;
    response
}

impl<S, ReqBody, ResBody> tower_service::Service<Request<ReqBody>> for McpToolScopesService<S>
where
    S: tower_service::Service<Request<ReqBody>, Response = Response<ResBody>>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
    ReqBody: Body + From<Bytes> + Send + 'static,
    ReqBody::Data: Send,
    ReqBody::Error: Send,
    ResBody: Default + 'static,
{
    type Response = Response<ResBody>;
    type Error = S::Error;
    type Future =
        Pin<Box<dyn Future<Output = Result<Response<ResBody>, S::Error>> + Send + 'static>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<ReqBody>) -> Self::Future {
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let rules = Arc::clone(&self.rules);
        Box::pin(async move {
            let (parts, body) = request.into_parts();
            // No layer in front: refuse before reading anything.
            if let ScopeVerdict::NoLayer = judge_scopes(&parts, &[], false) {
                return Ok(scope_refusal(
                    &parts,
                    &TokenRejection::Missing,
                    &[],
                    "McpToolScopes",
                ));
            }
            let content_length = parts
                .headers
                .get(http::header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.trim().parse::<u64>().ok());
            let hint = body.size_hint();
            // Any method: a JSON-RPC server other than MCP's Streamable HTTP
            // transport may read a `tools/call` from a `GET` or a `PUT` just
            // as well, so a body is classified wherever one may be present.
            let has_body = hint.upper() != Some(0)
                || content_length.is_some_and(|n| n > 0)
                || parts.headers.contains_key(http::header::TRANSFER_ENCODING);
            // No credential (an `optional()` layer passed the request): when
            // any tool needs a scope, refuse before reading the body — it
            // could need one, and an anonymous caller could not satisfy it.
            if has_body
                && !rules.strictest.is_empty()
                && parts
                    .extensions
                    .get::<crate::authenticate::Credential>()
                    .is_none()
            {
                return Ok(scope_refusal(
                    &parts,
                    &TokenRejection::Missing,
                    &rules.strictest,
                    "McpToolScopes",
                ));
            }
            let (required, body) = if has_body {
                let announced = content_length.unwrap_or(0).max(hint.lower());
                let read = if announced > rules.body_limit as u64 {
                    Err(ReadError::TooLarge)
                } else {
                    read_capped(Box::pin(body), rules.body_limit, announced).await
                };
                let bytes = match read {
                    Ok(bytes) => bytes,
                    Err(ReadError::TooLarge) => {
                        warn!(
                            path = %parts.uri.path(),
                            limit = rules.body_limit,
                            "MCP request body exceeds the limit; refusing it unread"
                        );
                        return Ok(plain(StatusCode::PAYLOAD_TOO_LARGE));
                    }
                    Err(ReadError::Failed) => {
                        warn!(
                            path = %parts.uri.path(),
                            "MCP request body could not be read; refusing the request"
                        );
                        return Ok(plain(StatusCode::BAD_REQUEST));
                    }
                };
                (rules.for_body(&bytes), ReqBody::from(bytes))
            } else {
                (rules.default.clone(), body)
            };
            match judge_scopes(&parts, &required, rules.static_bypasses) {
                ScopeVerdict::Pass => inner.call(Request::from_parts(parts, body)).await,
                ScopeVerdict::Refuse(rejection) => Ok(scope_refusal(
                    &parts,
                    &rejection,
                    &required,
                    "McpToolScopes",
                )),
                ScopeVerdict::NoLayer => Ok(scope_refusal(
                    &parts,
                    &TokenRejection::Missing,
                    &required,
                    "McpToolScopes",
                )),
            }
        })
    }
}

/// One JSON-RPC message, as far as tool scopes are concerned.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Message {
    /// Anything but a `tools/call` request.
    NotToolCall,
    /// A `tools/call` for this tool.
    ToolCall(String),
    /// A `tools/call` with no readable string `params.name`, a message with
    /// a repeated `method`, `params` or `params.name` member, or a batch
    /// element that is not an object: not classified with certainty.
    Ambiguous,
}

/// Every message of a body, collected (tests and the fuzz oracle only; the
/// request path folds them as they come, see [`for_each_message`]).
#[cfg(any(test, fuzzing))]
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Classified {
    /// One message, or a batch's messages in order (possibly none).
    Messages(Vec<Message>),
    /// Not JSON, or JSON that is neither an object nor an array.
    Unreadable,
}

/// [`for_each_message`], collected.
#[cfg(any(test, fuzzing))]
pub(crate) fn classify(body: &[u8]) -> Classified {
    let mut messages = Vec::new();
    if for_each_message(body, &mut |m| messages.push(m)) {
        Classified::Messages(messages)
    } else {
        Classified::Unreadable
    }
}

/// Hand every message of `body` — one object, or each element of a batch
/// array, in order — to `sink`, in ONE streaming pass that builds nothing
/// but a short-lived `String` per tool name. Returns `false` when the body is
/// not a JSON object or array, or is not valid JSON anywhere in it; `sink`
/// may then have seen some messages already, and the caller must discard
/// them (the request path answers `false` with the strictest set).
///
/// Every value it does not look at is still fully validated
/// ([`Validate`]: every string's UTF-8 and escapes, every number's range),
/// so it refuses exactly what `serde_json::from_slice::<Value>` refuses —
/// the `mcp_tool_calls` fuzz target checks that against `Value` — without
/// materializing the document (which costs about 16× the body). Bounded by
/// `serde_json`'s recursion limit; never panics.
pub(crate) fn for_each_message(body: &[u8], sink: &mut dyn FnMut(Message)) -> bool {
    let mut deserializer = serde_json::Deserializer::from_slice(body);
    TopSeed { sink }.deserialize(&mut deserializer).is_ok() && deserializer.end().is_ok()
}

/// Accept every scalar JSON value (after the deserializer has validated it)
/// as `$value`.
macro_rules! accept_scalars {
    ($value:expr) => {
        fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
            Ok($value)
        }
        fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
            Ok($value)
        }
        fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
            Ok($value)
        }
        fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
            Ok($value)
        }
        fn visit_str<E>(self, _: &str) -> Result<Self::Value, E> {
            Ok($value)
        }
        fn visit_unit<E>(self) -> Result<Self::Value, E> {
            Ok($value)
        }
    };
}

/// Any JSON value, validated in full and then dropped: the stand-in for
/// `IgnoredAny`, which skips a number or a string without checking it.
struct Validate;

impl<'de> Deserialize<'de> for Validate {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Validate;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("any JSON value")
            }
            accept_scalars!(Validate);
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Validate, A::Error> {
                while map.next_entry::<Validate, Validate>()?.is_some() {}
                Ok(Validate)
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Validate, A::Error> {
                while seq.next_element::<Validate>()?.is_some() {}
                Ok(Validate)
            }
        }
        deserializer.deserialize_any(V)
    }
}

/// The top-level value: one message (an object) or a batch (an array);
/// anything else is an error, i.e. unreadable.
struct TopSeed<'s> {
    sink: &'s mut dyn FnMut(Message),
}

impl<'de> DeserializeSeed<'de> for TopSeed<'_> {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        struct V<'s>(&'s mut dyn FnMut(Message));
        impl<'de> Visitor<'de> for V<'_> {
            type Value = ();
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a JSON-RPC message or batch")
            }
            fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<(), A::Error> {
                let message = read_message(map)?;
                (self.0)(message);
                Ok(())
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
                while seq
                    .next_element_seed(ElementSeed { sink: &mut *self.0 })?
                    .is_some()
                {}
                Ok(())
            }
        }
        deserializer.deserialize_any(V(self.sink))
    }
}

/// One batch element: a message, or anything else (`Ambiguous`).
struct ElementSeed<'s> {
    sink: &'s mut dyn FnMut(Message),
}

impl<'de> DeserializeSeed<'de> for ElementSeed<'_> {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Message;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("any JSON value")
            }
            accept_scalars!(Message::Ambiguous);
            fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Message, A::Error> {
                read_message(map)
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Message, A::Error> {
                while seq.next_element::<Validate>()?.is_some() {}
                Ok(Message::Ambiguous)
            }
        }
        let message = deserializer.deserialize_any(V)?;
        (self.sink)(message);
        Ok(())
    }
}

/// An object key, compared without allocating.
enum Key {
    Method,
    Params,
    Name,
    Other,
}

impl<'de> Deserialize<'de> for Key {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;
        impl Visitor<'_> for V {
            type Value = Key;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("an object key")
            }
            fn visit_str<E>(self, key: &str) -> Result<Key, E> {
                Ok(match key {
                    "method" => Key::Method,
                    "params" => Key::Params,
                    "name" => Key::Name,
                    _ => Key::Other,
                })
            }
        }
        deserializer.deserialize_any(V)
    }
}

/// A value read as a string when it is one (`Some`); any other value is
/// validated, consumed, and read as `None`.
struct StringValue(Option<String>);

impl<'de> Deserialize<'de> for StringValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = StringValue;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("any JSON value")
            }
            fn visit_bool<E>(self, _: bool) -> Result<StringValue, E> {
                Ok(StringValue(None))
            }
            fn visit_i64<E>(self, _: i64) -> Result<StringValue, E> {
                Ok(StringValue(None))
            }
            fn visit_u64<E>(self, _: u64) -> Result<StringValue, E> {
                Ok(StringValue(None))
            }
            fn visit_f64<E>(self, _: f64) -> Result<StringValue, E> {
                Ok(StringValue(None))
            }
            fn visit_unit<E>(self) -> Result<StringValue, E> {
                Ok(StringValue(None))
            }
            fn visit_str<E>(self, v: &str) -> Result<StringValue, E> {
                Ok(StringValue(Some(v.to_string())))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<StringValue, A::Error> {
                while map.next_entry::<Validate, Validate>()?.is_some() {}
                Ok(StringValue(None))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<StringValue, A::Error> {
                while seq.next_element::<Validate>()?.is_some() {}
                Ok(StringValue(None))
            }
        }
        deserializer.deserialize_any(V)
    }
}

/// What a message's `params` says about the tool name: `Some` only for an
/// object with exactly one `name`, a string.
struct ParamsName(Option<String>);

impl<'de> Deserialize<'de> for ParamsName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = ParamsName;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("any JSON value")
            }
            accept_scalars!(ParamsName(None));
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<ParamsName, A::Error> {
                let mut name: Option<Option<String>> = None;
                let mut repeated = false;
                while let Some(key) = map.next_key::<Key>()? {
                    match key {
                        Key::Name if name.is_none() => {
                            name = Some(map.next_value::<StringValue>()?.0);
                        }
                        Key::Name => {
                            repeated = true;
                            map.next_value::<Validate>()?;
                        }
                        _ => {
                            map.next_value::<Validate>()?;
                        }
                    }
                }
                Ok(ParamsName(match (repeated, name) {
                    (false, Some(name)) => name,
                    _ => None,
                }))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<ParamsName, A::Error> {
                while seq.next_element::<Validate>()?.is_some() {}
                Ok(ParamsName(None))
            }
        }
        deserializer.deserialize_any(V)
    }
}

/// Read one message object.
fn read_message<'de, A: MapAccess<'de>>(mut map: A) -> Result<Message, A::Error> {
    let mut method: Option<Option<String>> = None;
    let mut params: Option<Option<String>> = None;
    let mut repeated = false;
    while let Some(key) = map.next_key::<Key>()? {
        match key {
            Key::Method if method.is_none() => method = Some(map.next_value::<StringValue>()?.0),
            Key::Params if params.is_none() => params = Some(map.next_value::<ParamsName>()?.0),
            Key::Method | Key::Params => {
                repeated = true;
                map.next_value::<Validate>()?;
            }
            _ => {
                map.next_value::<Validate>()?;
            }
        }
    }
    Ok(match (repeated, method) {
        (true, _) => Message::Ambiguous,
        (false, Some(Some(method))) if method == "tools/call" => match params {
            Some(Some(name)) => Message::ToolCall(name),
            _ => Message::Ambiguous,
        },
        _ => Message::NotToolCall,
    })
}

#[cfg(all(test, feature = "axum"))]
mod service_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classification() {
        let one = |json: &str| classify(json.as_bytes());
        let msgs = |m: Vec<Message>| Classified::Messages(m);
        assert_eq!(
            one(
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"w","arguments":{"name":"x"}}}"#
            ),
            msgs(vec![Message::ToolCall("w".into())])
        );
        assert_eq!(
            one(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#),
            msgs(vec![Message::NotToolCall])
        );
        // A response, a notification: not tool calls.
        assert_eq!(
            one(r#"{"jsonrpc":"2.0","id":1,"result":{}}"#),
            msgs(vec![Message::NotToolCall])
        );
        assert_eq!(
            one(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#),
            msgs(vec![Message::NotToolCall])
        );
        // A method that is not a string is not `tools/call`.
        assert_eq!(one(r#"{"method":7}"#), msgs(vec![Message::NotToolCall]));
        // Escapes are decoded exactly as any JSON parser decodes them.
        assert_eq!(
            one(r#"{"method":"tools\/call","params":{"name":"w"}}"#),
            msgs(vec![Message::ToolCall("w".into())])
        );
        // No readable name: ambiguous.
        for json in [
            r#"{"method":"tools/call"}"#,
            r#"{"method":"tools/call","params":{}}"#,
            r#"{"method":"tools/call","params":{"name":1}}"#,
            r#"{"method":"tools/call","params":["w"]}"#,
            r#"{"method":"tools/call","params":{"name":"r","name":"w"}}"#,
            r#"{"method":"tools/list","method":"tools/call","params":{"name":"w"}}"#,
            r#"{"method":"tools/call","params":{"name":"r"},"params":{"name":"w"}}"#,
        ] {
            assert_eq!(one(json), msgs(vec![Message::Ambiguous]), "{json}");
        }
        // Batches, element by element; a non-object element is ambiguous.
        assert_eq!(
            one(r#"[{"method":"tools/list"},{"method":"tools/call","params":{"name":"w"}},3]"#),
            msgs(vec![
                Message::NotToolCall,
                Message::ToolCall("w".into()),
                Message::Ambiguous
            ])
        );
        assert_eq!(one("[]"), msgs(vec![]));
        // Not JSON, or not an object or array.
        for body in [
            "",
            "{",
            "nope",
            "7",
            "\"tools/call\"",
            "{} {}",
            "\u{feff}{}",
        ] {
            assert_eq!(one(body), Classified::Unreadable, "{body:?}");
        }
    }

    fn rules() -> McpToolScopes {
        McpToolScopes::new()
            .default(["mcp:read"])
            .tool("write_document", ["mcp:write"])
            .tool("admin", ["mcp:write", "mcp:admin"])
    }

    #[test]
    fn requirements_per_body() {
        let r = rules();
        let r = &r.rules;
        let req = |json: &str| r.for_body(json.as_bytes());
        assert_eq!(
            req(r#"{"method":"tools/call","params":{"name":"write_document"}}"#),
            ["mcp:write"]
        );
        assert_eq!(
            req(r#"{"method":"tools/call","params":{"name":"other"}}"#),
            ["mcp:read"]
        );
        assert_eq!(req(r#"{"method":"initialize"}"#), ["mcp:read"]);
        let strictest = ["mcp:read", "mcp:write", "mcp:admin"];
        assert_eq!(req("not json"), strictest);
        assert_eq!(req(r#"{"method":"tools/call"}"#), strictest);
        assert_eq!(
            req(
                r#"[{"method":"tools/call","params":{"name":"write_document"}},{"method":"tools/list"}]"#
            ),
            // The default first, then each tool's, in configuration order.
            ["mcp:read", "mcp:write"]
        );
        assert_eq!(req("[]"), ["mcp:read"]);
        // Anything a strict JSON parser refuses is unreadable, even in a
        // member nobody looks at: an out-of-range number, invalid UTF-8.
        assert_eq!(req(r#"{"method":"initialize","x":1e999}"#), strictest);
        assert_eq!(
            r.for_body(b"{\"method\":\"initialize\",\"x\":\"\xff\"}"),
            strictest
        );
        assert_eq!(req(r#"{"method":"initialize"} x"#), strictest);
        assert_eq!(rules().scopes_for_tool("admin"), ["mcp:write", "mcp:admin"]);
        assert_eq!(rules().scopes_for_tool("nope"), ["mcp:read"]);
    }

    #[test]
    fn a_repeated_tool_entry_replaces_the_earlier_one() {
        let r = McpToolScopes::new().tool("t", ["a"]).tool("t", ["b"]);
        assert_eq!(r.scopes_for_tool("t"), ["b"]);
        assert_eq!(r.rules.strictest, ["b"]);
    }

    #[test]
    #[should_panic(expected = "is not a valid scope")]
    fn an_invalid_scope_panics() {
        let _ = McpToolScopes::new().tool("t", ["has space"]);
    }

    #[test]
    fn the_try_forms_return_what_the_panicking_forms_panic_on() {
        match McpToolScopes::new().try_tool("t", ["ok", "has space"]) {
            Err(McpScopesError::InvalidScope(e)) => assert_eq!(e.scope(), "has space"),
            other => panic!("{other:?}"),
        }
        match McpToolScopes::new().try_default([""]) {
            Err(McpScopesError::InvalidScope(e)) => assert_eq!(e.scope(), ""),
            other => panic!("{other:?}"),
        }
        assert_eq!(
            McpToolScopes::new()
                .try_body_limit(MIN_BODY_LIMIT - 1)
                .unwrap_err(),
            McpScopesError::BodyLimitOutOfRange(MIN_BODY_LIMIT - 1)
        );
        let ok = McpToolScopes::new()
            .try_default(["r"])
            .and_then(|m| m.try_tool("t", ["w"]))
            .and_then(|m| m.try_body_limit(MAX_BODY_LIMIT))
            .unwrap();
        assert_eq!(ok.scopes_for_tool("t"), ["w"]);
        assert_eq!(ok.rules.body_limit, MAX_BODY_LIMIT);
    }

    #[test]
    #[should_panic(expected = "body_limit")]
    fn a_body_limit_out_of_bounds_panics() {
        let _ = McpToolScopes::new().body_limit(MAX_BODY_LIMIT + 1);
    }
}
