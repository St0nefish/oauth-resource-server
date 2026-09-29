//! An integration helper for [Model Context Protocol](https://modelcontextprotocol.io)
//! servers (feature `mcp`): per-tool scope requirements, enforced before the
//! MCP server sees the request. The rest of this crate is protocol-agnostic;
//! this module is the one place that knows what a JSON-RPC `tools/call` looks
//! like, and it depends on nothing MCP-specific (no MCP SDK — `serde_json`
//! only).
//!
//! An MCP server exposes every tool on one endpoint, so a route-level scope
//! ([`crate::http_layer::RequireScopes`]) cannot tell a read tool from a write
//! tool. [`McpToolScopes`] reads the tool name from the request body instead:
//!
//! ```
//! use axum::Router;
//! use oauth_resource_server::axum::AuthLayer;
//! use oauth_resource_server::mcp::McpToolScopes;
//!
//! # fn app(mcp_service: Router, auth: AuthLayer) -> Router {
//! let tool_scopes = McpToolScopes::new()
//!     .default(["mcp:read"])
//!     .tool("write_document", ["mcp:write"])
//!     .tool("delete_document", ["mcp:write", "mcp:admin"]);
//! Router::new()
//!     .nest_service("/mcp", mcp_service)
//!     // Behind the authentication layer: `route_layer`s added later run first.
//!     .route_layer(tool_scopes)
//!     .route_layer(auth)
//! # }
//! ```
//!
//! # What it enforces
//!
//! For every request the authentication layer in front of it let through
//! (it must sit behind the axum `AuthLayer` or the `tower` feature's
//! `HttpAuthLayer`; without one it answers 500):
//!
//! | Request | Scopes required (all-of, on top of the layer's) |
//! |---|---|
//! | not a `POST` (the `GET` event stream, `DELETE`, …) | the default |
//! | a `POST` whose JSON-RPC message is `tools/call` for a configured tool | that tool's (not the default's) |
//! | a `POST` whose message is `tools/call` for any other tool | the default |
//! | a `POST` whose message is anything else (`initialize`, `tools/list`, a notification, a response) | the default |
//! | a JSON-RPC **batch** (an array) | every scope any of its messages requires: all of them must be authorized, or none is served |
//! | a `POST` whose body is not JSON, or a `tools/call` without a readable string `params.name`, or a message with a repeated `method`, `params` or `params.name` | the **strictest** set: the default and every tool's scopes together |
//! | a `POST` body larger than the [limit](McpToolScopes::body_limit) | refused with 413, unread beyond the limit |
//!
//! A request whose credential lacks the scopes is refused with 403 and the
//! authentication layer's own refusal (its `on_reject` body), with a
//! `WWW-Authenticate` challenge naming the layer's scopes followed by the
//! ones this request needed — the MCP authorization spec's per-operation
//! challenge. A static token has no scopes, so it is refused the same way
//! whenever scopes are required, unless
//! [`static_token_bypasses_scopes`](McpToolScopes::static_token_bypasses_scopes).
//! A request with no credential (an `optional` layer passed it through) gets
//! the layer's own 401 when scopes are required, and is served when none
//! are. Anything served reaches the MCP server with its body byte-identical.
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
//! # Privacy
//!
//! Nothing from the body — tool name, arguments, identifiers — is ever
//! logged; refusals are logged (target `oauth_resource_server::http_layer`,
//! as for [`crate::http_layer::RequireScopes`]) with the request path and
//! the configured scopes only. Oversized and unreadable bodies are logged at
//! `warn` with the path and the limit.
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
use http::{Method, Request, Response, StatusCode};
use http_body::Body;
use serde::de::{DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use tracing::warn;

use crate::http_layer::{ScopeVerdict, checked_scopes, judge_scopes, scope_refusal};
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
/// # Panics
///
/// [`default`](Self::default) and [`tool`](Self::tool) panic on a scope that
/// is not an RFC 6749 §3.3 scope-token (empty, or holding a space, `"`,
/// `\`, a control or non-ASCII character) — no token can carry one — and
/// [`body_limit`](Self::body_limit) outside
/// [`MIN_BODY_LIMIT`]`..=`[`MAX_BODY_LIMIT`].
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

    /// The scopes a POST body requires (see the module docs' table).
    fn for_body(&self, body: &[u8]) -> Vec<String> {
        let messages = match classify(body) {
            Classified::Messages(messages) => messages,
            Classified::Unreadable => return self.strictest.clone(),
        };
        if messages.is_empty() {
            return self.default.clone();
        }
        let mut all: Vec<String> = Vec::new();
        for message in &messages {
            let scopes = match message {
                Message::NotToolCall => &self.default[..],
                Message::ToolCall(name) => self.for_tool(name),
                Message::Ambiguous => &self.strictest[..],
            };
            for scope in scopes {
                if !all.contains(scope) {
                    all.push(scope.clone());
                }
            }
        }
        all
    }
}

fn scopes_or_panic(what: &str, scopes: impl IntoIterator<Item = impl Into<String>>) -> Vec<String> {
    checked_scopes(scopes).unwrap_or_else(|| {
        panic!(
            "McpToolScopes::{what}: a scope is not a valid scope-token (printable ASCII with no \
             space, '\"' or '\\', RFC 6749 §3.3)"
        )
    })
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
    /// says otherwise: every non-`POST` request, every JSON-RPC message
    /// other than `tools/call`, and a `tools/call` for a tool with no entry.
    /// Replaces a default given earlier.
    ///
    /// # Panics
    ///
    /// On a scope that is not a scope-token; see the type's docs.
    pub fn default(self, scopes: impl IntoIterator<Item = impl Into<String>>) -> Self {
        let scopes = scopes_or_panic("default", scopes);
        self.update(|rules| rules.default = scopes)
    }

    /// The scopes a `tools/call` for the tool named `name` (exactly,
    /// case-sensitively) needs, instead of the [`default`](Self::default).
    /// An empty list means that tool needs nothing beyond the
    /// authentication layer's own scopes. Replaces an entry for the same
    /// name.
    ///
    /// # Panics
    ///
    /// On a scope that is not a scope-token; see the type's docs.
    pub fn tool(
        self,
        name: impl Into<String>,
        scopes: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        let name = name.into();
        let scopes = scopes_or_panic("tool", scopes);
        self.update(|rules| {
            rules.tools.retain(|(tool, _)| *tool != name);
            rules.tools.push((name, scopes));
        })
    }

    /// The largest `POST` body read, in bytes ([`DEFAULT_BODY_LIMIT`]
    /// unless set). A body announced larger (`Content-Length`, or the
    /// body's own size hint) is refused with 413 before any of it is read;
    /// one that turns out larger is refused as soon as a chunk crosses the
    /// limit, so no more than the limit plus one chunk is ever held.
    ///
    /// # Panics
    ///
    /// Outside [`MIN_BODY_LIMIT`]`..=`[`MAX_BODY_LIMIT`].
    pub fn body_limit(self, bytes: usize) -> Self {
        assert!(
            (MIN_BODY_LIMIT..=MAX_BODY_LIMIT).contains(&bytes),
            "McpToolScopes::body_limit: {bytes} is outside {MIN_BODY_LIMIT}..={MAX_BODY_LIMIT}"
        );
        self.update(|rules| rules.body_limit = bytes)
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
async fn read_capped<B: Body + Unpin>(mut body: B, limit: usize) -> Result<Bytes, ReadError> {
    if body.size_hint().lower() > limit as u64 {
        return Err(ReadError::TooLarge);
    }
    let mut buf: Vec<u8> = Vec::new();
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
            let (required, body) = if parts.method == Method::POST {
                let announced = parts
                    .headers
                    .get(http::header::CONTENT_LENGTH)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.trim().parse::<u64>().ok());
                let read = if announced.is_some_and(|n| n > rules.body_limit as u64) {
                    Err(ReadError::TooLarge)
                } else {
                    read_capped(Box::pin(body), rules.body_limit).await
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

/// What a `POST` body holds, as far as tool scopes are concerned.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Classified {
    /// One message, or a batch's messages in order (possibly none).
    Messages(Vec<Message>),
    /// Not JSON, or JSON that is neither an object nor an array.
    Unreadable,
}

/// One JSON-RPC message.
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

/// Classify a `POST` body. Pure, bounded by `serde_json`'s recursion limit,
/// and never panics (the `__fuzz` target checks that, against
/// `serde_json::Value` as an oracle).
///
/// The body must first parse as a whole `serde_json::Value`: the reader
/// below skips the members it does not look at without validating them (a
/// number out of `f64` range, say), and a body any strict JSON parser
/// refuses is `Unreadable` — the strictest set — rather than classified.
pub(crate) fn classify(body: &[u8]) -> Classified {
    if serde_json::from_slice::<serde_json::Value>(body).is_err() {
        return Classified::Unreadable;
    }
    match serde_json::from_slice::<Top>(body) {
        Ok(Top(messages)) => Classified::Messages(messages),
        Err(_) => Classified::Unreadable,
    }
}

/// The top-level JSON value: one message (an object) or a batch (an array).
struct Top(Vec<Message>);

impl<'de> Deserialize<'de> for Top {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct TopVisitor;
        impl<'de> Visitor<'de> for TopVisitor {
            type Value = Top;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a JSON-RPC message or batch")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Top, A::Error> {
                let message = read_message(&mut map).map_err(serde::de::Error::custom)?;
                Ok(Top(vec![message]))
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Top, A::Error> {
                let mut messages = Vec::new();
                while let Some(Element(message)) = seq.next_element()? {
                    messages.push(message);
                }
                Ok(Top(messages))
            }
        }
        deserializer.deserialize_any(TopVisitor)
    }
}

/// One batch element: a message, or anything else (`Ambiguous`).
struct Element(Message);

impl<'de> Deserialize<'de> for Element {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer
            .deserialize_any(AnyVisitor {
                on_map: read_message,
                other: Message::Ambiguous,
            })
            .map(Element)
    }
}

/// A visitor accepting any JSON value: an object goes to `on_map`, anything
/// else (consumed) yields `other`.
struct AnyVisitor<T, F> {
    on_map: F,
    other: T,
}

impl<'de, T, F> Visitor<'de> for AnyVisitor<T, F>
where
    F: FnOnce(&mut dyn ErasedMap<'de>) -> Result<T, String>,
{
    type Value = T;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("any JSON value")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<T, A::Error> {
        (self.on_map)(&mut map).map_err(serde::de::Error::custom)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<T, A::Error> {
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok(self.other)
    }

    fn visit_bool<E>(self, _: bool) -> Result<T, E> {
        Ok(self.other)
    }

    fn visit_i64<E>(self, _: i64) -> Result<T, E> {
        Ok(self.other)
    }

    fn visit_u64<E>(self, _: u64) -> Result<T, E> {
        Ok(self.other)
    }

    fn visit_f64<E>(self, _: f64) -> Result<T, E> {
        Ok(self.other)
    }

    fn visit_str<E>(self, _: &str) -> Result<T, E> {
        Ok(self.other)
    }

    fn visit_unit<E>(self) -> Result<T, E> {
        Ok(self.other)
    }
}

/// A `MapAccess` behind a trait object, so one reader serves every visitor.
/// Errors are carried as strings and turned back into the deserializer's.
trait ErasedMap<'de> {
    fn next_key(&mut self) -> Result<Option<String>, String>;
    fn next_value_string(&mut self) -> Result<Option<String>, String>;
    fn next_value_params(&mut self) -> Result<Params, String>;
    fn skip_value(&mut self) -> Result<(), String>;
}

impl<'de, A: MapAccess<'de>> ErasedMap<'de> for A {
    fn next_key(&mut self) -> Result<Option<String>, String> {
        MapAccess::next_key::<String>(self).map_err(|e| e.to_string())
    }

    fn next_value_string(&mut self) -> Result<Option<String>, String> {
        // `Some` for a JSON string, `None` for any other value (consumed).
        self.next_value_seed(StringOrOther)
            .map_err(|e| e.to_string())
    }

    fn next_value_params(&mut self) -> Result<Params, String> {
        self.next_value_seed(ParamsSeed).map_err(|e| e.to_string())
    }

    fn skip_value(&mut self) -> Result<(), String> {
        self.next_value::<IgnoredAny>()
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
}

/// A value read as a string when it is one; any other value is consumed and
/// read as `None`.
struct StringOrOther;

impl<'de> DeserializeSeed<'de> for StringOrOther {
    type Value = Option<String>;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Option<String>;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("any JSON value")
            }
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E> {
                Ok(Some(v.to_string()))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
                Ok(None)
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                while seq.next_element::<IgnoredAny>()?.is_some() {}
                Ok(None)
            }
            fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
                Ok(None)
            }
            fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
                Ok(None)
            }
            fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
                Ok(None)
            }
            fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
                Ok(None)
            }
            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(None)
            }
        }
        deserializer.deserialize_any(V)
    }
}

/// What a message's `params` says about the tool name.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Params {
    /// `params` is an object with exactly one `name`, a string.
    Name(String),
    /// Anything else: no object, no `name`, a non-string `name`, or a
    /// repeated `name`.
    Unreadable,
}

/// Reads a `params` value into [`Params`].
struct ParamsSeed;

impl<'de> DeserializeSeed<'de> for ParamsSeed {
    type Value = Params;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Params, D::Error> {
        deserializer.deserialize_any(AnyVisitor {
            on_map: |map: &mut dyn ErasedMap<'de>| {
                let mut name: Option<Option<String>> = None;
                let mut repeated = false;
                while let Some(key) = map.next_key()? {
                    if key == "name" {
                        if name.is_some() {
                            repeated = true;
                            map.skip_value()?;
                        } else {
                            name = Some(map.next_value_string()?);
                        }
                    } else {
                        map.skip_value()?;
                    }
                }
                Ok(match (repeated, name) {
                    (false, Some(Some(name))) => Params::Name(name),
                    _ => Params::Unreadable,
                })
            },
            other: Params::Unreadable,
        })
    }
}

/// Read one message object.
fn read_message<'de>(map: &mut dyn ErasedMap<'de>) -> Result<Message, String> {
    let mut method: Option<Option<String>> = None;
    let mut params: Option<Params> = None;
    let mut repeated = false;
    while let Some(key) = map.next_key()? {
        match key.as_str() {
            "method" if method.is_none() => method = Some(map.next_value_string()?),
            "params" if params.is_none() => params = Some(map.next_value_params()?),
            "method" | "params" => {
                repeated = true;
                map.skip_value()?;
            }
            _ => map.skip_value()?,
        }
    }
    Ok(match (repeated, method, params) {
        (true, _, _) => Message::Ambiguous,
        (false, Some(Some(method)), params) if method == "tools/call" => match params {
            Some(Params::Name(name)) => Message::ToolCall(name),
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
            ["mcp:write", "mcp:read"]
        );
        assert_eq!(req("[]"), ["mcp:read"]);
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
    #[should_panic(expected = "not a valid scope-token")]
    fn an_invalid_scope_panics() {
        let _ = McpToolScopes::new().tool("t", ["has space"]);
    }

    #[test]
    #[should_panic(expected = "body_limit")]
    fn a_body_limit_out_of_bounds_panics() {
        let _ = McpToolScopes::new().body_limit(MAX_BODY_LIMIT + 1);
    }
}
