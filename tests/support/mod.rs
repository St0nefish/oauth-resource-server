//! The request scenarios `tests/observability_logs.rs` and
//! `tests/observability_metrics.rs` both drive: one axum app behind a strict
//! layer (OAuth plus one labeled static token, with a `RequireScopes` route
//! and an `McpToolScopes` route), an `optional()` layer and an
//! `allow_unauthenticated` one, against an in-process `TestAuthority`.
#![allow(dead_code)] // each test binary uses its own subset

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::routing::{get, post};
use http::header::{AUTHORIZATION, CONTENT_TYPE};
use http::{Method, Request};
use oauth_resource_server::axum::{AuthLayer, RequireScopes};
use oauth_resource_server::mcp::McpToolScopes;
use oauth_resource_server::testing::TestAuthority;
use oauth_resource_server::{AuthorizedToken, OAuthValidator, StaticTokens};
use tower::ServiceExt;

/// The static token; it must never appear in any captured output.
pub const STATIC_SECRET: &str = "obs-static-secret-7Qx2";
/// Its label, which is log-safe by construction and is logged.
pub const STATIC_LABEL: &str = "ci-runner";
/// A `tools/call` for the one scoped tool.
pub const PURGE_CALL: &str =
    r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"purge"}}"#;

/// A `tools/call` for the one tool with a claim requirement.
pub const PROMOTE_CALL: &str =
    r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"promote"}}"#;
/// The `groups` value `promote` needs; a configured value, never logged.
pub const PROMOTE_GROUP: &str = "obs-group-value-Zq9";
/// A `groups` value a refused token carries; a presented value, never logged.
pub const PRESENTED_GROUP: &str = "obs-presented-group-Kv4";

/// A 5 KB `kid`full of control characters and ANSI escapes.
pub fn hostile_kid() -> String {
    let mut kid = String::from("\u{1b}[31mRED\u{1b}[0m\u{7}\r\n\u{202e}");
    while kid.len() < 5 * 1024 {
        kid.push_str("A\u{1b}[2J");
    }
    kid
}

pub struct Fixture {
    pub authority: TestAuthority,
    pub validator: Arc<OAuthValidator>,
    pub app: Router,
}

pub async fn fixture() -> Fixture {
    let authority = TestAuthority::start().await;
    let validator = Arc::new(OAuthValidator::new(&authority.config(|_| {})).unwrap());
    let tokens = StaticTokens::new()
        .with(Some(STATIC_LABEL), STATIC_SECRET)
        .unwrap();
    let strict = AuthLayer::builder()
        .oauth(Arc::clone(&validator))
        .static_tokens(tokens)
        .build()
        .unwrap();
    let optional = AuthLayer::builder()
        .oauth(Arc::clone(&validator))
        .optional()
        .build()
        .unwrap();
    let strict_routes = Router::new()
        .route("/any", get(ok))
        .route("/who", get(who))
        .merge(
            Router::new()
                .route("/admin", get(ok))
                .route_layer(RequireScopes::new(["api:admin"])),
        )
        .merge(
            Router::new().route("/mcp", post(ok)).route_layer(
                McpToolScopes::new()
                    .tool("purge", ["api:admin"])
                    .tool_claim("promote", "groups", [PROMOTE_GROUP]),
            ),
        )
        .route_layer(strict);
    let app = Router::new()
        .merge(strict_routes)
        .merge(Router::new().route("/opt", get(ok)).route_layer(optional))
        .merge(
            Router::new()
                .route("/open", get(ok))
                .route_layer(AuthLayer::allow_unauthenticated()),
        );
    Fixture {
        authority,
        validator,
        app,
    }
}

async fn ok() -> &'static str {
    "ok"
}

/// A handler that needs an OAuth token: a static token reaches it and is
/// refused by the extractor.
async fn who(token: AuthorizedToken) -> String {
    token.subject.unwrap_or_default()
}

/// Send one request; the response status.
pub async fn send(
    app: &Router,
    method: Method,
    path: &str,
    bearer: Option<&str>,
    body: &str,
) -> u16 {
    let mut request = Request::builder().method(method).uri(path);
    if let Some(token) = bearer {
        request = request.header(AUTHORIZATION, format!("Bearer {token}"));
    }
    if !body.is_empty() {
        request = request.header(CONTENT_TYPE, "application/json");
    }
    app.clone()
        .oneshot(request.body(Body::from(body.to_owned())).unwrap())
        .await
        .unwrap()
        .status()
        .as_u16()
}

/// `token`'s header and payload with another token's signature: a
/// well-formed JWT whose signature does not verify.
pub fn with_foreign_signature(token: &str, other: &str) -> String {
    let (signed, _) = token.rsplit_once('.').unwrap();
    let (_, signature) = other.rsplit_once('.').unwrap();
    format!("{signed}.{signature}")
}
