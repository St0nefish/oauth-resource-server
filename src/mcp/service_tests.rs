//! `McpToolScopes` end to end, behind both authentication layers.

use std::sync::Arc;

use ::axum::Router;
use ::axum::body::Body;
use ::axum::routing::any;
use bytes::Bytes;
use http::header::WWW_AUTHENTICATE;
use http_body_util::{BodyExt, Full};
use tower::{ServiceExt, service_fn};

use super::*;
use crate::OAuthValidator;
use crate::axum::AuthLayer;
use crate::http_layer::HttpAuthLayer;
use crate::testing;

const STATIC: &str = "static-secret";
const METADATA: &str = "https://kb.example.test/.well-known/oauth-protected-resource/mcp";

fn challenge_for(scopes: &str) -> String {
    format!(
        "Bearer error=\"insufficient_scope\", scope=\"{scopes}\", \
         resource_metadata=\"{METADATA}\""
    )
}

fn token(scope: &str) -> String {
    testing::mint(
        testing::KEY_A_PEM,
        testing::KID_A,
        &serde_json::json!({
            "iss": testing::ISSUER, "aud": testing::AUDIENCE, "sub": "user-1",
            "exp": testing::now() + 3600, "scope": scope,
        }),
    )
}

async fn validator() -> (testing::FakeJwksServer, Arc<OAuthValidator>) {
    let jwks = testing::spawn_jwks_server("200 OK", testing::jwks_body()).await;
    let v = Arc::new(OAuthValidator::new(&testing::resolved_config(&jwks.url)).unwrap());
    (jwks, v)
}

fn tool_scopes() -> McpToolScopes {
    McpToolScopes::new()
        .default(["mcp:read"])
        .tool("write_document", ["mcp:write"])
        .tool("purge", ["mcp:write", "mcp:admin"])
}

/// An MCP endpoint stand-in that echoes the body it received, byte for byte.
fn app(auth: AuthLayer, scopes: McpToolScopes) -> Router {
    Router::new()
        .route(
            "/mcp",
            any(|body: Bytes| async move {
                let mut echoed = b"served:".to_vec();
                echoed.extend_from_slice(&body);
                echoed
            }),
        )
        .route_layer(scopes)
        .route_layer(auth)
}

fn strict(v: &Arc<OAuthValidator>) -> AuthLayer {
    AuthLayer::builder()
        .oauth(Arc::clone(v))
        .static_token(STATIC)
        .build()
        .unwrap()
}

/// Status, `WWW-Authenticate` (if any) and body.
type Seen = (u16, Option<String>, Vec<u8>);

async fn send(app: &Router, method: http::Method, token: Option<&str>, body: Body) -> Seen {
    let mut request = Request::builder().method(method).uri("/mcp");
    if let Some(token) = token {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    let response = app
        .clone()
        .oneshot(request.body(body).unwrap())
        .await
        .unwrap();
    let status = response.status().as_u16();
    let challenge = response
        .headers()
        .get(WWW_AUTHENTICATE)
        .map(|v| v.to_str().unwrap().to_string());
    let body = response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    (status, challenge, body)
}

async fn post(app: &Router, token: Option<&str>, json: &str) -> Seen {
    send(app, http::Method::POST, token, Body::from(json.to_string())).await
}

fn served(json: &str) -> Seen {
    (200, None, format!("served:{json}").into_bytes())
}

fn call(tool: &str) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"{tool}","arguments":{{"text":"héllo \"world\""}}}}}}"#
    )
}

#[tokio::test]
async fn an_allowed_tool_is_served_with_its_body_byte_identical() {
    let (_jwks, v) = validator().await;
    let app = app(strict(&v), tool_scopes());
    let writer = token("mcp:read mcp:write");
    let body = call("write_document");
    assert_eq!(post(&app, Some(&writer), &body).await, served(&body));
    // Whitespace, key order and escapes all survive untouched.
    let odd = "  {\"params\":{\"name\":\"write_document\"} , \"method\" : \"tools\\/call\"}\n";
    assert_eq!(post(&app, Some(&writer), odd).await, served(odd));
}

#[tokio::test]
async fn a_denied_tool_is_a_403_naming_that_tools_scopes() {
    let (_jwks, v) = validator().await;
    let app = app(strict(&v), tool_scopes());
    let reader = token("mcp:read");
    assert_eq!(
        post(&app, Some(&reader), &call("write_document")).await,
        (403, Some(challenge_for("mcp:read mcp:write")), Vec::new())
    );
    let writer = token("mcp:read mcp:write");
    assert_eq!(
        post(&app, Some(&writer), &call("purge")).await,
        (
            403,
            Some(challenge_for("mcp:read mcp:write mcp:admin")),
            Vec::new()
        )
    );
    // The same bytes `refusal_for_scopes` gives for that tool's scopes.
    assert_eq!(
        crate::refusal_for_scopes(
            &TokenRejection::InsufficientScope,
            Some(&v),
            &["mcp:write", "mcp:admin"],
            None
        )
        .www_authenticate,
        Some(challenge_for("mcp:read mcp:write mcp:admin"))
    );
}

#[tokio::test]
async fn unknown_tools_and_other_methods_need_the_default() {
    let (_jwks, v) = validator().await;
    let app = app(strict(&v), tool_scopes().default(["mcp:read", "mcp:list"]));
    let reader = token("mcp:read");
    let lister = token("mcp:read mcp:list");
    for body in [
        call("search"),
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#.to_string(),
    ] {
        assert_eq!(
            post(&app, Some(&reader), &body).await,
            (403, Some(challenge_for("mcp:read mcp:list")), Vec::new())
        );
        assert_eq!(post(&app, Some(&lister), &body).await, served(&body));
    }
}

#[tokio::test]
async fn a_batch_needs_every_calls_scopes() {
    let (_jwks, v) = validator().await;
    let app = app(strict(&v), tool_scopes());
    let batch = format!(
        r#"[{},{},{{"jsonrpc":"2.0","id":3,"method":"tools/list"}}]"#,
        call("search"),
        call("write_document")
    );
    assert_eq!(
        post(&app, Some(&token("mcp:read")), &batch).await,
        (403, Some(challenge_for("mcp:read mcp:write")), Vec::new())
    );
    assert_eq!(
        post(&app, Some(&token("mcp:read mcp:write")), &batch).await,
        served(&batch)
    );
}

#[tokio::test]
async fn an_unreadable_body_needs_the_strictest_set() {
    let (_jwks, v) = validator().await;
    let app = app(strict(&v), tool_scopes());
    let strictest = challenge_for("mcp:read mcp:write mcp:admin");
    for body in [
        r#"{"method":"tools/call","params":{"name":"search"}"#, // truncated
        r#"{"method":"tools/call","params":{"name":42}}"#,
        r#"{"method":"tools/call","params":{"name":"search","name":"purge"}}"#,
        r#"{"method":"tools/list","method":"tools/call","params":{"name":"purge"}}"#,
        "not json at all",
    ] {
        assert_eq!(
            post(&app, Some(&token("mcp:read mcp:write")), body).await,
            (403, Some(strictest.clone()), Vec::new()),
            "{body}"
        );
        // Every scope any tool needs: passed on, unchanged, for the server
        // to answer.
        assert_eq!(
            post(&app, Some(&token("mcp:read mcp:write mcp:admin")), body).await,
            served(body),
            "{body}"
        );
    }
}

#[tokio::test]
async fn an_oversized_body_is_refused_unread() {
    let (_jwks, v) = validator().await;
    let app = app(strict(&v), tool_scopes().body_limit(MIN_BODY_LIMIT));
    let admin = token("mcp:read mcp:write mcp:admin");
    let big = format!(
        r#"{{"method":"tools/list","pad":"{}"}}"#,
        "x".repeat(MIN_BODY_LIMIT)
    );
    // Announced (Content-Length / exact size hint).
    assert_eq!(
        post(&app, Some(&admin), &big).await,
        (413, None, Vec::new())
    );
    // Streamed with no size hint: refused once a chunk crosses the limit,
    // without reading the rest (the stream would fail if polled further).
    let chunks: Vec<Result<Bytes, std::io::Error>> = vec![
        Ok(Bytes::from(big[..MIN_BODY_LIMIT / 2].to_string())),
        Ok(Bytes::from(big[MIN_BODY_LIMIT / 2..].to_string())),
        Err(std::io::Error::other("the layer read past the limit")),
    ];
    let streamed = Body::new(Chunks(chunks.into()));
    assert_eq!(
        send(&app, http::Method::POST, Some(&admin), streamed).await,
        (413, None, Vec::new())
    );
    // Exactly at the limit is fine.
    let fits = format!(
        r#"{{"method":"tools/list","pad":"{}"}}"#,
        "x".repeat(MIN_BODY_LIMIT - 32)
    );
    assert_eq!(fits.len(), MIN_BODY_LIMIT);
    assert_eq!(post(&app, Some(&admin), &fits).await, served(&fits));
}

/// A body that yields its chunks one frame at a time and announces no size.
struct Chunks(std::collections::VecDeque<Result<Bytes, std::io::Error>>);

impl http_body::Body for Chunks {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Bytes>, std::io::Error>>> {
        Poll::Ready(
            self.0
                .pop_front()
                .map(|chunk| chunk.map(http_body::Frame::data)),
        )
    }
}

#[tokio::test]
async fn every_method_with_a_body_is_classified_and_a_bodiless_one_needs_the_default() {
    let (_jwks, v) = validator().await;
    let app = app(strict(&v), tool_scopes());
    let reader = token("mcp:read");
    let writer = token("mcp:read mcp:write");
    let body = call("write_document");
    let methods = [
        http::Method::POST,
        http::Method::GET,
        http::Method::PUT,
        http::Method::PATCH,
        http::Method::DELETE,
        http::Method::OPTIONS,
        // A lowercase `post` is an extension method, not `POST`.
        http::Method::from_bytes(b"post").unwrap(),
    ];
    for method in methods {
        // A body carrying a `tools/call`: that tool's scopes, any method.
        assert_eq!(
            send(
                &app,
                method.clone(),
                Some(&reader),
                Body::from(body.clone())
            )
            .await,
            (403, Some(challenge_for("mcp:read mcp:write")), Vec::new()),
            "{method}"
        );
        assert_eq!(
            send(
                &app,
                method.clone(),
                Some(&writer),
                Body::from(body.clone())
            )
            .await,
            served(&body),
            "{method}"
        );
        // No body: the default.
        assert_eq!(
            send(&app, method.clone(), Some(&reader), Body::empty()).await,
            (200, None, b"served:".to_vec()),
            "{method}"
        );
    }
    // A body with no announced size (a stream) is a body too.
    let streamed = Body::new(Chunks(vec![Ok(Bytes::from(body.clone()))].into()));
    assert_eq!(
        send(&app, http::Method::GET, Some(&reader), streamed)
            .await
            .0,
        403
    );
}

#[tokio::test]
async fn static_tokens_are_refused_unless_they_bypass() {
    let (_jwks, v) = validator().await;
    let body = call("write_document");
    let refused = app(strict(&v), tool_scopes());
    assert_eq!(
        post(&refused, Some(STATIC), &body).await,
        (403, Some(challenge_for("mcp:read mcp:write")), Vec::new())
    );
    let bypass = app(strict(&v), tool_scopes().static_token_bypasses_scopes());
    assert_eq!(post(&bypass, Some(STATIC), &body).await, served(&body));
    // With no scopes required at all, a static token needs no bypass.
    let open = app(strict(&v), McpToolScopes::new());
    assert_eq!(post(&open, Some(STATIC), &body).await, served(&body));
}

#[tokio::test]
async fn no_credential_is_the_layers_401_and_no_layer_is_a_500() {
    let (_jwks, v) = validator().await;
    let optional = AuthLayer::builder()
        .oauth(Arc::clone(&v))
        .optional()
        .build()
        .unwrap();
    let app = app(optional, tool_scopes());
    assert_eq!(
        post(&app, None, &call("write_document")).await,
        (401, Some(v.invalid_token_challenge()), Vec::new())
    );
    // Refused before the body is read whenever any tool needs a scope: the
    // stream fails if it is polled at all.
    let optional = || {
        AuthLayer::builder()
            .oauth(Arc::clone(&v))
            .optional()
            .build()
            .unwrap()
    };
    let unread = || Body::new(Chunks(vec![Err(std::io::Error::other("read"))].into()));
    let app2 = self::app(
        optional(),
        McpToolScopes::new().tool("write_document", ["mcp:write"]),
    );
    assert_eq!(
        send(&app2, http::Method::POST, None, unread()).await,
        (401, Some(v.invalid_token_challenge()), Vec::new())
    );
    // A bodiless request with no default requirement is still served
    // anonymously, as the optional layer intends.
    assert_eq!(
        send(&app2, http::Method::GET, None, Body::empty()).await,
        (200, None, b"served:".to_vec())
    );
    // Nothing required anywhere: served anonymously, body and all.
    let app3 = self::app(optional(), McpToolScopes::new());
    let list = r#"{"method":"tools/list"}"#;
    assert_eq!(post(&app3, None, list).await, served(list));
    // No authentication layer at all: 500, and the body is never read.
    let bare = Router::new()
        .route("/mcp", any(|| async { "served" }))
        .route_layer(tool_scopes());
    assert_eq!(
        post(&bare, None, &call("search")).await,
        (500, None, Vec::new())
    );
}

#[tokio::test]
async fn behind_the_http_layer_with_a_full_body() {
    let (_jwks, v) = validator().await;
    let service = tower::ServiceBuilder::new()
        .layer(
            HttpAuthLayer::builder()
                .oauth(Arc::clone(&v))
                .build()
                .unwrap(),
        )
        .layer(tool_scopes())
        .service(service_fn(|request: Request<Full<Bytes>>| async move {
            let body = request.into_body().collect().await.unwrap().to_bytes();
            Ok::<_, std::convert::Infallible>(Response::new(Full::new(body)))
        }));
    let send = |token: &str, body: String| {
        let service = service.clone();
        let request = Request::post("/mcp")
            .header("authorization", format!("Bearer {token}"))
            .body(Full::new(Bytes::from(body)))
            .unwrap();
        async move {
            let response = service.oneshot(request).await.unwrap();
            let status = response.status().as_u16();
            let challenge = response
                .headers()
                .get(WWW_AUTHENTICATE)
                .map(|v| v.to_str().unwrap().to_string());
            let body = response.into_body().collect().await.unwrap().to_bytes();
            (status, challenge, body.to_vec())
        }
    };
    let body = call("write_document");
    assert_eq!(
        send(&token("mcp:read"), body.clone()).await,
        (403, Some(challenge_for("mcp:read mcp:write")), Vec::new())
    );
    assert_eq!(
        send(&token("mcp:read mcp:write"), body.clone()).await,
        (200, None, body.into_bytes())
    );
}
