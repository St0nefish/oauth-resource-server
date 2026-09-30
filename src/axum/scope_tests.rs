//! Per-route and per-handler scopes (oauth-resource-server#4): the layers'
//! `require_scopes`, the `RequireScopes` route layer and the `Scoped`
//! extractor, under both layers, byte for byte.

use ::axum::routing::post;
use http_body_util::BodyExt;
use tower::{ServiceExt, service_fn};

use super::*;
use crate::http_layer::HttpAuthLayer;
use crate::testing;
use crate::{refusal, refusal_for_scopes};

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

fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}

async fn validator() -> (testing::FakeJwksServer, Arc<OAuthValidator>) {
    let jwks = testing::spawn_jwks_server("200 OK", testing::jwks_body()).await;
    let v = Arc::new(OAuthValidator::new(&testing::resolved_config(&jwks.url)).unwrap());
    (jwks, v)
}

/// Status, `WWW-Authenticate` (if any) and body.
type Seen = (u16, Option<String>, Vec<u8>);

async fn seen_axum(app: &Router, method: Method, authorization: Option<&str>) -> Seen {
    let mut request = Request::builder().method(method).uri("/test");
    if let Some(value) = authorization {
        request = request.header("authorization", value);
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::empty()).unwrap())
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

type Ok200 = fn(
    http::Request<String>,
) -> std::future::Ready<Result<http::Response<String>, std::convert::Infallible>>;

fn ok_service(
    _: http::Request<String>,
) -> std::future::Ready<Result<http::Response<String>, std::convert::Infallible>> {
    std::future::ready(Ok(http::Response::new("ok".to_string())))
}

/// One request through `layer` around a plain (non-axum) `String` service.
async fn seen_http<L>(layer: L, authorization: Option<&str>) -> Seen
where
    L: tower_layer::Layer<tower::util::ServiceFn<Ok200>>,
    L::Service: tower_service::Service<
            http::Request<String>,
            Response = http::Response<String>,
            Error = std::convert::Infallible,
        >,
{
    let service = layer.layer(service_fn(ok_service as Ok200));
    let mut request = http::Request::builder().uri("/test");
    if let Some(value) = authorization {
        request = request.header("authorization", value);
    }
    let response = service
        .oneshot(request.body(String::new()).unwrap())
        .await
        .unwrap();
    let status = response.status().as_u16();
    let challenge = response
        .headers()
        .get(WWW_AUTHENTICATE)
        .map(|v| v.to_str().unwrap().to_string());
    (status, challenge, response.into_body().into_bytes())
}

fn ok_app(layers: impl FnOnce(Router) -> Router) -> Router {
    layers(Router::new().route("/test", get(|| async { "ok" }).post(|| async { "ok" })))
}

fn json_reject(cx: RejectContext<'_>) -> Response {
    (
        [(http::header::CONTENT_TYPE, "application/json")],
        format!(r#"{{"status":{}}}"#, cx.status.as_u16()),
    )
        .into_response()
}

#[tokio::test]
async fn a_layers_require_scopes_is_a_403_naming_the_floor_and_its_own_scopes() {
    let (_jwks, v) = validator().await;
    let axum_layer = AuthLayer::builder()
        .oauth(Arc::clone(&v))
        .static_token(STATIC)
        .require_scopes(["mcp:write"])
        .build()
        .unwrap();
    let http_layer = || {
        HttpAuthLayer::builder()
            .oauth(Arc::clone(&v))
            .static_token(STATIC)
            .require_scopes(["mcp:write"])
            .build()
            .unwrap()
    };
    let app = ok_app(|r| r.route_layer(axum_layer));
    let want_403 = Some(challenge_for("mcp:read mcp:write"));
    let cases: [(Option<String>, u16, Option<String>); 5] = [
        (Some(bearer(&token("mcp:read mcp:write"))), 200, None),
        // Valid, lacking the layer's scope.
        (Some(bearer(&token("mcp:read"))), 403, want_403.clone()),
        // Lacking the validator's floor: the same challenge, naming both.
        (Some(bearer(&token("mcp:write"))), 403, want_403.clone()),
        // A static token has no scopes: refused the same way.
        (Some(bearer(STATIC)), 403, want_403.clone()),
        (None, 401, Some(v.invalid_token_challenge())),
    ];
    for (authorization, status, challenge) in cases {
        let a = seen_axum(&app, Method::GET, authorization.as_deref()).await;
        let h = seen_http(http_layer(), authorization.as_deref()).await;
        assert_eq!((a.0, &a.1), (status, &challenge), "{authorization:?}");
        assert_eq!(h.0, status, "{authorization:?}");
        if status != 200 {
            // Byte parity between the two layers on every refusal.
            assert_eq!(a, h, "{authorization:?}");
        }
    }
    // `refusal_for_scopes` sends the same bytes for the same scopes.
    assert_eq!(
        refusal_for_scopes(
            &TokenRejection::InsufficientScope,
            Some(&v),
            &["mcp:write"],
            None
        )
        .www_authenticate,
        want_403
    );
}

#[tokio::test]
async fn static_tokens_bypass_a_layers_scopes_only_when_opted_in() {
    let (_jwks, v) = validator().await;
    let layer = AuthLayer::builder()
        .oauth(Arc::clone(&v))
        .static_token(STATIC)
        .require_scopes(["mcp:write"])
        .static_token_bypasses_scopes()
        .build()
        .unwrap();
    let app = ok_app(|r| r.route_layer(layer));
    assert_eq!(
        seen_axum(&app, Method::GET, Some(&bearer(STATIC))).await.0,
        200
    );
    // OAuth tokens are still checked.
    assert_eq!(
        seen_axum(&app, Method::GET, Some(&bearer(&token("mcp:read"))))
            .await
            .0,
        403
    );
    let http = HttpAuthLayer::builder()
        .oauth(v)
        .static_token(STATIC)
        .require_scopes(["mcp:write"])
        .static_token_bypasses_scopes()
        .build()
        .unwrap();
    assert_eq!(seen_http(http, Some(&bearer(STATIC))).await.0, 200);
}

#[tokio::test]
async fn an_optional_layer_with_scopes_still_passes_a_request_presenting_nothing() {
    let (_jwks, v) = validator().await;
    let layer = AuthLayer::builder()
        .oauth(v)
        .require_scopes(["mcp:write"])
        .optional()
        .build()
        .unwrap();
    let app = ok_app(|r| r.route_layer(layer));
    assert_eq!(seen_axum(&app, Method::GET, None).await.0, 200);
    assert_eq!(
        seen_axum(&app, Method::GET, Some(&bearer(&token("mcp:read"))))
            .await
            .0,
        403
    );
}

#[test]
fn a_layers_scopes_are_checked_when_it_is_built() {
    let v = Arc::new(
        OAuthValidator::new(&testing::resolved_config("http://127.0.0.1:1/jwks")).unwrap(),
    );
    for bad in ["", "two words", "q\"uote", "caf\u{e9}"] {
        assert_eq!(
            AuthLayer::builder()
                .oauth(Arc::clone(&v))
                .require_scopes([bad])
                .build()
                .unwrap_err(),
            AuthLayerError::InvalidScope,
            "{bad:?}"
        );
        assert_eq!(
            HttpAuthLayer::builder()
                .oauth(Arc::clone(&v))
                .require_scopes([bad])
                .build()
                .unwrap_err(),
            AuthLayerError::InvalidScope,
            "{bad:?}"
        );
    }
    // Static-only with scopes: nothing could ever pass.
    assert_eq!(
        AuthLayer::builder()
            .static_token(STATIC)
            .require_scopes(["x"])
            .build()
            .unwrap_err(),
        AuthLayerError::ScopesNeedOAuth
    );
    assert_eq!(
        HttpAuthLayer::builder()
            .static_token(STATIC)
            .require_scopes(["x"])
            .build()
            .unwrap_err(),
        AuthLayerError::ScopesNeedOAuth
    );
    assert!(
        AuthLayer::builder()
            .static_token(STATIC)
            .require_scopes(["x"])
            .static_token_bypasses_scopes()
            .build()
            .is_ok()
    );
}

fn strict(v: &Arc<OAuthValidator>) -> AuthLayer {
    AuthLayer::builder()
        .oauth(Arc::clone(v))
        .static_token(STATIC)
        .on_reject(json_reject)
        .build()
        .unwrap()
}

fn refused_403() -> Seen {
    (
        403,
        Some(challenge_for("mcp:read mcp:write")),
        br#"{"status":403}"#.to_vec(),
    )
}

#[tokio::test]
async fn require_scopes_behind_a_strict_layer() {
    let (_jwks, v) = validator().await;
    let app = ok_app(|r| {
        r.route_layer(RequireScopes::new(["mcp:write"]))
            .route_layer(strict(&v))
    });
    assert_eq!(
        seen_axum(
            &app,
            Method::GET,
            Some(&bearer(&token("mcp:read mcp:write")))
        )
        .await,
        (200, None, b"ok".to_vec())
    );
    // The layer's own `on_reject` body, the per-request challenge.
    assert_eq!(
        seen_axum(&app, Method::GET, Some(&bearer(&token("mcp:read")))).await,
        refused_403()
    );
    assert_eq!(
        seen_axum(&app, Method::GET, Some(&bearer(STATIC))).await,
        refused_403()
    );

    let bypass = ok_app(|r| {
        r.route_layer(RequireScopes::new(["mcp:write"]).static_token_bypasses_scopes())
            .route_layer(strict(&v))
    });
    assert_eq!(
        seen_axum(&bypass, Method::GET, Some(&bearer(STATIC)))
            .await
            .0,
        200
    );
    assert_eq!(
        seen_axum(&bypass, Method::GET, Some(&bearer(&token("mcp:read")))).await,
        refused_403()
    );
    // The same bytes as `refusal_for_scopes` for the same scopes.
    assert_eq!(
        refusal_for_scopes(
            &TokenRejection::InsufficientScope,
            Some(&v),
            &["mcp:write"],
            None
        )
        .www_authenticate,
        refused_403().1
    );
    // An empty requirement serves whatever the layer let through.
    let none = ok_app(|r| {
        r.route_layer(RequireScopes::new(Vec::<String>::new()))
            .route_layer(strict(&v))
    });
    assert_eq!(
        seen_axum(&none, Method::GET, Some(&bearer(STATIC))).await.0,
        200
    );
    // The layer's own refusals are untouched by a route layer behind it.
    assert_eq!(
        seen_axum(&app, Method::GET, Some(&bearer("not-a-token"))).await,
        (
            401,
            Some(v.invalid_token_challenge()),
            br#"{"status":401}"#.to_vec()
        )
    );
}

#[tokio::test]
async fn require_scopes_behind_an_optional_layer_answers_no_credential_with_the_layers_401() {
    let (_jwks, v) = validator().await;
    let optional = AuthLayer::builder()
        .oauth(Arc::clone(&v))
        .on_reject(json_reject)
        .optional()
        .build()
        .unwrap();
    let app = ok_app(|r| {
        r.route_layer(RequireScopes::new(["mcp:write"]))
            .route_layer(optional)
    });
    let got = seen_axum(&app, Method::GET, None).await;
    assert_eq!(
        got,
        (
            401,
            Some(v.invalid_token_challenge()),
            br#"{"status":401}"#.to_vec()
        )
    );
    // Exactly the challenge `refusal()` gives a missing credential.
    assert_eq!(
        refusal(&TokenRejection::Missing, Some(&v)).www_authenticate,
        got.1
    );
    assert_eq!(
        seen_axum(
            &app,
            Method::GET,
            Some(&bearer(&token("mcp:read mcp:write")))
        )
        .await
        .0,
        200
    );
    assert_eq!(
        seen_axum(&app, Method::GET, Some(&bearer(&token("mcp:read")))).await,
        refused_403()
    );
}

#[tokio::test]
async fn require_scopes_with_no_layer_or_an_open_layer_fails_closed() {
    // No layer at all: 500, never served.
    let app = ok_app(|r| r.route_layer(RequireScopes::new(["mcp:write"])));
    assert_eq!(
        seen_axum(&app, Method::GET, None).await,
        (500, None, Vec::new())
    );
    // An empty requirement too: the wiring mistake still surfaces.
    let app = ok_app(|r| r.route_layer(RequireScopes::new(Vec::<String>::new())));
    assert_eq!(seen_axum(&app, Method::GET, None).await.0, 500);
    // `allow_unauthenticated`: nothing can satisfy it; the default challenge.
    let app = ok_app(|r| {
        r.route_layer(RequireScopes::new(["mcp:write"]))
            .route_layer(AuthLayer::allow_unauthenticated())
    });
    assert_eq!(
        seen_axum(&app, Method::GET, None).await,
        (401, Some(DEFAULT_STATIC_CHALLENGE.to_string()), Vec::new())
    );
    // The same behind the generic layer's opt-out.
    let http = tower::ServiceBuilder::new()
        .layer(HttpAuthLayer::allow_unauthenticated())
        .layer(RequireScopes::new(["mcp:write"]));
    assert_eq!(
        seen_http(http, None).await,
        (401, Some(DEFAULT_STATIC_CHALLENGE.to_string()), Vec::new())
    );
}

#[tokio::test]
async fn require_scopes_answers_the_same_behind_either_layer() {
    let (_jwks, v) = validator().await;
    let axum_app = ok_app(|r| {
        r.route_layer(RequireScopes::new(["mcp:write"]))
            .route_layer(
                AuthLayer::builder()
                    .oauth(Arc::clone(&v))
                    .static_token(STATIC)
                    .build()
                    .unwrap(),
            )
    });
    let http = || {
        tower::ServiceBuilder::new()
            .layer(
                HttpAuthLayer::builder()
                    .oauth(Arc::clone(&v))
                    .static_token(STATIC)
                    .build()
                    .unwrap(),
            )
            .layer(RequireScopes::new(["mcp:write"]))
    };
    for authorization in [
        None,
        Some(bearer(STATIC)),
        Some(bearer(&token("mcp:read"))),
        Some(bearer("not-a-token")),
    ] {
        let a = seen_axum(&axum_app, Method::GET, authorization.as_deref()).await;
        let h = seen_http(http(), authorization.as_deref()).await;
        assert_eq!(a, h, "{authorization:?}");
        assert_ne!(a.0, 200);
    }
    assert_eq!(
        seen_http(http(), Some(&bearer(&token("mcp:read mcp:write"))))
            .await
            .0,
        200
    );
    // No layer in front of the generic one either: 500.
    assert_eq!(
        seen_http(RequireScopes::new(["mcp:write"]), None).await,
        (500, None, Vec::new())
    );
}

/// The generic route layer behind an `HttpAuthLayer` with an `on_reject`:
/// its body builder is reused when the body types match.
#[tokio::test]
async fn require_scopes_reuses_the_http_layers_on_reject() {
    let (_jwks, v) = validator().await;
    let layer = tower::ServiceBuilder::new()
        .layer(
            HttpAuthLayer::builder()
                .oauth(Arc::clone(&v))
                .on_reject(|cx: RejectContext<'_>| {
                    http::Response::new(format!("refused {}", cx.status.as_u16()))
                })
                .build()
                .unwrap(),
        )
        .layer(RequireScopes::new(["mcp:write"]));
    assert_eq!(
        seen_http(layer, Some(&bearer(&token("mcp:read")))).await,
        (
            403,
            Some(challenge_for("mcp:read mcp:write")),
            b"refused 403".to_vec()
        )
    );
}

struct Write;
impl ScopeSet for Write {
    const SCOPES: &'static [&'static str] = &["mcp:write"];
}

async fn write(token: Scoped<Write>) -> String {
    format!("written by {:?}", token.subject)
}

#[tokio::test]
async fn the_scoped_extractor_refuses_exactly_as_require_scopes() {
    let (_jwks, v) = validator().await;
    let app = Router::new()
        .route("/test", post(write))
        .route_layer(strict(&v));
    let layered = ok_app(|r| {
        r.route_layer(RequireScopes::new(["mcp:write"]))
            .route_layer(strict(&v))
    });
    assert_eq!(
        seen_axum(
            &app,
            Method::POST,
            Some(&bearer(&token("mcp:read mcp:write")))
        )
        .await,
        (200, None, b"written by Some(\"user-1\")".to_vec())
    );
    for authorization in [bearer(&token("mcp:read")), bearer(STATIC)] {
        let got = seen_axum(&app, Method::POST, Some(&authorization)).await;
        assert_eq!(got, refused_403());
        assert_eq!(
            got,
            seen_axum(&layered, Method::POST, Some(&authorization)).await
        );
    }
    // Behind an optional layer, no credential: the layer's 401.
    let optional = Router::new().route("/test", post(write)).route_layer(
        AuthLayer::builder()
            .oauth(Arc::clone(&v))
            .optional()
            .build()
            .unwrap(),
    );
    assert_eq!(
        seen_axum(&optional, Method::POST, None).await,
        (401, Some(v.invalid_token_challenge()), Vec::new())
    );
    // No layer: 500. (A scope set no token can carry does not compile: see
    // `ScopeSet`'s `compile_fail` doctest.)
    let bare = Router::new().route("/test", post(write));
    assert_eq!(seen_axum(&bare, Method::POST, None).await.0, 500);
}

/// Behind an `optional()` `HttpAuthLayer`, no credential: that layer's own
/// 401 with `resource_metadata`, not the no-layer 500.
#[tokio::test]
async fn the_scoped_extractor_behind_an_optional_http_layer_answers_its_401() {
    let (_jwks, v) = validator().await;
    let app = Router::new().route("/test", post(write)).layer(
        HttpAuthLayer::builder()
            .oauth(Arc::clone(&v))
            .optional()
            .build()
            .unwrap(),
    );
    let got = seen_axum(&app, Method::POST, None).await;
    assert_eq!(got, (401, Some(v.invalid_token_challenge()), Vec::new()));
    assert!(got.1.unwrap().contains("resource_metadata="));
}

/// A strict OAuth layer around an inner `allow_unauthenticated` one: a route
/// check behind both judges the outer layer's credential and answers an
/// under-scoped token with the outer layer's 403 step-up, not a 401.
#[tokio::test]
async fn a_route_check_behind_an_open_layer_inside_a_strict_one_answers_a_403() {
    let (_jwks, v) = validator().await;
    let app = ok_app(|r| {
        r.route_layer(RequireScopes::new(["mcp:write"]))
            .route_layer(AuthLayer::allow_unauthenticated())
            .route_layer(strict(&v))
    });
    assert_eq!(
        seen_axum(&app, Method::GET, Some(&bearer(&token("mcp:read")))).await,
        refused_403()
    );
    assert_eq!(
        seen_axum(
            &app,
            Method::GET,
            Some(&bearer(&token("mcp:read mcp:write")))
        )
        .await
        .0,
        200
    );
    // The same with the generic layers.
    let http = tower::ServiceBuilder::new()
        .layer(
            HttpAuthLayer::builder()
                .oauth(Arc::clone(&v))
                .build()
                .unwrap(),
        )
        .layer(HttpAuthLayer::allow_unauthenticated())
        .layer(RequireScopes::new(["mcp:write"]));
    assert_eq!(
        seen_http(http, Some(&bearer(&token("mcp:read")))).await,
        (403, Some(challenge_for("mcp:read mcp:write")), Vec::new())
    );
}

/// Behind a static-only layer (no OAuth), a route check refusing a static
/// token answers 403 with a bare `insufficient_scope` challenge (RFC 6750
/// §3.1), never the static 401 challenge's `invalid_token`.
#[tokio::test]
async fn a_route_check_behind_a_static_only_layer_answers_a_bare_insufficient_scope() {
    let static_only = || AuthLayer::builder().static_token(STATIC).build().unwrap();
    let bare = Some("Bearer error=\"insufficient_scope\"".to_string());
    let app = ok_app(|r| {
        r.route_layer(RequireScopes::new(["mcp:write"]))
            .route_layer(static_only())
    });
    assert_eq!(
        seen_axum(&app, Method::GET, Some(&bearer(STATIC))).await,
        (403, bare.clone(), Vec::new())
    );
    let scoped = Router::new()
        .route("/test", post(write))
        .route_layer(static_only());
    assert_eq!(
        seen_axum(&scoped, Method::POST, Some(&bearer(STATIC))).await,
        (403, bare.clone(), Vec::new())
    );
    let http = tower::ServiceBuilder::new()
        .layer(
            HttpAuthLayer::builder()
                .static_token(STATIC)
                .build()
                .unwrap(),
        )
        .layer(RequireScopes::new(["mcp:write"]));
    assert_eq!(
        seen_http(http, Some(&bearer(STATIC))).await,
        (403, bare, Vec::new())
    );
}

#[test]
fn an_unauthenticated_decision_refuses_a_builder_with_scopes() {
    assert_eq!(
        AuthLayer::builder()
            .require_scopes(["x"])
            .build_with_decision(StaticTokenDecision::Unauthenticated)
            .unwrap_err(),
        AuthLayerError::ScopesWithoutAuthentication
    );
    assert_eq!(
        HttpAuthLayer::builder()
            .require_scopes(["x"])
            .build_with_decision(StaticTokenDecision::Unauthenticated)
            .unwrap_err(),
        AuthLayerError::ScopesWithoutAuthentication
    );
    // Without scopes the explicit opt-out still builds.
    assert!(
        AuthLayer::builder()
            .build_with_decision(StaticTokenDecision::Unauthenticated)
            .unwrap()
            .allows_unauthenticated()
    );
}

#[test]
fn require_scopes_try_new_names_the_bad_scope() {
    assert_eq!(RequireScopes::try_new(["a", "a"]).unwrap().scopes(), ["a"]);
    for bad in ["", "two words", "q\"uote", "caf\u{e9}"] {
        assert_eq!(
            RequireScopes::try_new(["ok", bad]).unwrap_err().scope(),
            bad
        );
    }
    assert!(std::panic::catch_unwind(|| RequireScopes::new(["two words"])).is_err());
}

#[tokio::test]
async fn the_scoped_extractor_behind_the_http_layer_uses_its_refusal() {
    let (_jwks, v) = validator().await;
    let app = Router::new()
        .route("/test", post(write))
        .layer(HttpAuthLayer::builder().oauth(v).build().unwrap());
    assert_eq!(
        seen_axum(&app, Method::POST, Some(&bearer(&token("mcp:read")))).await,
        (403, Some(challenge_for("mcp:read mcp:write")), Vec::new())
    );
}

/// An `optional()` outer layer around an `allow_unauthenticated` inner one,
/// anonymous: `Scoped`, `AuthorizedToken` and `RequireScopes` all refuse
/// with the OUTER layer's 401 and challenge (with `resource_metadata`),
/// never the open layer's bare one.
#[tokio::test]
async fn extractors_and_route_checks_agree_behind_an_open_layer_inside_an_optional_one() {
    let (_jwks, v) = validator().await;
    let outer = || {
        AuthLayer::builder()
            .oauth(Arc::clone(&v))
            .optional()
            .build()
            .unwrap()
    };
    let scoped = Router::new()
        .route("/test", post(write))
        .route_layer(AuthLayer::allow_unauthenticated())
        .route_layer(outer());
    let token_route = Router::new()
        .route(
            "/test",
            post(|t: AuthorizedToken| async move { format!("{:?}", t.subject) }),
        )
        .route_layer(AuthLayer::allow_unauthenticated())
        .route_layer(outer());
    let layered = ok_app(|r| {
        r.route_layer(RequireScopes::new(["mcp:write"]))
            .route_layer(AuthLayer::allow_unauthenticated())
            .route_layer(outer())
    });
    let want = (401, Some(v.invalid_token_challenge()), Vec::new());
    assert!(want.1.as_deref().unwrap().contains("resource_metadata="));
    assert_eq!(seen_axum(&scoped, Method::POST, None).await, want);
    assert_eq!(seen_axum(&token_route, Method::POST, None).await, want);
    assert_eq!(seen_axum(&layered, Method::POST, None).await, want);
}

/// One request to `app` with the given headers: status, challenge, body.
async fn seen_with(app: &Router, method: Method, headers: &[(&str, &str)]) -> Seen {
    let mut request = Request::builder().method(method).uri("/test");
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::empty()).unwrap())
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

/// An axum `allow_unauthenticated` layer nested INSIDE an enforcing
/// `HttpAuthLayer`: a required extractor refuses with the outer layer's 401
/// and challenge (`resource_metadata` included), exactly as `RequireScopes`
/// and `Scoped` do on the same stack — never the open layer's bare
/// `DEFAULT_STATIC_CHALLENGE`.
#[tokio::test]
async fn a_required_extractor_behind_an_open_layer_inside_an_http_layer_sends_its_challenge() {
    let (_jwks, v) = validator().await;
    let want = (401, Some(v.invalid_token_challenge()), Vec::new());
    assert!(want.1.as_deref().unwrap().contains("resource_metadata="));
    let optional_outer = || {
        HttpAuthLayer::builder()
            .oauth(Arc::clone(&v))
            .optional()
            .build()
            .unwrap()
    };
    let token_route = Router::new()
        .route(
            "/test",
            post(|t: AuthorizedToken| async move { format!("{:?}", t.subject) }),
        )
        .route_layer(AuthLayer::allow_unauthenticated())
        .route_layer(optional_outer());
    let credential_route = Router::new()
        .route(
            "/test",
            post(|c: Credential| async move { format!("{c:?}") }),
        )
        .route_layer(AuthLayer::allow_unauthenticated())
        .route_layer(optional_outer());
    let scoped = Router::new()
        .route("/test", post(write))
        .route_layer(AuthLayer::allow_unauthenticated())
        .route_layer(optional_outer());
    let layered = ok_app(|r| {
        r.route_layer(RequireScopes::new(["mcp:write"]))
            .route_layer(AuthLayer::allow_unauthenticated())
            .route_layer(optional_outer())
    });
    for app in [&token_route, &credential_route, &scoped, &layered] {
        assert_eq!(seen_axum(app, Method::POST, None).await, want);
    }

    // A strict outer layer that accepted a static token: the handler wants an
    // OAuth token, so the outer layer's 401 `invalid_token`, with its
    // challenge.
    let token_route = Router::new()
        .route(
            "/test",
            post(|t: AuthorizedToken| async move { format!("{:?}", t.subject) }),
        )
        .route_layer(AuthLayer::allow_unauthenticated())
        .route_layer(
            HttpAuthLayer::builder()
                .oauth(Arc::clone(&v))
                .static_token(STATIC)
                .build()
                .unwrap(),
        );
    assert_eq!(
        seen_axum(&token_route, Method::POST, Some(&bearer(STATIC))).await,
        want
    );
}

/// An axum OAuth layer OUTSIDE an `HttpAuthLayer` holding only a static
/// token, a request presenting both: the innermost credential is the
/// static token, and `Scoped` answers from the innermost layer (its gate)
/// exactly as `RequireScopes` does — the same bytes on the same stack.
#[tokio::test]
async fn the_scoped_extractor_answers_from_the_innermost_layer_like_require_scopes() {
    let (_jwks, v) = validator().await;
    let outer = || {
        AuthLayer::builder()
            .oauth(Arc::clone(&v))
            .on_reject(json_reject)
            .build()
            .unwrap()
    };
    let inner = || {
        HttpAuthLayer::builder()
            .static_token(STATIC)
            .sources([CredentialSource::Raw(http::HeaderName::from_static(
                "x-api-key",
            ))])
            .build()
            .unwrap()
    };
    let scoped = Router::new()
        .route("/test", post(write))
        .route_layer(inner())
        .route_layer(outer());
    let layered = ok_app(|r| {
        r.route_layer(RequireScopes::new(["mcp:write"]))
            .route_layer(inner())
            .route_layer(outer())
    });
    let full = bearer(&token("mcp:read mcp:write"));
    let headers = [("authorization", full.as_str()), ("x-api-key", STATIC)];
    let from_scoped = seen_with(&scoped, Method::POST, &headers).await;
    let from_layer = seen_with(&layered, Method::POST, &headers).await;
    assert_eq!(from_scoped, from_layer);
    assert_eq!(from_scoped.0, 403);
    assert_eq!(
        from_scoped.1.as_deref(),
        Some(crate::refusal::BARE_INSUFFICIENT_SCOPE_CHALLENGE)
    );
}
