//! Credentials from two headers, a static API key alongside OAuth, and JSON
//! rejection bodies.
//!
//! ```sh
//! cargo run --example multiple_sources --features axum,testing
//! ```
//!
//! OAuth clients send `Authorization: Bearer <access token>`; scripts send a
//! static key in `X-Api-Key`. Every source is checked against every mechanism,
//! so a bad credential in one header never hides a good one in the other.
//!
//! To run without network access, the example starts a fake authorization
//! server on a loopback port (from the `testing` feature) and mints tokens with
//! its throwaway key; everything marked `DEMO ONLY` is replaced by your real
//! authorization server in an application.

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{HeaderName, Request, header};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Extension, Json, Router};
use oauth_resource_server::axum::{AuthLayer, CredentialSource, RejectContext, metadata_router};
use oauth_resource_server::testing;
use oauth_resource_server::{
    Credential, KeyNaming, OAuthConfig, OAuthValidator, TokenRejection, static_token_policy,
};
use tower::ServiceExt;

const ISSUER: &str = "https://auth.example.com/";
const API_KEY: &str = "example-static-key-change-me";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt().init();

    // DEMO ONLY: a fake authorization server publishing the throwaway key.
    let fake_as = testing::spawn_http_server(
        HashMap::from([("/jwks".to_string(), ("200 OK", testing::jwks_body()))]),
        None,
    )
    .await;

    let resolved = OAuthConfig {
        enabled: true,
        issuer: ISSUER.into(),
        jwks_uri: Some(fake_as.url.clone()),
        audience: "example-api".into(),
        resource: "https://api.example.com".into(),
        required_scope: Some("api:read".into()),
        scopes_supported: Some(vec!["api:read".into()]),
        ..OAuthConfig::default()
    }
    .resolve(KeyNaming::Dotted("oauth"))?
    .expect("enabled: true");

    let oauth = Arc::new(OAuthValidator::new(&resolved)?);
    oauth.spawn_background_refresh();
    oauth.refresh_now().await?;

    // Dual mode: the static key and OAuth are both accepted. In an application
    // the key comes from a secret store (see the `env_config` example).
    let decision = static_token_policy(Some(API_KEY.to_string()), Some(&resolved), false)?;
    println!("static-token decision: {decision:?}");

    let auth = AuthLayer::builder()
        .oauth(Arc::clone(&oauth))
        .sources([
            CredentialSource::authorization_bearer(),
            CredentialSource::Raw(HeaderName::from_static("x-api-key")),
        ])
        .on_reject(json_rejection)
        .build_with_decision(decision)?;

    let app = Router::new()
        .route("/whoami", get(whoami))
        .route_layer(auth)
        .merge(metadata_router(Some(oauth)));

    // DEMO ONLY: access tokens signed with the fake server's throwaway key.
    let reader = mint(&["api:read"]);
    let no_scope = mint(&["profile"]);
    let bearer = |token: &str| format!("Bearer {token}");

    let cases: Vec<(&str, Vec<(&str, String)>)> = vec![
        ("nothing", vec![]),
        ("API key", vec![("x-api-key", API_KEY.to_string())]),
        ("wrong API key", vec![("x-api-key", "guess".to_string())]),
        ("access token", vec![("authorization", bearer(&reader))]),
        (
            "access token without api:read",
            vec![("authorization", bearer(&no_scope))],
        ),
        (
            "junk bearer token plus a good API key",
            vec![
                ("authorization", bearer("junk")),
                ("x-api-key", API_KEY.to_string()),
            ],
        ),
    ];

    for (what, headers) in cases {
        let mut request = Request::builder().uri("/whoami");
        for (name, value) in &headers {
            request = request.header(*name, value);
        }
        let response = app.clone().oneshot(request.body(Body::empty())?).await?;
        println!("\n== {what}");
        println!("   status: {}", response.status());
        if let Some(challenge) = response.headers().get(header::WWW_AUTHENTICATE) {
            println!("   www-authenticate: {}", challenge.to_str()?);
        }
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024).await?;
        println!("   body: {}", String::from_utf8_lossy(&body));
    }
    Ok(())
}

/// The refusal body. The crate still sets the status and, since OAuth is on,
/// the `WWW-Authenticate` challenge, whatever this returns. The reason inside
/// `TokenRejection::Invalid` is deliberately not echoed: it would tell an
/// unauthenticated caller which check failed. The layer logs it instead.
fn json_rejection(cx: RejectContext<'_>) -> axum::response::Response {
    let (error, description) = match cx.rejection {
        TokenRejection::InsufficientScope => (
            "insufficient_scope",
            "the access token lacks a required scope",
        ),
        TokenRejection::Missing => ("unauthorized", "no credential was presented"),
        _ => ("unauthorized", "the credential was not accepted"),
    };
    (
        cx.status,
        Json(serde_json::json!({ "error": error, "error_description": description })),
    )
        .into_response()
}

async fn whoami(Extension(credential): Extension<Credential>) -> Json<serde_json::Value> {
    Json(match credential {
        Credential::OAuth(token) => serde_json::json!({
            "via": "oauth",
            "subject": token.subject,
            "principal": token.principal,
            "scopes": token.scopes,
        }),
        Credential::StaticToken => serde_json::json!({ "via": "static api key" }),
        _ => serde_json::json!({ "via": "unknown" }),
    })
}

/// DEMO ONLY: an RS256 access token for this example's issuer and audience.
fn mint(scopes: &[&str]) -> String {
    testing::mint(
        testing::KEY_A_PEM,
        testing::KID_A,
        &serde_json::json!({
            "iss": ISSUER,
            "aud": "example-api",
            "sub": "7f3e2d1c-0000-4000-8000-000000000001",
            "preferred_username": "alice",
            "exp": testing::now() + 3600,
            "scope": scopes.join(" "),
        }),
    )
}
