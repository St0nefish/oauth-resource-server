//! An axum API protected by OAuth: configuration from YAML, the auth layer on
//! the protected routes, and the RFC 9728 metadata routes outside it.
//!
//! ```sh
//! cargo run --example axum_basic --features axum,serde,testing
//! ```
//!
//! To run without network access, the example starts a fake authorization
//! server on a loopback port (from the `testing` feature) that publishes a
//! throwaway signing key, and mints its own tokens with that key. It then sends
//! requests through the router in-process and prints each response. In your
//! application, delete everything marked `DEMO ONLY`, point `issuer` at your
//! real authorization server, and serve the router with `axum::serve` as the
//! comment at the end shows.

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, header};
use axum::routing::get;
use axum::{Extension, Router};
use oauth_resource_server::axum::{AuthLayer, metadata_router};
use oauth_resource_server::testing;
use oauth_resource_server::{
    Credential, KeyNaming, OAuthConfig, OAuthValidator, static_token_policy,
};
use tower::ServiceExt;
use tracing::Level;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::prelude::*;

/// Stands in for your authorization server's issuer. In a real deployment the
/// JWKS would be discovered from it; here `jwks_uri` points at the fake server.
const ISSUER: &str = "https://auth.example.com/";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // This crate's `debug` lines (accepted tokens, requests with no credential)
    // are worth seeing while setting up; everything else at `info`.
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(
            Targets::new()
                .with_target("oauth_resource_server", Level::DEBUG)
                .with_default(Level::INFO),
        )
        .init();

    // DEMO ONLY: a fake authorization server publishing the throwaway key.
    let fake_as = testing::spawn_http_server(
        HashMap::from([("/jwks".to_string(), ("200 OK", testing::jwks_body()))]),
        None,
    )
    .await;

    // The configuration, as it would appear in your config file. Normally you
    // would omit `jwks_uri` and let it be discovered from `issuer`.
    let yaml = format!(
        r#"
enabled: true
issuer: "{ISSUER}"
jwks_uri: "{jwks}"
audience: "example-api"
resource: "https://api.example.com/v1"
required_scope: "api:read"
scopes_supported: ["api:read", "api:write"]
"#,
        jwks = fake_as.url,
    );
    let config: OAuthConfig = serde_yaml_ng::from_str(&yaml)?;
    let resolved = config
        .resolve(KeyNaming::Dotted("oauth"))?
        .expect("enabled: true");

    let oauth = Arc::new(OAuthValidator::new(&resolved)?);
    // Loads the keys now and re-reads them hourly. `refresh_now` waits for the
    // first load, so the log line below appears before the requests do.
    oauth.spawn_background_refresh();
    oauth.refresh_now().await?;

    let decision = static_token_policy(None, Some(&resolved), false)?;
    let auth = AuthLayer::from_decision(decision, Some(Arc::clone(&oauth)))?;

    let app = Router::new()
        .route("/v1/whoami", get(whoami))
        .route_layer(auth)
        .merge(metadata_router(Some(oauth)));

    // DEMO ONLY: tokens signed with the fake server's throwaway key.
    let reader = mint(&["api:read"]);
    let no_scope = mint(&["profile"]);

    for (what, uri, token) in [
        ("no token", "/v1/whoami", None),
        ("token without api:read", "/v1/whoami", Some(&no_scope)),
        ("token with api:read", "/v1/whoami", Some(&reader)),
        (
            "garbage token",
            "/v1/whoami",
            Some(&"not-a-jwt".to_string()),
        ),
        (
            "metadata (no token needed)",
            "/.well-known/oauth-protected-resource/v1",
            None,
        ),
    ] {
        let mut request = Request::builder().uri(uri);
        if let Some(token) = token {
            request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        let response = app.clone().oneshot(request.body(Body::empty())?).await?;
        println!("\n== {what}: GET {uri}");
        println!("   status: {}", response.status());
        if let Some(challenge) = response.headers().get(header::WWW_AUTHENTICATE) {
            println!("   www-authenticate: {}", challenge.to_str()?);
        }
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024).await?;
        if !body.is_empty() {
            println!("   body: {}", String::from_utf8_lossy(&body));
        }
    }

    // In a real server, instead of the requests above:
    //
    //     let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    //     axum::serve(listener, app).await?;
    Ok(())
}

/// Who called, read from the `Credential` the layer inserts.
async fn whoami(Extension(credential): Extension<Credential>) -> String {
    match credential {
        Credential::OAuth(token) => format!(
            "hello {} (scopes: {})",
            token.principal.as_deref().unwrap_or("(unnamed)"),
            token.scopes.join(" ")
        ),
        Credential::StaticToken => "hello, static-token caller".to_string(),
        _ => "hello".to_string(),
    }
}

/// DEMO ONLY: an RS256 access token for this example's issuer and audience,
/// valid for an hour, carrying `scopes`.
fn mint(scopes: &[&str]) -> String {
    testing::mint(
        testing::KEY_A_PEM,
        testing::KID_A,
        &serde_json::json!({
            "iss": ISSUER,
            "aud": "example-api",
            "sub": "0b9c7a52-0000-4000-8000-000000000003",
            "preferred_username": "alice",
            "exp": testing::now() + 3600,
            "scope": scopes.join(" "),
        }),
    )
}
