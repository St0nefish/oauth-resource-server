//! The validator on its own, without axum: discovery, `validate`,
//! `authenticate`, and the challenge headers to send on a refusal.
//!
//! ```sh
//! cargo run --example standalone_validator --features testing
//! ```
//!
//! To run without network access, the example starts a fake authorization
//! server on a loopback port (from the `testing` feature). It publishes an
//! OpenID Connect discovery document and a JWKS holding a throwaway key, and the
//! example mints its tokens with that key. With a real authorization server,
//! only the `issuer` changes; everything marked `DEMO ONLY` goes away.

use std::collections::HashMap;

use oauth_resource_server::testing;
use oauth_resource_server::{
    Credential, KeyNaming, OAuthConfig, OAuthValidator, TokenRejection, authenticate,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt().init();

    // DEMO ONLY: the fake authorization server. Its issuer is its own loopback
    // URL, so discovery can find it, and it serves the throwaway key.
    let fake_as = testing::spawn_http_server(HashMap::new(), None).await;
    let issuer = fake_as.base.clone();
    fake_as.routes.lock().unwrap().extend([
        (
            "/.well-known/openid-configuration".to_string(),
            (
                "200 OK",
                serde_json::json!({ "issuer": issuer, "jwks_uri": format!("{issuer}/jwks") })
                    .to_string(),
            ),
        ),
        ("/jwks".to_string(), ("200 OK", testing::jwks_body())),
    ]);

    // No `jwks_uri`: it is discovered from the issuer, and the discovered
    // document's `issuer` must match this one exactly.
    let resolved = OAuthConfig {
        enabled: true,
        issuer: issuer.clone(),
        audience: "example-api".into(),
        resource: "https://api.example.com".into(),
        required_scopes: vec!["api:read".into()],
        scopes_supported: Some(vec!["api:read".into(), "api:write".into()]),
        ..OAuthConfig::default()
    }
    .resolve(KeyNaming::Dotted("oauth"))?
    .expect("enabled: true");

    let validator = OAuthValidator::new(&resolved)?;
    // Discovery plus the first key load. A long-running server would call
    // `spawn_background_refresh` on an `Arc<OAuthValidator>` instead.
    let keys = validator.refresh_now().await?;
    println!("loaded {keys} signing key(s)");
    println!("metadata path:     {}", validator.metadata_path());
    println!("metadata document: {}", validator.metadata());
    println!("401 challenge:     {}", validator.invalid_token_challenge());
    println!(
        "403 challenge:     {}",
        validator.insufficient_scope_challenge()
    );

    // DEMO ONLY: tokens signed with the throwaway key.
    let claims = |scope: &str, exp_offset: i64, aud: &str| {
        serde_json::json!({
            "iss": issuer,
            "aud": aud,
            "sub": "5c1d8e4a-0000-4000-8000-000000000002",
            "exp": testing::now().saturating_add_signed(exp_offset),
            "scope": scope,
        })
    };
    let good = testing::mint(
        testing::KEY_A_PEM,
        testing::KID_A,
        &claims("api:read api:write", 3600, "example-api"),
    );
    let cases = [
        ("valid token", good.clone()),
        (
            "missing the required scope",
            testing::mint(
                testing::KEY_A_PEM,
                testing::KID_A,
                &claims("profile", 3600, "example-api"),
            ),
        ),
        (
            "expired an hour ago",
            testing::mint(
                testing::KEY_A_PEM,
                testing::KID_A,
                &claims("api:read", -3600, "example-api"),
            ),
        ),
        (
            "for another audience",
            testing::mint(
                testing::KEY_A_PEM,
                testing::KID_A,
                &claims("api:read", 3600, "some-other-api"),
            ),
        ),
        (
            "signed by a key the server never published",
            testing::mint(
                testing::KEY_B_PEM,
                testing::KID_A,
                &claims("api:read", 3600, "example-api"),
            ),
        ),
        ("not a JWT at all", "an-opaque-token".to_string()),
    ];

    println!();
    for (what, token) in &cases {
        match validator.validate(token).await {
            Ok(accepted) => println!(
                "{what}: accepted, subject {:?}, scopes {:?}",
                accepted.subject, accepted.scopes
            ),
            // 403: send `insufficient_scope_challenge()` in WWW-Authenticate.
            Err(TokenRejection::InsufficientScope) => {
                println!("{what}: 403 insufficient_scope")
            }
            // 401: send `invalid_token_challenge()`. The reason is for your
            // logs only; never return it to the caller. Its `kind()` is the
            // stable, matchable part (`as_str()` for a metrics label).
            Err(TokenRejection::Invalid(reason)) => {
                println!("{what}: 401, kind {}, reason: {reason}", reason.kind())
            }
            Err(other) => println!("{what}: 401 ({other:?})"),
        }
    }

    // `authenticate` checks several candidates (one per header, say) against a
    // static token and OAuth, and accepts if any one passes.
    println!();
    let static_token = Some("example-static-key-change-me");
    for (what, candidates) in [
        ("no candidates", vec![]),
        (
            "junk plus the static key",
            vec!["junk", "example-static-key-change-me"],
        ),
        (
            "junk plus a valid access token",
            vec!["junk", good.as_str()],
        ),
        ("junk only", vec!["junk"]),
    ] {
        let outcome = authenticate(candidates, static_token, Some(&validator)).await;
        let described = match outcome {
            Ok(Credential::StaticToken) => "accepted: static token".to_string(),
            Ok(Credential::OAuth(token)) => format!("accepted: OAuth, subject {:?}", token.subject),
            Ok(other) => format!("accepted: {other:?}"),
            Err(rejection) => format!("refused: {rejection:?}"),
        };
        println!("authenticate, {what}: {described}");
    }
    Ok(())
}
