//! Configuration from environment variables: the OAuth settings, a static API
//! key, an application default for the required scope, and the startup
//! decision about which credentials to accept.
//!
//! ```sh
//! # Nothing set: explains what to set, and exits.
//! cargo run --example env_config --features env,axum
//!
//! # OAuth plus a static key read from a file (dual mode).
//! echo 'example-static-key-change-me' > /tmp/api_key
//! MYAPP_OAUTH_ISSUER=https://auth.example.com/ \
//! MYAPP_OAUTH_AUDIENCE=example-api \
//! MYAPP_OAUTH_RESOURCE=https://api.example.com \
//! MYAPP_API_KEY_FILE=/tmp/api_key \
//!   cargo run --example env_config --features env,axum
//!
//! # A partial set fails, naming every missing variable at once.
//! MYAPP_OAUTH_ISSUER=https://auth.example.com/ cargo run --example env_config --features env,axum
//! ```
//!
//! The example builds everything a server needs and prints it, but makes no
//! network request: a server would also start the validator's background key
//! refresh and serve the router (see the `axum_basic` example).

use std::process::ExitCode;
use std::sync::Arc;

use axum::Router;
use axum::routing::get;
use oauth_resource_server::axum::{AuthLayer, metadata_router};
use oauth_resource_server::env::{secret_from_env, unresolved_oauth_config_from_env};
use oauth_resource_server::{OAuthValidator, StaticTokenDecision, static_token_policy};

/// This application's default when the operator names no required scope.
const DEFAULT_REQUIRED_SCOPE: &str = "api:read";

fn main() -> ExitCode {
    tracing_subscriber::fmt().init();
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // `ConfigError`'s Display lists every problem, one per line.
            eprintln!("startup failed: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    // MYAPP_API_KEY, or a path in MYAPP_API_KEY_FILE. Never printed.
    let api_key = secret_from_env("MYAPP_API_KEY")?;

    // MYAPP_OAUTH_ISSUER, MYAPP_OAUTH_AUDIENCE, ... (each also as `_FILE`).
    // The unresolved form lets the application apply its own defaults before
    // validation; `oauth_config_from_env` is the one-call form without them.
    let oauth_config = match unresolved_oauth_config_from_env("MYAPP_OAUTH_") {
        Some(mut loaded) => {
            let cfg = &mut loaded.config;
            if cfg.required_scope.is_none() && cfg.required_scopes.is_empty() {
                cfg.required_scope = Some(DEFAULT_REQUIRED_SCOPE.to_string());
            }
            // Unless MYAPP_OAUTH_SCOPES_SUPPORTED is set, `resolve` advertises
            // the required scopes, this default included.
            loaded.resolve()?
        }
        None => None,
    };

    let decision = match static_token_policy(api_key, oauth_config.as_ref(), false) {
        Ok(decision) => decision,
        Err(_) => {
            println!(
                "No authentication is configured. Set MYAPP_API_KEY (or MYAPP_API_KEY_FILE) \
                 for a static API key, and/or MYAPP_OAUTH_ISSUER, MYAPP_OAUTH_AUDIENCE and \
                 MYAPP_OAUTH_RESOURCE for OAuth. See this example's header for a full \
                 command line."
            );
            return Ok(());
        }
    };

    // The policy returns a decision, not a message, so the application says in
    // its own words what it decided.
    match &decision {
        StaticTokenDecision::StaticAndOAuth(_) => {
            println!("accepting the static API key and OAuth access tokens")
        }
        StaticTokenDecision::StaticOnly(_) => println!(
            "accepting the static API key only; set MYAPP_OAUTH_* to enable per-user OAuth"
        ),
        StaticTokenDecision::OAuthOnly => println!("accepting OAuth access tokens only"),
        StaticTokenDecision::StaticIgnored => println!(
            "accepting OAuth access tokens only: MYAPP_API_KEY is set but \
             MYAPP_OAUTH_ACCEPT_STATIC_BEARER=false"
        ),
        other => println!("decision: {other:?}"),
    }

    let oauth = match &oauth_config {
        Some(resolved) => {
            let validator = Arc::new(OAuthValidator::new(resolved)?);
            // A server would start the key refresh here:
            //     validator.spawn_background_refresh();
            println!("required scopes:   {:?}", resolved.required_scopes);
            println!("metadata path:     {}", validator.metadata_path());
            println!("metadata document: {}", validator.metadata());
            println!("401 challenge:     {}", validator.invalid_token_challenge());
            Some(validator)
        }
        None => None,
    };

    let auth = AuthLayer::from_decision(decision, oauth.clone())?;
    println!("auth layer: {auth:?}");
    let _app: Router = Router::new()
        .route("/v1/things", get(|| async { "the protected things" }))
        .route_layer(auth)
        .merge(metadata_router(oauth));
    println!("router built; a server would now serve it");
    Ok(())
}
