//! A plain hyper 1.x server with no web framework: `authenticate` checks the
//! credential, and `refusal` turns a refusal into the status and
//! `WWW-Authenticate` challenge the axum and tower layers would send.
//!
//! ```sh
//! cargo run --example hyper --features testing
//! ```
//!
//! To run without network access, the example starts a fake JWKS server on a
//! loopback port (from the `testing` feature), mints its tokens with that
//! server's throwaway key, and sends its own requests to the hyper server with
//! hyper's client. Everything marked `DEMO ONLY` goes away with a real
//! authorization server. (For a tower-based stack, the `tower` feature's
//! `HttpAuthLayer` does all of `handle` below in one layer.)

use std::convert::Infallible;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::{AUTHORIZATION, CONTENT_TYPE, WWW_AUTHENTICATE};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use oauth_resource_server::testing;
use oauth_resource_server::{
    Credential, KeyNaming, OAuthConfig, OAuthValidator, PROTECTED_RESOURCE_METADATA_PREFIX,
    TokenRejection, authenticate, refusal,
};
use tokio::net::{TcpListener, TcpStream};

const ISSUER: &str = "https://auth.example.com/";

/// The bearer token in an `Authorization` value: the scheme matched
/// case-insensitively (RFC 9110 §11.1), the token trimmed.
fn bearer(value: &str) -> Option<&str> {
    let (scheme, token) = value.split_once(' ')?;
    scheme.eq_ignore_ascii_case("bearer").then(|| token.trim())
}

async fn handle(
    request: Request<Incoming>,
    oauth: Arc<OAuthValidator>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let path = request.uri().path();

    // RFC 9728 metadata: outside authentication, since it is how a caller
    // with no credential finds out where to get one.
    if path == oauth.metadata_path() || path == PROTECTED_RESOURCE_METADATA_PREFIX {
        if request.method() != Method::GET {
            return Ok(status_only(StatusCode::METHOD_NOT_ALLOWED));
        }
        let mut response = Response::new(Full::from(oauth.metadata().to_string()));
        response
            .headers_mut()
            .insert(CONTENT_TYPE, "application/json".parse().unwrap());
        return Ok(response);
    }

    // One candidate per place a credential may be; here just `Authorization`.
    let candidate = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(bearer);
    match authenticate(candidate, None, Some(&oauth)).await {
        Ok(Credential::OAuth(token)) => Ok(Response::new(Full::from(format!(
            "hello, {}\n",
            token.principal.as_deref().unwrap_or("caller")
        )))),
        // `Credential` is `#[non_exhaustive]`; no static token is configured
        // here, so nothing else can be accepted.
        Ok(_) => Ok(status_only(StatusCode::INTERNAL_SERVER_ERROR)),
        Err(rejection) => {
            // The reason is for the log only, never the response. Every OAuth
            // client's first request has no credential, so that one is not
            // worth a warning (the layers log it at `debug` too).
            if rejection == TokenRejection::Missing {
                tracing::debug!(path, "no credential presented");
            } else {
                tracing::warn!(path, reason = ?rejection, "refused");
            }
            // The one mapping the layers use: 401 or 403, and the challenge
            // (`resource_metadata` included) on every refusal.
            let r = refusal(&rejection, Some(&oauth));
            let mut response = status_only(StatusCode::from_u16(r.status).unwrap());
            if let Some(challenge) = r.www_authenticate {
                response
                    .headers_mut()
                    .insert(WWW_AUTHENTICATE, challenge.parse().unwrap());
            }
            Ok(response)
        }
    }
}

fn status_only(status: StatusCode) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::default());
    *response.status_mut() = status;
    response
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt().init();

    // DEMO ONLY: a fake JWKS endpoint serving the throwaway key.
    let jwks = testing::spawn_jwks_server("200 OK", testing::jwks_body()).await;

    let resolved = OAuthConfig {
        enabled: true,
        issuer: ISSUER.into(),
        jwks_uri: Some(jwks.url.clone()),
        audience: "example-api".into(),
        resource: "https://api.example.com".into(),
        required_scopes: vec!["api:read".into()],
        ..OAuthConfig::default()
    }
    .resolve(KeyNaming::Dotted("oauth"))?
    .expect("enabled: true");
    let oauth = Arc::new(OAuthValidator::new(&resolved)?);
    oauth.spawn_background_refresh();

    // The server: one hyper HTTP/1 connection task per accepted socket.
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let server_oauth = Arc::clone(&oauth);
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            let oauth = Arc::clone(&server_oauth);
            tokio::spawn(async move {
                let service = service_fn(move |request| handle(request, Arc::clone(&oauth)));
                if let Err(e) = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await
                {
                    tracing::debug!("connection error: {e}");
                }
            });
        }
    });

    // DEMO ONLY: tokens signed with the throwaway key.
    let token = |scope: &str| {
        testing::mint(
            testing::KEY_A_PEM,
            testing::KID_A,
            &serde_json::json!({
                "iss": ISSUER, "aud": "example-api", "sub": "example-user",
                "exp": testing::now() + 300, "scope": scope,
            }),
        )
    };
    let requests = [
        ("no credential", "/api", None),
        (
            "valid token",
            "/api",
            Some(format!("Bearer {}", token("api:read"))),
        ),
        (
            "missing scope",
            "/api",
            Some(format!("Bearer {}", token("other"))),
        ),
        ("not a JWT", "/api", Some("Bearer not-a-jwt".to_string())),
        ("metadata", "/.well-known/oauth-protected-resource", None),
    ];
    for (label, path, authorization) in requests {
        let (status, challenge, body) = send(addr, path, authorization.as_deref()).await?;
        println!("{label}: {status}");
        if let Some(challenge) = challenge {
            println!("  WWW-Authenticate: {challenge}");
        }
        if !body.is_empty() {
            println!("  body: {}", body.trim_end());
        }
    }
    Ok(())
}

/// DEMO ONLY: one request over a fresh hyper client connection.
async fn send(
    addr: std::net::SocketAddr,
    path: &str,
    authorization: Option<&str>,
) -> Result<(StatusCode, Option<String>, String), Box<dyn std::error::Error>> {
    let stream = TcpStream::connect(addr).await?;
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
    tokio::spawn(connection);
    let mut request = Request::builder()
        .uri(path)
        .header("host", addr.to_string());
    if let Some(value) = authorization {
        request = request.header(AUTHORIZATION, value);
    }
    let response = sender
        .send_request(request.body(Full::<Bytes>::default())?)
        .await?;
    let status = response.status();
    let challenge = response
        .headers()
        .get(WWW_AUTHENTICATE)
        .map(|v| v.to_str().unwrap_or_default().to_string());
    let body = response.into_body().collect().await?.to_bytes();
    Ok((
        status,
        challenge,
        String::from_utf8_lossy(&body).into_owned(),
    ))
}
