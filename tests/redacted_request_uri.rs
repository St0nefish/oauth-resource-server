//! A credential in a refused request's query (RFC 6750 §2.3 `access_token`)
//! never reaches a log line or a `RejectContext` `Debug`, through either
//! layer.
//!
//! A test binary of its own so the capturing subscriber can be the global
//! default (see `tests/redacted_logs.rs` for why a thread-local one races);
//! every scenario runs inside the one test function below.
#![cfg(all(feature = "axum", feature = "testing"))]

use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{Request, Response, StatusCode};
use oauth_resource_server::axum::{AuthLayer, RejectContext};
use oauth_resource_server::http_layer::HttpAuthLayer;
use oauth_resource_server::{OAuthValidator, testing};
use tower::{ServiceBuilder, ServiceExt, service_fn};

const SECRET: &str = "s3cret";
const URI: &str = "/mcp/tools?access_token=s3cret&x=1";

#[derive(Clone, Default)]
struct Buf(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Buf {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Buf {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

fn validator() -> Arc<OAuthValidator> {
    // No key is ever fetched: every request here is refused before that.
    Arc::new(OAuthValidator::new(&testing::resolved_config("http://127.0.0.1:1/jwks")).unwrap())
}

#[tokio::test]
async fn a_credential_in_the_request_query_never_reaches_a_log_or_debug() {
    let logs = Buf::default();
    let writer = logs.clone();
    tracing::subscriber::set_global_default(
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish(),
    )
    .unwrap();
    let seen = Buf::default();

    // Every credential shape each layer can hold: static only, OAuth only,
    // both. The request presents a wrong static token and a junk bearer.
    for (static_token, oauth) in [(true, false), (false, true), (true, true)] {
        let mut axum_layer = AuthLayer::builder();
        let mut http_layer = HttpAuthLayer::builder();
        if static_token {
            axum_layer = axum_layer.static_token("expected-static-key");
            http_layer = http_layer.static_token("expected-static-key");
        }
        if oauth {
            axum_layer = axum_layer.oauth(validator());
            http_layer = http_layer.oauth(validator());
        }

        let out = seen.clone();
        let axum_layer = axum_layer
            .on_reject(move |cx: RejectContext<'_>| {
                let shown = format!("{cx:?}");
                assert!(shown.contains("/mcp/tools?***"), "{shown}");
                std::io::Write::write_all(&mut out.clone(), shown.as_bytes()).unwrap();
                axum::response::IntoResponse::into_response("refused")
            })
            .build()
            .unwrap();
        let app = axum::Router::new()
            .route("/mcp/tools", axum::routing::get(|| async { "ok" }))
            .layer(axum_layer);
        let response = app
            .oneshot(
                Request::builder()
                    .uri(URI)
                    .header("authorization", "Bearer s3cret.junk.token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let out = seen.clone();
        let http_layer = http_layer
            .on_reject(move |cx: RejectContext<'_>| {
                let shown = format!("{cx:?}");
                assert!(shown.contains("/mcp/tools?***"), "{shown}");
                std::io::Write::write_all(&mut out.clone(), shown.as_bytes()).unwrap();
                Response::new(String::from("refused"))
            })
            .build()
            .unwrap();
        let service = ServiceBuilder::new().layer(http_layer).service(service_fn(
            |_: Request<String>| async {
                Ok::<_, std::convert::Infallible>(Response::new(String::from("ok")))
            },
        ));
        let response = service
            .oneshot(
                Request::builder()
                    .uri(URI)
                    .header("authorization", "Bearer s3cret.junk.token")
                    .body(String::new())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    let shown = seen.text();
    assert_eq!(shown.matches("RejectContext").count(), 6, "{shown}");
    assert!(
        !shown.contains(SECRET),
        "leaked into a RejectContext: {shown}"
    );
    let logged = logs.text();
    assert!(
        logged.contains("/mcp/tools"),
        "the refusals were logged: {logged}"
    );
    assert!(!logged.contains(SECRET), "leaked into a log line: {logged}");
}
