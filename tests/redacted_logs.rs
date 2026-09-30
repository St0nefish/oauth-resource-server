//! A credential in a configured or discovered URL never reaches a log line.
//!
//! A test binary of its own, so the capturing subscriber can be the global
//! default: a thread-local one (`set_default`) races, under parallel tests,
//! with other threads first hitting the same `warn!` over tracing's global
//! callsite-interest cache, and then captures nothing. For the same reason
//! every scenario runs inside the one test function below.
//!
//! Every URL here carries the same secrets — userinfo `alice:s3cret` (sent as
//! Basic auth) and a query `key=t0ken` — and the one assertion that matters is
//! that none of them appears anywhere in the captured output, at `debug` and
//! above. `0.0.0.0` stands in for "a plain-http, non-loopback host": it is
//! not a loopback address, and a connection to port 1 on it is refused at
//! once, so no scenario waits on a network timeout.
#![cfg(feature = "testing")]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use oauth_resource_server::{OAuthValidator, ResolvedOAuthConfig, testing};

const SECRETS: [&str; 3] = ["alice", "s3cret", "t0ken"];

/// A plain-http, non-loopback URL carrying every secret.
const INSECURE_JWKS: &str = "http://alice:s3cret@0.0.0.0:1/keys?key=t0ken";

#[derive(Clone, Default)]
struct LogBuf(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for LogBuf {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl LogBuf {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }

    /// Yield until `marker` has been logged `count` times in total.
    async fn wait_for(&self, marker: &str, count: usize) {
        while self.text().matches(marker).count() < count {
            tokio::task::yield_now().await;
        }
    }
}

/// `url` with `alice:s3cret@` inserted after the scheme.
fn with_userinfo(url: &str) -> String {
    url.replacen("://", "://alice:s3cret@", 1)
}

/// A validator for `cfg`, with its background refresh running.
fn start(cfg: &ResolvedOAuthConfig) -> (Arc<OAuthValidator>, tokio::task::JoinHandle<()>) {
    let v = Arc::new(OAuthValidator::new(cfg).unwrap());
    let task = v.spawn_background_refresh();
    (v, task)
}

const LOADED: &str = "signing keys loaded";
const FAILED: &str = "could not load the authorization server";

#[tokio::test]
async fn a_credential_in_a_url_never_reaches_a_log_line() {
    let logs = LogBuf::default();
    let writer = logs.clone();
    tracing::subscriber::set_global_default(
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish(),
    )
    .unwrap();
    let mut failures = 0;

    // 1. A configured jwks_uri that fails: the background `warn` and its error.
    let down = testing::spawn_jwks_server("503 Service Unavailable", "{}".into()).await;
    let (_v, task) = start(&testing::resolved_config(&format!(
        "{}?key=t0ken",
        with_userinfo(&down.url)
    )));
    failures += 1;
    logs.wait_for(FAILED, failures).await;
    task.abort();
    let shown = format!("{}?***", down.url.replacen("://", "://***@", 1));
    assert!(logs.text().contains(&shown), "{}", logs.text());

    // 2. A configured jwks_uri that works: `Fetched JWKS` (debug) and the
    //    `keys loaded` line.
    let up = testing::spawn_jwks_server("200 OK", testing::jwks_body()).await;
    let (_v, task) = start(&testing::resolved_config(&format!(
        "{}?key=t0ken",
        with_userinfo(&up.url)
    )));
    logs.wait_for(LOADED, 1).await;
    task.abort();
    assert!(logs.text().contains("Fetched JWKS"), "{}", logs.text());

    // 3. Discovery from an issuer carrying userinfo, which names a plain-http,
    //    non-loopback jwks_uri (accepted under `allow_insecure_http`): the
    //    `discovered` info line and the insecure-URI warning.
    let idp = testing::spawn_http_server(HashMap::new(), None).await;
    let issuer = format!("{}/app/", with_userinfo(&idp.base));
    idp.routes.lock().unwrap().insert(
        "/app/.well-known/openid-configuration".into(),
        (
            "200 OK",
            serde_json::json!({"issuer": issuer, "jwks_uri": INSECURE_JWKS}).to_string(),
        ),
    );
    let mut cfg = testing::resolved_config("");
    cfg.issuer = issuer.clone();
    cfg.allow_insecure_http = true;
    let (_v, task) = start(&cfg);
    failures += 1;
    logs.wait_for(FAILED, failures).await;
    task.abort();
    let text = logs.text();
    assert!(text.contains("discovered the JWKS URI"), "{text}");
    assert!(
        text.contains("discovered JWKS URI uses plain http"),
        "{text}"
    );

    // 4. Failed discovery: the `Tried:` list, with both of
    //    `jwks_uri_from_metadata`'s refusals in it — a document for another
    //    issuer (OIDC path) and a cleartext non-loopback jwks_uri without the
    //    opt-in (RFC 8414 path).
    let idp = testing::spawn_http_server(HashMap::new(), None).await;
    let issuer = format!("{}/other/", with_userinfo(&idp.base));
    {
        let mut routes = idp.routes.lock().unwrap();
        routes.insert(
            "/other/.well-known/openid-configuration".into(),
            (
                "200 OK",
                serde_json::json!({
                    "issuer": "http://alice:s3cret@elsewhere.example.test/?key=t0ken",
                    "jwks_uri": INSECURE_JWKS,
                })
                .to_string(),
            ),
        );
        routes.insert(
            "/.well-known/oauth-authorization-server/other".into(),
            (
                "200 OK",
                serde_json::json!({"issuer": issuer, "jwks_uri": INSECURE_JWKS}).to_string(),
            ),
        );
    }
    let mut cfg = testing::resolved_config("");
    cfg.issuer = issuer;
    let (_v, task) = start(&cfg);
    failures += 1;
    logs.wait_for(FAILED, failures).await;
    task.abort();
    let text = logs.text();
    assert!(text.contains("Tried:"), "{text}");
    assert!(text.contains("does not match"), "{text}");
    assert!(text.contains("refused (RFC 8414"), "{text}");

    // 5. A loopback JWKS endpoint redirecting to a plain-http, non-loopback
    //    URL: refused, with or without the opt-in (a fetch that starts on
    //    loopback never leaves it), the target shown redacted.
    let status: &'static str =
        Box::leak(format!("302 Found\r\nLocation: {INSECURE_JWKS}").into_boxed_str());
    let hop = testing::spawn_jwks_server(status, "{}".into()).await;
    for allow_insecure_http in [false, true] {
        let mut cfg = testing::resolved_config(&hop.url);
        cfg.allow_insecure_http = allow_insecure_http;
        let (_v, task) = start(&cfg);
        failures += 1;
        logs.wait_for(FAILED, failures).await;
        task.abort();
    }
    let text = logs.text();
    assert_eq!(
        text.matches(
            "redirect from a loopback URL to a non-loopback host (http://***@0.0.0.0:1/keys?***)"
        )
        .count(),
        2,
        "{text}"
    );

    // 6. The validator's startup warnings for a plain-http, non-loopback
    //    issuer, jwks_uri and resource, all carrying userinfo (and the
    //    jwks_uri a query) under `allow_insecure_http`. No I/O.
    let mut cfg = testing::resolved_config(INSECURE_JWKS);
    cfg.issuer = "http://alice:s3cret@idp.example.test/app/".into();
    cfg.resource = "http://alice:s3cret@api.example.test/v1".into();
    cfg.allow_insecure_http = true;
    let _v = OAuthValidator::new(&cfg).unwrap();
    let text = logs.text();
    for setting in [
        "issuer uses plain http",
        "jwks_uri uses plain http",
        "resource uses plain http",
    ] {
        assert!(text.contains(setting), "{setting}: {text}");
    }
    //    The non-canonical-spelling warning, for a jwks_uri the parser has to
    //    repair, carrying both secrets; and the validator's own `Debug`.
    let mut cfg = testing::resolved_config("https:/alice:s3cret@idp.example.test/keys?key=t0ken");
    cfg.issuer = "https://alice:s3cret@idp.example.test/app/".into();
    let v = OAuthValidator::new(&cfg).unwrap();
    let text = logs.text();
    assert!(
        text.contains("jwks_uri \"https://***@idp.example.test/keys?***\" is not canonically"),
        "{text}"
    );
    let shown = format!("{v:?} {cfg:?}");
    assert!(
        shown.contains("https://***@idp.example.test/app/"),
        "{shown}"
    );
    for secret in SECRETS {
        assert!(!shown.contains(secret), "{secret} leaked into: {shown}");
    }

    // 7. An explicit proxy carrying a credential: the build-time cleartext
    //    warning for a plain-http, non-loopback proxy, then a background
    //    refresh failing through it (nothing listens there). A refused proxy
    //    URL's error and the builder's `Debug` are checked too.
    let mut cfg = testing::resolved_config("https://idp.example.test/jwks");
    cfg.allow_insecure_http = true;
    let builder = OAuthValidator::builder(&cfg).proxy("http://alice:s3cret@0.0.0.0:1");
    let shown = format!("{builder:?}");
    let v = Arc::new(builder.build().unwrap());
    let task = v.spawn_background_refresh();
    failures += 1;
    logs.wait_for(FAILED, failures).await;
    task.abort();
    assert!(
        logs.text().contains("the proxy URL carries a credential"),
        "{}",
        logs.text()
    );
    let err = OAuthValidator::builder(&cfg)
        .proxy("http://alice:s3cret@proxy.example.test/p?key=t0ken")
        .build()
        .unwrap_err();
    let shown = format!("{shown} {err} {err:?} {:?}", v.key_set_status());
    for secret in SECRETS {
        assert!(!shown.contains(secret), "{secret} leaked into: {shown}");
    }

    let logged = logs.text();
    for secret in SECRETS {
        assert!(!logged.contains(secret), "{secret} leaked into: {logged}");
    }
}
