//! A JWKS key that declares no `alg` (usable for every allowlisted algorithm
//! its type can produce — the documented RFC 8725 §3.1 deviation) is warned
//! about once, naming its `kid`, the first time it appears — not on every
//! refresh.
//!
//! A test binary of its own, so the capturing subscriber can be the global
//! default (see `tests/redacted_logs.rs` for why a thread-local one races).
#![cfg(feature = "testing")]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use oauth_resource_server::{OAuthValidator, testing};

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

    /// The captured lines carrying the ambiguous-key warning.
    fn warnings(&self) -> Vec<String> {
        self.text()
            .lines()
            .filter(|line| line.contains("declares no alg"))
            .map(str::to_owned)
            .collect()
    }
}

#[tokio::test]
async fn an_alg_less_key_is_warned_about_once_naming_its_kid() {
    let logs = LogBuf::default();
    let writer = logs.clone();
    tracing::subscriber::set_global_default(
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::WARN)
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish(),
    )
    .unwrap();

    let server = testing::spawn_http_server(HashMap::new(), None).await;
    let publish = |keys: &[serde_json::Value]| {
        server
            .routes
            .lock()
            .unwrap()
            .insert("/jwks".to_string(), ("200 OK", testing::jwks_of(keys)));
    };
    let v = OAuthValidator::new(&testing::resolved_config(&server.url)).unwrap();

    // A key set with one alg-less key: one warning, naming it.
    publish(&[testing::jwk_rsa_a_any_alg("ambiguous-one")]);
    assert_eq!(v.refresh_now().await.unwrap(), 1);
    let warnings = logs.warnings();
    assert_eq!(warnings.len(), 1, "{}", logs.text());
    assert!(warnings[0].contains("\"ambiguous-one\""), "{}", warnings[0]);
    assert!(warnings[0].contains("RS256"), "{}", warnings[0]);

    // The same key again on the next refresh: no new warning.
    assert_eq!(v.refresh_now().await.unwrap(), 1);
    assert_eq!(logs.warnings().len(), 1, "{}", logs.text());

    // A second alg-less key appears next to it: warned about, once.
    publish(&[
        testing::jwk_rsa_a_any_alg("ambiguous-one"),
        testing::jwk_rsa_a_any_alg("ambiguous-two"),
    ]);
    assert_eq!(v.refresh_now().await.unwrap(), 2);
    let warnings = logs.warnings();
    assert_eq!(warnings.len(), 2, "{}", logs.text());
    assert!(warnings[1].contains("\"ambiguous-two\""), "{}", warnings[1]);

    // Keys that declare their `alg` are never warned about.
    publish(&[testing::jwk_rsa_a(), testing::jwk_ec()]);
    assert_eq!(v.refresh_now().await.unwrap(), 2);
    assert_eq!(logs.warnings().len(), 2, "{}", logs.text());
}
