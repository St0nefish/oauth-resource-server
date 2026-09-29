//! A validator built from a hand-edited config whose `WWW-Authenticate`
//! challenge would not be a valid header value logs that exactly once, at
//! `error`, with the setting named and the URL redacted.
//!
//! A test binary of its own so the capturing subscriber can be the global
//! default (see `tests/redacted_logs.rs` for why a thread-local one races).
#![cfg(feature = "testing")]

use std::sync::{Arc, Mutex};

use oauth_resource_server::{OAuthValidator, TokenRejection, refusal, testing};

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

#[test]
fn an_invalid_challenge_is_logged_once_at_error_and_refusals_stay_valid() {
    let buf = LogBuf::default();
    let writer = buf.clone();
    tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_ansi(false)
        .with_max_level(tracing::Level::DEBUG)
        .init();

    let mut cfg = testing::resolved_config("http://127.0.0.1:1/jwks");
    cfg.resource = "https://alice:s3cret@api.example.test/v1\r\nX-Injected: 1".into();
    let v = OAuthValidator::new(&cfg).expect("a hand-edited config still builds");

    for rejection in [
        TokenRejection::Missing,
        TokenRejection::Invalid("x".into()),
        TokenRejection::InsufficientScope,
    ] {
        let challenge = refusal(&rejection, Some(&v)).www_authenticate.unwrap();
        assert!(
            challenge
                .bytes()
                .all(|b| b == b' ' || b == b'\t' || (0x21..=0x7e).contains(&b)),
            "{challenge:?}"
        );
    }

    let text = String::from_utf8_lossy(&buf.0.lock().unwrap()).into_owned();
    let marker = "is not a valid HTTP header value";
    assert_eq!(text.matches(marker).count(), 1, "{text}");
    let line = text.lines().find(|l| l.contains(marker)).unwrap();
    assert!(line.contains("ERROR"), "{line}");
    assert!(line.contains("oauth.resource"), "{line}");
    assert!(
        !text.contains("s3cret") && !text.contains("alice"),
        "{text}"
    );
}
