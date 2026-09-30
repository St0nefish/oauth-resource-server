//! The stable auth-outcome log fields and span fields (oauth-resource-server#11):
//! exact names and values for every outcome, no secret anywhere, and a
//! hostile `kid` bounded and escaped in the validation spans.
//!
//! A test binary of its own, so the capturing subscriber can be the global
//! default (see `tests/redacted_logs.rs` for why a thread-local one races),
//! and every scenario runs inside the one test function below.
#![cfg(all(feature = "axum", feature = "mcp", feature = "testing"))]

mod support;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use http::Method;
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::{Layer, Registry};

use support::{PURGE_CALL, STATIC_LABEL, STATIC_SECRET, fixture, send, with_foreign_signature};

type Fields = BTreeMap<String, String>;

/// One captured event: level, target and every field (`message` included).
#[derive(Clone, Debug)]
struct Captured {
    level: Level,
    target: String,
    fields: Fields,
}

/// One span as it ended up: its name and every field recorded on it.
#[derive(Clone, Debug)]
struct CapturedSpan {
    name: &'static str,
    fields: Fields,
}

#[derive(Clone, Default)]
struct Capture {
    events: Arc<Mutex<Vec<Captured>>>,
    spans: Arc<Mutex<Vec<(Id, CapturedSpan)>>>,
}

struct Collect<'a>(&'a mut Fields);

impl Visit for Collect<'_> {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.insert(field.name().into(), value.into());
    }
    fn record_u64(&mut self, field: &Field, value: u64) {
        self.0.insert(field.name().into(), value.to_string());
    }
    fn record_i64(&mut self, field: &Field, value: i64) {
        self.0.insert(field.name().into(), value.to_string());
    }
    fn record_bool(&mut self, field: &Field, value: bool) {
        self.0.insert(field.name().into(), value.to_string());
    }
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.0.insert(field.name().into(), format!("{value:?}"));
    }
}

impl<S: Subscriber + for<'a> LookupSpan<'a>> Layer<S> for Capture {
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, _: Context<'_, S>) {
        let mut fields = Fields::new();
        attrs.record(&mut Collect(&mut fields));
        self.spans.lock().unwrap().push((
            id.clone(),
            CapturedSpan {
                name: attrs.metadata().name(),
                fields,
            },
        ));
    }

    fn on_record(&self, id: &Id, values: &Record<'_>, _: Context<'_, S>) {
        let mut spans = self.spans.lock().unwrap();
        // Ids are reused once a span closes; the newest holder is this one.
        if let Some((_, span)) = spans.iter_mut().rev().find(|(sid, _)| sid == id) {
            values.record(&mut Collect(&mut span.fields));
        }
    }

    fn on_event(&self, event: &Event<'_>, _: Context<'_, S>) {
        let mut fields = Fields::new();
        event.record(&mut Collect(&mut fields));
        self.events.lock().unwrap().push(Captured {
            level: *event.metadata().level(),
            target: event.metadata().target().into(),
            fields,
        });
    }
}

impl Capture {
    fn take_events(&self) -> Vec<Captured> {
        std::mem::take(&mut *self.events.lock().unwrap())
    }
    fn take_spans(&self) -> Vec<CapturedSpan> {
        std::mem::take(&mut *self.spans.lock().unwrap())
            .into_iter()
            .map(|(_, span)| span)
            .collect()
    }
}

/// The one event carrying `auth.outcome`; the scenario must log exactly one.
fn auth_event(events: &[Captured]) -> Captured {
    let found: Vec<_> = events
        .iter()
        .filter(|e| e.fields.contains_key("auth.outcome"))
        .cloned()
        .collect();
    assert_eq!(found.len(), 1, "{events:#?}");
    found.into_iter().next().unwrap()
}

/// Assert `event`'s level, message and exact `auth.*` field set.
fn assert_auth(event: &Captured, level: Level, message: &str, auth: &[(&str, &str)]) {
    assert_eq!(event.level, level, "{event:#?}");
    assert_eq!(event.fields["message"], message, "{event:#?}");
    let got: Vec<(&str, &str)> = event
        .fields
        .iter()
        .filter(|(k, _)| k.starts_with("auth."))
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let mut want = auth.to_vec();
    want.sort();
    assert_eq!(got, want, "{event:#?}");
}

#[tokio::test]
async fn auth_outcomes_carry_stable_fields_and_spans_bound_the_header() {
    let capture = Capture::default();
    let text = Arc::new(Mutex::new(Vec::<u8>::new()));
    let sink = Arc::clone(&text);
    let fmt = tracing_subscriber::fmt::layer()
        .with_ansi(false)
        .with_writer(move || SinkWriter(Arc::clone(&sink)));
    tracing::subscriber::set_global_default(
        Registry::default()
            .with(capture.clone())
            .with(fmt.with_filter(tracing_subscriber::filter::LevelFilter::TRACE)),
    )
    .unwrap();

    let f = fixture().await;
    let app = &f.app;
    let valid = f.authority.token().sign();
    let expired = f.authority.token().expired().sign();
    let bad_signature =
        with_foreign_signature(&valid, &f.authority.token().subject("someone-else").sign());
    let unscoped = f.authority.token().scopes(["other:scope"]).sign();
    let mut presented = vec![
        valid.clone(),
        expired.clone(),
        bad_signature.clone(),
        unscoped.clone(),
    ];

    // 1. Accepted OAuth (the first request also loads the keys).
    assert_eq!(send(app, Method::GET, "/any", Some(&valid), "").await, 200);
    let events = capture.take_events();
    let accepted = auth_event(&events);
    assert_eq!(accepted.target, "oauth_resource_server::axum");
    assert_auth(
        &accepted,
        Level::DEBUG,
        "OAuth bearer auth accepted",
        &[("auth.mechanism", "oauth"), ("auth.outcome", "accepted")],
    );
    assert_eq!(accepted.fields["subject"], "Some(\"test-user\")");
    let spans = capture.take_spans();
    let names: Vec<_> = spans.iter().map(|s| s.name).collect();
    // The cache-only pass found no key, the full pass fetched them.
    assert_eq!(
        names,
        [
            "oauth_rs.validate_cached",
            "oauth_rs.validate",
            "oauth_rs.jwks_refresh"
        ],
        "{spans:#?}"
    );
    let cached = &spans[0].fields;
    assert_eq!(cached["alg"], "RS256");
    assert_eq!(cached["auth.outcome"], "needs_key_fetch");
    assert!(!cached.contains_key("auth.reason"), "{cached:?}");
    let full = &spans[1].fields;
    assert_eq!(full["alg"], "RS256");
    assert_eq!(full["kid"], cached["kid"]);
    assert_eq!(full["auth.outcome"], "accepted");
    let refresh = &spans[2].fields;
    assert_eq!(refresh["jwks.host"], "127.0.0.1");
    assert_eq!(refresh["result"], "success");
    assert_eq!(
        refresh["keys"],
        f.validator.key_set_status().keys.to_string()
    );

    // 2. Accepted static token, with its label.
    assert_eq!(
        send(app, Method::GET, "/any", Some(STATIC_SECRET), "").await,
        200
    );
    let events = capture.take_events();
    assert_auth(
        &auth_event(&events),
        Level::DEBUG,
        "Static bearer auth accepted",
        &[
            ("auth.mechanism", "static"),
            ("auth.outcome", "accepted"),
            ("auth.static_label", STATIC_LABEL),
        ],
    );
    capture.take_spans();

    // 3. Expired.
    assert_eq!(
        send(app, Method::GET, "/any", Some(&expired), "").await,
        401
    );
    let events = capture.take_events();
    assert_auth(
        &auth_event(&events),
        Level::WARN,
        "OAuth bearer auth rejected",
        &[
            ("auth.mechanism", "oauth"),
            ("auth.outcome", "rejected"),
            ("auth.reason", "expired"),
            ("auth.status", "401"),
        ],
    );
    let spans = capture.take_spans();
    assert_eq!(spans.len(), 1, "a cached key decides it: {spans:#?}");
    assert_eq!(spans[0].fields["auth.outcome"], "rejected");
    assert_eq!(spans[0].fields["auth.reason"], "expired");

    // 4. Bad signature.
    assert_eq!(
        send(app, Method::GET, "/any", Some(&bad_signature), "").await,
        401
    );
    assert_auth(
        &auth_event(&capture.take_events()),
        Level::WARN,
        "OAuth bearer auth rejected",
        &[
            ("auth.mechanism", "oauth"),
            ("auth.outcome", "rejected"),
            ("auth.reason", "bad_signature"),
            ("auth.status", "401"),
        ],
    );
    capture.take_spans();

    // 5. Insufficient scope at the validator: 403.
    assert_eq!(
        send(app, Method::GET, "/any", Some(&unscoped), "").await,
        403
    );
    assert_auth(
        &auth_event(&capture.take_events()),
        Level::WARN,
        "OAuth bearer auth rejected",
        &[
            ("auth.mechanism", "oauth"),
            ("auth.outcome", "rejected"),
            ("auth.reason", "insufficient_scope"),
            ("auth.status", "403"),
        ],
    );
    capture.take_spans();

    // 6. Missing: 401, quietly.
    assert_eq!(send(app, Method::GET, "/any", None, "").await, 401);
    assert_auth(
        &auth_event(&capture.take_events()),
        Level::DEBUG,
        "No bearer credential presented",
        &[
            ("auth.mechanism", "none"),
            ("auth.outcome", "rejected"),
            ("auth.reason", "missing"),
            ("auth.status", "401"),
        ],
    );
    capture.take_spans();

    // 7. An optional layer passes a request with no credential through.
    assert_eq!(send(app, Method::GET, "/opt", None, "").await, 200);
    assert_auth(
        &auth_event(&capture.take_events()),
        Level::DEBUG,
        "No credential presented; optional auth passes the request through",
        &[
            ("auth.mechanism", "none"),
            ("auth.outcome", "passed_through"),
        ],
    );

    // 8. `RequireScopes`: the layer accepts, the route refuses with 403.
    assert_eq!(
        send(app, Method::GET, "/admin", Some(&valid), "").await,
        403
    );
    let events = capture.take_events();
    let refusals: Vec<_> = events
        .iter()
        .filter(|e| e.fields.get("auth.outcome").map(String::as_str) == Some("rejected"))
        .cloned()
        .collect();
    assert_eq!(refusals.len(), 1, "{events:#?}");
    assert_eq!(refusals[0].target, "oauth_resource_server::http_layer");
    assert_eq!(refusals[0].fields["what"], "RequireScopes");
    assert_auth(
        &refusals[0],
        Level::INFO,
        "The credential lacks the scopes this route requires",
        &[
            ("auth.mechanism", "oauth"),
            ("auth.outcome", "rejected"),
            ("auth.reason", "insufficient_scope"),
            ("auth.status", "403"),
        ],
    );
    capture.take_spans();

    // 9. `McpToolScopes`: a `tools/call` for a scoped tool, denied.
    assert_eq!(
        send(app, Method::POST, "/mcp", Some(&valid), PURGE_CALL).await,
        403
    );
    let events = capture.take_events();
    let refusal = events
        .iter()
        .find(|e| e.fields.get("auth.outcome").map(String::as_str) == Some("rejected"))
        .expect("the denial is logged");
    assert_eq!(refusal.fields["what"], "McpToolScopes");
    assert_auth(
        refusal,
        Level::INFO,
        "The credential lacks the scopes this route requires",
        &[
            ("auth.mechanism", "oauth"),
            ("auth.outcome", "rejected"),
            ("auth.reason", "insufficient_scope"),
            ("auth.status", "403"),
        ],
    );
    // No log line carries body content, tool names included.
    assert!(!format!("{events:?}").contains("purge"), "{events:#?}");
    capture.take_spans();

    // 10. A hostile `kid`: 5 KB of control characters and ANSI escapes,
    //     bounded and escaped in both validation spans.
    let kid = support::hostile_kid();
    let hostile = f.authority.token().kid(kid.clone()).sign();
    presented.push(hostile.clone());
    assert_eq!(
        send(app, Method::GET, "/any", Some(&hostile), "").await,
        401
    );
    capture.take_events();
    let spans = capture.take_spans();
    let validations: Vec<_> = spans
        .iter()
        .filter(|s| s.name.starts_with("oauth_rs.validate"))
        .collect();
    assert!(!validations.is_empty(), "{spans:#?}");
    for span in validations {
        let shown = &span.fields["kid"];
        assert!(
            shown.len() <= 128 * 10 + '…'.len_utf8(),
            "{} bytes",
            shown.len()
        );
        assert!(shown.ends_with('…'), "{shown}");
        assert!(
            shown
                .chars()
                .all(|c| c.is_ascii_graphic() || c == ' ' || c == '…'),
            "{shown:?}"
        );
        assert!(
            shown.starts_with("\\u{1b}[31mRED\\u{1b}[0m\\u{7}\\u{d}\\u{a}\\u{202e}A"),
            "{shown}"
        );
        assert_eq!(span.fields["alg"], "RS256");
    }

    // 11. The `alg` field is the crate's own label, and a header jsonwebtoken
    //     cannot read still shows its raw (bounded, escaped) `alg` and `kid`:
    //     `none` (no parse at all) and `HS256` (parsed, but no `Algorithm`).
    for (header, alg, kid) in [
        (
            serde_json::json!({"alg": "none", "kid": "k\u{1b}1"}),
            "none",
            Some("k\\u{1b}1"),
        ),
        (
            serde_json::json!({"alg": "HS256", "typ": "at+jwt"}),
            "HS256",
            None,
        ),
    ] {
        let unsigned = format!(
            "{}.{}.c2ln",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(r#"{"sub":"x"}"#),
        );
        presented.push(unsigned.clone());
        assert_eq!(
            send(app, Method::GET, "/any", Some(&unsigned), "").await,
            401
        );
        capture.take_events();
        let spans = capture.take_spans();
        assert_eq!(spans.len(), 1, "refused from the header alone: {spans:#?}");
        assert_eq!(spans[0].name, "oauth_rs.validate_cached");
        assert_eq!(spans[0].fields["alg"], alg, "{spans:#?}");
        assert_eq!(spans[0].fields.get("kid").map(String::as_str), kid);
        assert_eq!(spans[0].fields["auth.outcome"], "rejected");
    }

    // Nothing secret anywhere: not in a field, not in the rendered output.
    let rendered = String::from_utf8(text.lock().unwrap().clone()).unwrap();
    assert!(rendered.contains("auth.outcome=\"accepted\""), "{rendered}");
    assert!(!rendered.contains('\u{1b}'), "raw escape in the output");
    for secret in presented.iter().map(String::as_str).chain([STATIC_SECRET]) {
        assert!(!rendered.contains(secret), "a credential reached the log");
        let signature = secret.rsplit('.').next().unwrap();
        assert!(!rendered.contains(signature), "a signature reached the log");
    }
    assert!(!rendered.contains(&kid), "the raw kid reached the log");
}

struct SinkWriter(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for SinkWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
