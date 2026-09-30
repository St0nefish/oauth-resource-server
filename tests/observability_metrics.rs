//! The `metrics` feature's counters and gauge (oauth-resource-server#11), read
//! back through `metrics-util`'s debugging recorder: exact label sets and
//! values for every outcome, and a JWKS refresh success and failure.
//!
//! A test binary of its own, so the recorder can be the global one, and every
//! scenario runs inside the one test function below. Each snapshot resets
//! the counters, so every assertion is on that scenario's delta alone.
#![cfg(all(
    feature = "metrics",
    feature = "axum",
    feature = "mcp",
    feature = "testing"
))]

mod support;

use std::collections::BTreeMap;
use std::sync::Arc;

use http::Method;
use metrics_util::MetricKind;
use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshotter};
use oauth_resource_server::observability::{JWKS_KEYS, JWKS_REFRESH_TOTAL, REQUESTS_TOTAL};
use oauth_resource_server::{InvalidTokenKind, OAuthValidator, TokenRejection, testing};

use support::{PURGE_CALL, STATIC_SECRET, fixture, send, with_foreign_signature};

/// A metric name and its labels, `k=v` sorted.
type Series = (String, Vec<String>);

/// Every non-zero counter and every gauge set since the last call.
fn take(snapshotter: &Snapshotter) -> BTreeMap<Series, f64> {
    let mut out = BTreeMap::new();
    for (key, _, _, value) in snapshotter.snapshot().into_vec() {
        let (kind, key) = key.into_parts();
        let mut labels: Vec<String> = key
            .labels()
            .map(|l| format!("{}={}", l.key(), l.value()))
            .collect();
        labels.sort();
        let value = match (kind, value) {
            (MetricKind::Counter, DebugValue::Counter(0)) => continue,
            (MetricKind::Counter, DebugValue::Counter(n)) => n as f64,
            (MetricKind::Gauge, DebugValue::Gauge(v)) => v.into_inner(),
            other => panic!("unexpected metric {other:?}"),
        };
        out.insert((key.name().to_string(), labels), value);
    }
    out
}

/// One request scenario: name, method, path, bearer token, body, expected
/// status, and the counter deltas it must produce.
type Case = (
    &'static str,
    Method,
    &'static str,
    Option<String>,
    &'static str,
    u16,
    Vec<(Series, f64)>,
);

/// A `requests_total` series decided by an authentication layer.
fn request(outcome: &str, mechanism: &str, reason: &str) -> Series {
    decided("layer", outcome, mechanism, reason)
}

/// A `requests_total` series decided at `stage`.
fn decided(stage: &str, outcome: &str, mechanism: &str, reason: &str) -> Series {
    (
        REQUESTS_TOTAL.into(),
        vec![
            format!("mechanism={mechanism}"),
            format!("outcome={outcome}"),
            format!("reason={reason}"),
            format!("stage={stage}"),
        ],
    )
}

fn refresh(host: &str, result: &str) -> Series {
    (
        JWKS_REFRESH_TOTAL.into(),
        vec![format!("issuer_host={host}"), format!("result={result}")],
    )
}

fn keys(host: &str) -> Series {
    (JWKS_KEYS.into(), vec![format!("issuer_host={host}")])
}

/// Every counter: the keys gauges are left out, since a snapshot reports
/// every gauge ever set (as 0 once read); they are asserted one by one.
fn counters(seen: &BTreeMap<Series, f64>) -> BTreeMap<Series, f64> {
    seen.iter()
        .filter(|((name, _), _)| name != JWKS_KEYS)
        .map(|(k, v)| (k.clone(), *v))
        .collect()
}

/// The `TestAuthority` and every other in-process server listen here.
const LOOPBACK: &str = "127.0.0.1";
/// `testing::ISSUER`'s host.
const FIXTURE_ISSUER_HOST: &str = "authentik.example.test";

#[tokio::test]
async fn every_outcome_and_refresh_is_counted_with_stable_labels() {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    recorder.install().unwrap();
    oauth_resource_server::observability::describe_metrics();

    let f = fixture().await;
    let app = &f.app;
    let valid = f.authority.token().sign();

    // Accepted OAuth; the first request loads the keys.
    assert_eq!(send(app, Method::GET, "/any", Some(&valid), "").await, 200);
    let held = f.validator.key_set_status().keys;
    assert!(held > 0);
    let seen = take(&snapshotter);
    assert_eq!(
        counters(&seen),
        BTreeMap::from([
            (request("accepted", "oauth", "none"), 1.0),
            (refresh(LOOPBACK, "success"), 1.0),
        ])
    );
    assert_eq!(seen[&keys(LOOPBACK)], held as f64);

    let cases: Vec<Case> = vec![
        (
            "static token",
            Method::GET,
            "/any",
            Some(STATIC_SECRET.into()),
            "",
            200,
            vec![(request("accepted", "static", "none"), 1.0)],
        ),
        (
            "expired",
            Method::GET,
            "/any",
            Some(f.authority.token().expired().sign()),
            "",
            401,
            vec![(request("rejected", "oauth", "expired"), 1.0)],
        ),
        (
            "bad signature",
            Method::GET,
            "/any",
            Some(with_foreign_signature(
                &valid,
                &f.authority.token().subject("someone-else").sign(),
            )),
            "",
            401,
            vec![(request("rejected", "oauth", "bad_signature"), 1.0)],
        ),
        (
            "insufficient scope",
            Method::GET,
            "/any",
            Some(f.authority.token().scopes(["other:scope"]).sign()),
            "",
            403,
            vec![(request("rejected", "oauth", "insufficient_scope"), 1.0)],
        ),
        (
            "missing",
            Method::GET,
            "/any",
            None,
            "",
            401,
            vec![(request("rejected", "none", "missing"), 1.0)],
        ),
        (
            "wrong static token (not a JWT)",
            Method::GET,
            "/any",
            Some("not-the-static-secret".into()),
            "",
            401,
            vec![(request("rejected", "oauth", "not_jwt"), 1.0)],
        ),
        (
            "optional pass-through",
            Method::GET,
            "/opt",
            None,
            "",
            200,
            vec![(request("passed_through", "none", "none"), 1.0)],
        ),
        (
            "allow_unauthenticated",
            Method::GET,
            "/open",
            None,
            "",
            200,
            vec![(request("passed_through", "none", "none"), 1.0)],
        ),
        (
            // One decision per stage: the layer accepts, the route refuses.
            "RequireScopes",
            Method::GET,
            "/admin",
            Some(valid.clone()),
            "",
            403,
            vec![
                (request("accepted", "oauth", "none"), 1.0),
                (
                    decided("route", "rejected", "oauth", "insufficient_scope"),
                    1.0,
                ),
            ],
        ),
        (
            "RequireScopes, static token",
            Method::GET,
            "/admin",
            Some(STATIC_SECRET.into()),
            "",
            403,
            vec![
                (request("accepted", "static", "none"), 1.0),
                (
                    decided("route", "rejected", "static", "insufficient_scope"),
                    1.0,
                ),
            ],
        ),
        (
            "McpToolScopes denial",
            Method::POST,
            "/mcp",
            Some(valid.clone()),
            PURGE_CALL,
            403,
            vec![
                (request("accepted", "oauth", "none"), 1.0),
                (
                    decided("route", "rejected", "oauth", "insufficient_scope"),
                    1.0,
                ),
            ],
        ),
        (
            // The layer accepts the static token; the handler's
            // `AuthorizedToken` extractor refuses it.
            "extractor refusal",
            Method::GET,
            "/who",
            Some(STATIC_SECRET.into()),
            "",
            401,
            vec![
                (request("accepted", "static", "none"), 1.0),
                (
                    decided("handler", "rejected", "static", "oauth_token_required"),
                    1.0,
                ),
            ],
        ),
    ];
    for (name, method, path, bearer, body, status, want) in cases {
        assert_eq!(
            send(app, method, path, bearer.as_deref(), body).await,
            status,
            "{name}"
        );
        assert_eq!(
            counters(&take(&snapshotter)),
            BTreeMap::from_iter(want),
            "{name}"
        );
    }

    // A failed refresh: counted with its `RefreshErrorKind` label, and the
    // gauge set to the keys held (none). Validated directly, so no request
    // is counted.
    let down = testing::spawn_jwks_server("503 Service Unavailable", "{}".into()).await;
    let failing = Arc::new(OAuthValidator::new(&testing::resolved_config(&down.url)).unwrap());
    match failing.validate(&testing::valid_token()).await {
        Err(TokenRejection::Invalid(invalid)) => {
            assert_eq!(invalid.kind(), InvalidTokenKind::KeySetUnavailable);
        }
        other => panic!("{other:?}"),
    }
    let seen = take(&snapshotter);
    assert_eq!(
        counters(&seen),
        BTreeMap::from([(refresh(FIXTURE_ISSUER_HOST, "fetch"), 1.0)])
    );
    assert_eq!(seen[&keys(FIXTURE_ISSUER_HOST)], 0.0);

    // A failed discovery: `discovery`.
    let idp = testing::spawn_http_server(Default::default(), None).await;
    let mut cfg = testing::resolved_config("");
    cfg.issuer = format!("{}/nowhere/", idp.base);
    cfg.jwks_uri = None;
    let lost = OAuthValidator::new(&cfg).unwrap();
    assert!(lost.validate(&testing::valid_token()).await.is_err());
    assert_eq!(
        counters(&take(&snapshotter)),
        BTreeMap::from([(refresh(LOOPBACK, "discovery"), 1.0)])
    );

    // Keys seeded with `initial_jwks` show in the gauge as soon as the
    // validator is built, before any refresh.
    let seeded = OAuthValidator::builder(&testing::resolved_config(&down.url))
        .initial_jwks(&testing::jwks_body())
        .build()
        .unwrap();
    let seen = take(&snapshotter);
    assert!(counters(&seen).is_empty(), "{seen:?}");
    assert_eq!(
        seen[&keys(FIXTURE_ISSUER_HOST)],
        seeded.key_set_status().keys as f64
    );
    assert!(seeded.key_set_status().keys > 0);
}
