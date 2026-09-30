//! The metrics this crate emits through the [`metrics`](https://docs.rs/metrics)
//! facade (feature `metrics`).
//!
//! Nothing is recorded until the application installs a recorder (an exporter
//! such as `metrics-exporter-prometheus`); with none installed, every update
//! is a no-op. The names and every label value are part of this crate's semver
//! contract — see the README's "Observability" section for the full
//! catalogue, the log fields that share the same vocabulary, and an example
//! query:
//!
//! | Metric | Type | Labels |
//! |---|---|---|
//! | [`REQUESTS_TOTAL`] | counter | `outcome`, `mechanism`, `reason` |
//! | [`JWKS_REFRESH_TOTAL`] | counter | `result` |
//! | [`JWKS_KEYS`] | gauge | — |
//!
//! The `oauth_rs_` prefix is fixed. An exporter or the scraper can rename a
//! metric (Prometheus `metric_relabel_configs`, say); a prefix set at run
//! time here would make every dashboard and alert built on these names
//! deployment-specific, which is the opposite of a stable name.
//!
//! # Examples
//!
//! ```
//! // Once at startup, after installing the recorder: HELP text for the
//! // exporter to publish alongside each metric.
//! oauth_resource_server::observability::describe_metrics();
//! assert_eq!(
//!     oauth_resource_server::observability::REQUESTS_TOTAL,
//!     "oauth_rs_requests_total"
//! );
//! ```

/// Counter: one increment per authentication decision — a layer's admission
/// (`accepted`, `rejected` or `passed_through`), and each refusal made after
/// it by a route-level check (`RequireScopes`, `McpToolScopes`, the axum
/// extractors). A request a layer accepted and a route then refused therefore
/// counts twice, once per decision. Labels: `outcome`, `mechanism`, `reason`.
pub const REQUESTS_TOTAL: &str = "oauth_rs_requests_total";

/// Counter: one increment per finished JWKS refresh attempt (the background
/// refresh, an unknown-`kid` refetch, or discovery failing first). Label
/// `result`: `success`, or the
/// [`RefreshErrorKind::as_str`](crate::RefreshErrorKind::as_str) label of
/// the failure (`discovery`, `fetch`, `parse`, `no_usable_keys`).
pub const JWKS_REFRESH_TOTAL: &str = "oauth_rs_jwks_refresh_total";

/// Gauge: how many usable verification keys the validator holds, set after
/// every refresh attempt (a failed one leaves the held keys, and the value,
/// unchanged). With several validators in one process, the value is the most
/// recent refresh's — per-validator status is
/// [`OAuthValidator::key_set_status`](crate::OAuthValidator::key_set_status).
pub const JWKS_KEYS: &str = "oauth_rs_jwks_keys";

/// Register a description for each metric with the installed recorder
/// (`describe_counter!`/`describe_gauge!`), which exporters publish as HELP
/// text. Optional: the metrics are emitted whether or not this is called.
/// Call it after installing the recorder; with none installed it does nothing.
pub fn describe_metrics() {
    metrics::describe_counter!(
        REQUESTS_TOTAL,
        "Authentication decisions, by outcome, credential mechanism and reason"
    );
    metrics::describe_counter!(
        JWKS_REFRESH_TOTAL,
        "Finished JWKS refresh attempts, by result"
    );
    metrics::describe_gauge!(
        JWKS_KEYS,
        "Usable JWKS verification keys held after the latest refresh"
    );
}
