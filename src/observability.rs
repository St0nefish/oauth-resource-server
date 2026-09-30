//! The metrics this crate emits through the [`metrics`](https://docs.rs/metrics)
//! facade (feature `metrics`).
//!
//! Nothing is recorded until the application installs a recorder (an exporter
//! such as `metrics-exporter-prometheus`); with none installed, every update
//! is a no-op. The names and every label value are part of this crate's semver
//! contract — see the README's "Observability" section for the full
//! catalogue, the log fields that share the same vocabulary, and example
//! queries:
//!
//! | Metric | Type | Labels |
//! |---|---|---|
//! | [`REQUESTS_TOTAL`] | counter | `stage`, `outcome`, `mechanism`, `reason` |
//! | [`JWKS_REFRESH_TOTAL`] | counter | `issuer_host`, `result` |
//! | [`JWKS_KEYS`] | gauge | `issuer_host` |
//!
//! Every label value comes from a fixed set, except `issuer_host`: the
//! configured issuer's host alone (no scheme, port, path, credential or
//! query), so it has one value per validator — bounded by configuration,
//! never by traffic.
//!
//! Only the two authentication layers, `RequireScopes`, `McpToolScopes` and
//! the axum extractors count requests. An application calling the
//! framework-free [`authenticate`](crate::authenticate()) or
//! [`OAuthValidator::validate`](crate::OAuthValidator::validate) itself gets
//! the key-set metrics and the tracing spans, but no `oauth_rs_requests_total`
//! (nor `auth.*` log fields): it counts its own decisions.
//!
//! The `oauth_rs_` prefix is fixed. An exporter or the scraper can rename a
//! metric (Prometheus `metric_relabel_configs`, say); a prefix set at run
//! time here would make every dashboard and alert built on these names
//! deployment-specific, which is the opposite of a stable name.
//!
//! # Examples
//!
//! ```
//! // Once at startup, after installing the recorder: HELP text and units for
//! // the exporter to publish alongside each metric.
//! oauth_resource_server::observability::describe_metrics();
//! assert_eq!(
//!     oauth_resource_server::observability::REQUESTS_TOTAL,
//!     "oauth_rs_requests_total"
//! );
//! ```

use metrics::Unit;

/// Counter: one increment per authentication **decision**, not per request.
/// Label `stage` says which check decided: `layer` (either authentication
/// layer's admission — exactly one per request per layer, so
/// `stage="layer"` is the request count), `route` (a refusal by
/// `RequireScopes` or `McpToolScopes`) or `handler` (a refusal by an axum
/// extractor, `Scoped` included). A request a layer accepted and a route then
/// refused counts once under each. The other labels: `outcome`, `mechanism`,
/// `reason`.
pub const REQUESTS_TOTAL: &str = "oauth_rs_requests_total";

/// Counter: one increment per finished JWKS refresh attempt (the background
/// refresh, an unknown-`kid` refetch, or discovery failing first). Labels
/// `issuer_host` (see the [module docs](self)) and `result`: `success`, or
/// the [`RefreshErrorKind::as_str`](crate::RefreshErrorKind::as_str) label
/// of the failure (`discovery`, `fetch`, `parse`, `no_usable_keys`).
pub const JWKS_REFRESH_TOTAL: &str = "oauth_rs_jwks_refresh_total";

/// Gauge: how many usable verification keys the validator for
/// `issuer_host` holds. Set when the validator is built (so keys seeded with
/// `initial_jwks` show at once) and after every refresh attempt (a failed
/// one leaves the held keys, and the value, unchanged). Two validators for
/// the same issuer host share the series.
pub const JWKS_KEYS: &str = "oauth_rs_jwks_keys";

/// Register a unit and a description for each metric with the installed
/// recorder (`describe_counter!`/`describe_gauge!`), which exporters publish
/// as HELP text. Optional: the metrics are emitted whether or not this is
/// called. Call it after installing the recorder; with none installed it does
/// nothing.
pub fn describe_metrics() {
    metrics::describe_counter!(
        REQUESTS_TOTAL,
        Unit::Count,
        "Authentication decisions, by stage, outcome, credential mechanism and reason"
    );
    metrics::describe_counter!(
        JWKS_REFRESH_TOTAL,
        Unit::Count,
        "Finished JWKS refresh attempts, by issuer host and result"
    );
    metrics::describe_gauge!(
        JWKS_KEYS,
        Unit::Count,
        "Usable JWKS verification keys held, by issuer host"
    );
}
