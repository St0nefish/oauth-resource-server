//! The stable, low-cardinality vocabulary of this crate's auth-outcome log
//! fields and (feature `metrics`) metric labels (oauth-resource-server#11).
//!
//! Every value here is a `&'static str` from a closed set, so a log field or a
//! metric label built from it can never carry a token, a claim value or
//! anything else a caller controls. The names and value sets are documented in
//! the README's "Observability" section as part of the semver contract (unlike
//! message text): renaming a field, a metric or a label value is breaking;
//! adding a value (a new `InvalidTokenKind`, say) is not.

use crate::token::TokenRejection;

/// `auth.reason` / the `reason` label for an outcome that is not a refusal.
#[cfg(feature = "tower")]
pub(crate) const REASON_NONE: &str = "none";

/// `auth.reason` / the `reason` label for a refusal caused by the server's
/// own wiring (every "Server misconfiguration" event, logged at `error`).
#[cfg(feature = "tower")]
pub(crate) const REASON_MISCONFIGURED: &str = "misconfigured";

/// `span.record(field, value)`, on every `tracing` this crate accepts: 0.1.29
/// (the `minimal-versions` floor) takes the value as `&V`, later releases
/// as any `V: Value`, which `&V` also is — so it is passed by reference.
#[allow(clippy::needless_borrows_for_generic_args)]
pub(crate) fn record_field<V: tracing::field::Value>(span: &tracing::Span, field: &str, value: V) {
    span.record(field, &value);
}

/// `auth.outcome`: what happened to the request.
#[cfg(feature = "tower")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// A credential was accepted.
    Accepted,
    /// The request was refused (401, 403 or 500).
    Rejected,
    /// An `optional()` or `allow_unauthenticated` layer let a request with
    /// no credential through.
    PassedThrough,
}

#[cfg(feature = "tower")]
impl Outcome {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::PassedThrough => "passed_through",
        }
    }
}

/// `auth.mechanism`: which credential mechanism decided.
#[cfg(feature = "tower")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Mechanism {
    /// A static token (accepted, or refused by a scope requirement or a
    /// static-only layer's comparison).
    Static,
    /// An OAuth access token.
    OAuth,
    /// No credential: none was presented, or none could be checked.
    None,
}

#[cfg(feature = "tower")]
impl Mechanism {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Static => "static",
            Self::OAuth => "oauth",
            Self::None => "none",
        }
    }

    /// The mechanism behind `rejection` when no accepted credential says
    /// otherwise (a layer's own refusal): a static-only comparison failure is
    /// `static`, no credential or no mechanism is `none`, everything else
    /// was decided by the OAuth validator.
    pub(crate) fn of_rejection(rejection: &TokenRejection) -> Self {
        use crate::token::InvalidTokenKind as K;
        match rejection {
            TokenRejection::Missing => Self::None,
            TokenRejection::Invalid(invalid) => match invalid.kind() {
                K::StaticTokenMismatch | K::OAuthTokenRequired => Self::Static,
                K::NoMechanism => Self::None,
                _ => Self::OAuth,
            },
            _ => Self::OAuth,
        }
    }

    /// The mechanism of the credential an earlier layer accepted (a
    /// route-level refusal judges that one), else [`Mechanism::of_rejection`].
    pub(crate) fn of_request(
        credential: Option<&crate::authenticate::Credential>,
        rejection: &TokenRejection,
    ) -> Self {
        use crate::authenticate::Credential;
        match credential {
            Some(Credential::OAuth(_)) => Self::OAuth,
            Some(Credential::StaticToken) => Self::Static,
            _ => Self::of_rejection(rejection),
        }
    }
}

/// `auth.reason`: [`crate::InvalidTokenKind::as_str`] for an `Invalid`,
/// `missing` / `insufficient_scope` for the other two variants, and `other`
/// for a variant added later.
pub(crate) fn reason(rejection: &TokenRejection) -> &'static str {
    match rejection {
        TokenRejection::Missing => "missing",
        TokenRejection::Invalid(invalid) => invalid.kind().as_str(),
        TokenRejection::InsufficientScope => "insufficient_scope",
        #[allow(unreachable_patterns)]
        _ => "other",
    }
}

/// `auth.status` for a refusal: `refusal::select`'s own status decision, so
/// the field can never disagree with the response.
#[cfg(feature = "tower")]
pub(crate) fn status(rejection: &TokenRejection) -> u16 {
    crate::refusal::select::<str>(rejection, None, None).0
}

/// The `stage` label of `oauth_rs_requests_total`: which check made the
/// decision, so one request's layer acceptance and a later route refusal can
/// be told apart (decisions, not requests, are counted).
#[cfg(feature = "tower")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Stage {
    /// Either authentication layer (`AuthLayer`, `HttpAuthLayer`), including
    /// an `allow_unauthenticated` one. Exactly one per request per layer.
    Layer,
    /// A route-level scope check: `RequireScopes`, `McpToolScopes`.
    Route,
    /// An axum extractor in the handler: `AuthorizedToken`, `Credential`,
    /// `StaticTokenMatch`, `Scoped`.
    Handler,
}

#[cfg(feature = "tower")]
impl Stage {
    // A metric label only (not a log field), so read with `metrics` alone.
    #[cfg_attr(not(feature = "metrics"), allow(dead_code))]
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Layer => "layer",
            Self::Route => "route",
            Self::Handler => "handler",
        }
    }
}

/// Count one authentication decision in `oauth_rs_requests_total` (feature
/// `metrics`; nothing at all without it).
#[cfg(feature = "tower")]
#[inline]
pub(crate) fn count_request(
    stage: Stage,
    outcome: Outcome,
    mechanism: Mechanism,
    reason: &'static str,
) {
    #[cfg(feature = "metrics")]
    ::metrics::counter!(
        crate::observability::REQUESTS_TOTAL,
        "stage" => stage.as_str(),
        "outcome" => outcome.as_str(),
        "mechanism" => mechanism.as_str(),
        "reason" => reason,
    )
    .increment(1);
    #[cfg(not(feature = "metrics"))]
    let _ = (stage, outcome, mechanism, reason);
}

/// Count one finished key refresh in `oauth_rs_jwks_refresh_total` (`result`
/// is `success` or a `RefreshErrorKind` label) and set `oauth_rs_jwks_keys`
/// to the number of keys now held, both labelled `issuer_host` (feature
/// `metrics`; nothing without it).
#[inline]
pub(crate) fn count_refresh(issuer_host: &str, result: &'static str, keys: usize) {
    #[cfg(feature = "metrics")]
    ::metrics::counter!(
        crate::observability::JWKS_REFRESH_TOTAL,
        "issuer_host" => issuer_host.to_owned(),
        "result" => result,
    )
    .increment(1);
    #[cfg(not(feature = "metrics"))]
    let _ = result;
    set_keys(issuer_host, keys);
}

/// Set `oauth_rs_jwks_keys{issuer_host}` (feature `metrics`): after every
/// refresh, and once when the validator is built, so seeded keys
/// (`initial_jwks`) show before the first refresh.
#[inline]
pub(crate) fn set_keys(issuer_host: &str, keys: usize) {
    #[cfg(feature = "metrics")]
    {
        // Precision loss only above 2^53 keys; the key set is capped at 64.
        #[allow(clippy::cast_precision_loss)]
        ::metrics::gauge!(
            crate::observability::JWKS_KEYS,
            "issuer_host" => issuer_host.to_owned(),
        )
        .set(keys as f64);
    }
    #[cfg(not(feature = "metrics"))]
    let _ = (issuer_host, keys);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::InvalidTokenKind;

    #[test]
    fn reasons_are_the_stable_labels() {
        assert_eq!(reason(&TokenRejection::Missing), "missing");
        assert_eq!(
            reason(&TokenRejection::InsufficientScope),
            "insufficient_scope"
        );
        assert_eq!(
            reason(&TokenRejection::invalid(InvalidTokenKind::Expired, "x")),
            "expired"
        );
    }

    #[cfg(feature = "tower")]
    #[test]
    fn mechanisms_follow_the_credential_then_the_rejection() {
        use crate::authenticate::Credential;
        let invalid = |kind| TokenRejection::invalid(kind, "x");
        for (rejection, want) in [
            (TokenRejection::Missing, Mechanism::None),
            (TokenRejection::InsufficientScope, Mechanism::OAuth),
            (
                invalid(InvalidTokenKind::StaticTokenMismatch),
                Mechanism::Static,
            ),
            (
                invalid(InvalidTokenKind::OAuthTokenRequired),
                Mechanism::Static,
            ),
            (invalid(InvalidTokenKind::NoMechanism), Mechanism::None),
            (
                invalid(InvalidTokenKind::StaticTokenRequired),
                Mechanism::OAuth,
            ),
            (invalid(InvalidTokenKind::BadSignature), Mechanism::OAuth),
        ] {
            assert_eq!(Mechanism::of_rejection(&rejection), want, "{rejection:?}");
        }
        assert_eq!(
            Mechanism::of_request(
                Some(&Credential::StaticToken),
                &TokenRejection::InsufficientScope
            ),
            Mechanism::Static
        );
        assert_eq!(status(&TokenRejection::InsufficientScope), 403);
        assert_eq!(status(&TokenRejection::Missing), 401);
    }
}
