//! Startup policy: which static token, if any, the auth layer holds alongside
//! OAuth — and whether the configuration leaves the protected routes open.
//!
//! Pure decision logic, no logging: every outcome is a distinct
//! [`StaticTokenDecision`] variant precisely so an application can say, in its
//! own words and naming its own settings, what it decided (a static-only
//! deployment deserves a startup nudge towards OAuth; an ignored token deserves
//! an explanation).

use crate::config::ResolvedOAuthConfig;

/// The outcome of [`static_token_policy`].
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum StaticTokenDecision {
    /// Dual mode: the static token and OAuth access tokens are both accepted.
    StaticAndOAuth(String),
    /// Only the static token protects the routes (OAuth is off).
    StaticOnly(String),
    /// Only OAuth access tokens are accepted; no static token was configured.
    OAuthOnly,
    /// A static token was configured but OAuth's
    /// [`accept_static_bearer`](crate::OAuthConfig::accept_static_bearer) is
    /// false, so it is ignored and only OAuth access tokens are accepted.
    StaticIgnored,
    /// Nothing is configured and the caller explicitly allowed unauthenticated
    /// access: the routes are open. Build the pass-through deliberately (with the
    /// `axum` feature, `AuthLayer::allow_unauthenticated`) and say so loudly at
    /// startup.
    Unauthenticated,
}

impl StaticTokenDecision {
    /// Whether the decision was made with OAuth on (a resolved OAuth config was
    /// passed to [`static_token_policy`]), i.e. whether an OAuth validator must
    /// accompany it.
    pub fn oauth_enabled(&self) -> bool {
        match self {
            Self::StaticAndOAuth(_) | Self::OAuthOnly | Self::StaticIgnored => true,
            Self::StaticOnly(_) | Self::Unauthenticated => false,
        }
    }

    /// The static token to accept, if any.
    pub fn static_token(&self) -> Option<&str> {
        match self {
            Self::StaticAndOAuth(t) | Self::StaticOnly(t) => Some(t),
            Self::OAuthOnly | Self::StaticIgnored | Self::Unauthenticated => None,
        }
    }

    /// Consume the decision, yielding the static token to accept, if any.
    pub fn into_static_token(self) -> Option<String> {
        match self {
            Self::StaticAndOAuth(t) | Self::StaticOnly(t) => Some(t),
            Self::OAuthOnly | Self::StaticIgnored | Self::Unauthenticated => None,
        }
    }
}

/// Hand-written so the token itself never reaches a log line through `{:?}`.
impl std::fmt::Debug for StaticTokenDecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StaticAndOAuth(_) => f.write_str("StaticAndOAuth(<redacted>)"),
            Self::StaticOnly(_) => f.write_str("StaticOnly(<redacted>)"),
            Self::OAuthOnly => f.write_str("OAuthOnly"),
            Self::StaticIgnored => f.write_str("StaticIgnored"),
            Self::Unauthenticated => f.write_str("Unauthenticated"),
        }
    }
}

/// Neither a static token nor OAuth is configured, and unauthenticated access
/// was not explicitly allowed. The application should refuse to start, telling
/// the operator in its own terms how to configure one of the two (or how to opt
/// out explicitly).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "no authentication is configured: set a static token or enable OAuth, or explicitly \
     allow unauthenticated access"
)]
#[non_exhaustive]
pub struct NoAuthConfigured;

/// Decide which static token the auth layer holds.
///
/// - `static_token`: the configured secret, read by the caller (from an
///   environment variable, a file, a vault...) so this stays a pure, testable
///   function. `Some("")` counts as unset. Whitespace is not trimmed here — a
///   secret loader that trims (such as the `env` feature's) does it first — and
///   an untrimmed whitespace-only value stays configured: a blank credential is
///   never matched, so it admits nobody rather than opening anything.
/// - `oauth`: the RESOLVED OAuth config — `Some` only when OAuth is genuinely
///   on ([`crate::OAuthConfig::resolve`] returns `None` for a disabled block) —
///   so neither `accept_static_bearer: false` nor a disabled OAuth block can be
///   what leaves the routes open.
/// - `allow_unauthenticated`: the explicit opt-out. It matters only when
///   nothing else is configured; it never weakens a configured credential.
///
/// This is the only reader of [`accept_static_bearer`](crate::OAuthConfig::accept_static_bearer):
/// build the auth layer from the decision (with the `axum` feature,
/// `AuthLayer::from_decision`), not from the raw static token, or that setting
/// has no effect.
///
/// # Errors
///
/// [`NoAuthConfigured`] when the result would leave the routes with no
/// authentication and `allow_unauthenticated` is false.
///
/// # Examples
///
/// ```
/// use oauth_resource_server::{StaticTokenDecision, static_token_policy};
///
/// // A static token and no OAuth.
/// let decision = static_token_policy(Some("k3y".into()), None, false).unwrap();
/// assert_eq!(decision, StaticTokenDecision::StaticOnly("k3y".into()));
/// assert_eq!(decision.static_token(), Some("k3y"));
/// assert!(!decision.oauth_enabled());
///
/// // Nothing configured: refused unless unauthenticated access is asked for by name.
/// assert!(static_token_policy(None, None, false).is_err());
/// assert_eq!(
///     static_token_policy(None, None, true).unwrap(),
///     StaticTokenDecision::Unauthenticated
/// );
/// ```
pub fn static_token_policy(
    static_token: Option<String>,
    oauth: Option<&ResolvedOAuthConfig>,
    allow_unauthenticated: bool,
) -> Result<StaticTokenDecision, NoAuthConfigured> {
    let static_token = static_token.filter(|v| !v.is_empty());
    match (static_token, oauth) {
        (Some(_), Some(o)) if !o.accept_static_bearer => Ok(StaticTokenDecision::StaticIgnored),
        (Some(token), Some(_)) => Ok(StaticTokenDecision::StaticAndOAuth(token)),
        (Some(token), None) => Ok(StaticTokenDecision::StaticOnly(token)),
        (None, Some(_)) => Ok(StaticTokenDecision::OAuthOnly),
        (None, None) if allow_unauthenticated => Ok(StaticTokenDecision::Unauthenticated),
        (None, None) => Err(NoAuthConfigured),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing;

    use StaticTokenDecision::*;

    fn tok() -> Option<String> {
        Some("secret".to_string())
    }

    /// Ported from mcp-md-wiki's `static_bearer_token_resolution_matrix`: the
    /// token each case yields is unchanged, and the variant says why.
    #[test]
    fn static_token_resolution_matrix() {
        let mut oauth = testing::resolved_config("http://127.0.0.1:1/jwks");

        // Dual mode, static-only, OAuth-only.
        let d = static_token_policy(tok(), Some(&oauth), false).unwrap();
        assert_eq!(d, StaticAndOAuth("secret".into()));
        assert_eq!(d.static_token(), Some("secret"));
        let d = static_token_policy(tok(), None, false).unwrap();
        assert_eq!(d, StaticOnly("secret".into()));
        assert_eq!(d.into_static_token(), tok());
        assert_eq!(
            static_token_policy(None, Some(&oauth), false).unwrap(),
            OAuthOnly
        );
        assert_eq!(
            static_token_policy(Some(String::new()), Some(&oauth), false).unwrap(),
            OAuthOnly
        );
        // No credential of either kind: refuse unless explicitly opted out.
        assert_eq!(
            static_token_policy(None, None, false).unwrap_err(),
            NoAuthConfigured
        );
        assert_eq!(
            static_token_policy(Some(String::new()), None, false).unwrap_err(),
            NoAuthConfigured
        );
        let d = static_token_policy(None, None, true).unwrap();
        assert_eq!(d, Unauthenticated);
        assert_eq!(d.static_token(), None);

        // `accept_static_bearer: false` drops a set token when OAuth is on.
        oauth.accept_static_bearer = false;
        let d = static_token_policy(tok(), Some(&oauth), false).unwrap();
        assert_eq!(d, StaticIgnored);
        assert_eq!(d.into_static_token(), None);
        // ...and without a token it is simply OAuth-only.
        assert_eq!(
            static_token_policy(None, Some(&oauth), false).unwrap(),
            OAuthOnly
        );
    }

    #[test]
    fn allow_unauthenticated_never_weakens_a_configured_credential() {
        let mut oauth = testing::resolved_config("http://127.0.0.1:1/jwks");
        assert_eq!(
            static_token_policy(tok(), None, true).unwrap(),
            StaticOnly("secret".into())
        );
        assert_eq!(
            static_token_policy(None, Some(&oauth), true).unwrap(),
            OAuthOnly
        );
        assert_eq!(
            static_token_policy(tok(), Some(&oauth), true).unwrap(),
            StaticAndOAuth("secret".into())
        );
        oauth.accept_static_bearer = false;
        assert_eq!(
            static_token_policy(tok(), Some(&oauth), true).unwrap(),
            StaticIgnored
        );
    }

    #[test]
    fn a_whitespace_token_stays_configured() {
        // Not trimmed here: treating it as unset would let `allow_unauthenticated`
        // turn it into an open server; kept, it admits nobody.
        assert_eq!(
            static_token_policy(Some("  ".into()), None, true).unwrap(),
            StaticOnly("  ".into())
        );
    }

    #[test]
    fn oauth_enabled_says_whether_a_validator_must_accompany_the_decision() {
        let oauth = testing::resolved_config("http://127.0.0.1:1/jwks");
        let mut ignoring = oauth.clone();
        ignoring.accept_static_bearer = false;
        for (decision, expected) in [
            (static_token_policy(tok(), Some(&oauth), false), true),
            (static_token_policy(None, Some(&oauth), false), true),
            (static_token_policy(tok(), Some(&ignoring), false), true),
            (static_token_policy(tok(), None, false), false),
            (static_token_policy(None, None, true), false),
        ] {
            let decision = decision.unwrap();
            assert_eq!(decision.oauth_enabled(), expected, "{decision:?}");
        }
    }

    #[test]
    fn debug_never_prints_the_token() {
        for d in [
            StaticAndOAuth("hunter2".into()),
            StaticOnly("hunter2".into()),
        ] {
            let rendered = format!("{d:?}");
            assert!(!rendered.contains("hunter2"), "{rendered}");
        }
    }
}
