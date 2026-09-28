//! What a validation produces: the accepted token ([`AuthorizedToken`]) or the
//! reason it was refused ([`TokenRejection`]), plus the claim readers and the
//! header `typ` check that feed them.

use std::collections::HashSet;

use serde_json::{Map, Value};

use crate::config::KeyNamingBuf;

/// Cap on a presented credential. Real access tokens are well under 8 KiB even
/// with group claims; anything larger is refused before it is base64-decoded.
pub(crate) const MAX_TOKEN_BYTES: usize = 16 * 1024;

/// Cap on any token-derived string that reaches a log line (`kid`, `typ`,
/// principal). A signed claim is trustworthy but not necessarily short, and an
/// unverified header field is neither.
pub(crate) const MAX_LOGGED_CHARS: usize = 128;

/// A successfully validated access token. The axum middleware (feature `axum`)
/// inserts it into request extensions, so handlers can read who called and with
/// which scopes.
///
/// The scopes come from the one place that actually verified them, so a handler
/// enforcing a finer-grained scope (say, a write scope on some routes) should ask
/// [`AuthorizedToken::has_scope`] rather than re-parse the header.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AuthorizedToken {
    /// The token's `sub`, verbatim, when it carried one as a string. It is
    /// signed, so it is safe to key per-user decisions on (it is bounded only
    /// by the 16 KiB credential cap); this crate's own log lines truncate it.
    pub subject: Option<String>,
    /// The first present, non-empty string claim of
    /// [`crate::OAuthConfig::principal_claims`], verbatim — who the request is
    /// from, for logs and attribution. Never the token itself. Which claim it
    /// came from depends on config, so key authorization on
    /// [`AuthorizedToken::subject`] rather than on this.
    pub principal: Option<String>,
    /// The union of every [`crate::OAuthConfig::scope_claims`] claim, in
    /// first-seen order, deduplicated.
    pub scopes: Vec<String>,
}

impl AuthorizedToken {
    /// Build a token record from parts, with `scopes` deduplicated in
    /// first-seen order (blank entries dropped), as a validation produces them.
    ///
    /// This verifies nothing — it is a plain value constructor for code that
    /// needs an `AuthorizedToken` without a validation, chiefly tests that place
    /// one in request extensions. [`crate::OAuthValidator::validate`] is the only
    /// source of a token that was actually checked. The struct is
    /// `#[non_exhaustive]`, so a field added later gets a default here rather
    /// than breaking callers.
    pub fn new(
        subject: Option<String>,
        principal: Option<String>,
        scopes: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        let mut deduped: Vec<String> = Vec::new();
        for scope in scopes {
            let scope = scope.into();
            let scope = scope.trim();
            if !scope.is_empty() && !deduped.iter().any(|s| s == scope) {
                deduped.push(scope.to_string());
            }
        }
        Self {
            subject,
            principal,
            scopes: deduped,
        }
    }

    /// Whether the token carries `scope` (exact, case-sensitive match, RFC 6749
    /// §3.3). The single place that answers the question, so callers never
    /// hand-roll a `.iter().any()` over `scopes`.
    ///
    /// # Examples
    ///
    /// ```
    /// use oauth_resource_server::AuthorizedToken;
    ///
    /// let token = AuthorizedToken::new(Some("user-1".into()), None, ["api:read", "api:write"]);
    /// assert!(token.has_scope("api:write"));
    /// assert!(!token.has_scope("API:WRITE"));
    /// ```
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|s| s == scope)
    }
}

/// Why a bearer credential was refused, and — crucially — with which HTTP status.
///
/// The split is the whole point: RFC 6750 distinguishes "this token is not good"
/// (401 `invalid_token`, go get a new one) from "this token is fine but not
/// sufficient" (403 `insufficient_scope`). A client that gets 401 for an
/// insufficient-scope token will loop through the authorization flow forever and
/// land back on the same refusal.
///
/// | Variant | Status | `WWW-Authenticate` (with OAuth configured) |
/// |---|---|---|
/// | [`Missing`](Self::Missing) | 401 | [`crate::OAuthValidator::invalid_token_challenge`] |
/// | [`Invalid`](Self::Invalid) | 401 | [`crate::OAuthValidator::invalid_token_challenge`] |
/// | [`InsufficientScope`](Self::InsufficientScope) | 403 | [`crate::OAuthValidator::insufficient_scope_challenge`] |
///
/// `#[non_exhaustive]`: treat a variant this code does not know as a 401.
///
/// It implements [`std::error::Error`], so `?` carries it into
/// `Box<dyn Error>` or `anyhow`. `Display` deliberately renders the category
/// only — `missing credential`, `invalid token`, `insufficient scope` — and
/// never [`Invalid`](Self::Invalid)'s reason, so a careless `format!("{e}")`
/// in a response body cannot tell a caller which check failed. The reason is
/// reachable through the variant itself and through `Debug`, for logs.
///
/// ```
/// use oauth_resource_server::TokenRejection;
///
/// let e = TokenRejection::Invalid("token rejected: InvalidAudience".into());
/// assert_eq!(e.to_string(), "invalid token");
/// assert!(format!("{e:?}").contains("InvalidAudience"));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TokenRejection {
    /// 401: the request carried no credential at all. Separate from `Invalid` so
    /// a server can log it quietly — every OAuth client's first request looks
    /// like this — not because the response differs (it should not: a missing
    /// credential gets the same `invalid_token` challenge as a bad one).
    #[error("missing credential")]
    Missing,
    /// 401 `invalid_token`: malformed, unsigned, wrong issuer/audience/type,
    /// expired, or signed by a key we could not obtain. The string is for logs
    /// only — never return it to the caller, since telling an unauthenticated
    /// client exactly which check failed is a free oracle.
    #[error("invalid token")]
    Invalid(String),
    /// 403 `insufficient_scope`: signature, issuer, audience and expiry all
    /// passed, but the token does not carry every required scope.
    #[error("insufficient scope")]
    InsufficientScope,
}

/// The union of every configured scope claim, in first-seen order, deduplicated.
///
/// Every claim is read in every shape: a string is split on whitespace (RFC 9068
/// §2.2.3's `scope`, and Entra ID's / Hydra's string `scp`), an array contributes
/// each string element whole (Authelia's and Okta's `scp`). Anything else — a
/// number, an object, a claim the token does not have — contributes nothing rather
/// than failing the token, since the only consequence of "no scopes found" is the
/// 403 for a missing required scope, which is the correct answer anyway.
pub(crate) fn extract_scopes(claims: &Map<String, Value>, claim_names: &[String]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    let mut push = |s: &str| {
        let s = s.trim();
        if !s.is_empty() && seen.insert(s.to_string()) {
            out.push(s.to_string());
        }
    };
    for name in claim_names {
        match claims.get(name) {
            Some(Value::String(s)) => s.split_whitespace().for_each(&mut push),
            Some(Value::Array(items)) => items.iter().filter_map(Value::as_str).for_each(&mut push),
            _ => {}
        }
    }
    out
}

/// The first present, non-empty string claim among `claim_names`, verbatim.
/// Truncate it (`for_log`) where it is logged, never here.
pub(crate) fn extract_principal(
    claims: &Map<String, Value>,
    claim_names: &[String],
) -> Option<String> {
    claim_names.iter().find_map(|name| match claims.get(name) {
        Some(Value::String(s)) if !s.trim().is_empty() => Some(s.clone()),
        _ => None,
    })
}

/// RFC 9068 §2.1 / §4: the header `typ` of a JWT access token is `at+jwt`
/// (`application/at+jwt` is the same media type, RFC 7515 §4.1.9, compared
/// case-insensitively). Many servers still emit `JWT` or nothing (Authentik, Entra
/// ID, Okta, Keycloak by default), so those pass unless `require_at_jwt` is on —
/// which an operator whose AS does emit `at+jwt` (Authelia, Kanidm) should turn on,
/// since it is the one check that tells an access token from an ID token minted
/// for the same client. Any OTHER explicit type (`dpop+jwt`, `logout+jwt`,
/// `secevent+jwt`...) is a different kind of JWT and is always refused.
///
/// `naming` only shapes the (log-only) rejection reason.
pub(crate) fn check_typ(
    typ: Option<&str>,
    require_at_jwt: bool,
    naming: &KeyNamingBuf,
) -> Result<(), TokenRejection> {
    let Some(raw) = typ else {
        return if require_at_jwt {
            Err(TokenRejection::Invalid(format!(
                "token header has no typ and {} is on",
                naming.key("require_at_jwt")
            )))
        } else {
            Ok(())
        };
    };
    let lower = raw.trim().to_ascii_lowercase();
    let media = lower.strip_prefix("application/").unwrap_or(&lower);
    match media {
        "at+jwt" => Ok(()),
        "jwt" if !require_at_jwt => Ok(()),
        _ => Err(TokenRejection::Invalid(format!(
            "token typ {:?} is not accepted as an access token{}",
            for_log(raw),
            if require_at_jwt {
                format!(" ({} is on)", naming.key("require_at_jwt"))
            } else {
                String::new()
            }
        ))),
    }
}

/// Truncate a token-derived string for a log line. See [`MAX_LOGGED_CHARS`].
pub(crate) fn for_log(s: &str) -> String {
    let mut out: String = s.chars().take(MAX_LOGGED_CHARS).collect();
    if s.chars().count() > MAX_LOGGED_CHARS {
        out.push('…');
    }
    out
}

/// A `kid` for a log line or rejection reason: quoted and truncated, or `(none)`.
pub(crate) fn describe_kid(kid: Option<&str>) -> String {
    match kid {
        Some(kid) => format!("{:?}", for_log(kid)),
        None => "(none)".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorized_token_new_dedupes_scopes_like_a_validation() {
        let t = AuthorizedToken::new(Some("sub-1".into()), None, ["b", " a", "b", "", "a", "c"]);
        assert_eq!(t.subject.as_deref(), Some("sub-1"));
        assert_eq!(t.principal, None);
        assert_eq!(t.scopes, ["b", "a", "c"]);
        assert!(t.has_scope("a"));
        assert!(!t.has_scope(""));
        let none = AuthorizedToken::new(None, None, Vec::<String>::new());
        assert!(none.scopes.is_empty());
    }

    #[test]
    fn a_rejection_displays_its_category_but_never_the_reason() {
        let secret_reason = "token rejected: InvalidAudience";
        let invalid = TokenRejection::Invalid(secret_reason.into());
        assert_eq!(invalid.to_string(), "invalid token");
        assert!(!invalid.to_string().contains("InvalidAudience"));
        assert!(format!("{invalid:?}").contains(secret_reason));
        assert_eq!(TokenRejection::Missing.to_string(), "missing credential");
        assert_eq!(
            TokenRejection::InsufficientScope.to_string(),
            "insufficient scope"
        );
        let boxed: Box<dyn std::error::Error + Send + Sync> = Box::new(invalid);
        assert_eq!(boxed.to_string(), "invalid token");
    }

    #[test]
    fn logged_values_are_truncated() {
        let long = "x".repeat(MAX_LOGGED_CHARS * 3);
        assert_eq!(for_log(&long).chars().count(), MAX_LOGGED_CHARS + 1);
        assert_eq!(for_log("short"), "short");
    }

    #[test]
    fn typ_rejection_reasons_name_the_setting_per_key_naming() {
        let dotted = KeyNamingBuf::Dotted("mcp.oauth".into());
        assert_eq!(
            check_typ(None, true, &dotted),
            Err(TokenRejection::Invalid(
                "token header has no typ and mcp.oauth.require_at_jwt is on".into()
            ))
        );
        assert_eq!(
            check_typ(Some("JWT"), true, &dotted),
            Err(TokenRejection::Invalid(
                "token typ \"JWT\" is not accepted as an access token \
                 (mcp.oauth.require_at_jwt is on)"
                    .into()
            ))
        );
        assert_eq!(
            check_typ(Some("dpop+jwt"), false, &dotted),
            Err(TokenRejection::Invalid(
                "token typ \"dpop+jwt\" is not accepted as an access token".into()
            ))
        );
        let env = KeyNamingBuf::Env("APP_OAUTH_".into());
        assert_eq!(
            check_typ(None, true, &env),
            Err(TokenRejection::Invalid(
                "token header has no typ and APP_OAUTH_REQUIRE_AT_JWT is on".into()
            ))
        );
    }
}
