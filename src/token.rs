//! What a validation produces: the accepted token ([`AuthorizedToken`]) or the
//! reason it was refused ([`TokenRejection`]), plus the claim readers and the
//! header `typ` check that feed them.

use std::collections::HashSet;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::de::DeserializeOwned;
use serde_json::{Map, Value};

use crate::config::KeyNamingBuf;

/// Cap on a presented credential. Real access tokens are well under 8 KiB even
/// with group claims; anything larger is refused before it is base64-decoded.
pub(crate) const MAX_TOKEN_BYTES: usize = 16 * 1024;

/// Cap on any token-derived string that reaches a log line (`kid`, `typ`,
/// principal). A signed claim is trustworthy but not necessarily short, and an
/// unverified header field is neither.
pub(crate) const MAX_LOGGED_CHARS: usize = 128;

/// What [`AuthorizedToken::new`] puts in `expires_at`: 2100-01-01T00:00:00Z.
const FAR_FUTURE_SECS: u64 = 4_102_444_800;

/// A successfully validated access token. The axum middleware (feature `axum`)
/// inserts it into request extensions, so handlers can read who called and with
/// which scopes.
///
/// The scopes come from the one place that actually verified them, so a handler
/// enforcing a finer-grained scope (say, a write scope on some routes) should ask
/// [`AuthorizedToken::has_scope`] rather than re-parse the header.
///
/// # The verified claims
///
/// Besides the fields below, the token keeps the whole claim set the signature
/// covered, read with [`AuthorizedToken::claims`] (raw) or
/// [`AuthorizedToken::claims_as`] (into your own type), for anything this crate
/// has no field for: `groups`, `roles`, `email`, a tenant id. There is no need to
/// decode the JWT a second time in a handler. The claims are stored once and
/// shared (`Arc`), so cloning a token is cheap. Their size is bounded by the
/// credential cap: a token is refused above 16 KiB before it is decoded, so
/// the stored claims cannot outgrow that (their parsed in-memory form is a small
/// multiple of it).
///
/// # Debug
///
/// `Debug` prints every field except the claim *values*: the claims appear as
/// their names only. Claims routinely carry personal data (`email`, `name`,
/// group memberships) and a `{token:?}` in a log line or a panic message must
/// not leak it. `subject`, `principal` and `client_id` are printed, as they
/// always have been (`subject`, `principal`) or are identifiers meant for logs.
/// Read values deliberately through [`AuthorizedToken::claims`].
#[derive(Clone, PartialEq, Eq)]
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
    /// The token's `iss`: the exact string that matched the configured issuer.
    /// Empty on a token built with [`AuthorizedToken::new`].
    pub issuer: String,
    /// The token's `aud`, normalized to a list whether the token carried a
    /// single string or an array (non-string entries are dropped). On a
    /// validated token at least one entry is a configured audience. Empty on a
    /// token built with [`AuthorizedToken::new`].
    pub audiences: Vec<String>,
    /// The token's `exp`. A validated token was not expired at the moment of
    /// validation (within the configured leeway), so a long-lived connection,
    /// such as an SSE stream, can close itself at this instant. A fractional
    /// `exp` is rounded to whole seconds exactly as the validation rounded it, and
    /// one later than 9999-12-31T23:59:59Z saturates to that instant. A token built
    /// with [`AuthorizedToken::new`] gets 2100-01-01T00:00:00Z.
    pub expires_at: SystemTime,
    /// The token's `iat`, when it carried a valid NumericDate. Not otherwise
    /// checked. Rounded and saturated like
    /// [`expires_at`](Self::expires_at); `None` when `iat` is absent or not a
    /// non-negative number (the token is still accepted then). `None` on a token built with [`AuthorizedToken::new`].
    pub issued_at: Option<SystemTime>,
    /// The OAuth client the token was issued to: `client_id` (RFC 9068 §2.2),
    /// else `azp`, the first that is a non-empty string. `None` when the token
    /// carries neither, and on a token built with [`AuthorizedToken::new`].
    pub client_id: Option<String>,
    /// The token's `jti`, when it carried one as a non-empty string. `None` on
    /// a token built with [`AuthorizedToken::new`].
    pub jti: Option<String>,
    claims: Arc<Map<String, Value>>,
}

impl fmt::Debug for AuthorizedToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthorizedToken")
            .field("subject", &self.subject)
            .field("principal", &self.principal)
            .field("scopes", &self.scopes)
            // The configured issuer, which may carry userinfo.
            .field("issuer", &crate::jwks::debug_url(&self.issuer))
            .field("audiences", &self.audiences)
            .field("expires_at", &self.expires_at)
            .field("issued_at", &self.issued_at)
            .field("client_id", &self.client_id)
            .field("jti", &self.jti)
            // Names only: the values may be personal data.
            .field("claims", &self.claims.keys().collect::<Vec<_>>())
            .finish()
    }
}

/// The latest time a token timestamp maps to: 9999-12-31T23:59:59Z. A claim later
/// than this (`jsonwebtoken` accepts an `exp` up to `u64::MAX`, more than
/// `SystemTime` can hold on every platform) saturates here instead of failing,
/// so a validly signed, far-future `exp` never reads as already expired.
const MAX_TIMESTAMP_SECS: u64 = 253_402_300_799;

/// The token's own timestamp claim as a point in time, read the way
/// `jsonwebtoken` reads `exp` and `nbf` (its `numeric_type` deserializer): a
/// non-negative integer, or a finite non-negative float rounded to the nearest
/// whole second (half away from zero). Anything later than
/// [`MAX_TIMESTAMP_SECS`] saturates to it. `None` for anything else (a string, a
/// negative, a non-finite or out-of-`u64` number). Never panics.
fn numeric_date(value: &Value) -> Option<SystemTime> {
    let secs = match value.as_u64() {
        Some(secs) => secs,
        None => {
            let f = value.as_f64()?;
            if !(f.is_finite() && f >= 0.0 && f < u64::MAX as f64) {
                return None;
            }
            f.round() as u64
        }
    };
    let secs = secs.min(MAX_TIMESTAMP_SECS);
    Some(UNIX_EPOCH + Duration::from_secs(secs))
}

/// `aud` as a list: a string is one audience, an array contributes its string
/// entries.
fn audiences_of(claims: &Map<String, Value>) -> Vec<String> {
    match claims.get("aud") {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect(),
        _ => Vec::new(),
    }
}

impl AuthorizedToken {
    /// Fill every field from a token's claims, with `subject`, `principal` and
    /// `scopes` already extracted by the caller. Only called on claims a
    /// signature verification produced. An `exp` that cannot be read (which
    /// the decoder has already refused, as it is required) would read as the
    /// epoch, i.e. expired, never as "never expires".
    pub(crate) fn from_verified_claims(
        claims: Map<String, Value>,
        subject: Option<String>,
        principal: Option<String>,
        scopes: Vec<String>,
    ) -> Self {
        let string_claim = |name: &str| {
            claims
                .get(name)
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
        };
        Self {
            subject,
            principal,
            scopes,
            issuer: claims
                .get("iss")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            audiences: audiences_of(&claims),
            expires_at: claims
                .get("exp")
                .and_then(numeric_date)
                .unwrap_or(UNIX_EPOCH),
            issued_at: claims.get("iat").and_then(numeric_date),
            client_id: string_claim("client_id").or_else(|| string_claim("azp")),
            jti: string_claim("jti"),
            claims: Arc::new(claims),
        }
    }

    /// Build a token record from parts, with `scopes` deduplicated in
    /// first-seen order (blank entries dropped), as a validation produces them.
    ///
    /// This verifies nothing — it is a plain value constructor for code that
    /// needs an `AuthorizedToken` without a validation, chiefly tests that place
    /// one in request extensions. [`crate::OAuthValidator::validate`] is the only
    /// source of a token that was actually checked. The struct is
    /// `#[non_exhaustive]`, so a field added later gets a default here rather
    /// than breaking callers.
    ///
    /// The fields beyond the three arguments get test-friendly defaults: empty
    /// `issuer`, `audiences` and [`claims`](Self::claims), `None` for
    /// `issued_at`, `client_id` and `jti`, and an `expires_at` of
    /// 2100-01-01T00:00:00Z. The far-future expiry is deliberate: a handler
    /// that closes a stream when the token expires must not see a fixture as
    /// already expired. Set any of them with the `with_*` builders.
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
            issuer: String::new(),
            audiences: Vec::new(),
            expires_at: UNIX_EPOCH + Duration::from_secs(FAR_FUTURE_SECS),
            issued_at: None,
            client_id: None,
            jti: None,
            claims: Arc::new(Map::new()),
        }
    }

    /// The verified claim set, exactly as the token carried it: every claim the
    /// signature covered, including the ones with their own field here.
    /// Empty for a token built with [`AuthorizedToken::new`] unless
    /// [`with_claims`](Self::with_claims) was used.
    ///
    /// # Security
    ///
    /// Claims are trustworthy only on a token a validation produced; one from
    /// [`AuthorizedToken::new`] holds whatever the caller put there. Claim
    /// values can be personal data, so [`Debug`](fmt::Debug) does not print them.
    ///
    /// # Examples
    ///
    /// ```
    /// use oauth_resource_server::AuthorizedToken;
    /// use serde_json::json;
    ///
    /// let token = AuthorizedToken::new(Some("user-1".into()), None, ["api:read"])
    ///     .with_claims(json!({"groups": ["admins", "dev"]}).as_object().unwrap().clone());
    /// let in_admins = token.claims()["groups"]
    ///     .as_array()
    ///     .is_some_and(|g| g.iter().any(|v| v == "admins"));
    /// assert!(in_admins);
    /// ```
    pub fn claims(&self) -> &Map<String, Value> {
        &self.claims
    }

    /// The verified claim set deserialized into your own type, for a typed view
    /// of the claims your application cares about. Unknown claims are ignored
    /// unless your type says otherwise (`deny_unknown_fields`). The claim map is
    /// cloned to deserialize it, so call this once per request, not per field.
    ///
    /// # Errors
    ///
    /// [`serde_json::Error`] when the claims do not fit `T`, for example a
    /// required field the token did not carry or one of the wrong type.
    ///
    /// # Examples
    ///
    /// ```
    /// use oauth_resource_server::AuthorizedToken;
    /// use serde::Deserialize;
    /// use serde_json::json;
    ///
    /// #[derive(Deserialize)]
    /// struct Claims {
    ///     email: String,
    ///     #[serde(default)]
    ///     groups: Vec<String>,
    /// }
    ///
    /// let token = AuthorizedToken::new(None, None, ["api:read"]).with_claims(
    ///     json!({"email": "ada@example.com", "groups": ["admins"]})
    ///         .as_object()
    ///         .unwrap()
    ///         .clone(),
    /// );
    /// let claims: Claims = token.claims_as().unwrap();
    /// assert_eq!(claims.email, "ada@example.com");
    /// assert_eq!(claims.groups, ["admins"]);
    /// ```
    pub fn claims_as<T: DeserializeOwned>(&self) -> Result<T, serde_json::Error> {
        serde_json::from_value(Value::Object((*self.claims).clone()))
    }

    /// Replace the claim set, for building a token in a test. Only the claim
    /// set changes: the typed fields ([`issuer`](Self::issuer),
    /// [`client_id`](Self::client_id), …) are not re-derived from it, so set
    /// them with their own `with_*` builders. Verifies nothing.
    #[must_use]
    pub fn with_claims(mut self, claims: Map<String, Value>) -> Self {
        self.claims = Arc::new(claims);
        self
    }

    /// Set [`issuer`](Self::issuer), for building a token in a test.
    #[must_use]
    pub fn with_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = issuer.into();
        self
    }

    /// Set [`audiences`](Self::audiences), for building a token in a test.
    #[must_use]
    pub fn with_audiences(
        mut self,
        audiences: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.audiences = audiences.into_iter().map(Into::into).collect();
        self
    }

    /// Set [`expires_at`](Self::expires_at), for building a token in a test.
    #[must_use]
    pub fn with_expires_at(mut self, expires_at: SystemTime) -> Self {
        self.expires_at = expires_at;
        self
    }

    /// Set [`issued_at`](Self::issued_at), for building a token in a test.
    #[must_use]
    pub fn with_issued_at(mut self, issued_at: SystemTime) -> Self {
        self.issued_at = Some(issued_at);
        self
    }

    /// Set [`client_id`](Self::client_id), for building a token in a test.
    #[must_use]
    pub fn with_client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = Some(client_id.into());
        self
    }

    /// Set [`jti`](Self::jti), for building a token in a test.
    #[must_use]
    pub fn with_jti(mut self, jti: impl Into<String>) -> Self {
        self.jti = Some(jti.into());
        self
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
    fn new_fills_the_metadata_fields_with_documented_test_defaults() {
        let t = AuthorizedToken::new(Some("sub-1".into()), None, ["a"]);
        assert_eq!(t.issuer, "");
        assert!(t.audiences.is_empty());
        assert_eq!(t.issued_at, None);
        assert_eq!(t.client_id, None);
        assert_eq!(t.jti, None);
        assert!(t.claims().is_empty());
        // 2100-01-01T00:00:00Z: a fixture is never already expired.
        assert_eq!(
            t.expires_at,
            UNIX_EPOCH + Duration::from_secs(4_102_444_800)
        );
        assert!(t.expires_at > SystemTime::now());
    }

    #[test]
    fn builders_set_their_field_and_with_claims_leaves_the_rest_alone() {
        let claims = serde_json::json!({"groups": ["g1"], "n": 1});
        let claims = claims.as_object().unwrap().clone();
        let exp = UNIX_EPOCH + Duration::from_secs(1_000);
        let t = AuthorizedToken::new(Some("sub-1".into()), Some("p".into()), ["a"])
            .with_claims(claims.clone())
            .with_issuer("https://issuer.example.test")
            .with_audiences(["aud-1", "aud-2"])
            .with_expires_at(exp)
            .with_issued_at(UNIX_EPOCH)
            .with_client_id("client-1")
            .with_jti("jti-1");
        assert_eq!(t.claims(), &claims);
        assert_eq!(t.issuer, "https://issuer.example.test");
        assert_eq!(t.audiences, ["aud-1", "aud-2"]);
        assert_eq!(t.expires_at, exp);
        assert_eq!(t.issued_at, Some(UNIX_EPOCH));
        assert_eq!(t.client_id.as_deref(), Some("client-1"));
        assert_eq!(t.jti.as_deref(), Some("jti-1"));
        assert_eq!(t.subject.as_deref(), Some("sub-1"));
        assert_eq!(t.scopes, ["a"]);
        // `with_claims` alone does not derive typed fields from the map.
        let only = AuthorizedToken::new(None, None, Vec::<String>::new()).with_claims(
            serde_json::json!({"iss": "x", "jti": "y"})
                .as_object()
                .unwrap()
                .clone(),
        );
        assert_eq!(only.issuer, "");
        assert_eq!(only.jti, None);
    }

    #[test]
    fn equality_and_clone_cover_the_claims() {
        let a = AuthorizedToken::new(None, None, ["a"])
            .with_claims(serde_json::json!({"k": 1}).as_object().unwrap().clone());
        assert_eq!(a.clone(), a);
        assert_ne!(a, AuthorizedToken::new(None, None, ["a"]));
    }

    #[test]
    fn numeric_date_reads_like_jsonwebtoken_and_saturates_and_never_panics() {
        let secs = |s: u64| Some(UNIX_EPOCH + Duration::from_secs(s));
        let max = secs(MAX_TIMESTAMP_SECS);
        assert_eq!(numeric_date(&serde_json::json!(10)), secs(10));
        // Rounded to the nearest second, half away from zero, as jsonwebtoken does.
        assert_eq!(numeric_date(&serde_json::json!(1.4)), secs(1));
        assert_eq!(numeric_date(&serde_json::json!(1.5)), secs(2));
        assert_eq!(numeric_date(&serde_json::json!(0.4)), secs(0));
        assert_eq!(numeric_date(&serde_json::json!(u64::MAX)), max);
        assert_eq!(numeric_date(&serde_json::json!(i64::MAX as u64 + 1)), max);
        assert_eq!(numeric_date(&serde_json::json!(1e19)), max);
        assert_eq!(numeric_date(&serde_json::json!(-1)), None);
        assert_eq!(numeric_date(&serde_json::json!(-0.4)), None);
        assert_eq!(numeric_date(&serde_json::json!(1e30)), None);
        assert_eq!(numeric_date(&serde_json::json!("10")), None);
    }

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
