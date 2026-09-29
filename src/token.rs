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
    /// The token's `iat`, when it carried a valid NumericDate. Checked only
    /// when [`crate::OAuthConfig::max_token_age_secs`] is set. Rounded and saturated like
    /// [`expires_at`](Self::expires_at); `None` when `iat` is absent or not a
    /// non-negative number (the token is still accepted then). `None` on a token built with [`AuthorizedToken::new`].
    pub issued_at: Option<SystemTime>,
    /// The OAuth client the token was issued to: `client_id` (RFC 9068 §2.2),
    /// else `azp`, the first that is a non-empty string — the same reading
    /// [`crate::OAuthConfig::allowed_client_ids`] is checked against. `None` when the token
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
            .field("issuer", &self.issuer)
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
    let secs = numeric_date_secs(value)?;
    Some(UNIX_EPOCH + Duration::from_secs(secs))
}

/// [`numeric_date`] as whole seconds since the epoch, saturated the same way.
pub(crate) fn numeric_date_secs(value: &Value) -> Option<u64> {
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
    Some(secs.min(MAX_TIMESTAMP_SECS))
}

/// The OAuth client a token was issued to: `client_id` (RFC 9068 §2.2), else
/// `azp`, the first that is a non-empty string. The one reading of it, shared
/// by [`AuthorizedToken::client_id`] and the `allowed_client_ids` check.
pub(crate) fn client_id_of(claims: &Map<String, Value>) -> Option<&str> {
    ["client_id", "azp"].into_iter().find_map(|name| {
        claims
            .get(name)
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
    })
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
            client_id: client_id_of(&claims).map(str::to_string),
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
/// reachable through the variant itself ([`InvalidToken`]) and through
/// `Debug`, for logs.
///
/// ```
/// use oauth_resource_server::{InvalidToken, InvalidTokenKind, TokenRejection};
///
/// let e = TokenRejection::Invalid(InvalidToken::new(
///     InvalidTokenKind::WrongAudience,
///     "token rejected: InvalidAudience",
/// ));
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
    /// expired, or signed by a key we could not obtain. The
    /// [`InvalidToken`] says which check failed: its
    /// [`kind`](InvalidToken::kind) is stable and matchable (a metrics label
    /// via [`InvalidTokenKind::as_str`]), its [`detail`](InvalidToken::detail)
    /// is for logs only — never return it to the caller, since telling an
    /// unauthenticated client exactly which check failed is a free oracle.
    #[error("invalid token")]
    Invalid(InvalidToken),
    /// 403 `insufficient_scope`: signature, issuer, audience and expiry all
    /// passed, but the token does not carry every required scope.
    #[error("insufficient scope")]
    InsufficientScope,
}

impl TokenRejection {
    /// `Invalid` of `kind`: the one constructor every refusal this crate makes
    /// goes through, so each site names its kind.
    pub(crate) fn invalid(kind: InvalidTokenKind, detail: impl Into<String>) -> Self {
        Self::Invalid(InvalidToken::new(kind, detail))
    }
}

/// Why a credential was refused as [`TokenRejection::Invalid`]: a stable,
/// matchable [`kind`](Self::kind) and a log-only [`detail`](Self::detail).
///
/// `Display` (and `Deref<Target = str>`) is the detail — the same reason text
/// `Invalid` carried as a `String` before 0.2.0 — so logging it, calling
/// `str` methods on it and comparing it with a string literal keep working.
/// Match on [`kind`](Self::kind), never on the text: the kind a given refusal
/// carries is part of this crate's semver contract, its wording is not.
///
/// Equality between two `InvalidToken`s compares the kind and the detail;
/// equality with a `str` compares the detail only.
///
/// # Security
///
/// The detail names the check that failed and can quote token-derived text
/// (truncated). Log it; never put it in a response body, where it would be a
/// free oracle for an unauthenticated caller. The kind's
/// [`as_str`](InvalidTokenKind::as_str) label is low-cardinality and meant for
/// metrics and logs; this crate's own responses never carry it either.
///
/// # Examples
///
/// ```
/// use oauth_resource_server::{InvalidToken, InvalidTokenKind, TokenRejection};
///
/// fn metrics_label(rejection: &TokenRejection) -> &'static str {
///     match rejection {
///         TokenRejection::Missing => "missing",
///         TokenRejection::Invalid(invalid) => invalid.kind().as_str(),
///         TokenRejection::InsufficientScope => "insufficient_scope",
///         _ => "other",
///     }
/// }
///
/// let expired = TokenRejection::Invalid(InvalidToken::new(
///     InvalidTokenKind::Expired,
///     "token rejected: ExpiredSignature",
/// ));
/// assert_eq!(metrics_label(&expired), "expired");
///
/// // The 0.1 shapes still compile: a string converts (kind `Other`), and the
/// // reason reads as a `str`.
/// let legacy = TokenRejection::Invalid("custom refusal".into());
/// if let TokenRejection::Invalid(reason) = &legacy {
///     assert_eq!(reason.kind(), InvalidTokenKind::Other);
///     assert!(reason.contains("custom"));
///     assert_eq!(reason, "custom refusal");
///     assert_eq!(reason.to_string(), "custom refusal");
/// }
/// ```
///
/// A `String` expression needs `.into()`: `Invalid(format!(..))` does not
/// compile, `Invalid(format!(..).into())` does.
///
/// ```compile_fail
/// # use oauth_resource_server::TokenRejection;
/// let _ = TokenRejection::Invalid(format!("{} candidates", 3));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct InvalidToken {
    kind: InvalidTokenKind,
    detail: String,
}

impl InvalidToken {
    /// A refusal of `kind`, with `detail` for the log. Every refusal this
    /// crate makes is built here; an application building its own (in a test,
    /// or for a check of its own) can name a kind the same way.
    pub fn new(kind: InvalidTokenKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
        }
    }

    /// Which check refused the token: stable and matchable, see
    /// [`InvalidTokenKind`].
    pub fn kind(&self) -> InvalidTokenKind {
        self.kind
    }

    /// The human-readable reason, for logs only (see the type's `# Security`).
    /// Its wording may change in any release.
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl fmt::Display for InvalidToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.detail)
    }
}

/// Kind [`InvalidTokenKind::Other`]: what a 0.1-style
/// `TokenRejection::Invalid(reason.into())` builds.
impl From<String> for InvalidToken {
    fn from(detail: String) -> Self {
        Self::new(InvalidTokenKind::Other, detail)
    }
}

/// Kind [`InvalidTokenKind::Other`]: what a 0.1-style
/// `TokenRejection::Invalid("reason".into())` builds.
impl From<&str> for InvalidToken {
    fn from(detail: &str) -> Self {
        Self::new(InvalidTokenKind::Other, detail)
    }
}

/// The [`detail`](InvalidToken::detail), so `str` methods (`contains`,
/// `starts_with`, ...) keep working on a 0.1-style `Invalid(reason)` binding.
impl std::ops::Deref for InvalidToken {
    type Target = str;

    fn deref(&self) -> &str {
        &self.detail
    }
}

/// Compares the [`detail`](InvalidToken::detail) only.
impl PartialEq<str> for InvalidToken {
    fn eq(&self, other: &str) -> bool {
        self.detail == other
    }
}

/// Compares the [`detail`](InvalidToken::detail) only.
impl PartialEq<&str> for InvalidToken {
    fn eq(&self, other: &&str) -> bool {
        self.detail == *other
    }
}

/// Which check refused a token — see [`InvalidToken::kind`].
///
/// Each kind names one family of checks, and [`as_str`](Self::as_str) gives it
/// a stable, low-cardinality `snake_case` label for metrics and alerting (for
/// example, [`KeySetUnavailable`](Self::KeySetUnavailable) is an
/// authorization-server outage, not junk traffic). Every kind is a 401
/// `invalid_token`; the kind changes nothing about the response.
///
/// `#[non_exhaustive]`: a kind may be added in a minor release, so match with a
/// wildcard arm. Which kind an existing refusal carries, and each kind's label,
/// are stable; the [`InvalidToken::detail`] text is not.
///
/// # Examples
///
/// ```
/// use oauth_resource_server::{InvalidToken, InvalidTokenKind};
///
/// /// Whether a refusal points at the authorization server rather than at the
/// /// caller — worth an alert of its own.
/// fn is_idp_trouble(invalid: &InvalidToken) -> bool {
///     match invalid.kind() {
///         InvalidTokenKind::KeySetUnavailable => true,
///         InvalidTokenKind::Expired | InvalidTokenKind::BadSignature => false,
///         _ => false,
///     }
/// }
///
/// let outage = InvalidToken::new(InvalidTokenKind::KeySetUnavailable, "JWKS refresh failed");
/// assert!(is_idp_trouble(&outage));
/// assert_eq!(outage.kind().as_str(), "key_set_unavailable");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum InvalidTokenKind {
    /// The credential is over the 16 KiB cap; refused before it is decoded.
    TooLarge,
    /// The credential is not three dot-separated segments: a mistyped static
    /// token, or an opaque (non-JWT) access token.
    NotJwt,
    /// The JWS protected header is not a base64url JSON object this crate can
    /// read (including an `alg` it does not know at all, such as `none`).
    MalformedHeader,
    /// The header lists critical extensions (`crit`, RFC 7515 §4.1.11), none of
    /// which this crate supports.
    CriticalHeader,
    /// The header's `alg` is not in the configured allowlist.
    AlgorithmNotAllowed,
    /// The header's `typ` is not an access-token type (or is absent or `JWT`
    /// while `require_at_jwt` is on).
    TypeNotAllowed,
    /// No held key matches the token's `kid` and `alg`: not in the key set
    /// even after a refetch, or unknown while the unknown-`kid` refetch
    /// cooldown runs.
    KeyNotFound,
    /// The key set could not be loaded: discovery or the JWKS fetch failed.
    /// An authorization-server (or network) outage, not the caller's fault.
    KeySetUnavailable,
    /// The header checks passed but the rest does not decode: the payload is
    /// not base64url JSON (an object), or the signature is not base64url.
    MalformedToken,
    /// The signature does not verify with the selected key (or the key could
    /// not be used to verify it).
    BadSignature,
    /// `exp` is in the past (beyond the configured leeway).
    Expired,
    /// `nbf` is in the future (beyond the configured leeway), or, with
    /// `max_token_age_secs` set, `iat` is.
    NotYetValid,
    /// `iss` is not exactly the configured issuer (including an `iss` array).
    WrongIssuer,
    /// No `aud` entry is an accepted audience.
    WrongAudience,
    /// A claim the checks need is absent: `exp`, `iss` or `aud`; `iat` with
    /// `max_token_age_secs` set; a `required_claims` entry.
    MissingClaim,
    /// A registered claim has the wrong type: an `nbf` (or, with
    /// `max_token_age_secs` set, an `iat`) that is not a NumericDate.
    MalformedClaim,
    /// The token carries `cnf` (a DPoP or mTLS sender constraint), which this
    /// crate cannot verify and so refuses as a bearer token.
    SenderConstrained,
    /// `allowed_client_ids` is set and the token's client (`client_id`, else
    /// `azp`) is absent or not listed.
    ClientNotAllowed,
    /// `max_token_age_secs` is set and the token was issued (`iat`) longer ago
    /// than that, plus the leeway.
    TokenTooOld,
    /// A `required_claims` entry is present in the token with another value
    /// (and, for an array claim, not among its elements).
    ClaimMismatch,
    /// Only a static token is configured (no OAuth validator) and no
    /// credential is it.
    StaticTokenMismatch,
    /// Neither a static token nor an OAuth validator is configured.
    NoMechanism,
    /// A credential was accepted, but the handler needs an OAuth access token
    /// (the axum `AuthorizedToken` extractor) and got a static token.
    OAuthTokenRequired,
    /// Anything else: every [`InvalidToken`] built from a `String` or `&str`,
    /// and a decoder failure this crate cannot classify more precisely.
    Other,
}

impl InvalidTokenKind {
    /// A stable, lowercase `snake_case` label (`"expired"`, `"bad_signature"`,
    /// `"key_set_unavailable"`, ...), for a metrics label or a log field. It
    /// does not change between releases for an existing kind.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TooLarge => "too_large",
            Self::NotJwt => "not_jwt",
            Self::MalformedHeader => "malformed_header",
            Self::CriticalHeader => "critical_header",
            Self::AlgorithmNotAllowed => "algorithm_not_allowed",
            Self::TypeNotAllowed => "type_not_allowed",
            Self::KeyNotFound => "key_not_found",
            Self::KeySetUnavailable => "key_set_unavailable",
            Self::MalformedToken => "malformed_token",
            Self::BadSignature => "bad_signature",
            Self::Expired => "expired",
            Self::NotYetValid => "not_yet_valid",
            Self::WrongIssuer => "wrong_issuer",
            Self::WrongAudience => "wrong_audience",
            Self::MissingClaim => "missing_claim",
            Self::MalformedClaim => "malformed_claim",
            Self::SenderConstrained => "sender_constrained",
            Self::ClientNotAllowed => "client_not_allowed",
            Self::TokenTooOld => "token_too_old",
            Self::ClaimMismatch => "claim_mismatch",
            Self::StaticTokenMismatch => "static_token_mismatch",
            Self::NoMechanism => "no_mechanism",
            Self::OAuthTokenRequired => "oauth_token_required",
            Self::Other => "other",
        }
    }
}

impl fmt::Display for InvalidTokenKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
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
            Err(TokenRejection::invalid(
                InvalidTokenKind::TypeNotAllowed,
                format!(
                    "token header has no typ and {} is on",
                    naming.key("require_at_jwt")
                ),
            ))
        } else {
            Ok(())
        };
    };
    let lower = raw.trim().to_ascii_lowercase();
    let media = lower.strip_prefix("application/").unwrap_or(&lower);
    match media {
        "at+jwt" => Ok(()),
        "jwt" if !require_at_jwt => Ok(()),
        _ => Err(TokenRejection::invalid(
            InvalidTokenKind::TypeNotAllowed,
            format!(
                "token typ {:?} is not accepted as an access token{}",
                for_log(raw),
                if require_at_jwt {
                    format!(" ({} is on)", naming.key("require_at_jwt"))
                } else {
                    String::new()
                }
            ),
        )),
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
        let typ = |detail: &str| {
            Err(TokenRejection::Invalid(InvalidToken::new(
                InvalidTokenKind::TypeNotAllowed,
                detail,
            )))
        };
        let dotted = KeyNamingBuf::Dotted("mcp.oauth".into());
        assert_eq!(
            check_typ(None, true, &dotted),
            typ("token header has no typ and mcp.oauth.require_at_jwt is on")
        );
        assert_eq!(
            check_typ(Some("JWT"), true, &dotted),
            typ("token typ \"JWT\" is not accepted as an access token \
                 (mcp.oauth.require_at_jwt is on)")
        );
        assert_eq!(
            check_typ(Some("dpop+jwt"), false, &dotted),
            typ("token typ \"dpop+jwt\" is not accepted as an access token")
        );
        let env = KeyNamingBuf::Env("APP_OAUTH_".into());
        assert_eq!(
            check_typ(None, true, &env),
            typ("token header has no typ and APP_OAUTH_REQUIRE_AT_JWT is on")
        );
    }

    /// The 0.1 uses of `Invalid(String)` that 0.2 keeps compiling, each as a
    /// consumer would write it.
    #[test]
    #[allow(clippy::op_ref, clippy::cmp_owned)]
    fn invalid_token_keeps_the_string_uses_compiling() {
        // Construction from a literal and from an owned `String`: kind `Other`.
        let from_str = TokenRejection::Invalid("bad token".into());
        let from_string = TokenRejection::Invalid(String::from("bad token").into());
        assert_eq!(from_str, from_string);
        let TokenRejection::Invalid(reason) = &from_str else {
            panic!("not Invalid")
        };
        assert_eq!(reason.kind(), InvalidTokenKind::Other);
        assert_eq!(reason.detail(), "bad token");
        // `Display` is the detail, byte for byte; `format!`/`to_string` too.
        assert_eq!(reason.to_string(), "bad token");
        assert_eq!(format!("refused: {reason}"), "refused: bad token");
        // `Deref<Target = str>`: `str` methods and `&str` coercion.
        assert!(reason.contains("bad"));
        assert!(reason.starts_with("bad "));
        assert_eq!(reason.len(), 9);
        let as_str: &str = reason;
        assert_eq!(as_str, "bad token");
        // `PartialEq<str>` and `PartialEq<&str>`, from a reference and a value.
        assert!(reason == "bad token");
        assert!(*reason == "bad token");
        assert!(reason.clone() == "bad token");
        assert!(&**reason == "bad token");
        assert!(reason != "other");
        // `matches!` on the variant, with and without a binding.
        assert!(matches!(from_str, TokenRejection::Invalid(_)));
        assert!(matches!(&from_str, TokenRejection::Invalid(r) if r.contains("bad")));
        // Equality between two `InvalidToken`s includes the kind.
        assert_ne!(
            InvalidToken::new(InvalidTokenKind::Expired, "bad token"),
            InvalidToken::from("bad token")
        );
        // `Debug` still carries the reason, for logs.
        assert!(format!("{from_str:?}").contains("bad token"));
        // `Invalid(format!(..))` alone no longer compiles; `.into()` does.
        let n = 3;
        let formatted = TokenRejection::Invalid(format!("{n} candidates").into());
        assert!(matches!(formatted, TokenRejection::Invalid(r) if r == "3 candidates"));
    }

    #[test]
    fn every_invalid_token_kind_label_is_distinct_snake_case() {
        use InvalidTokenKind as K;
        let all = [
            K::TooLarge,
            K::NotJwt,
            K::MalformedHeader,
            K::CriticalHeader,
            K::AlgorithmNotAllowed,
            K::TypeNotAllowed,
            K::KeyNotFound,
            K::KeySetUnavailable,
            K::MalformedToken,
            K::BadSignature,
            K::Expired,
            K::NotYetValid,
            K::WrongIssuer,
            K::WrongAudience,
            K::MissingClaim,
            K::MalformedClaim,
            K::SenderConstrained,
            K::ClientNotAllowed,
            K::TokenTooOld,
            K::ClaimMismatch,
            K::StaticTokenMismatch,
            K::NoMechanism,
            K::OAuthTokenRequired,
            K::Other,
        ];
        let labels: HashSet<&str> = all.iter().map(|k| k.as_str()).collect();
        assert_eq!(labels.len(), all.len());
        for (kind, label) in all.iter().zip(all.iter().map(|k| k.as_str())) {
            assert!(
                label.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'),
                "{label}"
            );
            assert_eq!(kind.to_string(), label);
        }
    }
}
