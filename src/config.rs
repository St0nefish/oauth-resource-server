//! Configuration: the unvalidated input shape ([`OAuthConfig`]), its validation
//! ([`OAuthConfig::resolve`]), and the validated shape the validator is built from
//! ([`ResolvedOAuthConfig`]).
//!
//! Validation is all-or-nothing: an enabled config either resolves completely or
//! fails with **every** problem at once, each naming the offending setting the way
//! the operator spelled it — a dotted YAML key or an environment variable, chosen
//! by [`KeyNaming`]. A half-usable OAuth config must fail at startup, with the key
//! in the message, rather than as a wall of 401s later.

use std::collections::BTreeMap;
use std::fmt;

use serde_json::Value;

use crate::algorithms::{Algorithm, DEFAULT_ALGORITHMS, parse_algorithm};
use crate::validator::plain_http_non_loopback;

/// Default [`OAuthConfig::scope_claims`]. `scope` is RFC 9068 §2.2.3's
/// space-delimited string (Authentik, Kanidm, Keycloak); `scp` is what Authelia
/// (array), Okta (array), Ory Hydra (array or string) and Entra ID (string) emit
/// instead. Reading both by default is what makes an Authelia token pass without
/// per-provider config, and it cannot widen access for a token that carries only
/// `scope` (every Authentik token) because a claim the token does not have
/// contributes nothing.
pub const DEFAULT_SCOPE_CLAIMS: &[&str] = &["scope", "scp"];

/// Default [`OAuthConfig::principal_claims`]. `email` is left out on purpose so a
/// default deployment does not write addresses into its logs; an operator who
/// wants it adds it.
pub const DEFAULT_PRINCIPAL_CLAIMS: &[&str] = &["preferred_username", "sub"];

/// Default [`OAuthConfig::leeway_secs`]: the clock-skew allowance, in seconds.
pub const DEFAULT_LEEWAY_SECS: u64 = 60;

/// Ceiling on [`OAuthConfig::leeway_secs`]. Leeway is for clock drift; a value
/// large enough to matter against a 5–15 minute token lifetime (Kanidm issues
/// 900 s tokens) is a way of switching `exp` off, which config must not be able
/// to do.
pub const MAX_LEEWAY_SECS: u64 = 300;

/// Ceiling on [`OAuthConfig::max_token_age_secs`]: 30 days. The setting bounds
/// how long ago a token may have been issued; an access token older than a
/// month is not something any deployment means to bound *to*, so a larger
/// value is a typo (seconds meant as minutes, an extra digit), not a policy.
pub const MAX_TOKEN_AGE_SECS: u64 = 30 * 24 * 3600;

/// Claims [`OAuthConfig::required_claims`] may not name, because this crate
/// already checks them, or refuses them outright: `iss`, `aud`, `exp` and
/// `nbf` are validated inside the signature-checking `decode` (an exact-value
/// requirement on top would either repeat that check or, for `aud`
/// membership and the time claims, contradict it); `iat` is what
/// [`OAuthConfig::max_token_age_secs`] bounds (a fixed `iat` would match one
/// token only); and a token carrying `cnf` is always refused.
pub(crate) const RESERVED_REQUIRED_CLAIMS: &[&str] = &["iss", "aud", "exp", "nbf", "iat", "cnf"];

/// How problem messages name a setting, so they match how the operator wrote it.
///
/// - `Dotted("mcp.oauth")` names the issuer `mcp.oauth.issuer` — a key in a YAML
///   (or other serde) config nested under that path.
/// - `Env("MYAPP_OAUTH_")` names it `MYAPP_OAUTH_ISSUER` — the field name
///   uppercased and appended to the prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyNaming<'a> {
    /// A dotted path prefix; a field is named `<prefix>.<field>`.
    Dotted(&'a str),
    /// An environment-variable prefix; a field is named `<PREFIX><FIELD>`.
    Env(&'a str),
}

impl KeyNaming<'_> {
    /// The name of setting `field` (a lower-case [`OAuthConfig`] field name).
    pub fn key(&self, field: &str) -> String {
        match self {
            KeyNaming::Dotted("") => field.to_string(),
            KeyNaming::Dotted(prefix) => format!("{prefix}.{field}"),
            KeyNaming::Env(prefix) => format!("{prefix}{}", field.to_ascii_uppercase()),
        }
    }

    /// The name of the whole block: the dotted prefix itself, or `PREFIX*` for
    /// environment variables. An empty dotted prefix (the OAuth fields at the
    /// root of the config) has no path to name, so the block is called
    /// `OAuth config` rather than rendering as an empty string.
    pub fn section(&self) -> String {
        match self {
            KeyNaming::Dotted("") => "OAuth config".to_string(),
            KeyNaming::Dotted(prefix) => prefix.to_string(),
            KeyNaming::Env(prefix) => format!("{prefix}*"),
        }
    }

    /// The owned form, for storing past the borrow.
    pub fn to_buf(&self) -> KeyNamingBuf {
        match self {
            KeyNaming::Dotted(p) => KeyNamingBuf::Dotted((*p).to_string()),
            KeyNaming::Env(p) => KeyNamingBuf::Env((*p).to_string()),
        }
    }
}

/// Owned [`KeyNaming`], carried on [`ResolvedOAuthConfig`] and [`ConfigError`] so
/// that log lines and errors produced after resolution (a token naming an
/// algorithm outside the allowlist, a discovery document for another issuer) name
/// settings the same way the config did.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyNamingBuf {
    /// See [`KeyNaming::Dotted`].
    Dotted(String),
    /// See [`KeyNaming::Env`].
    Env(String),
}

impl KeyNamingBuf {
    /// Borrow as a [`KeyNaming`].
    pub fn as_naming(&self) -> KeyNaming<'_> {
        match self {
            KeyNamingBuf::Dotted(p) => KeyNaming::Dotted(p),
            KeyNamingBuf::Env(p) => KeyNaming::Env(p),
        }
    }

    /// Shorthand for `self.as_naming().key(field)`.
    pub fn key(&self, field: &str) -> String {
        self.as_naming().key(field)
    }

    /// Shorthand for `self.as_naming().section()`.
    pub fn section(&self) -> String {
        self.as_naming().section()
    }
}

/// What kind of problem a [`ConfigProblem`] is, so a caller can react to it —
/// or write its own sentence for it — without matching the crate's prose.
///
/// `#[non_exhaustive]`: a new kind is an additive change, so match with a
/// wildcard arm. Every problem [`OAuthConfig::resolve`] and the
/// [`env`](crate::env) loader find has a specific kind; [`Other`](Self::Other)
/// is what a problem built from a plain `String` (an application loader's own)
/// gets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ProblemKind {
    /// A required setting is empty: `issuer`, `resource`, or both `audience`
    /// and `audiences`.
    MissingRequired,
    /// A URL setting (`issuer`, `resource`, `jwks_uri`) failed a `check_url`
    /// check: not an absolute `http(s)` URL, a query or fragment in an
    /// identifier (`issuer`, `resource`), leading or trailing whitespace, or a
    /// control or non-ASCII character.
    InvalidUrl,
    /// A plain-`http` URL on a non-loopback host without
    /// `allow_insecure_http`.
    InsecureHttp,
    /// `required_scope`, or an entry of `required_scopes`, is blank.
    BlankRequiredScope,
    /// `required_scope`, or an entry of `required_scopes`, holds more than one
    /// scope (whitespace inside it).
    MultiWordScope,
    /// A required or advertised scope is not an RFC 6749 §3.3 scope-token.
    InvalidScopeToken,
    /// A list setting (`audiences`, `scopes_supported`, `principal_claims`) has
    /// a blank entry.
    EmptyListEntry,
    /// No required scope is configured, `require_at_jwt` is off and
    /// `allow_unscoped_tokens` is not set.
    NoRequiredScope,
    /// `scope_claims` is empty or has a blank entry.
    EmptyScopeClaims,
    /// `algorithms` has an entry that is unknown or refused (HMAC, `none`).
    BadAlgorithm,
    /// `algorithms` is empty.
    NoAlgorithms,
    /// `leeway_secs` is over [`MAX_LEEWAY_SECS`].
    LeewayTooLarge,
    /// `max_token_age_secs` is `0` or over [`MAX_TOKEN_AGE_SECS`].
    TokenAgeOutOfRange,
    /// A `required_claims` entry has a blank name, names a claim this crate
    /// already checks (`iss`, `aud`, `exp`, `nbf`, `iat`, `cnf`), or requires
    /// a value other than a string, number or boolean.
    InvalidRequiredClaim,
    /// The env loader could not read a variable or its `_FILE` (both set, an
    /// unreadable or empty file).
    EnvLoad,
    /// The env loader read a value it could not parse (a bool other than
    /// `"true"`/`"false"`, a non-integer `leeway_secs`).
    EnvParse,
    /// Anything else, including every problem converted from a `String`.
    Other,
}

impl ProblemKind {
    /// A stable, lowercase `snake_case` label for the kind (`"missing_required"`,
    /// `"invalid_url"`, ...), for logs and metrics. Unlike a problem's message,
    /// it does not change between releases for an existing kind.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingRequired => "missing_required",
            Self::InvalidUrl => "invalid_url",
            Self::InsecureHttp => "insecure_http",
            Self::BlankRequiredScope => "blank_required_scope",
            Self::MultiWordScope => "multi_word_scope",
            Self::InvalidScopeToken => "invalid_scope_token",
            Self::EmptyListEntry => "empty_list_entry",
            Self::NoRequiredScope => "no_required_scope",
            Self::EmptyScopeClaims => "empty_scope_claims",
            Self::BadAlgorithm => "bad_algorithm",
            Self::NoAlgorithms => "no_algorithms",
            Self::LeewayTooLarge => "leeway_too_large",
            Self::TokenAgeOutOfRange => "token_age_out_of_range",
            Self::InvalidRequiredClaim => "invalid_required_claim",
            Self::EnvLoad => "env_load",
            Self::EnvParse => "env_parse",
            Self::Other => "other",
        }
    }
}

impl fmt::Display for ProblemKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One configuration problem: its [`ProblemKind`], the settings it names, and
/// the human-readable sentence.
///
/// [`kind`](Self::kind) and [`keys`](Self::keys) are what a caller matches on;
/// [`message`](Self::message) (also its `Display`) is for people, and its
/// wording may change in any release. `#[non_exhaustive]`.
///
/// An application loader mixes its own problems in with
/// `ConfigProblem::from(String)` (kind [`ProblemKind::Other`]) or
/// [`ConfigProblem::new`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ConfigProblem {
    kind: ProblemKind,
    keys: Vec<String>,
    message: String,
}

impl ConfigProblem {
    /// A problem of `kind` naming `keys` (already spelled the way the error's
    /// [`KeyNaming`] spells them), described by `message`.
    pub fn new(
        kind: ProblemKind,
        keys: impl IntoIterator<Item = impl Into<String>>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            keys: keys.into_iter().map(Into::into).collect(),
            message: message.into(),
        }
    }

    /// What kind of problem this is.
    pub fn kind(&self) -> ProblemKind {
        self.kind
    }

    /// The settings this problem names, rendered via [`KeyNaming`] (a dotted
    /// key or an environment variable). Empty for a problem converted from a
    /// `String`.
    pub fn keys(&self) -> &[String] {
        &self.keys
    }

    /// The human-readable sentence. Not a stable API: match on
    /// [`kind`](Self::kind) instead.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl From<String> for ConfigProblem {
    /// A problem of kind [`ProblemKind::Other`] with no keys.
    fn from(message: String) -> Self {
        Self::new(ProblemKind::Other, Vec::<String>::new(), message)
    }
}

impl fmt::Display for ConfigProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

/// An enabled config that cannot be used, with every problem found.
///
/// `Display` renders all of them under one header naming the block the way
/// [`KeyNaming`] spells it; for `Dotted("mcp.oauth")` that is
///
/// ```text
/// mcp.oauth.enabled is true but the OAuth config is not usable:
///   - <problem>
///   - <problem>
/// Fix these, or set mcp.oauth.enabled: false.
/// ```
///
/// Each problem is available two ways.
/// [`problem_details`](Self::problem_details) is the structured list
/// ([`ConfigProblem`]: a [`ProblemKind`], the settings named, the message); the
/// public [`problems`](Self::problems) field holds the same messages as plain
/// strings, kept for compatibility. Prefer matching on [`ProblemKind`] to
/// matching text: message wording is not a stable API.
#[derive(Debug, Clone, thiserror::Error)]
pub struct ConfigError {
    /// One human-readable sentence per problem, each naming its setting.
    ///
    /// Kept for compatibility; the structured form is
    /// [`problem_details`](Self::problem_details). Both are filled from one
    /// list at construction, in the same order. Editing this field in place
    /// does not update `problem_details()`; `Display` renders this field.
    pub problems: Vec<String>,
    details: Vec<ConfigProblem>,
    naming: KeyNamingBuf,
}

impl ConfigError {
    /// An error listing `problems`, whose header names settings per `naming`.
    /// For loaders that add their own problems (parse errors, say) alongside the
    /// ones [`OAuthConfig::resolve`] finds. Each string becomes a
    /// [`ProblemKind::Other`] problem in
    /// [`problem_details`](Self::problem_details); use
    /// [`from_problems`](Self::from_problems) to give them kinds.
    ///
    /// `problems` must not be empty: an error with nothing to fix would display
    /// as a header over one blank bullet. Debug builds assert it.
    pub fn new(naming: KeyNaming<'_>, problems: Vec<String>) -> Self {
        let details = problems.iter().cloned().map(ConfigProblem::from).collect();
        Self::assemble(naming, problems, details)
    }

    /// An error listing structured `problems`, whose header names settings per
    /// `naming`. [`problems`](Self::problems) is rendered from their messages,
    /// so the two views agree. A `String` converts with `.into()` (kind
    /// [`ProblemKind::Other`]), so an application loader can mix its own
    /// problems in with the crate's.
    ///
    /// `problems` must not be empty; debug builds assert it.
    pub fn from_problems(
        naming: KeyNaming<'_>,
        problems: impl IntoIterator<Item = ConfigProblem>,
    ) -> Self {
        let details: Vec<ConfigProblem> = problems.into_iter().collect();
        let text = details.iter().map(|p| p.message.clone()).collect();
        Self::assemble(naming, text, details)
    }

    /// `problems` and `details` are the same length, element for element.
    fn assemble(naming: KeyNaming<'_>, problems: Vec<String>, details: Vec<ConfigProblem>) -> Self {
        debug_assert!(!problems.is_empty(), "ConfigError built with no problems");
        debug_assert_eq!(problems.len(), details.len());
        Self {
            problems,
            details,
            naming: naming.to_buf(),
        }
    }

    /// The structured problems, in the order [`problems`](Self::problems) lists
    /// them. Match on [`ProblemKind`] rather than on message text:
    ///
    /// ```
    /// use oauth_resource_server::{KeyNaming, OAuthConfig, ProblemKind};
    ///
    /// let err = OAuthConfig {
    ///     enabled: true,
    ///     leeway_secs: 3600,
    ///     ..OAuthConfig::default()
    /// }
    /// .resolve(KeyNaming::Env("MYAPP_OAUTH_"))
    /// .unwrap_err();
    ///
    /// for problem in err.problem_details() {
    ///     match problem.kind() {
    ///         ProblemKind::MissingRequired => {
    ///             assert!(problem.keys().contains(&"MYAPP_OAUTH_ISSUER".to_string()));
    ///         }
    ///         ProblemKind::LeewayTooLarge => {
    ///             assert_eq!(problem.keys(), ["MYAPP_OAUTH_LEEWAY_SECS"]);
    ///         }
    ///         // `ProblemKind` is `#[non_exhaustive]`: keep a wildcard arm.
    ///         _ => {}
    ///     }
    /// }
    /// ```
    ///
    /// An error built with [`ConfigError::new`] reports every problem as
    /// [`ProblemKind::Other`]. The list is fixed at construction: editing the
    /// public `problems` field in place does not change it (that field is kept
    /// for compatibility).
    pub fn problem_details(&self) -> &[ConfigProblem] {
        &self.details
    }

    /// How this error names settings.
    pub fn naming(&self) -> KeyNaming<'_> {
        self.naming.as_naming()
    }
}

/// Equality is over [`problems`](ConfigError::problems) and the naming only,
/// as before structured details existed: an error rebuilt with
/// [`ConfigError::new`] from another's `problems` compares equal to it.
impl PartialEq for ConfigError {
    fn eq(&self, other: &Self) -> bool {
        self.problems == other.problems && self.naming == other.naming
    }
}

impl Eq for ConfigError {}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let list = self.problems.join("\n  - ");
        match &self.naming {
            KeyNamingBuf::Dotted(_) => {
                let enabled = self.naming.key("enabled");
                write!(
                    f,
                    "{enabled} is true but the OAuth config is not usable:\n  - {list}\n\
                     Fix these, or set {enabled}: false."
                )
            }
            KeyNamingBuf::Env(_) => {
                let section = self.naming.section();
                write!(
                    f,
                    "OAuth is configured through {section} but the config is not usable:\n  \
                     - {list}\nFix these, or unset every {section} variable."
                )
            }
        }
    }
}

/// The OAuth resource-server settings, as written by an operator — unvalidated.
///
/// Turns the process into an OAuth 2.0 *resource server* (RFC 9728, RFC 9068,
/// RFC 6750): it verifies JWT access tokens minted by a separate authorization
/// server and never issues, refreshes or introspects anything itself. Call
/// [`OAuthConfig::resolve`] to validate it into a [`ResolvedOAuthConfig`].
///
/// Provider-agnostic by construction: every provider-specific difference
/// (audience value, scope claim name and shape, signing algorithm, `typ`,
/// username claim) is a field below rather than a code path.
///
/// Every field is optional in serde input (feature `serde`); unknown keys are
/// refused. **Nest this in your own config; do not `#[serde(flatten)]` it** —
/// flattening silently defeats the unknown-key check (a general serde
/// limitation, not specific to this crate); see [Embedding `OAuthConfig` in
/// your own
/// config](https://github.com/St0nefish/oauth-resource-server#embedding-oauthconfig-in-your-own-config)
/// in the README. Nothing here hot-reloads: a changed value takes effect only
/// when a new validator is built from it, which in practice means a restart.
///
/// Deliberately not `#[non_exhaustive]`, so applications can write
/// `OAuthConfig { enabled: true, ..OAuthConfig::default() }` — a
/// functional-record update that keeps compiling even after a field is
/// added. What breaks instead is an exhaustive struct literal or
/// destructuring pattern that names every field, which is possible only
/// because every field here is public and the struct carries no
/// `#[non_exhaustive]`; adding a field is still a breaking change under
/// `0.x` (a new minor release, which Cargo treats as incompatible), just not
/// for the functional-record-update form above.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct OAuthConfig {
    /// Master switch. False (the default) means [`OAuthConfig::resolve`] returns
    /// `Ok(None)`: no JWT validation happens at all and nothing else here is
    /// checked.
    #[cfg_attr(feature = "serde", serde(default))]
    pub enabled: bool,
    /// The authorization server's issuer identifier, compared BYTE-EXACTLY
    /// against each token's `iss` claim and echoed verbatim in the
    /// protected-resource metadata's `authorization_servers`. Copy it from the
    /// AS's own discovery document including any trailing slash — Authentik's
    /// issuer ends in one, and a token minted with `.../app/` will not match
    /// `.../app`. Required; an absolute URL with no query or fragment, and no
    /// space, control or non-ASCII character. Write it `https://host/...`: a
    /// spelling the URL parser repairs (`https:/host`) never matches a token's
    /// `iss` byte-for-byte, and `OAuthValidator::new` warns about one.
    ///
    /// `https`, as RFC 8414 §2 requires of an issuer: the signing keys are
    /// found through it, and keys fetched over cleartext can be substituted by
    /// anyone on the path. Plain `http` is accepted only for a loopback host,
    /// or with [`OAuthConfig::allow_insecure_http`].
    ///
    /// Userinfo (`https://user:pass@…`) is accepted, and sent as HTTP Basic
    /// auth on the discovery fetches; this crate redacts it wherever it
    /// displays the URL (log lines, [`crate::RefreshError`]). The issuer is
    /// also published verbatim in the RFC 9728 metadata document, though, so
    /// a credential does not belong in it.
    #[cfg_attr(feature = "serde", serde(default))]
    pub issuer: String,
    /// Where to fetch the signing keys (JWKS). Optional: absent or blank, it is
    /// discovered from the issuer's own metadata (OpenID Connect Discovery, then
    /// RFC 8414), and the discovered document's `issuer` must equal `issuer`
    /// byte-for-byte or it is refused. Setting it explicitly skips discovery.
    /// Fetched at startup and hourly in the background, and on an unknown `kid`
    /// at most once a minute. The same URL rules as `issuer` apply, except
    /// that a query is allowed; RFC 8414 §2 requires `https` for it too.
    ///
    /// Userinfo (`https://user:pass@…`, sent as HTTP Basic auth) and a query
    /// (`…/jwks?key=…`) are accepted and used unchanged for the fetch; this
    /// crate redacts both wherever it displays the URL (log lines,
    /// [`crate::RefreshError`], [`crate::KeySetStatus::jwks_uri`]).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub jwks_uri: Option<String>,
    /// A value each token's `aud` claim must contain (string or array, RFC 7519
    /// §4.1.3). Unioned with `audiences`; at least one of the two must be set,
    /// and there is deliberately no default, because the right value depends on
    /// the authorization server and a wrong guess either rejects everything or
    /// accepts tokens meant for another service:
    ///
    /// - servers that honour RFC 8707 or let you configure an access-token
    ///   audience (Authelia with a client `audience`) put the RESOURCE URL there
    ///   — use the same value as `resource`;
    /// - servers that ignore RFC 8707 and stamp the OAuth CLIENT ID (Authentik,
    ///   Kanidm) need the client_id here.
    ///
    /// A client_id audience departs from RFC 9068 §4 (the `aud` must identify
    /// this resource server) and from MCP's requirement that a server accept
    /// only tokens issued for it as audience (RFC 8707 §2): every token that
    /// client obtains from the authorization server, for any resource, carries
    /// the same `aud`. It is sound only when that OAuth client is dedicated to
    /// this one resource server and shared with no other API. Prefer a
    /// resource-URL audience wherever the authorization server supports one.
    #[cfg_attr(feature = "serde", serde(default))]
    pub audience: String,
    /// Additional accepted audiences. A token passes the audience check if its
    /// `aud` contains ANY configured value. Useful while migrating from a
    /// client_id audience to a resource-URL audience.
    #[cfg_attr(feature = "serde", serde(default))]
    pub audiences: Vec<String>,
    /// This resource server's canonical identifier, published as `resource` in
    /// the protected-resource metadata and used to derive the metadata URL
    /// advertised in `WWW-Authenticate` (RFC 9728 §3). The public URL of the
    /// protected endpoint, e.g. `https://api.example.com/v1`; required, with
    /// the same URL rules as `issuer`.
    ///
    /// `https`, as RFC 9728 §1.2 requires of a resource identifier: it is the
    /// URL clients send their bearer tokens to (RFC 6750 §5.3). Plain `http` is
    /// accepted only for a loopback host, or with
    /// [`OAuthConfig::allow_insecure_http`].
    ///
    /// Not implicitly compared against `aud` — list it in `audience`/`audiences`
    /// when the authorization server stamps it there.
    ///
    /// It is published verbatim in the RFC 9728 metadata document and in the
    /// `resource_metadata` of every `WWW-Authenticate` challenge, so it must
    /// never carry a credential (userinfo is not refused, but has no place
    /// here).
    #[cfg_attr(feature = "serde", serde(default))]
    pub resource: String,
    /// A scope every token must carry. A valid token missing it gets 403
    /// `insufficient_scope`, not 401. A single RFC 6749 §3.3 scope-token —
    /// printable ASCII with no space, `"` or `\` — matched exactly and
    /// case-sensitively. Unioned with `required_scopes`.
    ///
    /// No default. With neither this nor `required_scopes` set, no scope is
    /// checked, and [`OAuthConfig::resolve`] then insists on
    /// `require_at_jwt` or [`OAuthConfig::allow_unscoped_tokens`]. An
    /// explicitly empty value is an error rather than "no scope", so a typo
    /// cannot silently drop the check.
    ///
    /// The check is an exact all-of match with no scope hierarchy: a token
    /// holding only `api:write` does not satisfy `api:read`, whatever the
    /// authorization server means by it. Require a scope every accepted token
    /// carries, and make finer, hierarchy-aware decisions in the application
    /// with [`crate::AuthorizedToken::has_scope`].
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub required_scope: Option<String>,
    /// Further scopes every token must carry — ALL of them, together with
    /// `required_scope`. Each entry follows the same rules as `required_scope`.
    /// Empty (the default) adds nothing.
    #[cfg_attr(feature = "serde", serde(default))]
    pub required_scopes: Vec<String>,
    /// Advertised in the metadata document's `scopes_supported` and the 401
    /// challenge's `scope` so a client knows what to ask for. Purely declarative —
    /// enforcement is `required_scope`/`required_scopes`. Each entry is a
    /// scope-token, as for `required_scope`.
    ///
    /// `None` (the default, and what an omitted key deserializes to) resolves to
    /// the required scopes (`required_scope`, then `required_scopes`), so a
    /// client that asks for exactly what is advertised gets a token that
    /// passes. `Some(vec![])` resolves to an empty list: the metadata document
    /// then omits `scopes_supported` (RFC 9728 §3.2), and the 401 challenge
    /// names the required scopes instead. The two are kept distinct so an
    /// application can supply its own default for an omitted key without
    /// overriding an operator's explicit empty list — e.g.
    /// `cfg.scopes_supported.get_or_insert_with(|| vec!["api:read".into()])`
    /// before [`OAuthConfig::resolve`].
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub scopes_supported: Option<Vec<String>>,
    /// Which claims hold the token's scopes. Every listed claim is read in every
    /// shape — a space-delimited string or an array of strings — and the results
    /// are unioned. The default ([`DEFAULT_SCOPE_CLAIMS`]) reads RFC 9068's
    /// `scope` AND the `scp` that Authelia, Okta, Ory Hydra and Entra ID use
    /// instead; reading a claim a token does not carry changes nothing.
    #[cfg_attr(feature = "serde", serde(default = "default_scope_claims"))]
    pub scope_claims: Vec<String>,
    /// Claims tried in order to name the caller in logs — the first present,
    /// non-empty string wins. Several servers put no username in access tokens
    /// (Authelia, Kanidm: only a UUID `sub`), hence a chain ending in `sub`.
    /// `email` is not in the default ([`DEFAULT_PRINCIPAL_CLAIMS`]) so addresses
    /// do not land in logs unasked. Used for logging only, never for an
    /// authorization decision.
    #[cfg_attr(feature = "serde", serde(default = "default_principal_claims"))]
    pub principal_claims: Vec<String>,
    /// JWS algorithms a token may be signed with. Each key in the JWKS is
    /// additionally limited to the algorithms its own type (and its `alg`, when
    /// it declares one) can produce. `HS256`/`HS384`/`HS512` and `none` are
    /// refused at resolve time: a resource server must never verify with a shared
    /// secret. The default ([`DEFAULT_ALGORITHMS`]) is every asymmetric algorithm
    /// this build can verify.
    #[cfg_attr(feature = "serde", serde(default = "default_algorithms"))]
    pub algorithms: Vec<String>,
    /// Clock-skew allowance, in seconds, applied to `exp` and `nbf`. Default
    /// [`DEFAULT_LEEWAY_SECS`]; capped at [`MAX_LEEWAY_SECS`], since a leeway
    /// comparable to a token's lifetime is a way of disabling expiry.
    #[cfg_attr(feature = "serde", serde(default = "default_leeway_secs"))]
    pub leeway_secs: u64,
    /// Require the JWT header `typ` to be `at+jwt` (RFC 9068 §2.1). Off by
    /// default because Authentik, Keycloak, Entra ID and Okta emit `JWT` or no
    /// `typ`. Turn it ON for servers that do emit `at+jwt` (Authelia, Kanidm): it
    /// is the check that stops an ID token minted for the same client from being
    /// replayed as an access token. With it off, `at+jwt`, `JWT` and no `typ` pass
    /// and any other type (`dpop+jwt`, `logout+jwt`...) is still refused.
    ///
    /// Off is a deliberate, configurable departure from RFC 9068 §4, under
    /// which a resource server MUST reject any `typ` other than `at+jwt` or
    /// `application/at+jwt`; RFC 8725 §3.11 recommends the same explicit
    /// typing. With it off, a required scope is what keeps ID tokens out.
    #[cfg_attr(feature = "serde", serde(default))]
    pub require_at_jwt: bool,
    /// Accept a configuration with no required scope and `require_at_jwt`
    /// off. Default false: [`OAuthConfig::resolve`] refuses that combination,
    /// because nothing in it tells an access token from an OIDC ID token
    /// minted for the same client (RFC 8725 §3.11–3.12), and on servers that
    /// stamp the client_id as `aud` (Authentik, Kanidm) the ID token a front
    /// end got at login would then be a working API credential. Set it only
    /// when "signed by this issuer for this audience" really is all the
    /// application needs; the validator still logs a `warn` at startup.
    #[cfg_attr(feature = "serde", serde(default))]
    pub allow_unscoped_tokens: bool,
    /// Accept a plain-`http` `issuer`, `jwks_uri` or `resource` on a
    /// non-loopback host. Default false: [`OAuthConfig::resolve`] refuses one,
    /// because signing keys fetched over cleartext can be substituted by anyone
    /// on the path (RFC 8414 §2 requires `https` for the issuer and its
    /// `jwks_uri`), and bearer tokens sent to a cleartext resource can be read
    /// in transit (RFC 9728 §1.2, RFC 6750 §5.3). Loopback hosts (`127.0.0.0/8`,
    /// `::1`, `localhost`) are always allowed, for tests and local development.
    ///
    /// The same rule holds at run time for URLs the configuration does not
    /// name: a `jwks_uri` discovered from a (plain-`http`) issuer's metadata,
    /// and every redirect a metadata or JWKS fetch follows, may reach plain
    /// `http` on a non-loopback host only with this set. An `https` issuer
    /// never hands out an `http` `jwks_uri`, and a redirect from `https` to
    /// `http` is never followed, whatever this says.
    ///
    /// Set it for an in-cluster address on a private network (an
    /// `http://idp:9000/...` `jwks_uri`, say) where the path itself is trusted;
    /// the validator still logs a `warn` for each such URL at startup, and for
    /// each such discovered URL or redirect when it is used.
    #[cfg_attr(feature = "serde", serde(default))]
    pub allow_insecure_http: bool,
    /// Whether a static token (an API key the application configures
    /// separately) is still accepted while OAuth is on. Default true: both
    /// credentials work side by side. Set false to run OAuth-only even if a
    /// static token is configured (it is then ignored). Read by
    /// [`crate::static_token_policy`]; the validator itself never looks at it.
    #[cfg_attr(feature = "serde", serde(default = "default_true"))]
    pub accept_static_bearer: bool,
    /// The OAuth clients whose tokens are accepted. A token's client is its
    /// `client_id` claim (RFC 9068 §2.2), else its `azp` — the first that is a
    /// non-empty string, exactly as [`crate::AuthorizedToken::client_id`]
    /// reads it — and it must equal one entry, byte for byte. A token naming
    /// no client, or another one, is refused (401,
    /// [`crate::InvalidTokenKind::ClientNotAllowed`]). `client_id` wins when
    /// both are present: a token whose `client_id` is not listed is refused
    /// even if its `azp` is, and a `client_id` that is present but empty or
    /// not a string is refused too, never read past to `azp` (stricter than
    /// the `AuthorizedToken::client_id` accessor, which skips it).
    ///
    /// Empty (the default) checks nothing. Use it where the audience is
    /// shared: an authorization server that stamps an API identifier as `aud`
    /// (Auth0, Okta custom authorization servers, Entra ID app ID URIs) gives
    /// every client of that API a token this resource server would otherwise
    /// accept. Entries must not be blank.
    ///
    /// # Examples
    ///
    /// ```
    /// # use oauth_resource_server::{KeyNaming, OAuthConfig};
    /// let base = OAuthConfig {
    ///     enabled: true,
    ///     issuer: "https://auth.example.com/".into(),
    ///     audience: "https://api.example.com/".into(),
    ///     resource: "https://api.example.com/".into(),
    ///     required_scope: Some("api:read".into()),
    ///     ..OAuthConfig::default()
    /// };
    /// let resolved = OAuthConfig {
    ///     allowed_client_ids: vec!["web-app".into(), "cli".into()],
    ///     ..base
    /// }
    /// .resolve(KeyNaming::Dotted("oauth"))
    /// .unwrap()
    /// .unwrap();
    /// assert_eq!(resolved.allowed_client_ids, ["web-app", "cli"]);
    /// ```
    #[cfg_attr(feature = "serde", serde(default))]
    pub allowed_client_ids: Vec<String>,
    /// Refuse a token issued more than this many seconds ago: `now - iat`
    /// must not exceed it, with [`OAuthConfig::leeway_secs`] of slack. With it
    /// set, a token must carry `iat` as a NumericDate (a missing one is
    /// [`crate::InvalidTokenKind::MissingClaim`], a malformed one
    /// [`MalformedClaim`](crate::InvalidTokenKind::MalformedClaim)), and an
    /// `iat` later than now plus the leeway is refused as
    /// [`NotYetValid`](crate::InvalidTokenKind::NotYetValid); too old is
    /// [`TokenTooOld`](crate::InvalidTokenKind::TokenTooOld). All 401.
    ///
    /// `None` (the default) checks nothing, and `iat` stays optional. Bounds a
    /// token's usable age independently of the `exp` the authorization server
    /// chose — useful when it issues long-lived tokens. `1..=`
    /// [`MAX_TOKEN_AGE_SECS`] (30 days); `0` is refused.
    ///
    /// # Examples
    ///
    /// ```
    /// # use oauth_resource_server::{KeyNaming, OAuthConfig};
    /// let base = OAuthConfig {
    ///     enabled: true,
    ///     issuer: "https://auth.example.com/".into(),
    ///     audience: "https://api.example.com/".into(),
    ///     resource: "https://api.example.com/".into(),
    ///     required_scope: Some("api:read".into()),
    ///     ..OAuthConfig::default()
    /// };
    /// // Refuse tokens issued more than an hour ago (plus the leeway).
    /// let one_hour = OAuthConfig { max_token_age_secs: Some(3600), ..base.clone() };
    /// assert!(one_hour.resolve(KeyNaming::Dotted("oauth")).is_ok());
    ///
    /// let zero = OAuthConfig { max_token_age_secs: Some(0), ..base };
    /// let err = zero.resolve(KeyNaming::Dotted("oauth")).unwrap_err();
    /// assert!(err.problems[0].contains("oauth.max_token_age_secs"));
    /// ```
    // Serialized even when `None`, so a consumer that derives its settings
    // from the serialized defaults sees every setting.
    #[cfg_attr(feature = "serde", serde(default))]
    pub max_token_age_secs: Option<u64>,
    /// Claims every token must carry with a given value, e.g. a tenant
    /// (`{"tid": "<tenant id>"}`) or a group (`{"groups": "api-users"}`).
    /// Each entry is checked against the verified claim of that name:
    ///
    /// - absent from the token: refused
    ///   ([`MissingClaim`](crate::InvalidTokenKind::MissingClaim));
    /// - equal to the value (JSON equality: type and value, so `"1"` is not
    ///   `1`, and an integer `1` is not the float `1.0`): passes;
    /// - an array containing an element equal to the value: passes
    ///   (membership, for `groups`, `roles` and the like);
    /// - anything else — a different value, `null`, an object, an array
    ///   without the value: refused
    ///   ([`ClaimMismatch`](crate::InvalidTokenKind::ClaimMismatch)).
    ///
    /// Every entry must pass. The value must be a string, number or boolean
    /// (`null`, an array or an object is refused by
    /// [`OAuthConfig::resolve`]); only top-level claims are matched, never a
    /// path into a nested object. The name must not be blank, nor one of the
    /// claims this crate already checks (`iss`, `aud`, `exp`, `nbf`, `iat`,
    /// `cnf`). Empty (the default) checks nothing. All refusals are 401.
    ///
    /// Naming a scope claim (`scope`, `scp`, or any `scope_claims` entry), or
    /// `azp`/`client_id`, is accepted but logged as a `warn` when the validator
    /// is built: a scope string is compared as one whole value (use
    /// `required_scopes`), and one client claim sidesteps
    /// [`allowed_client_ids`](Self::allowed_client_ids)' precedence. An array
    /// value is refused today; "any of these values" may be given that meaning
    /// later, as an additive change.
    ///
    /// # Examples
    ///
    /// ```
    /// use serde_json::json;
    /// # use oauth_resource_server::{KeyNaming, OAuthConfig};
    /// let base = OAuthConfig {
    ///     enabled: true,
    ///     issuer: "https://auth.example.com/".into(),
    ///     audience: "https://api.example.com/".into(),
    ///     resource: "https://api.example.com/".into(),
    ///     required_scope: Some("api:read".into()),
    ///     ..OAuthConfig::default()
    /// };
    /// // One tenant, and membership of one group (`groups` is an array claim).
    /// let config = OAuthConfig {
    ///     required_claims: [
    ///         ("tid".to_string(), json!("00000000-0000-0000-0000-000000000000")),
    ///         ("groups".to_string(), json!("api-users")),
    ///     ]
    ///     .into_iter()
    ///     .collect(),
    ///     ..base.clone()
    /// };
    /// assert!(config.resolve(KeyNaming::Dotted("oauth")).is_ok());
    ///
    /// // A claim this crate already checks, or a non-scalar value, is refused.
    /// let err = OAuthConfig {
    ///     required_claims: [("aud".to_string(), json!("x")), ("org".to_string(), json!({}))]
    ///         .into_iter()
    ///         .collect(),
    ///     ..base
    /// }
    /// .resolve(KeyNaming::Dotted("oauth"))
    /// .unwrap_err();
    /// assert_eq!(err.problems.len(), 2);
    /// ```
    #[cfg_attr(feature = "serde", serde(default))]
    pub required_claims: BTreeMap<String, Value>,
}

impl Default for OAuthConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            issuer: String::new(),
            jwks_uri: None,
            audience: String::new(),
            audiences: Vec::new(),
            resource: String::new(),
            required_scope: None,
            required_scopes: Vec::new(),
            scopes_supported: None,
            scope_claims: default_scope_claims(),
            principal_claims: default_principal_claims(),
            algorithms: default_algorithms(),
            leeway_secs: default_leeway_secs(),
            require_at_jwt: false,
            allow_unscoped_tokens: false,
            allow_insecure_http: false,
            accept_static_bearer: true,
            allowed_client_ids: Vec::new(),
            max_token_age_secs: None,
            required_claims: BTreeMap::new(),
        }
    }
}

fn strings(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

fn default_scope_claims() -> Vec<String> {
    strings(DEFAULT_SCOPE_CLAIMS)
}

fn default_principal_claims() -> Vec<String> {
    strings(DEFAULT_PRINCIPAL_CLAIMS)
}

fn default_algorithms() -> Vec<String> {
    strings(DEFAULT_ALGORITHMS)
}

fn default_leeway_secs() -> u64 {
    DEFAULT_LEEWAY_SECS
}

#[cfg(feature = "serde")]
fn default_true() -> bool {
    true
}

impl OAuthConfig {
    /// Validate and resolve: `Ok(None)` when disabled, `Ok(Some(..))` when
    /// enabled and usable, `Err` naming every problem it can find at once when
    /// enabled and not. `naming` decides how the problems (and, later, the
    /// validator's log lines) name each setting.
    ///
    /// Does no I/O: whether the issuer is reachable and publishes usable keys
    /// is found out later, by the validator.
    ///
    /// # Errors
    ///
    /// A [`ConfigError`] listing every problem in an enabled config: a blank
    /// `issuer` or `resource`, no audience in either `audience` or `audiences`,
    /// a URL (`issuer`, `resource` or `jwks_uri`) that is not absolute
    /// `http`/`https`, has surrounding whitespace or contains a space, control
    /// or non-ASCII character (or, for `issuer` and `resource`, that has a
    /// query or a fragment), a plain-`http` URL on a non-loopback host —
    /// decided on the URL as parsed, however it is spelled — without
    /// [`OAuthConfig::allow_insecure_http`], a blank or multi-word required
    /// scope, a required or supported scope that is not an RFC 6749 §3.3
    /// scope-token, no required scope with neither `require_at_jwt` nor
    /// [`OAuthConfig::allow_unscoped_tokens`] set, an empty `scope_claims`, a
    /// blank entry in a list, an algorithm that is HMAC, `none` or unknown, an
    /// empty algorithm list, a `leeway_secs` over [`MAX_LEEWAY_SECS`], a blank
    /// `allowed_client_ids` entry, a `max_token_age_secs` of `0` or over
    /// [`MAX_TOKEN_AGE_SECS`], or a `required_claims` entry with a blank or
    /// reserved name or a value that is not a string, number or boolean.
    ///
    /// # Examples
    ///
    /// ```
    /// use oauth_resource_server::{KeyNaming, OAuthConfig};
    ///
    /// let config = OAuthConfig {
    ///     enabled: true,
    ///     issuer: "https://auth.example.com/".into(),
    ///     audience: "example-api".into(),
    ///     resource: "https://api.example.com".into(),
    ///     required_scope: Some("api:read".into()),
    ///     scopes_supported: Some(vec!["api:read".into()]),
    ///     ..OAuthConfig::default()
    /// };
    /// let resolved = config.resolve(KeyNaming::Dotted("oauth")).unwrap().unwrap();
    /// assert_eq!(resolved.required_scopes, ["api:read"]);
    /// assert_eq!(resolved.jwks_uri, None); // discovered from the issuer later
    ///
    /// // Disabled: nothing is checked.
    /// assert_eq!(OAuthConfig::default().resolve(KeyNaming::Dotted("oauth")), Ok(None));
    ///
    /// // Broken: every problem at once, each named the way the operator wrote it.
    /// let err = OAuthConfig {
    ///     enabled: true,
    ///     required_scope: Some("api:read".into()),
    ///     leeway_secs: 3600,
    ///     ..OAuthConfig::default()
    /// }
    /// .resolve(KeyNaming::Env("MYAPP_OAUTH_"))
    /// .unwrap_err();
    /// assert_eq!(err.problems.len(), 2);
    /// assert!(err.problems[0].contains("MYAPP_OAUTH_ISSUER"));
    /// assert!(err.problems[1].contains("MYAPP_OAUTH_LEEWAY_SECS"));
    /// ```
    pub fn resolve(
        self,
        naming: KeyNaming<'_>,
    ) -> Result<Option<ResolvedOAuthConfig>, ConfigError> {
        if !self.enabled {
            return Ok(None);
        }
        let key = |field: &str| naming.key(field);
        let mut problems: Vec<ConfigProblem> = Vec::new();

        let mut blank_fields: Vec<&str> = Vec::new();
        for (name, value) in [("issuer", &self.issuer), ("resource", &self.resource)] {
            if value.trim().is_empty() {
                blank_fields.push(name);
            }
        }
        if self.audience.trim().is_empty() && self.audiences.is_empty() {
            blank_fields.push("audience");
        }
        if !blank_fields.is_empty() {
            // `audience` and `audiences` are one requirement: named together.
            let blank: Vec<String> = blank_fields
                .iter()
                .map(|&f| match f {
                    "audience" => format!("{} (or {})", key("audience"), key("audiences")),
                    _ => key(f),
                })
                .collect();
            let blank_keys: Vec<String> = blank_fields
                .iter()
                .flat_map(|&f| match f {
                    "audience" => vec![key("audience"), key("audiences")],
                    _ => vec![key(f)],
                })
                .collect();
            problems.push(ConfigProblem::new(
                ProblemKind::MissingRequired,
                blank_keys,
                format!(
                    "these required settings are empty: {}. Set issuer to the authorization \
                     server's issuer (byte-exact, including any trailing slash), resource to \
                     this server's public URL, and audience to what that server puts in \
                     an access token's `aud` — the resource URL if it honours RFC 8707 or \
                     lets you configure an audience (e.g. Authelia), or the OAuth client_id \
                     if it stamps that (e.g. Authentik, Kanidm)",
                    blank.join(", ")
                ),
            ));
        }

        let urls = [
            ("issuer", Some(&self.issuer), true),
            ("resource", Some(&self.resource), true),
            ("jwks_uri", self.jwks_uri.as_ref(), false),
        ];
        for (name, value, identifier) in urls {
            let Some(value) = value.filter(|v| !v.trim().is_empty()) else {
                continue;
            };
            match check_url(&key(name), value, identifier) {
                Err(e) => {
                    problems.push(ConfigProblem::new(ProblemKind::InvalidUrl, [key(name)], e));
                }
                Ok(()) if !self.allow_insecure_http && plain_http_non_loopback(value) => {
                    problems.push(ConfigProblem::new(
                        ProblemKind::InsecureHttp,
                        [key(name), key("allow_insecure_http")],
                        format!(
                            "{} {value:?} uses plain http on a non-loopback host — {}. Use \
                             https, or set {} if this address is on a network you trust",
                            key(name),
                            if name == "resource" {
                                "bearer tokens sent to it can be read in transit (RFC 9728 \
                                 §1.2 requires https)"
                            } else {
                                "signing keys fetched over it can be substituted by anyone on \
                                 the path (RFC 8414 §2 requires https)"
                            },
                            key("allow_insecure_http")
                        ),
                    ));
                }
                Ok(()) => {}
            }
        }
        if self.audiences.iter().any(|a| a.trim().is_empty()) {
            problems.push(ConfigProblem::new(
                ProblemKind::EmptyListEntry,
                [key("audiences")],
                format!("{} contains an empty entry", key("audiences")),
            ));
        }

        if let Some(required_scope) = &self.required_scope {
            let k = key("required_scope");
            if required_scope.trim().is_empty() {
                problems.push(ConfigProblem::new(
                    ProblemKind::BlankRequiredScope,
                    [k.clone()],
                    format!(
                        "{k} must not be empty — a blank required scope would let any signed \
                         token through unscoped. Use a scope your authorization server \
                         actually issues"
                    ),
                ));
            } else if required_scope.split_whitespace().count() != 1 {
                problems.push(ConfigProblem::new(
                    ProblemKind::MultiWordScope,
                    [k.clone()],
                    format!(
                        "{k} {required_scope:?} must be a single scope (no spaces) — scopes \
                         are matched one token at a time"
                    ),
                ));
            } else if !is_scope_token(required_scope.trim()) {
                problems.push(ConfigProblem::new(
                    ProblemKind::InvalidScopeToken,
                    [k.clone()],
                    scope_token_problem(&k, required_scope),
                ));
            }
        }
        for scope in &self.required_scopes {
            let k = key("required_scopes");
            if scope.trim().is_empty() {
                problems.push(ConfigProblem::new(
                    ProblemKind::BlankRequiredScope,
                    [k.clone()],
                    format!(
                        "{k} contains an empty entry — a blank required scope would let a \
                         token through without it. Remove the entry or name a scope your \
                         authorization server actually issues"
                    ),
                ));
            } else if scope.split_whitespace().count() != 1 {
                problems.push(ConfigProblem::new(
                    ProblemKind::MultiWordScope,
                    [k.clone()],
                    format!(
                        "{k} entry {scope:?} must be a single scope (no spaces) — scopes are \
                         matched one token at a time; list each one as its own entry"
                    ),
                ));
            } else if !is_scope_token(scope.trim()) {
                problems.push(ConfigProblem::new(
                    ProblemKind::InvalidScopeToken,
                    [k.clone()],
                    scope_token_problem(&format!("{k} entry"), scope),
                ));
            }
        }
        if let Some(supported) = &self.scopes_supported {
            let k = key("scopes_supported");
            if supported.iter().any(|s| s.trim().is_empty()) {
                problems.push(ConfigProblem::new(
                    ProblemKind::EmptyListEntry,
                    [k.clone()],
                    format!("{k} contains an empty entry"),
                ));
            }
            for scope in supported.iter().filter(|s| !s.trim().is_empty()) {
                if !is_scope_token(scope.trim()) {
                    problems.push(ConfigProblem::new(
                        ProblemKind::InvalidScopeToken,
                        [k.clone()],
                        scope_token_problem(&format!("{k} entry"), scope),
                    ));
                }
            }
        }
        if self.required_scope.is_none()
            && self.required_scopes.is_empty()
            && !self.require_at_jwt
            && !self.allow_unscoped_tokens
        {
            problems.push(ConfigProblem::new(
                ProblemKind::NoRequiredScope,
                [
                    key("required_scope"),
                    key("required_scopes"),
                    key("require_at_jwt"),
                    key("allow_unscoped_tokens"),
                ],
                format!(
                    "no required scope is configured ({} and {} are unset) and {} is off — \
                     nothing would tell an access token from an OIDC ID token minted for the \
                     same client, so any token this issuer signs for the audience would be \
                     accepted. Set {} to a scope only access tokens carry, turn on {} if the \
                     authorization server emits typ at+jwt, or set {} to accept that",
                    key("required_scope"),
                    key("required_scopes"),
                    key("require_at_jwt"),
                    key("required_scope"),
                    key("require_at_jwt"),
                    key("allow_unscoped_tokens")
                ),
            ));
        }
        if self.scope_claims.is_empty() || self.scope_claims.iter().any(|c| c.trim().is_empty()) {
            problems.push(ConfigProblem::new(
                ProblemKind::EmptyScopeClaims,
                [key("scope_claims")],
                format!(
                    "{} must list at least one non-empty claim name (default: [\"scope\", \
                     \"scp\"])",
                    key("scope_claims")
                ),
            ));
        }
        if self.principal_claims.iter().any(|c| c.trim().is_empty()) {
            problems.push(ConfigProblem::new(
                ProblemKind::EmptyListEntry,
                [key("principal_claims")],
                format!("{} contains an empty entry", key("principal_claims")),
            ));
        }

        let mut algorithms = Vec::new();
        let mut bad_algorithms = Vec::new();
        for name in &self.algorithms {
            match parse_algorithm(name) {
                Ok(alg) if !algorithms.contains(&alg) => algorithms.push(alg),
                Ok(_) => {}
                Err(reason) => bad_algorithms.push(reason.to_string()),
            }
        }
        if !bad_algorithms.is_empty() {
            problems.push(ConfigProblem::new(
                ProblemKind::BadAlgorithm,
                [key("algorithms")],
                format!(
                    "{} has unacceptable entries: {}",
                    key("algorithms"),
                    bad_algorithms.join("; ")
                ),
            ));
        } else if algorithms.is_empty() {
            problems.push(ConfigProblem::new(
                ProblemKind::NoAlgorithms,
                [key("algorithms")],
                format!("{} must list at least one algorithm", key("algorithms")),
            ));
        }

        if self.leeway_secs > MAX_LEEWAY_SECS {
            problems.push(ConfigProblem::new(
                ProblemKind::LeewayTooLarge,
                [key("leeway_secs")],
                format!(
                    "{} {} is over the {}-second cap — leeway is for clock drift, not for \
                     extending token lifetimes",
                    key("leeway_secs"),
                    self.leeway_secs,
                    MAX_LEEWAY_SECS
                ),
            ));
        }

        if self.allowed_client_ids.iter().any(|c| c.trim().is_empty()) {
            problems.push(ConfigProblem::new(
                ProblemKind::EmptyListEntry,
                [key("allowed_client_ids")],
                format!(
                    "{} contains an empty entry — list the OAuth client IDs whose tokens \
                     are accepted",
                    key("allowed_client_ids")
                ),
            ));
        }
        if let Some(age) = self.max_token_age_secs
            && !(1..=MAX_TOKEN_AGE_SECS).contains(&age)
        {
            problems.push(ConfigProblem::new(
                ProblemKind::TokenAgeOutOfRange,
                [key("max_token_age_secs")],
                format!(
                    "{} {age} is outside 1..={MAX_TOKEN_AGE_SECS} seconds (30 days) — leave it \
                     unset to not bound token age",
                    key("max_token_age_secs")
                ),
            ));
        }
        for (name, value) in &self.required_claims {
            let k = key("required_claims");
            let why = if name.trim().is_empty() {
                Some("has an entry with a blank claim name".to_string())
            } else if RESERVED_REQUIRED_CLAIMS.contains(&name.as_str()) {
                Some(format!(
                    "names {name:?}, which this crate already checks (iss, aud, exp, nbf, iat, \
                     cnf) — use issuer/audience, leeway_secs or max_token_age_secs instead"
                ))
            } else if !matches!(value, Value::String(_) | Value::Number(_) | Value::Bool(_)) {
                Some(format!(
                    "entry {name:?} requires {value}, but a required value must be a string, \
                     number or boolean (a token's array claim passes when it contains it)"
                ))
            } else {
                None
            };
            if let Some(why) = why {
                problems.push(ConfigProblem::new(
                    ProblemKind::InvalidRequiredClaim,
                    [k.clone()],
                    format!("{k} {why}"),
                ));
            }
        }

        if !problems.is_empty() {
            return Err(ConfigError::from_problems(naming, problems));
        }

        // `required_scope` first, then `required_scopes` in order, trimmed and
        // deduplicated — a stable order keeps the 403 challenge's `scope` value
        // the same from one start to the next.
        let mut required_scopes: Vec<String> = Vec::new();
        for scope in self
            .required_scope
            .iter()
            .chain(self.required_scopes.iter())
        {
            let scope = scope.trim();
            if !required_scopes.iter().any(|s| s == scope) {
                required_scopes.push(scope.to_string());
            }
        }

        // An omitted `scopes_supported` advertises what is required, so a client
        // that asks for exactly the advertised scopes gets a token that passes.
        let scopes_supported = match self.scopes_supported {
            Some(listed) => listed.iter().map(|s| s.trim().to_string()).collect(),
            None => required_scopes.clone(),
        };

        Ok(Some(ResolvedOAuthConfig {
            issuer: self.issuer,
            jwks_uri: self.jwks_uri.filter(|u| !u.trim().is_empty()),
            audience: self.audience,
            audiences: self.audiences,
            resource: self.resource,
            required_scopes,
            scopes_supported,
            scope_claims: self.scope_claims,
            principal_claims: self.principal_claims,
            algorithms,
            leeway_secs: self.leeway_secs,
            require_at_jwt: self.require_at_jwt,
            allow_unscoped_tokens: self.allow_unscoped_tokens,
            allow_insecure_http: self.allow_insecure_http,
            accept_static_bearer: self.accept_static_bearer,
            allowed_client_ids: self.allowed_client_ids,
            max_token_age_secs: self.max_token_age_secs,
            required_claims: self.required_claims,
            resource_name: None,
            key_naming: naming.to_buf(),
        }))
    }
}

/// Check that a URL setting is an absolute http(s) URL, and (for the two
/// identifiers, `issuer` and `resource`) that it carries no fragment or query:
/// RFC 8414 §2 forbids both in an issuer, RFC 8707 §2 a fragment in a resource,
/// and either one in an identifier that is compared byte-for-byte is a typo
/// waiting to reject every token.
///
/// It also refuses a space, a control character or a non-ASCII character
/// anywhere in the value. The URL parser would silently drop an embedded tab or
/// newline and percent-encode the rest, but the RAW string is what is stored,
/// compared and echoed into every `WWW-Authenticate` challenge — where such a
/// character makes the header invalid, and the 401 would go out without one.
///
/// A spelling the parser repairs (`https:/host`, `http:\\host`) is accepted
/// here; `OAuthValidator::build` warns about it (`non_canonical_url`), and the
/// plain-http check in `resolve` decides on the parsed URL, so no spelling
/// avoids it.
fn check_url(key: &str, value: &str, identifier: bool) -> Result<(), String> {
    let parsed = reqwest::Url::parse(value.trim())
        .map_err(|e| format!("{key} {value:?} is not an absolute URL ({e})"))?;
    if !matches!(parsed.scheme(), "https" | "http") {
        return Err(format!("{key} {value:?} must be an http(s) URL"));
    }
    if identifier && (parsed.fragment().is_some() || parsed.query().is_some()) {
        return Err(format!(
            "{key} {value:?} must not contain a query or fragment"
        ));
    }
    if value != value.trim() {
        return Err(format!(
            "{key} {value:?} has leading/trailing whitespace — it is compared byte-for-byte"
        ));
    }
    if value.chars().any(|c| !c.is_ascii_graphic()) {
        return Err(format!(
            "{key} {value:?} contains a space, a control character or a non-ASCII \
             character — write it percent-encoded (and an internationalized host in its \
             punycode form)"
        ));
    }
    Ok(())
}

/// RFC 6749 §3.3 `scope-token = 1*( %x21 / %x23-5B / %x5D-7E )`: printable
/// ASCII other than space, `"` and `\`. RFC 6750 §3 holds the `scope` attribute
/// of a challenge to the same set, and RFC 9728 §2 `scopes_supported` to the
/// same values.
pub(crate) fn is_scope_token(scope: &str) -> bool {
    !scope.is_empty()
        && scope
            .bytes()
            .all(|b| b == 0x21 || (0x23..=0x5B).contains(&b) || (0x5D..=0x7E).contains(&b))
}

fn scope_token_problem(what: &str, scope: &str) -> String {
    format!(
        "{what} {scope:?} is not a valid scope — a scope is printable ASCII with no space, \
         '\"' or '\\' (RFC 6749 §3.3)"
    )
}

/// The validated config an [`crate::OAuthValidator`] is built from.
///
/// Only [`OAuthConfig::resolve`] produces one with every invariant checked, so
/// holding a `ResolvedOAuthConfig` (rather than an `Option` of one) IS the answer
/// to "is OAuth on and usable" — nothing downstream re-checks a boolean. Fields
/// are public so tests and applications can adjust a resolved value (the
/// validator re-checks the invariants whose violation it could not survive: a
/// non-empty audience set, a non-empty algorithm list, and `leeway_secs` within
/// [`MAX_LEEWAY_SECS`]).
///
/// `#[non_exhaustive]`: outside this crate one comes from
/// [`OAuthConfig::resolve`] (or, in tests, `testing::resolved_config`) and is
/// then adjusted field by field, never built with a struct literal — which is
/// what lets a new resolved setting be added without a breaking change.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ResolvedOAuthConfig {
    /// See [`OAuthConfig::issuer`]; byte-exact.
    pub issuer: String,
    /// `None` means "discover from the issuer's metadata". Never blank.
    pub jwks_uri: Option<String>,
    /// The single audience; may be empty when `audiences` is not. Use
    /// [`ResolvedOAuthConfig::accepted_audiences`] for the effective set.
    pub audience: String,
    /// See [`OAuthConfig::audiences`].
    pub audiences: Vec<String>,
    /// See [`OAuthConfig::resource`].
    pub resource: String,
    /// `required_scope` ∪ `required_scopes`: trimmed, deduplicated, in config
    /// order (`required_scope` first). A token must carry every one; empty means
    /// no scope check at all.
    pub required_scopes: Vec<String>,
    /// See [`OAuthConfig::scopes_supported`]; `None` there resolves to
    /// `required_scopes`. Advertised in the metadata document (omitted from it
    /// when empty) and in the 401 challenge.
    pub scopes_supported: Vec<String>,
    /// See [`OAuthConfig::scope_claims`].
    pub scope_claims: Vec<String>,
    /// See [`OAuthConfig::principal_claims`].
    pub principal_claims: Vec<String>,
    /// Parsed and deduplicated. [`Algorithm`] has no HMAC or `none` variant,
    /// so this can never hold one.
    pub algorithms: Vec<Algorithm>,
    /// See [`OAuthConfig::leeway_secs`].
    pub leeway_secs: u64,
    /// See [`OAuthConfig::require_at_jwt`].
    pub require_at_jwt: bool,
    /// See [`OAuthConfig::allow_unscoped_tokens`]. Informational once
    /// resolved: `resolve` has already applied it.
    pub allow_unscoped_tokens: bool,
    /// See [`OAuthConfig::allow_insecure_http`]. `resolve` has already applied
    /// it to the configured URLs; the validator still reads it, for a
    /// discovered `jwks_uri` and for redirects followed while fetching keys.
    pub allow_insecure_http: bool,
    /// See [`OAuthConfig::accept_static_bearer`].
    pub accept_static_bearer: bool,
    /// See [`OAuthConfig::allowed_client_ids`]; empty means no client check.
    pub allowed_client_ids: Vec<String>,
    /// See [`OAuthConfig::max_token_age_secs`]; `None` means no age check.
    pub max_token_age_secs: Option<u64>,
    /// See [`OAuthConfig::required_claims`]; empty means no claim check.
    pub required_claims: BTreeMap<String, Value>,
    /// Human-readable name published as `resource_name` in the RFC 9728
    /// metadata document; omitted from it when `None`. Not a config key:
    /// [`OAuthConfig::resolve`] leaves it `None`, and an application that wants
    /// one sets it on the resolved value (it names the application, which the
    /// operator has no reason to change).
    pub resource_name: Option<String>,
    /// How the validator's log lines and errors name settings; what `resolve`
    /// was given.
    pub key_naming: KeyNamingBuf,
}

impl ResolvedOAuthConfig {
    /// `audience` ∪ `audiences`, blanks dropped, in config order.
    pub fn accepted_audiences(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for a in std::iter::once(&self.audience).chain(self.audiences.iter()) {
            if !a.trim().is_empty() && !out.contains(a) {
                out.push(a.clone());
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WIKI: KeyNaming<'static> = KeyNaming::Dotted("mcp.oauth");

    /// An enabled block with every required key set, for the rejection tests to
    /// break one key at a time. It opts into an unscoped configuration, so a
    /// test that sets no scope is not also refused for that; the unscoped
    /// refusal has tests of its own.
    fn enabled(edit: impl FnOnce(&mut OAuthConfig)) -> OAuthConfig {
        let mut cfg = OAuthConfig {
            enabled: true,
            issuer: "https://idp.example.test/".into(),
            resource: "https://kb.example.test/mcp".into(),
            audience: "c".into(),
            allow_unscoped_tokens: true,
            ..OAuthConfig::default()
        };
        edit(&mut cfg);
        cfg
    }

    fn resolve_err(cfg: OAuthConfig) -> String {
        cfg.resolve(WIKI).unwrap_err().to_string()
    }

    // ── defaults ─────────────────────────────────────────────────────────────

    #[test]
    fn oauth_is_disabled_by_default_and_has_no_default_scope() {
        let cfg = OAuthConfig::default();
        assert!(!cfg.enabled);
        // The crate is not MCP-specific: no required scope and no advertised
        // scopes unless the application or operator names them.
        assert_eq!(cfg.required_scope, None);
        assert!(cfg.required_scopes.is_empty());
        assert_eq!(cfg.scopes_supported, None);
        assert_eq!(cfg.jwks_uri, None);
        assert_eq!(cfg.scope_claims, ["scope", "scp"]);
        assert_eq!(cfg.principal_claims, ["preferred_username", "sub"]);
        assert_eq!(cfg.algorithms, DEFAULT_ALGORITHMS);
        assert_eq!(cfg.leeway_secs, 60);
        assert!(!cfg.require_at_jwt);
        assert!(!cfg.allow_unscoped_tokens);
        assert!(!cfg.allow_insecure_http);
        assert!(cfg.accept_static_bearer);
    }

    #[test]
    fn disabled_resolves_to_none() {
        assert_eq!(OAuthConfig::default().resolve(WIKI), Ok(None));
        // Even a broken disabled block: nothing is checked.
        let cfg = OAuthConfig {
            algorithms: vec!["HS256".into()],
            ..OAuthConfig::default()
        };
        assert_eq!(cfg.resolve(WIKI), Ok(None));
    }

    #[test]
    fn a_minimal_enabled_block_resolves_with_every_default() {
        let cfg = OAuthConfig {
            enabled: true,
            issuer: "https://authentik.example.test/application/o/example-app/".into(),
            jwks_uri: Some("https://authentik.example.test/application/o/example-app/jwks/".into()),
            audience: "some-client-id".into(),
            resource: "https://kb.example.test/mcp".into(),
            required_scope: Some("api:read".into()),
            ..OAuthConfig::default()
        };
        let oauth = cfg.resolve(WIKI).unwrap().expect("enabled");
        // The trailing slash must survive verbatim: it is compared byte-exactly
        // against the `iss` claim, and Authentik's issuer has one.
        assert_eq!(
            oauth.issuer,
            "https://authentik.example.test/application/o/example-app/"
        );
        assert_eq!(oauth.audience, "some-client-id");
        assert_eq!(oauth.resource, "https://kb.example.test/mcp");
        assert_eq!(oauth.required_scopes, ["api:read"]);
        // An omitted `scopes_supported` advertises the required scopes.
        assert_eq!(oauth.scopes_supported, ["api:read"]);
        assert_eq!(oauth.accepted_audiences(), ["some-client-id"]);
        assert_eq!(oauth.scope_claims, ["scope", "scp"]);
        assert_eq!(oauth.principal_claims, ["preferred_username", "sub"]);
        assert!(oauth.algorithms.contains(&Algorithm::RS256));
        assert_eq!(oauth.leeway_secs, 60);
        assert!(!oauth.require_at_jwt);
        assert!(!oauth.allow_unscoped_tokens);
        assert!(!oauth.allow_insecure_http);
        assert!(oauth.accept_static_bearer);
        assert_eq!(oauth.resource_name, None);
        assert_eq!(oauth.key_naming, KeyNamingBuf::Dotted("mcp.oauth".into()));
    }

    // ── rejection: every problem at once, each naming its key ────────────────

    #[test]
    fn enabled_with_blank_required_settings_is_rejected_naming_all_of_them() {
        let cfg = OAuthConfig {
            enabled: true,
            ..OAuthConfig::default()
        };
        let err = resolve_err(cfg);
        for setting in [
            "mcp.oauth.issuer",
            "mcp.oauth.audience",
            "mcp.oauth.resource",
        ] {
            assert!(err.contains(setting), "{setting} missing from: {err}");
        }
        // Optional: an absent jwks_uri means "discover it".
        assert!(!err.contains("mcp.oauth.jwks_uri"), "{err}");
    }

    /// The two phrases where mcp-md-wiki's messages are MCP-specific and this
    /// crate's are not. mcp-md-wiki#308: mcp-md-wiki keeps its historical text
    /// byte-identical by rewriting exactly these in `ConfigError::problems`
    /// before display.
    ///
    /// An early warning, not a contract. Message text is not a stable API (see
    /// the README's semver policy), and what actually guarantees mcp-md-wiki's
    /// text is its own test pinning its full output, which fails there on the
    /// dependency bump if this wording changes. This pin only makes the
    /// breakage visible here first: when a test below fails, change the text
    /// deliberately and tell mcp-md-wiki, rather than treating the phrase as
    /// frozen.
    const WIKI_REWRITES: [(&str, &str); 2] = [
        ("this server's public URL,", "this server's public MCP URL,"),
        (
            "unscoped. Use a scope your",
            "unscoped. Use \"mcp:read\" (the default) or a scope your",
        ),
    ];

    fn as_wiki_text(problem: &str) -> String {
        WIKI_REWRITES
            .iter()
            .fold(problem.to_string(), |p, (generic, wiki)| {
                p.replace(generic, wiki)
            })
    }

    #[test]
    fn config_error_display_for_dotted_naming_is_generic_and_maps_to_mcp_md_wiki_text() {
        // A required scope, as mcp-md-wiki always supplies one before resolving,
        // so the unscoped refusal does not join the one problem pinned here.
        let cfg = OAuthConfig {
            enabled: true,
            required_scope: Some("mcp:read".into()),
            ..OAuthConfig::default()
        };
        // Spelled out in full, not rebuilt from the format strings under test.
        let expected = "mcp.oauth.enabled is true but the OAuth config is not usable:\n  - \
these required settings are empty: mcp.oauth.issuer, mcp.oauth.resource, mcp.oauth.audience \
(or mcp.oauth.audiences). Set issuer to the authorization server's issuer (byte-exact, \
including any trailing slash), resource to this server's public URL, and audience to \
what that server puts in an access token's `aud` — the resource URL if it honours RFC 8707 \
or lets you configure an audience (e.g. Authelia), or the OAuth client_id if it stamps that \
(e.g. Authentik, Kanidm)\nFix these, or set mcp.oauth.enabled: false.";
        let mut err = cfg.resolve(WIKI).unwrap_err();
        assert_eq!(err.to_string(), expected);
        assert_eq!(err.problems[0].matches(WIKI_REWRITES[0].0).count(), 1);

        // The text mcp-md-wiki printed before mcp-md-wiki#308, recovered by its
        // rewrite of the generic phrase.
        let wiki_expected = "mcp.oauth.enabled is true but the OAuth config is not usable:\n  - \
these required settings are empty: mcp.oauth.issuer, mcp.oauth.resource, mcp.oauth.audience \
(or mcp.oauth.audiences). Set issuer to the authorization server's issuer (byte-exact, \
including any trailing slash), resource to this server's public MCP URL, and audience to \
what that server puts in an access token's `aud` — the resource URL if it honours RFC 8707 \
or lets you configure an audience (e.g. Authelia), or the OAuth client_id if it stamps that \
(e.g. Authentik, Kanidm)\nFix these, or set mcp.oauth.enabled: false.";
        err.problems = err.problems.iter().map(|p| as_wiki_text(p)).collect();
        assert_eq!(err.to_string(), wiki_expected);
    }

    #[test]
    fn scope_problem_messages_are_generic_and_map_to_mcp_md_wiki_text() {
        let err = enabled(|c| c.required_scope = Some(String::new()))
            .resolve(WIKI)
            .unwrap_err();
        assert_eq!(
            err.problems,
            [
                "mcp.oauth.required_scope must not be empty — a blank required scope would \
              let any signed token through unscoped. Use a scope your authorization server \
              actually issues"
            ]
        );
        assert_eq!(err.problems[0].matches(WIKI_REWRITES[1].0).count(), 1);
        // mcp-md-wiki#308: mcp-md-wiki's pre-extraction text, recovered.
        assert_eq!(
            as_wiki_text(&err.problems[0]),
            "mcp.oauth.required_scope must not be empty — a blank required scope would \
              let any signed token through unscoped. Use \"mcp:read\" (the default) or a \
              scope your authorization server actually issues"
        );
        // Nothing MCP-specific leaks into a non-MCP consumer's messages.
        let text = OAuthConfig {
            enabled: true,
            required_scope: Some(String::new()),
            ..OAuthConfig::default()
        }
        .resolve(KeyNaming::Env("APP_OAUTH_"))
        .unwrap_err()
        .to_string();
        assert!(!text.contains("MCP") && !text.contains("mcp"), "{text}");
        let err = enabled(|c| c.required_scope = Some("mcp:read mcp:write".into()))
            .resolve(WIKI)
            .unwrap_err();
        assert_eq!(
            err.problems,
            [
                "mcp.oauth.required_scope \"mcp:read mcp:write\" must be a single scope (no \
              spaces) — scopes are matched one token at a time"
            ]
        );
        let err = enabled(|c| c.leeway_secs = 3600).resolve(WIKI).unwrap_err();
        assert_eq!(
            err.to_string(),
            "mcp.oauth.enabled is true but the OAuth config is not usable:\n  - \
             mcp.oauth.leeway_secs 3600 is over the 300-second cap — leeway is for clock \
             drift, not for extending token lifetimes\nFix these, or set mcp.oauth.enabled: \
             false."
        );
    }

    #[test]
    fn env_naming_uppercases_and_appends_the_field() {
        let naming = KeyNaming::Env("MYAPP_OAUTH_");
        assert_eq!(naming.key("issuer"), "MYAPP_OAUTH_ISSUER");
        assert_eq!(naming.key("required_scopes"), "MYAPP_OAUTH_REQUIRED_SCOPES");
        assert_eq!(naming.section(), "MYAPP_OAUTH_*");
        assert_eq!(
            KeyNaming::Dotted("mcp.oauth").key("issuer"),
            "mcp.oauth.issuer"
        );
        assert_eq!(KeyNaming::Dotted("").key("issuer"), "issuer");
        assert_eq!(KeyNaming::Dotted("").section(), "OAuth config");
        assert_eq!(KeyNaming::Dotted("mcp.oauth").section(), "mcp.oauth");

        let cfg = OAuthConfig {
            enabled: true,
            required_scope: Some(String::new()),
            ..OAuthConfig::default()
        };
        let err = cfg.resolve(naming).unwrap_err();
        let text = err.to_string();
        for key in [
            "MYAPP_OAUTH_ISSUER",
            "MYAPP_OAUTH_RESOURCE",
            "MYAPP_OAUTH_AUDIENCE (or MYAPP_OAUTH_AUDIENCES)",
            "MYAPP_OAUTH_REQUIRED_SCOPE must not be empty",
        ] {
            assert!(text.contains(key), "{key} missing from: {text}");
        }
        assert!(!text.contains("mcp.oauth"), "{text}");
        assert!(
            text.starts_with(
                "OAuth is configured through MYAPP_OAUTH_* but the config is not \
                 usable:\n  - "
            ),
            "{text}"
        );
        assert!(
            text.ends_with("\nFix these, or unset every MYAPP_OAUTH_* variable."),
            "{text}"
        );
        assert_eq!(err.naming(), naming);
    }

    #[test]
    fn accepts_audiences_without_audience_and_an_omitted_or_blank_jwks_uri() {
        for jwks_uri in [None, Some(String::new()), Some("  ".to_string())] {
            let oauth = enabled(|c| {
                c.audience = String::new();
                c.audiences = vec!["https://kb.example.test/mcp".into()];
                c.jwks_uri = jwks_uri.clone();
            })
            .resolve(WIKI)
            .unwrap()
            .unwrap();
            assert_eq!(oauth.accepted_audiences(), ["https://kb.example.test/mcp"]);
            assert_eq!(oauth.jwks_uri, None, "blank means discover: {jwks_uri:?}");
        }
    }

    #[test]
    fn refuses_hmac_and_none_algorithms() {
        for alg in ["HS256", "none"] {
            let err = resolve_err(enabled(|c| {
                c.algorithms = vec!["RS256".into(), alg.into()];
            }));
            assert!(err.contains("mcp.oauth.algorithms"), "{err}");
            assert!(err.contains(alg), "{err}");
        }
        let err = resolve_err(enabled(|c| c.algorithms = vec![]));
        assert!(err.contains("at least one algorithm"), "{err}");
    }

    #[test]
    fn refuses_malformed_urls_naming_the_key() {
        for jwks_uri in ["idp.example.test/jwks", "ftp://idp.example.test/jwks"] {
            let err = resolve_err(enabled(|c| c.jwks_uri = Some(jwks_uri.into())));
            assert!(err.contains("mcp.oauth.jwks_uri"), "{err}");
        }
        let err = resolve_err(enabled(|c| {
            c.issuer = "https://idp.example.test/?x=1".into();
            c.resource = "kb.example.test/mcp".into();
        }));
        assert!(err.contains("mcp.oauth.issuer"), "{err}");
        assert!(err.contains("mcp.oauth.resource"), "{err}");
        let err = resolve_err(enabled(|c| c.issuer = " https://idp.example.test/".into()));
        assert!(err.contains("leading/trailing whitespace"), "{err}");
    }

    #[test]
    fn refuses_bad_scope_and_leeway_settings() {
        type Edit = fn(&mut OAuthConfig);
        let cases: [(Edit, &str); 5] = [
            (
                |c| c.required_scope = Some("mcp:read mcp:write".into()),
                "single scope",
            ),
            (|c| c.scope_claims = vec![], "mcp.oauth.scope_claims"),
            (
                |c| c.principal_claims = vec![String::new()],
                "mcp.oauth.principal_claims",
            ),
            (|c| c.leeway_secs = 3600, "mcp.oauth.leeway_secs"),
            (|c| c.audiences = vec![String::new()], "mcp.oauth.audiences"),
        ];
        for (edit, needle) in cases {
            let err = resolve_err(enabled(edit));
            assert!(err.contains(needle), "{needle} not in: {err}");
        }
    }

    #[test]
    fn a_blank_required_scope_is_rejected_not_treated_as_absent() {
        for blank in ["", "   "] {
            let err = resolve_err(enabled(|c| c.required_scope = Some(blank.into())));
            assert!(
                err.contains("mcp.oauth.required_scope"),
                "an empty required scope must not silently mean 'no scope': {err}"
            );
        }
    }

    #[test]
    fn every_problem_is_reported_at_once() {
        let err = enabled(|c| {
            c.issuer = String::new();
            c.required_scope = Some(String::new());
            c.required_scopes = vec!["a b".into()];
            c.leeway_secs = 9999;
            c.algorithms = vec!["HS256".into()];
        })
        .resolve(WIKI)
        .unwrap_err();
        assert_eq!(err.problems.len(), 5, "{err}");
    }

    // ── required_scopes ──────────────────────────────────────────────────────

    #[test]
    fn required_scopes_are_a_trimmed_deduplicated_order_stable_union() {
        let oauth = enabled(|c| {
            c.required_scope = Some(" a ".into());
            c.required_scopes = vec!["b".into(), "a".into(), " c".into(), "b".into()];
        })
        .resolve(WIKI)
        .unwrap()
        .unwrap();
        assert_eq!(oauth.required_scopes, ["a", "b", "c"]);

        let only_list = enabled(|c| c.required_scopes = vec!["x".into(), "y".into()])
            .resolve(WIKI)
            .unwrap()
            .unwrap();
        assert_eq!(only_list.required_scopes, ["x", "y"]);

        let only_single = enabled(|c| c.required_scope = Some("mcp:read".into()))
            .resolve(WIKI)
            .unwrap()
            .unwrap();
        assert_eq!(only_single.required_scopes, ["mcp:read"]);
    }

    #[test]
    fn an_empty_required_scope_union_is_valid_and_means_no_scope_check() {
        let oauth = enabled(|_| {}).resolve(WIKI).unwrap().unwrap();
        assert!(oauth.required_scopes.is_empty());
    }

    #[test]
    fn required_scopes_entries_follow_the_single_scope_rules() {
        let err = enabled(|c| c.required_scopes = vec!["ok".into(), "  ".into()])
            .resolve(WIKI)
            .unwrap_err();
        assert_eq!(err.problems.len(), 1, "{err}");
        assert!(
            err.problems[0].starts_with("mcp.oauth.required_scopes contains an empty entry"),
            "{err}"
        );
        let err = enabled(|c| c.required_scopes = vec!["a b".into()])
            .resolve(WIKI)
            .unwrap_err();
        assert!(
            err.problems[0]
                .starts_with("mcp.oauth.required_scopes entry \"a b\" must be a single scope"),
            "{err}"
        );
    }

    // ── serde ────────────────────────────────────────────────────────────────

    #[cfg(feature = "serde")]
    #[test]
    fn round_trips_from_yaml_with_every_default() {
        let yaml = "enabled: true
issuer: \"https://authentik.example.test/application/o/example-app/\"
jwks_uri: \"https://authentik.example.test/application/o/example-app/jwks/\"
audience: \"some-client-id\"
resource: \"https://kb.example.test/mcp\"
";
        let parsed: OAuthConfig = serde_yaml_ng::from_str(yaml).unwrap();
        assert_eq!(
            parsed,
            OAuthConfig {
                enabled: true,
                issuer: "https://authentik.example.test/application/o/example-app/".into(),
                jwks_uri: Some(
                    "https://authentik.example.test/application/o/example-app/jwks/".into()
                ),
                audience: "some-client-id".into(),
                resource: "https://kb.example.test/mcp".into(),
                ..OAuthConfig::default()
            }
        );
        let back: OAuthConfig =
            serde_yaml_ng::from_str(&serde_yaml_ng::to_string(&parsed).unwrap()).unwrap();
        assert_eq!(back, parsed);
        // An empty document is the default config.
        let empty: OAuthConfig = serde_yaml_ng::from_str("{}").unwrap();
        assert_eq!(empty, OAuthConfig::default());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_reads_both_scope_keys_and_refuses_unknown_keys() {
        let parsed: OAuthConfig =
            serde_yaml_ng::from_str("required_scope: \"a\"\nrequired_scopes: [\"b\", \"c\"]\n")
                .unwrap();
        assert_eq!(parsed.required_scope.as_deref(), Some("a"));
        assert_eq!(parsed.required_scopes, ["b", "c"]);
        // An explicit empty string is Some(""), which resolve refuses.
        let parsed: OAuthConfig = serde_yaml_ng::from_str("required_scope: \"\"\n").unwrap();
        assert_eq!(parsed.required_scope.as_deref(), Some(""));
        assert!(serde_yaml_ng::from_str::<OAuthConfig>("bogus: true\n").is_err());
        assert!(serde_yaml_ng::from_str::<OAuthConfig>("resource_name: \"x\"\n").is_err());
        let parsed: OAuthConfig =
            serde_yaml_ng::from_str("allow_unscoped_tokens: true\nallow_insecure_http: true\n")
                .unwrap();
        assert!(parsed.allow_unscoped_tokens && parsed.allow_insecure_http);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_distinguishes_an_omitted_scopes_supported_from_an_explicit_empty_list() {
        let omitted: OAuthConfig = serde_yaml_ng::from_str("enabled: true\n").unwrap();
        assert_eq!(omitted.scopes_supported, None);
        let empty: OAuthConfig = serde_yaml_ng::from_str("scopes_supported: []\n").unwrap();
        assert_eq!(empty.scopes_supported, Some(vec![]));
        let listed: OAuthConfig =
            serde_yaml_ng::from_str("scopes_supported: [\"a\", \"b\"]\n").unwrap();
        assert_eq!(listed.scopes_supported, Some(vec!["a".into(), "b".into()]));
        // Both survive a round trip: `None` is skipped on output (so it reads back
        // as omitted), and an explicit `[]` is written out.
        for cfg in [omitted, empty, listed] {
            let yaml = serde_yaml_ng::to_string(&cfg).unwrap();
            let back: OAuthConfig = serde_yaml_ng::from_str(&yaml).unwrap();
            assert_eq!(back, cfg, "{yaml}");
        }
    }

    #[test]
    fn an_omitted_scopes_supported_advertises_the_required_scopes_and_an_explicit_list_wins() {
        let with_required = |required: Option<&str>, scopes: Option<Vec<String>>| {
            enabled(|c| {
                c.required_scope = required.map(str::to_string);
                c.required_scopes = vec!["b".into(), "a".into()];
                c.scopes_supported = scopes;
            })
            .resolve(WIKI)
            .unwrap()
            .expect("enabled")
            .scopes_supported
        };
        // Omitted: the required scopes, in their resolved order.
        assert_eq!(with_required(Some("a"), None), ["a", "b"]);
        assert_eq!(with_required(None, None), ["b", "a"]);
        // An explicit list, even an empty one, is kept as written (trimmed).
        assert!(with_required(Some("a"), Some(vec![])).is_empty());
        assert_eq!(with_required(Some("a"), Some(vec![" c ".into()])), ["c"]);

        // Nothing required: an omitted list advertises nothing.
        let resolve = |scopes: Option<Vec<String>>| {
            enabled(|c| c.scopes_supported = scopes)
                .resolve(WIKI)
                .unwrap()
                .expect("enabled")
                .scopes_supported
        };
        assert!(resolve(None).is_empty());
        assert!(resolve(Some(vec![])).is_empty());
        assert_eq!(
            resolve(Some(vec!["mcp:read".into(), "mcp:write".into()])),
            ["mcp:read", "mcp:write"]
        );
        // The application-default pattern: fill an omitted key, leave an explicit
        // empty list alone.
        let app_default = |mut c: OAuthConfig| {
            c.scopes_supported
                .get_or_insert_with(|| vec!["mcp:read".into(), "mcp:write".into()]);
            c.resolve(WIKI).unwrap().expect("enabled").scopes_supported
        };
        assert_eq!(
            app_default(enabled(|c| c.scopes_supported = None)),
            ["mcp:read", "mcp:write"]
        );
        assert!(app_default(enabled(|c| c.scopes_supported = Some(vec![]))).is_empty());
    }

    // ── scope-token syntax (RFC 6749 §3.3) ───────────────────────────────────

    #[test]
    fn every_required_and_advertised_scope_must_be_a_scope_token() {
        for bad in ["a\"b", "a\\b", "caf\u{e9}", "a\u{7f}"] {
            let err = enabled(|c| c.required_scope = Some(bad.into()))
                .resolve(WIKI)
                .unwrap_err();
            assert_eq!(err.problems.len(), 1, "{err}");
            assert!(
                err.problems[0].starts_with("mcp.oauth.required_scope ")
                    && err.problems[0].contains("is not a valid scope"),
                "{err}"
            );
            let err = enabled(|c| c.required_scopes = vec!["ok".into(), bad.into()])
                .resolve(WIKI)
                .unwrap_err();
            assert!(
                err.problems[0].starts_with("mcp.oauth.required_scopes entry "),
                "{err}"
            );
            let err = enabled(|c| c.scopes_supported = Some(vec![bad.into()]))
                .resolve(WIKI)
                .unwrap_err();
            assert!(
                err.problems[0].starts_with("mcp.oauth.scopes_supported entry "),
                "{err}"
            );
        }
        // Blank and multi-word advertised entries are refused too.
        let err = enabled(|c| c.scopes_supported = Some(vec!["".into(), "two words".into()]))
            .resolve(WIKI)
            .unwrap_err();
        assert_eq!(err.problems.len(), 2, "{err}");
        assert_eq!(
            err.problems[0],
            "mcp.oauth.scopes_supported contains an empty entry"
        );
        assert!(err.problems[1].contains("\"two words\""), "{err}");
        // Every visible-ASCII scope-token character is fine, including the
        // `:`, `/`, `.` and `!` real scopes use.
        let oauth = enabled(|c| {
            c.required_scope =
                Some("https://api.example.test/things.read!#$%&'()*+,-./:;<=>?@[]^_`{|}~".into());
        })
        .resolve(WIKI)
        .unwrap()
        .unwrap();
        assert_eq!(oauth.required_scopes.len(), 1);
    }

    // ── URL characters, and plain http ───────────────────────────────────────

    #[test]
    fn a_url_with_a_space_control_or_non_ascii_character_is_refused() {
        // `url` would silently drop the tab/newline and percent-encode the rest,
        // but the raw string is what reaches every challenge header.
        for bad in [
            "https://kb.example.test/m\ncp",
            "https://kb.example.test/m\tcp",
            "https://kb.example.test/m cp",
            "https://kb.example.test/caf\u{e9}",
        ] {
            let err = resolve_err(enabled(|c| c.resource = bad.into()));
            assert!(
                err.contains("mcp.oauth.resource") && err.contains("percent-encoded"),
                "{bad:?}: {err}"
            );
            let err = resolve_err(enabled(|c| c.issuer = bad.into()));
            assert!(err.contains("mcp.oauth.issuer"), "{bad:?}: {err}");
            let err = resolve_err(enabled(|c| c.jwks_uri = Some(bad.into())));
            assert!(err.contains("mcp.oauth.jwks_uri"), "{bad:?}: {err}");
        }
        // Percent-encoded is fine, and so is a query on the jwks_uri.
        enabled(|c| {
            c.resource = "https://kb.example.test/caf%C3%A9".into();
            c.jwks_uri = Some("https://idp.example.test/keys?tenant=a".into());
        })
        .resolve(WIKI)
        .unwrap()
        .unwrap();
    }

    #[test]
    fn plain_http_off_loopback_is_refused_unless_explicitly_allowed() {
        let err = enabled(|c| {
            c.issuer = "http://idp.internal.test/app/".into();
            c.jwks_uri = Some("http://idp.internal.test/app/jwks/".into());
            c.resource = "http://kb.internal.test/mcp".into();
        })
        .resolve(WIKI)
        .unwrap_err();
        assert_eq!(err.problems.len(), 3, "{err}");
        assert!(
            err.problems[0].starts_with(
                "mcp.oauth.issuer \"http://idp.internal.test/app/\" uses plain http on a \
                 non-loopback host — signing keys"
            ),
            "{err}"
        );
        assert!(err.problems[0].contains("RFC 8414 §2"), "{err}");
        assert!(err.problems[1].starts_with("mcp.oauth.resource "), "{err}");
        assert!(err.problems[1].contains("RFC 9728 §1.2"), "{err}");
        assert!(err.problems[2].starts_with("mcp.oauth.jwks_uri "), "{err}");
        assert!(
            err.problems[2].contains("set mcp.oauth.allow_insecure_http"),
            "{err}"
        );

        // The explicit opt-in accepts all three.
        let oauth = enabled(|c| {
            c.issuer = "http://idp.internal.test/app/".into();
            c.jwks_uri = Some("http://idp.internal.test/app/jwks/".into());
            c.resource = "http://kb.internal.test/mcp".into();
            c.allow_insecure_http = true;
        })
        .resolve(WIKI)
        .unwrap()
        .unwrap();
        assert!(oauth.allow_insecure_http);

        // Loopback never needs it.
        enabled(|c| {
            c.issuer = "http://127.0.0.1:9000/app/".into();
            c.jwks_uri = Some("http://[::1]:9000/jwks".into());
            c.resource = "http://localhost:8001/mcp".into();
        })
        .resolve(WIKI)
        .unwrap()
        .unwrap();
    }

    /// Spellings of a plain-http, non-loopback URL that the URL parser
    /// normalizes to `http://idp.example.test/...` — so reqwest would fetch
    /// it over cleartext — but that do not literally begin with `http://`.
    const NON_CANONICAL_HTTP: [&str; 4] = [
        "http:/idp.example.test/jwks",
        "http:idp.example.test/jwks",
        "HTTP:\\\\idp.example.test\\jwks",
        " http://idp.example.test/jwks",
    ];

    /// `enabled()` with `name` (`issuer`, `jwks_uri` or `resource`) set to `url`.
    fn with_url(name: &str, url: &str, allow_insecure_http: bool) -> OAuthConfig {
        enabled(|c| {
            c.allow_insecure_http = allow_insecure_http;
            match name {
                "issuer" => c.issuer = url.into(),
                "jwks_uri" => c.jwks_uri = Some(url.into()),
                "resource" => c.resource = url.into(),
                other => panic!("no URL setting {other}"),
            }
        })
    }

    #[test]
    fn non_canonical_plain_http_spellings_are_refused_for_every_url_setting() {
        for spelling in NON_CANONICAL_HTTP {
            for name in ["issuer", "jwks_uri", "resource"] {
                let err = with_url(name, spelling, false)
                    .resolve(WIKI)
                    .expect_err(&format!("{name} = {spelling:?} must be refused"));
                assert_eq!(err.problems.len(), 1, "{name} = {spelling:?}: {err}");
                assert!(
                    err.problems[0].starts_with(&format!("mcp.oauth.{name} ")),
                    "{name} = {spelling:?}: {err}"
                );
                // Surrounding whitespace was always refused on its own; every
                // other spelling is refused as the cleartext URL it is.
                let expected = if spelling.starts_with(' ') {
                    ProblemKind::InvalidUrl
                } else {
                    ProblemKind::InsecureHttp
                };
                assert_eq!(
                    err.problem_details()[0].kind(),
                    expected,
                    "{name} = {spelling:?}: {err}"
                );
            }
        }
    }

    #[test]
    fn non_canonical_spellings_that_are_not_a_cleartext_hole_resolve_with_a_warning() {
        // With the opt-in, the plain-http spellings; without it, loopback and
        // https ones. Each resolves as 0.1.2 resolved it, and the validator's
        // startup warnings name the setting and give the canonical form.
        let cases: [(&str, bool, &str); 8] = [
            (
                "http:/idp.example.test/jwks",
                true,
                "http://idp.example.test/jwks",
            ),
            (
                "http:idp.example.test/jwks",
                true,
                "http://idp.example.test/jwks",
            ),
            (
                "HTTP:\\\\idp.example.test\\jwks",
                true,
                "http://idp.example.test/jwks",
            ),
            (
                "http:/localhost:9000/jwks",
                false,
                "http://localhost:9000/jwks",
            ),
            (
                "https:/idp.example.test/jwks",
                false,
                "https://idp.example.test/jwks",
            ),
            (
                "https:idp.example.test/jwks",
                false,
                "https://idp.example.test/jwks",
            ),
            (
                "https://idp.example.test\\jwks",
                false,
                "https://idp.example.test/jwks",
            ),
            (
                "https:///idp.example.test/jwks",
                false,
                "https://idp.example.test/jwks",
            ),
        ];
        for (spelling, opt_in, canonical) in cases {
            for name in ["issuer", "jwks_uri", "resource"] {
                let resolved = with_url(name, spelling, opt_in)
                    .resolve(WIKI)
                    .unwrap_or_else(|e| panic!("{name} = {spelling:?}: {e}"))
                    .unwrap();
                let warnings = crate::validator::non_canonical_warnings(&resolved);
                assert_eq!(warnings.len(), 1, "{name} = {spelling:?}: {warnings:?}");
                assert!(
                    warnings[0].starts_with(&format!(
                        "mcp.oauth.{name} {spelling:?} is not canonically spelled — it is \
                         read as {canonical:?}; "
                    )),
                    "{name} = {spelling:?}: {warnings:?}"
                );
            }
        }
        // A canonically spelled config warns about nothing.
        let resolved = enabled(|c| c.jwks_uri = Some("https://idp.example.test/jwks".into()))
            .resolve(WIKI)
            .unwrap()
            .unwrap();
        assert!(crate::validator::non_canonical_warnings(&resolved).is_empty());
    }

    #[test]
    fn canonical_url_spellings_behave_as_before() {
        // Canonical plain http off loopback: refused without the opt-in and
        // admitted with it — an upper-case scheme included.
        for url in [
            "http://idp.example.test/jwks",
            "HTTP://idp.example.test/jwks",
        ] {
            for name in ["issuer", "jwks_uri", "resource"] {
                let err = with_url(name, url, false).resolve(WIKI).unwrap_err();
                assert_eq!(err.problems.len(), 1, "{name} = {url:?}: {err}");
                assert!(
                    err.problems[0].contains("uses plain http on a non-loopback host"),
                    "{name} = {url:?}: {err}"
                );
                with_url(name, url, true)
                    .resolve(WIKI)
                    .unwrap_or_else(|e| panic!("{name} = {url:?}: {e}"))
                    .unwrap();
            }
        }
        // Loopback and https need no opt-in; a URL with no path, a default
        // port or an upper-case host is not "non-canonical".
        for url in [
            "http://localhost/jwks",
            "http://127.0.0.1:9000/jwks",
            "http://[::1]:9000/jwks",
            "https://idp.example.test/jwks",
            "https://IDP.example.test:443",
        ] {
            for name in ["issuer", "jwks_uri", "resource"] {
                with_url(name, url, false)
                    .resolve(WIKI)
                    .unwrap_or_else(|e| panic!("{name} = {url:?}: {e}"))
                    .unwrap();
            }
        }
    }

    // ── the unscoped posture ─────────────────────────────────────────────────

    #[test]
    fn no_required_scope_and_no_typ_check_is_refused_unless_explicitly_allowed() {
        let bare = |edit: fn(&mut OAuthConfig)| {
            let mut cfg = enabled(|c| c.allow_unscoped_tokens = false);
            edit(&mut cfg);
            cfg.resolve(WIKI)
        };
        let err = bare(|_| {}).unwrap_err();
        assert_eq!(err.problems.len(), 1, "{err}");
        assert_eq!(
            err.problems[0],
            "no required scope is configured (mcp.oauth.required_scope and \
             mcp.oauth.required_scopes are unset) and mcp.oauth.require_at_jwt is off — \
             nothing would tell an access token from an OIDC ID token minted for the same \
             client, so any token this issuer signs for the audience would be accepted. Set \
             mcp.oauth.required_scope to a scope only access tokens carry, turn on \
             mcp.oauth.require_at_jwt if the authorization server emits typ at+jwt, or set \
             mcp.oauth.allow_unscoped_tokens to accept that"
        );
        // Any one of the three is enough.
        assert!(bare(|c| c.required_scope = Some("a".into())).is_ok());
        assert!(bare(|c| c.required_scopes = vec!["a".into()]).is_ok());
        assert!(bare(|c| c.require_at_jwt = true).is_ok());
        let allowed = bare(|c| c.allow_unscoped_tokens = true).unwrap().unwrap();
        assert!(allowed.required_scopes.is_empty());
        assert!(allowed.allow_unscoped_tokens);
        // A blank scope is its own problem, not "unscoped" as well.
        let err = bare(|c| c.required_scope = Some(String::new())).unwrap_err();
        assert_eq!(err.problems.len(), 1, "{err}");
        // Named per the key naming.
        let err = OAuthConfig {
            enabled: true,
            ..OAuthConfig::default()
        }
        .resolve(KeyNaming::Env("APP_OAUTH_"))
        .unwrap_err();
        assert!(
            err.problems
                .iter()
                .any(|p| p.contains("set APP_OAUTH_ALLOW_UNSCOPED_TOKENS")),
            "{err}"
        );
    }

    // ── structured problems ──────────────────────────────────────────────────

    /// A field's name spelled by hand for `naming`, independent of
    /// `KeyNaming::key`, so a wrong key in a problem cannot cancel out.
    fn spelled(naming: KeyNaming<'_>, field: &str) -> String {
        match naming {
            KeyNaming::Dotted(p) => format!("{p}.{field}"),
            KeyNaming::Env(p) => format!("{p}{}", field.to_uppercase()),
        }
    }

    type Edit = fn(&mut OAuthConfig);

    /// One config per kind `resolve` can produce, with the fields the problem
    /// must name.
    fn one_problem_per_kind() -> Vec<(ProblemKind, Edit, &'static [&'static str])> {
        vec![
            (
                ProblemKind::MissingRequired,
                |c| c.issuer.clear(),
                &["issuer"],
            ),
            (
                ProblemKind::MissingRequired,
                |c| {
                    c.audience.clear();
                    c.audiences.clear();
                },
                &["audience", "audiences"],
            ),
            (
                ProblemKind::InvalidUrl,
                |c| c.jwks_uri = Some("not a url".into()),
                &["jwks_uri"],
            ),
            (
                ProblemKind::InsecureHttp,
                |c| c.resource = "http://kb.example.test/mcp".into(),
                &["resource", "allow_insecure_http"],
            ),
            (
                ProblemKind::BlankRequiredScope,
                |c| c.required_scope = Some(" ".into()),
                &["required_scope"],
            ),
            (
                ProblemKind::BlankRequiredScope,
                |c| c.required_scopes = vec!["".into()],
                &["required_scopes"],
            ),
            (
                ProblemKind::MultiWordScope,
                |c| c.required_scope = Some("a b".into()),
                &["required_scope"],
            ),
            (
                ProblemKind::MultiWordScope,
                |c| c.required_scopes = vec!["a b".into()],
                &["required_scopes"],
            ),
            (
                ProblemKind::InvalidScopeToken,
                |c| c.required_scope = Some("a\"b".into()),
                &["required_scope"],
            ),
            (
                ProblemKind::InvalidScopeToken,
                |c| c.required_scopes = vec!["a\\b".into()],
                &["required_scopes"],
            ),
            (
                ProblemKind::InvalidScopeToken,
                |c| c.scopes_supported = Some(vec!["a\"b".into()]),
                &["scopes_supported"],
            ),
            (
                ProblemKind::EmptyListEntry,
                |c| c.audiences = vec!["".into()],
                &["audiences"],
            ),
            (
                ProblemKind::EmptyListEntry,
                |c| c.scopes_supported = Some(vec!["".into()]),
                &["scopes_supported"],
            ),
            (
                ProblemKind::EmptyListEntry,
                |c| c.principal_claims = vec!["".into()],
                &["principal_claims"],
            ),
            (
                ProblemKind::NoRequiredScope,
                |c| c.allow_unscoped_tokens = false,
                &[
                    "required_scope",
                    "required_scopes",
                    "require_at_jwt",
                    "allow_unscoped_tokens",
                ],
            ),
            (
                ProblemKind::EmptyScopeClaims,
                |c| c.scope_claims.clear(),
                &["scope_claims"],
            ),
            (
                ProblemKind::BadAlgorithm,
                |c| c.algorithms = vec!["HS256".into()],
                &["algorithms"],
            ),
            (
                ProblemKind::NoAlgorithms,
                |c| c.algorithms.clear(),
                &["algorithms"],
            ),
            (
                ProblemKind::LeewayTooLarge,
                |c| c.leeway_secs = MAX_LEEWAY_SECS + 1,
                &["leeway_secs"],
            ),
            (
                ProblemKind::EmptyListEntry,
                |c| c.allowed_client_ids = vec!["client-a".into(), " ".into()],
                &["allowed_client_ids"],
            ),
            (
                ProblemKind::TokenAgeOutOfRange,
                |c| c.max_token_age_secs = Some(0),
                &["max_token_age_secs"],
            ),
            (
                ProblemKind::TokenAgeOutOfRange,
                |c| c.max_token_age_secs = Some(MAX_TOKEN_AGE_SECS + 1),
                &["max_token_age_secs"],
            ),
            (
                ProblemKind::InvalidRequiredClaim,
                |c| {
                    c.required_claims.insert(" ".into(), "x".into());
                },
                &["required_claims"],
            ),
            (
                ProblemKind::InvalidRequiredClaim,
                |c| {
                    c.required_claims.insert("aud".into(), "x".into());
                },
                &["required_claims"],
            ),
            (
                ProblemKind::InvalidRequiredClaim,
                |c| {
                    c.required_claims.insert("tid".into(), Value::Null);
                },
                &["required_claims"],
            ),
            (
                ProblemKind::InvalidRequiredClaim,
                |c| {
                    c.required_claims
                        .insert("groups".into(), serde_json::json!(["a"]));
                },
                &["required_claims"],
            ),
            (
                ProblemKind::InvalidRequiredClaim,
                |c| {
                    c.required_claims
                        .insert("org".into(), serde_json::json!({"id": 1}));
                },
                &["required_claims"],
            ),
        ]
    }

    #[test]
    fn every_kind_resolve_can_produce_is_produced_and_names_its_settings() {
        let mut seen = std::collections::HashSet::new();
        for naming in [WIKI, KeyNaming::Env("APP_OAUTH_")] {
            for (kind, edit, fields) in one_problem_per_kind() {
                let err = enabled(edit).resolve(naming).unwrap_err();
                let details = err.problem_details();
                assert_eq!(details.len(), 1, "{kind:?}: {err}");
                let p = &details[0];
                assert_eq!(p.kind(), kind, "{err}");
                let want: Vec<String> = fields.iter().map(|f| spelled(naming, f)).collect();
                assert_eq!(p.keys(), want.as_slice(), "{kind:?} under {naming:?}");
                assert_eq!(p.message(), err.problems[0]);
                assert_eq!(p.to_string(), p.message());
                seen.insert(kind);
            }
        }
        // Every kind but the env loader's two and the catch-all is covered.
        for kind in [
            ProblemKind::MissingRequired,
            ProblemKind::InvalidUrl,
            ProblemKind::InsecureHttp,
            ProblemKind::BlankRequiredScope,
            ProblemKind::MultiWordScope,
            ProblemKind::InvalidScopeToken,
            ProblemKind::EmptyListEntry,
            ProblemKind::NoRequiredScope,
            ProblemKind::EmptyScopeClaims,
            ProblemKind::BadAlgorithm,
            ProblemKind::NoAlgorithms,
            ProblemKind::LeewayTooLarge,
            ProblemKind::TokenAgeOutOfRange,
            ProblemKind::InvalidRequiredClaim,
        ] {
            assert!(seen.contains(&kind), "{kind:?} is never produced");
        }
        // Exhaustive over today's kinds: a new one must be classified here.
        for kind in seen {
            match kind {
                ProblemKind::EnvLoad | ProblemKind::EnvParse | ProblemKind::Other => {
                    panic!("resolve produced {kind:?}")
                }
                _ => {}
            }
        }
    }

    #[test]
    fn a_missing_required_problem_names_every_blank_setting() {
        let err = enabled(|c| {
            c.issuer.clear();
            c.resource.clear();
            c.audience.clear();
        })
        .resolve(KeyNaming::Env("APP_OAUTH_"))
        .unwrap_err();
        assert_eq!(
            err.problem_details()[0].keys(),
            [
                "APP_OAUTH_ISSUER",
                "APP_OAUTH_RESOURCE",
                "APP_OAUTH_AUDIENCE",
                "APP_OAUTH_AUDIENCES"
            ]
        );
    }

    #[test]
    fn problems_and_problem_details_agree_across_a_multi_problem_config() {
        let cfg = OAuthConfig {
            enabled: true,
            leeway_secs: MAX_LEEWAY_SECS + 1,
            required_scope: Some("a b".into()),
            algorithms: vec!["none".into()],
            principal_claims: vec![" ".into()],
            ..OAuthConfig::default()
        };
        for naming in [WIKI, KeyNaming::Env("APP_OAUTH_")] {
            let err = cfg.clone().resolve(naming).unwrap_err();
            let details = err.problem_details();
            assert_eq!(details.len(), 5, "{err}");
            let texts: Vec<&str> = details.iter().map(ConfigProblem::message).collect();
            assert_eq!(texts, err.problems);
            let kinds: Vec<ProblemKind> = details.iter().map(ConfigProblem::kind).collect();
            assert_eq!(
                kinds,
                [
                    ProblemKind::MissingRequired,
                    ProblemKind::MultiWordScope,
                    ProblemKind::EmptyListEntry,
                    ProblemKind::BadAlgorithm,
                    ProblemKind::LeewayTooLarge,
                ]
            );
        }
    }

    #[test]
    fn config_error_new_is_unchanged_and_wraps_strings_as_other() {
        let err = ConfigError::new(WIKI, vec!["first".to_string(), "second".to_string()]);
        assert_eq!(err.problems, ["first", "second"]);
        let details = err.problem_details();
        assert_eq!(details.len(), 2);
        assert!(details.iter().all(|p| p.kind() == ProblemKind::Other));
        assert!(details.iter().all(|p| p.keys().is_empty()));
        assert_eq!(details[1].message(), "second");
        assert_eq!(
            err.to_string(),
            "mcp.oauth.enabled is true but the OAuth config is not usable:\n  - first\n  - second\n\
             Fix these, or set mcp.oauth.enabled: false."
        );
        // Inference through `collect()` keeps working (an existing caller's shape).
        let collected = ConfigError::new(WIKI, ["a", "b"].iter().map(|s| s.to_string()).collect());
        assert_eq!(collected.problems, ["a", "b"]);
    }

    #[test]
    fn from_problems_and_from_string_mix_structured_and_plain_problems() {
        let p = ConfigProblem::from("app problem".to_string());
        assert_eq!(p.kind(), ProblemKind::Other);
        assert!(p.keys().is_empty());
        assert_eq!(p.message(), "app problem");
        assert_eq!(p.to_string(), "app problem");

        let own = ConfigProblem::new(ProblemKind::InvalidUrl, ["my.key"], "my.key is bad");
        assert_eq!(own.keys(), ["my.key"]);
        let err = ConfigError::from_problems(WIKI, [own.clone(), p.clone()]);
        assert_eq!(err.problems, ["my.key is bad", "app problem"]);
        assert_eq!(err.problem_details(), [own, p]);
        assert!(
            err.to_string()
                .contains("\n  - my.key is bad\n  - app problem\n")
        );
        assert_eq!(err.naming(), WIKI);
    }

    #[test]
    fn config_error_equality_ignores_the_structured_details() {
        let err = enabled(|c| c.leeway_secs = MAX_LEEWAY_SECS + 1)
            .resolve(WIKI)
            .unwrap_err();
        // 0.1.2 semantics: an error rebuilt from the strings is equal.
        let rebuilt = ConfigError::new(WIKI, err.problems.clone());
        assert_eq!(rebuilt, err);
        assert_ne!(rebuilt.problem_details(), err.problem_details());
        // Different problems or naming are not equal.
        assert_ne!(ConfigError::new(WIKI, vec!["other".into()]), err);
        assert_ne!(
            ConfigError::new(KeyNaming::Env("APP_OAUTH_"), err.problems.clone()),
            err
        );
    }

    #[test]
    fn editing_the_public_problems_field_does_not_touch_problem_details() {
        let mut err = enabled(|c| c.leeway_secs = MAX_LEEWAY_SECS + 1)
            .resolve(WIKI)
            .unwrap_err();
        let before = err.problem_details().to_vec();
        err.problems.push("extra".into());
        assert_eq!(err.problem_details(), before);
    }

    #[test]
    fn problem_kind_labels_are_stable_and_distinct() {
        let all = [
            (ProblemKind::MissingRequired, "missing_required"),
            (ProblemKind::InvalidUrl, "invalid_url"),
            (ProblemKind::InsecureHttp, "insecure_http"),
            (ProblemKind::BlankRequiredScope, "blank_required_scope"),
            (ProblemKind::MultiWordScope, "multi_word_scope"),
            (ProblemKind::InvalidScopeToken, "invalid_scope_token"),
            (ProblemKind::EmptyListEntry, "empty_list_entry"),
            (ProblemKind::NoRequiredScope, "no_required_scope"),
            (ProblemKind::EmptyScopeClaims, "empty_scope_claims"),
            (ProblemKind::BadAlgorithm, "bad_algorithm"),
            (ProblemKind::NoAlgorithms, "no_algorithms"),
            (ProblemKind::LeewayTooLarge, "leeway_too_large"),
            (ProblemKind::TokenAgeOutOfRange, "token_age_out_of_range"),
            (ProblemKind::InvalidRequiredClaim, "invalid_required_claim"),
            (ProblemKind::EnvLoad, "env_load"),
            (ProblemKind::EnvParse, "env_parse"),
            (ProblemKind::Other, "other"),
        ];
        for (kind, label) in all {
            assert_eq!(kind.as_str(), label);
            assert_eq!(kind.to_string(), label);
        }
        let labels: std::collections::HashSet<_> = all.iter().map(|(_, l)| *l).collect();
        assert_eq!(labels.len(), all.len());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn the_claim_policy_settings_deserialize_and_default_to_off() {
        let yaml = "\
enabled: true
allowed_client_ids: [\"client-a\", \"client-b\"]
max_token_age_secs: 3600
required_claims:
  tid: \"tenant-1\"
  level: 2
  mfa: true
";
        let parsed: OAuthConfig = serde_yaml_ng::from_str(yaml).unwrap();
        assert_eq!(parsed.allowed_client_ids, ["client-a", "client-b"]);
        assert_eq!(parsed.max_token_age_secs, Some(3600));
        assert_eq!(parsed.required_claims["tid"], serde_json::json!("tenant-1"));
        assert_eq!(parsed.required_claims["level"], serde_json::json!(2));
        assert_eq!(parsed.required_claims["mfa"], serde_json::json!(true));
        let back: OAuthConfig =
            serde_yaml_ng::from_str(&serde_yaml_ng::to_string(&parsed).unwrap()).unwrap();
        assert_eq!(back, parsed);

        // Omitted: exactly the defaults, which check nothing.
        let empty: OAuthConfig = serde_yaml_ng::from_str("{}").unwrap();
        assert_eq!(empty, OAuthConfig::default());
        assert!(empty.allowed_client_ids.is_empty());
        assert_eq!(empty.max_token_age_secs, None);
        assert!(empty.required_claims.is_empty());
        // `deny_unknown_fields` still refuses a misspelled one.
        assert!(serde_yaml_ng::from_str::<OAuthConfig>("allowed_clients: [\"a\"]\n").is_err());
        assert!(serde_yaml_ng::from_str::<OAuthConfig>("max_token_age: 5\n").is_err());
    }

    #[test]
    fn the_claim_policy_settings_resolve_unchanged_and_default_off() {
        let resolved = enabled(|_| {}).resolve(WIKI).unwrap().unwrap();
        assert!(resolved.allowed_client_ids.is_empty());
        assert_eq!(resolved.max_token_age_secs, None);
        assert!(resolved.required_claims.is_empty());

        let resolved = enabled(|c| {
            c.allowed_client_ids = vec!["client-a".into()];
            c.max_token_age_secs = Some(MAX_TOKEN_AGE_SECS);
            c.required_claims
                .insert("groups".into(), serde_json::json!("api-users"));
            c.required_claims
                .insert("level".into(), serde_json::json!(2));
            c.required_claims
                .insert("mfa".into(), serde_json::json!(false));
        })
        .resolve(WIKI)
        .unwrap()
        .unwrap();
        assert_eq!(resolved.allowed_client_ids, ["client-a"]);
        assert_eq!(resolved.max_token_age_secs, Some(MAX_TOKEN_AGE_SECS));
        assert_eq!(resolved.required_claims.len(), 3);
        let one = enabled(|c| c.max_token_age_secs = Some(1)).resolve(WIKI);
        assert!(one.unwrap().is_some());

        // Every reserved claim is refused, each named, all at once.
        let err = enabled(|c| {
            for name in RESERVED_REQUIRED_CLAIMS {
                c.required_claims.insert((*name).into(), "x".into());
            }
        })
        .resolve(KeyNaming::Env("APP_OAUTH_"))
        .unwrap_err();
        assert_eq!(err.problems.len(), RESERVED_REQUIRED_CLAIMS.len(), "{err}");
        for p in err.problem_details() {
            assert_eq!(p.kind(), ProblemKind::InvalidRequiredClaim);
            assert_eq!(p.keys(), ["APP_OAUTH_REQUIRED_CLAIMS"]);
        }
    }

    #[test]
    fn no_problem_message_carries_a_run_of_spaces() {
        // A dropped `\` at the end of a wrapped string literal leaves the next
        // line's indentation inside the message.
        for naming in [WIKI, KeyNaming::Env("APP_OAUTH_")] {
            for (kind, edit, _) in one_problem_per_kind() {
                let err = enabled(edit).resolve(naming).unwrap_err();
                for problem in &err.problems {
                    assert!(!problem.contains("  "), "{kind:?}: {problem:?}");
                }
            }
        }
    }

    #[cfg(feature = "serde")]
    #[test]
    fn unset_claim_policy_settings_are_still_serialized() {
        // Consumers derive their list of settings from the serialized
        // defaults, so a new setting must appear even when it is off.
        let yaml = serde_yaml_ng::to_string(&OAuthConfig::default()).unwrap();
        for key in [
            "allowed_client_ids",
            "max_token_age_secs",
            "required_claims",
        ] {
            assert!(yaml.contains(key), "{key} missing from {yaml}");
        }
    }
}
