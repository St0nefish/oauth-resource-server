//! Loading secrets and the OAuth config from environment variables (with
//! `VAR_FILE` support).
//!
//! [`secret_from_env`] reads one value, accepting either `VAR` directly or a
//! path in `VAR_FILE` (the shape Docker Compose `secrets:` mounts use).
//! [`oauth_config_from_env`] builds a whole [`OAuthConfig`] the same way, one
//! field per `<PREFIX><FIELD>` variable, and [`OAuthConfig::resolve`]s it.
//!
//! Every function here has a `_lookup` twin that takes the variable lookup and
//! file reader as arguments instead of calling `std::env::var`/
//! `std::fs::read_to_string` directly, so tests can exercise every case
//! without mutating the process environment — `std::env::set_var` is `unsafe`
//! as of the 2024 edition.

use std::io;

use crate::config::{
    ConfigError, ConfigProblem, KeyNaming, OAuthConfig, ProblemKind, ResolvedOAuthConfig,
};

/// A problem loading a secret from the environment.
///
/// `Debug` and `Display` never include a secret's *value* — only variable
/// names and file paths, neither of which is secret itself.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum EnvError {
    /// `var` and `<var>_FILE` were both set. Ambiguous on purpose: silently
    /// preferring one would hide the other from an operator who set both by
    /// mistake.
    #[error("{var} and {var}_FILE are both set (file: {path}) — set exactly one, not both")]
    #[non_exhaustive]
    BothSet {
        /// The plain variable name (already fully qualified, e.g. with its
        /// `oauth_config_from_env` prefix applied).
        var: String,
        /// The path named by `<var>_FILE`, not the file's contents.
        path: String,
    },
    /// `<var>_FILE` named a file that could not be read.
    ///
    /// `Display` names the variable and path only; the I/O failure is the
    /// error's [`source`](std::error::Error::source), not part of its text, so
    /// a reporter that walks the source chain (`anyhow`, for one) prints the
    /// cause once rather than twice. [`oauth_config_from_env`] appends it to
    /// the problem text itself.
    #[error("{var}_FILE={path}: failed to read secret file")]
    #[non_exhaustive]
    ReadFailed {
        /// The plain variable name.
        var: String,
        /// The path that failed to read.
        path: String,
        /// The underlying I/O failure.
        #[source]
        source: io::Error,
    },
    /// The file named by `<var>_FILE` was read successfully but was empty (or
    /// all whitespace). Unlike a blank `VAR`, this is an error rather than
    /// "unset": a secrets-mount file that exists but is empty is far more
    /// likely a provisioning mistake than an intentional absence.
    #[error("{var}_FILE={path}: secret file is empty")]
    #[non_exhaustive]
    EmptyFile {
        /// The plain variable name.
        var: String,
        /// The path that was empty.
        path: String,
    },
}

/// Read a secret from `var`, falling back to the file named by `<var>_FILE`.
///
/// Docker Compose `secrets:` mounts a file rather than setting a variable, so
/// each secret accepts both forms. Setting **both** is rejected rather than
/// silently preferring one, so a misconfigured deployment is told which value
/// would have won.
///
/// Values are trimmed. This matters for the file form (a secret file written
/// by any ordinary means ends with a trailing newline, which would otherwise
/// become part of the value) and is applied to the direct form too so the two
/// paths cannot disagree. `VAR` empty, or empty after trimming, is treated as
/// unset (`Ok(None)`) — but a `VAR_FILE` that reads successfully and comes out
/// empty after trimming is an error ([`EnvError::EmptyFile`]), since a secrets
/// file existing but empty is a provisioning mistake, not an absence.
///
/// This is [`secret_from_lookup`] wired to the real process environment and
/// filesystem; use that directly to test callers without mutating either. A
/// variable whose value is not valid Unicode reads as unset.
///
/// # Errors
///
/// - [`EnvError::BothSet`] when `var` and `<var>_FILE` are both set.
/// - [`EnvError::ReadFailed`] when the file named by `<var>_FILE` cannot be
///   read.
/// - [`EnvError::EmptyFile`] when that file is empty after trimming.
///
/// # Security
///
/// The value is returned, never logged, and no error includes it: errors name
/// the variable and the file path only.
///
/// # Examples
///
/// ```no_run
/// use oauth_resource_server::env::secret_from_env;
///
/// // MYAPP_API_KEY=..., or MYAPP_API_KEY_FILE=/run/secrets/api_key
/// match secret_from_env("MYAPP_API_KEY") {
///     Ok(Some(_key)) => println!("static API key configured"),
///     Ok(None) => println!("no static API key"),
///     Err(e) => eprintln!("MYAPP_API_KEY: {e}"),
/// }
/// ```
pub fn secret_from_env(var: &str) -> Result<Option<String>, EnvError> {
    secret_from_lookup(
        var,
        |v| std::env::var(v).ok(),
        |path| std::fs::read_to_string(path),
    )
}

/// [`secret_from_env`] with the variable lookup and file reader injected, so
/// tests can exercise every case (both set, an unreadable file, an empty
/// file, trimming, absence) without calling the `unsafe`
/// `std::env::set_var` or touching the real filesystem.
///
/// `lookup` returns a variable's value (or `None` when unset); `read_file`
/// reads the file at a path. `read_file` is called only when `<var>_FILE` is
/// set and `var` is not.
///
/// # Errors
///
/// As [`secret_from_env`].
///
/// # Examples
///
/// ```
/// use std::collections::HashMap;
/// use std::io;
///
/// use oauth_resource_server::env::{EnvError, secret_from_lookup};
///
/// let vars = HashMap::from([("MYAPP_API_KEY_FILE", "/run/secrets/api_key")]);
/// let lookup = |name: &str| vars.get(name).map(|v| v.to_string());
/// let read_file = |path: &str| match path {
///     "/run/secrets/api_key" => Ok("s3cret\n".to_string()),
///     _ => Err(io::Error::from(io::ErrorKind::NotFound)),
/// };
///
/// // The file form, trimmed.
/// let key = secret_from_lookup("MYAPP_API_KEY", &lookup, &read_file).unwrap();
/// assert_eq!(key.as_deref(), Some("s3cret"));
///
/// // Unset entirely.
/// assert_eq!(secret_from_lookup("MYAPP_OTHER", &lookup, &read_file).unwrap(), None);
///
/// // Both forms set: an error, not a silent preference.
/// let both = HashMap::from([("K", "a"), ("K_FILE", "/x")]);
/// let err = secret_from_lookup("K", |n| both.get(n).map(|v| v.to_string()), &read_file);
/// assert!(matches!(err, Err(EnvError::BothSet { .. })));
/// ```
pub fn secret_from_lookup(
    var: &str,
    lookup: impl Fn(&str) -> Option<String>,
    read_file: impl Fn(&str) -> io::Result<String>,
) -> Result<Option<String>, EnvError> {
    let file_var = format!("{var}_FILE");
    let direct = lookup(var).filter(|s| !s.trim().is_empty());
    let path = lookup(&file_var).filter(|s| !s.trim().is_empty());

    match (direct, path) {
        (Some(_), Some(path)) => Err(EnvError::BothSet {
            var: var.to_string(),
            path,
        }),
        (Some(v), None) => Ok(Some(v.trim().to_string())),
        (None, Some(path)) => {
            let raw = read_file(&path).map_err(|source| EnvError::ReadFailed {
                var: var.to_string(),
                path: path.clone(),
                source,
            })?;
            let value = raw.trim().to_string();
            if value.is_empty() {
                return Err(EnvError::EmptyFile {
                    var: var.to_string(),
                    path,
                });
            }
            Ok(Some(value))
        }
        (None, None) => Ok(None),
    }
}

/// Split a whitespace-separated list value (`required_scopes`,
/// `scopes_supported`, `scope_claims`, `principal_claims`, `algorithms`,
/// `audiences`, `allowed_client_ids`) into its entries.
fn split_list(value: &str) -> Vec<String> {
    value.split_whitespace().map(str::to_string).collect()
}

/// Parse a strictly-spelled boolean: exactly `"true"` or `"false"` (already
/// trimmed by [`secret_from_lookup`]), nothing looser — no `1`/`0`, no
/// case-insensitivity. A typo should fail loudly rather than silently reading
/// as `false`.
fn parse_strict_bool(value: &str) -> Result<bool, ()> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(()),
    }
}

/// The problem text for a `bool` variable that is neither `"true"` nor
/// `"false"`. The value is echoed back: every `bool` setting here is a plain
/// switch, never secret.
fn bool_problem(naming: KeyNaming<'_>, field: &str, value: &str) -> ConfigProblem {
    ConfigProblem::new(
        ProblemKind::EnvParse,
        [naming.key(field)],
        format!(
            "{} {value:?} must be \"true\" or \"false\"",
            naming.key(field)
        ),
    )
}

/// The problem text for a failed load: the error's `Display` followed by its
/// source chain, `": "`-separated. A [`ConfigError`] problem is a flat string
/// with no source chain of its own, so [`EnvError::ReadFailed`]'s I/O cause —
/// deliberately left out of its `Display` — is appended here instead.
fn env_problem(err: &EnvError) -> ConfigProblem {
    let mut text = err.to_string();
    let mut source = std::error::Error::source(err);
    while let Some(cause) = source {
        text.push_str(": ");
        text.push_str(&cause.to_string());
        source = cause.source();
    }
    // Name the variables the operator has to look at: both when both are set,
    // otherwise the `_FILE` whose file could not be used.
    let keys = match err {
        EnvError::BothSet { var, .. } => vec![var.clone(), format!("{var}_FILE")],
        EnvError::ReadFailed { var, .. } | EnvError::EmptyFile { var, .. } => {
            vec![format!("{var}_FILE")]
        }
    };
    ConfigProblem::new(ProblemKind::EnvLoad, keys, text)
}

/// Record a failed load as a problem and read it as unset, so one bad
/// variable never stops the rest from being checked.
fn take(
    result: Result<Option<String>, EnvError>,
    problems: &mut Vec<ConfigProblem>,
) -> Option<String> {
    result.unwrap_or_else(|e| {
        problems.push(env_problem(&e));
        None
    })
}

/// The variables that decide whether OAuth is configured at all when
/// `<PREFIX>ENABLED` is unset: `issuer`, `jwks_uri`, `audience`, `audiences`,
/// `resource`. A named struct rather than a list of names, so destructuring
/// it makes the compiler check that every one is applied to the config.
///
/// `jwks_uri` counts because it alone is enough to mean "configure OAuth",
/// even though [`OAuthConfig::resolve`] does not itself require it (an absent
/// `jwks_uri` means "discover it from `issuer`").
struct IdentifyingVars {
    issuer: Result<Option<String>, EnvError>,
    jwks_uri: Result<Option<String>, EnvError>,
    audience: Result<Option<String>, EnvError>,
    audiences: Result<Option<String>, EnvError>,
    resource: Result<Option<String>, EnvError>,
}

impl IdentifyingVars {
    /// Whether any of them was set. "Set" means either a non-empty value
    /// loaded, or loading it failed (both forms set, or an unreadable/empty
    /// `_FILE`): an operator who typo'd `ISSUER_FILE`'s path did try to
    /// configure OAuth, and must be told why it did not load, not silently
    /// land on "OAuth disabled".
    fn any_set(&self) -> bool {
        [
            &self.issuer,
            &self.jwks_uri,
            &self.audience,
            &self.audiences,
            &self.resource,
        ]
        .into_iter()
        .any(|r| !matches!(r, Ok(None)))
    }
}

/// Load an [`OAuthConfig`] from environment variables named
/// `<PREFIX><FIELD_UPPER>` (e.g. `MYAPP_OAUTH_ISSUER`) and
/// [`OAuthConfig::resolve`] it.
///
/// This is [`unresolved_oauth_config_from_env`] followed straight by
/// [`EnvOAuthConfig::resolve`]. An application that needs its own defaults
/// (a default required scope, say) applies them between those two calls
/// instead; see [`EnvOAuthConfig`].
///
/// Whether OAuth is on:
///
/// - `<PREFIX>ENABLED=false` returns `Ok(None)` without reading any other
///   variable — the switch for turning OAuth off while the rest of its
///   settings stay in place, like `enabled: false` in a config file.
/// - `<PREFIX>ENABLED=true` turns it on regardless of the others, so a
///   missing setting is reported rather than silently leaving OAuth off.
/// - `<PREFIX>ENABLED` unset infers it: `Ok(None)` when none of the
///   identifying variables — `ISSUER`, `JWKS_URI`, `AUDIENCE`, `AUDIENCES`,
///   `RESOURCE` — is set (no variable outside those and `ENABLED` is read),
///   and on when any of them is, so a partial set fails naming what is
///   missing.
/// - `<PREFIX>ENABLED` set to anything else, or failing to load, is a problem
///   reported alongside the rest, with OAuth treated as on so every other
///   problem is found in the same run.
///
/// Once on, every field is read (each through [`secret_from_lookup`], so
/// `<FIELD>_FILE` works too), list-valued fields are split on whitespace,
/// `bool` fields are parsed strictly (`"true"`/`"false"` only), integer fields
/// are parsed as decimal (`MAX_TOKEN_AGE_SECS` set to a number means
/// `Some(number)`), `<PREFIX>REQUIRED_CLAIMS` is one JSON object
/// (`{"tid": "<tenant id>", "groups": "api-users"}`), and every problem — a variable that failed to load,
/// a value that failed to parse, or a problem [`OAuthConfig::resolve`] itself
/// found — is collected into one [`ConfigError`], never reported one at a
/// time across repeated runs. The loader's own problems come first. A
/// required setting whose variable failed to load is therefore reported
/// twice: once with the load failure (the actual cause), and again among
/// `resolve`'s "these required settings are empty", since it never got a
/// value.
///
/// A field whose variable is unset keeps [`OAuthConfig::default`]'s value for
/// it (so, for example, an unset `<PREFIX>ALGORITHMS` still resolves to
/// [`crate::DEFAULT_ALGORITHMS`], not an empty list). An unset
/// `<PREFIX>SCOPES_SUPPORTED` therefore resolves, as an omitted
/// `scopes_supported` does anywhere, to the required scopes (`REQUIRED_SCOPE`,
/// then `REQUIRED_SCOPES`, deduplicated), so the metadata document and the 401
/// challenge advertise the scope a client must ask for. An environment
/// variable cannot express an explicitly empty list — an empty value reads as
/// unset — so this default never overrides an operator's choice.
///
/// No secret file's contents ever appear in a problem: [`EnvError`] names
/// variables and paths only, and a failed read adds the I/O error's own text
/// (e.g. "No such file or directory"), which never carries file contents.
/// Non-secret setting values can appear: a value that fails to parse is
/// echoed back, and [`OAuthConfig::resolve`] quotes the URLs and scopes it
/// rejects. None of the settings read here is secret — they are public
/// discovery and authorization material — but a secret-valued field added
/// later must not be reported the same way.
///
/// # Errors
///
/// A [`ConfigError`] when OAuth is on and anything is wrong: a variable that
/// failed to load (see [`EnvError`]), a value that failed to parse, or any
/// problem [`OAuthConfig::resolve`] reports. All of them at once; its
/// `Display` names each variable.
///
/// # Examples
///
/// ```no_run
/// use std::sync::Arc;
///
/// use oauth_resource_server::OAuthValidator;
/// use oauth_resource_server::env::oauth_config_from_env;
///
/// # #[tokio::main]
/// # async fn main() {
/// // MYAPP_OAUTH_ISSUER=https://auth.example.com/
/// // MYAPP_OAUTH_AUDIENCE=example-api
/// // MYAPP_OAUTH_RESOURCE=https://api.example.com
/// // MYAPP_OAUTH_REQUIRED_SCOPE=api:read
/// let oauth = match oauth_config_from_env("MYAPP_OAUTH_") {
///     Ok(Some(resolved)) => {
///         let validator = Arc::new(OAuthValidator::new(&resolved).expect("validator"));
///         validator.spawn_background_refresh();
///         Some(validator)
///     }
///     Ok(None) => None, // OAuth not configured
///     Err(e) => {
///         eprintln!("{e}"); // every problem, one per line
///         std::process::exit(1);
///     }
/// };
/// # let _ = oauth;
/// # }
/// ```
pub fn oauth_config_from_env(prefix: &str) -> Result<Option<ResolvedOAuthConfig>, ConfigError> {
    oauth_config_from_lookup(
        prefix,
        |v| std::env::var(v).ok(),
        |path| std::fs::read_to_string(path),
    )
}

/// [`oauth_config_from_env`] with the variable lookup and file reader
/// injected, for tests. See [`unresolved_oauth_config_from_lookup`] for which
/// variables it consults.
///
/// # Errors
///
/// As [`oauth_config_from_env`].
///
/// # Examples
///
/// ```
/// use std::collections::HashMap;
/// use std::io;
///
/// use oauth_resource_server::env::oauth_config_from_lookup;
///
/// let vars = HashMap::from([
///     ("MYAPP_OAUTH_ISSUER", "https://auth.example.com/"),
///     ("MYAPP_OAUTH_AUDIENCE", "example-api"),
///     ("MYAPP_OAUTH_RESOURCE", "https://api.example.com"),
///     ("MYAPP_OAUTH_REQUIRED_SCOPES", "api:read api:write"),
/// ]);
/// let lookup = |name: &str| vars.get(name).map(|v| v.to_string());
/// let no_files = |_: &str| Err(io::Error::from(io::ErrorKind::NotFound));
///
/// let resolved = oauth_config_from_lookup("MYAPP_OAUTH_", &lookup, &no_files)
///     .unwrap()
///     .expect("the identifying variables are set, so OAuth is on");
/// assert_eq!(resolved.required_scopes, ["api:read", "api:write"]);
/// // SCOPES_SUPPORTED is unset, so it advertises the required scopes.
/// assert_eq!(resolved.scopes_supported, ["api:read", "api:write"]);
///
/// // No identifying variable set: OAuth is off.
/// let empty = |_: &str| None;
/// assert_eq!(oauth_config_from_lookup("OTHER_", empty, &no_files).unwrap(), None);
///
/// // A partial set fails, naming each missing variable.
/// let partial = |name: &str| (name == "APP2_ISSUER").then(|| "https://auth.example.com/".to_string());
/// let err = oauth_config_from_lookup("APP2_", partial, &no_files).unwrap_err();
/// assert!(err.to_string().contains("APP2_RESOURCE"));
/// ```
pub fn oauth_config_from_lookup<L, R>(
    prefix: &str,
    lookup: L,
    read_file: R,
) -> Result<Option<ResolvedOAuthConfig>, ConfigError>
where
    L: Fn(&str) -> Option<String>,
    R: Fn(&str) -> io::Result<String>,
{
    match unresolved_oauth_config_from_lookup(prefix, lookup, read_file) {
        Some(loaded) => loaded.resolve(),
        None => Ok(None),
    }
}

/// An [`OAuthConfig`] read from the environment but not yet resolved, with
/// the problems the loader itself found (variables that failed to load,
/// values that failed to parse).
///
/// Returned by [`unresolved_oauth_config_from_env`] so an application can
/// apply its own defaults to [`config`](Self::config) before
/// [`resolve`](Self::resolve) validates it — the same hook a config-file
/// application has between deserializing an [`OAuthConfig`] and calling
/// [`OAuthConfig::resolve`]. For example, to require `api:read` unless the
/// operator named a required scope:
///
/// ```
/// # fn main() -> Result<(), oauth_resource_server::ConfigError> {
/// use oauth_resource_server::env::unresolved_oauth_config_from_env;
///
/// if let Some(mut loaded) = unresolved_oauth_config_from_env("MYAPP_OAUTH_") {
///     let cfg = &mut loaded.config;
///     if cfg.required_scope.is_none() && cfg.required_scopes.is_empty() {
///         cfg.required_scope = Some("api:read".into());
///     }
///     let resolved = loaded.resolve()?;
///     # let _ = resolved;
/// }
/// # Ok(())
/// # }
/// ```
///
/// A default set this way is validated by `resolve` like any other value, and
/// is included in the `scopes_supported` default below.
///
/// [`config`](Self::config)`.scopes_supported` is `None` when
/// `<PREFIX>SCOPES_SUPPORTED` was unset (or failed to load);
/// [`OAuthConfig::resolve`] turns `None` into the required scopes as they
/// stand at that point, application defaults included. Set it to `Some(..)` —
/// `Some(vec![])` for an explicitly empty list — to override that.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct EnvOAuthConfig {
    /// The loaded config, `enabled: true`, every unset field at its
    /// [`OAuthConfig::default`] value. Free to modify before
    /// [`resolve`](Self::resolve).
    pub config: OAuthConfig,
    /// Problems the loader found, each naming its variable. Reported by
    /// [`resolve`](Self::resolve) ahead of any it finds itself; `resolve`
    /// fails whenever this is non-empty.
    ///
    /// Kept for compatibility; the structured form is
    /// [`problem_details`](Self::problem_details), filled from the same list at
    /// load time. Editing this field in place (an application appending its
    /// own problem, say) does not update `problem_details()`, but
    /// [`resolve`](Self::resolve) reports whatever this field holds.
    pub problems: Vec<String>,
    details: Vec<ConfigProblem>,
    prefix: String,
}

/// Equality covers every field except the structured `details`, which are
/// derived from `problems` (this type derived `PartialEq` before they existed).
impl PartialEq for EnvOAuthConfig {
    fn eq(&self, other: &Self) -> bool {
        self.config == other.config
            && self.problems == other.problems
            && self.prefix == other.prefix
    }
}

impl Eq for EnvOAuthConfig {}

impl EnvOAuthConfig {
    /// The loader's problems as structured [`ConfigProblem`]s, in the order
    /// [`problems`](Self::problems) lists them: [`ProblemKind::EnvLoad`] for a
    /// variable or `_FILE` that could not be read, [`ProblemKind::EnvParse`]
    /// for a value that could not be parsed. Match on the kind, not the text.
    ///
    /// Fixed at load time: editing the public `problems` field in place does
    /// not change it, so this can be stale until [`resolve`](Self::resolve),
    /// which reconciles the two. `keys()` of an `EnvLoad` problem is the
    /// variable and its `_FILE` twin when both were set, else the `_FILE`
    /// variable whose file could not be used.
    pub fn problem_details(&self) -> &[ConfigProblem] {
        &self.details
    }

    /// The variable prefix this config was loaded with, which
    /// [`resolve`](Self::resolve) also uses to name settings in problems.
    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    /// [`OAuthConfig::resolve`] with [`KeyNaming::Env`] of this prefix,
    /// failing with the loader's [`problems`](Self::problems) followed by
    /// `resolve`'s own if there are any of either.
    ///
    /// `Ok(None)` only if the application set
    /// [`config`](Self::config)`.enabled` to `false` and the loader found no
    /// problems.
    ///
    /// # Errors
    ///
    /// A [`ConfigError`] when [`problems`](Self::problems) is non-empty or
    /// [`OAuthConfig::resolve`] finds any, listing the loader's first. The
    /// public [`problems`](Self::problems) decides what is reported: an entry
    /// the application edited or added surfaces in the resulting
    /// [`ConfigError`] as [`ProblemKind::Other`], while an untouched one keeps
    /// its kind and keys. [`problem_details`](Self::problem_details) may be
    /// stale before this call; the reconciliation happens inside it.
    pub fn resolve(self) -> Result<Option<ResolvedOAuthConfig>, ConfigError> {
        let Self {
            config,
            problems,
            details,
            prefix,
        } = self;
        let naming = KeyNaming::Env(&prefix);
        // `problems` is public and may have been edited since loading, so it
        // stays the authority for what is reported; each entry keeps its
        // structured form when one still matches, and is `Other` otherwise.
        let mut all = reconcile(problems, details);
        match config.resolve(naming) {
            Ok(resolved) if all.is_empty() => Ok(resolved),
            Ok(_) => Err(ConfigError::from_problems(naming, all)),
            Err(resolve_err) => {
                all.extend(resolve_err.problem_details().iter().cloned());
                Err(ConfigError::from_problems(naming, all))
            }
        }
    }
}

/// One [`ConfigProblem`] per string in `problems`, in order: the first unused
/// entry of `details` with the same message, else a plain `Other` problem.
fn reconcile(problems: Vec<String>, details: Vec<ConfigProblem>) -> Vec<ConfigProblem> {
    let mut pool: Vec<Option<ConfigProblem>> = details.into_iter().map(Some).collect();
    problems
        .into_iter()
        .map(|text| {
            pool.iter_mut()
                .find(|slot| slot.as_ref().is_some_and(|d| d.message() == text))
                .and_then(Option::take)
                .unwrap_or_else(|| ConfigProblem::from(text))
        })
        .collect()
}

/// Load an [`OAuthConfig`] from `<PREFIX><FIELD_UPPER>` variables without
/// resolving it, so the application can apply its own defaults first; see
/// [`EnvOAuthConfig`].
///
/// `None` means OAuth is off, decided exactly as [`oauth_config_from_env`]
/// describes (`<PREFIX>ENABLED=false`, or `ENABLED` and every identifying
/// variable unset). Every other outcome is `Some`, with any load and parse
/// problems carried in [`EnvOAuthConfig::problems`] rather than returned
/// here, so [`EnvOAuthConfig::resolve`] reports them together with its own.
pub fn unresolved_oauth_config_from_env(prefix: &str) -> Option<EnvOAuthConfig> {
    unresolved_oauth_config_from_lookup(
        prefix,
        |v| std::env::var(v).ok(),
        |path| std::fs::read_to_string(path),
    )
}

/// [`unresolved_oauth_config_from_env`] with the variable lookup and file
/// reader injected, for tests.
///
/// For each field consulted, `lookup` is called for both `<PREFIX><FIELD>` and
/// `<PREFIX><FIELD>_FILE`, and `read_file` only when the `_FILE` form is set
/// and the plain one is not. When the result is `None` because OAuth is off,
/// no field outside `ENABLED` and the identifying set (`ISSUER`, `JWKS_URI`,
/// `AUDIENCE`, `AUDIENCES`, `RESOURCE`) is consulted — and none but `ENABLED`
/// when that is `false`.
pub fn unresolved_oauth_config_from_lookup<L, R>(
    prefix: &str,
    lookup: L,
    read_file: R,
) -> Option<EnvOAuthConfig>
where
    L: Fn(&str) -> Option<String>,
    R: Fn(&str) -> io::Result<String>,
{
    let naming = KeyNaming::Env(prefix);
    let field = |f: &str| secret_from_lookup(&naming.key(f), &lookup, &read_file);
    let mut problems: Vec<ConfigProblem> = Vec::new();

    // `true` when ENABLED was set in any form other than a clean "false" —
    // including an unparsable value or a load failure, which are reported
    // and must not silently leave OAuth off.
    let explicitly_enabled = match field("enabled") {
        Ok(None) => false,
        Ok(Some(v)) => match parse_strict_bool(&v) {
            Ok(false) => return None,
            Ok(true) => true,
            Err(()) => {
                problems.push(bool_problem(naming, "enabled", &v));
                true
            }
        },
        Err(e) => {
            problems.push(env_problem(&e));
            true
        }
    };

    let identifying = IdentifyingVars {
        issuer: field("issuer"),
        jwks_uri: field("jwks_uri"),
        audience: field("audience"),
        audiences: field("audiences"),
        resource: field("resource"),
    };
    if !explicitly_enabled && !identifying.any_set() {
        return None;
    }

    let mut cfg = OAuthConfig {
        enabled: true,
        ..OAuthConfig::default()
    };
    let IdentifyingVars {
        issuer,
        jwks_uri,
        audience,
        audiences,
        resource,
    } = identifying;
    if let Some(v) = take(issuer, &mut problems) {
        cfg.issuer = v;
    }
    cfg.jwks_uri = take(jwks_uri, &mut problems);
    if let Some(v) = take(audience, &mut problems) {
        cfg.audience = v;
    }
    if let Some(v) = take(audiences, &mut problems) {
        cfg.audiences = split_list(&v);
    }
    if let Some(v) = take(resource, &mut problems) {
        cfg.resource = v;
    }

    cfg.required_scope = take(field("required_scope"), &mut problems);
    if let Some(v) = take(field("required_scopes"), &mut problems) {
        cfg.required_scopes = split_list(&v);
    }
    // Left `None` when unset; `EnvOAuthConfig::resolve` supplies the default.
    cfg.scopes_supported = take(field("scopes_supported"), &mut problems).map(|v| split_list(&v));
    if let Some(v) = take(field("scope_claims"), &mut problems) {
        cfg.scope_claims = split_list(&v);
    }
    if let Some(v) = take(field("principal_claims"), &mut problems) {
        cfg.principal_claims = split_list(&v);
    }
    if let Some(v) = take(field("algorithms"), &mut problems) {
        cfg.algorithms = split_list(&v);
    }
    if let Some(v) = take(field("leeway_secs"), &mut problems) {
        match v.parse::<u64>() {
            Ok(n) => cfg.leeway_secs = n,
            Err(_) => problems.push(ConfigProblem::new(
                ProblemKind::EnvParse,
                [naming.key("leeway_secs")],
                format!(
                    "{} {v:?} is not a valid non-negative integer",
                    naming.key("leeway_secs")
                ),
            )),
        }
    }
    if let Some(v) = take(field("allowed_client_ids"), &mut problems) {
        cfg.allowed_client_ids = split_list(&v);
    }
    if let Some(v) = take(field("max_token_age_secs"), &mut problems) {
        match v.parse::<u64>() {
            Ok(n) => cfg.max_token_age_secs = Some(n),
            Err(_) => problems.push(ConfigProblem::new(
                ProblemKind::EnvParse,
                [naming.key("max_token_age_secs")],
                format!(
                    "{} {v:?} is not a valid non-negative integer",
                    naming.key("max_token_age_secs")
                ),
            )),
        }
    }
    if let Some(v) = take(field("required_claims"), &mut problems) {
        // One JSON object, `{"claim": value, ...}`: a claim value can be a
        // string, number or boolean, which a whitespace-split list cannot
        // carry. `resolve` checks the entries themselves.
        match serde_json::from_str::<serde_json::Value>(&v) {
            Ok(serde_json::Value::Object(map)) => cfg.required_claims = map.into_iter().collect(),
            Ok(_) => problems.push(ConfigProblem::new(
                ProblemKind::EnvParse,
                [naming.key("required_claims")],
                format!(
                    "{} must be a JSON object, e.g. {{\"tid\": \"<tenant id>\"}}",
                    naming.key("required_claims")
                ),
            )),
            Err(e) => problems.push(ConfigProblem::new(
                ProblemKind::EnvParse,
                [naming.key("required_claims")],
                format!(
                    "{} is not valid JSON ({e}); it must be a JSON object, e.g. \
                     {{\"tid\": \"<tenant id>\"}}",
                    naming.key("required_claims")
                ),
            )),
        }
    }
    for (name, slot) in [
        ("require_at_jwt", &mut cfg.require_at_jwt),
        ("allow_unscoped_tokens", &mut cfg.allow_unscoped_tokens),
        ("allow_insecure_http", &mut cfg.allow_insecure_http),
        ("accept_static_bearer", &mut cfg.accept_static_bearer),
    ] {
        if let Some(v) = take(field(name), &mut problems) {
            match parse_strict_bool(&v) {
                Ok(b) => *slot = b,
                Err(()) => problems.push(bool_problem(naming, name, &v)),
            }
        }
    }

    Some(EnvOAuthConfig {
        config: cfg,
        problems: problems.iter().map(|p| p.message().to_string()).collect(),
        details: problems,
        prefix: prefix.to_string(),
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::collections::HashMap;

    // ── secret_from_lookup / secret_from_env ────────────────────────────────

    fn lookup_from<'a>(
        vars: &'a HashMap<&'static str, &'static str>,
    ) -> impl Fn(&str) -> Option<String> + 'a {
        move |k| vars.get(k).map(|v| v.to_string())
    }

    fn files_from<'a>(
        files: &'a HashMap<&'static str, &'static str>,
    ) -> impl Fn(&str) -> io::Result<String> + 'a {
        move |p| {
            files
                .get(p)
                .map(|c| c.to_string())
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no such file"))
        }
    }

    #[test]
    fn absent_is_none() {
        let vars = HashMap::new();
        let files = HashMap::new();
        // `EnvError` wraps `std::io::Error`, which has no `PartialEq`, so
        // `Result<_, EnvError>` cannot be compared with `assert_eq!` directly
        // — unwrap the `Ok` side first throughout this module's tests.
        assert_eq!(
            secret_from_lookup("FOO", lookup_from(&vars), files_from(&files)).unwrap(),
            None
        );
    }

    #[test]
    fn direct_value_is_trimmed() {
        let vars = HashMap::from([("FOO", "  bar  ")]);
        let files = HashMap::new();
        assert_eq!(
            secret_from_lookup("FOO", lookup_from(&vars), files_from(&files)).unwrap(),
            Some("bar".to_string())
        );
    }

    #[test]
    fn direct_value_empty_or_whitespace_is_none() {
        for value in ["", "   "] {
            let vars = HashMap::from([("FOO", value)]);
            let files = HashMap::new();
            assert_eq!(
                secret_from_lookup("FOO", lookup_from(&vars), files_from(&files)).unwrap(),
                None,
                "{value:?} should read as unset"
            );
        }
    }

    #[test]
    fn file_value_is_read_and_trimmed() {
        let vars = HashMap::from([("FOO_FILE", "/run/secrets/foo")]);
        let files = HashMap::from([("/run/secrets/foo", "bar\n")]);
        assert_eq!(
            secret_from_lookup("FOO", lookup_from(&vars), files_from(&files)).unwrap(),
            Some("bar".to_string())
        );
    }

    /// A value no error message could contain by coincidence.
    const SENTINEL: &str = "s3cr3t-sentinel";

    /// Neither `Display` nor `Debug` of `err` may contain [`SENTINEL`].
    fn assert_no_leak(err: &EnvError) {
        let display = err.to_string();
        let debug = format!("{err:?}");
        assert!(!display.contains(SENTINEL), "Display leaks: {display}");
        assert!(!debug.contains(SENTINEL), "Debug leaks: {debug}");
    }

    #[test]
    fn both_set_is_an_error_naming_var_and_path_only() {
        let vars = HashMap::from([("FOO", SENTINEL), ("FOO_FILE", "/run/secrets/foo")]);
        let files = HashMap::from([("/run/secrets/foo", SENTINEL)]);
        let err = secret_from_lookup("FOO", lookup_from(&vars), files_from(&files)).unwrap_err();
        let text = err.to_string();
        assert!(text.contains("FOO"), "{text}");
        assert!(text.contains("FOO_FILE"), "{text}");
        assert!(text.contains("/run/secrets/foo"), "{text}");
        assert!(matches!(err, EnvError::BothSet { .. }));
        assert_no_leak(&err);
    }

    #[test]
    fn unreadable_file_is_an_error_naming_the_path() {
        let vars = HashMap::from([("FOO_FILE", "/run/secrets/missing")]);
        let files = HashMap::new();
        let err = secret_from_lookup("FOO", lookup_from(&vars), files_from(&files)).unwrap_err();
        assert!(matches!(err, EnvError::ReadFailed { .. }));
        let text = err.to_string();
        assert!(text.contains("FOO_FILE"), "{text}");
        assert!(text.contains("/run/secrets/missing"), "{text}");
        // The I/O cause is the source, not part of Display, so a chain-walking
        // reporter prints it once.
        assert!(!text.contains("no such file"), "{text}");
        let source = std::error::Error::source(&err).expect("the I/O error is the source");
        assert_eq!(source.to_string(), "no such file");
    }

    /// A `ConfigError` problem has no source chain, so the loader appends the
    /// I/O cause to a `ReadFailed` problem itself — exactly once.
    #[test]
    fn a_read_failure_problem_carries_its_io_cause_once() {
        let vars = HashMap::from([
            ("APP_OAUTH_ISSUER_FILE", "/run/secrets/missing"),
            ("APP_OAUTH_AUDIENCE", "client-id"),
            ("APP_OAUTH_RESOURCE", "https://svc.example.test/api"),
        ]);
        let files = HashMap::new();
        let err = oauth_config_from_lookup("APP_OAUTH_", lookup_from(&vars), files_from(&files))
            .unwrap_err();
        assert_eq!(
            err.problems[0],
            "APP_OAUTH_ISSUER_FILE=/run/secrets/missing: failed to read secret file: no such file"
        );
        assert_eq!(err.to_string().matches("no such file").count(), 1);
    }

    /// `read_to_string` fails on a file that exists but is not valid UTF-8,
    /// after reading its bytes. Neither the I/O error nor `ReadFailed` may
    /// carry those bytes. The injected reader stands in for a file holding the
    /// sentinel, failing the way `read_to_string` does.
    #[test]
    fn a_file_that_fails_to_decode_does_not_leak_its_contents() {
        let vars = HashMap::from([("FOO_FILE", "/run/secrets/foo")]);
        let files = HashMap::from([("/run/secrets/foo", SENTINEL)]);
        let read_file = |path: &str| -> io::Result<String> {
            assert!(files.contains_key(path), "unexpected path {path}");
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "stream did not contain valid UTF-8",
            ))
        };
        let err = secret_from_lookup("FOO", lookup_from(&vars), read_file).unwrap_err();
        assert!(matches!(err, EnvError::ReadFailed { .. }));
        assert_no_leak(&err);
    }

    #[test]
    fn empty_file_is_an_error_not_none() {
        // The file is blank, so the only secret around is in a neighbouring
        // variable, which the error must not pick up either.
        let vars = HashMap::from([("FOO_FILE", "/run/secrets/foo"), ("FOO_TOKEN", SENTINEL)]);
        let files = HashMap::from([("/run/secrets/foo", "   \n")]);
        let err = secret_from_lookup("FOO", lookup_from(&vars), files_from(&files)).unwrap_err();
        assert!(matches!(err, EnvError::EmptyFile { .. }));
        let text = err.to_string();
        assert!(text.contains("FOO_FILE"), "{text}");
        assert!(text.contains("/run/secrets/foo"), "{text}");
        assert_no_leak(&err);
    }

    #[test]
    fn secret_from_env_wraps_the_real_environment() {
        // No var of this name is plausibly set in CI; this only exercises that
        // the plain function delegates without panicking.
        assert_eq!(
            secret_from_env("OAUTH_RESOURCE_SERVER_ENV_RS_TEST_UNSET_VAR_9f3c").unwrap(),
            None
        );
    }

    // ── oauth_config_from_lookup ─────────────────────────────────────────────

    /// A lookup that also records every variable it was asked about, so a
    /// test can assert which variables `oauth_config_from_lookup` consults
    /// when OAuth turns out to be off.
    struct RecordingLookup<'a> {
        vars: &'a HashMap<&'static str, &'static str>,
        calls: Cell<Vec<String>>,
    }

    impl<'a> RecordingLookup<'a> {
        fn new(vars: &'a HashMap<&'static str, &'static str>) -> Self {
            Self {
                vars,
                calls: Cell::new(Vec::new()),
            }
        }

        fn call(&self, var: &str) -> Option<String> {
            let mut calls = self.calls.take();
            calls.push(var.to_string());
            self.calls.set(calls);
            self.vars.get(var).map(|v| v.to_string())
        }
    }

    #[test]
    fn nothing_set_is_none_and_touches_only_identifying_variables() {
        let vars = HashMap::new();
        let files = HashMap::new();
        let recorder = RecordingLookup::new(&vars);
        let result =
            oauth_config_from_lookup("APP_OAUTH_", |v| recorder.call(v), files_from(&files));
        assert_eq!(result, Ok(None));
        let calls = recorder.calls.take();
        for var in &calls {
            assert!(
                var.starts_with("APP_OAUTH_")
                    && (var.ends_with("ENABLED")
                        || var.ends_with("ENABLED_FILE")
                        || var.ends_with("ISSUER")
                        || var.ends_with("ISSUER_FILE")
                        || var.ends_with("JWKS_URI")
                        || var.ends_with("JWKS_URI_FILE")
                        || var.ends_with("AUDIENCE")
                        || var.ends_with("AUDIENCE_FILE")
                        || var.ends_with("AUDIENCES")
                        || var.ends_with("AUDIENCES_FILE")
                        || var.ends_with("RESOURCE")
                        || var.ends_with("RESOURCE_FILE")),
                "unexpected variable consulted while OAuth is unconfigured: {var} (all: {calls:?})"
            );
        }
        assert!(!calls.is_empty(), "the identifying vars must be checked");
    }

    /// A typical prefixed variable set (`MYAPP_OAUTH_{ISSUER,JWKS_URI,
    /// AUDIENCE,RESOURCE,REQUIRED_SCOPE,SCOPES_SUPPORTED}`) resolves every
    /// field it names verbatim, splits SCOPES_SUPPORTED on whitespace, and
    /// leaves every field it does not name at the crate default.
    #[test]
    fn a_typical_prefixed_variable_set_resolves_verbatim() {
        let vars = HashMap::from([
            (
                "MYAPP_OAUTH_ISSUER",
                "https://idp.example.test/application/o/myapp/",
            ),
            (
                "MYAPP_OAUTH_JWKS_URI",
                "https://idp.example.test/application/o/myapp/jwks/",
            ),
            ("MYAPP_OAUTH_AUDIENCE", "myapp-client-id"),
            ("MYAPP_OAUTH_RESOURCE", "https://myapp.example.test/mcp"),
            ("MYAPP_OAUTH_REQUIRED_SCOPE", "myapp:read"),
            ("MYAPP_OAUTH_SCOPES_SUPPORTED", "myapp:read myapp:write"),
        ]);
        let files = HashMap::new();
        let resolved =
            oauth_config_from_lookup("MYAPP_OAUTH_", lookup_from(&vars), files_from(&files))
                .unwrap()
                .expect("identifying vars are set");

        assert_eq!(
            resolved.issuer,
            "https://idp.example.test/application/o/myapp/"
        );
        assert_eq!(
            resolved.jwks_uri.as_deref(),
            Some("https://idp.example.test/application/o/myapp/jwks/")
        );
        assert_eq!(resolved.audience, "myapp-client-id");
        assert_eq!(resolved.resource, "https://myapp.example.test/mcp");
        assert_eq!(resolved.required_scopes, ["myapp:read"]);
        assert_eq!(resolved.scopes_supported, ["myapp:read", "myapp:write"]);
        // Fields the variable set does not name keep the crate's defaults.
        assert_eq!(resolved.scope_claims, ["scope", "scp"]);
        assert!(!resolved.require_at_jwt);
        assert!(resolved.accept_static_bearer);
    }

    #[test]
    fn jwks_uri_alone_counts_as_identifying_even_though_resolve_does_not_require_it() {
        let vars = HashMap::from([("APP_OAUTH_JWKS_URI", "https://idp.example.test/jwks")]);
        let files = HashMap::new();
        let err = oauth_config_from_lookup("APP_OAUTH_", lookup_from(&vars), files_from(&files))
            .unwrap_err();
        // Enabled, but issuer/audience/resource are still required — jwks_uri
        // alone does not satisfy them.
        assert!(err.problems.iter().any(|p| p.contains("APP_OAUTH_ISSUER")));
        assert!(
            !err.problems
                .iter()
                .any(|p| p.contains("APP_OAUTH_JWKS_URI"))
        );
    }

    #[test]
    fn partial_set_is_an_error_listing_what_is_missing() {
        let vars = HashMap::from([("APP_OAUTH_ISSUER", "https://idp.example.test/")]);
        let files = HashMap::new();
        let err = oauth_config_from_lookup("APP_OAUTH_", lookup_from(&vars), files_from(&files))
            .unwrap_err();
        let text = err.to_string();
        assert!(text.contains("APP_OAUTH_AUDIENCE"), "{text}");
        assert!(text.contains("APP_OAUTH_RESOURCE"), "{text}");
    }

    #[test]
    fn a_both_set_error_on_an_identifying_variable_still_counts_as_configured() {
        let vars = HashMap::from([
            ("APP_OAUTH_ISSUER", "https://idp.example.test/"),
            ("APP_OAUTH_ISSUER_FILE", "/run/secrets/issuer"),
        ]);
        let files = HashMap::from([("/run/secrets/issuer", "https://idp.example.test/")]);
        let err = oauth_config_from_lookup("APP_OAUTH_", lookup_from(&vars), files_from(&files))
            .unwrap_err();
        // The load failure is reported first — it is the actual cause.
        assert!(
            err.problems[0].contains("APP_OAUTH_ISSUER") && err.problems[0].contains("both set"),
            "{:?}",
            err.problems
        );
        // ISSUER then never got a value, so `resolve` also lists it among the
        // empty required settings. The duplication is accepted (and documented
        // on `oauth_config_from_env`): suppressing it would mean rewriting
        // `resolve`'s message, and the first entry already names the cause.
        assert!(
            err.problems[1..]
                .iter()
                .any(|p| p.starts_with("these required settings are empty")
                    && p.contains("APP_OAUTH_ISSUER")),
            "{:?}",
            err.problems
        );
    }

    /// An unset SCOPES_SUPPORTED advertises the required scope, so the metadata and
    /// the 401 challenge tell a client what to ask for.
    #[test]
    fn scopes_supported_defaults_to_the_required_scope() {
        let vars = HashMap::from([
            ("MYAPP_OAUTH_ISSUER", "https://idp.example.test/"),
            ("MYAPP_OAUTH_JWKS_URI", "http://127.0.0.1:1/jwks"),
            ("MYAPP_OAUTH_AUDIENCE", "myapp-client-id"),
            ("MYAPP_OAUTH_RESOURCE", "https://myapp.example.test/mcp"),
            ("MYAPP_OAUTH_REQUIRED_SCOPE", "myapp:read"),
        ]);
        let files = HashMap::new();
        let resolved =
            oauth_config_from_lookup("MYAPP_OAUTH_", lookup_from(&vars), files_from(&files))
                .unwrap()
                .unwrap();
        assert_eq!(resolved.required_scopes, ["myapp:read"]);
        assert_eq!(resolved.scopes_supported, ["myapp:read"]);
    }

    #[test]
    fn scopes_supported_default_unions_required_scopes_in_order_without_duplicates() {
        let vars = HashMap::from([
            ("APP_OAUTH_ISSUER", "https://idp.example.test/"),
            ("APP_OAUTH_AUDIENCE", "client-id"),
            ("APP_OAUTH_RESOURCE", "https://svc.example.test/api"),
            ("APP_OAUTH_REQUIRED_SCOPE", "api:read"),
            ("APP_OAUTH_REQUIRED_SCOPES", "api:write api:read"),
        ]);
        let files = HashMap::new();
        let resolved =
            oauth_config_from_lookup("APP_OAUTH_", lookup_from(&vars), files_from(&files))
                .unwrap()
                .unwrap();
        assert_eq!(resolved.scopes_supported, ["api:read", "api:write"]);
    }

    #[test]
    fn scopes_supported_stays_empty_with_no_required_scope() {
        let vars = HashMap::from([
            ("APP_OAUTH_ISSUER", "https://idp.example.test/"),
            ("APP_OAUTH_AUDIENCE", "client-id"),
            ("APP_OAUTH_RESOURCE", "https://svc.example.test/api"),
            // No scope at all needs the explicit opt-in.
            ("APP_OAUTH_ALLOW_UNSCOPED_TOKENS", "true"),
            // Blank reads as unset: it cannot mean "explicitly empty".
            ("APP_OAUTH_SCOPES_SUPPORTED", "  "),
        ]);
        let files = HashMap::new();
        let resolved =
            oauth_config_from_lookup("APP_OAUTH_", lookup_from(&vars), files_from(&files))
                .unwrap()
                .unwrap();
        assert!(resolved.required_scopes.is_empty());
        assert!(resolved.scopes_supported.is_empty());
    }

    #[test]
    fn explicit_scopes_supported_is_not_replaced_by_the_default() {
        let vars = HashMap::from([
            ("APP_OAUTH_ISSUER", "https://idp.example.test/"),
            ("APP_OAUTH_AUDIENCE", "client-id"),
            ("APP_OAUTH_RESOURCE", "https://svc.example.test/api"),
            ("APP_OAUTH_REQUIRED_SCOPE", "api:read"),
            ("APP_OAUTH_SCOPES_SUPPORTED", "api:admin"),
        ]);
        let files = HashMap::new();
        let resolved =
            oauth_config_from_lookup("APP_OAUTH_", lookup_from(&vars), files_from(&files))
                .unwrap()
                .unwrap();
        assert_eq!(resolved.scopes_supported, ["api:admin"]);
    }

    #[test]
    fn enabled_true_alone_turns_oauth_on_and_reports_what_is_missing() {
        let vars = HashMap::from([("APP_OAUTH_ENABLED", "true")]);
        let files = HashMap::new();
        let err = oauth_config_from_lookup("APP_OAUTH_", lookup_from(&vars), files_from(&files))
            .unwrap_err();
        let text = err.to_string();
        assert!(text.contains("APP_OAUTH_ISSUER"), "{text}");
        assert!(text.contains("APP_OAUTH_AUDIENCE"), "{text}");
        assert!(text.contains("APP_OAUTH_RESOURCE"), "{text}");
    }

    #[test]
    fn enabled_true_with_a_complete_set_resolves() {
        let vars = HashMap::from([
            ("APP_OAUTH_ENABLED", "true"),
            ("APP_OAUTH_ISSUER", "https://idp.example.test/"),
            ("APP_OAUTH_AUDIENCE", "client-id"),
            ("APP_OAUTH_RESOURCE", "https://svc.example.test/api"),
            ("APP_OAUTH_REQUIRED_SCOPE", "api:read"),
        ]);
        let files = HashMap::new();
        let resolved =
            oauth_config_from_lookup("APP_OAUTH_", lookup_from(&vars), files_from(&files)).unwrap();
        assert!(resolved.is_some());
    }

    #[test]
    fn enabled_false_turns_oauth_off_without_reading_anything_else() {
        let vars = HashMap::from([
            ("APP_OAUTH_ENABLED", "false"),
            ("APP_OAUTH_ISSUER", "https://idp.example.test/"),
            ("APP_OAUTH_AUDIENCE", "client-id"),
            ("APP_OAUTH_RESOURCE", "https://svc.example.test/api"),
            // Would be an error if it were read.
            ("APP_OAUTH_LEEWAY_SECS", "not-a-number"),
        ]);
        let files = HashMap::new();
        let recorder = RecordingLookup::new(&vars);
        let result =
            oauth_config_from_lookup("APP_OAUTH_", |v| recorder.call(v), files_from(&files));
        assert_eq!(result, Ok(None));
        let calls = recorder.calls.take();
        assert_eq!(calls, ["APP_OAUTH_ENABLED", "APP_OAUTH_ENABLED_FILE"]);
    }

    #[test]
    fn enabled_from_a_file_is_honoured() {
        let vars = HashMap::from([
            ("APP_OAUTH_ENABLED_FILE", "/run/secrets/enabled"),
            ("APP_OAUTH_ISSUER", "https://idp.example.test/"),
        ]);
        let files = HashMap::from([("/run/secrets/enabled", "false\n")]);
        assert_eq!(
            oauth_config_from_lookup("APP_OAUTH_", lookup_from(&vars), files_from(&files)),
            Ok(None)
        );
    }

    #[test]
    fn an_unparsable_enabled_is_reported_and_treated_as_on() {
        let vars = HashMap::from([("APP_OAUTH_ENABLED", "yes")]);
        let files = HashMap::new();
        let err = oauth_config_from_lookup("APP_OAUTH_", lookup_from(&vars), files_from(&files))
            .unwrap_err();
        assert!(
            err.problems[0].contains("APP_OAUTH_ENABLED")
                && err.problems[0].contains("must be \"true\" or \"false\""),
            "{:?}",
            err.problems
        );
        // Treated as on, so the rest is checked in the same run.
        assert!(err.to_string().contains("APP_OAUTH_ISSUER"));
    }

    #[test]
    fn an_enabled_that_fails_to_load_is_reported_and_treated_as_on() {
        let vars = HashMap::from([("APP_OAUTH_ENABLED_FILE", "/run/secrets/missing")]);
        let files = HashMap::new();
        let err = oauth_config_from_lookup("APP_OAUTH_", lookup_from(&vars), files_from(&files))
            .unwrap_err();
        assert!(
            err.problems[0].contains("APP_OAUTH_ENABLED_FILE"),
            "{:?}",
            err.problems
        );
        assert!(err.to_string().contains("APP_OAUTH_ISSUER"));
    }

    #[test]
    fn loader_problems_carry_env_load_and_env_parse_kinds() {
        let vars = HashMap::from([
            ("APP_OAUTH_ISSUER", "https://idp.example.test/"),
            ("APP_OAUTH_ISSUER_FILE", "/run/secrets/issuer"),
            ("APP_OAUTH_AUDIENCE_FILE", "/run/secrets/missing"),
            ("APP_OAUTH_RESOURCE", "https://kb.example.test/"),
            ("APP_OAUTH_REQUIRE_AT_JWT", "yes"),
            ("APP_OAUTH_LEEWAY_SECS", "soon"),
            ("APP_OAUTH_ALLOW_UNSCOPED_TOKENS_FILE", "/run/secrets/empty"),
        ]);
        let files = HashMap::from([("/run/secrets/empty", "  ")]);
        let loaded = unresolved_oauth_config_from_lookup(
            "APP_OAUTH_",
            lookup_from(&vars),
            files_from(&files),
        )
        .unwrap();
        let got: Vec<_> = loaded
            .problem_details()
            .iter()
            .map(|p| (p.kind(), p.keys().to_vec()))
            .collect();
        let env = |v: &str| vec![v.to_string()];
        assert_eq!(
            got,
            [
                (
                    ProblemKind::EnvLoad,
                    vec![
                        "APP_OAUTH_ISSUER".to_string(),
                        "APP_OAUTH_ISSUER_FILE".to_string()
                    ],
                ),
                (ProblemKind::EnvLoad, env("APP_OAUTH_AUDIENCE_FILE")),
                (ProblemKind::EnvParse, env("APP_OAUTH_LEEWAY_SECS")),
                (ProblemKind::EnvParse, env("APP_OAUTH_REQUIRE_AT_JWT")),
                (
                    ProblemKind::EnvLoad,
                    env("APP_OAUTH_ALLOW_UNSCOPED_TOKENS_FILE")
                ),
            ]
        );
        // The strings are rendered from the same list, in the same order.
        let texts: Vec<&str> = loaded
            .problem_details()
            .iter()
            .map(ConfigProblem::message)
            .collect();
        assert_eq!(texts, loaded.problems);

        // `resolve` carries them, then its own, into the `ConfigError`.
        let err = loaded.resolve().unwrap_err();
        assert_eq!(err.problems.len(), err.problem_details().len());
        assert_eq!(err.problem_details()[0].kind(), ProblemKind::EnvLoad);
        assert_eq!(err.problem_details()[2].kind(), ProblemKind::EnvParse);
        let texts: Vec<&str> = err
            .problem_details()
            .iter()
            .map(ConfigProblem::message)
            .collect();
        assert_eq!(texts, err.problems);
    }

    #[test]
    fn env_oauth_config_equality_ignores_the_structured_details() {
        let vars = HashMap::from([
            ("APP_OAUTH_ISSUER", "https://idp.example.test/"),
            ("APP_OAUTH_ALLOW_INSECURE_HTTP", "maybe"),
        ]);
        let files = HashMap::new();
        let load = || {
            unresolved_oauth_config_from_lookup(
                "APP_OAUTH_",
                lookup_from(&vars),
                files_from(&files),
            )
            .unwrap()
        };
        let a = load();
        let mut b = load();
        assert_eq!(a, b);
        // Same public fields, different details: still equal, as in 0.1.2.
        b.details = vec![ConfigProblem::from(a.problems[0].clone())];
        assert_eq!(a, b);
        // A differing public field is not.
        b.problems.push("extra".into());
        assert_ne!(a, b);
    }

    #[test]
    fn an_enabled_that_is_not_a_bool_is_an_env_parse_problem() {
        let vars = HashMap::from([("APP_OAUTH_ENABLED", "maybe")]);
        let files = HashMap::new();
        let err = oauth_config_from_lookup("APP_OAUTH_", lookup_from(&vars), files_from(&files))
            .unwrap_err();
        let p = &err.problem_details()[0];
        assert_eq!(p.kind(), ProblemKind::EnvParse);
        assert_eq!(p.keys(), ["APP_OAUTH_ENABLED"]);
        // resolve's own problems keep their kinds and env-spelled keys.
        assert!(
            err.problem_details()
                .iter()
                .any(|p| p.kind() == ProblemKind::MissingRequired
                    && p.keys().contains(&"APP_OAUTH_ISSUER".to_string()))
        );
    }

    #[test]
    fn edited_problems_still_reach_resolve_as_other_and_matches_keep_their_kind() {
        let vars = HashMap::from([
            ("APP_OAUTH_ISSUER", "https://idp.example.test/"),
            ("APP_OAUTH_AUDIENCE", "client-id"),
            ("APP_OAUTH_RESOURCE", "https://kb.example.test/"),
            ("APP_OAUTH_ALLOW_UNSCOPED_TOKENS", "maybe"),
        ]);
        let files = HashMap::new();
        let mut loaded = unresolved_oauth_config_from_lookup(
            "APP_OAUTH_",
            lookup_from(&vars),
            files_from(&files),
        )
        .unwrap();
        loaded.problems.insert(0, "app-side problem".into());
        // `problem_details` is fixed at load time.
        assert_eq!(loaded.problem_details().len(), 1);
        let err = loaded.resolve().unwrap_err();
        assert_eq!(err.problems[0], "app-side problem");
        assert_eq!(err.problem_details()[0].kind(), ProblemKind::Other);
        assert_eq!(err.problem_details()[1].kind(), ProblemKind::EnvParse);
    }

    #[test]
    fn whitespace_lists_are_split() {
        let vars = HashMap::from([
            ("APP_OAUTH_ISSUER", "https://idp.example.test/"),
            ("APP_OAUTH_AUDIENCE", "client-id"),
            ("APP_OAUTH_RESOURCE", "https://svc.example.test/api"),
            ("APP_OAUTH_REQUIRED_SCOPES", "  api:read   api:write  "),
            ("APP_OAUTH_AUDIENCES", "extra-aud another-aud"),
            ("APP_OAUTH_ALGORITHMS", "RS256 ES256"),
        ]);
        let files = HashMap::new();
        let resolved =
            oauth_config_from_lookup("APP_OAUTH_", lookup_from(&vars), files_from(&files))
                .unwrap()
                .unwrap();
        assert_eq!(resolved.required_scopes, ["api:read", "api:write"]);
        assert_eq!(
            resolved.accepted_audiences(),
            ["client-id", "extra-aud", "another-aud"]
        );
        assert!(resolved.algorithms.contains(&crate::Algorithm::RS256));
        assert!(resolved.algorithms.contains(&crate::Algorithm::ES256));
    }

    #[test]
    fn parse_errors_for_bool_and_integer_fields_are_aggregated_with_other_problems() {
        let vars = HashMap::from([
            ("APP_OAUTH_ISSUER", "https://idp.example.test/"),
            ("APP_OAUTH_AUDIENCE", "client-id"),
            ("APP_OAUTH_RESOURCE", "https://svc.example.test/api"),
            ("APP_OAUTH_REQUIRED_SCOPE", "api:read"),
            ("APP_OAUTH_LEEWAY_SECS", "not-a-number"),
            ("APP_OAUTH_REQUIRE_AT_JWT", "yes"),
            ("APP_OAUTH_ACCEPT_STATIC_BEARER", "0"),
        ]);
        let files = HashMap::new();
        let err = oauth_config_from_lookup("APP_OAUTH_", lookup_from(&vars), files_from(&files))
            .unwrap_err();
        assert_eq!(err.problems.len(), 3, "{:?}", err.problems);
        let text = err.to_string();
        assert!(text.contains("APP_OAUTH_LEEWAY_SECS"), "{text}");
        assert!(text.contains("not-a-number"), "{text}");
        assert!(text.contains("APP_OAUTH_REQUIRE_AT_JWT"), "{text}");
        assert!(text.contains("APP_OAUTH_ACCEPT_STATIC_BEARER"), "{text}");
    }

    #[test]
    fn strict_bool_parsing_accepts_only_true_and_false() {
        for good in ["true", "false"] {
            let vars = HashMap::from([
                ("APP_OAUTH_ISSUER", "https://idp.example.test/"),
                ("APP_OAUTH_AUDIENCE", "client-id"),
                ("APP_OAUTH_RESOURCE", "https://svc.example.test/api"),
                ("APP_OAUTH_REQUIRED_SCOPE", "api:read"),
                ("APP_OAUTH_REQUIRE_AT_JWT", good),
            ]);
            let files = HashMap::new();
            let resolved =
                oauth_config_from_lookup("APP_OAUTH_", lookup_from(&vars), files_from(&files))
                    .unwrap()
                    .unwrap();
            assert_eq!(resolved.require_at_jwt, good == "true");
        }
        for bad in ["True", "FALSE", "1", "0", "yes"] {
            let vars = HashMap::from([
                ("APP_OAUTH_ISSUER", "https://idp.example.test/"),
                ("APP_OAUTH_AUDIENCE", "client-id"),
                ("APP_OAUTH_RESOURCE", "https://svc.example.test/api"),
                ("APP_OAUTH_REQUIRED_SCOPE", "api:read"),
                ("APP_OAUTH_REQUIRE_AT_JWT", bad),
            ]);
            let files = HashMap::new();
            let result =
                oauth_config_from_lookup("APP_OAUTH_", lookup_from(&vars), files_from(&files));
            assert!(result.is_err(), "{bad:?} should be rejected");
        }
        // An empty value reads as unset, not a parse failure.
        let vars = HashMap::from([
            ("APP_OAUTH_ISSUER", "https://idp.example.test/"),
            ("APP_OAUTH_AUDIENCE", "client-id"),
            ("APP_OAUTH_RESOURCE", "https://svc.example.test/api"),
            ("APP_OAUTH_REQUIRED_SCOPE", "api:read"),
            ("APP_OAUTH_REQUIRE_AT_JWT", ""),
        ]);
        let files = HashMap::new();
        let resolved =
            oauth_config_from_lookup("APP_OAUTH_", lookup_from(&vars), files_from(&files))
                .unwrap()
                .unwrap();
        assert!(!resolved.require_at_jwt);
    }

    #[test]
    fn the_explicit_opt_ins_are_read_as_strict_booleans() {
        let files = HashMap::new();
        let vars = HashMap::from([
            ("APP_OAUTH_ISSUER", "http://idp.internal.test/"),
            ("APP_OAUTH_AUDIENCE", "client-id"),
            ("APP_OAUTH_RESOURCE", "https://svc.example.test/api"),
            ("APP_OAUTH_ALLOW_UNSCOPED_TOKENS", "true"),
            ("APP_OAUTH_ALLOW_INSECURE_HTTP", "true"),
        ]);
        let resolved =
            oauth_config_from_lookup("APP_OAUTH_", lookup_from(&vars), files_from(&files))
                .unwrap()
                .unwrap();
        assert!(resolved.allow_unscoped_tokens && resolved.allow_insecure_http);

        // Without them, both are problems — named by variable.
        let mut vars = vars;
        vars.remove("APP_OAUTH_ALLOW_UNSCOPED_TOKENS");
        vars.insert("APP_OAUTH_ALLOW_INSECURE_HTTP", "yes");
        let err = oauth_config_from_lookup("APP_OAUTH_", lookup_from(&vars), files_from(&files))
            .unwrap_err();
        let text = err.to_string();
        assert!(
            text.contains("APP_OAUTH_ALLOW_INSECURE_HTTP \"yes\" must be"),
            "{text}"
        );
        assert!(
            text.contains("APP_OAUTH_ISSUER \"http://idp.internal.test/\" uses plain http"),
            "{text}"
        );
        assert!(
            text.contains("set APP_OAUTH_ALLOW_UNSCOPED_TOKENS"),
            "{text}"
        );
    }

    #[test]
    fn problem_messages_are_named_with_the_configured_prefix() {
        let vars = HashMap::from([("MYAPP_OAUTH_ISSUER", "https://idp.example.test/")]);
        let files = HashMap::new();
        let err = oauth_config_from_lookup("MYAPP_OAUTH_", lookup_from(&vars), files_from(&files))
            .unwrap_err();
        let text = err.to_string();
        assert!(text.starts_with(
            "OAuth is configured through MYAPP_OAUTH_* but the config is not usable:"
        ));
        assert!(text.contains("MYAPP_OAUTH_AUDIENCE"), "{text}");
        assert!(text.contains("MYAPP_OAUTH_RESOURCE"), "{text}");
        assert!(!text.contains("mcp.oauth"), "{text}");
    }

    // ── unresolved_oauth_config_from_lookup / EnvOAuthConfig ────────────────

    /// A complete set with no scope configured.
    fn base_vars() -> HashMap<&'static str, &'static str> {
        HashMap::from([
            ("APP_OAUTH_ISSUER", "https://idp.example.test/"),
            ("APP_OAUTH_AUDIENCE", "client-id"),
            ("APP_OAUTH_RESOURCE", "https://svc.example.test/api"),
        ])
    }

    /// The pattern `EnvOAuthConfig`'s docs show: an app default for the
    /// required scope, applied only when the operator named none.
    fn with_app_scope_default(mut loaded: EnvOAuthConfig) -> EnvOAuthConfig {
        let cfg = &mut loaded.config;
        if cfg.required_scope.is_none() && cfg.required_scopes.is_empty() {
            cfg.required_scope = Some("mcp:read".into());
        }
        loaded
    }

    #[test]
    fn unresolved_is_none_exactly_when_oauth_is_off() {
        let files = HashMap::new();
        let nothing = HashMap::new();
        assert_eq!(
            unresolved_oauth_config_from_lookup(
                "APP_OAUTH_",
                lookup_from(&nothing),
                files_from(&files)
            ),
            None
        );
        let mut disabled = base_vars();
        disabled.insert("APP_OAUTH_ENABLED", "false");
        assert_eq!(
            unresolved_oauth_config_from_lookup(
                "APP_OAUTH_",
                lookup_from(&disabled),
                files_from(&files)
            ),
            None
        );
        let loaded = unresolved_oauth_config_from_lookup(
            "APP_OAUTH_",
            lookup_from(&base_vars()),
            files_from(&files),
        )
        .expect("identifying vars are set");
        assert!(loaded.config.enabled);
        assert_eq!(loaded.config.issuer, "https://idp.example.test/");
        assert_eq!(
            loaded.config.scopes_supported, None,
            "default not yet applied"
        );
        assert!(loaded.problems.is_empty());
        assert_eq!(loaded.prefix(), "APP_OAUTH_");
    }

    #[test]
    fn an_app_scope_default_is_enforced_and_advertised() {
        let files = HashMap::new();
        let loaded = unresolved_oauth_config_from_lookup(
            "APP_OAUTH_",
            lookup_from(&base_vars()),
            files_from(&files),
        )
        .unwrap();
        let resolved = with_app_scope_default(loaded).resolve().unwrap().unwrap();
        assert_eq!(resolved.required_scopes, ["mcp:read"]);
        // The scopes_supported default runs at resolve, so it sees the app's
        // default — the metadata and challenge advertise it.
        assert_eq!(resolved.scopes_supported, ["mcp:read"]);
    }

    #[test]
    fn an_operator_scope_wins_over_the_app_default() {
        let mut vars = base_vars();
        vars.insert("APP_OAUTH_REQUIRED_SCOPE", "api:read");
        let files = HashMap::new();
        let loaded = unresolved_oauth_config_from_lookup(
            "APP_OAUTH_",
            lookup_from(&vars),
            files_from(&files),
        )
        .unwrap();
        let resolved = with_app_scope_default(loaded).resolve().unwrap().unwrap();
        assert_eq!(resolved.required_scopes, ["api:read"]);
        assert_eq!(resolved.scopes_supported, ["api:read"]);
    }

    #[test]
    fn an_app_default_goes_through_resolves_validation() {
        let files = HashMap::new();
        let mut loaded = unresolved_oauth_config_from_lookup(
            "APP_OAUTH_",
            lookup_from(&base_vars()),
            files_from(&files),
        )
        .unwrap();
        loaded.config.required_scope = Some("mcp:read mcp:write".into());
        let err = loaded.resolve().unwrap_err();
        assert!(
            err.problems
                .iter()
                .any(|p| p.contains("APP_OAUTH_REQUIRED_SCOPE") && p.contains("single scope")),
            "{:?}",
            err.problems
        );
    }

    #[test]
    fn an_app_set_explicit_empty_scopes_supported_is_kept() {
        let mut vars = base_vars();
        vars.insert("APP_OAUTH_REQUIRED_SCOPE", "api:read");
        let files = HashMap::new();
        let mut loaded = unresolved_oauth_config_from_lookup(
            "APP_OAUTH_",
            lookup_from(&vars),
            files_from(&files),
        )
        .unwrap();
        loaded.config.scopes_supported = Some(vec![]);
        let resolved = loaded.resolve().unwrap().unwrap();
        assert!(resolved.scopes_supported.is_empty());
    }

    #[test]
    fn loader_problems_are_carried_and_reported_first_by_resolve() {
        let mut vars = base_vars();
        vars.insert("APP_OAUTH_LEEWAY_SECS", "soon");
        vars.remove("APP_OAUTH_RESOURCE");
        let files = HashMap::new();
        let loaded = unresolved_oauth_config_from_lookup(
            "APP_OAUTH_",
            lookup_from(&vars),
            files_from(&files),
        )
        .unwrap();
        assert_eq!(loaded.problems.len(), 1, "{:?}", loaded.problems);
        assert!(loaded.problems[0].contains("APP_OAUTH_LEEWAY_SECS"));
        let err = loaded.resolve().unwrap_err();
        assert!(
            err.problems[0].contains("APP_OAUTH_LEEWAY_SECS"),
            "{:?}",
            err.problems
        );
        assert!(
            err.problems[1..]
                .iter()
                .any(|p| p.contains("APP_OAUTH_RESOURCE")),
            "{:?}",
            err.problems
        );
    }

    #[test]
    fn loader_problems_fail_resolve_even_when_the_config_is_otherwise_valid() {
        let mut vars = base_vars();
        vars.insert("APP_OAUTH_REQUIRED_SCOPE", "api:read");
        vars.insert("APP_OAUTH_REQUIRE_AT_JWT", "yes");
        let files = HashMap::new();
        let loaded = unresolved_oauth_config_from_lookup(
            "APP_OAUTH_",
            lookup_from(&vars),
            files_from(&files),
        )
        .unwrap();
        let err = loaded.resolve().unwrap_err();
        assert_eq!(err.problems.len(), 1, "{:?}", err.problems);
        assert!(err.problems[0].contains("APP_OAUTH_REQUIRE_AT_JWT"));
    }

    #[test]
    fn unresolved_oauth_config_from_env_wraps_the_real_environment() {
        assert_eq!(
            unresolved_oauth_config_from_env("OAUTH_RESOURCE_SERVER_ENV_RS_TEST_UNSET_9f3c_"),
            None
        );
    }

    #[test]
    fn oauth_config_from_env_wraps_the_real_environment() {
        // No var of this prefix is plausibly set in CI; this only exercises
        // that the plain function delegates without panicking.
        assert_eq!(
            oauth_config_from_env("OAUTH_RESOURCE_SERVER_ENV_RS_TEST_UNSET_9f3c_"),
            Ok(None)
        );
    }
    // ── allowed_client_ids, max_token_age_secs, required_claims ─────────────

    fn policy_vars() -> HashMap<&'static str, &'static str> {
        HashMap::from([
            ("APP_OAUTH_ISSUER", "https://idp.example.test/"),
            ("APP_OAUTH_AUDIENCE", "client-a"),
            ("APP_OAUTH_RESOURCE", "https://kb.example.test/"),
            ("APP_OAUTH_REQUIRED_SCOPE", "api:read"),
        ])
    }

    #[test]
    fn the_claim_policy_settings_load_from_their_variables() {
        let mut vars = policy_vars();
        vars.insert("APP_OAUTH_ALLOWED_CLIENT_IDS", "client-a  client-b");
        vars.insert("APP_OAUTH_MAX_TOKEN_AGE_SECS", "3600");
        vars.insert(
            "APP_OAUTH_REQUIRED_CLAIMS",
            r#"{"tid": "tenant-1", "level": 2, "mfa": true}"#,
        );
        let files = HashMap::new();
        let resolved =
            oauth_config_from_lookup("APP_OAUTH_", lookup_from(&vars), files_from(&files))
                .unwrap()
                .unwrap();
        assert_eq!(resolved.allowed_client_ids, ["client-a", "client-b"]);
        assert_eq!(resolved.max_token_age_secs, Some(3600));
        assert_eq!(
            resolved.required_claims,
            [
                ("level".to_string(), serde_json::json!(2)),
                ("mfa".to_string(), serde_json::json!(true)),
                ("tid".to_string(), serde_json::json!("tenant-1")),
            ]
            .into_iter()
            .collect()
        );

        // Unset: every one stays off.
        let vars = policy_vars();
        let resolved =
            oauth_config_from_lookup("APP_OAUTH_", lookup_from(&vars), files_from(&files))
                .unwrap()
                .unwrap();
        assert!(resolved.allowed_client_ids.is_empty());
        assert_eq!(resolved.max_token_age_secs, None);
        assert!(resolved.required_claims.is_empty());
    }

    #[test]
    fn claim_policy_parse_and_resolve_problems_are_reported_together() {
        let mut vars = policy_vars();
        vars.insert("APP_OAUTH_MAX_TOKEN_AGE_SECS", "an hour");
        vars.insert("APP_OAUTH_REQUIRED_CLAIMS", r#"["tid"]"#);
        let files = HashMap::new();
        let err = oauth_config_from_lookup("APP_OAUTH_", lookup_from(&vars), files_from(&files))
            .unwrap_err();
        let got: Vec<_> = err
            .problem_details()
            .iter()
            .map(|p| (p.kind(), p.keys().to_vec()))
            .collect();
        assert_eq!(
            got,
            [
                (
                    ProblemKind::EnvParse,
                    vec!["APP_OAUTH_MAX_TOKEN_AGE_SECS".to_string()]
                ),
                (
                    ProblemKind::EnvParse,
                    vec!["APP_OAUTH_REQUIRED_CLAIMS".to_string()]
                ),
            ]
        );
        assert!(err.problems[1].contains("must be a JSON object"), "{err}");

        // Not JSON at all.
        let mut vars = policy_vars();
        vars.insert("APP_OAUTH_REQUIRED_CLAIMS", "tid=tenant-1");
        let err = oauth_config_from_lookup("APP_OAUTH_", lookup_from(&vars), files_from(&files))
            .unwrap_err();
        assert_eq!(err.problem_details()[0].kind(), ProblemKind::EnvParse);
        assert!(err.problems[0].contains("is not valid JSON"), "{err}");

        // Loaded fine, refused by `resolve`, named as variables — every one at
        // once.
        let mut vars = policy_vars();
        vars.insert("APP_OAUTH_ALLOWED_CLIENT_IDS", "client-a");
        vars.insert("APP_OAUTH_MAX_TOKEN_AGE_SECS", "0");
        vars.insert(
            "APP_OAUTH_REQUIRED_CLAIMS",
            r#"{"aud": "x", "org": {"id": 1}}"#,
        );
        let err = oauth_config_from_lookup("APP_OAUTH_", lookup_from(&vars), files_from(&files))
            .unwrap_err();
        let got: Vec<_> = err
            .problem_details()
            .iter()
            .map(|p| (p.kind(), p.keys().to_vec()))
            .collect();
        assert_eq!(
            got,
            [
                (
                    ProblemKind::TokenAgeOutOfRange,
                    vec!["APP_OAUTH_MAX_TOKEN_AGE_SECS".to_string()]
                ),
                (
                    ProblemKind::InvalidRequiredClaim,
                    vec!["APP_OAUTH_REQUIRED_CLAIMS".to_string()]
                ),
                (
                    ProblemKind::InvalidRequiredClaim,
                    vec!["APP_OAUTH_REQUIRED_CLAIMS".to_string()]
                ),
            ]
        );
    }
}
