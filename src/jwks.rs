//! The authorization server's signing keys: discovery, fetching, caching and
//! per-key algorithm binding.
//!
//! Everything here fails closed — an unreachable IdP, a malformed key set, an
//! unknown `kid` during the refetch cooldown, a key whose type cannot produce the
//! token's `alg` all mean "no key", never "skip the check" — and a failed refresh
//! keeps the keys already held, so an IdP outage does not revoke keys that are
//! still good — until a refresh succeeds. A key the authorization server has
//! withdrawn therefore stays trusted for as long as refreshes keep failing;
//! there is deliberately no maximum staleness after which held keys are
//! dropped, since that would turn an IdP outage into a full outage here too.
//!
//! Every refetch runs in a task of its own that holds the refresh lock until
//! the fetch completes, so a caller that stops waiting (a client disconnect, a
//! timeout layer) cannot cancel a fetch halfway and leave the unknown-`kid`
//! cooldown spent with no keys loaded.

use std::collections::HashSet;
use std::sync::{Arc, PoisonError};
use std::time::{Duration, Instant, SystemTime};

use jsonwebtoken::DecodingKey;
use jsonwebtoken::jwk::{Jwk, KeyOperations, PublicKeyUse};
use serde_json::Value;
use tokio::sync::{Mutex, OwnedMutexGuard, RwLock};
use tracing::{debug, info, warn};

use crate::algorithms::{Algorithm, key_algorithms, signing_algorithm};
use crate::config::{KeyNamingBuf, ResolvedOAuthConfig};
use crate::token::{TokenRejection, describe_kid, for_log};
use crate::validator::plain_http_non_loopback;

/// How long an unknown `kid` is allowed to trigger a JWKS refetch again.
///
/// An unknown `kid` is attacker-controllable — it is just a field in an unverified
/// token header — so without this a stream of junk tokens would turn this server
/// into an amplifier pointed at the identity provider. One refetch per minute is
/// far faster than any real key rotation needs (JWKS rollovers publish the new key
/// alongside the old one well before signing with it) and slow enough that the IdP
/// never notices us.
pub(crate) const JWKS_MIN_REFETCH_INTERVAL: Duration = Duration::from_secs(60);

/// Ceiling on a single metadata or JWKS fetch. Bounds how long a refresh holds
/// `refresh_lock`, and therefore how long a stalled IdP can stall validation of
/// a token whose key is not already cached.
const JWKS_FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// How often the background task re-reads the JWKS even when every `kid` is known.
///
/// The unknown-`kid` refetch picks up a NEW key; only a periodic re-read notices a
/// key the authorization server has WITHDRAWN (rotated out after a compromise, for
/// instance). Without it a retired key would stay trusted for the life of the
/// process. An hour bounds that window — once a re-read succeeds — without
/// being a load anyone would notice. After a FAILED pass the background task
/// retries sooner (see [`background_retry_delay`]).
pub(crate) const JWKS_BACKGROUND_REFRESH_INTERVAL: Duration = Duration::from_secs(3600);

/// How long the background task waits after its `failures`-th consecutive
/// failed pass: [`JWKS_MIN_REFETCH_INTERVAL`], doubling each time, capped at
/// [`JWKS_BACKGROUND_REFRESH_INTERVAL`]. A validator whose first load failed
/// (the IdP was down at boot) is then keyless for about a minute rather than
/// an hour, without retrying a long outage more than hourly.
pub(crate) fn background_retry_delay(failures: u32) -> Duration {
    let doublings = failures.saturating_sub(1).min(16);
    JWKS_MIN_REFETCH_INTERVAL
        .saturating_mul(1 << doublings)
        .min(JWKS_BACKGROUND_REFRESH_INTERVAL)
}

/// First retry after a failed background pass while NO key is held (the first
/// load failed and none has succeeded since). One request every 5 s is nothing
/// to an authorization server, and it is the floor: nothing here retries faster.
pub(crate) const KEYLESS_RETRY_FLOOR: Duration = Duration::from_secs(5);

/// Ceiling on the keyless retry delay. A keyless validator refuses every token,
/// and a readiness probe on [`crate::OAuthValidator::is_ready`] keeps traffic —
/// and with it every request-driven refetch — away from it, so this schedule
/// is its only way back. Five minutes bounds how long it stays down after the
/// authorization server recovers; at the cap it is 12 requests an hour.
pub(crate) const KEYLESS_RETRY_CAP: Duration = Duration::from_secs(300);

/// How long the background task waits after its `failures`-th consecutive
/// failed pass while no key is held: [`KEYLESS_RETRY_FLOOR`], doubling each
/// time, capped at [`KEYLESS_RETRY_CAP`] (5, 10, 20, 40, 80, 160, then 300 s).
/// Once any key is held the task uses [`background_retry_delay`] instead.
/// Timer-driven only — nothing a request carries can shorten it, so it is no
/// amplification surface — and independent of the unknown-`kid` cooldown
/// ([`JWKS_MIN_REFETCH_INTERVAL`]), which it neither shortens nor bypasses.
pub(crate) fn keyless_retry_delay(failures: u32) -> Duration {
    let doublings = failures.saturating_sub(1).min(16);
    KEYLESS_RETRY_FLOOR
        .saturating_mul(1 << doublings)
        .min(KEYLESS_RETRY_CAP)
}

/// Cap on a metadata/JWKS response body. Real key sets are a few KiB; the cap is
/// there so a misbehaving (or impersonated) endpoint cannot make this process
/// buffer an unbounded body on the credential-checking path.
pub(crate) const MAX_FETCH_BYTES: usize = 256 * 1024;

/// Cap on keys taken from one JWK Set, for the same reason as [`MAX_FETCH_BYTES`]:
/// every key is parsed and scanned on lookup, and no real AS publishes dozens.
pub(crate) const MAX_JWKS_KEYS: usize = 64;

/// A failed key refresh: discovery, fetch, or a key set with nothing usable in
/// it. The keys held before the attempt are kept.
///
/// `Display` is the whole cause chain, outermost first, joined with `": "` (e.g.
/// `fetching the JWKS from https://…: request failed: …`), so a log line needs no
/// special formatting to show the root cause. [`RefreshError::kind`] is the
/// coarse, matchable stage that failed.
///
/// # Security
///
/// A configured `issuer` or `jwks_uri` may carry a credential: userinfo
/// (`https://user:pass@…`, which the fetch sends as HTTP Basic auth) or a
/// query string (`…/jwks?key=…`). Every URL in the message is therefore
/// redacted — userinfo becomes `***@`, a query `?***` and a fragment `#***`,
/// while scheme, host, port and path stay, so the endpoint is still
/// identifiable — and upstream errors are included without the URL they
/// would otherwise repeat verbatim. The fetch itself uses the URL unchanged.
/// The message still names the endpoints and repeats upstream error text,
/// so it is for logs and operators: a public, unauthenticated endpoint (a
/// health check reachable from outside, say) should report
/// [`RefreshError::kind`] instead.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct RefreshError {
    kind: RefreshErrorKind,
    message: String,
}

impl RefreshError {
    fn new(kind: RefreshErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    /// The same error, with `context` prepended to the message.
    fn context(self, context: impl std::fmt::Display) -> Self {
        Self {
            kind: self.kind,
            message: format!("{context}: {}", self.message),
        }
    }

    /// Which stage of the refresh failed.
    pub fn kind(&self) -> RefreshErrorKind {
        self.kind
    }
}

/// The stage at which a key refresh failed — see [`RefreshError::kind`].
///
/// `#[non_exhaustive]`: match with a wildcard arm; a stage may be added in a
/// minor release.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RefreshErrorKind {
    /// No `jwks_uri` is configured and none could be discovered: every
    /// metadata URL failed, answered for a different issuer, or named a
    /// refused `jwks_uri`.
    Discovery,
    /// The JWKS request failed: network, TLS, a refused redirect, a timeout, a
    /// non-success status, or a body over the size cap.
    Fetch,
    /// The JWKS response was not JSON, or not a JWK Set.
    Parse,
    /// The JWK Set held no key usable for a signature under the configured
    /// algorithms.
    NoUsableKeys,
}

impl RefreshErrorKind {
    /// A short, stable, lower-case label (`discovery`, `fetch`, `parse`,
    /// `no_usable_keys`), suitable for a metrics label or a public health
    /// response.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Discovery => "discovery",
            Self::Fetch => "fetch",
            Self::Parse => "parse",
            Self::NoUsableKeys => "no_usable_keys",
        }
    }
}

impl std::fmt::Display for RefreshErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A point-in-time view of the signing keys an [`crate::OAuthValidator`] holds,
/// from [`crate::OAuthValidator::key_set_status`].
///
/// Reading it does no I/O and never waits on a refresh in flight, so a
/// readiness probe, a status page or a metrics scrape can call it as often as
/// it likes. `#[non_exhaustive]`: read its fields, never build one; a field
/// may be added in a minor release.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct KeySetStatus {
    /// How many usable verification keys are held.
    pub keys: usize,
    /// The JWKS URL in use: the configured `jwks_uri`, or the one discovered
    /// from the issuer's metadata — `None` while it is still undiscovered.
    /// Redacted as [`RefreshError`]'s `# Security` note describes: any
    /// userinfo shows as `***@` and any query as `?***`.
    pub jwks_uri: Option<String>,
    /// When the most recent refresh started, whether or not it has finished
    /// and however it ended; `None` before the first one.
    pub last_attempt: Option<SystemTime>,
    /// When a refresh last succeeded (loaded a key set with at least one
    /// usable key); `None` if none ever has. A failed refresh leaves it — and
    /// the keys — as they were.
    pub last_success: Option<SystemTime>,
    /// Why the most recent *finished* refresh failed; `None` if it succeeded
    /// or none has finished yet. Read [`RefreshError`]'s `# Security` note
    /// before exposing its `Display` publicly.
    pub last_error: Option<RefreshError>,
}

impl KeySetStatus {
    /// At least one usable key is held — see
    /// [`crate::OAuthValidator::is_ready`].
    pub fn is_ready(&self) -> bool {
        self.keys > 0
    }
}

/// `raw` with any credential it may carry masked, for a log line, an error
/// message or [`KeySetStatus::jwks_uri`]: userinfo (user, or user and
/// password) becomes `***@`, a query `?***` and a fragment `#***`. Scheme,
/// host, port and path are kept, so the endpoint stays identifiable. A URL
/// with none of the three comes back exactly as given; one that does not
/// parse as a URL with a host comes back as a fixed placeholder, since there
/// is then no telling where a credential in it might be. Never panics.
pub(crate) fn redact_url(raw: &str) -> String {
    const UNPARSEABLE: &str = "<unparseable URL, redacted>";
    // No host means no telling userinfo from path: `alice:s3cret@idp/jwks`
    // parses as scheme `alice` with an opaque path.
    let Ok(mut url) = reqwest::Url::parse(raw) else {
        return UNPARSEABLE.to_string();
    };
    if url.host_str().is_none() {
        return UNPARSEABLE.to_string();
    }
    let userinfo = !url.username().is_empty() || url.password().is_some();
    if !userinfo && url.query().is_none() && url.fragment().is_none() {
        return raw.to_string();
    }
    if userinfo && (url.set_password(None).is_err() || url.set_username("***").is_err()) {
        return UNPARSEABLE.to_string();
    }
    if url.query().is_some() {
        url.set_query(Some("***"));
    }
    if url.fragment().is_some() {
        url.set_fragment(Some("***"));
    }
    url.to_string()
}

/// `err` and every `source()` below it, joined with `": "`.
fn error_chain(err: &dyn std::error::Error) -> String {
    let mut out = err.to_string();
    let mut source = err.source();
    while let Some(cause) = source {
        out.push_str(": ");
        out.push_str(&cause.to_string());
        source = cause.source();
    }
    out
}

/// `context: <err and its causes>`.
fn context(context: &str, err: &dyn std::error::Error) -> String {
    format!("{context}: {}", error_chain(err))
}

/// Where a redirect may go, decided by [`judge_redirect`].
#[derive(Debug, PartialEq, Eq)]
enum Hop {
    Follow,
    /// Plain http to a non-loopback host, followed only because
    /// `allow_insecure_http` is set — logged as a `warn`.
    FollowInsecure,
    Refuse(String),
}

/// Judge one redirect hop to `next`, after the `previous` URLs.
///
/// A hop from https to plain http is refused outright: it would let anyone on
/// the path substitute the signing keys. A hop to plain http on a
/// non-loopback host is held to the same `allow_insecure_http` rule as a
/// configured URL (`opt_in_key` names that setting), so a loopback `jwks_uri`
/// or issuer cannot redirect key fetches onto a cleartext network path
/// without the opt-in. Some servers redirect their JWKS path (a trailing-slash
/// rewrite, say); a handful of hops covers that, and an unbounded chain only
/// stretches a refresh out.
fn judge_redirect(
    next: &reqwest::Url,
    previous: &[reqwest::Url],
    allow_insecure_http: bool,
    opt_in_key: &str,
) -> Hop {
    if next.scheme() != "https" && previous.iter().any(|u| u.scheme() == "https") {
        return Hop::Refuse("redirect from https to a non-https URL refused".to_string());
    }
    let insecure = plain_http_non_loopback(next.as_str());
    if insecure && !allow_insecure_http {
        return Hop::Refuse(format!(
            "redirect to plain http on a non-loopback host ({}) refused — set {opt_in_key} \
             to permit it",
            for_log(&redact_url(next.as_str()))
        ));
    }
    if previous.len() > 3 {
        Hop::Refuse("too many redirects".to_string())
    } else if insecure {
        Hop::FollowInsecure
    } else {
        Hop::Follow
    }
}

/// The HTTP client every metadata and JWKS fetch goes through. Redirects are
/// judged by [`judge_redirect`]; `opt_in_key` names the `allow_insecure_http`
/// setting in a refusal or warning.
pub(crate) fn http_client(
    allow_insecure_http: bool,
    opt_in_key: String,
) -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .timeout(JWKS_FETCH_TIMEOUT)
        .redirect(reqwest::redirect::Policy::custom(
            move |attempt| match judge_redirect(
                attempt.url(),
                attempt.previous(),
                allow_insecure_http,
                &opt_in_key,
            ) {
                Hop::Follow => attempt.follow(),
                Hop::FollowInsecure => {
                    warn!(
                        url = %for_log(&redact_url(attempt.url().as_str())),
                        "OAuth: following a redirect to plain http on a non-loopback host \
                         ({opt_in_key} is set) — signing keys fetched over it can be \
                         substituted by anyone on the path"
                    );
                    attempt.follow()
                }
                Hop::Refuse(reason) => attempt.error(reason),
            },
        ))
        .build()
}

/// One usable verification key from the JWK Set, with the algorithms it may verify.
///
/// `algorithms` is the intersection of what the key's TYPE can produce, what its
/// own `alg` parameter declares (when present) and the configured allowlist. A
/// token's `alg` must be in it, which is what stops an attacker-chosen header from
/// steering an RSA key into an ECDSA verification, or any key into HMAC.
pub(crate) struct CachedKey {
    kid: Option<String>,
    key: DecodingKey,
    pub(crate) algorithms: Vec<Algorithm>,
    /// The JWK declared no `alg` and more than one allowlisted algorithm fits
    /// its type — the RFC 8725 §3.1 deviation warned about when the key first
    /// appears.
    ambiguous: bool,
}

/// The in-memory JWKS plus when we last *attempted* to refresh it.
///
/// Attempt, not success, on purpose: a failing IdP must be backed off exactly like
/// a successful-but-stale one, or an outage turns every junk token into a retry
/// against a service that is already struggling.
#[derive(Default)]
struct JwksCache {
    keys: Vec<CachedKey>,
    last_attempt: Option<Instant>,
}

/// The fields behind [`JwksStore::status`].
#[derive(Default)]
struct Tracked {
    /// What a status read copies. Its `jwks_uri` is [`redact_url`] of the
    /// one below, so a credential in the URL never reaches a status page.
    public: KeySetStatus,
    /// The `jwks_uri` the fetch uses, unredacted: the configured one when
    /// there is one; otherwise `None` until discovery fills it in, after
    /// which it is fixed for the life of the process (a new value means a
    /// config change, which means a new validator).
    jwks_uri: Option<String>,
    /// How many refreshes have started, stamped with `last_attempt`. Lets a
    /// refresh task that died tell whether a newer attempt has run since.
    attempts: u64,
}

impl Tracked {
    fn set_jwks_uri(&mut self, uri: Option<String>) {
        self.public.jwks_uri = uri.as_deref().map(redact_url);
        self.jwks_uri = uri;
    }
}

/// The key source behind [`crate::OAuthValidator`]: owns the JWKS cache and every
/// fetch that fills it.
pub(crate) struct JwksStore {
    issuer: String,
    /// See [`crate::OAuthConfig::allow_insecure_http`]: whether a discovered
    /// `jwks_uri` may be plain http on a non-loopback host.
    allow_insecure_http: bool,
    algorithms: Vec<Algorithm>,
    naming: KeyNamingBuf,
    http: reqwest::Client,
    /// Only ever held for in-memory reads and swaps — never across a network
    /// call. tokio's `RwLock` queues new readers behind a waiting writer, so a
    /// writer parked on a slow IdP would stall every request, including ones whose
    /// key is already cached.
    jwks: RwLock<JwksCache>,
    /// What [`JwksStore::status`] reports, plus the `jwks_uri` actually
    /// fetched — see [`Tracked`].
    ///
    /// A synchronous `std` mutex, separate from `jwks`, so reading the status
    /// is a plain function a probe can call from anywhere. It is locked only
    /// to copy or overwrite these few fields — never across an `.await`, and
    /// never while taking `jwks` or `refresh_lock` — so it can never wait on a
    /// network call or on a refresh in flight. Reading `jwks` instead would
    /// make the status async and queue it behind tokio's writer-preferring
    /// lock, and `try_read` would fail spuriously whenever a swap was queued.
    status: std::sync::Mutex<Tracked>,
    /// Serializes refreshes instead: a burst of unknown-`kid` requests, or
    /// the background refresher racing one, collapse into one fetch while
    /// cached-key lookups carry on untouched. Owned guards, so the detached
    /// task running a fetch holds it until the fetch is done, whoever was
    /// waiting on it.
    refresh_lock: Arc<Mutex<()>>,
    /// Normally [`JWKS_MIN_REFETCH_INTERVAL`]; overridden only by tests, which
    /// would otherwise have to sleep a minute to observe a refetch.
    min_refetch_interval: Duration,
}

impl JwksStore {
    pub(crate) fn new(
        config: &ResolvedOAuthConfig,
        http: reqwest::Client,
        min_refetch_interval: Duration,
    ) -> Self {
        let mut tracked = Tracked::default();
        tracked.set_jwks_uri(config.jwks_uri.clone().filter(|uri| !uri.trim().is_empty()));
        Self {
            issuer: config.issuer.clone(),
            allow_insecure_http: config.allow_insecure_http,
            algorithms: config.algorithms.clone(),
            naming: config.key_naming.clone(),
            http,
            jwks: RwLock::new(JwksCache::default()),
            status: std::sync::Mutex::new(tracked),
            refresh_lock: Arc::new(Mutex::new(())),
            min_refetch_interval,
        }
    }

    /// Load (or reload) the key set now, discovering the JWKS URI first if
    /// needed. Returns how many usable keys it holds. On failure the previous
    /// keys are kept.
    pub(crate) async fn refresh_now(self: &Arc<Self>) -> Result<usize, RefreshError> {
        let guard = Arc::clone(&self.refresh_lock).lock_owned().await;
        self.refresh_detached(guard).await
    }

    /// The status fields, locked for the instant a caller copies or updates
    /// them. Never hold the guard across an `.await`. A poisoned lock (a panic
    /// mid-update of plain data) is still readable, so it is not propagated.
    fn status_fields(&self) -> std::sync::MutexGuard<'_, Tracked> {
        self.status.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A copy of the key-set status. No I/O; never waits on `jwks` or
    /// `refresh_lock`.
    pub(crate) fn status(&self) -> KeySetStatus {
        self.status_fields().public.clone()
    }

    /// Whether at least one usable key is held. As [`JwksStore::status`].
    pub(crate) fn has_keys(&self) -> bool {
        self.status_fields().public.keys > 0
    }

    /// Whether a refresh holds `refresh_lock` right now — for tests that
    /// drive a paused clock and must know when a fetch has finished.
    #[cfg(test)]
    pub(crate) fn refresh_in_flight(&self) -> bool {
        self.refresh_lock.try_lock().is_err()
    }

    /// Run one refresh in a task of its own, which holds `guard` (the refresh
    /// lock) until the fetch completes, and wait for it.
    ///
    /// Detached so the fetch cannot be cancelled by its caller being dropped —
    /// a client disconnecting mid-request, a timeout layer, an HTTP/2 reset.
    /// Run inline, a drop after [`JwksStore::refresh`] stamps `last_attempt`
    /// would spend the unknown-`kid` cooldown without loading any keys, and an
    /// unauthenticated client could repeat that every minute to keep a rotated
    /// key from ever being picked up on demand.
    async fn refresh_detached(
        self: &Arc<Self>,
        guard: OwnedMutexGuard<()>,
    ) -> Result<usize, RefreshError> {
        // Read while `guard` is held, so no other refresh can start first:
        // this task's own attempt, if it got as far as stamping one, is the
        // next number.
        let ours = self.status_fields().attempts + 1;
        let store = Arc::clone(self);
        let task = tokio::spawn(async move {
            let _refreshing = guard;
            store.refresh().await
        });
        task.await.unwrap_or_else(|e| {
            let err = RefreshError::new(
                RefreshErrorKind::Fetch,
                format!("the key refresh task did not finish: {e}"),
            );
            // A cancelled task means the runtime is shutting down: nothing
            // failed, and nobody is left to read the status. A panicked one
            // released the refresh lock while unwinding, so a newer attempt
            // may already have run — and succeeded; record the panic only if
            // none has started since.
            if e.is_panic() {
                let mut status = self.status_fields();
                if status.attempts <= ours {
                    status.public.last_error = Some(err.clone());
                }
            }
            Err(err)
        })
    }

    /// The verification key for `kid` and `alg` among the keys already held, or
    /// `None`. Never fetches and never waits on `refresh_lock`.
    pub(crate) async fn cached_decoding_key(
        &self,
        kid: Option<&str>,
        alg: Algorithm,
    ) -> Option<DecodingKey> {
        lookup(&self.jwks.read().await.keys, kid, alg)
    }

    /// Resolve the verification key for `kid` and `alg`, fetching or refetching the
    /// JWKS as needed.
    ///
    /// Fails closed in every failure mode — an unreachable IdP, a malformed key set,
    /// an unknown `kid` during the refetch cooldown, a key whose type cannot produce
    /// `alg` — because the alternative shape ("could not check, so allow") is the
    /// one bug in this crate that would be worth a CVE.
    pub(crate) async fn decoding_key(
        self: &Arc<Self>,
        kid: Option<&str>,
        alg: Algorithm,
    ) -> Result<DecodingKey, TokenRejection> {
        if let Some(key) = lookup(&self.jwks.read().await.keys, kid, alg) {
            return Ok(key);
        }

        // One refresher at a time. A thundering herd of concurrent unknown-`kid`
        // requests queues HERE, not on the key lock, so requests whose key is
        // already cached are never held up by a slow IdP; `JWKS_FETCH_TIMEOUT`
        // bounds how long the queued ones wait.
        let refreshing = Arc::clone(&self.refresh_lock).lock_owned().await;

        // Another task may have fetched while we waited.
        let last_attempt = {
            let cache = self.jwks.read().await;
            if let Some(key) = lookup(&cache.keys, kid, alg) {
                return Ok(key);
            }
            cache.last_attempt
        };

        if let Some(last) = last_attempt
            && last.elapsed() < self.min_refetch_interval
        {
            // See `JWKS_MIN_REFETCH_INTERVAL`: `kid` comes from an unverified token
            // header, so an unknown one must not be able to schedule IdP traffic.
            return Err(TokenRejection::Invalid(format!(
                "no {alg} key for kid {} and the JWKS was refetched less than {}s ago",
                describe_kid(kid),
                self.min_refetch_interval.as_secs()
            )));
        }

        if let Err(e) = self.refresh_detached(refreshing).await {
            warn!(
                issuer = %redact_url(&self.issuer),
                error = %e,
                "JWKS refresh failed — tokens signed by a key we do not already hold will \
                 be rejected until the next attempt"
            );
            return Err(TokenRejection::Invalid(format!("JWKS refresh failed: {e}")));
        }

        lookup(&self.jwks.read().await.keys, kid, alg).ok_or_else(|| {
            TokenRejection::Invalid(format!(
                "no {alg} key for kid {} in the fetched JWKS",
                describe_kid(kid)
            ))
        })
    }

    /// One refresh attempt. The caller holds `refresh_lock`; the key lock is taken
    /// only for the instant it takes to read or swap in-memory state, never across
    /// the network. Records the attempt time first, so a failure is backed off like
    /// a success, and leaves the old keys in place on any failure. The outcome is
    /// recorded in the status fields once it is known.
    async fn refresh(&self) -> Result<usize, RefreshError> {
        self.jwks.write().await.last_attempt = Some(Instant::now());
        let known_uri = {
            let mut status = self.status_fields();
            status.attempts += 1;
            status.public.last_attempt = Some(SystemTime::now());
            status.jwks_uri.clone()
        };
        let result = self.load(known_uri).await;
        let status = &mut self.status_fields().public;
        match &result {
            Ok(count) => {
                status.keys = *count;
                status.last_success = Some(SystemTime::now());
                status.last_error = None;
            }
            Err(e) => status.last_error = Some(e.clone()),
        }
        result
    }

    /// Discover the JWKS URI if `known_uri` is `None`, then fetch the key set
    /// and swap it in: the body of [`JwksStore::refresh`].
    async fn load(&self, known_uri: Option<String>) -> Result<usize, RefreshError> {
        let jwks_uri = match known_uri {
            Some(uri) => uri,
            None => {
                let uri = self.discover_jwks_uri().await?;
                info!(
                    issuer = %redact_url(&self.issuer),
                    jwks_uri = %redact_url(&uri),
                    "OAuth: discovered the JWKS URI from the issuer's metadata"
                );
                if plain_http_non_loopback(&uri) {
                    // Reachable only with the opt-in: `jwks_uri_from_metadata`
                    // refuses this without it.
                    warn!(
                        jwks_uri = %redact_url(&uri),
                        "the discovered JWKS URI uses plain http on a non-loopback host \
                         ({} is set) — signing keys fetched over it can be substituted by \
                         anyone on the path. Use https.",
                        self.naming.key("allow_insecure_http")
                    );
                }
                self.status_fields().set_jwks_uri(Some(uri.clone()));
                uri
            }
        };
        let shown = redact_url(&jwks_uri);
        let keys = self
            .fetch_jwks(&jwks_uri)
            .await
            .map_err(|e| e.context(format_args!("fetching the JWKS from {shown}")))?;
        let count = keys.len();
        debug!(count, jwks_uri = %shown, "Fetched JWKS");
        let previous = std::mem::replace(&mut self.jwks.write().await.keys, keys);
        self.warn_about_new_ambiguous_keys(&previous).await;
        Ok(count)
    }

    /// RFC 8725 §3.1 binds each key to exactly one algorithm. A JWK that
    /// declares no `alg` (it is OPTIONAL, RFC 7517 §4.4) is usable here for
    /// every allowlisted algorithm its type can produce — an RSA key for
    /// RS256/384/512 and PS256/384/512 by default. Accepted, because an
    /// authorization server that omits `alg` gives no other way to know which
    /// one it signs with, and no practical attack mixing those on one key is
    /// known; but said once per key, when it first appears, with the fix.
    async fn warn_about_new_ambiguous_keys(&self, previous: &[CachedKey]) {
        let already: HashSet<Option<&str>> = previous
            .iter()
            .filter(|k| k.ambiguous)
            .map(|k| k.kid.as_deref())
            .collect();
        let cache = self.jwks.read().await;
        for key in cache.keys.iter().filter(|k| k.ambiguous) {
            if already.contains(&key.kid.as_deref()) {
                continue;
            }
            let algorithms: Vec<&str> = key.algorithms.iter().map(|a| a.as_str()).collect();
            warn!(
                kid = %describe_kid(key.kid.as_deref()),
                algorithms = %algorithms.join(" "),
                "JWKS key declares no alg, so it may verify any of {} — RFC 8725 §3.1 binds a \
                 key to one algorithm. Narrow {} to the algorithm the authorization server \
                 signs with.",
                algorithms.join(", "),
                self.naming.key("algorithms")
            );
        }
    }

    /// Find the JWKS URI in the issuer's own metadata (used only when no
    /// `jwks_uri` is configured).
    ///
    /// Only URLs derived from the CONFIGURED issuer are ever fetched — nothing in a
    /// token influences where this goes, so it is not an SSRF surface. The
    /// document's `issuer` must equal the configured one byte-for-byte (RFC 8414
    /// §3.3, OIDC Discovery §4.3: a mismatching document MUST NOT be used), which is
    /// what stops a proxy or a misconfigured path from handing us some other
    /// server's keys.
    async fn discover_jwks_uri(&self) -> Result<String, RefreshError> {
        let issuer_key = self.naming.key("issuer");
        let mut errors = Vec::new();
        for url in discovery_urls(&self.issuer) {
            match self.fetch_json(&url).await {
                Ok(doc) => match jwks_uri_from_metadata(
                    &doc,
                    &self.issuer,
                    &issuer_key,
                    self.allow_insecure_http,
                    &self.naming.key("allow_insecure_http"),
                ) {
                    Ok(uri) => return Ok(uri),
                    Err(e) => errors.push(format!("{}: {e}", redact_url(&url))),
                },
                Err(e) => errors.push(format!("{}: {e}", redact_url(&url))),
            }
        }
        Err(RefreshError::new(
            RefreshErrorKind::Discovery,
            format!(
                "could not discover a jwks_uri for {issuer_key} {:?} — set {} explicitly or \
                 fix the issuer. Tried: {}",
                redact_url(&self.issuer),
                self.naming.key("jwks_uri"),
                errors.join("; ")
            ),
        ))
    }

    async fn fetch_jwks(&self, uri: &str) -> Result<Vec<CachedKey>, RefreshError> {
        let doc = self.fetch_json(uri).await?;
        let entries = doc.get("keys").and_then(Value::as_array).ok_or_else(|| {
            RefreshError::new(
                RefreshErrorKind::Parse,
                "response is not a JWK Set (no \"keys\" array)",
            )
        })?;
        if entries.len() > MAX_JWKS_KEYS {
            warn!(
                published = entries.len(),
                used = MAX_JWKS_KEYS,
                "JWK Set has more keys than this server will consider; the rest are ignored"
            );
        }

        let mut keys = Vec::new();
        for entry in entries.iter().take(MAX_JWKS_KEYS) {
            if let Some(key) = parse_jwks_entry(entry, &self.algorithms) {
                keys.push(key);
            }
        }
        if keys.is_empty() {
            return Err(RefreshError::new(
                RefreshErrorKind::NoUsableKeys,
                format!(
                    "the JWK Set contained no usable signature keys for {} {:?}",
                    self.naming.key("algorithms"),
                    self.algorithms
                ),
            ));
        }
        Ok(keys)
    }

    /// GET a JSON document with the body capped at [`MAX_FETCH_BYTES`].
    async fn fetch_json(&self, url: &str) -> Result<Value, RefreshError> {
        let fetch = |message: String| RefreshError::new(RefreshErrorKind::Fetch, message);
        let mut resp = self
            .http
            .get(url)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|e| fetch(context("request failed", &e.without_url())))?
            .error_for_status()
            .map_err(|e| fetch(context("non-success status", &e.without_url())))?;
        if let Some(len) = resp.content_length()
            && len > MAX_FETCH_BYTES as u64
        {
            return Err(fetch(format!(
                "response is {len} bytes, over the {MAX_FETCH_BYTES}-byte cap"
            )));
        }
        let mut body = Vec::new();
        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(|e| fetch(context("reading the response body", &e.without_url())))?
        {
            if body.len() + chunk.len() > MAX_FETCH_BYTES {
                return Err(fetch(format!(
                    "response exceeds the {MAX_FETCH_BYTES}-byte cap"
                )));
            }
            body.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&body).map_err(|e| {
            RefreshError::new(
                RefreshErrorKind::Parse,
                context("response was not JSON", &e),
            )
        })
    }
}

/// Build a [`CachedKey`] from one raw JWK Set entry, or `None` when the entry
/// is unparseable or the key must not be used (see [`cached_key`]).
///
/// Parsed one key at a time: `jsonwebtoken::jwk::JwkSet` refuses the WHOLE set
/// if any single key has a kty/crv/alg it does not model (an X25519 encryption
/// key, say), and one exotic key must not take the usable ones down with it.
/// Pure — no I/O, never panics on hostile input — which is what lets the fuzz
/// targets drive it directly.
pub(crate) fn parse_jwks_entry(entry: &Value, allowed: &[Algorithm]) -> Option<CachedKey> {
    let jwk: Jwk = match serde_json::from_value(entry.clone()) {
        Ok(jwk) => jwk,
        Err(e) => {
            debug!(error = %e, "Skipping a JWKS entry this server cannot parse");
            return None;
        }
    };
    cached_key(&jwk, allowed)
}

/// Build a [`CachedKey`] from one JWK, or `None` when the key must not be used.
fn cached_key(jwk: &Jwk, allowed: &[Algorithm]) -> Option<CachedKey> {
    // `use: enc` keys exist in real key sets (Keycloak publishes one). An
    // encryption key verifying a signature is a key-confusion bug in waiting.
    match &jwk.common.public_key_use {
        None | Some(PublicKeyUse::Signature) => {}
        Some(_) => return None,
    }
    // `key_ops` (RFC 7517 §4.3) is the other way a JWK says what it is for.
    // A key whose operations do not include `verify` — `["encrypt"]`,
    // `["wrapKey"]` — is the same confusion as `use: enc`.
    if let Some(ops) = &jwk.common.key_operations
        && !ops.contains(&KeyOperations::Verify)
    {
        return None;
    }
    let mut algorithms = key_algorithms(&jwk.algorithm)?;
    // When the key names its own algorithm, that is the ONLY one it verifies. A
    // declared algorithm the key type cannot produce (an RSA key labelled ES256)
    // means the entry is broken; skipping it is safer than guessing.
    if let Some(declared) = &jwk.common.key_algorithm {
        match signing_algorithm(declared) {
            Some(alg) if algorithms.contains(&alg) => algorithms = vec![alg],
            _ => return None,
        }
    }
    algorithms.retain(|alg| allowed.contains(alg));
    if algorithms.is_empty() {
        return None;
    }
    let ambiguous = jwk.common.key_algorithm.is_none() && algorithms.len() > 1;
    match DecodingKey::from_jwk(jwk) {
        Ok(key) => Some(CachedKey {
            kid: jwk.common.key_id.clone(),
            key,
            algorithms,
            ambiguous,
        }),
        Err(e) => {
            warn!(
                kid = ?jwk.common.key_id.as_deref().map(for_log),
                error = %e,
                "Skipping unusable JWKS entry"
            );
            None
        }
    }
}

/// Find the key for `kid` that can verify `alg`.
///
/// A token header with no `kid` falls back to the single key that can verify its
/// `alg`, when there is exactly one. That is not laxity: with one candidate key
/// there is exactly one key the signature could have been made with, so the
/// fallback picks the same key an explicit `kid` would have. With two or more it
/// refuses rather than trying each, which would turn key rotation into a
/// signature-verification oracle.
fn lookup(keys: &[CachedKey], kid: Option<&str>, alg: Algorithm) -> Option<DecodingKey> {
    let mut candidates = keys.iter().filter(|k| k.algorithms.contains(&alg));
    match kid {
        Some(kid) => candidates
            .find(|k| k.kid.as_deref() == Some(kid))
            .map(|k| k.key.clone()),
        None => {
            let only = candidates.next()?;
            candidates.next().is_none().then(|| only.key.clone())
        }
    }
}

/// The metadata URLs to try for `issuer`, in order: OpenID Connect Discovery
/// (§4: the issuer with any trailing slash removed, plus
/// `/.well-known/openid-configuration` — where every server this crate has been
/// tested against publishes, including per-application issuers like Authentik's
/// and Kanidm's), then RFC 8414 §3.1's form (the well-known segment inserted
/// between host and path).
pub(crate) fn discovery_urls(issuer: &str) -> Vec<String> {
    let trimmed = issuer.trim_end_matches('/');
    let mut urls = vec![format!("{trimmed}/.well-known/openid-configuration")];
    if let Some((scheme, rest)) = trimmed.split_once("://") {
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, ""),
        };
        let rfc8414 =
            format!("{scheme}://{authority}/.well-known/oauth-authorization-server{path}");
        if !urls.contains(&rfc8414) {
            urls.push(rfc8414);
        }
    }
    urls
}

/// Pull `jwks_uri` out of an authorization-server metadata document, refusing a
/// document for a different issuer and a key URL that would downgrade transport.
/// `issuer_key` names the issuer setting in the error.
///
/// A plain-http `jwks_uri` is accepted only from a plain-http issuer, and —
/// when it points at a non-loopback host — only with `allow_insecure_http`
/// (named by `opt_in_key`), the same rule `resolve` applies to a configured
/// `jwks_uri` (RFC 8414 §2: `jwks_uri` MUST use https). Without that, a
/// loopback issuer, which needs no opt-in, could steer key fetches onto a
/// cleartext network path.
fn jwks_uri_from_metadata(
    doc: &Value,
    issuer: &str,
    issuer_key: &str,
    allow_insecure_http: bool,
    opt_in_key: &str,
) -> Result<String, String> {
    // Every URL in a message is redacted: the configured issuer may carry a
    // credential, and a document echoing it back may too.
    let shown_issuer = redact_url(issuer);
    let found = doc.get("issuer").and_then(Value::as_str);
    if found != Some(issuer) {
        return Err(format!(
            "metadata issuer {} does not match {issuer_key} {shown_issuer:?} byte-for-byte \
             (RFC 8414 §3.3 / OIDC Discovery §4.3: such a document must not be used)",
            found.map_or_else(
                || "(absent)".to_string(),
                |f| format!("{:?}", for_log(&redact_url(f)))
            )
        ));
    }
    let uri = doc
        .get("jwks_uri")
        .and_then(Value::as_str)
        .ok_or_else(|| "metadata has no jwks_uri".to_string())?;
    let parsed =
        reqwest::Url::parse(uri).map_err(|e| context("jwks_uri is not an absolute URL", &e))?;
    match parsed.scheme() {
        "https" => {}
        // Plain http only when the issuer itself is plain http (a loopback test
        // setup); an https issuer must never hand us keys over http.
        "http" if issuer.starts_with("http://") => {
            if !allow_insecure_http && plain_http_non_loopback(uri) {
                return Err(format!(
                    "jwks_uri {:?} uses plain http on a non-loopback host — refused \
                     (RFC 8414 §2) unless {opt_in_key} is set",
                    for_log(&redact_url(uri))
                ));
            }
        }
        other => {
            return Err(format!(
                "jwks_uri scheme {other:?} is not allowed for issuer {shown_issuer:?}"
            ));
        }
    }
    Ok(uri.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const OPT_IN: &str = "mcp.oauth.allow_insecure_http";

    #[test]
    fn discovery_urls_follow_oidc_then_rfc_8414() {
        assert_eq!(
            discovery_urls("https://auth.example.com/application/o/wiki/"),
            [
                "https://auth.example.com/application/o/wiki/.well-known/openid-configuration",
                "https://auth.example.com/.well-known/oauth-authorization-server/application/o/wiki",
            ]
        );
        assert_eq!(
            discovery_urls("https://auth.example.com"),
            [
                "https://auth.example.com/.well-known/openid-configuration",
                "https://auth.example.com/.well-known/oauth-authorization-server",
            ]
        );
    }

    #[test]
    fn discovered_jwks_uri_must_not_downgrade_transport() {
        let key = "mcp.oauth.issuer";
        let doc = serde_json::json!({
            "issuer": "https://auth.example.com",
            "jwks_uri": "http://auth.example.com/jwks",
        });
        assert!(
            jwks_uri_from_metadata(&doc, "https://auth.example.com", key, false, OPT_IN).is_err()
        );
        let doc = serde_json::json!({
            "issuer": "https://auth.example.com",
            "jwks_uri": "file:///etc/passwd",
        });
        assert!(
            jwks_uri_from_metadata(&doc, "https://auth.example.com", key, false, OPT_IN).is_err()
        );
        let doc = serde_json::json!({"issuer": "https://auth.example.com"});
        assert!(
            jwks_uri_from_metadata(&doc, "https://auth.example.com", key, false, OPT_IN).is_err()
        );
        // The opt-in never lets an https issuer hand out http keys.
        let doc = serde_json::json!({
            "issuer": "https://auth.example.com",
            "jwks_uri": "http://auth.example.com/jwks",
        });
        assert!(
            jwks_uri_from_metadata(&doc, "https://auth.example.com", key, true, OPT_IN).is_err()
        );
    }

    #[test]
    fn a_loopback_issuer_cannot_discover_a_cleartext_non_loopback_jwks_uri() {
        let key = "mcp.oauth.issuer";
        let issuer = "http://localhost:9000/app/";
        let doc =
            serde_json::json!({"issuer": issuer, "jwks_uri": "http://idp.internal.test/jwks"});
        let err = jwks_uri_from_metadata(&doc, issuer, key, false, OPT_IN).unwrap_err();
        assert!(err.contains("plain http on a non-loopback host"), "{err}");
        assert!(err.contains(OPT_IN), "{err}");
        // With the opt-in it is accepted (and `refresh` warns about it).
        assert_eq!(
            jwks_uri_from_metadata(&doc, issuer, key, true, OPT_IN).unwrap(),
            "http://idp.internal.test/jwks"
        );
        // A loopback http jwks_uri never needs the opt-in.
        let doc = serde_json::json!({"issuer": issuer, "jwks_uri": "http://127.0.0.1:9000/jwks"});
        assert!(jwks_uri_from_metadata(&doc, issuer, key, false, OPT_IN).is_ok());
    }

    #[test]
    fn redirects_are_held_to_the_insecure_http_policy() {
        let url = |s: &str| reqwest::Url::parse(s).unwrap();
        let loopback = [url("http://127.0.0.1:9000/jwks")];
        let https = [url("https://auth.example.com/jwks")];
        // Loopback http → non-loopback http: refused without the opt-in, warned with it.
        let Hop::Refuse(reason) = judge_redirect(
            &url("http://idp.internal.test/jwks"),
            &loopback,
            false,
            OPT_IN,
        ) else {
            panic!("a cleartext non-loopback hop must be refused without the opt-in");
        };
        assert!(reason.contains(OPT_IN), "{reason}");
        assert_eq!(
            judge_redirect(
                &url("http://idp.internal.test/jwks"),
                &loopback,
                true,
                OPT_IN
            ),
            Hop::FollowInsecure
        );
        // Loopback → loopback, and anything → https, are plain follows.
        assert_eq!(
            judge_redirect(&url("http://localhost:9000/keys"), &loopback, false, OPT_IN),
            Hop::Follow
        );
        assert_eq!(
            judge_redirect(
                &url("https://idp.example.com/keys"),
                &loopback,
                false,
                OPT_IN
            ),
            Hop::Follow
        );
        // https → http is refused whatever the opt-in says, loopback included.
        for target in ["http://idp.internal.test/jwks", "http://127.0.0.1/jwks"] {
            assert!(matches!(
                judge_redirect(&url(target), &https, true, OPT_IN),
                Hop::Refuse(_)
            ));
        }
        // The hop limit still applies.
        let many = [
            url("https://a.example.com/"),
            url("https://b.example.com/"),
            url("https://c.example.com/"),
            url("https://d.example.com/"),
        ];
        assert_eq!(
            judge_redirect(&url("https://e.example.com/"), &many, false, OPT_IN),
            Hop::Refuse("too many redirects".to_string())
        );
    }

    #[test]
    fn error_chain_matches_the_context_colon_cause_shape() {
        #[derive(Debug, thiserror::Error)]
        #[error("outer")]
        struct Outer(#[source] Inner);
        #[derive(Debug, thiserror::Error)]
        #[error("inner")]
        struct Inner;
        assert_eq!(context("fetching", &Outer(Inner)), "fetching: outer: inner");
    }

    fn rsa_jwk(extra: Value) -> Jwk {
        let mut jwk = serde_json::json!({
            "kty": "RSA", "kid": "k", "n": crate::testing::N_A, "e": "AQAB",
        });
        for (k, v) in extra.as_object().unwrap() {
            jwk[k] = v.clone();
        }
        serde_json::from_value(jwk).unwrap()
    }

    #[test]
    fn key_ops_without_verify_make_a_key_unusable() {
        let all: Vec<Algorithm> = crate::DEFAULT_ALGORITHMS
            .iter()
            .map(|a| crate::parse_algorithm(a).unwrap())
            .collect();
        for ops in [
            serde_json::json!(["encrypt"]),
            serde_json::json!(["encrypt", "wrapKey"]),
            serde_json::json!(["sign"]),
            serde_json::json!([]),
            serde_json::json!(["some-future-op"]),
        ] {
            assert!(
                cached_key(&rsa_jwk(serde_json::json!({ "key_ops": ops })), &all).is_none(),
                "key_ops {ops} must not verify"
            );
        }
        for ops in [
            serde_json::json!(["verify"]),
            serde_json::json!(["sign", "verify"]),
        ] {
            assert!(
                cached_key(&rsa_jwk(serde_json::json!({ "key_ops": ops })), &all).is_some(),
                "key_ops {ops} may verify"
            );
        }
        // Absent, as nearly every authorization server publishes it: usable.
        assert!(cached_key(&rsa_jwk(serde_json::json!({})), &all).is_some());
    }

    fn all_algorithms() -> Vec<Algorithm> {
        crate::DEFAULT_ALGORITHMS
            .iter()
            .map(|a| crate::parse_algorithm(a).unwrap())
            .collect()
    }

    fn rsa_entry(extra: Value) -> Value {
        let mut entry = serde_json::json!({
            "kty": "RSA", "kid": "k", "n": crate::testing::N_A, "e": "AQAB",
        });
        for (k, v) in extra.as_object().unwrap() {
            entry[k] = v.clone();
        }
        entry
    }

    #[test]
    fn a_plain_signature_entry_is_parsed_into_a_key() {
        let all = all_algorithms();
        let key = parse_jwks_entry(&rsa_entry(serde_json::json!({})), &all).unwrap();
        assert_eq!(key.kid.as_deref(), Some("k"));
        let key = parse_jwks_entry(&rsa_entry(serde_json::json!({"use": "sig"})), &all).unwrap();
        assert_eq!(key.kid.as_deref(), Some("k"));
    }

    #[test]
    fn an_encryption_use_entry_is_skipped() {
        let all = all_algorithms();
        for usage in ["enc", "something-else"] {
            assert!(
                parse_jwks_entry(&rsa_entry(serde_json::json!({ "use": usage })), &all).is_none(),
                "use {usage} must not verify"
            );
        }
    }

    #[test]
    fn a_key_ops_entry_without_verify_is_skipped_at_entry_level_too() {
        let all = all_algorithms();
        let entry = rsa_entry(serde_json::json!({ "key_ops": ["encrypt"] }));
        assert!(parse_jwks_entry(&entry, &all).is_none());
    }

    #[test]
    fn an_hmac_entry_is_skipped() {
        let all = all_algorithms();
        let entry = serde_json::json!({"kty": "oct", "kid": "hmac", "k": "c2VjcmV0"});
        assert!(parse_jwks_entry(&entry, &all).is_none());
    }

    #[test]
    fn an_unparseable_entry_is_skipped_not_fatal() {
        let all = all_algorithms();
        for entry in [
            serde_json::json!({"kty": "OKP", "crv": "X25519", "kid": "x", "x": "AA"}),
            serde_json::json!({"kty": "no-such-type"}),
            serde_json::json!({"kid": "no kty at all"}),
            serde_json::json!("not an object"),
            serde_json::json!(null),
            serde_json::json!(42),
            serde_json::json!([]),
        ] {
            assert!(parse_jwks_entry(&entry, &all).is_none(), "{entry}");
        }
        // ...and the entry after one such skip is still usable.
        assert!(parse_jwks_entry(&rsa_entry(serde_json::json!({})), &all).is_some());
    }

    #[test]
    fn an_entry_outside_the_allowlist_is_skipped() {
        let entry = rsa_entry(serde_json::json!({}));
        assert!(parse_jwks_entry(&entry, &[Algorithm::ES256]).is_none());
        assert!(parse_jwks_entry(&entry, &[]).is_none());
    }

    #[test]
    fn an_alg_less_key_usable_under_several_algorithms_is_flagged_ambiguous() {
        let all: Vec<Algorithm> = crate::DEFAULT_ALGORITHMS
            .iter()
            .map(|a| crate::parse_algorithm(a).unwrap())
            .collect();
        let key = cached_key(&rsa_jwk(serde_json::json!({})), &all).unwrap();
        assert!(key.ambiguous);
        assert_eq!(key.algorithms.len(), 6);
        // A declared alg binds it to one algorithm.
        let key = cached_key(&rsa_jwk(serde_json::json!({"alg": "PS256"})), &all).unwrap();
        assert!(!key.ambiguous);
        assert_eq!(key.algorithms, [Algorithm::PS256]);
        // So does narrowing the allowlist to one RSA algorithm.
        let key = cached_key(&rsa_jwk(serde_json::json!({})), &[Algorithm::RS256]).unwrap();
        assert!(!key.ambiguous);
        assert_eq!(key.algorithms, [Algorithm::RS256]);
    }

    #[test]
    fn background_retries_back_off_from_a_minute_to_an_hour() {
        assert_eq!(background_retry_delay(1), Duration::from_secs(60));
        assert_eq!(background_retry_delay(2), Duration::from_secs(120));
        assert_eq!(background_retry_delay(3), Duration::from_secs(240));
        assert_eq!(background_retry_delay(6), Duration::from_secs(1920));
        assert_eq!(background_retry_delay(7), Duration::from_secs(3600));
        assert_eq!(background_retry_delay(u32::MAX), Duration::from_secs(3600));
    }

    #[test]
    fn redact_url_masks_userinfo_query_and_fragment_only() {
        for (raw, shown) in [
            // user and password
            (
                "https://alice:s3cret@idp.example.com:8443/jwks",
                "https://***@idp.example.com:8443/jwks",
            ),
            // user only, and password only
            (
                "https://alice@idp.example.com/jwks",
                "https://***@idp.example.com/jwks",
            ),
            (
                "https://:s3cret@idp.example.com/jwks",
                "https://***@idp.example.com/jwks",
            ),
            // query
            (
                "https://idp.example.com/jwks?key=t0ken",
                "https://idp.example.com/jwks?***",
            ),
            // all of them
            (
                "https://alice:s3cret@idp.example.com/o/app/jwks?key=t0ken#frag",
                "https://***@idp.example.com/o/app/jwks?***#***",
            ),
            // IPv6 host with a port
            (
                "http://alice:s3cret@[::1]:9000/jwks?key=t0ken",
                "http://***@[::1]:9000/jwks?***",
            ),
        ] {
            let redacted = redact_url(raw);
            assert_eq!(redacted, shown, "{raw}");
            for secret in ["alice", "s3cret", "t0ken", "frag"] {
                assert!(!redacted.contains(secret), "{raw} -> {redacted}");
            }
        }
        // Nothing to mask: returned exactly as given, not normalized.
        for raw in [
            "https://idp.example.com/app/",
            "https://IDP.example.com",
            "http://[::1]:9000/jwks",
        ] {
            assert_eq!(redact_url(raw), raw);
        }
        // Unparseable: a fixed placeholder, never the input, never a panic.
        for raw in [
            "",
            "not a url",
            "alice:s3cret@idp.example.com/jwks",
            "http://[::1",
            "https://alice:s3cret@",
        ] {
            let redacted = redact_url(raw);
            assert!(!redacted.contains("s3cret"), "{raw} -> {redacted}");
            assert_eq!(redacted, "<unparseable URL, redacted>", "{raw}");
        }
    }

    #[test]
    fn keyless_retries_back_off_from_five_seconds_to_five_minutes() {
        let secs: Vec<u64> = (1..=9).map(|n| keyless_retry_delay(n).as_secs()).collect();
        assert_eq!(secs, [5, 10, 20, 40, 80, 160, 300, 300, 300]);
        assert_eq!(keyless_retry_delay(0), KEYLESS_RETRY_FLOOR);
        assert_eq!(keyless_retry_delay(u32::MAX), KEYLESS_RETRY_CAP);
        for n in 0..64 {
            assert!(
                keyless_retry_delay(n) >= Duration::from_secs(5),
                "never under the floor"
            );
        }
    }

    #[test]
    fn refresh_error_kinds_have_stable_labels() {
        let labels: Vec<&str> = [
            RefreshErrorKind::Discovery,
            RefreshErrorKind::Fetch,
            RefreshErrorKind::Parse,
            RefreshErrorKind::NoUsableKeys,
        ]
        .iter()
        .map(|k| k.as_str())
        .collect();
        assert_eq!(labels, ["discovery", "fetch", "parse", "no_usable_keys"]);
        let err = RefreshError::new(RefreshErrorKind::Parse, "inner").context("outer");
        assert_eq!(err.to_string(), "outer: inner");
        assert_eq!(err.kind(), RefreshErrorKind::Parse);
    }

    #[test]
    fn the_http_client_builds_with_the_enabled_tls_backend() {
        // Whichever of `rustls-tls` / `native-tls` this build enabled, the client
        // the validator fetches keys with must build.
        http_client(false, OPT_IN.to_string()).expect("the JWKS HTTP client must build");
    }
}
