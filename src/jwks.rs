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
use std::sync::Arc;
use std::time::{Duration, Instant};

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

/// Cap on a metadata/JWKS response body. Real key sets are a few KiB; the cap is
/// there so a misbehaving (or impersonated) endpoint cannot make this process
/// buffer an unbounded body on the credential-checking path.
pub(crate) const MAX_FETCH_BYTES: usize = 256 * 1024;

/// Cap on keys taken from one JWK Set, for the same reason as [`MAX_FETCH_BYTES`]:
/// every key is parsed and scanned on lookup, and no real AS publishes dozens.
const MAX_JWKS_KEYS: usize = 64;

/// A failed key refresh: discovery, fetch, or a key set with nothing usable in
/// it. The keys held before the attempt are kept.
///
/// `Display` is the whole cause chain, outermost first, joined with `": "` (e.g.
/// `fetching the JWKS from https://…: request failed: …`), so a log line needs no
/// special formatting to show the root cause.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct RefreshError {
    message: String,
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
            for_log(next.as_str())
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
                        url = %for_log(attempt.url().as_str()),
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
struct CachedKey {
    kid: Option<String>,
    key: DecodingKey,
    algorithms: Vec<Algorithm>,
    /// The JWK declared no `alg` and more than one allowlisted algorithm fits
    /// its type — the RFC 8725 §3.1 deviation warned about when the key first
    /// appears.
    ambiguous: bool,
}

/// The in-memory JWKS, the URI it came from, plus when we last *attempted* to
/// refresh it.
///
/// Attempt, not success, on purpose: a failing IdP must be backed off exactly like
/// a successful-but-stale one, or an outage turns every junk token into a retry
/// against a service that is already struggling.
#[derive(Default)]
struct JwksCache {
    /// The configured `jwks_uri` when there is one; otherwise `None` until
    /// discovery fills it in, after which it is fixed for the life of the
    /// process (a new value means a config change, which means a new validator).
    jwks_uri: Option<String>,
    keys: Vec<CachedKey>,
    last_attempt: Option<Instant>,
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
        Self {
            issuer: config.issuer.clone(),
            allow_insecure_http: config.allow_insecure_http,
            algorithms: config.algorithms.clone(),
            naming: config.key_naming.clone(),
            http,
            jwks: RwLock::new(JwksCache {
                jwks_uri: config.jwks_uri.clone().filter(|uri| !uri.trim().is_empty()),
                ..JwksCache::default()
            }),
            refresh_lock: Arc::new(Mutex::new(())),
            min_refetch_interval,
        }
    }

    /// Load (or reload) the key set now, discovering the JWKS URI first if
    /// needed. Returns how many usable keys it holds. On failure the previous
    /// keys are kept.
    pub(crate) async fn refresh_now(self: &Arc<Self>) -> Result<usize, RefreshError> {
        let guard = Arc::clone(&self.refresh_lock).lock_owned().await;
        self.refresh_detached(guard)
            .await
            .map_err(|message| RefreshError { message })
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
    ) -> Result<usize, String> {
        let store = Arc::clone(self);
        let task = tokio::spawn(async move {
            let _refreshing = guard;
            store.refresh().await
        });
        task.await
            .unwrap_or_else(|e| Err(format!("the key refresh task did not finish: {e}")))
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
                issuer = %self.issuer,
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
    /// a success, and leaves the old keys in place on any failure.
    async fn refresh(&self) -> Result<usize, String> {
        let known_uri = {
            let mut cache = self.jwks.write().await;
            cache.last_attempt = Some(Instant::now());
            cache.jwks_uri.clone()
        };
        let jwks_uri = match known_uri {
            Some(uri) => uri,
            None => {
                let uri = self.discover_jwks_uri().await?;
                info!(
                    issuer = %self.issuer,
                    jwks_uri = %uri,
                    "OAuth: discovered the JWKS URI from the issuer's metadata"
                );
                if plain_http_non_loopback(&uri) {
                    // Reachable only with the opt-in: `jwks_uri_from_metadata`
                    // refuses this without it.
                    warn!(
                        jwks_uri = %uri,
                        "the discovered JWKS URI uses plain http on a non-loopback host \
                         ({} is set) — signing keys fetched over it can be substituted by \
                         anyone on the path. Use https.",
                        self.naming.key("allow_insecure_http")
                    );
                }
                self.jwks.write().await.jwks_uri = Some(uri.clone());
                uri
            }
        };
        let keys = self
            .fetch_jwks(&jwks_uri)
            .await
            .map_err(|e| format!("fetching the JWKS from {jwks_uri}: {e}"))?;
        let count = keys.len();
        debug!(count, jwks_uri = %jwks_uri, "Fetched JWKS");
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
    async fn discover_jwks_uri(&self) -> Result<String, String> {
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
                    Err(e) => errors.push(format!("{url}: {e}")),
                },
                Err(e) => errors.push(format!("{url}: {e}")),
            }
        }
        Err(format!(
            "could not discover a jwks_uri for {issuer_key} {:?} — set {} explicitly or fix \
             the issuer. Tried: {}",
            self.issuer,
            self.naming.key("jwks_uri"),
            errors.join("; ")
        ))
    }

    async fn fetch_jwks(&self, uri: &str) -> Result<Vec<CachedKey>, String> {
        let doc = self.fetch_json(uri).await?;
        let entries = doc
            .get("keys")
            .and_then(Value::as_array)
            .ok_or_else(|| "response is not a JWK Set (no \"keys\" array)".to_string())?;
        if entries.len() > MAX_JWKS_KEYS {
            warn!(
                published = entries.len(),
                used = MAX_JWKS_KEYS,
                "JWK Set has more keys than this server will consider; the rest are ignored"
            );
        }

        let mut keys = Vec::new();
        for entry in entries.iter().take(MAX_JWKS_KEYS) {
            // Parsed one key at a time: `jsonwebtoken::jwk::JwkSet` refuses the
            // WHOLE set if any single key has a kty/crv/alg it does not model (an
            // X25519 encryption key, say), and one exotic key must not take the
            // usable ones down with it.
            let jwk: Jwk = match serde_json::from_value(entry.clone()) {
                Ok(jwk) => jwk,
                Err(e) => {
                    debug!(error = %e, "Skipping a JWKS entry this server cannot parse");
                    continue;
                }
            };
            if let Some(key) = cached_key(&jwk, &self.algorithms) {
                keys.push(key);
            }
        }
        if keys.is_empty() {
            return Err(format!(
                "the JWK Set contained no usable signature keys for {} {:?}",
                self.naming.key("algorithms"),
                self.algorithms
            ));
        }
        Ok(keys)
    }

    /// GET a JSON document with the body capped at [`MAX_FETCH_BYTES`].
    async fn fetch_json(&self, url: &str) -> Result<Value, String> {
        let mut resp = self
            .http
            .get(url)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|e| context("request failed", &e))?
            .error_for_status()
            .map_err(|e| context("non-success status", &e))?;
        if let Some(len) = resp.content_length()
            && len > MAX_FETCH_BYTES as u64
        {
            return Err(format!(
                "response is {len} bytes, over the {MAX_FETCH_BYTES}-byte cap"
            ));
        }
        let mut body = Vec::new();
        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(|e| context("reading the response body", &e))?
        {
            if body.len() + chunk.len() > MAX_FETCH_BYTES {
                return Err(format!("response exceeds the {MAX_FETCH_BYTES}-byte cap"));
            }
            body.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&body).map_err(|e| context("response was not JSON", &e))
    }
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
fn discovery_urls(issuer: &str) -> Vec<String> {
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
    let found = doc.get("issuer").and_then(Value::as_str);
    if found != Some(issuer) {
        return Err(format!(
            "metadata issuer {} does not match {issuer_key} {issuer:?} byte-for-byte \
             (RFC 8414 §3.3 / OIDC Discovery §4.3: such a document must not be used)",
            found.map_or_else(|| "(absent)".to_string(), |f| format!("{:?}", for_log(f)))
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
                    for_log(uri)
                ));
            }
        }
        other => {
            return Err(format!(
                "jwks_uri scheme {other:?} is not allowed for issuer {issuer:?}"
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
    fn the_http_client_builds_with_the_enabled_tls_backend() {
        // Whichever of `rustls-tls` / `native-tls` this build enabled, the client
        // the validator fetches keys with must build.
        http_client(false, OPT_IN.to_string()).expect("the JWKS HTTP client must build");
    }
}
