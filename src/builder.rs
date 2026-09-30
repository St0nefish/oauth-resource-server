//! [`OAuthValidatorBuilder`]: how an [`OAuthValidator`] fetches its keys,
//! beyond what [`crate::OAuthConfig`] describes — extra TLS trust anchors, an
//! explicit proxy, the fetch timeout, and a key set to start from.
//!
//! These are code, not config: an application wires them in where it builds
//! the validator, and, like every config setting, they take effect only when
//! a validator is built. No `reqwest` type appears here: the options are
//! plain bytes, strings and durations, turned into the HTTP client's own
//! types privately, so the HTTP library's version stays out of this crate's
//! public API.

use std::time::Duration;

use tracing::{info, warn};

use crate::config::ResolvedOAuthConfig;
use crate::jwks::{
    CachedKey, DEFAULT_FETCH_TIMEOUT, FetchSettings, JWKS_MIN_REFETCH_INTERVAL, MAX_FETCH_TIMEOUT,
    MIN_FETCH_TIMEOUT, error_chain, keys_from_jwk_set_json, redact_url,
};
use crate::validator::{OAuthValidator, ValidatorError, parsed_plain_http_non_loopback};

/// Builds an [`OAuthValidator`] with options for its metadata and JWKS
/// fetches; get one from [`OAuthValidator::builder`].
///
/// With no option set, [`OAuthValidatorBuilder::build`] behaves exactly like
/// [`OAuthValidator::new`] (which is implemented as that). Every option is
/// checked by `build`, never earlier, and a refused one is a
/// [`ValidatorError`] — nothing is silently ignored. Calling an option twice
/// replaces the earlier value, except
/// [`OAuthValidatorBuilder::add_root_certificate_pem`], which adds.
///
/// Every protection a fetched key set gets still applies whatever is set
/// here: the redirect policy, the `https` and `allow_insecure_http` rules,
/// the response size cap, the key-count cap and per-key algorithm narrowing.
///
/// `Debug` never prints the proxy URL (it may carry a credential) or the
/// initial key set, only whether they are set.
///
/// # Examples
///
/// An authorization server behind a private CA, reached through a proxy:
///
/// ```no_run
/// use std::sync::Arc;
/// use std::time::Duration;
///
/// use oauth_resource_server::{KeyNaming, OAuthConfig, OAuthValidator};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let resolved = OAuthConfig {
///     enabled: true,
///     issuer: "https://idp.internal.example.com/".into(),
///     audience: "example-api".into(),
///     resource: "https://api.example.com/".into(),
///     required_scope: Some("api:read".into()),
///     ..OAuthConfig::default()
/// }
/// .resolve(KeyNaming::Dotted("oauth"))?
/// .expect("OAuth is enabled");
///
/// let ca = std::fs::read("/etc/ssl/private-ca.pem")?;
/// let validator = Arc::new(
///     OAuthValidator::builder(&resolved)
///         .add_root_certificate_pem(&ca)
///         .proxy("http://proxy.example.com:3128")
///         .fetch_timeout(Duration::from_secs(5))
///         .build()?,
/// );
/// validator.spawn_background_refresh();
/// # Ok(())
/// # }
/// ```
#[must_use = "a builder does nothing until `build` is called"]
#[derive(Clone)]
pub struct OAuthValidatorBuilder {
    config: ResolvedOAuthConfig,
    root_pems: Vec<Vec<u8>>,
    proxy: Option<String>,
    fetch_timeout: Duration,
    initial_jwks: Option<String>,
    /// [`JWKS_MIN_REFETCH_INTERVAL`] except in this crate's own tests.
    min_refetch_interval: Duration,
}

impl std::fmt::Debug for OAuthValidatorBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthValidatorBuilder")
            .field("issuer", &redact_url(&self.config.issuer))
            .field("root_certificate_pems", &self.root_pems.len())
            .field("proxy", &self.proxy.as_ref().map(|_| "<redacted>"))
            .field("fetch_timeout", &self.fetch_timeout)
            .field(
                "initial_jwks_bytes",
                &self.initial_jwks.as_ref().map(String::len),
            )
            .finish_non_exhaustive()
    }
}

impl OAuthValidatorBuilder {
    pub(crate) fn new(config: &ResolvedOAuthConfig) -> Self {
        Self {
            config: config.clone(),
            root_pems: Vec::new(),
            proxy: None,
            fetch_timeout: DEFAULT_FETCH_TIMEOUT,
            initial_jwks: None,
            min_refetch_interval: JWKS_MIN_REFETCH_INTERVAL,
        }
    }

    /// Trust the certificate(s) in `pem` as TLS root certificates for the
    /// metadata and JWKS fetches, **in addition to** the roots the TLS
    /// feature already trusts (the Mozilla set for `rustls-tls`, the OS store
    /// for `rustls-tls-native-roots` and `native-tls`) — never instead of
    /// them. For an authorization server behind a private or internal CA.
    /// When `native-tls` and a rustls feature are both enabled, reqwest uses
    /// native-tls, so the OS store is what these are added to.
    ///
    /// `pem` may hold one certificate or a bundle of several (every
    /// `CERTIFICATE` block is added). Call it again to add another file. It
    /// works with every TLS feature.
    ///
    /// # Security
    ///
    /// A root added here can vouch for ANY host name, not only the
    /// authorization server's, for this validator's fetches: whoever holds
    /// the CA's private key can serve signing keys this validator trusts.
    /// Add the CA that actually issues the authorization server's
    /// certificate, and nothing broader.
    ///
    /// Pass only real CA certificates. Under rustls a trust anchor keeps
    /// only its subject, public key and name constraints — its
    /// `basicConstraints` and `keyUsage` are ignored — so a `CA:FALSE` leaf
    /// certificate passed here becomes an anchor that can issue for any
    /// host.
    ///
    /// # Errors
    ///
    /// None here; [`OAuthValidatorBuilder::build`] returns
    /// [`ValidatorError::InvalidRootCertificate`] when `pem` holds no
    /// certificate, one the TLS backend cannot parse or use, or any
    /// private-key block (`-----BEGIN … PRIVATE KEY-----`): a resource server
    /// never needs a private key, so one here is a mistake, not ignored.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn f(resolved: &oauth_resource_server::ResolvedOAuthConfig)
    /// #     -> Result<(), Box<dyn std::error::Error>> {
    /// use oauth_resource_server::OAuthValidator;
    ///
    /// let validator = OAuthValidator::builder(resolved)
    ///     .add_root_certificate_pem(&std::fs::read("/etc/ssl/private-ca.pem")?)
    ///     .build()?;
    /// # drop(validator);
    /// # Ok(())
    /// # }
    /// ```
    pub fn add_root_certificate_pem(mut self, pem: &[u8]) -> Self {
        self.root_pems.push(pem.to_vec());
        self
    }

    /// Send the metadata and JWKS fetches through the proxy at `url`
    /// (`http://host:port`, or `https://` for a TLS connection to the proxy
    /// itself; `user:password@` in it is sent as proxy Basic auth). https
    /// fetches are tunnelled with `CONNECT`, so TLS still runs end to end to
    /// the authorization server and its certificate is still checked.
    ///
    /// Without this, non-loopback fetches use reqwest's own proxy handling,
    /// untouched: the `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY`/`NO_PROXY`
    /// environment variables and, on macOS and Windows when reqwest's
    /// `system-proxy` feature is on in the build, the system settings.
    /// Setting a proxy here turns all of those off, `NO_PROXY` included.
    /// Either way, a fetch of a loopback URL (`localhost`, `*.localhost`,
    /// `127.0.0.0/8`, `::1`) uses a separate client with no proxy at all: a
    /// loopback URL names this host, which through a proxy it would not, and
    /// a plain-http loopback fetch would cross the network in cleartext.
    /// (A redirect from a non-loopback URL to a loopback one stays in the
    /// client the fetch started with; see the README's security model.)
    ///
    /// # Security
    ///
    /// The URL may carry a credential, so it never appears in a log line or
    /// `Debug` other than redacted (`***@`), and a refused one never appears
    /// in the error at all. A plain-`http` proxy on a non-loopback host needs
    /// no opt-in: an https fetch through it is a `CONNECT` tunnel it cannot
    /// read or alter, and a plain-http fetch already needed
    /// `allow_insecure_http` for its own URL. A credential in such a proxy
    /// URL, though, would cross the network in cleartext, so that is refused
    /// unless `allow_insecure_http` is set (and then logged as a `warn`) —
    /// use an `https://` proxy URL for a proxy that authenticates.
    ///
    /// # Errors
    ///
    /// None here; [`OAuthValidatorBuilder::build`] returns
    /// [`ValidatorError::InvalidProxy`] unless `url` is an absolute `http` or
    /// `https` URL with a host and nothing after the port (no path, query or
    /// fragment), with no space, control or non-ASCII character, and — when
    /// plain http on a non-loopback host — no credential unless
    /// `allow_insecure_http` is set. SOCKS proxies are not supported.
    ///
    /// # Examples
    ///
    /// ```
    /// # let resolved = oauth_resource_server::OAuthConfig {
    /// #     enabled: true,
    /// #     issuer: "https://auth.example.com/".into(),
    /// #     audience: "example-api".into(),
    /// #     resource: "https://api.example.com/".into(),
    /// #     required_scope: Some("api:read".into()),
    /// #     ..Default::default()
    /// # }
    /// # .resolve(oauth_resource_server::KeyNaming::Dotted("oauth"))
    /// # .unwrap()
    /// # .unwrap();
    /// use oauth_resource_server::OAuthValidator;
    ///
    /// let validator = OAuthValidator::builder(&resolved)
    ///     .proxy("http://proxy.example.com:3128")
    ///     .build()
    ///     .unwrap();
    /// # drop(validator);
    /// ```
    pub fn proxy(mut self, url: impl Into<String>) -> Self {
        self.proxy = Some(url.into());
        self
    }

    /// How long one metadata or JWKS request may take, connection through
    /// the last byte of the body; [`DEFAULT_FETCH_TIMEOUT`] (10 s) unless
    /// set.
    ///
    /// A refresh holds the refresh lock for as long as its requests take
    /// (discovery can chain three), and a request whose key is not cached
    /// waits behind it, so this is also how long a stalled authorization
    /// server can hold up such a request.
    ///
    /// # Errors
    ///
    /// None here; [`OAuthValidatorBuilder::build`] returns
    /// [`ValidatorError::FetchTimeoutOutOfRange`] outside
    /// [`MIN_FETCH_TIMEOUT`]`..=`[`MAX_FETCH_TIMEOUT`] (1 s to 60 s), zero
    /// included.
    ///
    /// # Examples
    ///
    /// ```
    /// # let resolved = oauth_resource_server::OAuthConfig {
    /// #     enabled: true,
    /// #     issuer: "https://auth.example.com/".into(),
    /// #     audience: "example-api".into(),
    /// #     resource: "https://api.example.com/".into(),
    /// #     required_scope: Some("api:read".into()),
    /// #     ..Default::default()
    /// # }
    /// # .resolve(oauth_resource_server::KeyNaming::Dotted("oauth"))
    /// # .unwrap()
    /// # .unwrap();
    /// use std::time::Duration;
    ///
    /// use oauth_resource_server::OAuthValidator;
    ///
    /// let validator = OAuthValidator::builder(&resolved)
    ///     .fetch_timeout(Duration::from_secs(3))
    ///     .build()
    ///     .unwrap();
    /// # drop(validator);
    /// ```
    pub fn fetch_timeout(mut self, timeout: Duration) -> Self {
        self.fetch_timeout = timeout;
        self
    }

    /// Start with the keys in `json`, a JWK Set (`{"keys": [...]}`), already
    /// loaded: tokens they signed validate before — or without — any fetch.
    /// For a warm start through an authorization-server outage, or a key set
    /// shipped alongside the application. Read one from a file with
    /// `std::fs::read_to_string` and pass the text.
    ///
    /// The set goes through exactly the checks a fetched one does: the
    /// 256 KiB size cap, at most 64 keys considered, and per-key narrowing
    /// (no HMAC `oct` key, no `use: enc` or `key_ops`-without-`verify` key,
    /// each key limited to the configured algorithms its own type and `alg`
    /// allow; an unusable entry is skipped).
    ///
    /// The seeded keys are refreshed like fetched ones: the first refresh
    /// that succeeds (from [`OAuthValidator::spawn_background_refresh`],
    /// [`OAuthValidator::refresh_now`] or an unknown `kid`) replaces them
    /// with the authorization server's set, and a failed one keeps them.
    /// Until then, [`OAuthValidator::key_set_status`] reports them in `keys`
    /// (so [`OAuthValidator::is_ready`] is `true` from the start), with
    /// `last_attempt` and `last_success` still `None`: no fetch has happened,
    /// and `last_success` only ever means the authorization server answered.
    /// `keys > 0` with `last_success == None` is how to tell seeded keys
    /// apart. Seeded keys count as held, so a failed background pass retries
    /// on the held-keys schedule (a minute, backing off to an hour), not the
    /// 5-second keyless one.
    ///
    /// # Security
    ///
    /// Seeded keys are trusted exactly like keys the authorization server
    /// served — until a refresh succeeds, even one it has since withdrawn.
    /// Seed only a key set taken from the authorization server itself.
    ///
    /// # Errors
    ///
    /// None here; [`OAuthValidatorBuilder::build`] returns
    /// [`ValidatorError::InvalidInitialJwks`] when `json` is over the size
    /// cap, not JSON, not a JWK Set, or holds no key usable under the
    /// configured algorithms.
    ///
    /// # Examples
    ///
    /// ```
    /// # let resolved = oauth_resource_server::OAuthConfig {
    /// #     enabled: true,
    /// #     issuer: "https://auth.example.com/".into(),
    /// #     audience: "example-api".into(),
    /// #     resource: "https://api.example.com/".into(),
    /// #     required_scope: Some("api:read".into()),
    /// #     ..Default::default()
    /// # }
    /// # .resolve(oauth_resource_server::KeyNaming::Dotted("oauth"))
    /// # .unwrap()
    /// # .unwrap();
    /// # let jwks = r#"{"keys":[{"kty":"EC","crv":"P-256","alg":"ES256","kid":"k",
    /// #     "x":"wpIx0OTOkazNUz0OsLr6pbXMEWuAC7PyXfdjeT12isI",
    /// #     "y":"f3g97NNNjq8W3-K-Nx9JIbnBadxSVz3aWyKk5dGqAtk"}]}"#;
    /// use oauth_resource_server::OAuthValidator;
    ///
    /// // `jwks`: a JWK Set saved from the authorization server's jwks_uri.
    /// let validator = OAuthValidator::builder(&resolved)
    ///     .initial_jwks(jwks)
    ///     .build()
    ///     .unwrap();
    /// assert!(validator.is_ready());
    /// assert_eq!(validator.key_set_status().last_success, None);
    /// ```
    pub fn initial_jwks(mut self, json: &str) -> Self {
        self.initial_jwks = Some(json.to_string());
        self
    }

    /// Build the validator.
    ///
    /// Does no network I/O, like [`OAuthValidator::new`]: keys are fetched on
    /// first use or by [`OAuthValidator::spawn_background_refresh`] (unless
    /// seeded). Logs the same startup warnings `new` does.
    ///
    /// # Errors
    ///
    /// Every error [`OAuthValidator::new`] returns, checked first; then
    /// [`ValidatorError::FetchTimeoutOutOfRange`],
    /// [`ValidatorError::InvalidRootCertificate`],
    /// [`ValidatorError::InvalidProxy`] or
    /// [`ValidatorError::InvalidInitialJwks`] for a refused option (the
    /// first one found, in that order).
    pub fn build(self) -> Result<OAuthValidator, ValidatorError> {
        OAuthValidator::from_builder(&self)
    }

    pub(crate) fn config(&self) -> &ResolvedOAuthConfig {
        &self.config
    }

    pub(crate) fn refetch_interval(&self) -> Duration {
        self.min_refetch_interval
    }

    #[cfg(test)]
    pub(crate) fn min_refetch_interval(mut self, interval: Duration) -> Self {
        self.min_refetch_interval = interval;
        self
    }

    /// The HTTP client settings, every option checked.
    pub(crate) fn fetch_settings(&self) -> Result<FetchSettings, ValidatorError> {
        if !(MIN_FETCH_TIMEOUT..=MAX_FETCH_TIMEOUT).contains(&self.fetch_timeout) {
            return Err(ValidatorError::FetchTimeoutOutOfRange {
                timeout: self.fetch_timeout,
                min: MIN_FETCH_TIMEOUT,
                max: MAX_FETCH_TIMEOUT,
            });
        }
        let mut roots = Vec::new();
        for (index, pem) in self.root_pems.iter().enumerate() {
            roots.extend(
                parse_root_pem(pem)
                    .map_err(|reason| ValidatorError::InvalidRootCertificate { index, reason })?,
            );
        }
        let opt_in_key = self.config.key_naming.key("allow_insecure_http");
        let proxy = self
            .proxy
            .as_deref()
            .map(|raw| check_proxy(raw, self.config.allow_insecure_http, &opt_in_key))
            .transpose()?;
        Ok(FetchSettings {
            timeout: self.fetch_timeout,
            roots,
            proxy,
        })
    }

    /// The keys [`OAuthValidatorBuilder::initial_jwks`] seeds, through the
    /// same parsing and narrowing as a fetched set; empty without one.
    pub(crate) fn seed_keys(&self) -> Result<Vec<CachedKey>, ValidatorError> {
        let Some(json) = &self.initial_jwks else {
            return Ok(Vec::new());
        };
        let keys = keys_from_jwk_set_json(json, &self.config.algorithms, &self.config.key_naming)
            .map_err(|e| ValidatorError::InvalidInitialJwks {
            reason: e.to_string(),
        })?;
        info!(
            keys = keys.len(),
            "OAuth: signing keys seeded from the initial JWK Set; the first successful refresh \
             replaces them"
        );
        Ok(keys)
    }
}

/// Every certificate in `pem`, or why it is unusable. A PEM with no
/// `CERTIFICATE` block is refused rather than silently adding nothing.
///
/// rustls parses a certificate's DER only when a client is built, and
/// native-tls when the certificate is read, so a probe client trusting only
/// these certificates is built here: a certificate either backend cannot use
/// fails with its own index, not later as a generic HTTP-client error.
fn parse_root_pem(pem: &[u8]) -> Result<Vec<reqwest::Certificate>, String> {
    // A trust anchor is public; a resource server never needs a private key,
    // and one handed over by mistake should not be quietly skipped.
    if String::from_utf8_lossy(pem)
        .lines()
        .any(|line| line.trim_start().starts_with("-----BEGIN") && line.contains("PRIVATE KEY"))
    {
        return Err(
            "it contains private-key material (a PRIVATE KEY block) — pass only the CA \
             certificate; a resource server never needs a private key"
                .to_string(),
        );
    }
    let certs = reqwest::Certificate::from_pem_bundle(pem).map_err(|e| error_chain(&e))?;
    if certs.is_empty() {
        return Err("no PEM CERTIFICATE block found".to_string());
    }
    let mut probe = reqwest::Client::builder()
        .tls_built_in_root_certs(false)
        .no_proxy();
    for cert in &certs {
        probe = probe.add_root_certificate(cert.clone());
    }
    probe.build().map_err(|e| error_chain(&e))?;
    Ok(certs)
}

/// The proxy URL, parsed, or a refusal that shows it only redacted.
///
/// A refused value is never echoed, not even redacted: a malformed URL can
/// hide its credential where no parser sees userinfo
/// (`http://alice:1234/s3cret@host` is host `alice`, port `1234`, path
/// `/s3cret@host`). The error shows the scheme, when it is one of the
/// proxy schemes, and nothing else.
///
/// A plain-http proxy URL on a non-loopback host carrying a credential is
/// refused without `allow_insecure_http` (named by `opt_in_key`): the
/// credential would cross the network in cleartext. Without a credential it
/// is accepted — https fetches `CONNECT`-tunnel through it end to end.
fn check_proxy(
    raw: &str,
    allow_insecure_http: bool,
    opt_in_key: &str,
) -> Result<reqwest::Url, ValidatorError> {
    let shown = reqwest::Url::parse(raw)
        .ok()
        .filter(|u| {
            matches!(
                u.scheme(),
                "http" | "https" | "socks4" | "socks4a" | "socks5" | "socks5h"
            )
        })
        .map_or_else(
            || "<redacted>".to_string(),
            |u| format!("{}://<redacted>", u.scheme()),
        );
    let refuse = |reason: &str| ValidatorError::InvalidProxy {
        proxy: shown.clone(),
        reason: reason.to_string(),
    };
    if raw.is_empty() || raw.chars().any(|c| !c.is_ascii_graphic()) {
        return Err(refuse(
            "it is empty or contains a space, a control character or a non-ASCII character",
        ));
    }
    // The parse error is not quoted: some carry the input's text.
    let url = reqwest::Url::parse(raw).map_err(|_| refuse("it is not an absolute URL"))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(refuse(
            "it must be an http:// or https:// URL (SOCKS proxies are not supported)",
        ));
    }
    if url.host_str().is_none_or(str::is_empty) {
        return Err(refuse("it has no host"));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(refuse("it must not carry a query or fragment"));
    }
    if url.path() != "/" {
        return Err(refuse("it must not carry a path"));
    }
    // Decided on the parsed, normalized URL: `http:/alice:…@host`,
    // `http:alice:…@host` and `HTTP:\\alice:…@host` all parse to
    // `http://alice:…@host`, which a raw `http://` prefix test would miss.
    let credential = !url.username().is_empty() || url.password().is_some();
    if parsed_plain_http_non_loopback(&url) && credential {
        if !allow_insecure_http {
            return Err(refuse(&format!(
                "it carries a credential but is plain http on a non-loopback host, so the \
                 credential would cross the network in cleartext — use an https:// proxy URL, \
                 or set {opt_in_key} to permit it"
            )));
        }
        warn!(
            proxy = %redact_url(url.as_str()),
            "OAuth: the proxy URL carries a credential but is plain http on a non-loopback \
             host — the credential crosses the network in cleartext ({opt_in_key} is set). \
             Use an https:// proxy URL."
        );
    }
    Ok(url)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use serde_json::json;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_rustls::rustls;
    use tokio_rustls::rustls::pki_types::pem::PemObject;
    use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

    use super::*;
    use crate::RefreshErrorKind;
    use crate::testing;

    // A throwaway CA and a server certificate it signed (P-256, SAN
    // `127.0.0.1` and `localhost`, valid until 2126), generated with openssl
    // for this test suite only and used nowhere else. The private key is
    // public knowledge: nothing outside these tests may trust this CA.
    const TEST_CA_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIBtzCCAV2gAwIBAgIUZQgSlghpInufq/WjTUNuj0M1omMwCgYIKoZIzj0EAwIw
KDEmMCQGA1UEAwwdb2F1dGgtcmVzb3VyY2Utc2VydmVyIHRlc3QgQ0EwIBcNMjYw
OTI5MjAxMjAyWhgPMjEyNjA5MDUyMDEyMDJaMCgxJjAkBgNVBAMMHW9hdXRoLXJl
c291cmNlLXNlcnZlciB0ZXN0IENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
e7My2gfib5QnEAeGyAJKjT2GdFWSr/gsJp9Qt89ft6HM3x/OpSD4QcJCYX9PYiHV
W6SHYgHp4WFVjGM9qjmoraNjMGEwHwYDVR0jBBgwFoAU9eooe6hx3H8ZdYPDWBk9
aL6DwgYwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYE
FPXqKHuocdx/GXWDw1gZPWi+g8IGMAoGCCqGSM49BAMCA0gAMEUCICqXMiIGLPEt
7US8NxHfZFnG0C9Vm8OpblVteFqhgC35AiEAkX4NND+zxhsgLubA/IRLv8Y1X/UF
uaPm9BLhB9Et/O8=
-----END CERTIFICATE-----
";
    const TEST_SERVER_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIB1DCCAXmgAwIBAgIUQ9Ls7gwbeQhAuWSfkTYfsDchl6wwCgYIKoZIzj0EAwIw
KDEmMCQGA1UEAwwdb2F1dGgtcmVzb3VyY2Utc2VydmVyIHRlc3QgQ0EwIBcNMjYw
OTI5MjAxMjAyWhgPMjEyNjA5MDUyMDEyMDJaMBQxEjAQBgNVBAMMCWxvY2FsaG9z
dDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABBCXOskkxlIBL+lhnOrlrPu1L9gC
jY+G7j8/szHLOJNsRDMgpxFmu6Xt23R6KqWvpxHbnPFAiokHl/7TkMBswWWjgZIw
gY8wDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYB
BQUHAwEwGgYDVR0RBBMwEYcEfwAAAYIJbG9jYWxob3N0MB0GA1UdDgQWBBSzR7DI
xRoRBT2TR7C6hIp0ZIjywTAfBgNVHSMEGDAWgBT16ih7qHHcfxl1g8NYGT1ovoPC
BjAKBggqhkjOPQQDAgNJADBGAiEA1zI6rId65FWP1wGk6HgvZM6luKCVqMKrpALd
FvufkWECIQD9fFokhSzPz7PDudHrdBF3qa/53rK4XeyPR1eSxhBksA==
-----END CERTIFICATE-----
";
    const TEST_SERVER_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgAh1xbGWuQST6HGs7
d7BfjO2Q7Vr/U9DdDr6Mr8l/olKhRANCAAQQlzrJJMZSAS/pYZzq5az7tS/YAo2P
hu4/P7MxyziTbEQzIKcRZrul7dt0eiqlr6cR25zxQIqJB5f+05DAbMFl
-----END PRIVATE KEY-----
";

    const SECRETS: [&str; 3] = ["alice", "s3cret", "t0ken"];

    fn assert_no_secret(text: &str) {
        for secret in SECRETS {
            assert!(!text.contains(secret), "{secret:?} leaked into: {text}");
        }
    }

    /// An https server on 127.0.0.1 presenting [`TEST_SERVER_CERT_PEM`] and
    /// answering every request with `body`. Returns its JWKS URL and how many
    /// requests got through the TLS handshake.
    async fn spawn_https_jwks(body: String) -> (String, Arc<AtomicUsize>) {
        spawn_https("200 OK\r\nContent-Type: application/json", body).await
    }

    /// [`spawn_https_jwks`] answering with the status line and extra headers
    /// `head` (`"302 Found\r\nLocation: ..."`, say).
    async fn spawn_https(head: &'static str, body: String) -> (String, Arc<AtomicUsize>) {
        let certs: Vec<CertificateDer<'static>> =
            CertificateDer::pem_slice_iter(TEST_SERVER_CERT_PEM.as_bytes())
                .collect::<Result<_, _>>()
                .unwrap();
        let key = PrivateKeyDer::from_pem_slice(TEST_SERVER_KEY_PEM.as_bytes()).unwrap();
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&hits);
        tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                let body = body.clone();
                let counter = Arc::clone(&counter);
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(sock).await else {
                        return;
                    };
                    let mut buf = Vec::new();
                    let mut tmp = [0u8; 4096];
                    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        match tls.read(&mut tmp).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&tmp[..n]),
                        }
                    }
                    counter.fetch_add(1, Ordering::SeqCst);
                    let resp = format!(
                        "HTTP/1.1 {head}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = tls.write_all(resp.as_bytes()).await;
                    let _ = tls.shutdown().await;
                });
            }
        });
        (format!("https://127.0.0.1:{port}/jwks"), hits)
    }

    #[tokio::test]
    async fn the_builder_with_no_options_is_new() {
        let server = testing::spawn_jwks_server("200 OK", testing::jwks_body()).await;
        let cfg = testing::resolved_config(&server.url);
        let built = OAuthValidator::builder(&cfg).build().unwrap();
        let new = OAuthValidator::new(&cfg).unwrap();
        assert_eq!(format!("{built:?}"), format!("{new:?}"));
        assert_eq!(built.config(), new.config());
        assert_eq!(built.metadata(), new.metadata());
        assert_eq!(built.metadata_path(), new.metadata_path());
        assert_eq!(
            built.invalid_token_challenge(),
            new.invalid_token_challenge()
        );
        assert_eq!(
            built.insufficient_scope_challenge(),
            new.insufficient_scope_challenge()
        );
        assert_eq!(built.key_set_status(), new.key_set_status());
        assert!(!built.is_ready());

        let defaults = OAuthValidator::builder(&cfg).fetch_settings().unwrap();
        assert_eq!(defaults.timeout, DEFAULT_FETCH_TIMEOUT);
        assert!(defaults.roots.is_empty());
        assert!(defaults.proxy.is_none());
        assert!(
            OAuthValidator::builder(&cfg)
                .seed_keys()
                .unwrap()
                .is_empty()
        );

        for v in [&built, &new] {
            v.validate(&testing::valid_token()).await.unwrap();
        }
        assert_eq!(server.hits.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_private_ca_root_lets_the_tls_fetch_succeed_and_its_absence_fails_closed() {
        let (url, hits) = spawn_https_jwks(testing::jwks_body()).await;
        let cfg = testing::resolved_config(&url);

        let without = OAuthValidator::new(&cfg).unwrap();
        let err = without.refresh_now().await.unwrap_err();
        assert_eq!(err.kind(), RefreshErrorKind::Fetch, "{err}");
        assert!(!without.is_ready());
        assert!(without.validate(&testing::valid_token()).await.is_err());
        assert_eq!(
            hits.load(Ordering::SeqCst),
            0,
            "no request past the handshake"
        );

        let with = OAuthValidator::builder(&cfg)
            .add_root_certificate_pem(TEST_CA_PEM.as_bytes())
            .build()
            .unwrap();
        assert_eq!(with.refresh_now().await.unwrap(), 1);
        with.validate(&testing::valid_token()).await.unwrap();
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    /// End to end: an https key fetch redirected to plain http is refused —
    /// loopback target or not, opt-in or not — and the plain-http URL is
    /// never requested.
    #[tokio::test]
    async fn an_https_fetch_redirected_to_plain_http_is_refused() {
        let plain = testing::spawn_jwks_server("200 OK", testing::jwks_body()).await;
        let head: &'static str =
            Box::leak(format!("302 Found\r\nLocation: {}", plain.url).into_boxed_str());
        let (url, hits) = spawn_https(head, String::new()).await;
        for allow_insecure_http in [false, true] {
            let mut cfg = testing::resolved_config(&url);
            cfg.allow_insecure_http = allow_insecure_http;
            let v = OAuthValidator::builder(&cfg)
                .add_root_certificate_pem(TEST_CA_PEM.as_bytes())
                .build()
                .unwrap();
            let err = v.refresh_now().await.unwrap_err();
            assert_eq!(err.kind(), RefreshErrorKind::Fetch);
            assert!(
                err.to_string()
                    .contains("redirect from https to a non-https URL refused"),
                "{err}"
            );
        }
        assert_eq!(hits.load(Ordering::SeqCst), 2, "the https URL was asked");
        assert_eq!(plain.hits.load(Ordering::SeqCst), 0, "the http one never");
    }

    #[tokio::test]
    async fn a_pem_bundle_and_repeated_calls_add_every_certificate() {
        let (url, _) = spawn_https_jwks(testing::jwks_body()).await;
        let cfg = testing::resolved_config(&url);
        // The CA second in a bundle, after an unrelated certificate.
        let bundle = format!("{TEST_SERVER_CERT_PEM}{TEST_CA_PEM}");
        let v = OAuthValidator::builder(&cfg)
            .add_root_certificate_pem(bundle.as_bytes())
            .build()
            .unwrap();
        assert_eq!(v.refresh_now().await.unwrap(), 1);
        // The CA in a second call.
        let v = OAuthValidator::builder(&cfg)
            .add_root_certificate_pem(TEST_SERVER_CERT_PEM.as_bytes())
            .add_root_certificate_pem(TEST_CA_PEM.as_bytes())
            .build()
            .unwrap();
        assert_eq!(v.refresh_now().await.unwrap(), 1);
        let settings = OAuthValidator::builder(&cfg)
            .add_root_certificate_pem(bundle.as_bytes())
            .add_root_certificate_pem(TEST_CA_PEM.as_bytes())
            .fetch_settings()
            .unwrap();
        assert_eq!(settings.roots.len(), 3);
    }

    #[test]
    fn an_unusable_root_pem_is_a_build_error() {
        let cfg = testing::resolved_config("https://idp.example.test/jwks");
        for (pem, what) in [
            ("", "empty"),
            ("not a pem at all", "no PEM block"),
            (TEST_SERVER_KEY_PEM, "a private key, no certificate"),
            (
                &format!("{TEST_CA_PEM}{TEST_SERVER_KEY_PEM}"),
                "a certificate with a private key beside it",
            ),
            (
                &format!(
                    "{TEST_CA_PEM}-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n"
                ),
                "a certificate with a legacy private-key block beside it",
            ),
            (
                "-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n",
                "bad base64",
            ),
            (
                "-----BEGIN CERTIFICATE-----\nAAAAAAAA\n-----END CERTIFICATE-----\n",
                "valid base64, not a certificate",
            ),
        ] {
            let err = OAuthValidator::builder(&cfg)
                .add_root_certificate_pem(TEST_CA_PEM.as_bytes())
                .add_root_certificate_pem(pem.as_bytes())
                .build()
                .unwrap_err();
            assert!(
                matches!(err, ValidatorError::InvalidRootCertificate { index: 1, .. }),
                "{what}: {err:?}"
            );
        }
    }

    #[tokio::test]
    async fn fetches_go_through_the_proxy_and_its_credential_never_shows() {
        // A plain-HTTP forward proxy sees the absolute-form request target.
        // `jwks.example.test` never resolves, so a success can only have come
        // through the proxy.
        let target = "http://jwks.example.test/jwks";
        let proxy_server = testing::spawn_http_server(
            HashMap::from([(target.to_string(), ("200 OK", testing::jwks_body()))]),
            None,
        )
        .await;
        let mut cfg = testing::resolved_config(target);
        cfg.allow_insecure_http = true;
        let proxy_url = proxy_server
            .base
            .replacen("://", "://alice:s3cret@", 1)
            .to_string();
        let builder = OAuthValidator::builder(&cfg).proxy(&proxy_url);
        assert_no_secret(&format!("{builder:?}"));
        let v = builder.build().unwrap();
        assert_eq!(v.refresh_now().await.unwrap(), 1);
        assert_eq!(proxy_server.hits.load(Ordering::SeqCst), 1);
        v.validate(&testing::valid_token()).await.unwrap();
        assert_no_secret(&format!("{v:?} {:?}", v.key_set_status()));

        // A dead proxy fails the fetch closed, and the error does not name it.
        let v = OAuthValidator::builder(&cfg)
            .proxy("http://alice:s3cret@127.0.0.2:1")
            .build()
            .unwrap();
        let err = v.refresh_now().await.unwrap_err();
        assert_eq!(err.kind(), RefreshErrorKind::Fetch);
        assert_no_secret(&format!("{err} {err:?} {:?}", v.key_set_status()));
    }

    #[tokio::test]
    async fn a_loopback_target_bypasses_the_proxy() {
        let server = testing::spawn_jwks_server("200 OK", testing::jwks_body()).await;
        for host in ["127.0.0.1", "localhost"] {
            let cfg = testing::resolved_config(&server.url.replace("127.0.0.1", host));
            // Nothing listens on the proxy's port: used, it would fail.
            let v = OAuthValidator::builder(&cfg)
                .proxy("http://proxy.example.test:1")
                .build()
                .unwrap();
            assert_eq!(v.refresh_now().await.unwrap(), 1, "{host}");
        }
    }

    #[test]
    fn a_malformed_proxy_url_is_refused_without_showing_it() {
        let cfg = testing::resolved_config("https://idp.example.test/jwks");
        for proxy in [
            "",
            "not a url",
            "proxy.example.test:3128",
            "socks5://alice:s3cret@proxy.example.test:1080",
            "ftp://alice:s3cret@proxy.example.test",
            "http://alice:s3cret@proxy.example.test:3128/path",
            "http://alice:s3cret@proxy.example.test:3128/?key=t0ken",
            "http://alice:s3cret@proxy.example.test:3128/#t0ken",
            "http://alice:s3cret@proxy example.test:3128",
            " http://alice:s3cret@proxy.example.test:3128",
            "http://alice:s3cret@proxy.éxample.test:3128",
            // Parses as host `alice`, port `1234`, path `/s3cret@proxy…`.
            "http://alice:1234/s3cret@proxy.example.test:3128",
            "http://proxy.example.test:3128/alice:s3cret@x",
            "http://proxy.example.test:3128/?u=alice:s3cret@x",
            // A credential over plain http to a non-loopback proxy, in every
            // spelling the URL parser normalizes to `http://`.
            "http://alice:s3cret@proxy.example.test:3128",
            "http:/alice:s3cret@proxy.example.test:3128",
            "http:alice:s3cret@proxy.example.test:3128",
            "HTTP:\\\\alice:s3cret@proxy.example.test:3128",
            "HtTp://alice:s3cret@proxy.example.test:3128",
        ] {
            let err = OAuthValidator::builder(&cfg)
                .proxy(proxy)
                .build()
                .unwrap_err();
            assert!(
                matches!(err, ValidatorError::InvalidProxy { .. }),
                "{proxy:?}: {err:?}"
            );
            assert_no_secret(&format!("{err} {err:?}"));
            let ValidatorError::InvalidProxy { proxy: shown, .. } = &err else {
                unreachable!()
            };
            assert!(
                shown == "<redacted>" || shown.ends_with("://<redacted>"),
                "{proxy:?} shown as {shown:?}"
            );
            assert!(
                !shown.contains("1234") && !shown.contains("example"),
                "{shown}"
            );
        }
        let err = OAuthValidator::builder(&cfg)
            .proxy("http://alice:s3cret@proxy.example.test:3128")
            .build()
            .unwrap_err();
        assert!(
            err.to_string().contains("mcp.oauth.allow_insecure_http"),
            "{err}"
        );
        // With the opt-in, a credentialed plain-http proxy is accepted (and
        // warned about).
        let mut insecure = cfg.clone();
        insecure.allow_insecure_http = true;
        assert!(
            OAuthValidator::builder(&insecure)
                .proxy("http://alice:s3cret@proxy.example.test:3128")
                .build()
                .is_ok()
        );
        for proxy in [
            "http://proxy.example.test:3128",
            "http://proxy.example.test:3128/",
            "https://alice:s3cret@proxy.example.test:8443",
            "http://alice:s3cret@127.0.0.1:3128",
            "http://[::1]:3128",
        ] {
            assert!(
                OAuthValidator::builder(&cfg).proxy(proxy).build().is_ok(),
                "{proxy:?}"
            );
        }
    }

    #[test]
    fn loopback_urls_get_the_proxy_free_client_and_others_the_normal_one() {
        for proxy in [None, Some("http://proxy.example.test:3128")] {
            let mut builder = OAuthValidator::builder(&testing::resolved_config(""));
            if let Some(proxy) = proxy {
                builder = builder.proxy(proxy);
            }
            let clients =
                crate::jwks::http_clients(false, "opt-in", &builder.fetch_settings().unwrap())
                    .unwrap();
            for url in [
                "http://localhost/jwks",
                "http://LOCALHOST:9000/jwks",
                "https://idp.localhost/.well-known/openid-configuration",
                "http://127.0.0.1:9000/jwks",
                "http://127.10.20.30/jwks",
                "http://[::1]:9000/jwks",
                // Non-canonical spellings are judged as parsed, as `resolve` judges them.
                "http:/localhost:9000/jwks",
                "HTTP:\\\\127.0.0.1\\jwks",
                " http://[::1]/jwks",
            ] {
                assert!(
                    std::ptr::eq(clients.for_url(url), &clients.loopback),
                    "{url} with proxy {proxy:?}"
                );
            }
            for url in [
                "https://idp.example.test/jwks",
                "http://203.0.113.1/jwks",
                "http://localhost.example.test/jwks",
                "http://[::2]/jwks",
                "http://198.51.100.1/jwks",
                "not a url",
                "http:/idp.example.test/jwks",
                "http:localhost.example.test/jwks",
                "HTTP:\\\\idp.example.test\\jwks",
            ] {
                assert!(
                    std::ptr::eq(clients.for_url(url), &clients.normal),
                    "{url} with proxy {proxy:?}"
                );
            }
            // Client choice and `resolve`'s plain-http judgment agree for
            // every http spelling: loopback client exactly when no opt-in is
            // needed.
            for url in [
                "http:/localhost/jwks",
                "http:127.0.0.1/jwks",
                "http:/idp.example.test/jwks",
                " http://idp.example.test/jwks",
                "HTTP:\\\\[::1]\\jwks",
            ] {
                assert_eq!(
                    std::ptr::eq(clients.for_url(url), &clients.loopback),
                    !crate::validator::plain_http_non_loopback(url),
                    "{url}"
                );
            }
        }
    }

    #[test]
    fn the_fetch_timeout_is_bounded() {
        let cfg = testing::resolved_config("https://idp.example.test/jwks");
        for timeout in [
            Duration::ZERO,
            Duration::from_millis(999),
            Duration::from_secs(61),
            Duration::MAX,
        ] {
            let err = OAuthValidator::builder(&cfg)
                .fetch_timeout(timeout)
                .build()
                .unwrap_err();
            assert!(
                matches!(err, ValidatorError::FetchTimeoutOutOfRange { .. }),
                "{timeout:?}: {err:?}"
            );
        }
        for timeout in [MIN_FETCH_TIMEOUT, MAX_FETCH_TIMEOUT, Duration::from_secs(5)] {
            let settings = OAuthValidator::builder(&cfg)
                .fetch_timeout(timeout)
                .fetch_settings()
                .unwrap();
            assert_eq!(settings.timeout, timeout);
        }
    }

    #[tokio::test]
    async fn the_fetch_timeout_is_honored() {
        let server = testing::spawn_jwks_server("200 OK", testing::jwks_body()).await;
        server.hold.store(true, Ordering::SeqCst);
        let v = OAuthValidator::builder(&testing::resolved_config(&server.url))
            .fetch_timeout(MIN_FETCH_TIMEOUT)
            .build()
            .unwrap();
        let started = std::time::Instant::now();
        let err = v.refresh_now().await.unwrap_err();
        let elapsed = started.elapsed();
        assert_eq!(err.kind(), RefreshErrorKind::Fetch, "{err}");
        assert!(elapsed >= MIN_FETCH_TIMEOUT, "{elapsed:?}");
        assert!(elapsed < DEFAULT_FETCH_TIMEOUT / 2, "{elapsed:?}");
        assert_eq!(server.hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn seeded_keys_validate_without_a_fetch() {
        let server = testing::spawn_jwks_server("200 OK", testing::jwks_body()).await;
        let v = OAuthValidator::builder(&testing::resolved_config(&server.url))
            .initial_jwks(&testing::jwks_body())
            .build()
            .unwrap();
        let status = v.key_set_status();
        assert_eq!(status.keys, 1);
        assert!(v.is_ready() && status.is_ready());
        assert_eq!(status.last_attempt, None);
        assert_eq!(status.last_success, None);
        assert_eq!(status.last_error, None);
        assert_eq!(status.jwks_uri.as_deref(), Some(server.url.as_str()));
        v.validate(&testing::valid_token()).await.unwrap();
        assert_eq!(server.hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_refresh_replaces_seeded_keys_and_a_failed_one_keeps_them() {
        // The authorization server now publishes only the EC key.
        let server =
            testing::spawn_jwks_server("200 OK", testing::jwks_of(&[testing::jwk_ec()])).await;
        let v = OAuthValidator::builder(&testing::resolved_config(&server.url))
            .initial_jwks(&testing::jwks_body())
            .build()
            .unwrap();

        // A failed refresh keeps the seed.
        server
            .routes
            .lock()
            .unwrap()
            .insert("/jwks".into(), ("503 Service Unavailable", "{}".into()));
        assert!(v.refresh_now().await.is_err());
        let status = v.key_set_status();
        assert_eq!(status.keys, 1);
        assert!(status.last_attempt.is_some());
        assert_eq!(status.last_success, None);
        v.validate(&testing::valid_token()).await.unwrap();

        // A successful one replaces it: the seeded RSA key is gone.
        server.routes.lock().unwrap().clear();
        assert_eq!(v.refresh_now().await.unwrap(), 1);
        let status = v.key_set_status();
        assert!(status.last_success.is_some());
        assert_eq!(status.last_error, None);
        assert!(v.validate(&testing::valid_token()).await.is_err());
    }

    #[test]
    fn seeded_keys_are_narrowed_exactly_like_fetched_ones() {
        let cfg = testing::resolved_config("https://idp.example.test/jwks");
        let oct = json!({"kty": "oct", "kid": "hmac", "k": "c2VjcmV0"});
        let mut enc = testing::jwk_rsa_a();
        enc["use"] = json!("enc");
        let mut encrypt_only = testing::jwk_rsa_a();
        encrypt_only["key_ops"] = json!(["encrypt"]);

        let refused = |json: &str| {
            let err = OAuthValidator::builder(&cfg)
                .initial_jwks(json)
                .build()
                .unwrap_err();
            assert!(
                matches!(err, ValidatorError::InvalidInitialJwks { .. }),
                "{err:?}"
            );
            err.to_string()
        };
        // No usable key at all.
        for keys in [
            vec![oct.clone()],
            vec![enc.clone()],
            vec![encrypt_only.clone()],
            vec![oct.clone(), enc.clone(), encrypt_only.clone()],
        ] {
            let err = refused(&testing::jwks_of(&keys));
            assert!(err.contains("no usable signature keys"), "{err}");
        }
        // Past the key cap: a usable key at position 65 is never considered.
        let mut over_cap = vec![oct.clone(); crate::jwks::MAX_JWKS_KEYS];
        over_cap.push(testing::jwk_rsa_a());
        refused(&testing::jwks_of(&over_cap));
        // Over the size cap, not JSON, not a JWK Set.
        let padded = format!(
            "{{\"pad\":\"{}\",\"keys\":[{}]}}",
            "x".repeat(crate::jwks::MAX_FETCH_BYTES),
            testing::jwk_rsa_a()
        );
        assert!(refused(&padded).contains("byte cap"));
        assert!(refused("{not json").contains("not JSON"));
        assert!(refused(r#"{"keys": {}}"#).contains("not a JWK Set"));
        // A key outside the configured algorithms.
        let mut es_only = cfg.clone();
        es_only.algorithms = vec![crate::Algorithm::ES256];
        assert!(
            OAuthValidator::builder(&es_only)
                .initial_jwks(&testing::jwks_body())
                .build()
                .is_err()
        );

        // Unusable entries are skipped one at a time, the usable one kept —
        // including at the last position under the cap.
        let mut mixed = vec![oct.clone(); crate::jwks::MAX_JWKS_KEYS - 3];
        mixed.extend([enc, encrypt_only, testing::jwk_rsa_a()]);
        let v = OAuthValidator::builder(&cfg)
            .initial_jwks(&testing::jwks_of(&mixed))
            .build()
            .unwrap();
        assert_eq!(v.key_set_status().keys, 1);
    }

    #[test]
    fn debug_never_shows_the_proxy_or_the_seed() {
        let cfg = testing::resolved_config("https://idp.example.test/jwks");
        let builder = OAuthValidator::builder(&cfg)
            .proxy("https://alice:s3cret@proxy.example.test:8443")
            .initial_jwks(&testing::jwks_body())
            .add_root_certificate_pem(TEST_CA_PEM.as_bytes());
        let shown = format!("{builder:?}");
        assert_no_secret(&shown);
        assert!(!shown.contains(testing::N_A), "{shown}");
        assert!(shown.contains("root_certificate_pems: 1"), "{shown}");
    }
}
