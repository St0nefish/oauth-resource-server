//! **Test-only** JWT/JWKS fixtures: throwaway keypairs, JWK builders, token
//! minting and a fake HTTP server to stand in for the authorization server.
//!
//! Compiled for this crate's own tests and, for consumers' tests, behind the
//! `testing` feature. **Never enable `testing` in a production build**: the
//! private keys below are public knowledge, and anything that trusts them trusts
//! everyone. Enable it from `[dev-dependencies]` only.
//!
//! The fixtures model a plausible Authentik deployment (per-application issuer
//! with a trailing slash, client-id audience, `mcp:read`/`mcp:write` scopes)
//! because that is the production shape the validator's regression tests were
//! written against; nothing about them is required by the crate. [`mint`] and
//! [`mint_with`] take arbitrary claims, so a test can use its own issuer,
//! audience and scopes.
//!
//! # Examples
//!
//! A consumer's test: point a validator at the fake server and check that a
//! token it minted passes.
//!
//! ```
//! use oauth_resource_server::OAuthValidator;
//! use oauth_resource_server::testing;
//!
//! # #[tokio::main(flavor = "current_thread")]
//! # async fn main() {
//! let jwks = testing::spawn_jwks_server("200 OK", testing::jwks_body()).await;
//! let validator = OAuthValidator::new(&testing::resolved_config(&jwks.url)).unwrap();
//!
//! let token = validator.validate(&testing::valid_token()).await.unwrap();
//! assert!(token.has_scope("mcp:read"));
//!
//! // A token for this test's own claims, signed with the published test key.
//! // Any `Serialize` value works as claims: a `json!` literal, or a struct.
//! let unscoped = testing::mint(
//!     testing::KEY_A_PEM,
//!     testing::KID_A,
//!     &serde_json::json!({
//!         "iss": testing::ISSUER,
//!         "aud": testing::AUDIENCE,
//!         "exp": testing::now() + 60,
//!     }),
//! );
//! assert!(validator.validate(&unscoped).await.is_err()); // lacks the required scope
//! # }
//! ```

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use jsonwebtoken::{EncodingKey, Header, encode};
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::algorithms::{Algorithm, DEFAULT_ALGORITHMS, parse_algorithm};
use crate::config::{
    DEFAULT_LEEWAY_SECS, DEFAULT_PRINCIPAL_CLAIMS, DEFAULT_SCOPE_CLAIMS, KeyNamingBuf,
    ResolvedOAuthConfig,
};

/// `kid` of the throwaway 2048-bit RSA keypair [`KEY_A_PEM`], generated for this
/// test suite and used nowhere else.
pub const KID_A: &str = "test-key-a";
/// Modulus of [`KEY_A_PEM`]'s public half, base64url, as a JWK `n`.
pub const N_A: &str = "zXtrd9E8iuVecx_7KN0nxRV0m0DgZayGgW5D4bPJMwUcFX6SIsyYpSCAGjT1Fia85xH-YrMxk9XSjuMpYB8GphQ5NitAaVx8CQeoVQw8WEi1YSG53OfuSftmkX79D48nVP6VxKq3JW_RIaTM8xsisVV2zzFeQVN_NsFNCAsClYoXLUj8Wfc9WsFz8DszbQep6I4gceD6WNCs72AQMXR5vIOfGxK5eP5JWOjK7FN95njVNbXY6p5QUQii_3HkFSDQv9drzpzeKXdDziFdSG5qZfMwGuqjfCMDNfwYKxC4AbAGbtSTCHFEWe0CuWX95xgqvyJCsVjkh8xMz-WpPoWLSQ";

/// Throwaway RSA private key A (PKCS#8 PEM). Its public half is [`jwk_rsa_a`].
pub const KEY_A_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDNe2t30TyK5V5z
H/so3SfFFXSbQOBlrIaBbkPhs8kzBRwVfpIizJilIIAaNPUWJrznEf5iszGT1dKO
4ylgHwamFDk2K0BpXHwJB6hVDDxYSLVhIbnc5+5J+2aRfv0PjydU/pXEqrclb9Eh
pMzzGyKxVXbPMV5BU382wU0ICwKVihctSPxZ9z1awXPwOzNtB6nojiBx4PpY0Kzv
YBAxdHm8g58bErl4/klY6MrsU33meNU1tdjqnlBRCKL/ceQVINC/12vOnN4pd0PO
IV1Ibmpl8zAa6qN8IwM1/BgrELgBsAZu1JMIcURZ7QK5Zf3nGCq/IkKxWOSHzEzP
5ak+hYtJAgMBAAECggEAPpyQWxKZGZOZi4ffroxw3VdT0CjdF24SECdKrN/s+0xf
ydbm7Y6dJpe4IQQo+AZ2wgwUEPwcK7lYLuzeAymBC6MW6cAVIOWq789zBfM0Agyp
o/60VTEgxU9C6iuhLZgHupjWhvYj11byiQdf4eXPVOy/RpP67fnkxgjxkXVVZL4C
zJ5KQZRLi+DH9l5Vd5nKqyRVVFVaaD0ws5Lw7n2HBrraq/omV6FlcIkePB4Tx2gD
WudBhUPnrhukXaoEWEvBNXnVSExU+bZMeWvQdcGVL6OE1LG9IqsjYiumF2kb0n0L
ZTalPbtAHoNDEKIG2+rwCqsLBZQvFnLcFTlc1WAExwKBgQDr8IjWaZ8I0mQHbRhM
BsrLDjf2qBVclBMchYafmh6NoI5E2+928NTo/uxssGTEX4ce0v6CW6dHo8vNVfN/
cUxjQW479qvugi8EBp6rQ9ZOjSra078L145jTCaJLfxMuYDgjycvcv8wOqxJL/80
F1Qjkn+pGsQFvjCAEikjwcG0cwKBgQDe8/J8W2tPpnRiv40T2Hgu4Th8gRfm/79k
RBZqeiO/EiI9zwHmOj9s02fK3tBPyQgZMyQyQNMJjFuWzCjHE8gaBdLAqGrpILL2
jR7EvXBPrGRpWcbnRCyODURcaIY1dTVImT1g9rhwzDJNQFd7XPGR60LCMUxL8b2p
hlgFlw9OUwKBgFAqvpP792mL8ykCzIqolCdCgYlxuzBlr8i1JfT87Py6XRzQjiEf
23f/hl234cVHoCW9E3U/pysUYJ84YTAgUxA2nzoIqoqz+T2o8ijHN/4gwTrxT6y6
ZUsgCMf7tAptzXh/q5TXwhWlGf0ULeaJNrGPiYjv60L4SIp7oTbhEuw5AoGAdJg8
yn4Am7HgEbg87hD5oQKVSL82Ic7DZ4sX8e0X/pdcIti8FIuHmcDg+b4WUHNAcfVF
y6YM92RYjX8NIDcfIUTEV458ApjgHoHkglzTfEcaZ+HUXCNR7aPQiUb8UL6P8/x3
ldrQz+Rpte6dEV2k03ul+OpRDTJJznr8U0gRcBMCgYB/aUF16/RJvW5nLGWTbAS8
D4d9SgETq0P0zbuDUk60Fk6kQbQ+bwX+ffgsEP/P/CFTNJ+opoCo0/6uK8WlKs15
uVx1QLn2oATcEUusHESeflBUSSaYlhHXFL7ahvAgBs3vzgWZnUVnz2A3QDCiLu6H
EmjUKNFGC0zInLUM1Cbu9w==
-----END PRIVATE KEY-----
";

/// A second throwaway RSA private key (public knowledge, like every key in this
/// module) whose public half is in no fixture JWKS: it exists only to produce a
/// signature that [`KEY_A_PEM`]'s public half must reject.
pub const KEY_B_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQClweugXTF1SY0q
ar8Z68ong9eCzOI3kCSipuiCDhVPad8Gn4be0RM4B7t342iuG4UjyXnCQpCoWGiN
L4KN52hFBE7M8c/7JutAtmpJFm33cFKZ+yWfAcX5FFtC/BdOPfaPtije98QJRmlv
lJ6n7c8uMpXhtV1ZIqwm9g7chVWlUHKAgMFGaUeKWdksQ9tTZgDKeHO1vfRZZlYT
XdvDpNe7Dxz1o3eefTsrKsE1DDTXrDfJPUDPPpBTMmT+xrPRehuNqrNQRUJWEIAR
bJpV5ltnhNX4zs3YQ39/XTCcQjnbu4wRpDUgTIhPuomg18t8vqi1CbhaN8+Ww3oU
FRdXKE59AgMBAAECggEAMeZ2umDD3mTFmCLpo/KNeabhrrFiWsrMlKC9t0VpGe6r
4xEMZ7C2YfRF9hoibePACZ2CR76FUQDIfNR0L6ceB0T8OguECr5VLTadOaKEeWy5
mTx3v24nvMvpi3lbxMS3oNz8Yd9iB07It/wcZT6c0/ILmBbi4s4i2FnT8IQ9W9Ym
iuMwqujeyrEUG/O3HrUJLHNe6PwJj6s8mbAKxfmCqnDLCyWlQejR2FL24mriCSQD
G03gZ6VazAnDt19SjToPKH1e6XjB6FySUX3gDhA9yXSPphCdaa9Ov9w/4UktlEtz
RRobV9e+e5e2qUrv77CZu3PMlH/gZARM/ncSCKlYGwKBgQDqVHUYvBArQWLO2po6
9SvjcvB631+cUO94k+nV4vlbXbzjMznXPPShijf5cirzRhazSRqxp5Yt6959vVDI
Pe/vjP0lM0dLZwiOnsEaq+ArEoAnidD09bUn81qMnsH3eUpXtIthB5ltkNX3tXb2
Xs04OxDm4IrSoMg7/w2HXb4YbwKBgQC1FhMz8PvXDAb7uJ5ydjd4Gw1CEqw93YSf
S1koX2x86qhELfUglAHb+h5RHxE7zqi5fqzrsHl3Ow3392O3clcqrbME4u//fvmV
XCr7eHraeIByX/ZpnBiiuYjrvN6MKDUy00yBDdGMGGA0JT2+aH/06qg/G5xG8SiV
0ajx8wAF0wKBgQDnbTQckpfRcIk6TBFoSvzmbHzujS9rPU/UoRifAcRNpP1I0i28
0lm0NMLlXAjpLH584KU5cY7TmZCqVE+1A960kmTs2YD/CiocWNPUGI2TXHkvE2BI
nWYlp6T1HlHorGRszEWfNZck65c2RoTP+37omwUtT/Qq41n+Tv44g6+bhwKBgGyQ
EW8gWDsycLVUl1lT2ildPnOQMkbcmPfO+mKj4qx5GevWCZFAamTw7GAB2hka6jha
41xhblC2zMcOP2/pUqy5egvB6dQo0YRjvzkHn89+UrM/KMFj3bkgth9uGZW5PTt9
Re5Q1IHC01ovwXZ3u86fJ8K90NEPHx/ClCCJaEgVAoGAHlopDQ/w7JN5sCBYDZeE
eAfND1Q/hnbfjdUgg13/Qmhqwm86RYJ3E9mxjcCNKZ3hNX3Xcs5NW5oC9tj9Nb9G
B5bK2earcA3sKw66Uvzd5AtypET7/RPOSgpXOD34f1RN38fWqc+L0pdHZ41D5eif
13kE7LEf//HMi5ix93dRdZw=
-----END PRIVATE KEY-----
";

/// `kid` of the throwaway P-256 keypair [`EC_PEM`] (generated with
/// `openssl genpkey`, used nowhere else) — so ES256, Kanidm's default, is
/// exercised end to end, not just RS256.
pub const KID_EC: &str = "test-key-ec";
/// Throwaway P-256 private key (PKCS#8 PEM). Its public half is [`jwk_ec`].
pub const EC_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgt+Eh+ZhHxw1rLcOh
VFTMghCKj2Vjq7F3zWwemIamL62hRANCAATCkjHQ5M6RrM1TPQ6wuvqltcwRa4AL
s/Jd92N5PXaKwn94PezTTY6vFt/ivjcfSSG5wWncUlc92lsipOXRqgLZ
-----END PRIVATE KEY-----
";
/// [`EC_PEM`]'s public `x` coordinate, base64url.
pub const EC_X: &str = "wpIx0OTOkazNUz0OsLr6pbXMEWuAC7PyXfdjeT12isI";
/// [`EC_PEM`]'s public `y` coordinate, base64url.
pub const EC_Y: &str = "f3g97NNNjq8W3-K-Nx9JIbnBadxSVz3aWyKk5dGqAtk";

/// `kid` of the throwaway Ed25519 keypair [`ED_PEM`] (generated with
/// `openssl genpkey`, used nowhere else) — so EdDSA is exercised end to end.
pub const KID_ED: &str = "test-key-ed";
/// Throwaway Ed25519 private key (PKCS#8 PEM). Its public half is [`jwk_ed`].
pub const ED_PEM: &str = "-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEICpZSYX0J1AafpNnoaSXF7Lm/Nmt73HqecXyoFLjchf8
-----END PRIVATE KEY-----
";
/// [`ED_PEM`]'s public key, base64url, as a JWK `x`.
pub const ED_X: &str = "C4HUUU7zy0ZEyY__PV16YbPgh4b4clhBg0oVMg0_EaQ";

/// The fixture issuer: an Authentik-style per-application issuer
/// (`<host>/application/o/<slug>/`), trailing slash included. The host and the
/// application slug are placeholders.
pub const ISSUER: &str = "https://authentik.example.test/application/o/example-app/";
/// The fixture audience: an OAuth client_id, the way Authentik stamps `aud`.
pub const AUDIENCE: &str = "test-client-id";
/// The fixture protected resource.
pub const RESOURCE: &str = "https://kb.example.test/mcp";

/// The JWK for [`KEY_A_PEM`]'s public half, as an AS would serve it (`alg`
/// RS256, `use` sig).
pub fn jwk_rsa_a() -> serde_json::Value {
    serde_json::json!({
        "kty": "RSA", "use": "sig", "alg": "RS256", "kid": KID_A, "n": N_A, "e": "AQAB",
    })
}

/// The same RSA key with no `alg`, so it may verify any RS*/PS* algorithm.
pub fn jwk_rsa_a_any_alg(kid: &str) -> serde_json::Value {
    serde_json::json!({"kty": "RSA", "use": "sig", "kid": kid, "n": N_A, "e": "AQAB"})
}

/// The JWK for [`EC_PEM`]'s public half (`alg` ES256).
pub fn jwk_ec() -> serde_json::Value {
    serde_json::json!({
        "kty": "EC", "crv": "P-256", "use": "sig", "alg": "ES256", "kid": KID_EC,
        "x": EC_X, "y": EC_Y,
    })
}

/// The JWK for [`ED_PEM`]'s public half (`alg` EdDSA).
pub fn jwk_ed() -> serde_json::Value {
    serde_json::json!({
        "kty": "OKP", "crv": "Ed25519", "use": "sig", "alg": "EdDSA", "kid": KID_ED,
        "x": ED_X,
    })
}

/// A JWK Set document holding `keys`.
pub fn jwks_of(keys: &[serde_json::Value]) -> String {
    serde_json::json!({ "keys": keys }).to_string()
}

/// A JWK Set carrying only [`KEY_A_PEM`]'s public half — the shape Authentik
/// serves.
pub fn jwks_body() -> String {
    jwks_of(&[jwk_rsa_a()])
}

/// Every test key: RSA A (RS256-labelled), a PS256-capable copy of it (`kid`
/// `test-key-a-pss`), the P-256 key and the Ed25519 key.
pub fn jwks_body_all() -> String {
    jwks_of(&[
        jwk_rsa_a(),
        jwk_rsa_a_any_alg("test-key-a-pss"),
        jwk_ec(),
        jwk_ed(),
    ])
}

/// A resolved config matching the fixtures: [`ISSUER`], [`AUDIENCE`],
/// [`RESOURCE`], `mcp:read` required, `mcp:read mcp:write` advertised, keys at
/// `jwks_uri` (empty means "discover from the issuer"), and every other setting
/// at its default. Settings are named `mcp.oauth.*` in errors and logs.
///
/// # Panics
///
/// Never in practice: it would panic only if one of the crate's own default
/// algorithm names failed to parse, which the crate's tests rule out.
pub fn resolved_config(jwks_uri: &str) -> ResolvedOAuthConfig {
    ResolvedOAuthConfig {
        issuer: ISSUER.to_string(),
        jwks_uri: (!jwks_uri.is_empty()).then(|| jwks_uri.to_string()),
        audience: AUDIENCE.to_string(),
        audiences: Vec::new(),
        resource: RESOURCE.to_string(),
        required_scopes: vec!["mcp:read".to_string()],
        scopes_supported: vec!["mcp:read".to_string(), "mcp:write".to_string()],
        scope_claims: DEFAULT_SCOPE_CLAIMS.iter().map(|s| s.to_string()).collect(),
        principal_claims: DEFAULT_PRINCIPAL_CLAIMS
            .iter()
            .map(|s| s.to_string())
            .collect(),
        algorithms: DEFAULT_ALGORITHMS
            .iter()
            .map(|s| parse_algorithm(s).expect("every default algorithm parses"))
            .collect(),
        leeway_secs: DEFAULT_LEEWAY_SECS,
        require_at_jwt: false,
        allow_unscoped_tokens: false,
        allow_insecure_http: false,
        accept_static_bearer: true,
        resource_name: None,
        key_naming: KeyNamingBuf::Dotted("mcp.oauth".to_string()),
    }
}

/// Seconds since the epoch, for `exp`/`nbf`/`iat`.
///
/// # Panics
///
/// If the system clock reads earlier than the Unix epoch.
pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("the clock is after 1970")
        .as_secs()
}

/// Mint an RS256 token with full control over every field a test might want
/// wrong. `pem` is which key signs it; `kid` is what the header *claims* signed
/// it — letting a test say "signed by B, labelled A" for the bad-signature case.
/// `claims` is anything that serializes to a JSON object: a
/// `serde_json::json!` literal, or the test's own claims struct.
///
/// # Panics
///
/// If `pem` is not a valid RSA private key in PEM form, or if the claims fail
/// to serialize.
pub fn mint(pem: &str, kid: &str, claims: &impl Serialize) -> String {
    let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some(kid.to_string());
    encode(
        &header,
        claims,
        &EncodingKey::from_rsa_pem(pem.as_bytes()).expect("a valid RSA PEM"),
    )
    .expect("the token encodes")
}

/// Mint with an explicit algorithm, `kid` and `typ`. RS*/PS* sign with
/// [`KEY_A_PEM`], ES256 with [`EC_PEM`], EdDSA with [`ED_PEM`]. `claims` as
/// for [`mint`].
///
/// # Panics
///
/// If `alg` is any other algorithm (there is no test key for it), or if the
/// claims fail to serialize.
pub fn mint_with(
    alg: Algorithm,
    kid: Option<&str>,
    typ: Option<&str>,
    claims: &impl Serialize,
) -> String {
    let mut header = Header::new(alg.to_jwt());
    header.kid = kid.map(str::to_string);
    header.typ = typ.map(str::to_string);
    let key = match alg {
        Algorithm::RS256
        | Algorithm::RS384
        | Algorithm::RS512
        | Algorithm::PS256
        | Algorithm::PS384
        | Algorithm::PS512 => EncodingKey::from_rsa_pem(KEY_A_PEM.as_bytes()),
        Algorithm::ES256 => EncodingKey::from_ec_pem(EC_PEM.as_bytes()),
        Algorithm::EdDSA => EncodingKey::from_ed_pem(ED_PEM.as_bytes()),
        other => panic!("no test key for {other:?}"),
    }
    .expect("a valid test key");
    encode(&header, claims, &key).expect("the token encodes")
}

/// The happy-path token for [`resolved_config`]: right key, right issuer, right
/// audience, valid for an hour, carrying `mcp:read mcp:write`.
pub fn valid_token() -> String {
    mint(
        KEY_A_PEM,
        KID_A,
        &serde_json::json!({
            "iss": ISSUER,
            "aud": AUDIENCE,
            "azp": AUDIENCE,
            "sub": "user-1",
            "exp": now() + 3600,
            "scope": "mcp:read mcp:write",
        }),
    )
}

/// A throwaway loopback HTTP server standing in for the authorization server,
/// counting hits. Hand-rolled so the crate needs no HTTP-mock dependency.
///
/// `routes` maps a request path to `(status line, body)` and can be changed while
/// the server runs (key rotation tests); a path with no route gets the fallback,
/// or a 404 when there is none. Every response is `application/json`.
///
/// `#[non_exhaustive]`: get one from [`spawn_jwks_server`] or
/// [`spawn_http_server`]; a field may be added without a breaking change.
#[derive(Debug)]
#[non_exhaustive]
pub struct FakeJwksServer {
    /// `http://127.0.0.1:<port>/jwks`.
    pub url: String,
    /// `http://127.0.0.1:<port>`, for building issuer and discovery URLs.
    pub base: String,
    /// Requests answered so far.
    pub hits: Arc<AtomicUsize>,
    /// Path → `(status line, body)`, e.g. `("200 OK", jwks_body())`.
    pub routes: Arc<Mutex<HashMap<String, (&'static str, String)>>>,
    /// Milliseconds to stall before answering — a slow IdP. Read when a
    /// connection is accepted, so a change applies to the next request.
    pub delay_ms: Arc<AtomicU64>,
}

/// Answer every request, whatever its path, with one canned response.
///
/// # Panics
///
/// As [`spawn_http_server`].
pub async fn spawn_jwks_server(status_line: &'static str, body: String) -> FakeJwksServer {
    spawn_http_server(HashMap::new(), Some((status_line, body))).await
}

/// Serve `routes`, falling back to `fallback` (or a 404) for any other path.
///
/// # Panics
///
/// If no loopback port can be bound. Must be called inside a tokio runtime
/// (it spawns the accept loop).
pub async fn spawn_http_server(
    routes: HashMap<String, (&'static str, String)>,
    fallback: Option<(&'static str, String)>,
) -> FakeJwksServer {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a loopback port");
    let addr = listener.local_addr().expect("a bound address");
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&hits);
    let routes = Arc::new(Mutex::new(routes));
    let shared_routes = Arc::clone(&routes);
    let fallback = Arc::new(fallback);
    let delay_ms = Arc::new(AtomicU64::new(0));
    let shared_delay = Arc::clone(&delay_ms);

    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let counter = Arc::clone(&counter);
            let routes = Arc::clone(&shared_routes);
            let fallback = Arc::clone(&fallback);
            let delay = shared_delay.load(Ordering::SeqCst);
            tokio::spawn(async move {
                if delay > 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                }
                // A GET has no body, so end-of-headers is end-of-request.
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                loop {
                    match sock.read(&mut tmp).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&tmp[..n]),
                    }
                    if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                counter.fetch_add(1, Ordering::SeqCst);
                let request = String::from_utf8_lossy(&buf);
                let path = request
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .unwrap_or("/")
                    .to_string();
                let (status_line, body) = routes
                    .lock()
                    .expect("routes lock")
                    .get(&path)
                    .cloned()
                    .or_else(|| (*fallback).clone())
                    .unwrap_or(("404 Not Found", "{}".to_string()));
                let resp = format!(
                    "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.flush().await;
            });
        }
    });

    FakeJwksServer {
        url: format!("http://{addr}/jwks"),
        base: format!("http://{addr}"),
        hits,
        routes,
        delay_ms,
    }
}
