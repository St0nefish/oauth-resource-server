//! **Test-only** fixtures for testing code that sits behind this crate: a fake
//! authorization server ([`TestAuthority`]), a fluent token builder
//! ([`TokenBuilder`]), and the lower-level throwaway keys, JWK builders, minting
//! functions and fake HTTP server they are built from.
//!
//! Compiled for this crate's own tests and, for consumers' tests, behind the
//! `testing` feature. **Never enable `testing` in a production build**: the
//! private keys here are public knowledge, and anything that trusts them trusts
//! everyone. Enable it from `[dev-dependencies]` only.
//!
//! # Semver
//!
//! This module follows semver like the rest of the crate: removing or renaming
//! an item, or changing what an existing one does, is a breaking change and
//! ships in a new `0.x` minor. Test suites are consumers too, and an exemption
//! would make every upgrade a coin toss for them. The throwaway keys, their
//! `kid`s and the keys [`TestAuthority`] serves are stable in the same sense.
//! What is *not* promised is the wording of a panic message. Adding an item, or
//! a key to the served JWK Set, is additive.
//!
//! # Start with [`TestAuthority`]
//!
//! [`TestAuthority::start`] runs a loopback fake authorization server that
//! serves discovery (both OpenID Connect and RFC 8414) and a JWKS, with its
//! own issuer and `jwks_uri`. [`TestAuthority::config`] resolves a
//! [`ResolvedOAuthConfig`] consistent with it, and [`TestAuthority::token`]
//! builds tokens that config accepts, so the common test is three lines and each
//! thing a test wants *wrong* is one builder call. Nothing in it is specific to
//! a provider or an application: the defaults are neutral
//! (`https://api.example.test/`, scope `api:read`).
//!
//! ```
//! use oauth_resource_server::testing::TestAuthority;
//! use oauth_resource_server::{Algorithm, OAuthValidator, TokenRejection};
//!
//! # #[tokio::main(flavor = "current_thread")]
//! # async fn main() {
//! let authority = TestAuthority::start().await;
//! let validator = OAuthValidator::new(&authority.config(|_| {})).unwrap();
//!
//! // The defaults are a token that config accepts.
//! let token = validator.validate(&authority.token().sign()).await.unwrap();
//! assert!(token.has_scope("api:read"));
//!
//! // Each knob makes exactly one thing wrong (or different).
//! let expired = authority.token().expired().sign();
//! assert!(matches!(
//!     validator.validate(&expired).await,
//!     Err(TokenRejection::Invalid(_))
//! ));
//! let no_scope = authority.token().scopes(["other:scope"]).sign();
//! assert!(matches!(
//!     validator.validate(&no_scope).await,
//!     Err(TokenRejection::InsufficientScope)
//! ));
//! let es256 = authority.token().alg(Algorithm::ES256).sign();
//! assert!(validator.validate(&es256).await.is_ok());
//! # }
//! ```
//!
//! Handler tests that do not need a real token can skip validation altogether
//! and build the verified value directly with
//! [`AuthorizedToken::new`](crate::AuthorizedToken::new) and its `with_*`
//! builders, for example
//! [`with_claims`](crate::AuthorizedToken::with_claims).
//!
//! # Testing an axum handler end to end
//!
//! With the `axum` feature, run a real request through
//! [`AuthLayer`](crate::axum::AuthLayer) and the
//! [`AuthorizedToken`](crate::AuthorizedToken) extractor. This needs `tower`
//! with its `util` feature (for `ServiceExt::oneshot`) as a dev-dependency.
//! The body is the same as the README's "Testing your integration" example, so
//! that example is compiled and run here (`#` lines only gate it on the
//! `axum` feature):
//!
//! ```
//! # #[cfg(feature = "axum")]
//! use std::sync::Arc;
//!
//! # #[cfg(feature = "axum")]
//! use axum::{Router, body::Body, http::{Request, StatusCode}, routing::get};
//! # #[cfg(feature = "axum")]
//! use oauth_resource_server::axum::AuthLayer;
//! # #[cfg(feature = "axum")]
//! use oauth_resource_server::testing::TestAuthority;
//! # #[cfg(feature = "axum")]
//! use oauth_resource_server::{AuthorizedToken, OAuthValidator};
//! # #[cfg(feature = "axum")]
//! use tower::ServiceExt; // for `oneshot`
//!
//! # #[cfg(feature = "axum")]
//! #[tokio::main(flavor = "current_thread")]
//! async fn main() {
//!     let authority = TestAuthority::start().await;
//!     // Adjust anything before the config is resolved; it panics with the
//!     // `ConfigError` text if the result is invalid.
//!     let config = authority.config(|c| c.require_at_jwt = true);
//!     let validator = Arc::new(OAuthValidator::new(&config).unwrap());
//!
//!     let app = Router::new()
//!         .route(
//!             "/whoami",
//!             get(|token: AuthorizedToken| async move { token.subject.unwrap_or_default() }),
//!         )
//!         .route_layer(AuthLayer::builder().oauth(validator).build().unwrap());
//!     let request = |bearer: String| {
//!         Request::builder()
//!             .uri("/whoami")
//!             .header("authorization", format!("Bearer {bearer}"))
//!             .body(Body::empty())
//!             .unwrap()
//!     };
//!
//!     let ok = app.clone().oneshot(request(authority.token().subject("ada").sign())).await.unwrap();
//!     assert_eq!(ok.status(), StatusCode::OK);
//!
//!     let expired = app.clone().oneshot(request(authority.token().expired().sign())).await.unwrap();
//!     assert_eq!(expired.status(), StatusCode::UNAUTHORIZED);
//!
//!     let no_scope = app.oneshot(request(authority.token().scopes(["other:scope"]).sign())).await.unwrap();
//!     assert_eq!(no_scope.status(), StatusCode::FORBIDDEN);
//! }
//! # #[cfg(not(feature = "axum"))]
//! # fn main() {}
//! ```
//!
//! # The lower-level building blocks
//!
//! Everything below [`TestAuthority`] stays available: the key constants
//! ([`KEY_A_PEM`], [`KEY_B_PEM`], [`EC_PEM`], [`ED_PEM`]), the JWK builders
//! ([`jwk_rsa_a`], [`jwk_ec`], [`jwk_ed`], [`jwks_of`], [`jwks_body`],
//! [`jwks_body_all`]), [`mint`], [`mint_with`] and [`valid_token`], the fake
//! HTTP server ([`FakeJwksServer`], [`spawn_jwks_server`],
//! [`spawn_http_server`]) and [`resolved_config`].
//!
//! Those fixtures model a plausible Authentik deployment (per-application issuer
//! with a trailing slash, client-id audience, `mcp:read`/`mcp:write` scopes)
//! because that is the production shape this crate's own regression tests were
//! written against. That shape is an implementation detail, not a recommendation
//! and not something the crate requires. Reach for them when a test needs to
//! control something [`TestAuthority`] does not, such as a hand-built JWK Set
//! or a misbehaving server. [`mint`] and [`mint_with`] take arbitrary claims, so
//! a test can use its own issuer, audience and scopes.
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
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use jsonwebtoken::{EncodingKey, Header, encode};
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::algorithms::{Algorithm, DEFAULT_ALGORITHMS, parse_algorithm};
use crate::config::{
    DEFAULT_LEEWAY_SECS, DEFAULT_PRINCIPAL_CLAIMS, DEFAULT_SCOPE_CLAIMS, KeyNaming, KeyNamingBuf,
    OAuthConfig, ResolvedOAuthConfig,
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
/// `kid` of [`KEY_B_PEM`]'s public half as [`TestAuthority`] publishes it.
pub const KID_B: &str = "test-key-b";
/// Modulus of [`KEY_B_PEM`]'s public half, base64url, as a JWK `n` (the public
/// half of the existing throwaway key, not new key material).
pub const N_B: &str = "pcHroF0xdUmNKmq_GevKJ4PXgsziN5Akoqbogg4VT2nfBp-G3tETOAe7d-NorhuFI8l5wkKQqFhojS-CjedoRQROzPHP-ybrQLZqSRZt93BSmfslnwHF-RRbQvwXTj32j7Yo3vfECUZpb5Sep-3PLjKV4bVdWSKsJvYO3IVVpVBygIDBRmlHilnZLEPbU2YAynhztb30WWZWE13bw6TXuw8c9aN3nn07KyrBNQw016w3yT1Azz6QUzJk_saz0XobjaqzUEVCVhCAEWyaVeZbZ4TV-M7N2EN_f10wnEI527uMEaQ1IEyIT7qJoNfLfL6otQm4WjfPlsN6FBUXVyhOfQ";

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
    /// While set, a request is counted in `hits` and then held until
    /// `release` is notified (once per held request) — lets this crate's own
    /// tests keep a fetch in flight for exactly as long as they need. Read
    /// only by those tests, hence unused in a `testing`-feature build.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) hold: Arc<AtomicBool>,
    /// See `hold`.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) release: Arc<tokio::sync::Notify>,
    /// Requests answered per path, for [`TestAuthority`].
    pub(crate) path_hits: Arc<Mutex<HashMap<String, usize>>>,
    /// Stops the accept loop; used by [`TestAuthority`]'s `Drop`.
    pub(crate) accept_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
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
    let hold = Arc::new(AtomicBool::new(false));
    let shared_hold = Arc::clone(&hold);
    let release = Arc::new(tokio::sync::Notify::new());
    let shared_release = Arc::clone(&release);
    let path_hits = Arc::new(Mutex::new(HashMap::<String, usize>::new()));
    let shared_path_hits = Arc::clone(&path_hits);

    let accept_task = tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let counter = Arc::clone(&counter);
            let routes = Arc::clone(&shared_routes);
            let fallback = Arc::clone(&fallback);
            let delay = shared_delay.load(Ordering::SeqCst);
            let hold = shared_hold.load(Ordering::SeqCst);
            let release = Arc::clone(&shared_release);
            let path_hits = Arc::clone(&shared_path_hits);
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
                if hold {
                    release.notified().await;
                }
                let request = String::from_utf8_lossy(&buf);
                let path = request
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .unwrap_or("/")
                    .to_string();
                *path_hits
                    .lock()
                    .expect("path hits lock")
                    .entry(path.clone())
                    .or_default() += 1;
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
        hold,
        release,
        path_hits,
        accept_task: Mutex::new(Some(accept_task)),
    }
}

/// The JWK for [`KEY_B_PEM`]'s public half (`alg` RS256), under [`KID_B`].
pub fn jwk_rsa_b() -> serde_json::Value {
    serde_json::json!({
        "kty": "RSA", "use": "sig", "alg": "RS256", "kid": KID_B, "n": N_B, "e": "AQAB",
    })
}

/// Which throwaway RSA key [`TestAuthority`] currently signs RSA tokens with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RsaKey {
    A,
    B,
}

/// The RSA algorithms other than RS256. Each gets its own JWK (with its own
/// `alg`, `kid` `<key kid>-<alg lowercase>`, e.g. `test-key-a-ps256`), so no
/// key in the served set is alg-less and none trips the crate's ambiguous-key
/// warning.
const OTHER_RSA_ALGS: [Algorithm; 5] = [
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::PS256,
    Algorithm::PS384,
    Algorithm::PS512,
];

impl RsaKey {
    fn other(self) -> Self {
        match self {
            RsaKey::A => RsaKey::B,
            RsaKey::B => RsaKey::A,
        }
    }

    fn pem(self) -> &'static str {
        match self {
            RsaKey::A => KEY_A_PEM,
            RsaKey::B => KEY_B_PEM,
        }
    }

    fn n(self) -> &'static str {
        match self {
            RsaKey::A => N_A,
            RsaKey::B => N_B,
        }
    }

    fn kid(self) -> &'static str {
        match self {
            RsaKey::A => KID_A,
            RsaKey::B => KID_B,
        }
    }

    /// The `kid` this key is published under for `alg`: the bare key `kid` for
    /// RS256, `<kid>-<alg lowercase>` for the other RSA algorithms.
    fn kid_for(self, alg: Algorithm) -> String {
        match alg {
            Algorithm::RS256 => self.kid().to_string(),
            other => format!("{}-{}", self.kid(), other.as_str().to_ascii_lowercase()),
        }
    }

    /// One JWK per RSA algorithm, each with its own `alg`.
    fn jwks(self) -> Vec<serde_json::Value> {
        let mut keys = vec![match self {
            RsaKey::A => jwk_rsa_a(),
            RsaKey::B => jwk_rsa_b(),
        }];
        for alg in OTHER_RSA_ALGS {
            keys.push(serde_json::json!({
                "kty": "RSA", "use": "sig", "alg": alg.as_str(),
                "kid": self.kid_for(alg), "n": self.n(), "e": "AQAB",
            }));
        }
        keys
    }
}

/// Which RSA keys the authority signs with and publishes.
#[derive(Debug, Clone, Copy)]
struct KeyState {
    active: RsaKey,
    /// Whether the previously active RSA key is still published.
    retained: bool,
}

impl KeyState {
    /// At most 14 keys: 6 per RSA key, plus the P-256 and Ed25519 keys.
    fn jwks_body(self) -> String {
        let mut keys = self.active.jwks();
        if self.retained {
            keys.extend(self.active.other().jwks());
        }
        keys.extend([jwk_ec(), jwk_ed()]);
        jwks_of(&keys)
    }
}

const DISCOVERY_OIDC: &str = "/.well-known/openid-configuration";
const DISCOVERY_RFC8414: &str = "/.well-known/oauth-authorization-server";
const JWKS_PATH: &str = "/jwks";

/// A self-consistent fake authorization server for a consumer's tests: a
/// loopback HTTP server that serves OpenID Connect discovery, RFC 8414
/// discovery and a JWKS, with an issuer and `jwks_uri` that agree with each
/// other, plus everything needed to build a matching config and mint matching
/// tokens.
///
/// It publishes the throwaway RSA, P-256 and Ed25519 keys, so a token signed
/// with any algorithm [`TokenBuilder::alg`] accepts validates. Every published
/// key carries its own `alg` (one JWK per RSA algorithm, `kid`s such as
/// `test-key-a` for RS256 and `test-key-a-ps256`), so a validator never logs
/// the alg-less-key warning for this JWKS.
///
/// The server runs until the `TestAuthority` is dropped, which stops its accept
/// loop.
///
/// # Security
///
/// Test-only: the keys are public. See the [module docs](self).
///
/// # Examples
///
/// ```
/// use oauth_resource_server::OAuthValidator;
/// use oauth_resource_server::testing::TestAuthority;
///
/// # #[tokio::main(flavor = "current_thread")]
/// # async fn main() {
/// let authority = TestAuthority::start().await;
/// // Adjust anything before the config is resolved.
/// let config = authority.config(|c| c.required_scopes = vec!["notes:write".into()]);
/// let validator = OAuthValidator::new(&config).unwrap();
///
/// let ok = authority.token().scopes(["notes:write"]).sign();
/// assert!(validator.validate(&ok).await.is_ok());
/// assert_eq!(authority.jwks_fetches(), 1); // the JWKS was fetched once
/// # }
/// ```
#[derive(Debug)]
pub struct TestAuthority {
    server: FakeJwksServer,
    issuer: String,
    keys: Mutex<KeyState>,
}

impl Drop for TestAuthority {
    fn drop(&mut self) {
        if let Some(task) = self
            .server
            .accept_task
            .lock()
            .ok()
            .and_then(|mut t| t.take())
        {
            task.abort();
        }
    }
}

impl TestAuthority {
    /// The audience [`config`](Self::config) accepts and [`token`](Self::token)
    /// stamps by default: `https://api.example.test/audience`. Deliberately
    /// different from [`RESOURCE`](Self::RESOURCE), the way an API identifier
    /// (RFC 8707 style) differs from the resource's URL in real deployments, so
    /// a test catches code that swaps the two.
    pub const AUDIENCE: &'static str = "https://api.example.test/audience";
    /// The protected resource [`config`](Self::config) uses:
    /// `https://api.example.test/`.
    pub const RESOURCE: &'static str = "https://api.example.test/";
    /// The scope [`config`](Self::config) requires and [`token`](Self::token)
    /// carries by default: `api:read`.
    pub const SCOPE: &'static str = "api:read";

    /// Start the fake authority on a loopback port. Its issuer is its own base
    /// URL (`http://127.0.0.1:<port>`); discovery is served at both
    /// `/.well-known/openid-configuration` and
    /// `/.well-known/oauth-authorization-server`, and the JWKS at `/jwks`.
    ///
    /// # Panics
    ///
    /// If no loopback port can be bound. Must be called inside a tokio runtime.
    pub async fn start() -> Self {
        let server = spawn_http_server(HashMap::new(), None).await;
        let issuer = server.base.clone();
        let authority = Self {
            server,
            issuer,
            keys: Mutex::new(KeyState {
                active: RsaKey::A,
                retained: false,
            }),
        };
        let discovery = serde_json::json!({
            "issuer": authority.issuer,
            "jwks_uri": authority.server.url,
        })
        .to_string();
        {
            let mut routes = authority.server.routes.lock().expect("routes lock");
            routes.insert(DISCOVERY_OIDC.to_string(), ("200 OK", discovery.clone()));
            routes.insert(DISCOVERY_RFC8414.to_string(), ("200 OK", discovery));
        }
        authority.publish();
        authority
    }

    /// The issuer this authority stamps into discovery and, by default, into
    /// tokens: `http://127.0.0.1:<port>`.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// The URL of the JWKS: `http://127.0.0.1:<port>/jwks`.
    pub fn jwks_uri(&self) -> &str {
        &self.server.url
    }

    fn path_hits(&self, paths: &[&str]) -> usize {
        let hits = self.server.path_hits.lock().expect("path hits lock");
        paths
            .iter()
            .map(|p| hits.get(*p).copied().unwrap_or(0))
            .sum()
    }

    /// How many times the JWKS has been fetched.
    pub fn jwks_fetches(&self) -> usize {
        self.path_hits(&[JWKS_PATH])
    }

    /// How many times a discovery document (OpenID Connect or RFC 8414) has
    /// been fetched. Zero when the config sets `jwks_uri`.
    pub fn discovery_fetches(&self) -> usize {
        self.path_hits(&[DISCOVERY_OIDC, DISCOVERY_RFC8414])
    }

    /// Stall every response by `delay`, to test a slow authority. Applies to
    /// connections accepted after the call; [`Duration::ZERO`] turns it off.
    pub fn set_response_delay(&self, delay: Duration) {
        let millis = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX);
        self.server.delay_ms.store(millis, Ordering::SeqCst);
    }

    /// Rotate the RSA signing key: from now on [`token`](Self::token) signs RSA
    /// tokens with the other throwaway key (`KEY_B_PEM` after the first
    /// rotation, `KEY_A_PEM` again after the second), and the JWKS is
    /// republished with **both** RSA keys, as a real authority does while
    /// tokens signed with the old key are still in flight. The P-256 and
    /// Ed25519 keys are unaffected. Follow with
    /// [`withdraw_old_key`](Self::withdraw_old_key) to model an authority that
    /// retires the old key.
    ///
    /// A token built *before* the rotation keeps the old key (the builder
    /// captures the key when [`token`](Self::token) is called). A running
    /// validator learns the new key on an unknown-`kid` refetch (at most one per
    /// 60 seconds) or
    /// [`OAuthValidator::refresh_now`](crate::OAuthValidator::refresh_now).
    pub fn rotate_key(&self) {
        {
            let mut keys = self.keys.lock().expect("key state lock");
            keys.active = keys.active.other();
            keys.retained = true;
        }
        self.publish();
    }

    /// Withdraw the previous RSA key that [`rotate_key`](Self::rotate_key) left
    /// published: the JWKS then holds only the active RSA key. A validator that
    /// has the old key cached keeps trusting it until its next successful
    /// refresh ([`refresh_now`](crate::OAuthValidator::refresh_now) or the
    /// hourly background pass); after that, tokens signed with the old key
    /// fail. A no-op when nothing is retained.
    pub fn withdraw_old_key(&self) {
        self.keys.lock().expect("key state lock").retained = false;
        self.publish();
    }

    fn publish(&self) {
        let body = self.keys.lock().expect("key state lock").jwks_body();
        self.server
            .routes
            .lock()
            .expect("routes lock")
            .insert(JWKS_PATH.to_string(), ("200 OK", body));
    }

    /// A [`ResolvedOAuthConfig`] for this authority, with neutral defaults:
    ///
    /// - `issuer` and `jwks_uri` are this authority's own;
    /// - `audience` is [`AUDIENCE`](Self::AUDIENCE)
    ///   (`https://api.example.test/audience`) and `resource`
    ///   [`RESOURCE`](Self::RESOURCE) (`https://api.example.test/`);
    /// - `api:read` ([`SCOPE`](Self::SCOPE)) is the one required scope;
    /// - settings are named `oauth.*` in errors ([`KeyNaming::Dotted`]);
    /// - everything else is the crate default, so `require_at_jwt` is off.
    ///
    /// The authority is plain `http` on loopback, which
    /// [`OAuthConfig::resolve`] accepts without `allow_insecure_http`. `adjust`
    /// edits the [`OAuthConfig`] before it is resolved: set `require_at_jwt`,
    /// add `audiences`, clear `jwks_uri` to exercise discovery, and so on.
    ///
    /// # Panics
    ///
    /// If the adjusted config does not resolve (the message is the
    /// [`ConfigError`](crate::ConfigError) text, every problem at once), or
    /// `adjust` sets `enabled` to `false`. Acceptable in a test helper; use
    /// [`OAuthConfig::resolve`] directly to assert on a refusal.
    ///
    /// # Examples
    ///
    /// ```
    /// use oauth_resource_server::testing::TestAuthority;
    ///
    /// # #[tokio::main(flavor = "current_thread")]
    /// # async fn main() {
    /// let authority = TestAuthority::start().await;
    /// let config = authority.config(|c| {
    ///     c.require_at_jwt = true;
    ///     c.jwks_uri = None; // find the keys through discovery instead
    /// });
    /// assert_eq!(config.issuer, authority.issuer());
    /// assert!(config.jwks_uri.is_none());
    /// # }
    /// ```
    pub fn config(&self, adjust: impl FnOnce(&mut OAuthConfig)) -> ResolvedOAuthConfig {
        let mut config = OAuthConfig {
            enabled: true,
            issuer: self.issuer.clone(),
            jwks_uri: Some(self.server.url.clone()),
            audience: Self::AUDIENCE.to_string(),
            resource: Self::RESOURCE.to_string(),
            required_scopes: vec![Self::SCOPE.to_string()],
            ..OAuthConfig::default()
        };
        adjust(&mut config);
        match config.resolve(KeyNaming::Dotted("oauth")) {
            Ok(Some(resolved)) => resolved,
            Ok(None) => panic!("TestAuthority::config: the adjusted config has enabled = false"),
            Err(err) => panic!("TestAuthority::config: the adjusted config is invalid: {err}"),
        }
    }

    /// Start a [`TokenBuilder`] whose defaults produce a token the
    /// [`config`](Self::config) validator accepts: this authority's issuer,
    /// [`AUDIENCE`](Self::AUDIENCE), subject `test-user`, scope
    /// [`SCOPE`](Self::SCOPE), valid for an hour, `typ: at+jwt`, signed RS256
    /// with the currently active RSA key.
    pub fn token(&self) -> TokenBuilder {
        let now = now();
        TokenBuilder {
            rsa: self.keys.lock().expect("key state lock").active,
            issuer: self.issuer.clone(),
            audiences: vec![Self::AUDIENCE.to_string()],
            subject: "test-user".to_string(),
            scopes: vec![Self::SCOPE.to_string()],
            exp: now + 3600,
            iat: now,
            nbf: None,
            typ: Some("at+jwt".to_string()),
            alg: Algorithm::RS256,
            kid: None,
            set: serde_json::Map::new(),
            removed: Vec::new(),
        }
    }
}

/// A fluent builder for a signed JWT access token, from
/// [`TestAuthority::token`]. Every method changes one thing about the token, so
/// a test states exactly what is wrong (or different) about it; the defaults
/// are documented on [`TestAuthority::token`].
///
/// Time setters are relative to now and in seconds ([`expires_in`],
/// [`expired`], [`not_before_in`], [`issued_ago`]). For an absolute or odd value
/// use [`claim`](Self::claim): `.claim("nbf", 4102444800_u64)`,
/// `.claim("exp", "soon")`.
///
/// Claim-shaping calls apply in this order: the fields above (`iss`, `aud`,
/// `sub`, `scope`, `exp`, `iat`, `nbf`), then [`claim`](Self::claim) overrides,
/// then [`without_claim`](Self::without_claim) removals, so
/// `without_claim("exp")` really produces a token with no `exp`.
///
/// [`expires_in`]: Self::expires_in
/// [`expired`]: Self::expired
/// [`not_before_in`]: Self::not_before_in
/// [`issued_ago`]: Self::issued_ago
///
/// # Examples
///
/// ```
/// use oauth_resource_server::Algorithm;
/// use oauth_resource_server::testing::TestAuthority;
///
/// # #[tokio::main(flavor = "current_thread")]
/// # async fn main() {
/// let authority = TestAuthority::start().await;
/// let jwt = authority
///     .token()
///     .subject("ada")
///     .scopes(["api:read", "api:write"])
///     .audience("https://other.example.test/")
///     .expires_in(60)
///     .typ("at+jwt")
///     .alg(Algorithm::ES256)
///     .claim("groups", ["admins"])
///     .sign();
/// assert_eq!(jwt.split('.').count(), 3);
/// # }
/// ```
#[derive(Debug, Clone)]
#[must_use = "a TokenBuilder does nothing until `.sign()` is called"]
pub struct TokenBuilder {
    rsa: RsaKey,
    issuer: String,
    audiences: Vec<String>,
    subject: String,
    scopes: Vec<String>,
    exp: u64,
    iat: u64,
    nbf: Option<u64>,
    typ: Option<String>,
    alg: Algorithm,
    kid: Option<String>,
    set: serde_json::Map<String, serde_json::Value>,
    removed: Vec<String>,
}

impl TokenBuilder {
    /// Set `sub`.
    pub fn subject(mut self, subject: impl Into<String>) -> Self {
        self.subject = subject.into();
        self
    }

    /// Replace the scopes, carried in the space-delimited `scope` claim. An
    /// empty list omits the claim.
    pub fn scopes<I, S>(mut self, scopes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.scopes = scopes.into_iter().map(Into::into).collect();
        self
    }

    /// Set `aud` to this one audience (a JSON string).
    pub fn audience(mut self, audience: impl Into<String>) -> Self {
        self.audiences = vec![audience.into()];
        self
    }

    /// Set `aud` to these audiences (a JSON array, or a string when there is
    /// exactly one).
    pub fn audiences<I, S>(mut self, audiences: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.audiences = audiences.into_iter().map(Into::into).collect();
        self
    }

    /// Override `iss` (default: the authority's issuer), for a wrong-issuer test.
    pub fn issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = issuer.into();
        self
    }

    /// Make the token expire `secs` seconds from now.
    pub fn expires_in(mut self, secs: u64) -> Self {
        self.exp = now() + secs;
        self
    }

    /// Make the token expired: `exp` an hour in the past, well beyond the
    /// default 60-second leeway.
    pub fn expired(mut self) -> Self {
        self.exp = now().saturating_sub(3600);
        self
    }

    /// Set `nbf` to `secs` seconds in the future, so the token is not yet
    /// valid (mind the default 60-second leeway).
    pub fn not_before_in(mut self, secs: u64) -> Self {
        self.nbf = Some(now() + secs);
        self
    }

    /// Set `iat` to `secs` seconds in the past (default: now).
    pub fn issued_ago(mut self, secs: u64) -> Self {
        self.iat = now().saturating_sub(secs);
        self
    }

    /// Set the JOSE header `typ` (default `at+jwt`, RFC 9068).
    pub fn typ(mut self, typ: impl Into<String>) -> Self {
        self.typ = Some(typ.into());
        self
    }

    /// Omit the JOSE header `typ` entirely.
    pub fn without_typ(mut self) -> Self {
        self.typ = None;
        self
    }

    /// Sign with `alg` (default [`Algorithm::RS256`]), using the matching
    /// throwaway key: the active RSA key for RS*/PS*, the P-256 key for ES256,
    /// the Ed25519 key for EdDSA. All of them are published by the authority,
    /// each under its own `kid`. The header `kid` follows unless
    /// [`kid`](Self::kid) overrides it. ES384 has no throwaway key:
    /// [`sign`](Self::sign) panics for it.
    pub fn alg(mut self, alg: Algorithm) -> Self {
        self.alg = alg;
        self
    }

    /// Set the header `kid`, overriding the one that names the signing key
    /// (for an unknown-`kid` or "signed by one key, labelled as another" test).
    pub fn kid(mut self, kid: impl Into<String>) -> Self {
        self.kid = Some(kid.into());
        self
    }

    /// Set (or override) one claim, any JSON-serializable value. This is also
    /// how to set an absolute or malformed `exp`/`nbf`/`iat`.
    ///
    /// # Panics
    ///
    /// If `value` fails to serialize.
    pub fn claim(mut self, name: impl Into<String>, value: impl Serialize) -> Self {
        let name = name.into();
        self.removed.retain(|removed| *removed != name);
        self.set.insert(
            name,
            serde_json::to_value(value).expect("the claim value serializes"),
        );
        self
    }

    /// Leave a claim out of the token, including a default one such as `exp`,
    /// `aud` or `iss`.
    pub fn without_claim(mut self, name: impl Into<String>) -> Self {
        let name = name.into();
        self.set.remove(&name);
        self.removed.push(name);
        self
    }

    /// Sign the token and return the compact JWT.
    ///
    /// # Panics
    ///
    /// If [`alg`](Self::alg) is an algorithm with no throwaway key (ES384).
    pub fn sign(self) -> String {
        let mut claims = serde_json::Map::new();
        claims.insert("iss".into(), self.issuer.clone().into());
        claims.insert(
            "aud".into(),
            match self.audiences.as_slice() {
                [one] => one.clone().into(),
                many => many.to_vec().into(),
            },
        );
        claims.insert("sub".into(), self.subject.clone().into());
        if !self.scopes.is_empty() {
            claims.insert("scope".into(), self.scopes.join(" ").into());
        }
        claims.insert("exp".into(), self.exp.into());
        claims.insert("iat".into(), self.iat.into());
        if let Some(nbf) = self.nbf {
            claims.insert("nbf".into(), nbf.into());
        }
        claims.extend(self.set.clone());
        for name in &self.removed {
            claims.remove(name);
        }

        let (pem, default_kid) = match self.alg {
            Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::PS256
            | Algorithm::PS384
            | Algorithm::PS512 => (self.rsa.pem(), self.rsa.kid_for(self.alg)),
            Algorithm::ES256 => (EC_PEM, KID_EC.to_string()),
            Algorithm::EdDSA => (ED_PEM, KID_ED.to_string()),
            other => panic!("no test key for {other:?}"),
        };
        let key = match self.alg {
            Algorithm::ES256 => EncodingKey::from_ec_pem(pem.as_bytes()),
            Algorithm::EdDSA => EncodingKey::from_ed_pem(pem.as_bytes()),
            _ => EncodingKey::from_rsa_pem(pem.as_bytes()),
        }
        .expect("a valid test key");
        let mut header = Header::new(self.alg.to_jwt());
        header.typ = self.typ.clone();
        header.kid = Some(self.kid.clone().unwrap_or(default_kid));
        encode(&header, &serde_json::Value::Object(claims), &key).expect("the token encodes")
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{Credential, OAuthValidator, TokenRejection, authenticate};

    fn validator(config: &ResolvedOAuthConfig) -> OAuthValidator {
        OAuthValidator::new(config).unwrap()
    }

    /// No unknown-`kid` cooldown, so a test can observe a refetch without
    /// sleeping out the 60 seconds.
    fn validator_no_cooldown(config: &ResolvedOAuthConfig) -> OAuthValidator {
        OAuthValidator::build(config, Duration::ZERO).unwrap()
    }

    async fn outcome(
        config: &ResolvedOAuthConfig,
        token: &str,
    ) -> Result<Credential, TokenRejection> {
        let v = validator(config);
        authenticate([token], None, Some(&v)).await
    }

    fn is_invalid<T>(r: &Result<T, TokenRejection>) -> bool {
        matches!(r, Err(TokenRejection::Invalid(_)))
    }

    #[tokio::test]
    async fn default_token_is_accepted_through_authenticate() {
        let authority = TestAuthority::start().await;
        let config = authority.config(|_| {});
        assert_eq!(config.issuer, authority.issuer());
        assert_eq!(config.jwks_uri.as_deref(), Some(authority.jwks_uri()));
        assert_eq!(config.audience, TestAuthority::AUDIENCE);
        assert_eq!(config.required_scopes, [TestAuthority::SCOPE]);
        assert!(!config.allow_insecure_http, "loopback needs no opt-in");

        let token = authority.token().sign();
        let Ok(Credential::OAuth(t)) = outcome(&config, &token).await else {
            panic!("the default token must validate");
        };
        assert_eq!(t.subject.as_deref(), Some("test-user"));
        assert!(t.has_scope("api:read"));
        assert_eq!(t.issuer, authority.issuer());
        assert_eq!(t.audiences, [TestAuthority::AUDIENCE]);
    }

    #[tokio::test]
    async fn each_builder_knob_changes_the_outcome() {
        let authority = TestAuthority::start().await;
        let config = authority.config(|c| c.require_at_jwt = true);
        let check = |token: String| {
            let config = &config;
            async move { outcome(config, &token).await }
        };

        assert!(check(authority.token().sign()).await.is_ok());
        assert!(is_invalid(&check(authority.token().expired().sign()).await));
        let elsewhere = "https://elsewhere.example.test/";
        assert!(is_invalid(
            &check(authority.token().audience(elsewhere).sign()).await
        ));
        assert!(is_invalid(
            &check(authority.token().issuer(elsewhere).sign()).await
        ));
        assert!(matches!(
            check(authority.token().scopes(["other:scope"]).sign()).await,
            Err(TokenRejection::InsufficientScope)
        ));
        assert!(is_invalid(
            &check(authority.token().typ("JWT").sign()).await
        ));
        assert!(is_invalid(
            &check(authority.token().without_typ().sign()).await
        ));
        assert!(is_invalid(
            &check(authority.token().not_before_in(3600).sign()).await
        ));
        for claim in ["exp", "aud", "iss"] {
            assert!(
                is_invalid(&check(authority.token().without_claim(claim).sign()).await),
                "a token with no {claim} must be refused"
            );
        }
        // Accepted variations.
        let both = authority
            .token()
            .audiences([elsewhere, TestAuthority::AUDIENCE]);
        assert!(check(both.sign()).await.is_ok());
        // A past `nbf` (set absolutely through `claim`) and an earlier `iat`.
        let past = now() - 10;
        assert!(
            check(authority.token().claim("nbf", past).issued_ago(10).sign())
                .await
                .is_ok()
        );
        assert!(check(authority.token().expires_in(30).sign()).await.is_ok());
        // An unknown `kid` is refused: no such key in the JWKS.
        assert!(is_invalid(
            &check(authority.token().kid("no-such-key").sign()).await
        ));
    }

    #[tokio::test]
    async fn claim_and_without_claim_shape_the_claims() {
        let authority = TestAuthority::start().await;
        let v = validator(&authority.config(|_| {}));
        let token = authority
            .token()
            .subject("ada")
            .claim("groups", ["admins"])
            .claim("email", "ada@example.test")
            .without_claim("email")
            .claim("azp", "client-1")
            .sign();
        let t = v.validate(&token).await.unwrap();
        assert_eq!(t.subject.as_deref(), Some("ada"));
        assert_eq!(t.client_id.as_deref(), Some("client-1"));
        assert_eq!(t.claims()["groups"], serde_json::json!(["admins"]));
        assert!(!t.claims().contains_key("email"));
        // `claim` after `without_claim` puts it back.
        let token = authority
            .token()
            .without_claim("sub")
            .claim("sub", "back")
            .sign();
        let t = v.validate(&token).await.unwrap();
        assert_eq!(t.subject.as_deref(), Some("back"));
    }

    #[tokio::test]
    async fn every_algorithm_with_a_test_key_validates() {
        let authority = TestAuthority::start().await;
        let v = validator(&authority.config(|_| {}));
        for alg in [
            Algorithm::RS256,
            Algorithm::RS384,
            Algorithm::RS512,
            Algorithm::PS256,
            Algorithm::PS384,
            Algorithm::PS512,
            Algorithm::ES256,
            Algorithm::EdDSA,
        ] {
            let token = authority.token().alg(alg).sign();
            assert!(v.validate(&token).await.is_ok(), "{alg:?} must validate");
        }
    }

    #[tokio::test]
    #[should_panic(expected = "no test key for ES384")]
    async fn an_algorithm_without_a_test_key_panics() {
        let authority = TestAuthority::start().await;
        let _ = authority.token().alg(Algorithm::ES384).sign();
    }

    #[tokio::test]
    async fn rotate_key_publishes_both_keys_and_signs_with_the_new_one() {
        let authority = TestAuthority::start().await;
        let v = validator_no_cooldown(&authority.config(|_| {}));
        let old = authority.token().sign();
        assert!(v.validate(&old).await.is_ok());
        let before = authority.jwks_fetches();

        authority.rotate_key();
        let new = authority.token().sign();
        // Signed with the other key, under the other `kid`.
        assert_ne!(old.split('.').next(), new.split('.').next());
        // The unknown `kid` triggers a refetch, which finds the new key...
        assert!(v.validate(&new).await.is_ok());
        assert!(
            authority.jwks_fetches() > before,
            "the rotation was refetched"
        );
        // ...and the old key is still published, so the old token still works.
        assert!(v.validate(&old).await.is_ok());

        // A second rotation returns to the first key.
        authority.rotate_key();
        let again = authority.token().sign();
        assert_eq!(old.split('.').next(), again.split('.').next());
    }

    #[tokio::test]
    async fn withdrawing_the_old_key_fails_its_tokens_after_a_refresh() {
        let authority = TestAuthority::start().await;
        let v = validator_no_cooldown(&authority.config(|_| {}));
        let old = authority.token().sign();
        assert!(v.validate(&old).await.is_ok());

        authority.rotate_key();
        authority.withdraw_old_key();
        // Fail-closed caching: the withdrawn key stays trusted until a refresh.
        assert!(v.validate(&old).await.is_ok());
        v.refresh_now().await.unwrap();
        assert!(is_invalid(&v.validate(&old).await));
        assert!(v.validate(&authority.token().sign()).await.is_ok());
    }

    #[tokio::test]
    async fn withdraw_old_key_drops_the_retained_key() {
        let authority = TestAuthority::start().await;
        let v = validator_no_cooldown(&authority.config(|_| {}));
        let old = authority.token().sign();
        authority.rotate_key();
        v.refresh_now().await.unwrap();
        assert!(v.validate(&old).await.is_ok(), "retained after rotate_key");
        authority.withdraw_old_key();
        v.refresh_now().await.unwrap();
        assert!(is_invalid(&v.validate(&old).await));
        assert!(v.validate(&authority.token().sign()).await.is_ok());
    }

    #[tokio::test]
    async fn discovery_finds_the_jwks_through_either_document() {
        let authority = TestAuthority::start().await;
        let config = authority.config(|c| c.jwks_uri = None);
        assert!(config.jwks_uri.is_none());
        let v = validator(&config);
        assert!(v.validate(&authority.token().sign()).await.is_ok());

        assert!(authority.discovery_fetches() >= 1);
        assert_eq!(authority.jwks_fetches(), 1);

        // With the OIDC document gone, RFC 8414 discovery still works.
        authority
            .server
            .routes
            .lock()
            .unwrap()
            .remove(DISCOVERY_OIDC);
        let v = validator(&config);
        let es256 = authority.token().alg(Algorithm::ES256).sign();
        assert!(v.validate(&es256).await.is_ok());
    }

    #[tokio::test]
    async fn the_served_jwks_has_no_alg_less_key_and_stays_under_the_key_cap() {
        let authority = TestAuthority::start().await;
        let all: Vec<Algorithm> = DEFAULT_ALGORITHMS
            .iter()
            .map(|a| parse_algorithm(a).unwrap())
            .collect();
        for retained in [false, true] {
            let body = KeyState {
                active: RsaKey::A,
                retained,
            }
            .jwks_body();
            let jwks: serde_json::Value = serde_json::from_str(&body).unwrap();
            let keys = jwks["keys"].as_array().unwrap();
            assert!(keys.len() <= crate::jwks::MAX_JWKS_KEYS);
            for entry in keys {
                let key = crate::jwks::parse_jwks_entry(entry, &all)
                    .unwrap_or_else(|| panic!("usable key expected: {entry}"));
                assert!(!key.ambiguous, "the crate would warn about {entry}");
            }
        }
        // And what the live server serves is the same document.
        let served = authority
            .server
            .routes
            .lock()
            .unwrap()
            .get(JWKS_PATH)
            .cloned()
            .unwrap()
            .1;
        assert_eq!(
            served,
            KeyState {
                active: RsaKey::A,
                retained: false
            }
            .jwks_body()
        );
    }

    #[tokio::test]
    async fn dropping_the_authority_stops_its_server() {
        let authority = TestAuthority::start().await;
        let addr = authority
            .server
            .base
            .trim_start_matches("http://")
            .to_string();
        assert!(tokio::net::TcpStream::connect(&addr).await.is_ok());
        drop(authority);
        let mut stopped = false;
        for _ in 0..100 {
            if tokio::net::TcpStream::connect(&addr).await.is_err() {
                stopped = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(stopped, "the accept loop must end with the authority");
    }

    #[tokio::test]
    async fn a_response_delay_stalls_the_authority() {
        let authority = TestAuthority::start().await;
        authority.set_response_delay(Duration::from_millis(300));
        let started = std::time::Instant::now();
        let v = validator(&authority.config(|_| {}));
        assert!(v.validate(&authority.token().sign()).await.is_ok());
        assert!(started.elapsed() >= Duration::from_millis(300));
    }

    #[tokio::test]
    #[should_panic(expected = "the adjusted config is invalid")]
    async fn config_panics_with_the_resolve_error() {
        let authority = TestAuthority::start().await;
        let _ = authority.config(|c| c.audience = String::new());
    }

    #[cfg(feature = "axum")]
    #[tokio::test]
    async fn axum_end_to_end_with_layer_and_extractor() {
        use std::sync::Arc;

        use ::axum::Router;
        use ::axum::body::Body;
        use ::axum::http::{Request, StatusCode};
        use ::axum::routing::get;
        use tower::ServiceExt;

        use crate::AuthorizedToken;
        use crate::axum::AuthLayer;

        let authority = TestAuthority::start().await;
        let validator = Arc::new(OAuthValidator::new(&authority.config(|_| {})).unwrap());
        let layer = AuthLayer::builder().oauth(validator).build().unwrap();
        let app = Router::new()
            .route(
                "/whoami",
                get(|token: AuthorizedToken| async move { token.subject.unwrap_or_default() }),
            )
            .route_layer(layer);
        let call = |bearer: Option<String>| {
            let app = app.clone();
            async move {
                let mut req = Request::builder().uri("/whoami");
                if let Some(bearer) = bearer {
                    req = req.header("authorization", format!("Bearer {bearer}"));
                }
                app.oneshot(req.body(Body::empty()).unwrap()).await.unwrap()
            }
        };

        let resp = call(Some(authority.token().subject("ada").sign())).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = ::axum::body::to_bytes(resp.into_body(), 1024)
            .await
            .unwrap();
        assert_eq!(body, "ada");

        let resp = call(Some(authority.token().expired().sign())).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(resp.headers().contains_key("www-authenticate"));
        let resp = call(Some(authority.token().scopes(["other:scope"]).sign())).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let resp = call(None).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}
