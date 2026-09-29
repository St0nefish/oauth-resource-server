//! Transport-agnostic credential checking: a static token and/or OAuth, over
//! every candidate credential a request carries.
//!
//! This is the framework-free core of the axum middleware (feature `axum`). An
//! application on another HTTP stack collects its candidate header values itself
//! and calls [`authenticate`]; the status code and challenge for a failure follow
//! from the returned [`TokenRejection`] (see its docs).

use subtle::ConstantTimeEq;

use crate::token::{AuthorizedToken, TokenRejection};
use crate::validator::{CachedAttempt, OAuthValidator};

/// Which mechanism accepted a request.
///
/// Deliberately not something to put in a response: a client should not be able
/// to tell from the outcome which mechanism accepted (or refused) which of its
/// credentials. The axum middleware inserts it into request extensions so a
/// handler can, for example, attribute a write to an OAuth principal.
// `OAuth` holds the token inline: boxing it would change a public variant's type
// (a breaking change), for a value that exists once per request.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Credential {
    /// A candidate matched the configured static token.
    StaticToken,
    /// A candidate validated as an OAuth access token carrying every required
    /// scope.
    OAuth(AuthorizedToken),
}

/// Check every candidate credential against every configured mechanism, and
/// accept if ANY candidate satisfies ANY mechanism.
///
/// `candidates` is every value that could carry a credential — typically the
/// token from `Authorization: Bearer <token>` and, for an application that also
/// takes one, the value of a raw API-key header — in any order, however many are
/// present. The presence of one candidate never decides whether another is
/// looked at, so an invalid credential in one place cannot hide a valid one in
/// another.
///
/// Candidates are used verbatim; an empty or whitespace-only candidate counts as
/// absent. `static_token` of `None` or `Some("")` means no static token is
/// configured (a blank secret must never be matchable); `oauth` of `None` means
/// OAuth is off. With neither configured nothing can succeed: this function
/// never passes a request through. Deciding to run without authentication is the
/// caller's explicit choice, made before calling it (see
/// [`crate::static_token_policy`]).
///
/// # Order
///
/// Every candidate is first compared with the static token, in constant time
/// (`subtle`; the lengths are not hidden). A match is decisive and needs no
/// network, so the common static-token request never reaches the JWT machinery
/// or depends on the authorization server being up. Only then is every
/// candidate validated through OAuth, in order, until one is accepted — first
/// against the signing keys already held, and only if that accepts none of them
/// is a candidate whose `kid` is not held allowed to trigger a key refetch. A
/// foreign JWT in one source therefore never makes a request wait on the
/// authorization server when another candidate's key is already cached.
///
/// # Result
///
/// - `Ok` as soon as any candidate is accepted.
/// - Otherwise [`TokenRejection::InsufficientScope`] if any candidate was a
///   valid OAuth token lacking a required scope: "this credential is fine but
///   not sufficient" (RFC 6750's 403) is the more useful answer when it is true
///   of any of them.
/// - Otherwise [`TokenRejection::Missing`] if there was no non-blank candidate.
/// - Otherwise [`TokenRejection::Invalid`] carrying the first candidate's
///   reason — the validator's, when OAuth is configured. The reason is for logs
///   only; never send it to the caller.
///
/// Map a refusal to a response the same way the axum layer does: 403 with
/// [`OAuthValidator::insufficient_scope_challenge`] for `InsufficientScope`,
/// 401 with [`OAuthValidator::invalid_token_challenge`] for everything else,
/// and (with OAuth configured) the challenge in `WWW-Authenticate` on both.
///
/// # Errors
///
/// A [`TokenRejection`], chosen as described under "Result" above. This
/// function logs nothing; logging the refusal is the caller's job.
///
/// # Panics
///
/// Outside a Tokio 1.x runtime, when an OAuth candidate's signing key has to
/// be fetched (see [`OAuthValidator`]'s "Runtime" section). A static-token
/// match, or a key already held, needs no runtime.
///
/// # Security
///
/// The static token is compared in constant time, but its length is not
/// hidden. Candidates are never trimmed or normalized, so a static token is
/// matched only byte for byte.
///
/// # Examples
///
/// ```
/// use oauth_resource_server::{Credential, TokenRejection, authenticate};
///
/// # #[tokio::main(flavor = "current_thread")]
/// # async fn main() {
/// // Static token only (no OAuth validator): a junk value in one header does
/// // not stop the key in another from being accepted.
/// let key = Some("example-static-key");
/// let ok = authenticate(["junk", "example-static-key"], key, None).await;
/// assert_eq!(ok, Ok(Credential::StaticToken));
///
/// assert_eq!(authenticate([" ", ""], key, None).await, Err(TokenRejection::Missing));
/// assert!(matches!(
///     authenticate(["guess"], key, None).await,
///     Err(TokenRejection::Invalid(_))
/// ));
/// # }
/// ```
pub async fn authenticate<'a>(
    candidates: impl IntoIterator<Item = &'a str>,
    static_token: Option<&str>,
    oauth: Option<&OAuthValidator>,
) -> Result<Credential, TokenRejection> {
    // Every candidate is considered, never just the first one present:
    // choosing the `Authorization` header whenever it was present would let a
    // foreign JWT there, added by a proxy, make a valid token in a second
    // credential header (such as `X-Api-Key`) unreachable.
    let candidates: Vec<&str> = candidates
        .into_iter()
        .filter(|c| !c.trim().is_empty())
        .collect();
    if candidates.is_empty() {
        return Err(TokenRejection::Missing);
    }

    let static_token = static_token.filter(|t| !t.is_empty());
    if let Some(expected) = static_token {
        for candidate in &candidates {
            if bool::from(candidate.as_bytes().ct_eq(expected.as_bytes())) {
                return Ok(Credential::StaticToken);
            }
        }
    }

    let Some(validator) = oauth else {
        return Err(TokenRejection::Invalid(
            if static_token.is_some() {
                "credential does not match the static token"
            } else {
                "no credential mechanism is configured"
            }
            .to_string(),
        ));
    };

    // Two passes. The first decides every candidate it can from the keys
    // already held; only if none of them is accepted does the second validate
    // the rest, which may refetch the JWKS. Otherwise a foreign JWT in an
    // earlier source (a proxy's own token, signed by some other issuer, so an
    // unknown `kid`) would queue every request behind a key refetch even when a
    // later candidate's key is cached. Refusals are recorded per candidate
    // position, so the reason reported is still the first candidate's.
    let mut refusals: Vec<Option<TokenRejection>> = Vec::with_capacity(candidates.len());
    for candidate in &candidates {
        match validator.validate_cached(candidate).await {
            CachedAttempt::Decided(Ok(token)) => return Ok(Credential::OAuth(token)),
            CachedAttempt::Decided(Err(rejection)) => refusals.push(Some(rejection)),
            CachedAttempt::NeedsKeyFetch => refusals.push(None),
        }
    }
    for (candidate, refusal) in candidates.iter().zip(refusals.iter_mut()) {
        if refusal.is_none() {
            match validator.validate(candidate).await {
                Ok(token) => return Ok(Credential::OAuth(token)),
                Err(rejection) => *refusal = Some(rejection),
            }
        }
    }

    let mut insufficient_scope = false;
    let mut first_reason: Option<String> = None;
    for refusal in refusals.into_iter().flatten() {
        match refusal {
            TokenRejection::InsufficientScope => insufficient_scope = true,
            TokenRejection::Invalid(reason) => {
                first_reason.get_or_insert(reason);
            }
            // `Missing` is unreachable for a non-blank candidate. Recorded as a
            // refusal all the same: whatever the validator says that is not
            // `Ok` must never read as acceptance.
            TokenRejection::Missing => {
                first_reason.get_or_insert_with(|| "no credential presented".to_string());
            }
        }
    }
    if insufficient_scope {
        return Err(TokenRejection::InsufficientScope);
    }
    Err(TokenRejection::Invalid(first_reason.unwrap_or_else(|| {
        "no candidate credential was accepted".to_string()
    })))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::testing;

    const STATIC: &str = "static-secret";

    /// A validator whose JWKS endpoint refuses connections: anything that
    /// reaches key lookup fails, so a test that succeeds against it proves the
    /// request never needed the authorization server.
    fn unreachable_validator() -> Arc<OAuthValidator> {
        Arc::new(OAuthValidator::new(&testing::resolved_config("http://127.0.0.1:1/jwks")).unwrap())
    }

    async fn live_validator() -> (testing::FakeJwksServer, Arc<OAuthValidator>) {
        let jwks = testing::spawn_jwks_server("200 OK", testing::jwks_body()).await;
        let v = Arc::new(OAuthValidator::new(&testing::resolved_config(&jwks.url)).unwrap());
        (jwks, v)
    }

    fn unscoped_token() -> String {
        testing::mint(
            testing::KEY_A_PEM,
            testing::KID_A,
            &serde_json::json!({
                "iss": testing::ISSUER, "aud": testing::AUDIENCE, "sub": "user-2",
                "exp": testing::now() + 3600, "scope": "openid profile",
            }),
        )
    }

    fn expired_token() -> String {
        testing::mint(
            testing::KEY_A_PEM,
            testing::KID_A,
            &serde_json::json!({
                "iss": testing::ISSUER, "aud": testing::AUDIENCE,
                "exp": testing::now() - 3600, "scope": "mcp:read",
            }),
        )
    }

    #[tokio::test]
    async fn a_static_match_wins_without_touching_oauth() {
        let v = unreachable_validator();
        assert_eq!(
            authenticate([STATIC], Some(STATIC), Some(&v)).await,
            Ok(Credential::StaticToken)
        );
        assert_eq!(
            authenticate([STATIC], Some(STATIC), None).await,
            Ok(Credential::StaticToken)
        );
    }

    #[tokio::test]
    async fn an_oauth_match_returns_the_authorized_token() {
        let (jwks, v) = live_validator().await;
        let token = testing::valid_token();
        for static_token in [None, Some(STATIC)] {
            match authenticate([token.as_str()], static_token, Some(&v)).await {
                Ok(Credential::OAuth(t)) => {
                    assert_eq!(t.subject.as_deref(), Some("user-1"));
                    assert!(t.has_scope("mcp:read"));
                }
                other => panic!("expected an OAuth credential, got {other:?}"),
            }
        }
        assert!(jwks.hits.load(std::sync::atomic::Ordering::SeqCst) >= 1);
    }

    #[tokio::test]
    async fn a_valid_token_lacking_scope_is_insufficient_scope() {
        let (_jwks, v) = live_validator().await;
        let token = unscoped_token();
        assert_eq!(
            authenticate([token.as_str()], Some(STATIC), Some(&v)).await,
            Err(TokenRejection::InsufficientScope)
        );
    }

    #[tokio::test]
    async fn no_candidate_is_missing_whatever_is_configured() {
        let v = unreachable_validator();
        for (static_token, oauth) in [
            (Some(STATIC), None),
            (None, Some(&*v)),
            (Some(STATIC), Some(&*v)),
            (None, None),
        ] {
            assert_eq!(
                authenticate(std::iter::empty(), static_token, oauth).await,
                Err(TokenRejection::Missing),
                "static={static_token:?} oauth={}",
                oauth.is_some()
            );
        }
    }

    #[tokio::test]
    async fn blank_candidates_count_as_absent() {
        let v = unreachable_validator();
        assert_eq!(
            authenticate(["", "   ", "\t"], Some(STATIC), Some(&v)).await,
            Err(TokenRejection::Missing)
        );
        // A blank candidate before a good one does not mask it.
        assert_eq!(
            authenticate(["", " ", STATIC], Some(STATIC), Some(&v)).await,
            Ok(Credential::StaticToken)
        );
    }

    #[tokio::test]
    async fn a_blank_static_token_never_matches() {
        // `Some("")` is "not configured", not "matches the empty credential".
        assert_eq!(
            authenticate([""], Some(""), None).await,
            Err(TokenRejection::Missing)
        );
        assert_eq!(
            authenticate(["x"], Some(""), None).await,
            Err(TokenRejection::Invalid(
                "no credential mechanism is configured".into()
            ))
        );
    }

    #[tokio::test]
    async fn an_invalid_credential_carries_the_first_reason() {
        let (_jwks, v) = live_validator().await;
        let expired = expired_token();
        match authenticate([expired.as_str(), "not-a-jwt"], Some(STATIC), Some(&v)).await {
            Err(TokenRejection::Invalid(reason)) => {
                assert!(reason.starts_with("token rejected:"), "{reason}");
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
        match authenticate(["not-a-jwt", expired.as_str()], Some(STATIC), Some(&v)).await {
            Err(TokenRejection::Invalid(reason)) => {
                assert!(reason.starts_with("credential is not a JWT"), "{reason}");
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn static_only_refuses_a_jwt_without_validating_it() {
        let token = testing::valid_token();
        assert_eq!(
            authenticate([token.as_str()], Some(STATIC), None).await,
            Err(TokenRejection::Invalid(
                "credential does not match the static token".into()
            ))
        );
    }

    #[tokio::test]
    async fn oauth_only_refuses_the_static_value() {
        let v = unreachable_validator();
        match authenticate([STATIC], None, Some(&v)).await {
            Err(TokenRejection::Invalid(reason)) => {
                assert!(reason.starts_with("credential is not a JWT"), "{reason}");
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn neither_mechanism_configured_accepts_nothing() {
        assert_eq!(
            authenticate([STATIC], None, None).await,
            Err(TokenRejection::Invalid(
                "no credential mechanism is configured".into()
            ))
        );
    }

    /// A validator with no refetch cooldown, so any unknown `kid` that reaches
    /// key lookup WOULD refetch — the hit counter then shows whether it did.
    async fn eager_refetch_validator() -> (testing::FakeJwksServer, OAuthValidator) {
        let jwks = testing::spawn_jwks_server("200 OK", testing::jwks_body()).await;
        let v = OAuthValidator::build(
            &testing::resolved_config(&jwks.url),
            std::time::Duration::ZERO,
        )
        .unwrap();
        (jwks, v)
    }

    /// A well-formed token signed by some other issuer's key, under a `kid`
    /// this validator has never seen (a proxy's own JWT, say).
    fn foreign_token() -> String {
        testing::mint(
            testing::KEY_B_PEM,
            "proxy-key",
            &serde_json::json!({
                "iss": "https://proxy.example.test/", "aud": "proxy",
                "exp": testing::now() + 3600,
            }),
        )
    }

    fn hits(jwks: &testing::FakeJwksServer) -> usize {
        jwks.hits.load(std::sync::atomic::Ordering::SeqCst)
    }

    #[tokio::test]
    async fn a_foreign_kid_does_not_trigger_a_refetch_when_another_candidate_is_cached() {
        let (jwks, v) = eager_refetch_validator().await;
        let valid = testing::valid_token();
        let foreign = foreign_token();
        // Warm the cache.
        assert!(v.validate(&valid).await.is_ok());
        assert_eq!(hits(&jwks), 1);

        // The foreign JWT first, as a proxy-added `Authorization` header would
        // be: the cached candidate decides the request with no fetch at all.
        for candidates in [
            [foreign.as_str(), valid.as_str()],
            [valid.as_str(), foreign.as_str()],
        ] {
            assert!(matches!(
                authenticate(candidates, None, Some(&v)).await,
                Ok(Credential::OAuth(_))
            ));
        }
        assert_eq!(hits(&jwks), 1, "no refetch for the foreign kid");

        // With nothing else acceptable, the unknown kid still gets its refetch
        // (it could be a genuinely rotated key) and is then refused.
        match authenticate([foreign.as_str(), "garbage"], None, Some(&v)).await {
            Err(TokenRejection::Invalid(reason)) => {
                assert!(reason.contains("proxy-key"), "{reason}");
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
        assert_eq!(hits(&jwks), 2);
    }

    #[tokio::test]
    async fn a_cold_cache_still_fetches_for_the_only_candidate() {
        let (jwks, v) = eager_refetch_validator().await;
        let valid = testing::valid_token();
        assert_eq!(hits(&jwks), 0);
        assert!(matches!(
            authenticate([valid.as_str()], None, Some(&v)).await,
            Ok(Credential::OAuth(_))
        ));
        assert_eq!(hits(&jwks), 1);
        // The reported reason is still the FIRST candidate's, even though the
        // second was decided in the cache-only pass and the first only after
        // its refetch.
        let (_jwks, v) = eager_refetch_validator().await;
        match authenticate([foreign_token().as_str(), "not-a-jwt"], None, Some(&v)).await {
            Err(TokenRejection::Invalid(reason)) => {
                assert!(reason.contains("proxy-key"), "{reason}");
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    /// A bad candidate in one position must never mask a good
    /// one in another, in either order and for either mechanism.
    #[tokio::test]
    async fn mixed_candidates_any_success_wins_in_either_order() {
        let (_jwks, v) = live_validator().await;
        let valid = testing::valid_token();
        let unscoped = unscoped_token();
        let expired = expired_token();

        for candidates in [
            vec![expired.as_str(), STATIC],
            vec![STATIC, expired.as_str()],
            vec!["garbage", STATIC],
            vec![unscoped.as_str(), STATIC],
        ] {
            assert_eq!(
                authenticate(candidates.iter().copied(), Some(STATIC), Some(&v)).await,
                Ok(Credential::StaticToken),
                "{candidates:.30?}"
            );
        }
        for candidates in [
            vec!["wrong-static", valid.as_str()],
            vec![valid.as_str(), "wrong-static"],
            vec![unscoped.as_str(), valid.as_str()],
            vec![expired.as_str(), valid.as_str()],
        ] {
            assert!(
                matches!(
                    authenticate(candidates.iter().copied(), Some(STATIC), Some(&v)).await,
                    Ok(Credential::OAuth(_))
                ),
                "{candidates:.30?}"
            );
        }
        // No success: a scope-lacking valid token outranks any invalid one.
        for candidates in [
            vec![unscoped.as_str(), "garbage"],
            vec!["garbage", unscoped.as_str()],
            vec![expired.as_str(), unscoped.as_str()],
        ] {
            assert_eq!(
                authenticate(candidates.iter().copied(), Some(STATIC), Some(&v)).await,
                Err(TokenRejection::InsufficientScope),
                "{candidates:.30?}"
            );
        }
    }
}
