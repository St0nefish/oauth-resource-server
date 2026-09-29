//! The framework-free mapping from a [`TokenRejection`] to the HTTP refusal it
//! calls for: the status (RFC 6750 §3.1: 401 for a missing or invalid
//! credential, 403 for a valid token without the required scopes) and the
//! `WWW-Authenticate` challenge.
//!
//! [`refusal`] and [`refusal_with_static_challenge`] are for an HTTP stack this
//! crate has no integration for (hyper, actix-web, poem, ...), which calls
//! [`crate::authenticate()`] itself. The `axum` and `tower` layers make the
//! same decision through the same private function ([`select`]), so a hand-built
//! integration and the provided layers cannot disagree about a status or a
//! challenge.

use crate::challenge::is_header_value;
use crate::token::TokenRejection;
use crate::validator::OAuthValidator;

/// The `WWW-Authenticate` value a refusal carries when no OAuth validator is
/// configured, unless the application chose another (the layers'
/// `static_challenge`, or [`refusal_with_static_challenge`]).
///
/// RFC 9110 §15.5.2 requires a 401 to carry at least one challenge, and RFC
/// 6750 §3 a `Bearer` challenge with at least one parameter. This is the same
/// `invalid_token` challenge an OAuth refusal sends (without the
/// `resource_metadata` there is nothing to point at), for a missing credential
/// as well as a wrong one.
pub const DEFAULT_STATIC_CHALLENGE: &str = "Bearer error=\"invalid_token\"";

/// The HTTP refusal a [`TokenRejection`] calls for; see [`refusal`].
///
/// `#[non_exhaustive]`: read its fields; more may be added without a breaking
/// change.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Refusal {
    /// `401` (missing or invalid credential) or `403` (a valid token without
    /// the required scopes).
    pub status: u16,
    /// The `WWW-Authenticate` value to send, replacing any other. `None` only
    /// when no OAuth validator is configured and the application opted out of
    /// the static challenge ([`refusal_with_static_challenge`] with `None`).
    pub www_authenticate: Option<String>,
}

/// The status and `WWW-Authenticate` challenge to answer a refused request
/// with — exactly what the `axum` and `tower` layers send.
///
/// - [`TokenRejection::InsufficientScope`] is `403`; everything else
///   ([`Missing`](TokenRejection::Missing), [`Invalid`](TokenRejection::Invalid),
///   any future variant) is `401`.
/// - With `oauth`, the challenge is the validator's:
///   [`OAuthValidator::insufficient_scope_challenge`] for a 403,
///   [`OAuthValidator::invalid_token_challenge`] for every 401 — a request
///   with NO credential included, since `resource_metadata` in that challenge
///   is how a client finds the authorization server (RFC 6750 §3.1's "SHOULD
///   NOT include an error code" for that case is deliberately not followed).
/// - Without `oauth`, the challenge is [`DEFAULT_STATIC_CHALLENGE`]. Use
///   [`refusal_with_static_challenge`] for another, or for none.
///
/// Send the status and set (not append) `WWW-Authenticate` on every refusal,
/// whatever body you build. Never put [`TokenRejection::Invalid`]'s reason in
/// the response: it is for your log.
///
/// # Examples
///
/// ```
/// use oauth_resource_server::{DEFAULT_STATIC_CHALLENGE, TokenRejection, refusal};
///
/// // A static-token-only service (no OAuth validator).
/// let r = refusal(&TokenRejection::Missing, None);
/// assert_eq!(r.status, 401);
/// assert_eq!(r.www_authenticate.as_deref(), Some(DEFAULT_STATIC_CHALLENGE));
/// ```
///
/// With a validator, in any HTTP stack:
///
/// ```no_run
/// use oauth_resource_server::{OAuthValidator, authenticate, refusal};
///
/// # async fn handle(oauth: &OAuthValidator, authorization: Option<&str>) {
/// // The scheme is case-insensitive (RFC 9110 §11.1): `bearer x` is `Bearer x`.
/// let bearer = authorization
///     .and_then(|v| v.split_once(' '))
///     .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("bearer"))
///     .map(|(_, token)| token.trim());
/// match authenticate(bearer, None, Some(oauth)).await {
///     Ok(_credential) => { /* serve the request */ }
///     Err(rejection) => {
///         let r = refusal(&rejection, Some(oauth));
///         // Respond with `r.status`, and `WWW-Authenticate: <value>` for
///         // `r.www_authenticate`.
///         # let _ = r;
///     }
/// }
/// # }
/// ```
pub fn refusal(rejection: &TokenRejection, oauth: Option<&OAuthValidator>) -> Refusal {
    refusal_with_static_challenge(rejection, oauth, Some(DEFAULT_STATIC_CHALLENGE))
}

/// [`refusal`], with the challenge to send when `oauth` is `None` chosen by the
/// caller — the counterpart of the layers' `static_challenge` setting.
/// `static_challenge` is ignored when `oauth` is `Some`: with OAuth, every
/// refusal carries the validator's challenge.
///
/// `Some(value)` sends `value` (`Bearer realm="my-api"`, say, or your own
/// scheme for an API-key header); `None` sends no challenge at all. That
/// departs from RFC 9110 §15.5.2 (a 401 MUST carry a challenge); use it only
/// to keep an existing API's responses unchanged.
///
/// # Security
///
/// The returned challenge is always a valid header value. A `static_challenge`
/// holding any byte other than visible ASCII, SP or HTAB (a CR or LF above
/// all, which would split the header) is not sent: [`DEFAULT_STATIC_CHALLENGE`]
/// is sent in its place. With OAuth the validator's challenges are used,
/// which are always valid too: a validator built from a hand-edited config
/// whose challenges would not be falls back to `Bearer error="invalid_token"`
/// / `Bearer error="insufficient_scope"` (with `scope` only when valid) and
/// logs that at `error`.
///
/// # Examples
///
/// ```
/// use oauth_resource_server::{TokenRejection, refusal_with_static_challenge};
///
/// let r = refusal_with_static_challenge(
///     &TokenRejection::Invalid("wrong key".into()),
///     None,
///     Some("Bearer realm=\"my-api\""),
/// );
/// assert_eq!(r.status, 401);
/// assert_eq!(r.www_authenticate.as_deref(), Some("Bearer realm=\"my-api\""));
///
/// let r = refusal_with_static_challenge(&TokenRejection::Missing, None, None);
/// assert_eq!(r.www_authenticate, None);
/// ```
pub fn refusal_with_static_challenge(
    rejection: &TokenRejection,
    oauth: Option<&OAuthValidator>,
    static_challenge: Option<&str>,
) -> Refusal {
    let oauth_challenges = oauth.map(|v| {
        (
            v.invalid_token_challenge(),
            v.insufficient_scope_challenge(),
        )
    });
    let (status, challenge) = select(
        rejection,
        oauth_challenges
            .as_ref()
            .map(|(i, s)| (i.as_str(), s.as_str())),
        // Never hand out a value that is not a header value (see `# Security`).
        static_challenge.map(|c| {
            if is_header_value(c) {
                c
            } else {
                DEFAULT_STATIC_CHALLENGE
            }
        }),
    );
    Refusal {
        status,
        www_authenticate: challenge.map(str::to_owned),
    }
}

/// [`refusal`] for a request that needed `scopes` on top of the validator's
/// own required scopes — a per-route or per-operation requirement checked
/// with [`crate::AuthorizedToken::require_scopes`]. Everything but the 403
/// challenge is exactly [`refusal`]'s: the same status for every rejection,
/// the same 401 challenge, [`DEFAULT_STATIC_CHALLENGE`] without OAuth.
///
/// With OAuth, [`TokenRejection::InsufficientScope`] carries
/// [`OAuthValidator::insufficient_scope_challenge_for`] naming the
/// validator's `required_scopes` followed by `scopes` (deduplicated): every
/// scope this request needs, so a client that re-authorizes for exactly that
/// set passes both checks. `description` becomes its `error_description`
/// (sanitized as that method documents; `None` for none). This is the same
/// challenge the layers' `require_scopes`, the `RequireScopes` route layer,
/// the `Scoped` extractor and the `mcp` feature send for the same scopes.
///
/// # Examples
///
/// ```no_run
/// use oauth_resource_server::{
///     Credential, OAuthValidator, TokenRejection, authenticate, refusal, refusal_for_scopes,
/// };
///
/// # async fn handle(oauth: &OAuthValidator, bearer: Option<&str>) {
/// let token = match authenticate(bearer, None, Some(oauth)).await {
///     Ok(Credential::OAuth(token)) => token,
///     Ok(_) => unreachable!("no static token was given"),
///     Err(rejection) => {
///         let r = refusal(&rejection, Some(oauth));
///         # let _ = r;
///         return; // respond with r.status and r.www_authenticate
///     }
/// };
/// // This operation needs a write scope on top of the validator's floor.
/// if let Err(missing) = token.require_scopes(&["docs:write"]) {
///     let r = refusal_for_scopes(&missing.into(), Some(oauth), &["docs:write"], None);
///     assert_eq!(r.status, 403);
///     # let _ = r;
///     return; // respond with r.status and r.www_authenticate
/// }
/// # }
/// ```
pub fn refusal_for_scopes(
    rejection: &TokenRejection,
    oauth: Option<&OAuthValidator>,
    scopes: &[&str],
    description: Option<&str>,
) -> Refusal {
    let oauth_challenges = oauth.map(|v| {
        (
            v.invalid_token_challenge(),
            v.insufficient_scope_challenge_for(&v.scopes_with_floor(scopes), description),
        )
    });
    let (status, challenge) = select(
        rejection,
        oauth_challenges
            .as_ref()
            .map(|(i, s)| (i.as_str(), s.as_str())),
        Some(DEFAULT_STATIC_CHALLENGE),
    );
    Refusal {
        status,
        www_authenticate: challenge.map(str::to_owned),
    }
}

/// The one decision behind every refusal this crate builds: the status for
/// `rejection`, and which of the given challenges it carries.
/// `oauth_challenges` is `(invalid_token, insufficient_scope)`, `Some` exactly
/// when OAuth is configured.
///
/// Generic over the challenge's representation so the public [`refusal`]
/// (strings) and the layers (pre-validated `http::HeaderValue`s, which may hold
/// bytes a `&str` cannot) share it without a fallible conversion per request.
pub(crate) fn select<'c, C: ?Sized>(
    rejection: &TokenRejection,
    oauth_challenges: Option<(&'c C, &'c C)>,
    static_challenge: Option<&'c C>,
) -> (u16, Option<&'c C>) {
    let status = match rejection {
        TokenRejection::InsufficientScope => 403,
        // `Missing`, `Invalid`, and any future variant: never a pass.
        _ => 401,
    };
    let challenge = match (oauth_challenges, rejection) {
        (Some((_, insufficient)), TokenRejection::InsufficientScope) => Some(insufficient),
        (Some((invalid, _)), _) => Some(invalid),
        (None, _) => static_challenge,
    };
    (status, challenge)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_follows_rfc_6750() {
        let cases = [
            (TokenRejection::Missing, 401),
            (TokenRejection::Invalid("x".into()), 401),
            (TokenRejection::InsufficientScope, 403),
        ];
        for (rejection, status) in cases {
            assert_eq!(refusal(&rejection, None).status, status, "{rejection:?}");
        }
    }

    #[test]
    fn a_static_challenge_that_is_not_a_header_value_falls_back_to_the_default() {
        for bad in [
            "Bearer realm=\"x\"\r\nSet-Cookie: a=b",
            "Bearer\nx",
            "Bearer \u{7f}",
            "Bearer réalm",
        ] {
            assert_eq!(
                refusal_with_static_challenge(&TokenRejection::Missing, None, Some(bad))
                    .www_authenticate
                    .as_deref(),
                Some(DEFAULT_STATIC_CHALLENGE),
                "{bad:?}"
            );
        }
        // SP and HTAB are allowed.
        assert_eq!(
            refusal_with_static_challenge(&TokenRejection::Missing, None, Some("A\tb c"))
                .www_authenticate
                .as_deref(),
            Some("A\tb c")
        );
    }

    #[test]
    fn a_validator_whose_challenge_is_not_a_header_value_builds_with_fallbacks() {
        let rejections = [
            TokenRejection::Missing,
            TokenRejection::Invalid("x".into()),
            TokenRejection::InsufficientScope,
        ];
        // A CR/LF in `resource`: the validator still builds, and every
        // refusal carries a valid fallback (the scopes are fine, so kept).
        let mut cfg = crate::testing::resolved_config("http://127.0.0.1:1/jwks");
        cfg.resource = "https://api.example.test/v1\r\nX-Injected: 1".into();
        let v = OAuthValidator::new(&cfg).expect("a hand-edited config still builds");
        assert!(v.challenge_fell_back());
        let got: Vec<_> = rejections
            .iter()
            .map(|r| refusal(r, Some(&v)).www_authenticate.unwrap())
            .collect();
        assert_eq!(
            got,
            [
                "Bearer error=\"invalid_token\", scope=\"mcp:read mcp:write\"",
                "Bearer error=\"invalid_token\", scope=\"mcp:read mcp:write\"",
                "Bearer error=\"insufficient_scope\", scope=\"mcp:read\"",
            ]
        );
        // An invalid scope: the fallback drops the attribute it cannot send.
        let mut cfg = crate::testing::resolved_config("http://127.0.0.1:1/jwks");
        cfg.scopes_supported = vec!["read\u{0}".into()];
        let v = OAuthValidator::new(&cfg).unwrap();
        assert_eq!(
            refusal(&TokenRejection::Missing, Some(&v))
                .www_authenticate
                .unwrap(),
            "Bearer error=\"invalid_token\""
        );
        // The fixture itself does not fall back, and its challenges are valid.
        let v = OAuthValidator::new(&crate::testing::resolved_config("http://127.0.0.1:1/jwks"))
            .unwrap();
        assert!(!v.challenge_fell_back());
        for rejection in &rejections {
            let challenge = refusal(rejection, Some(&v)).www_authenticate.unwrap();
            assert!(is_header_value(&challenge), "{challenge}");
            assert!(challenge.contains("resource_metadata="), "{challenge}");
        }
    }

    #[test]
    fn refusal_for_scopes_differs_from_refusal_only_in_the_403_challenge() {
        let v = OAuthValidator::new(&crate::testing::resolved_config("http://127.0.0.1:1/jwks"))
            .unwrap();
        for rejection in [TokenRejection::Missing, TokenRejection::Invalid("x".into())] {
            assert_eq!(
                refusal_for_scopes(&rejection, Some(&v), &["mcp:write"], Some("d")),
                refusal(&rejection, Some(&v))
            );
            assert_eq!(
                refusal_for_scopes(&rejection, None, &["mcp:write"], None),
                refusal(&rejection, None)
            );
        }
        let r = refusal_for_scopes(
            &TokenRejection::InsufficientScope,
            Some(&v),
            &["mcp:write", "mcp:read"],
            Some("write needed"),
        );
        assert_eq!(r.status, 403);
        // The validator's floor first, then the request's own, once each.
        assert_eq!(
            r.www_authenticate.as_deref(),
            Some(
                "Bearer error=\"insufficient_scope\", scope=\"mcp:read mcp:write\", \
                 resource_metadata=\"https://kb.example.test/.well-known/oauth-protected-resource/mcp\", \
                 error_description=\"write needed\""
            )
        );
        // No extra scopes: exactly `refusal()`'s 403.
        assert_eq!(
            refusal_for_scopes(&TokenRejection::InsufficientScope, Some(&v), &[], None),
            refusal(&TokenRejection::InsufficientScope, Some(&v))
        );
        // Without OAuth there is no scope challenge to send.
        assert_eq!(
            refusal_for_scopes(&TokenRejection::InsufficientScope, None, &["x"], None),
            refusal(&TokenRejection::InsufficientScope, None)
        );
    }

    #[test]
    fn static_challenge_is_the_default_unless_overridden() {
        for rejection in [
            TokenRejection::Missing,
            TokenRejection::Invalid("x".into()),
            TokenRejection::InsufficientScope,
        ] {
            assert_eq!(
                refusal(&rejection, None).www_authenticate.as_deref(),
                Some(DEFAULT_STATIC_CHALLENGE)
            );
            assert_eq!(
                refusal_with_static_challenge(&rejection, None, Some("Custom x"))
                    .www_authenticate
                    .as_deref(),
                Some("Custom x")
            );
            assert_eq!(
                refusal_with_static_challenge(&rejection, None, None).www_authenticate,
                None
            );
        }
    }
}
