//! Which JWS algorithms may ever verify a token, and which ones each key may.
//!
//! Two independent gates: the configured allowlist ([`parse_algorithm`] refuses
//! HMAC and `none` outright, and [`Algorithm`] has no variant for either, so no
//! config can turn them on), and the key a token names, whose own type bounds
//! the algorithms it can verify ([`key_algorithms`]). A token's `alg` must pass
//! both, which is what stops an attacker-chosen header from steering an RSA key
//! into an ECDSA verification, or any key into HMAC.

use std::fmt;

use jsonwebtoken::jwk::{AlgorithmParameters, EllipticCurve, KeyAlgorithm};

/// Default [`crate::OAuthConfig::algorithms`]: every asymmetric JWS algorithm
/// this crate can verify. Deliberately wide — which algorithm a token may use is
/// ALSO constrained by the key it names, so accepting ES256 here cannot make an
/// RSA key verify an ES256 signature. HS256/384/512 and `none` are not merely
/// absent: [`parse_algorithm`] refuses them, so no config can turn them on.
/// ES512 is absent because the underlying `ring` cannot verify P-521.
pub const DEFAULT_ALGORITHMS: &[&str] = &[
    "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "EdDSA",
];

/// A JWS signature algorithm this crate can verify an access token with.
///
/// Crate-owned rather than a re-export of the JWT library's type, so replacing
/// that library is not a breaking change here. It has no variant for HMAC
/// (`HS256`/`HS384`/`HS512`) or for `none`: a resource server must never verify
/// with a shared secret, and a [`crate::ResolvedOAuthConfig`] whose
/// `algorithms` names one cannot be written down.
///
/// `Display` (and [`Algorithm::as_str`]) give the JWS name; `Debug` prints the
/// same name. `#[non_exhaustive]`: an algorithm may be added in a minor
/// release.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[allow(clippy::upper_case_acronyms)]
pub enum Algorithm {
    /// RSASSA-PKCS1-v1_5 with SHA-256.
    RS256,
    /// RSASSA-PKCS1-v1_5 with SHA-384.
    RS384,
    /// RSASSA-PKCS1-v1_5 with SHA-512.
    RS512,
    /// RSASSA-PSS with SHA-256.
    PS256,
    /// RSASSA-PSS with SHA-384.
    PS384,
    /// RSASSA-PSS with SHA-512.
    PS512,
    /// ECDSA on P-256 with SHA-256.
    ES256,
    /// ECDSA on P-384 with SHA-384.
    ES384,
    /// EdDSA (Ed25519).
    EdDSA,
}

impl Algorithm {
    /// The JWS `alg` name, e.g. `"RS256"` or `"EdDSA"`.
    pub fn as_str(self) -> &'static str {
        match self {
            Algorithm::RS256 => "RS256",
            Algorithm::RS384 => "RS384",
            Algorithm::RS512 => "RS512",
            Algorithm::PS256 => "PS256",
            Algorithm::PS384 => "PS384",
            Algorithm::PS512 => "PS512",
            Algorithm::ES256 => "ES256",
            Algorithm::ES384 => "ES384",
            Algorithm::EdDSA => "EdDSA",
        }
    }

    /// The JWT library's equivalent, for verification.
    pub(crate) fn to_jwt(self) -> jsonwebtoken::Algorithm {
        match self {
            Algorithm::RS256 => jsonwebtoken::Algorithm::RS256,
            Algorithm::RS384 => jsonwebtoken::Algorithm::RS384,
            Algorithm::RS512 => jsonwebtoken::Algorithm::RS512,
            Algorithm::PS256 => jsonwebtoken::Algorithm::PS256,
            Algorithm::PS384 => jsonwebtoken::Algorithm::PS384,
            Algorithm::PS512 => jsonwebtoken::Algorithm::PS512,
            Algorithm::ES256 => jsonwebtoken::Algorithm::ES256,
            Algorithm::ES384 => jsonwebtoken::Algorithm::ES384,
            Algorithm::EdDSA => jsonwebtoken::Algorithm::EdDSA,
        }
    }

    /// The crate's equivalent of a JWT library algorithm; `None` for HMAC, which
    /// this crate never verifies.
    pub(crate) fn from_jwt(alg: jsonwebtoken::Algorithm) -> Option<Self> {
        Some(match alg {
            jsonwebtoken::Algorithm::RS256 => Algorithm::RS256,
            jsonwebtoken::Algorithm::RS384 => Algorithm::RS384,
            jsonwebtoken::Algorithm::RS512 => Algorithm::RS512,
            jsonwebtoken::Algorithm::PS256 => Algorithm::PS256,
            jsonwebtoken::Algorithm::PS384 => Algorithm::PS384,
            jsonwebtoken::Algorithm::PS512 => Algorithm::PS512,
            jsonwebtoken::Algorithm::ES256 => Algorithm::ES256,
            jsonwebtoken::Algorithm::ES384 => Algorithm::ES384,
            jsonwebtoken::Algorithm::EdDSA => Algorithm::EdDSA,
            _ => return None,
        })
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why [`parse_algorithm`] refused a name.
///
/// `Display` spells out the reason, quoting the refused value; it is what
/// [`crate::OAuthConfig::resolve`] puts in its problem list.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AlgorithmError {
    /// `none`, in any case: an unsigned token.
    #[error("\"{name}\" — an unsigned token is never acceptable")]
    #[non_exhaustive]
    Unsigned {
        /// The refused value, trimmed.
        name: String,
    },
    /// `HS256`, `HS384` or `HS512`: verification with a shared secret.
    #[error(
        "\"{name}\" — HMAC algorithms verify with a shared secret, which a resource \
         server must never hold, and accepting one alongside a public key set is the \
         classic key-confusion attack (a token signed with the PUBLIC key as the HMAC \
         secret)"
    )]
    #[non_exhaustive]
    Hmac {
        /// The refused value, trimmed.
        name: String,
    },
    /// Anything else that is not a JWS algorithm this crate can verify
    /// (including `ES512`, which the underlying `ring` cannot, and a name in
    /// the wrong case).
    #[error("\"{name}\" — not a JWS algorithm this server can verify (supported: {supported})")]
    #[non_exhaustive]
    Unsupported {
        /// The refused value, trimmed.
        name: String,
        /// [`DEFAULT_ALGORITHMS`], comma-separated.
        supported: String,
    },
}

/// Parse one [`crate::OAuthConfig::algorithms`] entry, refusing everything that
/// must never be accepted with the reason spelled out (the error lands in a
/// startup failure). [`crate::OAuthConfig::resolve`] calls it for every entry;
/// it is public for applications that validate an algorithm list themselves.
///
/// Names are JWS names, matched case-sensitively after trimming.
///
/// # Errors
///
/// [`AlgorithmError::Unsigned`] for `none` (in any case),
/// [`AlgorithmError::Hmac`] for `HS256`/`HS384`/`HS512`, and
/// [`AlgorithmError::Unsupported`] for anything else that is not a JWS
/// algorithm this crate can verify (including `ES512`, which the underlying
/// `ring` cannot).
///
/// # Examples
///
/// ```
/// use oauth_resource_server::{Algorithm, AlgorithmError, parse_algorithm};
///
/// assert_eq!(parse_algorithm("ES256"), Ok(Algorithm::ES256));
/// let err = parse_algorithm("HS256").unwrap_err();
/// assert!(matches!(err, AlgorithmError::Hmac { .. }));
/// assert!(err.to_string().contains("key-confusion"));
/// assert!(matches!(parse_algorithm("none"), Err(AlgorithmError::Unsigned { .. })));
/// ```
pub fn parse_algorithm(name: &str) -> Result<Algorithm, AlgorithmError> {
    let name = name.trim();
    if name.eq_ignore_ascii_case("none") {
        return Err(AlgorithmError::Unsigned {
            name: name.to_string(),
        });
    }
    match name.parse::<jsonwebtoken::Algorithm>() {
        Ok(
            jsonwebtoken::Algorithm::HS256
            | jsonwebtoken::Algorithm::HS384
            | jsonwebtoken::Algorithm::HS512,
        ) => Err(AlgorithmError::Hmac {
            name: name.to_string(),
        }),
        Ok(alg) => Algorithm::from_jwt(alg).ok_or_else(|| unsupported(name)),
        Err(_) => Err(unsupported(name)),
    }
}

fn unsupported(name: &str) -> AlgorithmError {
    AlgorithmError::Unsupported {
        name: name.to_string(),
        supported: DEFAULT_ALGORITHMS.join(", "),
    }
}

/// The signature algorithms a key of this type can produce. `None` for a key that
/// can never verify an access token here: symmetric (`oct`) keys above all — a
/// shared secret has no business in a public key set, and honouring one would
/// re-open the HMAC confusion that [`parse_algorithm`] closes — plus curves `ring`
/// cannot verify (P-521) and non-signature curves (X25519).
pub(crate) fn key_algorithms(params: &AlgorithmParameters) -> Option<Vec<Algorithm>> {
    use Algorithm::*;
    match params {
        AlgorithmParameters::RSA(_) => Some(vec![RS256, RS384, RS512, PS256, PS384, PS512]),
        AlgorithmParameters::EllipticCurve(p) => match p.curve {
            EllipticCurve::P256 => Some(vec![ES256]),
            EllipticCurve::P384 => Some(vec![ES384]),
            _ => None,
        },
        AlgorithmParameters::OctetKeyPair(p) => match p.curve {
            EllipticCurve::Ed25519 => Some(vec![EdDSA]),
            _ => None,
        },
        AlgorithmParameters::OctetKey(_) => None,
    }
}

/// A JWK `alg` as a JWS signature algorithm; `None` for HMAC and for key-management
/// (encryption) algorithms, neither of which may verify an access token.
pub(crate) fn signing_algorithm(alg: &KeyAlgorithm) -> Option<Algorithm> {
    Some(match alg {
        KeyAlgorithm::RS256 => Algorithm::RS256,
        KeyAlgorithm::RS384 => Algorithm::RS384,
        KeyAlgorithm::RS512 => Algorithm::RS512,
        KeyAlgorithm::PS256 => Algorithm::PS256,
        KeyAlgorithm::PS384 => Algorithm::PS384,
        KeyAlgorithm::PS512 => Algorithm::PS512,
        KeyAlgorithm::ES256 => Algorithm::ES256,
        KeyAlgorithm::ES384 => Algorithm::ES384,
        KeyAlgorithm::EdDSA => Algorithm::EdDSA,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_and_none_can_never_be_configured() {
        for bad in [
            "HS256", "HS384", "HS512", "none", "None", "ES512", "rs256", "",
        ] {
            assert!(parse_algorithm(bad).is_err(), "{bad:?} must be refused");
        }
        assert!(
            parse_algorithm("HS256")
                .unwrap_err()
                .to_string()
                .contains("key-confusion")
        );
        for good in DEFAULT_ALGORITHMS {
            let alg = parse_algorithm(good).expect("every default parses");
            assert_eq!(alg.as_str(), *good);
            assert_eq!(alg.to_string(), *good);
            assert_eq!(format!("{alg:?}"), *good);
            assert_eq!(Algorithm::from_jwt(alg.to_jwt()), Some(alg));
        }
    }

    #[test]
    fn refusals_are_typed_and_keep_their_text() {
        assert_eq!(
            parse_algorithm(" none "),
            Err(AlgorithmError::Unsigned {
                name: "none".into()
            })
        );
        assert_eq!(
            parse_algorithm("none").unwrap_err().to_string(),
            "\"none\" — an unsigned token is never acceptable"
        );
        assert!(matches!(
            parse_algorithm("HS384"),
            Err(AlgorithmError::Hmac { .. })
        ));
        let err = parse_algorithm("ES512").unwrap_err();
        assert!(matches!(err, AlgorithmError::Unsupported { .. }));
        assert_eq!(
            err.to_string(),
            "\"ES512\" — not a JWS algorithm this server can verify (supported: RS256, RS384, \
             RS512, PS256, PS384, PS512, ES256, ES384, EdDSA)"
        );
        // A std error, so `?` into `Box<dyn Error>` works.
        let _: Box<dyn std::error::Error + Send + Sync> = Box::new(err);
    }

    #[test]
    fn hmac_has_no_crate_algorithm() {
        for hmac in [
            jsonwebtoken::Algorithm::HS256,
            jsonwebtoken::Algorithm::HS384,
            jsonwebtoken::Algorithm::HS512,
        ] {
            assert_eq!(Algorithm::from_jwt(hmac), None);
        }
    }
}
