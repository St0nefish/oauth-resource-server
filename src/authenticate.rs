//! Transport-agnostic credential checking: static tokens and/or OAuth, over
//! every candidate credential a request carries.
//!
//! This is the framework-free core of the axum middleware (feature `axum`). An
//! application on another HTTP stack collects its candidate header values itself
//! and calls [`authenticate`] (one static token) or
//! [`authenticate_with_static_tokens`] (a [`StaticTokens`] set, reporting which
//! entry matched); the status code and challenge for a failure follow from the
//! returned [`TokenRejection`] (see its docs).

use std::fmt;

use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroizing;

use crate::token::{AuthorizedToken, InvalidToken, InvalidTokenKind, TokenRejection};
use crate::validator::{CachedAttempt, OAuthValidator};

// Counts every static-token comparison `find_static` makes, so a test can
// prove no entry is skipped once one has matched. Test builds only.
#[cfg(test)]
thread_local! {
    pub(crate) static STATIC_COMPARISONS: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
}

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
    /// A candidate matched a configured static token. Which one, when several
    /// are configured, is reported separately as a [`StaticTokenMatch`]: by
    /// [`authenticate_with_static_tokens`], and in request extensions by the
    /// layers.
    StaticToken,
    /// A candidate validated as an OAuth access token carrying every required
    /// scope.
    OAuth(AuthorizedToken),
}

/// A set of static API keys, each with an optional label: several keys
/// accepted at once, for rotating a key with no downtime (the old and the new
/// one both accepted until every client has moved) or for one key per client.
///
/// Opaque: nothing reads a secret back out of it. Build it with
/// [`StaticTokens::single`] or [`StaticTokens::new`] and
/// [`StaticTokens::with`]; hand it to [`authenticate_with_static_tokens`], or
/// to a layer's `static_tokens` builder method (features `axum`/`tower`). The
/// `env` feature's `static_tokens_from_env` loads a current and a next key.
///
/// # Rules
///
/// Checked by [`StaticTokens::with`], which refuses (never silently fixes) an
/// entry that breaks one:
///
/// - A secret must not be empty or whitespace-only
///   ([`StaticTokensError::BlankSecret`]). It is otherwise kept verbatim,
///   untrimmed, like the single `static_token` everywhere else.
/// - A secret must not repeat one already in the set
///   ([`StaticTokensError::DuplicateSecret`]): two entries holding one secret
///   would make the reported label depend on insertion order, and for
///   per-client keys means two clients share a key, so it is refused rather
///   than deduplicated.
/// - A label is 1 to [`StaticTokens::MAX_LABEL_LEN`] (64) visible ASCII
///   characters, `!` through `~` — no space, no control character, nothing
///   else ([`StaticTokensError::InvalidLabel`]) — so it is always safe to put
///   in a log line or a metric. Labels are not secrets.
/// - A label must not repeat one already in the set
///   ([`StaticTokensError::DuplicateLabel`]); any number of entries may be
///   unlabeled.
///
/// # Security
///
/// Comparison is constant-time across entries: every candidate is compared
/// with every entry, with no early exit once one matches, and the matching
/// index is selected without a data-dependent branch (`subtle`). What is not
/// hidden is length: each single comparison returns faster when the
/// candidate's length differs from that entry's, exactly as the single-token
/// comparison always has, so the total time depends on how many entries share
/// the candidate's length (never on which entry matched, apart from cloning
/// the matched label after the comparison, observable only by a holder of a
/// valid key). Use high-entropy keys of one fixed length, and the length
/// reveals nothing useful.
///
/// `Debug` prints the number of entries and their labels, never a secret. No
/// `PartialEq`: comparing two sets would compare secrets in variable time.
/// Each secret is held in a `zeroize::Zeroizing` buffer, wiped when the
/// set (or a clone of it) is dropped; so are the layer builders' single
/// `static_token`, and the `env` loaders' intermediate copies (untrimmed
/// values, a next key equal to the current one). What is *not* wiped: the
/// strings a caller passes in or keeps (`with`'s argument before it is
/// moved in, `secret_from_env`'s returned `String`), a
/// [`StaticTokenDecision`](crate::StaticTokenDecision)'s `String` payload,
/// the process environment, and a secrets file. A `String`'s earlier
/// buffers, left behind if it was grown before being handed over, are not
/// wiped either.
///
/// # Examples
///
/// ```
/// use oauth_resource_server::{StaticTokens, StaticTokensError};
///
/// # fn main() -> Result<(), StaticTokensError> {
/// // Rotation: the current key and the one replacing it.
/// let tokens = StaticTokens::new()
///     .with(Some("current"), "example-key-2024")?
///     .with(Some("next"), "example-key-2025")?;
/// assert_eq!(tokens.len(), 2);
/// assert!(!format!("{tokens:?}").contains("example-key"));
///
/// // Blank secrets and repeated secrets are refused.
/// assert!(matches!(
///     StaticTokens::single("  "),
///     Err(StaticTokensError::BlankSecret { .. })
/// ));
/// assert!(matches!(
///     tokens.with(None, "example-key-2025"),
///     Err(StaticTokensError::DuplicateSecret { .. })
/// ));
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Default)]
pub struct StaticTokens {
    entries: Vec<StaticEntry>,
}

#[derive(Clone)]
struct StaticEntry {
    label: Option<String>,
    secret: Zeroizing<String>,
}

/// Why [`StaticTokens::with`] (or [`StaticTokens::single`]) refused an entry.
/// Each variant names the entry by its 0-based position in the set, and never
/// includes a secret.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum StaticTokensError {
    /// The secret was empty or whitespace-only; a blank secret must never be
    /// matchable.
    #[error("the static token at position {index} is empty or blank")]
    #[non_exhaustive]
    BlankSecret {
        /// The refused entry's position.
        index: usize,
    },
    /// The secret is already in the set, at position `first`.
    #[error("the static token at position {index} repeats the one at position {first}")]
    #[non_exhaustive]
    DuplicateSecret {
        /// The refused entry's position.
        index: usize,
        /// The position of the entry holding the same secret.
        first: usize,
    },
    /// The label is empty, longer than [`StaticTokens::MAX_LABEL_LEN`], or
    /// holds a character outside visible ASCII (`!` through `~`). The label
    /// itself is not echoed, since it failed the rules that make it log-safe.
    #[error(
        "the label of the static token at position {index} must be 1 to 64 visible ASCII \
         characters (no spaces)"
    )]
    #[non_exhaustive]
    InvalidLabel {
        /// The refused entry's position.
        index: usize,
    },
    /// The label is already used by the entry at position `first`.
    #[error(
        "the label {label:?} of the static token at position {index} is already used at \
         position {first}"
    )]
    #[non_exhaustive]
    DuplicateLabel {
        /// The refused entry's position.
        index: usize,
        /// The position of the entry with the same label.
        first: usize,
        /// The repeated label (valid, so log-safe).
        label: String,
    },
}

impl StaticTokens {
    /// The longest label [`StaticTokens::with`] accepts, in bytes (every
    /// accepted character is one byte).
    pub const MAX_LABEL_LEN: usize = 64;

    /// An empty set. Add entries with [`StaticTokens::with`]. An empty set
    /// accepts nothing and, handed to a layer, does not count as a credential
    /// mechanism.
    pub fn new() -> Self {
        Self::default()
    }

    /// A set holding one unlabeled secret: the same credential a single
    /// `static_token` configures.
    ///
    /// # Errors
    ///
    /// [`StaticTokensError::BlankSecret`] for an empty or whitespace-only
    /// secret.
    pub fn single(secret: impl Into<String>) -> Result<Self, StaticTokensError> {
        Self::new().with(None, secret)
    }

    /// This set plus one more secret, optionally labeled (see the
    /// [rules](StaticTokens#rules)).
    ///
    /// # Errors
    ///
    /// [`StaticTokensError::BlankSecret`], [`StaticTokensError::InvalidLabel`],
    /// [`StaticTokensError::DuplicateLabel`] or
    /// [`StaticTokensError::DuplicateSecret`], checked in that order. The set
    /// is consumed either way; on an error its secrets are wiped with it.
    pub fn with(
        mut self,
        label: Option<&str>,
        secret: impl Into<String>,
    ) -> Result<Self, StaticTokensError> {
        let secret = Zeroizing::new(secret.into());
        let index = self.entries.len();
        if secret.trim().is_empty() {
            return Err(StaticTokensError::BlankSecret { index });
        }
        if let Some(label) = label {
            if !is_log_safe_label(label) {
                return Err(StaticTokensError::InvalidLabel { index });
            }
            if let Some(first) = self
                .entries
                .iter()
                .position(|e| e.label.as_deref() == Some(label))
            {
                return Err(StaticTokensError::DuplicateLabel {
                    index,
                    first,
                    label: label.to_string(),
                });
            }
        }
        if let Some(first) = self.position_of(&secret) {
            return Err(StaticTokensError::DuplicateSecret { index, first });
        }
        self.entries.push(StaticEntry {
            label: label.map(str::to_string),
            secret,
        });
        Ok(self)
    }

    /// How many secrets the set holds.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the set holds none.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Every entry's label, in insertion order (`None` for an unlabeled
    /// one) — for a startup log line saying which keys are accepted.
    pub fn labels(&self) -> impl Iterator<Item = Option<&str>> {
        self.entries.iter().map(|e| e.label.as_deref())
    }

    /// `set` plus `token` (a single `static_token` setting), as one set.
    /// `token` is added as an unlabeled entry unless it is empty (not
    /// configured) or an entry already holds it, in which case that entry
    /// (and its label) stands for both. Unlike [`StaticTokens::with`], a
    /// whitespace-only `token` is kept, exactly as the single-token API always
    /// has: configured, and never matched (blank candidates are discarded
    /// before any comparison). `None` when the result is empty.
    #[cfg(feature = "tower")]
    pub(crate) fn merged(set: Option<Self>, token: Option<Zeroizing<String>>) -> Option<Self> {
        let mut merged = set.unwrap_or_default();
        // A `token` that is empty or already in the set is dropped here,
        // wiped by its `Zeroizing`.
        if let Some(token) = token.filter(|t| !t.is_empty())
            && merged.position_of(&token).is_none()
        {
            merged.entries.push(StaticEntry {
                label: None,
                secret: token,
            });
        }
        (!merged.is_empty()).then_some(merged)
    }

    /// Add an entry the caller has already checked against every rule
    /// (non-blank, valid unique label, secret not in the set).
    #[cfg(feature = "env")]
    pub(crate) fn push_checked(&mut self, label: &str, secret: Zeroizing<String>) {
        debug_assert!(is_log_safe_label(label) && !secret.trim().is_empty());
        self.entries.push(StaticEntry {
            label: Some(label.to_string()),
            secret,
        });
    }

    /// Whether `secret` is already in the set (compared in constant time).
    #[cfg(feature = "env")]
    pub(crate) fn contains(&self, secret: &str) -> bool {
        self.position_of(secret).is_some()
    }

    /// The position of the entry holding `secret`, compared in constant time
    /// (startup-only: used to refuse or merge a repeated secret).
    fn position_of(&self, secret: &str) -> Option<usize> {
        let secrets: Vec<&str> = self.secrets();
        find_static(&[secret], &secrets)
    }

    fn secrets(&self) -> Vec<&str> {
        self.entries.iter().map(|e| e.secret.as_str()).collect()
    }

    fn match_at(&self, index: usize) -> StaticTokenMatch {
        StaticTokenMatch {
            label: self.entries.get(index).and_then(|e| e.label.clone()),
        }
    }
}

/// Hand-written so no secret ever reaches a log line through `{:?}`: the
/// count and the labels (log-safe by construction), never a secret.
impl fmt::Debug for StaticTokens {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StaticTokens")
            .field("len", &self.entries.len())
            .field("labels", &self.labels().collect::<Vec<_>>())
            .field("secrets", &"<redacted>")
            .finish()
    }
}

/// 1 to [`StaticTokens::MAX_LABEL_LEN`] visible ASCII characters.
fn is_log_safe_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= StaticTokens::MAX_LABEL_LEN
        && label.bytes().all(|b| b.is_ascii_graphic())
}

/// Which [`StaticTokens`] entry accepted a request: returned by
/// [`authenticate_with_static_tokens`] next to [`Credential::StaticToken`],
/// and inserted into request extensions by the layers (features `axum` and
/// `tower`) whenever they insert [`Credential::StaticToken`] — with the
/// `axum` feature it is also an extractor. It carries the entry's label only;
/// nothing in it exposes the secret.
///
/// A layer configured with a single `static_token` inserts one too, with no
/// label.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct StaticTokenMatch {
    label: Option<String>,
}

impl StaticTokenMatch {
    /// The matched entry's label, as given to [`StaticTokens::with`]; `None`
    /// for an unlabeled entry.
    pub fn label(&self) -> Option<&str> {
        self.label.as_deref()
    }

    /// The match for an unlabeled entry.
    #[cfg(feature = "tower")]
    pub(crate) fn unlabeled() -> Self {
        Self { label: None }
    }
}

/// `subtle`'s constant-time equality of two strings' bytes: the one place a
/// static token is compared, so the test-only `STATIC_COMPARISONS` counter
/// counts actual comparisons, not loop iterations.
fn counted_ct_eq(candidate: &str, secret: &str) -> Choice {
    #[cfg(test)]
    STATIC_COMPARISONS.with(|n| n.set(n.get() + 1));
    candidate.as_bytes().ct_eq(secret.as_bytes())
}

/// The position of the first entry of `secrets` any candidate equals — the
/// first matching candidate's, in `candidates` order — compared in constant
/// time: every candidate against every entry, no early exit, and the index
/// chosen by `conditional_assign`, never a branch on a comparison. The one
/// static-token comparison in the crate; see [`StaticTokens`]' "Security"
/// for what its timing does and does not reveal.
fn find_static(candidates: &[&str], secrets: &[&str]) -> Option<usize> {
    let mut found = Choice::from(0);
    let mut index: u64 = 0;
    // This loop must stay branch-free on secret-derived values (`equal`,
    // `found`): no `if`, no `break`, no skipping a comparison once one has
    // matched. `counted_ct_eq` is the only comparison, so the test-only
    // counter catches a skipped comparison. Replacing `conditional_assign`
    // with an `if` would change timing only, which no functional test can
    // observe; that property rests on review, not on a test.
    for candidate in candidates {
        for (i, secret) in (0u64..).zip(secrets) {
            let equal = counted_ct_eq(candidate, secret);
            index.conditional_assign(&i, equal & !found);
            found |= equal;
        }
    }
    if bool::from(found) {
        usize::try_from(index).ok()
    } else {
        None
    }
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
/// (`subtle`; the lengths are not hidden — see [`StaticTokens`]' "Security",
/// the same comparison over a one-entry set). A match is decisive and needs no
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
///   [`InvalidToken`] — the validator's, when OAuth is configured, kind
///   included; without OAuth, [`InvalidTokenKind::StaticTokenMismatch`] (or
///   [`InvalidTokenKind::NoMechanism`] with nothing configured). Its detail
///   is for logs only; never send it to the caller.
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
/// To accept several static tokens (key rotation, one key per client) and
/// learn which one matched, use [`authenticate_with_static_tokens`]: this
/// function is that one over a one-entry set, the same code.
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
    // A one-entry set, borrowed rather than copied into a `StaticTokens`: the
    // secret is not duplicated on the heap for every request.
    let one: [&str; 1];
    let secrets: &[&str] = match static_token.filter(|t| !t.is_empty()) {
        Some(token) => {
            one = [token];
            &one
        }
        None => &[],
    };
    check_candidates(candidates, secrets, oauth)
        .await
        .map(|(credential, _)| credential)
}

/// [`authenticate`] against a set of static tokens, reporting which one
/// matched: the same candidate handling, order and refusal precedence, over
/// every entry of `static_tokens` instead of one token.
///
/// On a static match the result is `(Credential::StaticToken,
/// Some(StaticTokenMatch))`, the match naming the entry's label; on an OAuth
/// match, `(Credential::OAuth(..), None)`. If several candidates match
/// entries, the first matching candidate (in `candidates` order) decides the
/// reported entry. `static_tokens` of `None` or an empty set means no static
/// token is configured.
///
/// [`authenticate`] is this function over a one-entry set — one
/// implementation — so a one-entry [`StaticTokens`] behaves exactly as
/// `authenticate` with that token, down to the refusal reason.
///
/// # Errors
///
/// As [`authenticate`]. With more than one entry, an unmatched candidate's
/// reason (static-only) reads "credential does not match any static token".
///
/// # Panics
///
/// As [`authenticate`]: outside a Tokio 1.x runtime, only when an OAuth
/// candidate's signing key has to be fetched.
///
/// # Security
///
/// Every candidate is compared with every entry in constant time, with no
/// early exit once one matches; lengths are not hidden. See [`StaticTokens`].
///
/// # Examples
///
/// ```
/// use oauth_resource_server::{
///     Credential, StaticTokens, TokenRejection, authenticate_with_static_tokens,
/// };
///
/// # #[tokio::main(flavor = "current_thread")]
/// # async fn main() {
/// let tokens = StaticTokens::new()
///     .with(Some("current"), "example-key-old")
///     .and_then(|t| t.with(Some("next"), "example-key-new"))
///     .unwrap();
///
/// let (credential, matched) =
///     authenticate_with_static_tokens(["example-key-new"], Some(&tokens), None)
///         .await
///         .unwrap();
/// assert_eq!(credential, Credential::StaticToken);
/// assert_eq!(matched.unwrap().label(), Some("next"));
///
/// assert!(matches!(
///     authenticate_with_static_tokens(["guess"], Some(&tokens), None).await,
///     Err(TokenRejection::Invalid(_))
/// ));
/// # }
/// ```
pub async fn authenticate_with_static_tokens<'a>(
    candidates: impl IntoIterator<Item = &'a str>,
    static_tokens: Option<&StaticTokens>,
    oauth: Option<&OAuthValidator>,
) -> Result<(Credential, Option<StaticTokenMatch>), TokenRejection> {
    let secrets = static_tokens.map(StaticTokens::secrets).unwrap_or_default();
    let (credential, index) = check_candidates(candidates, &secrets, oauth).await?;
    let matched = index.zip(static_tokens).map(|(i, set)| set.match_at(i));
    Ok((credential, matched))
}

/// The one implementation behind [`authenticate`] and
/// [`authenticate_with_static_tokens`]; on a static match, also the position
/// of the matching entry of `secrets`.
async fn check_candidates<'a>(
    candidates: impl IntoIterator<Item = &'a str>,
    secrets: &[&str],
    oauth: Option<&OAuthValidator>,
) -> Result<(Credential, Option<usize>), TokenRejection> {
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

    if let Some(index) = find_static(&candidates, secrets) {
        return Ok((Credential::StaticToken, Some(index)));
    }

    let Some(validator) = oauth else {
        return Err(match secrets.len() {
            0 => TokenRejection::invalid(
                InvalidTokenKind::NoMechanism,
                "no credential mechanism is configured",
            ),
            1 => TokenRejection::invalid(
                InvalidTokenKind::StaticTokenMismatch,
                "credential does not match the static token",
            ),
            _ => TokenRejection::invalid(
                InvalidTokenKind::StaticTokenMismatch,
                "credential does not match any static token",
            ),
        });
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
            CachedAttempt::Decided(Ok(token)) => return Ok((Credential::OAuth(token), None)),
            CachedAttempt::Decided(Err(rejection)) => refusals.push(Some(rejection)),
            CachedAttempt::NeedsKeyFetch => refusals.push(None),
        }
    }
    for (candidate, refusal) in candidates.iter().zip(refusals.iter_mut()) {
        if refusal.is_none() {
            match validator.validate(candidate).await {
                Ok(token) => return Ok((Credential::OAuth(token), None)),
                Err(rejection) => *refusal = Some(rejection),
            }
        }
    }

    let mut insufficient_scope = false;
    let mut first_reason: Option<InvalidToken> = None;
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
                first_reason.get_or_insert_with(|| {
                    InvalidToken::new(InvalidTokenKind::Other, "no credential presented")
                });
            }
        }
    }
    if insufficient_scope {
        return Err(TokenRejection::InsufficientScope);
    }
    // Unreachable in practice (every non-blank candidate left a refusal),
    // and still a refusal, never an acceptance.
    Err(TokenRejection::Invalid(first_reason.unwrap_or_else(|| {
        InvalidToken::new(
            InvalidTokenKind::Other,
            "no candidate credential was accepted",
        )
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
        crate::token::assert_invalid(
            authenticate(["x"], Some(""), None).await,
            InvalidTokenKind::NoMechanism,
            "no credential mechanism is configured",
            "",
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
        crate::token::assert_invalid(
            authenticate([token.as_str()], Some(STATIC), None).await,
            InvalidTokenKind::StaticTokenMismatch,
            "credential does not match the static token",
            "",
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
        crate::token::assert_invalid(
            authenticate([STATIC], None, None).await,
            InvalidTokenKind::NoMechanism,
            "no credential mechanism is configured",
            "",
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

    // ── StaticTokens / authenticate_with_static_tokens ──────────────────────

    fn rotation() -> StaticTokens {
        StaticTokens::new()
            .with(Some("current"), "key-current")
            .and_then(|t| t.with(Some("next"), "key-next"))
            .and_then(|t| t.with(None, "key-unlabeled"))
            .unwrap()
    }

    fn label_of(
        result: Result<(Credential, Option<StaticTokenMatch>), TokenRejection>,
    ) -> Option<String> {
        match result {
            Ok((Credential::StaticToken, Some(m))) => m.label().map(str::to_string),
            other => panic!("expected a static match, got {other:?}"),
        }
    }

    /// A one-entry set and `authenticate` with the same token give the same
    /// outcome — credential, refusal and refusal reason — for every shape of
    /// request, with and without OAuth.
    #[tokio::test]
    async fn a_one_entry_set_is_identical_to_the_single_token() {
        let (_jwks, live) = live_validator().await;
        let valid = testing::valid_token();
        let unscoped = unscoped_token();
        let expired = expired_token();
        let single = StaticTokens::single(STATIC).unwrap();
        let candidate_sets: Vec<Vec<&str>> = vec![
            vec![],
            vec!["", " "],
            vec![STATIC],
            vec!["wrong"],
            vec!["wrong", STATIC],
            vec![valid.as_str()],
            vec![unscoped.as_str()],
            vec![expired.as_str(), "garbage"],
            vec!["static-secret "],
        ];
        for oauth in [None, Some(&*live)] {
            for candidates in &candidate_sets {
                let old = authenticate(candidates.iter().copied(), Some(STATIC), oauth).await;
                let new = authenticate_with_static_tokens(
                    candidates.iter().copied(),
                    Some(&single),
                    oauth,
                )
                .await;
                match (&old, &new) {
                    (Ok(Credential::StaticToken), Ok((Credential::StaticToken, Some(m)))) => {
                        assert_eq!(m.label(), None);
                    }
                    (Ok(Credential::OAuth(a)), Ok((Credential::OAuth(b), None))) => {
                        assert_eq!(a.subject, b.subject);
                    }
                    (Err(a), Err(b)) => assert_eq!(a, b, "{candidates:.30?}"),
                    _ => panic!("{candidates:.30?}: {old:?} vs {new:?}"),
                }
            }
        }
        // No set, and an empty set, are "no static token", as `None` is.
        for set in [None, Some(&StaticTokens::new())] {
            crate::token::assert_invalid(
                authenticate_with_static_tokens(["x"], set, None).await,
                InvalidTokenKind::NoMechanism,
                "no credential mechanism is configured",
                "",
            );
        }
    }

    #[tokio::test]
    async fn every_entry_is_accepted_and_named() {
        let set = rotation();
        let v = unreachable_validator();
        for (secret, label) in [
            ("key-current", Some("current")),
            ("key-next", Some("next")),
            ("key-unlabeled", None),
        ] {
            for oauth in [None, Some(&*v)] {
                let result = authenticate_with_static_tokens([secret], Some(&set), oauth).await;
                assert_eq!(label_of(result).as_deref(), label, "{secret}");
            }
            // Behind a junk candidate.
            let result = authenticate_with_static_tokens(["junk", secret], Some(&set), None).await;
            assert_eq!(label_of(result).as_deref(), label);
        }
        // Several matching candidates: the first one decides the label.
        let result =
            authenticate_with_static_tokens(["key-next", "key-current"], Some(&set), None).await;
        assert_eq!(label_of(result).as_deref(), Some("next"));
    }

    #[tokio::test]
    async fn a_wrong_token_is_refused() {
        let set = rotation();
        for candidate in ["key-", "key-current ", "KEY-CURRENT", "key-nextx", "other"] {
            crate::token::assert_invalid(
                authenticate_with_static_tokens([candidate], Some(&set), None).await,
                InvalidTokenKind::StaticTokenMismatch,
                "credential does not match any static token",
                candidate,
            );
        }
        assert_eq!(
            authenticate_with_static_tokens([" "], Some(&set), None).await,
            Err(TokenRejection::Missing)
        );
        // With OAuth the validator's reason wins, as with one token.
        let v = unreachable_validator();
        match authenticate_with_static_tokens(["other"], Some(&set), Some(&v)).await {
            Err(TokenRejection::Invalid(reason)) => {
                assert!(reason.starts_with("credential is not a JWT"), "{reason}");
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn a_blank_secret_is_refused_at_construction() {
        for blank in ["", " ", "\t\n", "   "] {
            assert_eq!(
                StaticTokens::single(blank).unwrap_err(),
                StaticTokensError::BlankSecret { index: 0 }
            );
        }
        assert_eq!(
            StaticTokens::single("a")
                .unwrap()
                .with(Some("x"), " ")
                .unwrap_err(),
            StaticTokensError::BlankSecret { index: 1 }
        );
    }

    #[test]
    fn duplicates_and_bad_labels_are_refused() {
        let base = || StaticTokens::single("one").unwrap();
        assert_eq!(
            base().with(Some("again"), "one").unwrap_err(),
            StaticTokensError::DuplicateSecret { index: 1, first: 0 }
        );
        let labeled = StaticTokens::new().with(Some("a"), "one").unwrap();
        assert_eq!(
            labeled.clone().with(Some("a"), "two").unwrap_err(),
            StaticTokensError::DuplicateLabel {
                index: 1,
                first: 0,
                label: "a".into()
            }
        );
        // Unlabeled entries may repeat; distinct labels are fine.
        let ok = labeled
            .with(None, "two")
            .and_then(|t| t.with(None, "three"))
            .and_then(|t| t.with(Some("b"), "four"))
            .unwrap();
        assert_eq!(ok.len(), 4);
        assert!(!ok.is_empty() && StaticTokens::new().is_empty());
        assert_eq!(
            ok.labels().collect::<Vec<_>>(),
            [Some("a"), None, None, Some("b")]
        );

        let longest = "l".repeat(StaticTokens::MAX_LABEL_LEN);
        assert!(base().with(Some(&longest), "two").is_ok());
        assert!(base().with(Some("!~"), "two").is_ok());
        let too_long = "l".repeat(StaticTokens::MAX_LABEL_LEN + 1);
        for bad in [
            "",
            "has space",
            "tab\t",
            "new\nline",
            "caf\u{e9}",
            "\u{1b}[31m",
            &too_long,
        ] {
            assert_eq!(
                base().with(Some(bad), "two").unwrap_err(),
                StaticTokensError::InvalidLabel { index: 1 },
                "{bad:?}"
            );
        }
        // No error text carries a secret.
        let err = StaticTokens::single("hunter2")
            .and_then(|t| t.with(Some("again"), "hunter2"))
            .unwrap_err();
        assert!(!err.to_string().contains("hunter2") && !format!("{err:?}").contains("hunter2"));
    }

    #[test]
    fn debug_never_prints_a_secret() {
        let set = StaticTokens::new()
            .with(Some("current"), "hunter2-current")
            .and_then(|t| t.with(None, "hunter2-other"))
            .unwrap();
        let rendered = format!("{set:?} {set:#?}");
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(rendered.contains("current") && rendered.contains("<redacted>"));
        assert!(rendered.contains("len: 2"), "{rendered}");
        let matched = StaticTokenMatch {
            label: Some("current".into()),
        };
        assert!(!format!("{matched:?}").contains("hunter2"));
    }

    fn comparisons() -> usize {
        STATIC_COMPARISONS.with(std::cell::Cell::get)
    }

    fn reset_comparisons() {
        STATIC_COMPARISONS.with(|n| n.set(0));
    }

    /// Not a timing measurement: an instrumented count proving there is no
    /// early exit — every candidate is compared with every entry, whichever
    /// entry matches, including the first.
    #[tokio::test(flavor = "current_thread")]
    async fn every_entry_is_compared_even_when_the_first_matches() {
        let set = rotation();
        for (candidates, matched) in [
            (vec!["key-current"], Some(Some("current"))),
            (vec!["key-unlabeled"], Some(None)),
            (vec!["nothing"], None),
            (vec!["key-current", "junk"], Some(Some("current"))),
            (vec!["junk", "key-next"], Some(Some("next"))),
        ] {
            reset_comparisons();
            let result =
                authenticate_with_static_tokens(candidates.iter().copied(), Some(&set), None).await;
            assert_eq!(
                comparisons(),
                candidates.len() * set.len(),
                "{candidates:?}"
            );
            match matched {
                Some(label) => assert_eq!(label_of(result).as_deref(), label),
                None => assert!(result.is_err()),
            }
        }
        // The single-token API goes through the same comparison.
        reset_comparisons();
        assert!(
            authenticate([STATIC, "junk"], Some(STATIC), None)
                .await
                .is_ok()
        );
        assert_eq!(comparisons(), 2);
    }

    #[test]
    fn find_static_picks_the_first_matching_candidate() {
        let secrets = ["a1", "b22", "c333"];
        assert_eq!(find_static(&["c333"], &secrets), Some(2));
        assert_eq!(find_static(&["a1"], &secrets), Some(0));
        assert_eq!(find_static(&["b22", "a1"], &secrets), Some(1));
        assert_eq!(find_static(&["zz"], &secrets), None);
        assert_eq!(find_static(&["a1"], &[]), None);
    }
}
