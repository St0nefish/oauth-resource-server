//! Entry points for the `fuzz/` cargo-fuzz crate into crate-internal parsers.
//!
//! Compiled only under `--cfg fuzzing` (which cargo-fuzz sets) and hidden from
//! rustdoc, so none of it is public API: no ordinary build, docs.rs render or
//! downstream consumer ever sees this module. Needs the `axum` and `testing`
//! features (the fuzz crate enables both, and `mcp` for `mcp_tool_calls`).
//!
//! Each function drives one internal with attacker-shaped input and asserts the
//! properties that must hold for *every* input, so a fuzzer finds a broken
//! invariant, not only a panic.

use std::collections::HashSet;
use std::sync::OnceLock;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Map, Value};

use crate::algorithms::{Algorithm, DEFAULT_ALGORITHMS, parse_algorithm};
use crate::config::KeyNamingBuf;
use crate::token::{MAX_TOKEN_BYTES, TokenRejection};
use crate::validator::OAuthValidator;

/// `http_layer::bearer_credential`: the result is always a sub-slice of the input
/// and never carries surrounding whitespace.
pub fn bearer_credential(header: &str) {
    let token = crate::http_layer::bearer_credential(header);
    assert!(header.contains(token));
    assert_eq!(token, token.trim());
}

/// One validator per `require_at_jwt` setting, built once: construction builds
/// an HTTP client, far too slow to repeat per fuzz iteration.
fn validators() -> &'static [OAuthValidator; 2] {
    static VALIDATORS: OnceLock<[OAuthValidator; 2]> = OnceLock::new();
    VALIDATORS.get_or_init(|| {
        let build = |require_at_jwt: bool| {
            let mut config = crate::testing::resolved_config("https://auth.example.test/jwks");
            config.require_at_jwt = require_at_jwt;
            OAuthValidator::new(&config).expect("the fixture config builds")
        };
        [build(false), build(true)]
    })
}

/// `OAuthValidator::check_header` (which runs `check_crit` and `check_typ`) on
/// an arbitrary credential. Whatever it accepts must be a within-cap,
/// three-segment token whose raw header has no `crit` member.
pub fn check_header(token: &str, require_at_jwt: bool) {
    let validator = &validators()[usize::from(require_at_jwt)];
    if validator
        .check_header(token, &tracing::Span::none())
        .is_ok()
    {
        assert!(token.len() <= MAX_TOKEN_BYTES);
        assert_eq!(token.split('.').count(), 3);
        let segment = token.split('.').next().unwrap();
        let raw = URL_SAFE_NO_PAD
            .decode(segment)
            .expect("an accepted header decodes");
        let header: Map<String, Value> =
            serde_json::from_slice(&raw).expect("an accepted header is a JSON object");
        assert!(!header.contains_key("crit"), "a crit header was accepted");
    }
}

/// `validator::check_crit` alone, on an arbitrary string (it documents that
/// the caller has already run `decode_header`, so it must still not panic on
/// anything else).
pub fn check_crit(token: &str) {
    let _ = crate::validator::check_crit(token);
}

/// `token::check_typ` against RFC 9068 §2.1 / RFC 7515 §4.1.9, as an oracle
/// written without the implementation's prefix stripping: `at+jwt` (bare or
/// `application/at+jwt`, case-insensitive, surrounding whitespace ignored) is
/// always accepted; `jwt` likewise only while `require_at_jwt` is off; a
/// missing `typ` is accepted only while it is off; anything else is refused
/// with `TokenRejection::Invalid`.
pub fn check_typ(typ: Option<&str>, require_at_jwt: bool) {
    let naming = KeyNamingBuf::Dotted("app.oauth".to_string());
    let expected_ok = match typ {
        None => !require_at_jwt,
        Some(raw) => {
            let t = raw.trim().to_ascii_lowercase();
            matches!(t.as_str(), "at+jwt" | "application/at+jwt")
                || (!require_at_jwt && matches!(t.as_str(), "jwt" | "application/jwt"))
        }
    };
    match crate::token::check_typ(typ, require_at_jwt, &naming) {
        Ok(()) => assert!(
            expected_ok,
            "accepted typ {typ:?}, require_at_jwt={require_at_jwt}"
        ),
        Err(rejection) => {
            assert!(
                !expected_ok,
                "refused typ {typ:?}, require_at_jwt={require_at_jwt}"
            );
            assert!(matches!(rejection, TokenRejection::Invalid(_)));
        }
    }
}

/// `token::extract_scopes` and `token::extract_principal` over arbitrary
/// claims JSON (anything that is not a JSON object is ignored).
pub fn extract_claims(claims_json: &[u8], claim_names: &[String]) {
    let Ok(Value::Object(claims)) = serde_json::from_slice::<Value>(claims_json) else {
        return;
    };
    let scopes = crate::token::extract_scopes(&claims, claim_names);
    let mut seen = HashSet::new();
    for scope in &scopes {
        assert!(!scope.is_empty());
        assert_eq!(scope, scope.trim());
        assert!(seen.insert(scope), "scopes are deduplicated");
    }
    if let Some(principal) = crate::token::extract_principal(&claims, claim_names) {
        assert!(!principal.trim().is_empty());
    }
}

/// `challenge::resource_metadata_url` and `challenge::metadata_path`, which the
/// validator chains: the URL always carries the well-known prefix and the
/// path is always absolute.
pub fn metadata_urls(resource: &str) {
    let url = crate::challenge::resource_metadata_url(resource);
    assert!(url.contains(crate::challenge::PROTECTED_RESOURCE_METADATA_PREFIX));
    assert!(crate::challenge::metadata_path(&url).starts_with('/'));
    // `metadata_path` also takes any string, not only the URL builder's output.
    assert!(crate::challenge::metadata_path(resource).starts_with('/'));
}

/// `OAuthValidator::insufficient_scope_challenge_for` on arbitrary scopes and
/// description: always a header value, always the `insufficient_scope`
/// error, and the description can never close its quoted string early, carry
/// an escape, or add an attribute.
pub fn scope_challenge(scopes: &[String], description: Option<&str>) {
    let scopes: Vec<&str> = scopes.iter().map(String::as_str).collect();
    let challenge = validators()[0].insufficient_scope_challenge_for(&scopes, description);
    assert!(
        crate::challenge::is_header_value(&challenge),
        "{challenge:?}"
    );
    assert!(challenge.starts_with("Bearer error=\"insufficient_scope\""));
    if let Some((_, described)) = challenge.split_once(", error_description=\"") {
        assert_eq!(described.matches('"').count(), 1, "{challenge:?}");
        assert!(described.ends_with('"'), "{challenge:?}");
        assert!(!described.contains('\\'), "{challenge:?}");
    }
}

/// `mcp::classify`, the tool-name extraction behind `McpToolScopes`, against
/// `serde_json::Value` as an oracle: it reads a body as messages exactly when
/// the body is a JSON object or array; a `ToolCall(name)` is a message whose
/// `method` is `"tools/call"` and whose `params.name` is `name`; a
/// `NotToolCall` is a message whose `method` is not `"tools/call"`.
/// (`Ambiguous` — repeated members, no readable name — may be anything.)
#[cfg(feature = "mcp")]
pub fn mcp_tool_calls(body: &[u8]) {
    use crate::mcp::{Classified, NamedMessage as Message};

    let oracle = serde_json::from_slice::<Value>(body).ok();
    let elements: Option<Vec<&Value>> = match &oracle {
        Some(Value::Array(items)) => Some(items.iter().collect()),
        Some(object @ Value::Object(_)) => Some(vec![object]),
        _ => None,
    };
    match (crate::mcp::classify(body), elements) {
        (Classified::Unreadable, None) => {}
        (Classified::Messages(messages), Some(elements)) => {
            assert_eq!(messages.len(), elements.len());
            for (message, element) in messages.iter().zip(elements) {
                let method = element.get("method").and_then(Value::as_str);
                match message {
                    Message::ToolCall(name) => {
                        assert_eq!(method, Some("tools/call"));
                        assert_eq!(
                            element
                                .get("params")
                                .and_then(|p| p.get("name"))
                                .and_then(Value::as_str),
                            Some(name.as_str())
                        );
                    }
                    Message::NotToolCall => {
                        assert!(element.is_object());
                        assert_ne!(method, Some("tools/call"));
                    }
                    Message::Ambiguous => {}
                }
            }
        }
        (classified, elements) => {
            panic!("classify disagrees with serde_json: {classified:?} vs {elements:?}")
        }
    }
}

/// `jwks::discovery_urls`: OIDC first, at most one RFC 8414 fallback.
pub fn discovery_urls(issuer: &str) {
    let urls = crate::jwks::discovery_urls(issuer);
    assert!((1..=2).contains(&urls.len()));
    assert!(urls[0].ends_with("/.well-known/openid-configuration"));
}

/// The per-entry JWK parse in the JWKS fetch path. `data` is parsed as JSON;
/// a JWK Set object has each entry of its `keys` array parsed (capped as
/// production caps it), anything else is parsed as one entry. Every key that
/// comes out must have a non-empty algorithm list drawn from the allowlist.
pub fn jwks_entries(data: &[u8]) {
    let Ok(doc) = serde_json::from_slice::<Value>(data) else {
        return;
    };
    let allowed: Vec<Algorithm> = DEFAULT_ALGORITHMS
        .iter()
        .map(|a| parse_algorithm(a).expect("default algorithms parse"))
        .collect();
    let entries: Vec<&Value> = match doc.get("keys").and_then(Value::as_array) {
        Some(keys) => keys.iter().take(crate::jwks::MAX_JWKS_KEYS).collect(),
        None => vec![&doc],
    };
    for entry in entries {
        if let Some(key) = crate::jwks::parse_jwks_entry(entry, &allowed) {
            assert!(!key.algorithms.is_empty());
            assert!(key.algorithms.iter().all(|a| allowed.contains(a)));
        }
    }
}
