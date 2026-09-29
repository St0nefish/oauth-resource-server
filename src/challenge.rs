//! RFC 9728 protected-resource metadata and RFC 6750 `WWW-Authenticate`
//! challenges: the document a client fetches to find the authorization server,
//! and the headers that point it there.

use serde_json::Value;

use crate::config::ResolvedOAuthConfig;
use crate::validator::is_canonical_url;

/// Path segment RFC 9728 §3 splices between a resource's authority and its path
/// to form the metadata URL. The bare prefix is also the route that answers for
/// a resource whose URL has no path.
pub const PROTECTED_RESOURCE_METADATA_PREFIX: &str = "/.well-known/oauth-protected-resource";

/// Derive a resource's protected-resource metadata URL, per RFC 9728 §3.1: the
/// well-known segment goes between the authority and the resource's path, NOT at
/// the end. For `https://kb.example.com/mcp` that is
/// `https://kb.example.com/.well-known/oauth-protected-resource/mcp` — which is
/// also why clients probe the path-suffixed form before the bare one.
///
/// The path is kept verbatim, trailing slash included: RFC 9728 §3.1 removes
/// only a terminating slash that directly follows the host, so
/// `https://api.example.com/v1/` is described at
/// `.../oauth-protected-resource/v1/`, which is where a client deriving the
/// URL itself will look.
pub(crate) fn resource_metadata_url(resource: &str) -> String {
    let trimmed = resource.trim();
    // Only a URL that parses and is canonically spelled is taken apart.
    // `https:///host/path` has an empty raw authority, so splitting it would
    // put `.well-known` where the host goes and send clients to a host nobody
    // configured; the parser repairs `https:/host` and `https://host\x`
    // without a `://` split finding the host either. `OAuthValidator::new`
    // warns about all of them.
    if reqwest::Url::parse(trimmed).is_err() {
        // Reachable only from a hand-edited `ResolvedOAuthConfig` (`resolve`
        // refuses it). Anything appended to, say, `https://` would parse with
        // `.well-known` as its host, so there is no absolute URL to give: the
        // bare path, which names no host at all, is the fail-closed answer.
        return PROTECTED_RESOURCE_METADATA_PREFIX.to_string();
    }
    let split = trimmed
        .split_once("://")
        .filter(|_| is_canonical_url(trimmed));
    let Some((scheme, rest)) = split else {
        // A non-canonical spelling `resolve` accepts. Append rather than
        // split, so the result stays on the host the parser reads and the
        // mismatch surfaces as a discovery 404 with the offending string
        // visible in the metadata document, not as a crash.
        return format!(
            "{}{PROTECTED_RESOURCE_METADATA_PREFIX}",
            trimmed.trim_end_matches('/')
        );
    };
    let (authority, path) = match rest.find('/') {
        // A bare "/" path is the host's terminating slash, which §3.1 drops.
        Some(i) if &rest[i..] == "/" => (&rest[..i], ""),
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    format!("{scheme}://{authority}{PROTECTED_RESOURCE_METADATA_PREFIX}{path}")
}

/// The path part of a metadata URL from [`resource_metadata_url`] — the route a
/// server must answer on. Falls back to the bare prefix for a metadata URL with no `://` (a resource
/// spelled `https:/host`, say), which has no authority to strip.
pub(crate) fn metadata_path(metadata_url: &str) -> String {
    metadata_url
        .split_once("://")
        .and_then(|(_, rest)| rest.find('/').map(|i| rest[i..].to_string()))
        .unwrap_or_else(|| PROTECTED_RESOURCE_METADATA_PREFIX.to_string())
}

/// The RFC 9728 document for `config`.
pub(crate) fn metadata_document(config: &ResolvedOAuthConfig) -> Value {
    let mut doc = serde_json::json!({
        "resource": config.resource,
        // Echoed byte-identically. A client compares this against the `iss` of
        // the tokens it receives and against the AS metadata's `issuer`, so
        // normalizing (adding or trimming a trailing slash, lowercasing) here
        // would break that comparison.
        "authorization_servers": [config.issuer],
        "bearer_methods_supported": ["header"],
    });
    // RFC 9728 §3.2: "Parameters with zero values MUST be omitted".
    if !config.scopes_supported.is_empty() {
        doc["scopes_supported"] = serde_json::json!(config.scopes_supported);
    }
    if let Some(name) = &config.resource_name {
        doc["resource_name"] = Value::String(name.clone());
    }
    doc
}

/// `Bearer error="invalid_token", resource_metadata="…", scope="…"`. With no
/// scope to name the `scope` attribute is omitted rather than sent empty:
/// RFC 6749 §3.3 requires at least one scope-token in it.
pub(crate) fn invalid_token(resource_metadata_url: &str, supported_scopes: &str) -> String {
    if supported_scopes.is_empty() {
        return format!(
            "Bearer error=\"invalid_token\", resource_metadata=\"{}\"",
            quoted(resource_metadata_url)
        );
    }
    format!(
        "Bearer error=\"invalid_token\", resource_metadata=\"{}\", scope=\"{}\"",
        quoted(resource_metadata_url),
        quoted(supported_scopes)
    )
}

/// `Bearer error="insufficient_scope", scope="…", resource_metadata="…"`, with
/// `required_scopes` space-delimited (RFC 6750 §3). With no required scope — a
/// configuration under which no token is ever refused for scope — the `scope`
/// attribute is omitted rather than sent empty.
pub(crate) fn insufficient_scope(required_scopes: &str, resource_metadata_url: &str) -> String {
    if required_scopes.is_empty() {
        return format!(
            "Bearer error=\"insufficient_scope\", resource_metadata=\"{}\"",
            quoted(resource_metadata_url)
        );
    }
    format!(
        "Bearer error=\"insufficient_scope\", scope=\"{}\", resource_metadata=\"{}\"",
        quoted(required_scopes),
        quoted(resource_metadata_url)
    )
}

/// The longest `error_description` a per-request challenge carries, in bytes;
/// a longer one is cut here (it is ASCII by then, so any byte is a boundary).
pub(crate) const MAX_ERROR_DESCRIPTION_BYTES: usize = 256;

/// A per-request 403 challenge (`OAuthValidator::insufficient_scope_challenge_for`):
/// `Bearer error="insufficient_scope", scope="…", resource_metadata="…",
/// error_description="…"`, each attribute present only when there is
/// something to put in it.
///
/// Built to be a valid header value whatever the input:
/// - `scopes`: each entry is kept only if it is an RFC 6749 §3.3 scope-token
///   (printable ASCII, no space, `"` or `\`), so none needs escaping and none
///   can split into two; duplicates are dropped, order kept. With none left
///   the attribute is omitted (RFC 6749 §3.3 requires at least one).
/// - `resource_metadata_url`: `None` for a validator on its fallback
///   challenges (its URL is what was invalid). Escaped with [`quoted`].
/// - `description`: RFC 6750 §3 allows only `%x20-21 / %x23-5B / %x5D-7E` in
///   `error_description` — no `"`, no `\`, nothing outside printable ASCII —
///   so every other character (a CR or LF above all) is replaced by a space,
///   never escaped or passed through; the result is trimmed, cut to
///   [`MAX_ERROR_DESCRIPTION_BYTES`], and omitted when blank.
pub(crate) fn insufficient_scope_for(
    scopes: &[&str],
    resource_metadata_url: Option<&str>,
    description: Option<&str>,
) -> String {
    let mut kept: Vec<&str> = Vec::new();
    for scope in scopes {
        if crate::config::is_scope_token(scope) && !kept.contains(scope) {
            kept.push(scope);
        }
    }
    let mut out = String::from("Bearer error=\"insufficient_scope\"");
    if !kept.is_empty() {
        out.push_str(&format!(", scope=\"{}\"", kept.join(" ")));
    }
    if let Some(url) = resource_metadata_url {
        out.push_str(&format!(", resource_metadata=\"{}\"", quoted(url)));
    }
    if let Some(description) = description.map(error_description).filter(|d| !d.is_empty()) {
        out.push_str(&format!(", error_description=\"{description}\""));
    }
    out
}

/// `description` reduced to RFC 6750 §3's `error_description` character set
/// (see [`insufficient_scope_for`]).
pub(crate) fn error_description(description: &str) -> String {
    let allowed = |c: char| c == ' ' || c == '!' || matches!(c, '#'..='[' | ']'..='~');
    let replaced: String = description
        .chars()
        .map(|c| if allowed(c) { c } else { ' ' })
        .collect();
    let mut trimmed = replaced.trim().to_string();
    if trimmed.len() > MAX_ERROR_DESCRIPTION_BYTES {
        trimmed.truncate(MAX_ERROR_DESCRIPTION_BYTES);
        trimmed.truncate(trimmed.trim_end().len());
    }
    trimmed
}

/// Escape a value for an HTTP `quoted-string` (RFC 9110 §5.6.4).
///
/// Every value in a `WWW-Authenticate` auth-param here is config-derived, so this
/// is defence against a typo in config producing a header that a client parses as
/// something other than intended — not against an attacker. Cheaper than
/// validating URLs at load time and it keeps the header well-formed regardless.
pub(crate) fn quoted(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

/// The challenge sent in place of one that would not be a valid header value
/// (see `OAuthValidator::build`): `Bearer error="<error>"`, plus the `scope`
/// attribute only when `scopes` is non-empty and itself a valid header value.
/// No `resource_metadata`: the URL it would carry is what was invalid, or sat
/// next to what was.
pub(crate) fn fallback(error: &str, scopes: &str) -> String {
    let bare = format!("Bearer error=\"{error}\"");
    if scopes.is_empty() {
        return bare;
    }
    let with_scope = format!("{bare}, scope=\"{}\"", quoted(scopes));
    if is_header_value(&with_scope) {
        with_scope
    } else {
        bare
    }
}

/// Whether `value` can be sent as an HTTP header value as is: visible ASCII,
/// SP and HTAB only (RFC 9110 §5.5, without the obs-text a `&str` challenge
/// has no business carrying). CR and LF in particular are refused, so no
/// challenge this crate hands out can split a header.
pub(crate) fn is_header_value(value: &str) -> bool {
    value
        .bytes()
        .all(|b| b == b' ' || b == b'\t' || (0x21..=0x7e).contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_url_splices_the_well_known_segment_before_the_path() {
        // The well-known segment goes between authority and path, NOT appended.
        assert_eq!(
            resource_metadata_url("https://kb.example.com/mcp"),
            "https://kb.example.com/.well-known/oauth-protected-resource/mcp"
        );
    }

    #[test]
    fn metadata_url_for_a_path_less_resource_is_the_bare_well_known() {
        assert_eq!(
            resource_metadata_url("https://kb.example.com"),
            "https://kb.example.com/.well-known/oauth-protected-resource"
        );
        assert_eq!(
            resource_metadata_url("https://kb.example.com/"),
            "https://kb.example.com/.well-known/oauth-protected-resource"
        );
    }

    #[test]
    fn metadata_url_keeps_a_port_and_the_path_verbatim() {
        assert_eq!(
            resource_metadata_url("http://localhost:8001/mcp"),
            "http://localhost:8001/.well-known/oauth-protected-resource/mcp"
        );
        // RFC 9728 §3.1 drops only a slash directly after the host; a path's
        // own trailing slash is part of the resource identifier.
        assert_eq!(
            resource_metadata_url("http://localhost:8001/mcp/"),
            "http://localhost:8001/.well-known/oauth-protected-resource/mcp/"
        );
    }

    #[test]
    fn metadata_url_of_a_malformed_resource_does_not_panic() {
        // `OAuthConfig::resolve` refuses a non-URL `resource`, so this is
        // unreachable from config — but the function itself must still degrade,
        // not panic, and never into an absolute URL on a host nobody named.
        for malformed in ["kb.example.com/mcp", "https://", "https:///", "http:"] {
            assert_eq!(
                resource_metadata_url(malformed),
                PROTECTED_RESOURCE_METADATA_PREFIX,
                "{malformed:?}"
            );
        }
    }

    #[test]
    fn metadata_path_is_the_route_to_serve() {
        for (resource, path) in [
            (
                "https://kb.example.com/mcp",
                "/.well-known/oauth-protected-resource/mcp",
            ),
            (
                "https://kb.example.com/api/v1/",
                "/.well-known/oauth-protected-resource/api/v1/",
            ),
            (
                "https://kb.example.com",
                "/.well-known/oauth-protected-resource",
            ),
            (
                "kb.example.com/mcp",
                "/.well-known/oauth-protected-resource",
            ),
        ] {
            assert_eq!(
                metadata_path(&resource_metadata_url(resource)),
                path,
                "{resource}"
            );
        }
    }

    #[test]
    fn challenge_values_are_escaped_not_pasted() {
        assert_eq!(quoted(r#"a"b\c"#), r#"a\"b\\c"#);
    }

    #[test]
    fn an_invalid_token_challenge_with_no_advertised_scope_omits_scope() {
        assert_eq!(
            invalid_token("https://x/.well-known/oauth-protected-resource", ""),
            "Bearer error=\"invalid_token\", \
             resource_metadata=\"https://x/.well-known/oauth-protected-resource\""
        );
        assert_eq!(
            invalid_token("https://x/.well-known/oauth-protected-resource", "a b"),
            "Bearer error=\"invalid_token\", \
             resource_metadata=\"https://x/.well-known/oauth-protected-resource\", scope=\"a b\""
        );
    }

    #[test]
    fn an_insufficient_scope_challenge_with_no_required_scope_omits_scope() {
        assert_eq!(
            insufficient_scope("", "https://x/.well-known/oauth-protected-resource"),
            "Bearer error=\"insufficient_scope\", \
             resource_metadata=\"https://x/.well-known/oauth-protected-resource\""
        );
    }

    /// The host a URL string actually reaches once the parser has read it.
    fn host(url: &str) -> Option<String> {
        reqwest::Url::parse(url)
            .ok()
            .and_then(|u| u.host_str().map(str::to_owned))
    }

    #[test]
    fn urls_built_from_a_non_canonical_spelling_stay_on_its_host() {
        // `resolve` accepts these (with a startup warning). Whatever the
        // metadata and discovery URLs built from them look like, none may
        // reach a host other than the one the parser reads in the input — in
        // particular `https:///host/path` must not become a URL on host
        // `.well-known`. A 404 (a route that does not match) is the fail-closed
        // outcome.
        for resource in [
            "https:/api.example.test/v1",
            "https:api.example.test/v1",
            "https://api.example.test\\v1",
            "https:///api.example.test/v1",
            "HTTPS:\\\\api.example.test\\v1",
        ] {
            let url = resource_metadata_url(resource);
            assert_eq!(
                host(&url).as_deref(),
                Some("api.example.test"),
                "{resource:?} -> {url:?}"
            );
            assert_eq!(
                url,
                format!("{resource}{PROTECTED_RESOURCE_METADATA_PREFIX}"),
                "{resource:?}"
            );
        }
        for issuer in [
            "https:/idp.example.test/app/",
            "https:idp.example.test/app/",
            "https://idp.example.test\\app\\",
            "https:///idp.example.test/app/",
            "HTTPS:\\\\idp.example.test\\app\\",
        ] {
            let urls = crate::jwks::discovery_urls(issuer);
            assert_eq!(urls.len(), 1, "{issuer:?}: {urls:?}");
            assert_eq!(
                host(&urls[0]).as_deref(),
                Some("idp.example.test"),
                "{issuer:?}: {urls:?}"
            );
        }
        // Canonical spellings are untouched: still both discovery forms.
        assert_eq!(
            crate::jwks::discovery_urls("https://idp.example.test/app/").len(),
            2
        );
    }
}
