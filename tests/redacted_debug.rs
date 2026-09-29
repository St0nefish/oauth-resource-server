//! A credential in a configured URL never reaches a `Debug` rendering or a
//! configuration problem message (oauth-resource-server#38).
//!
//! Every URL here carries the same secrets — userinfo `alice:s3cret` (sent as
//! Basic auth on a fetch) and, where the setting allows one, a query
//! `key=t0ken` — and none of them may appear in the output, while the host and
//! path still do, so the output stays useful. Log lines are covered by
//! `tests/redacted_logs.rs`.

use std::sync::Arc;

use oauth_resource_server::{ConfigError, KeyNaming, OAuthConfig, OAuthValidator};

const SECRETS: [&str; 3] = ["alice", "s3cret", "t0ken"];

const ISSUER: &str = "https://alice:s3cret@idp.example.test/app/";
const JWKS_URI: &str = "https://alice:s3cret@idp.example.test/o/jwks?key=t0ken";
const RESOURCE: &str = "https://alice:s3cret@api.example.test/v1";

/// The parts of the three URLs above that must still be shown.
const SHOWN: [&str; 3] = [
    "https://***@idp.example.test/app/",
    "https://***@idp.example.test/o/jwks?***",
    "https://***@api.example.test/v1",
];

const NAMING: KeyNaming<'static> = KeyNaming::Dotted("app.oauth");

fn assert_no_secret(text: &str) {
    for secret in SECRETS {
        assert!(!text.contains(secret), "{secret} leaked into: {text}");
    }
}

fn assert_shows_endpoints(text: &str) {
    for part in SHOWN {
        assert!(text.contains(part), "{part} missing from: {text}");
    }
}

fn config() -> OAuthConfig {
    OAuthConfig {
        enabled: true,
        issuer: ISSUER.into(),
        jwks_uri: Some(JWKS_URI.into()),
        audience: "api".into(),
        resource: RESOURCE.into(),
        required_scope: Some("read".into()),
        ..OAuthConfig::default()
    }
}

fn validator() -> Arc<OAuthValidator> {
    let resolved = config().resolve(NAMING).unwrap().unwrap();
    Arc::new(OAuthValidator::new(&resolved).unwrap())
}

#[test]
fn config_debug_masks_every_url() {
    let cfg = config();
    let shown = format!("{cfg:?} {cfg:#?}");
    assert_no_secret(&shown);
    assert_shows_endpoints(&shown);
    // Every other field still prints.
    assert!(shown.contains("required_scope: Some(\"read\")"), "{shown}");
    assert!(shown.contains("audience: \"api\""), "{shown}");
    // An unset URL prints as it is, not as a placeholder.
    let default = format!("{:?}", OAuthConfig::default());
    assert!(default.contains("issuer: \"\""), "{default}");
    assert!(default.contains("jwks_uri: None"), "{default}");

    let resolved = cfg.resolve(NAMING).unwrap().unwrap();
    let shown = format!("{resolved:?} {resolved:#?}");
    assert_no_secret(&shown);
    assert_shows_endpoints(&shown);
    assert!(shown.contains("required_scopes: [\"read\"]"), "{shown}");
}

#[tokio::test]
async fn validator_and_builder_debug_mask_every_url() {
    let resolved = config().resolve(NAMING).unwrap().unwrap();
    let builder = OAuthValidator::builder(&resolved);
    let shown = format!("{builder:?}");
    assert_no_secret(&shown);
    assert!(shown.contains(SHOWN[0]), "{shown}");

    let v = validator();
    let shown = format!("{v:?} {v:#?}");
    assert_no_secret(&shown);
    assert!(
        shown.contains(SHOWN[0]) && shown.contains(SHOWN[2]),
        "{shown}"
    );
}

#[cfg(feature = "axum")]
#[tokio::test]
async fn axum_layer_debug_masks_every_url() {
    use oauth_resource_server::axum::AuthLayer;
    let builder = AuthLayer::builder().oauth(validator());
    let shown = format!("{builder:?}");
    let layer = builder.build().unwrap();
    let shown = format!("{shown} {layer:?}");
    assert_no_secret(&shown);
    assert!(
        shown.contains(SHOWN[0]) && shown.contains(SHOWN[2]),
        "{shown}"
    );
}

#[cfg(feature = "tower")]
#[tokio::test]
async fn http_layer_debug_masks_every_url() {
    use oauth_resource_server::http_layer::HttpAuthLayer;
    let builder = HttpAuthLayer::builder().oauth(validator());
    let shown = format!("{builder:?}");
    let layer = builder.build().unwrap();
    let shown = format!("{shown} {layer:?}");
    assert_no_secret(&shown);
    assert!(
        shown.contains(SHOWN[0]) && shown.contains(SHOWN[2]),
        "{shown}"
    );
}

/// Everything a `ConfigError` renders: `Display`, `Debug`, `problems` and
/// every `problem_details()` message.
fn rendered(err: &ConfigError) -> String {
    let details: Vec<&str> = err.problem_details().iter().map(|p| p.message()).collect();
    format!("{err}\n{err:?}\n{:?}\n{}", err.problems, details.join("\n"))
}

/// One change to [`config`], making it fail `resolve`.
type Edit = fn(&mut OAuthConfig);

#[test]
fn config_problems_never_echo_a_credential() {
    // Each `check_url` refusal with a redactable value names the setting and
    // the redacted URL.
    let cases: [(&str, Edit, &str); 6] = [
        (
            "must not contain a query or fragment",
            |c| c.issuer = format!("{ISSUER}?key=t0ken#frag"),
            "\"https://***@idp.example.test/app/?***#***\"",
        ),
        (
            "uses plain http on a non-loopback host",
            |c| c.resource = RESOURCE.replacen("https", "http", 1),
            "\"http://***@api.example.test/v1\"",
        ),
        (
            "has leading/trailing whitespace",
            |c| c.jwks_uri = Some(format!(" {JWKS_URI}")),
            "\"https://***@idp.example.test/o/jwks?***\"",
        ),
        (
            "must be an http(s) URL",
            |c| c.jwks_uri = Some(JWKS_URI.replacen("https", "ftp", 1)),
            "\"ftp://***@idp.example.test/o/jwks?***\"",
        ),
        (
            "contains a space, a control character or a non-ASCII character",
            |c| c.jwks_uri = Some(JWKS_URI.replacen("/o/", "/ö/", 1)),
            "idp.example.test",
        ),
        (
            "contains a space, a control character or a non-ASCII character",
            |c| c.jwks_uri = Some(JWKS_URI.replacen("/o/", "/o\t/", 1)),
            "idp.example.test",
        ),
    ];
    for (problem, edit, shown) in cases {
        let mut cfg = config();
        edit(&mut cfg);
        let err = cfg.resolve(NAMING).unwrap_err();
        let text = rendered(&err);
        assert_no_secret(&text);
        assert!(text.contains(problem), "{problem}: {text}");
        assert!(text.contains(shown), "{shown} missing from: {text}");
    }

    // A value that is not an absolute URL with a host, or hides an `@` in
    // what parsed as its path: the setting and the diagnosis, no value at all.
    let cases: [(&str, Edit); 3] = [
        ("app.oauth.issuer is not an absolute URL (", |c| {
            c.issuer = "//alice:s3cret@idp.example.test/app/?key=t0ken".into()
        }),
        ("app.oauth.jwks_uri must be an http(s) URL", |c| {
            c.jwks_uri = Some("alice:s3cret@idp.example.test/jwks?key=t0ken".into())
        }),
        (
            "app.oauth.resource uses plain http on a non-loopback host",
            |c| c.resource = "http://alice:1234/s3cret@api.example.test/v1".into(),
        ),
    ];
    for (problem, edit) in cases {
        let mut cfg = config();
        edit(&mut cfg);
        let err = cfg.resolve(NAMING).unwrap_err();
        let text = rendered(&err);
        assert_no_secret(&text);
        assert!(text.contains(problem), "{problem}: {text}");
        assert!(!text.contains("<unparseable URL"), "{text}");
    }
}

/// The problem text `resource = value` produces.
fn resource_problem(value: &str) -> String {
    let mut cfg = config();
    cfg.resource = value.into();
    rendered(&cfg.resolve(NAMING).unwrap_err())
}

#[test]
fn a_value_that_cannot_hold_a_credential_is_still_quoted() {
    // Not a URL, but no `@`, `?`, `#` or invisible/non-ASCII character: quoted,
    // so the operator sees the typo.
    let text = resource_problem("kb.example.test/mcp");
    assert!(
        text.contains("app.oauth.resource \"kb.example.test/mcp\" is not an absolute URL ("),
        "{text}"
    );
    // Anything that could hold one is not quoted at all.
    for value in ["user:pw@host/x", "host/x?key=1", "host/x#frag", "host/ x"] {
        let text = resource_problem(value);
        // `user:pw@host/x` parses as scheme `user`, the rest as not URLs.
        assert!(
            text.contains("app.oauth.resource is not an absolute URL (")
                || text.contains("app.oauth.resource must be an http(s) URL"),
            "{value}: {text}"
        );
        assert!(!text.contains("app.oauth.resource \""), "{value}: {text}");
        for part in ["pw", "key=1", "frag", "host/"] {
            assert!(!text.contains(part), "{value}: {part} in {text}");
        }
    }
    // A long safe value is truncated like any other logged value.
    let long = format!("kb.example.test/{}", "a".repeat(300));
    let text = resource_problem(&long);
    assert!(!text.contains(&long) && text.contains('…'), "{text}");
}

#[test]
fn a_redacted_value_says_it_was_changed() {
    // Masked: marked, so a whitespace diagnosis never quotes a clean-looking value.
    let text = resource_problem(&format!(" {RESOURCE}"));
    assert!(
        text.contains(
            "app.oauth.resource \"https://***@api.example.test/v1\" (shown normalized, \
             credential masked) has leading/trailing whitespace"
        ),
        "{text}"
    );
    // Nothing to mask: the value exactly as given, whitespace included, unmarked.
    let text = resource_problem(" https://api.example.test/v1");
    assert!(
        text.contains(
            "app.oauth.resource \" https://api.example.test/v1\" has leading/trailing whitespace"
        ),
        "{text}"
    );
    assert!(!text.contains("shown normalized"), "{text}");
}

#[test]
fn authorized_token_debug_masks_its_issuer() {
    let mut token = oauth_resource_server::AuthorizedToken::new(None, None, ["read"]);
    token.issuer = ISSUER.into();
    let shown = format!("{token:?}");
    assert_no_secret(&shown);
    assert!(shown.contains(SHOWN[0]), "{shown}");
    // The default, empty issuer stays empty rather than a placeholder.
    let shown = format!(
        "{:?}",
        oauth_resource_server::AuthorizedToken::new(None, None, ["read"])
    );
    assert!(shown.contains("issuer: \"\""), "{shown}");
}

#[cfg(feature = "env")]
#[test]
fn env_config_debug_and_problems_never_echo_a_credential() {
    use oauth_resource_server::env::unresolved_oauth_config_from_lookup;
    let vars = [
        ("MYAPP_OAUTH_ISSUER", ISSUER),
        ("MYAPP_OAUTH_JWKS_URI", JWKS_URI),
        ("MYAPP_OAUTH_AUDIENCE", "api"),
        ("MYAPP_OAUTH_RESOURCE", RESOURCE),
        ("MYAPP_OAUTH_REQUIRED_SCOPE", "read"),
    ];
    let load = |vars: &[(&str, &str)]| {
        let vars: Vec<(String, String)> = vars
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        unresolved_oauth_config_from_lookup(
            "MYAPP_OAUTH_",
            move |k| vars.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone()),
            |_| Err(std::io::Error::other("no files")),
        )
        .unwrap()
    };
    let env = load(&vars);
    let shown = format!("{env:?}");
    assert_no_secret(&shown);
    assert_shows_endpoints(&shown);

    let mut bad = vars;
    bad[0].1 = "https://alice:s3cret@idp.example.test/app/?key=t0ken";
    let err = load(&bad).resolve().unwrap_err();
    let text = rendered(&err);
    assert_no_secret(&text);
    assert!(
        text.contains("MYAPP_OAUTH_ISSUER \"https://***@idp.example.test/app/?***\""),
        "{text}"
    );
}
