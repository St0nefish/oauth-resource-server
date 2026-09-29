// The crate documentation IS the README, so its Rust snippets run as doctests
// and the two cannot drift. Those snippets use the `serde`, `env` and `axum`
// features, so the README is included only when all three are on (as with
// `--all-features`, which CI and docs.rs use); any narrower build gets the
// short pointer below instead, rather than doctests that cannot compile.
#![cfg_attr(
    all(feature = "serde", feature = "env", feature = "axum"),
    doc = include_str!("../README.md")
)]
// Linked for rustdoc readers; the README itself has no intra-doc links, since
// GitHub and crates.io would render them as literal brackets.
#![cfg_attr(
    all(feature = "serde", feature = "env", feature = "axum"),
    doc = "
## API map

| Item | Role |
|---|---|
| [`OAuthConfig`], [`OAuthConfig::resolve`] | The unvalidated settings, and their all-or-nothing validation into a [`ResolvedOAuthConfig`] or a [`ConfigError`]. [`KeyNaming`] decides how problems name settings. |
| [`OAuthValidator`] | Validates one token ([`OAuthValidator::validate`]), renders the challenges and the metadata document, and keeps the signing keys fresh ([`OAuthValidator::spawn_background_refresh`]). |
| [`AuthorizedToken`], [`TokenRejection`] | The two outcomes of a validation. |
| [`authenticate`], [`Credential`] | Framework-free checking of several candidate credentials against a static token and OAuth. |
| [`Algorithm`], [`parse_algorithm`], [`AlgorithmError`] | The JWS algorithms a config may allow (never HMAC or `none`). |
| [`static_token_policy`], [`StaticTokenDecision`] | The startup decision about a static API key alongside OAuth. |
| [`axum::AuthLayer`], [`axum::require_auth`], [`axum::metadata_router`] | The axum integration (feature `axum`), including extractors for [`Credential`] and [`AuthorizedToken`]. |
| [`env::oauth_config_from_env`], [`env::secret_from_env`] | Configuration from environment variables (feature `env`). |"
)]
// The last row links the `testing` module, which exists only with that feature;
// without it the row is rendered with no link, so a `serde,env,axum` doc build
// has no unresolved intra-doc link.
#![cfg_attr(
    all(
        feature = "serde",
        feature = "env",
        feature = "axum",
        feature = "testing"
    ),
    doc = "| [`testing`] | Fixtures for your tests (feature `testing`). |"
)]
#![cfg_attr(
    all(
        feature = "serde",
        feature = "env",
        feature = "axum",
        not(feature = "testing")
    ),
    doc = "| `testing` | Fixtures for your tests (feature `testing`, not enabled in this build). |"
)]
#![cfg_attr(
    not(all(feature = "serde", feature = "env", feature = "axum")),
    doc = "OAuth 2.0 bearer-token resource server for Rust HTTP services: JWT \
           access-token validation against a JWKS (RFC 9068), RFC 9728 \
           protected-resource metadata, RFC 6750 `WWW-Authenticate` challenges, an \
           optional static API key alongside OAuth, and axum integration.\n\n\
           The full guide is this crate's README, which becomes the crate \
           documentation when it is built with the `serde`, `env` and `axum` \
           features (as on docs.rs): <https://docs.rs/oauth-resource-server>."
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs)]
#![forbid(unsafe_code)]

// Without a TLS backend reqwest cannot fetch an https JWKS, and every real
// authorization server serves its keys over https — the validator would build,
// then fail closed on every token. Refuse at compile time instead. No cfg(test)
// or docs exemption: `cargo test` and `cargo doc` build with the default
// feature set, which includes `rustls-tls`.
#[cfg(not(any(
    feature = "rustls-tls",
    feature = "rustls-tls-native-roots",
    feature = "native-tls"
)))]
compile_error!(
    "oauth-resource-server needs a TLS backend for JWKS fetches: enable the `rustls-tls` \
     (default), `rustls-tls-native-roots` or `native-tls` feature"
);

mod algorithms;
mod challenge;
pub mod config;
mod jwks;
mod token;
mod validator;

mod authenticate;
mod policy;

#[cfg(feature = "env")]
#[cfg_attr(docsrs, doc(cfg(feature = "env")))]
pub mod env;

#[cfg(feature = "axum")]
#[cfg_attr(docsrs, doc(cfg(feature = "axum")))]
pub mod axum;

// Entry points for the `fuzz/` cargo-fuzz crate into internals that are not
// public API. cargo-fuzz sets `--cfg fuzzing`; no ordinary build (including
// docs.rs and every CI job but `fuzz.yml`) compiles this module. cargo-fuzz
// sets the cfg for every crate in the build, so a project that fuzzes ITSELF
// while depending on this crate compiles this one with `fuzzing` on as well.
// That works either way: the module needs the `axum` and `testing` features
// (`bearer_credential`, `resolved_config`), and is simply left out unless a
// build enables both.
#[cfg(all(fuzzing, feature = "axum", feature = "testing"))]
#[doc(hidden)]
pub mod __fuzz;

#[cfg(any(test, feature = "testing"))]
#[cfg_attr(docsrs, doc(cfg(feature = "testing")))]
pub mod testing;

pub use algorithms::{Algorithm, AlgorithmError, DEFAULT_ALGORITHMS, parse_algorithm};
pub use authenticate::{Credential, authenticate};
pub use challenge::PROTECTED_RESOURCE_METADATA_PREFIX;
pub use config::{
    ConfigError, DEFAULT_LEEWAY_SECS, DEFAULT_PRINCIPAL_CLAIMS, DEFAULT_SCOPE_CLAIMS, KeyNaming,
    KeyNamingBuf, MAX_LEEWAY_SECS, OAuthConfig, ResolvedOAuthConfig,
};
pub use jwks::RefreshError;
pub use policy::{NoAuthConfigured, StaticTokenDecision, static_token_policy};
pub use token::{AuthorizedToken, TokenRejection};
pub use validator::{OAuthValidator, ValidatorError};
