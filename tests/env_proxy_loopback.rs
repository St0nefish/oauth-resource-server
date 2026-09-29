//! An `HTTP_PROXY` from the real process environment never carries a
//! loopback key fetch (those use the validator's proxy-free loopback
//! client), while a non-loopback one goes through it exactly as a plain
//! reqwest client's does.
//!
//! A test binary of its own, with a single test, because it sets process
//! environment variables (`unsafe` since the 2024 edition: another thread
//! reading the environment meanwhile is undefined behavior). They are set
//! before this test starts any runtime thread of its own, and nothing else
//! runs in this process. The library's unit tests cover which client each
//! URL is given.
#![cfg(feature = "testing")]

use std::collections::HashMap;
use std::sync::atomic::Ordering;

use oauth_resource_server::{OAuthValidator, testing};

#[test]
fn an_environment_proxy_never_carries_a_loopback_fetch() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    // Bind the fake proxy first (it needs the runtime), then set the
    // environment before any validator reads it. A current-thread runtime
    // runs no worker threads, so nothing reads the environment concurrently.
    let proxy = runtime.block_on(testing::spawn_http_server(
        HashMap::from([
            (
                "http://localhost:9/jwks".to_string(),
                ("200 OK", testing::jwks_body()),
            ),
            (
                "http://jwks.example.test/jwks".to_string(),
                ("200 OK", testing::jwks_body()),
            ),
        ]),
        None,
    ));
    // SAFETY: single-threaded at this point (see the module docs).
    unsafe {
        for var in [
            "NO_PROXY",
            "no_proxy",
            "ALL_PROXY",
            "all_proxy",
            "HTTPS_PROXY",
            "https_proxy",
            "http_proxy",
            "REQUEST_METHOD",
        ] {
            std::env::remove_var(var);
        }
        std::env::set_var("HTTP_PROXY", &proxy.base);
    }

    runtime.block_on(async {
        // A loopback jwks_uri (no `allow_insecure_http` needed) is fetched
        // directly: port 9 on this host has nothing listening, so the fetch
        // fails, and the proxy — which would have answered — sees nothing.
        let v = OAuthValidator::new(&testing::resolved_config("http://localhost:9/jwks")).unwrap();
        assert!(v.refresh_now().await.is_err());
        assert_eq!(proxy.hits.load(Ordering::SeqCst), 0);

        // The environment proxy is live: a non-loopback URL goes through it,
        // as it does for a plain reqwest client (whose default proxy
        // handling the validator's normal client keeps untouched).
        let mut cfg = testing::resolved_config("http://jwks.example.test/jwks");
        cfg.allow_insecure_http = true;
        let v = OAuthValidator::new(&cfg).unwrap();
        assert_eq!(v.refresh_now().await.unwrap(), 1);
        assert_eq!(proxy.hits.load(Ordering::SeqCst), 1);
        let plain = reqwest::Client::new()
            .get("http://jwks.example.test/jwks")
            .send()
            .await
            .unwrap();
        assert!(plain.status().is_success());
        assert_eq!(proxy.hits.load(Ordering::SeqCst), 2);
    });
}
