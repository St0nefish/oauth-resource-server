//! A downstream module that glob-imports this crate's root and also uses the
//! `tower` crate must compile. A crate-root module named `tower` made that
//! `tower` ambiguous (E0659/E0432), which is why the `tower` feature's module
//! is `http_layer`. This file failing to compile is the regression.

use oauth_resource_server::*;
use tower::ServiceBuilder;

#[test]
fn a_glob_import_of_the_root_leaves_the_tower_crate_usable() {
    // Something from the glob, so it is not an unused import in any build.
    assert!(!OAuthConfig::default().enabled);
    let builder = ServiceBuilder::new();

    #[cfg(feature = "tower")]
    {
        let layer = http_layer::HttpAuthLayer::builder()
            .static_token("example-static-key")
            .build()
            .unwrap();
        let _service = builder.layer(layer).service(tower::service_fn(
            |_request: http::Request<String>| async {
                Ok::<_, std::convert::Infallible>(http::Response::new(String::new()))
            },
        ));
    }
    #[cfg(not(feature = "tower"))]
    let _ = builder;
}
