#![no_main]

use libfuzzer_sys::fuzz_target;

// The OIDC / RFC 8414 discovery-URL builder on any issuer string.
fuzz_target!(|data: &str| {
    oauth_resource_server::__fuzz::discovery_urls(data);
});
