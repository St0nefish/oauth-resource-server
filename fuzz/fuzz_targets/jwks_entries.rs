#![no_main]

use libfuzzer_sys::fuzz_target;

// The per-entry JWK parse of the JWKS fetch path, over a JWK Set document or
// a single entry.
fuzz_target!(|data: &[u8]| {
    oauth_resource_server::__fuzz::jwks_entries(data);
});
