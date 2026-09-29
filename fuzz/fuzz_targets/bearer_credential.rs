#![no_main]

use libfuzzer_sys::fuzz_target;

// The `Bearer <token>` header parser, on any header value that is valid UTF-8
// (it reaches the parser as a `&str`).
fuzz_target!(|data: &str| {
    oauth_resource_server::__fuzz::bearer_credential(data);
});
