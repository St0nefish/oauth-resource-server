#![no_main]

use libfuzzer_sys::fuzz_target;

// RFC 9728 `resource_metadata_url` / `metadata_path` on any resource string.
fuzz_target!(|data: &str| {
    oauth_resource_server::__fuzz::metadata_urls(data);
});
