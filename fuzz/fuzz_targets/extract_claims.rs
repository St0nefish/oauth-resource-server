#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct Input<'a> {
    claim_names: Vec<String>,
    claims_json: &'a [u8],
}

// `extract_scopes` / `extract_principal` over a claims object of any shape.
fuzz_target!(|input: Input| {
    oauth_resource_server::__fuzz::extract_claims(input.claims_json, &input.claim_names);
});
