#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct Input {
    scopes: Vec<String>,
    description: Option<String>,
}

// `OAuthValidator::insufficient_scope_challenge_for` on arbitrary scopes and
// an arbitrary (attacker-shaped) description.
fuzz_target!(|input: Input| {
    oauth_resource_server::__fuzz::scope_challenge(&input.scopes, input.description.as_deref());
});
