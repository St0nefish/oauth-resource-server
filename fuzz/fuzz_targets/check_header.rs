#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct Input<'a> {
    require_at_jwt: bool,
    token: &'a str,
    typ: Option<&'a str>,
}

// The validator's header gate, which runs before any key fetch: size, JWS
// shape, `crit`, `alg` allowlist, `typ`. Also drives `check_crit` and
// `check_typ` directly with unconstrained input.
fuzz_target!(|input: Input| {
    oauth_resource_server::__fuzz::check_header(input.token, input.require_at_jwt);
    oauth_resource_server::__fuzz::check_crit(input.token);
    oauth_resource_server::__fuzz::check_typ(input.typ, input.require_at_jwt);
});
