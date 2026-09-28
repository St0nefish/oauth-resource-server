---
name: Provider compatibility report
about: An authorization server's token/JWKS/metadata shape isn't handled correctly
title: "provider: "
labels: provider-compatibility
assignees: ""
---

**Redact before posting.** This template asks for the *shape* of your
provider's tokens and keys, not real ones. Replace every real value:

- issuer -> `https://idp.example.test/` (keep the trailing slash or lack of
  one, since that detail matters for discovery)
- audience / client ID -> `example-client-id`
- resource URL -> `https://api.example.test/resource`
- key IDs (`kid`) -> `example-kid-1`
- any actual token, key, secret, or PII in a claim value -> remove entirely
  or replace with a placeholder of the same type (`"sub": "example-user"`)

If you can't safely redact a real token by hand, decode it locally first —
never paste a real token into a third-party site such as jwt.io, and note
that this crate *verifies* tokens rather than decoding them, so pointing an
example at a real token would mean this crate contacting the real
authorization server. A JWT's header and claims are just base64url-encoded
JSON, so a local decode needs nothing but a shell:

```sh
# base64url has no padding; base64 -d needs it restored to a multiple of 4.
decode_b64url() {
  local s="${1//_//}"; s="${s//-/+}"
  case $(( ${#s} % 4 )) in 2) s+="==" ;; 3) s+="=" ;; esac
  printf '%s' "$s" | base64 -d
}
decode_b64url "$(cut -d. -f1 <<<"$TOKEN")"; echo  # header
decode_b64url "$(cut -d. -f2 <<<"$TOKEN")"; echo  # claims
```

Paste only the resulting JSON, redacted per the above — never the raw token
string.

## Provider

Name and, if relevant, version/self-hosted vs. hosted.

## What's wrong

What this crate does with a token or JWKS from this provider, and what you
expected instead (per RFC 9068 / the provider's own docs, with a link if you
have one).

## Token header (redacted)

```json
{
  "alg": "...",
  "typ": "...",
  "kid": "..."
}
```

## Token claims shape (redacted)

```json
{
  "iss": "https://idp.example.test/",
  "aud": "...",
  "sub": "...",
  "scope_or_scp_claim_name_and_shape": "..."
}
```

Note here specifically:

- which claim carries scopes, and whether it's a space-delimited string or
  an array (`scope`, `scp`, something else)
- which claim (if any) carries a human-readable username, if `sub` is an
  opaque ID
- whether `aud` is the client ID, a resource URL, or something else

## JWKS shape (redacted), if relevant

```json
{
  "keys": [
    {
      "kty": "...",
      "alg": "...",
      "use": "...",
      "kid": "example-kid-1"
    }
  ]
}
```

## Discovery, if relevant

The exact URL this crate tried (`jwks_uri` derived from `issuer` via OIDC
discovery, or RFC 8414) and what it returned, redacted the same way.

## Have you verified this against a running instance of this provider?

Yes / No — this determines whether a fixture test for this shape gets
labeled "verified in a sandbox" or "documented-shape fixture, not
live-tested" in `docs/providers.md`.
