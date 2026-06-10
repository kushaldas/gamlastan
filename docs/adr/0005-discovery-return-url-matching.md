# ADR 0005 — Discovery return URL matching preserves registered query

- **Status:** Accepted
- **Date:** 2026-06-10
- **Deciders:** gamlastan maintainers
- **Spec:** Identity Provider Discovery Service Protocol and Profile (`specs/sstc-saml-idp-discovery.txt`), section 2.4.1
- **Implementation:** `crates/gamlastan/src/profiles/idp_discovery.rs`

## Context

The Discovery Service profile uses the SP's registered
`idpdisc:DiscoveryResponse` endpoints as a phishing defense: a discovery
service must not redirect the browser to an arbitrary `return` URL supplied in
request parameters.

Our first implementation compared only the pre-`?` portion of the caller's
`return` URL against the registered endpoint location. That preserved the path
check, but it accidentally weakened the query-string part of the contract:
when metadata registered a return URL with fixed query parameters, the caller
could replace those parameters entirely and still pass validation.

The code comment already stated the intended behavior: the registered query may
be extended, not rewritten.

## Decision

Treat the registered DiscoveryResponse URL as:

- an exact match for scheme, host, port, and path, and
- a fixed query prefix when metadata already contains a query string.

Concretely:

- if the registered endpoint has no query string, any caller-supplied query is
  allowed;
- if the registered endpoint has a query string, the supplied `return` URL must
  preserve that exact query string and may only append additional parameters
  using `&`.

This is implemented in `verify_return_url()` by comparing the base URL and then
requiring the supplied query to equal the registered query or begin with the
registered query followed by `&`.

## Consequences

- The phishing-protection check now enforces the contract expressed in the
  function documentation.
- SPs that register stateful return URLs in metadata keep those parameters
  stable across discovery redirects.
- The comparison is intentionally strict about query ordering and raw string
  form. That is acceptable because metadata locations are deployment-owned and
  stable.

## Alternatives considered

- **Ignore the registered query string.** Rejected because it allows a caller
  to rewrite metadata-owned return parameters.
- **Parse query parameters as an unordered map.** Deferred. It is more complex
  and not required for the current metadata model, where the registered URL is
  expected to be emitted in one canonical form.

## Validation

- Added `test_verify_return_url_preserves_registered_query`.
- Re-ran `cargo test -p gamlastan test_verify_return_url`.
