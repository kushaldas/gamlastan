# ADR 0028 - Signature verification binds to the consumed SAML object

- **Status:** Accepted
- **Date:** 2026-06-28
- **Deciders:** gamlastan maintainers
- **Spec:** SAML 2.0 Core §5, XML Signature, CWE-347 / CWE-345 (XML Signature Wrapping)
- **Implementation:** `crates/gamlastan-mdq/src/verify.rs`, `crates/gamlastan/src/profiles/swedenconnect/response.rs`, `spid-sp-test/src/main.rs`, `example-idp/src/main.rs`

## Context

A security review (`report.md`, findings 1, 3, 6, 17) found several paths that
reduced XML-DSig verification to a boolean (`VerifyResult::is_valid()` or a
local `signed` flag) and **discarded the verified reference targets**. The XML
object later consumed for identity, attributes, keys, or endpoints was then
selected by a *separate* parse step.

This is the classic XML Signature Wrapping (XSW) gap: a signature that validly
covers object *A* (a sibling assertion, the response envelope, a relocated
`EntitiesDescriptor`) is accepted as if it protected the consumed object *B*.
Trusted-key validity alone does not prove *which* object was signed.

The Actix SP ACS path (`crates/gamlastan-actix/src/sp.rs`) already did this
correctly: it keeps `VerifyResult::Valid { references, .. }` and converts the
reference URIs into the set of signed SAML object IDs.

## Decision

Every path that verifies a signature and then consumes a SAML object must
**bind** the two: a verified XML-DSig reference must target the consumed
object's `ID` (a `#id` same-document reference) or the document root (an empty
`URI`, which signs the element the parser reads).

- **MDQ** (`verify_if_configured`) requires a verified reference covering the
  parsed `EntityDescriptor`/`EntitiesDescriptor` element before its keys and
  endpoints are trusted; otherwise `MdqError::SignatureNotBound`.
- **Sweden Connect** (`process_response`) replaces the fabricated
  `verified_signed_ids = [response.base.id]` with the IDs carried in from
  `verify_and_process_response`'s `VerifyResult::Valid { references }`, and
  rejects with `SignatureNotBoundToResponse` when the consumed Response ID is
  not among them.
- **SPID test ACS** keeps the verified reference IDs and requires the consumed
  assertion's `ID` to be among them.
- **Example IdP** requires an enveloped AuthnRequest signature's reference to
  target the parsed request before its fields are trusted.

## Consequences

- A valid signature over a sibling object no longer authorizes a wrapped object.
- The "signature present" markup flag (`has_signature`) is treated as a
  structural hint only, never as proof of cryptographic protection.
- Same-document `#id` and root (empty-URI) references remain accepted, so
  conformant single-object signatures are unaffected.

## Validation

- `test_rejects_signature_wrapping_unbound_to_response`,
  `test_rejects_signature_verified_but_no_references` (Sweden Connect)
- `reference_to_sibling_object_is_rejected` and siblings (MDQ, helper level)
- `signature_wrapping_over_sibling_element_is_rejected` (MDQ, **end-to-end**: a
  real federation-key signature over a sibling `EntityDescriptor` — a relocation
  bergshamra's own XSW check permits — is rejected by the verified-reference
  binding with `MdqError::SignatureNotBound`)
- `test_acs_wrapping_rejects_unsigned_consumed_assertion`,
  `test_acs_rejects_tampered_response_signature` (Actix SP ACS, end-to-end with
  real signing)
- `test_assertion_signature_binding` (SPID test)
- `test_request_reference_covers` (example IdP)
- `cargo test --workspace`

### Defence-in-depth note

The underlying `bergshamra` verifier enforces its own strict XSW check: a
`Reference` target must be an ancestor, sibling, or the document element relative
to the `Signature`, otherwise verification fails outright. gamlastan's
`reference_uri_covers` binding closes the residual case that strict check still
*permits* — a signature over a genuine **sibling** (or the document element) that
is nonetheless not the consumed/returned object. The end-to-end MDQ fixture above
exercises exactly that residual case, so the two layers are verified together.
