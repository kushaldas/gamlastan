# ADR 0033 - In-core IdP response/assertion signing helpers

- **Status:** Accepted
- **Date:** 2026-06-29
- **Deciders:** gamlastan maintainers
- **Spec:** SAML 2.0 Core 3.2.2 (`StatusResponseType` element order), 2.3.3
  (`AssertionType` element order); XML-DSig (enveloped signature, exclusive c14n)
- **Implementation:** `crates/gamlastan/src/profiles/sso/idp.rs`,
  `crates/gamlastan/tests/response_signing.rs`

## Context

`profiles::sso::idp::create_response` (and `create_unsolicited_response`) return
an **unsigned** `Response`. Delivering one to a service provider that requires
signed responses/assertions - the common production posture - means:

1. serializing the `Response` to XML,
2. splicing an empty enveloped `<ds:Signature>` template (empty `DigestValue` /
   `SignatureValue`, a single `Reference` to the target element's ID, the signing
   certificate in `<ds:KeyInfo>`) into that XML, and
3. filling it in with `SamlSigner::sign_enveloped`.

`sign_enveloped` deliberately operates on "XML that already contains a template"
(see its doc comment); it does not know where the template belongs. So every
consumer that wants a signed IdP response has been re-deriving steps 1-2 by hand:

- `gamlastan-actix` carries `signature_template` / `insert_signature_after_element`
  / `sign_response_xml`;
- the `examples/django-idp` IdP reimplements the same splice in Python;
- the `pygamlastan` PyO3 binding would have to do it a third time for its
  pysaml2-compatibility IdP adapter.

Two problems follow. First, duplication: the canonical template and splice live
in a web-framework crate (`gamlastan-actix`), unreachable by other consumers of
core `gamlastan`. Second, **correctness drift**: the `gamlastan-actix` splice
inserts the signature as the signed element's *first child* (immediately after
its opening tag, **before** `<saml:Issuer>`). SAML Core orders these elements:

- `StatusResponseType`: `Issuer?`, `Signature?`, `Extensions?`, `Status`, ...
- `AssertionType`: `Issuer`, `Signature?`, `Subject?`, `Conditions?`, ...

i.e. `<ds:Signature>` must come **after** `<saml:Issuer>`. A first-child
placement produces schema-invalid ordering that a strict SP verifier can reject.
The Python example, by contrast, correctly splices after `</saml:Issuer>`.

## Decision

Provide the signing helpers in **core gamlastan**, next to the response builders
they complement, and make the placement **schema-correct**.

Added to `profiles::sso::idp`:

- `signature_template(reference_id, cert_der_b64, signature_method_uri) -> String`
  - the canonical empty enveloped template: exclusive c14n, the
    enveloped-signature transform, a single `Reference URI="#reference_id"`, a
    SHA-256 `DigestMethod`, and the certificate in `<ds:KeyInfo>`.
- `sign_response_xml(response_xml, signer, cert_der_b64, response_id,
  assertion_id, sign_assertions, sign_responses) -> Result<String, ProfileError>`
  - splice + `sign_enveloped`, signing the assertion (inner) before the response
    (outer) when both are requested, so the response signature covers the
    already-signed assertion.
- `create_signed_response(options, name_id, times, signer, cert_der_b64,
  sign_assertions, sign_responses) -> Result<String, ProfileError>`
  - the one-call path: `create_response` + serialize + `sign_response_xml`.

Two design points:

- **Anchor after `<saml:Issuer>`.** The internal splice finds the target
  element's opening tag, then the first `</saml:Issuer>` at or after it, and
  inserts the template there - schema-correct for both the response and the
  assertion, matching the worked Python example rather than the actix first-child
  placement.
- **Embed the certificate explicitly.** The template always carries the signing
  cert in `<ds:KeyInfo>`, so it is valid on both the in-process and the HSM
  signing paths (bergshamra-dsig does not populate `<ds:KeyInfo>` from the key
  manager on the HSM path).

## Consequences

- Core consumers (the `pygamlastan` IdP adapter, the django example, any
  embedder) call one function instead of hand-rolling the template and the
  splice. This is the building block the pysaml2-compat IdP adapter
  (`server.Server`) needs for `create_authn_response(..., sign_response=True)`.
- The placement is schema-correct by construction; an SP doing strict schema
  validation will not reject on Signature ordering.
- `gamlastan-actix`'s local `signature_template` / `sign_response_xml` are now
  superseded and should migrate to these core helpers; its first-child placement
  is the schema-incorrect variant and is the one to drop.
- These helpers do not change `create_response` or `sign_enveloped`; they are
  additive and the unsigned builders remain available.

## Alternatives considered

- **Leave it in `gamlastan-actix`.** Rejected: it is unreachable from core, which
  is exactly why the binding and the example each re-implemented it, and the only
  in-tree copy has the schema-incorrect placement.
- **A typed-DOM signer that inserts `<ds:Signature>` into the parsed model before
  serialization.** Rejected for now as heavier than warranted: `sign_enveloped`
  already defines a template-in-XML contract, and the string splice against the
  library's own deterministic serializer output is simple and well-tested.

## Testing

- Unit tests (`profiles::sso::idp::tests`): template contents (reference URI,
  algorithms, placeholders, embedded cert) and that the splice lands after the
  correct `<saml:Issuer>` (and errors when the target element is absent).
- Integration test (`tests/response_signing.rs`): a real RSA sign -> verify
  roundtrip for assertion-only and assertion+response signing, asserting the
  signature is positioned after the Issuer and that `verify_enveloped` validates.
