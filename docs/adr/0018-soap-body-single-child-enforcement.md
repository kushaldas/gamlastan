# ADR 0018 - Enforce a single SOAP Body child

- **Status:** Accepted
- **Date:** 2026-06-21
- **Deciders:** gamlastan maintainers
- **Spec:** SAML 2.0 SOAP Binding, SOAP 1.1
- **Implementation:** `crates/gamlastan/src/bindings/soap.rs`

## Context

The SOAP binding wrapper documented that a SOAP Body contains a single SAML
element, but the unwrap path returned the first non-Fault element child and
ignored additional element children.

That behavior creates a wrapping/confusion risk. If one layer verifies or
inspects one SOAP Body child while another layer consumes a different child,
the application can act on the wrong SAML message.

## Decision

SOAP unwrap now validates the envelope by expanded XML name and requires:

1. The document root is `{http://schemas.xmlsoap.org/soap/envelope/}Envelope`.
2. There is at most one SOAP 1.1 Header element.
3. There is exactly one SOAP 1.1 Body element.
4. The SOAP Body contains exactly one element child.
5. A SOAP Fault is handled only when it is the single SOAP Body element child.
6. Duplicate Header elements, duplicate Body elements, non-SOAP Envelope
   elements, and extra Body element
   children are rejected.

## Consequences

- SOAP, PAOS, ECP, and artifact-style flows using this unwrap helper no longer
  ignore additional Body elements.
- Producers that send non-SOAP namespaces or multiple Body children fail fast.
- The parser behavior now matches the binding comment and avoids local-name-only
  Envelope matching.

## Validation

- `test_soap_unwrap_rejects_non_soap_envelope_namespace`
- `test_soap_unwrap_rejects_duplicate_body`
- `test_soap_unwrap_rejects_multiple_body_element_children`
- `cargo test -p gamlastan`
