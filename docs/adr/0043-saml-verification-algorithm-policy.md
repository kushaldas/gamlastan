# ADR 0043 - Enforce algorithms at the SAML verification boundary

- **Status:** Accepted
- **Date:** 2026-09-03
- **Deciders:** gamlastan maintainers
- **Implementation:** `crates/gamlastan/src/crypto/config.rs`, `crates/gamlastan/src/crypto/verifier.rs`, `crates/gamlastan-actix/src/config.rs`, `crates/gamlastan-mdq/src/client.rs`

## Context

XML Digital Signature is a general-purpose standard with algorithms retained
for compatibility, including SHA-1 and other methods that are inappropriate as
modern SAML federation defaults. `bergshamra` needs that broad support to remain
a useful XML security implementation and to pass legacy xmlsec interoperability
tests. Before this decision, `SamlVerifier` dispatched every backend-supported
`SignatureMethod` and `DigestMethod` except HMAC.

The algorithm identifiers are carried in attacker-reachable signed input. A
trusted signature still has to verify, so accepting a deprecated method is not
by itself an unsigned-message bypass. It does, however, expose every SAML trust
boundary to legacy algorithms, frustrates federation policy enforcement, and
increases the impact of a future practical weakness in an old method.

Algorithm inspection must have the same structural interpretation as the
cryptographic verifier. A document-wide search would be wrong: XML Encryption
can carry a `ds:DigestMethod` for RSA-OAEP that is not a signature Reference
digest. Single-signature verification also deliberately consumes only the first
signature, while all-signature verification consumes each one.

## Decision

1. Keep bergshamra's supported algorithm set unchanged. Enforce SAML-specific
   policy in `SamlVerifier` before invoking bergshamra.
2. Add an owned `AlgorithmPolicy`. Its default allowlist is RSA and ECDSA with
   SHA-256, SHA-384, or SHA-512 for signatures, and SHA-256, SHA-384, or SHA-512
   for XMLDSig Reference digests.
3. Provide custom allowlists and an explicitly named `permissive` policy for
   legacy interoperability. An empty allowlist denies all algorithms; it never
   disables policy. Allowlists are sorted and deduplicated so policy equality
   represents the accepted set, independent of input order. HMAC rejection
   remains a separate control and must also be explicitly disabled before HMAC
   can be used.
4. Inspect expanded XML names, require exactly one direct `SignedInfo` and
   `SignatureMethod` per selected `Signature`, and exactly one direct
   `DigestMethod` per direct `Reference`. Missing `Algorithm` attributes,
   duplicate structural choices, and parser failures fail closed.
5. Preserve verifier selection semantics: `verify_enveloped` checks the first
   XMLDSig Signature, while `verify_all_enveloped` checks every Signature. The
   Redirect `SigAlg` is checked directly before backend dispatch.
6. Store the policy on the ready Actix SP and IdP configurations and on the MDQ
   client, with secure defaults and builder overrides. Sweden Connect retains
   its stricter fixed profile validation; a generic override cannot widen that
   profile.
7. Changing a dynamic MDQ client's policy invalidates metadata cached under the
   old policy. A static MDQ client has already accepted its sole document, so
   policy changes must be configured before conversion to static mode.

## Consequences

- Deprecated algorithms are rejected before their implementation runs at core,
  Actix, Redirect-binding, and MDQ verification boundaries.
- Existing SAML deployments using SHA-1 or another non-default method must opt
  into an exact custom allowlist or `AlgorithmPolicy::permissive`. This is an
  intentional pre-1.0 behavior change.
- Legacy xmlsec interoperability remains available at the bergshamra layer and
  through gamlastan's explicit compatibility policy.
- Public Actix configuration structs gain a field, which can require updates for
  consumers constructing those pre-1.0 structs with literals. Constructor and
  builder users receive the secure default automatically.
- `CryptoError` gains distinct disallowed-signature and disallowed-digest
  variants. Exhaustive downstream matches must handle them; separating local
  policy rejection from backend capability errors makes failure handling and
  audit logs unambiguous.
- Metadata algorithm advertisements remain negotiation information, not trusted
  input capable of rewriting the local allowlist.

## Validation

Regression tests cover SHA-1 rejection before key lookup, secure SHA-2 controls,
custom and permissive policies, empty allowlists, namespace-prefix variation,
first-versus-all signature selection, malformed structures, and separation of
XML Encryption digests from XMLDSig Reference digests. The workspace test suite,
examples, SPID test application, formatting, linting, and dependency audit are
run for the release.
