# ADR 0046 - Restrict signature Reference transforms and URIs at the SAML verification boundary

- **Status:** Proposed
- **Date:** 2026-11-23
- **Deciders:** gamlastan maintainers
- **Spec:** SAML 2.0 Core 5.4 (signature profile), XML Signature 4.4.3 (transforms)
- **Related:** ADR 0028 (signature binding), ADR 0039 (one security interpretation of signed XML), ADR 0043 (algorithm policy)
- **Implementation:** `crates/gamlastan/src/crypto/transform_policy.rs`, `crates/gamlastan/src/crypto/verifier.rs`

## Context

ADR 0028 requires that a verified `Reference` target the consumed object (a
`#id` reference or the document root). That binding looks at the reference URI
and the digest. It does not look at the transforms that produced the digested
bytes, and an XPath filter transform can drop parts of the document from what is
signed while the URI still names the signed element. A request signed with
`not(ancestor-or-self::saml:Issuer)` as its filter verified, and kept verifying
after its `Issuer` was changed; the existing checks passed.

`bergshamra` supports the full XML-DSig transform set on purpose (XPath, XPath
Filter 2.0, XSLT, Base64, the c14n variants), documents that callers must check
what a signature covers, and resolves a simple relative `Reference URI` as a
local file against the working directory for xmlsec interoperability. Both are
documented behavior of a general library. SAML Core 5.4 allows only a
same-document reference with the `enveloped-signature` and exclusive
canonicalization transforms, so the policy belongs at gamlastan's SAML boundary,
as ADR 0043 did for algorithms.

Exploiting the transform gap needs a signature the key holder made over such a
`SignedInfo`, so it is defense in depth and conformance, not a remote bypass by
itself. The file read is reachable by an unauthenticated message: a `Reference
URI` naming a file in the working directory made the verifier read it, and the
error differed between an existing and a missing file.

## Decision

1. Add `TransformPolicy`, owned by `SamlVerifier` like `AlgorithmPolicy`, checked
   in `parse_enveloped` on the same parsed document, before bergshamra runs. A
   refused transform is never executed and a refused URI is never read.
2. The default, `TransformPolicy::saml()`, allows `enveloped-signature` and
   exclusive c14n (with and without comments) as transforms, `""` or `#id` as
   reference URIs (an XPointer fragment is not accepted), and at most 8
   references per signature and 8 transforms per reference. Every signature the
   verifier would consume is checked, using the same selection as the algorithm
   policy.
   Transforms are selected the way bergshamra selects them: every child of
   `ds:Transforms` whose local name is `Transform`, in any namespace or none
   (bergshamra's fast path and generic pipeline both do this, while it finds
   `Signature`, `SignedInfo`, `Reference` and `Transforms` by namespace). A
   `Transform` outside the XML-DSig namespace is refused, since a SAML
   signature never has one and bergshamra would otherwise run it unseen.
   Inclusive canonicalization (`REC-xml-c14n-20010315`) and canonical XML 1.1
   (`REC-xml-c14n11`), with or without comments, are deliberately **not** in
   the default set: SAML Core 5.4 names exclusive canonicalization only, and
   bergshamra supports the others (so this is a decision, not an omission). A
   deployment whose signers use one adds it with `with_additional_transforms`
   (which keeps the SAML set) rather than `with_transforms` (which replaces it).
   A `#xpointer(...)` fragment is likewise refused as a reference URI.
   The allowlist only constrains transforms that are present, so the profile
   structure is required as well: every reference must have exactly one
   `enveloped-signature` transform and exactly one canonicalization transform.
   Without that, a reference with no `ds:Transforms`, or with only
   `enveloped-signature`, passes and the backend canonicalizes it with inclusive
   c14n, the thing the default allowlist refuses; leaving the transforms out would
   be a way round it. `with_require_profile_transforms(false)` relaxes it.
   Key retrieval in a signature's `KeyInfo` is refused too: a `ds:RetrievalMethod`
   (which makes bergshamra read a certificate from a file named by the message,
   relative or absolute, with none of the guards the `Reference` URI path has)
   and a `dsig11:KeyInfoReference` (which makes it treat *any* element of the
   document, found by ID, as the signature's `KeyInfo`, so a `RetrievalMethod`
   could hide elsewhere). Both are matched by local name, because the backend
   accepts a `RetrievalMethod` in the XML-DSig namespace or in none. With
   `trusted_keys_only` on, the default, the verifier ignores them; an integrator
   that turned it off would otherwise let a message supply its own trust anchor
   (reproduced: a signature verified with no configured keys under a certificate
   read from a path in the message). SAML signatures never need either.
   `with_allow_key_retrieval(true)` allows them.
3. Make it configurable rather than fixed: `permissive()` restores the previous
   behavior, `with_transforms` and `with_any_transform` change the transform
   allowlist, `with_reference_uris(ReferenceUris::AnyIncludingLocalFiles)` allows other URIs (and so
   the working-directory file read, hence the long name),
   `with_require_single_reference` enforces SAML Core 5.4.2, `with_allow_key_retrieval` allows
   `RetrievalMethod` and `KeyInfoReference`, and the limits can
   be changed or lifted.
4. Report refusals as `CryptoError::VerificationFailed` with a message that
   quotes the offending value escaped and cut to 64 characters, and gives the
   same message whether or not a named file exists.
5. Do not restrict `SignedInfo/CanonicalizationMethod` here; it can follow the
   same pattern if wanted.

## Consequences

- Every consumer of `SamlVerifier` (request and response verification,
  assertions, metadata, logout, artifact resolution, and integrators such as
  tunnelbana) gets the policy through one choke point, with no per-caller code.
- The default is stricter. A signer that uses a transform outside the profile,
  for example inclusive c14n as a `Reference` transform, is refused until
  allowed with `with_transforms` or `permissive()`. Interop with real signers
  (eduID, SWAMID metadata, the QA release-check) should be checked before a
  deployment relies on the default.
- The check reads the transforms as declared in the document. That matches what
  bergshamra executes, and the policy and the verifier share one parsed
  `Document`, so they cannot disagree about which signatures exist (ADR 0039).
- No logging dependency is added, so there is no warn-only mode; the explicit
  `permissive()` opt-out is the escape hatch. A warn-only mode would need a
  logging or callback decision.

## Evidence from signatures in the workspace

The default was run over every XML file with a signature in the neighbouring
checkouts (pysaml2 and its fork, gamlastan, tunnelbana test data, SATOSA, grindvakt:
169 XML files, 49 with a `ds:Signature` that parses). 40 are accepted and 9 are
refused; all 9 are gamlastan's own `attacks/` corpus (an unknown transform, an
absolute-URI reference, a missing canonicalization or enveloped transform, multiple
`SignedInfo`), which is meant to be rejected. Every other signature, including the
eIDAS response, InCommon, SWAMID and AAI metadata, a SimpleSAMLphp response and the
xmlsec1 samples, uses exactly one `enveloped-signature` and one exclusive c14n
transform. This is test data, not captured traffic: per-entity signatures from live
MDQ responses and IdP responses from the QA release-check are still to be checked
before a deployment relies on the default (the `edugain-v2.xml` aggregate holds a
single signature and says nothing about per-entity signers).

## Alternatives considered

- **Expose the transforms on bergshamra's `VerifiedReference` and check after
  verification.** Non-breaking in bergshamra, but it runs after the transforms
  and the file read have happened, needs a bergshamra release, and leaves the
  file read open.
- **A transform allowlist inside bergshamra.** Correct for a library with this
  behavior documented, but policy about SAML belongs in the SAML layer, and
  gamlastan can enforce it today.
- **Per-integrator checks.** Reproduces the drift this change removes.

## Validation

- `transform_policy_tests`: an XPath filter that excludes the `Issuer` is
  refused (and verified before the change); a relative file reference is refused
  before any file is read, with the same message for an existing and a missing
  file; other URI forms, the limits, single-reference, every-signature checking,
  and each option; the standard signature, and exclusive c14n with comments,
  still verify. Mutation checks: disabling the all-signatures loop, the
  transform limit or the reference limit each fails a test.
- `verifier_document_tests`: the differential oracle mirrors the new guard, and
  the test that signs with an XPath transform opts in with `permissive()`.
- The full workspace test suite, including the attack corpus and MDQ tests,
  passes with the new default.
