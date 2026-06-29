# Security hardening

This document records the security controls gamlastan enforces against the
SAML-specific attack classes catalogued in [`samlattacks.md`](../samlattacks.md),
and maps the June 2026 security review findings to their fixes,
Architecture Decision Records, and regression tests.

The library is built to **fail closed**: when an input cannot be fully validated
or a trust decision cannot be proven, the operation is rejected rather than
allowed. The patterns below state the invariant each control upholds.

## Signature binding (XML Signature Wrapping)

> **Invariant:** a signature is trusted only over the exact object that is then
> consumed.

`VerifyResult::Valid` carries the verified XML-DSig reference targets. Every
path that verifies a signature and then reads identity, attributes, keys, or
endpoints binds the two: a verified reference must target the consumed object's
`ID` (`#id`) or the document root (empty `URI`). A valid signature over a
sibling object does not authorize a wrapped object.

- MDQ metadata verification (`gamlastan-mdq`), Sweden Connect response
  processing, the SPID conformance ACS, and the example IdP all enforce this.
- The E91 `ds:Object` guard is namespace-aware and fails closed on unparseable
  signature XML.
- The binding composes with `bergshamra`'s own strict XSW check (a reference must
  target an ancestor/sibling/document-element of the `Signature`); the gamlastan
  binding closes the residual sibling/document-element case bergshamra permits.
  An **end-to-end** MDQ fixture
  (`signature_wrapping_over_sibling_element_is_rejected`) signs a real sibling
  `EntityDescriptor` with the federation key and confirms the wrap is rejected
  with `MdqError::SignatureNotBound`.
- See **ADR 0028** (binding) and **ADR 0020** (E91). Findings 1, 3, 6, 16, 17.

## Request correlation (replay / capture-replay)

> **Invariant:** a solicited response must carry and match the request it
> answers; a dangling correlation value is rejected.

The back-channel response helpers (artifact, ManageNameID, NameIDMapping,
assertion query) require `InResponseTo` to be present and equal to the expected
request ID. The shared `AssertionValidator` rejects a response or bearer
`SubjectConfirmationData` that carries `InResponseTo` when no outstanding request
was found (tracker miss / expiry), instead of treating it as unsolicited.

- See **ADR 0029**. Findings 8, 9, 10, 11, 12.

## Trust boundaries on ready-made IdP handlers

> **Invariant:** the ready Actix IdP handlers act only on input bound to trusted
> SP metadata, and fail closed when that trust material is absent.

`IdpConfig` carries a registry of trusted SPs. The SSO handler validates the
request-supplied `AssertionConsumerServiceURL` against SP metadata; the artifact
and SLO handlers require a trusted, signature-bound, correctly-addressed message
before consuming an artifact or destroying a session. Deployments that
authenticate the transport (mutual TLS) may opt out via
`allow_unauthenticated_backchannel`.

Federation deployments that learn SP metadata from MDQ rather than registering
SPs statically implement `TrustedSpResolver` (over a `gamlastan_mdq::MdqClient`)
and register it with `IdpConfig::with_sp_resolver`; the handlers resolve trust
dynamically and still fail closed when an issuer is unknown.

- See **ADR 0030** and **ADR 0019** (SP SLO). Findings 4, 5, 13.

## Metadata trust anchors and input validation

> **Invariant:** trust anchors come only from conformant XMLDSig structure, and
> unusual or un-inspectable input is rejected.

- Signing certificates are extracted only from `<X509Certificate>` elements in
  the XML Signature namespace (or unqualified) nested under `<X509Data>`;
  foreign-namespace lookalikes are rejected. The unparseable-fragment fallback
  anchors trust to the `<KeyInfo>` root prefix, so both inline **and
  ancestor-declared** foreign-namespace lookalikes are rejected. This
  trust-anchor-confusion control is documented in depth in
  [`docs/keyinfo-certificate-extraction.md`](keyinfo-certificate-extraction.md).
- RelayState rejects all control characters and is whitespace-normalized before
  dangerous-scheme checks (E90).
- SP-side assertion validation requires an `AudienceRestriction` naming this SP
  (E46); `Conditions` with no audience binding fails.
- See **ADR 0031**. Findings 2, 14, 15.

## Attribute release keys on stable Name

> **Invariant:** IdP attribute-release decisions key on the trusted, stable
> attribute `Name`, never an SP-supplied `FriendlyName`.

The release matcher resolves a `<md:RequestedAttribute>` to a local key through
the IdP's trusted NameFormat converters only, or matches the exact wire `Name`.
The non-unique, attacker-controllable `FriendlyName` is never used as a release
authorization key, so an SP cannot obtain a locally-mapped attribute by labelling
a bogus `Name` with that attribute's `FriendlyName`.

For migrations off pysaml2 that depend on its legacy behaviour (matching an
*unmapped* `Name` by `FriendlyName`), `ReleasePolicy::allow_friendly_name_release_matching(true)`
restores it. It is **off by default** and re-opens this surface, so enable it
only when the SP metadata feed is trusted.

- See **ADR 0032**. Finding 7.

## Out-of-scope deployment controls

Some protections are the deployment's responsibility and the library documents
rather than enforces them:

- **Golden SAML / key compromise** — protect IdP signing keys (HSM/PKCS#11
  signing is supported; see ADR 0004).
- **Mutual TLS** on the SOAP back-channel and holder-of-key transport.
- **XXE / DTD** — rejected at the parse boundary (ADR 0024), but operators
  should still constrain network egress.

## Finding-to-control map

| Finding | Control | ADR | Key regression test |
| --- | --- | --- | --- |
| 1 MDQ signed-object mismatch | Signature binding | 0028 | `signature_wrapping_over_sibling_element_is_rejected` (end-to-end) |
| 2 KeyInfo X509 lookalike | Fail-closed key extraction | 0031 | `test_x509_certificates_der_rejects_foreign_namespace_lookalike` |
| 3 Sweden Connect unbound signature | Signature binding | 0028 | `test_rejects_signature_wrapping_unbound_to_response` |
| 4 IdP issues to request ACS | SP trust binding | 0030 | `test_trusted_sp_lookup` |
| 5 Unauthenticated artifact resolve | SP trust binding | 0030 | `test_artifact_resolve_rejected_when_no_trusted_sps` |
| 6 SPID ACS boolean signature | Signature binding | 0028 | `test_assertion_signature_binding` |
| 7 FriendlyName attribute release | Trusted-Name release matching | 0032 | `test_friendly_name_cannot_authorize_release` |
| 8 ArtifactResponse missing InResponseTo | Request correlation | 0029 | `test_process_artifact_response_missing_irt_rejected` |
| 9 Dangling InResponseTo | Request correlation | 0029 | `test_dangling_in_response_to_rejected` |
| 10 ManageNameID missing InResponseTo | Request correlation | 0029 | `test_process_manage_name_id_response_missing_irt_rejected` |
| 11 Query response missing InResponseTo | Request correlation | 0029 | `test_process_query_response_missing_irt_rejected` |
| 12 NameIDMapping missing InResponseTo | Request correlation | 0029 | `test_process_name_id_mapping_response_missing_irt_rejected` |
| 13 SLO destroys sessions unsigned | SP trust binding | 0030 | `test_slo_rejected_when_no_trusted_sps` |
| 14 RelayState obfuscated schemes | Input validation | 0031 | `test_relay_state_embedded_control_char_scheme` |
| 15 Empty AudienceRestriction | Input validation | 0031 | `test_conditions_without_audience_restriction_rejected` |
| 16 E91 fail-open | Signature binding | 0028 | `test_unparseable_xml_fails_closed` |
| 17 Example IdP unbound AuthnRequest | Signature binding | 0028 | `test_request_reference_covers` |
