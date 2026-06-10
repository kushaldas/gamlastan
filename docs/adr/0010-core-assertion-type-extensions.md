# ADR 0010 — Core assertion type extensions: NameID-valued attributes and `saml:Advice`

- **Status:** Accepted
- **Date:** 2026-06-10
- **Deciders:** gamlastan maintainers
- **Spec:** SAML V2.0 Core §2.7.3.1.1 (AttributeValue), §2.3.3 / §2.6 (Advice); eduPerson `eduPersonTargetedID`
- **Implementation:** `crates/gamlastan/src/core/assertion/{attribute.rs,types.rs}`, `crates/gamlastan/src/xml/assertion/{serialize.rs,deserialize.rs}`

## Context

Two SAML constructs that gamlastan's dual-typed assertion model did not yet
represent became necessary for pysaml2 parity (ADR 0008) and per-request
encryption (ADR 0011):

1. **NameID-valued attribute values.** `eduPersonTargetedID` (and similar) is not a
   string — its `<saml:AttributeValue>` contains a nested `<saml:NameID>` element.
   The existing `AttributeValue` enum only modelled string/boolean/datetime/base64/
   raw-XML/null, so an EPTID either round-tripped as opaque `Xml` bytes (losing the
   structured NameID) or not at all.

2. **`saml:Advice`.** An assertion may carry an `<saml:Advice>` element holding
   assertion references and embedded (possibly encrypted) assertions that a relying
   party *may ignore*. gamlastan dropped it on parse and could not emit it — yet
   encrypted Advice is exactly where PEFIM-style attribute encryption lands
   (ADR 0011).

Both are the same kind of change — extend the dual-typed core structs and teach the
XML layer to round-trip them — so they are recorded together.

## Decision

Extend the core assertion types, preserving the borrowed/owned (`*Ref` / owned)
pattern and full round-trip through `SamlSerialize` / `SamlDeserialize`.

### NameID-valued attribute values

- Add `AttributeValueRef::NameId(NameIdRef<'a>)` and `AttributeValue::NameId(NameId)`,
  with `to_owned()` wired through.
- **Deserialize:** when an `<saml:AttributeValue>` has element children and its
  *single* element child is a `<saml:NameID>`, parse it as `NameId` rather than
  falling through to the raw-`Xml` branch. The single-child guard keeps genuinely
  arbitrary XML values on the `Xml` path.
- **Serialize:** emit `<saml:AttributeValue>` wrapping the serialized `<saml:NameID>`.

### `saml:Advice`

- Add `AdviceRef<'a>` / `Advice` (both `Default`) holding `assertion_id_refs`,
  `assertion_uri_refs`, embedded `assertions`, and embedded `encrypted_assertions`,
  and an `advice: Option<Advice>` field on `Assertion` / `AssertionRef`.
- Round-trip through the XML layer: deserialize collects the four child kinds;
  serialize emits `AssertionIDRef` / `AssertionURIRef` / nested assertions /
  verbatim encrypted-assertion bytes, placed after `Conditions` per the schema.

## Consequences

- **Breaking (pre-release):** `Assertion` / `AssertionRef` gained the `advice`
  field and `AttributeValue` / `AttributeValueRef` gained the `NameId` variant.
  Every struct literal that builds an assertion now sets `advice: None`, and every
  exhaustive `match` on `AttributeValue` now handles `NameId` (updated across
  `profiles::sso::{sp,idp}`, `swedenconnect::response`, `security::validation`,
  and `spid-sp-test`, which renders it as the NameID value string). Documented in
  `CHANGELOG.md`.
- EPTID now survives a full parse → serialize round-trip as structured XML.
- `Advice` gives ADR 0011 a typed home for encrypted advice assertions.
- These additions live in the **core types**, not a profile layer — they are
  generic SAML constructs, unlike the Sweden Connect extensions of ADR 0001 which
  were deliberately kept out of core.

## Alternatives considered

- **Keep EPTID as raw `Xml` bytes.** Rejected: callers (e.g. the SPID test SP,
  release policies) need the NameID value, not an opaque blob; re-parsing bytes at
  every use is wasteful and error-prone.
- **Model the NameID-valued case as a profile concern.** Rejected: NameID-valued
  attributes are standard Core, used well beyond any one profile.
- **Store `Advice` as an opaque `raw_xml` blob** (as metadata `Extensions` do).
  Rejected: the encrypted-advice flow (ADR 0011) must *construct* and *append to*
  Advice, which needs a typed, mutable representation, not an opaque string.

## Validation

- `cargo test -p gamlastan` — 592 unit tests passing after the literal/`match`
  updates.
- `tests/cert_encryption.rs` round-trips both a NameID-valued attribute
  (`test_encrypted_advice_roundtrip` via `eptid_attribute`) and an `Advice`
  carrying an encrypted assertion.

## Publication status

Unreleased; the new field and variant may still change shape before a tagged
release.
