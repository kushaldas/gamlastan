# ADR 0009 — Attribute name conversion with code-generated shipped maps

- **Status:** Accepted
- **Date:** 2026-06-10
- **Deciders:** gamlastan maintainers
- **Spec:** SAML V2.0 Core §2.7.3.1 (Attribute, NameFormat); pysaml2 `AttributeConverter` / `attributemaps`
- **Implementation:** `crates/gamlastan/src/attribute_map/`, `scripts/gen_attribute_maps.py`

## Context

On the wire, SAML attributes are named by stable identifiers — `urn:oid:…` (the
`urn:oasis:names:tc:SAML:2.0:attrname-format:uri` NameFormat), `urn:mace:…`
(basic), ADFS claim URLs, etc. Application code, release policies (ADR 0008), and
operators want to work in **local friendly names** (`mail`, `eduPersonPrincipalName`,
`givenName`). pysaml2 bridges the two with `AttributeConverter` objects loaded from
a large curated collection of attribute maps; gamlastan had no equivalent, so the
release-policy engine and any attribute-facing API had nothing to resolve names
against.

Two questions: (1) what conversion abstraction, and (2) where the substantial map
*data* (hundreds of name pairs across eduPerson, SCHAC, eIDAS, X.500, ADFS, …)
comes from and how it stays faithful to pysaml2's curation.

## Decision

Add a `gamlastan::attribute_map` module with a bidirectional converter, and ship
the map data as **code-generated Rust statics** produced from pysaml2's curated
maps by `scripts/gen_attribute_maps.py`.

### Conversion model

- `StaticAttributeMap` — a shipped map: an `identifier` (the NameFormat it applies
  to) plus `fro` (wire → local) and `to` (local → wire) static slices.
- `AttributeConverter` — one NameFormat's **case-insensitive bidirectional** maps
  (`to_local`, `from_local`, `local_name`), matching pysaml2 case behaviour.
- `AttributeConverterSet` — the ordered set of converters with
  `allow_unknown_attributes` drop-or-passthrough semantics (pysaml2 §3.2).

`DEFAULT_MAPS` fixes the lookup order `[SAML_URI, BASIC, SHIBBOLETH_URI, ADFS_V20,
ADFS_V1X]`. Order is load-bearing: ADFS v1.x and v2.0 share the `unspecified`
NameFormat, so v2.0 is listed first and wins on conflicting wire names.

### Maps are generated, not hand-curated

The map modules under `maps/` (`saml_uri`, `basic`, `shibboleth_uri`, `adfs_v1x`,
`adfs_v20`) are **data only** and carry a header noting they are generated. The
generator script reads pysaml2's authoritative maps and emits the `IDENTIFIER` /
`FRO` / `TO` constants. The conversion *logic* lives in `attribute_map`; the
*data* is mechanically derived.

- ➕ Faithful to pysaml2's curation; re-runnable when upstream maps change.
- ➕ Zero runtime parsing/allocation — the maps are `&'static` slices baked into
  the binary; converters build their `HashMap`s lazily from them.
- ➖ Regenerating requires the script and a pysaml2 checkout; the generated files
  are checked in so the build never depends on that.

## Consequences

- The release-policy engine (ADR 0008) resolves policy attribute names through an
  `AttributeConverterSet`, so policies can be authored against friendly names while
  the wire carries `urn:oid:…`.
- EPTID helpers (`eptid_attribute`) live here, producing NameID-valued attributes
  (ADR 0010) under the correct wire name.
- A `base64` dev-dependency was added for the module/EPTID tests.
- Additive: no breaking change to existing types.

## Alternatives considered

- **Load maps from files at runtime** (closest to pysaml2). Rejected: adds I/O, a
  parse step, and a deployment-path dependency; defeats the zero-copy/zero-alloc
  posture. Static slices give the same data with none of that.
- **Hand-transcribe the maps into Rust.** Rejected: hundreds of pairs across many
  schemas — error-prone and drifts from upstream. Generation keeps them faithful.
- **A general config-driven converter only, no shipped maps.** Rejected: every
  consumer would have to supply the eduPerson/SCHAC/eIDAS data themselves; shipping
  the curated set is the whole point of parity with pysaml2 here.

## Validation

- `cargo test -p gamlastan` — converter tests (case-insensitive `to_local` /
  `from_local`, `allow_unknown_attributes` semantics, default-map ordering) pass
  within the 592-test suite.
- The EPTID roundtrip in `tests/cert_encryption.rs` exercises `eptid_attribute`.

