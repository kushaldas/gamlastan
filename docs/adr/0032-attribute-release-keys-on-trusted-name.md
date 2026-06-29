# ADR 0032 - Attribute release matches on trusted Name, never SP FriendlyName

- **Status:** Accepted
- **Date:** 2026-06-29
- **Deciders:** gamlastan maintainers
- **Spec:** SAML 2.0 Core §2.7.3.1 (Attribute `Name`/`FriendlyName`), CWE-345
- **Implementation:** `crates/gamlastan/src/idp/policy.rs`, `crates/gamlastan/src/attribute_map/mod.rs`

## Context

The security review (`report.md`, finding **#7**) found that IdP attribute
**release** decisions could be driven by an SP-supplied `FriendlyName`.

An SP's `<md:RequestedAttribute>` carries a wire `Name` (stable, namespaced,
e.g. an OID or URI) and an optional `FriendlyName` (a human-readable label).
Per SAML Core, `FriendlyName` "has no effect on the semantics" and is explicitly
not used for comparison — it is non-unique and, in SP metadata, fully
attacker-controllable.

The release matcher resolved the requested attribute to a local key via
`AttributeConverterSet::local_name`, whose final fallback is the attribute's own
`FriendlyName`. So an SP could request a locally-mapped attribute it was not
entitled to name by putting that attribute's local name in the `FriendlyName` of
a `RequestedAttribute` whose wire `Name` did not map:

```xml
<md:RequestedAttribute Name="urn:example:not-a-real-attribute"
                       FriendlyName="mail" isRequired="true"/>
```

If the IdP held a `mail` attribute, the matcher keyed both sides to `"mail"`
(the held attribute by its mapping, the request by its FriendlyName) and released
it — turning a non-unique label into an authorization key (CWE-345). The same
confusion applied to the entity-category release path, which keyed the SP's
required attributes the same way.

## Decision

Attribute-release matching keys the **requested** (SP-supplied) attribute only on
trusted, stable identifiers, never on its `FriendlyName`:

- A new `AttributeConverterSet::local_name_via_converters` resolves a wire
  attribute to its local name through the registered NameFormat converters
  **only** — it never falls back to the attribute's `FriendlyName`.
- `ReleasePolicy::trusted_local_key` wraps it for the policy layer.
- `matching_requested_attribute` keys the requested attribute on
  `trusted_local_key` (when a converter maps it) **or** the exact wire `Name`
  (case-insensitive). It no longer uses the requested `FriendlyName`.
- The entity-category release path keys required attributes the same way
  (trusted local key plus exact wire `Name`).

Held attributes (the IdP's own, trusted data) continue to use `local_key`
(FriendlyName-inclusive): the trust concern is only the *untrusted* requested
side.

### pysaml2-compatibility opt-in

pysaml2's release matcher (`src/saml2/assertion.py`, `_identify_attribute`,
added in pysaml2 7.1.2) *does* fall back to the requested `FriendlyName` when the
`Name`/`NameFormat` cannot be resolved through the attribute maps — and it has a
dedicated test (`test_filter_on_attributes_with_missing_name_format`). gamlastan
is intended as a pysaml2 replacement, so for migrations that genuinely depend on
that behaviour (SPs requesting **unmapped** attributes and binding by
`FriendlyName`) the legacy matching is available behind an explicit, **off-by-
default** switch:

```rust
let policy = ReleasePolicy::new().allow_friendly_name_release_matching(true);
```

When set, `requested_match_key` falls back to the requested `FriendlyName` for an
unmappable `Name`, reproducing pysaml2. This re-opens the Finding #7 surface, so
it must be used only when the SP metadata feed is trusted; it is documented as
such and defaults off.

## Consequences

- An SP can obtain an attribute only by naming it with the correct wire `Name`
  (or a `Name` the IdP's converters map). A bogus `Name` plus a matching
  `FriendlyName` no longer releases anything.
- **Behavioural change:** in a deployment with **no converters configured**, an
  SP that requested an attribute by a `Name` the IdP does not use, relying on
  `FriendlyName` to bridge to a locally-named held attribute, will no longer
  match. This is the intended hardening — release is now bound to the stable
  `Name`, per SAML Core. Such deployments must request attributes by the exact
  `Name` the IdP releases, or configure converters that map the requested `Name`
  to the local name.
- Legitimate requests that name the attribute by its real wire `Name` (with or
  without a `FriendlyName`) are unaffected, including OID/URI requests resolved
  through the default converter maps.

## Validation

- `test_friendly_name_cannot_authorize_release` (idp::policy) — secure default
- `test_friendly_name_release_matching_pysaml2_compat` (idp::policy) — the
  opt-in flag restores pysaml2 FriendlyName matching, and the default rejects the
  same request
- Existing release/entity-category tests continue to pass
  (`test_filter_on_attributes_releases_only_requested`,
  `test_entity_category_release_refeds`, …)
- `cargo test -p gamlastan`

## Related

- **ADR 0027** — registration-authority attribute-release policy selection.
- **ADR 0031** — fail-closed metadata key extraction and input validation
  (the other half of "do not trust attacker-shaped metadata").
- [`docs/security-hardening.md`](../security-hardening.md) — overview of all
  hardening controls.
