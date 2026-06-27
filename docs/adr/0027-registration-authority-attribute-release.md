# ADR 0027 -- Registration-authority-based attribute-release policy selection

- **Status:** Accepted
- **Date:** 2026-06-27
- **Deciders:** gamlastan maintainers
- **Spec:** SAML V2.0 Metadata Extensions for Registration and Publication
  Information (`mdrpi:RegistrationInfo`), SAML V2.0 Metadata Extensions for
  Entity Attributes (`mdattr:EntityAttributes`)
- **Implementation:** `crates/gamlastan/src/metadata/types/md_extensions.rs`,
  `crates/gamlastan/src/metadata/types/entity_descriptor.rs`,
  `crates/gamlastan/src/idp/policy.rs`
- **Related:** ADR 0008 (IdP server infrastructure), ADR 0014 / ADR 0026
  (entity categories)

## Context

In SWAMID and other federations an IdP selects an SP's attribute-release policy
by the SP's **registration authority** -- the federation operator that
registered the SP, published in metadata as
`mdrpi:RegistrationInfo/@registrationAuthority`. A common rule is "release the
full attribute set to any SP registered by `http://www.swamid.se/`". pysaml2's
`Policy.get` implements this with the precedence SP entity ID > registration
authority > default.

gamlastan's `ReleasePolicy` (ADR 0008) keyed entries only on the SP entity ID
(plus a `default`), and the metadata layer stored `Extensions` as opaque raw
XML, so neither the registration authority nor the SP's published entity
categories were reachable. An IdP could not express a per-federation policy, and
could not feed the entity-category engine the SP's categories from metadata --
the two facts the SWAMID release rules depend on.

## Decision

Parse the two release-relevant metadata extensions, and let the policy resolve
by registration authority:

- New `metadata::types::md_extensions::MdExtensions` parses, from the raw
  `Extensions` XML, `mdrpi:RegistrationInfo/@registrationAuthority` and the
  `mdattr:EntityAttributes` `(Name, values)` pairs. Parsing reuses the
  `parse_secure` path (ADR 0024: DTD rejected, resources bounded) and is
  **fail-soft**: missing or malformed extensions yield an empty value, never an
  error, so a single bad SP cannot break policy evaluation.
- `EntityDescriptor` gains `registration_authority()`, `entity_categories()`
  (the `http://macedir.org/entity-category` values), and the general
  `entity_attribute_values(name)` (e.g. for `subject-id:req`).
- `ReleasePolicy` carries an SP-entity-id -> registration-authority map.
  `set_registration_authority` / `with_registration_authority` populate it
  directly, and `register_sp_metadata(&EntityDescriptor)` reads it from the SP's
  metadata. The internal `get` resolver now tries the SP entry, then the
  registration-authority entry, then `default`, matching pysaml2's precedence.

The registration-authority map is consulted only as a fallback, so SPs with
their own entry are unaffected, and a policy with no registration authorities
configured behaves exactly as before (SP > default).

## Consequences

### Positive

- IdPs can express federation-wide release policy keyed on the registration
  authority, the SWAMID/eduID deployment pattern, with the same precedence as
  pysaml2.
- The SP's published entity categories and `subject-id:req` are now reachable
  from metadata, so the entity-category and subject-id release logic can run on
  real metadata rather than caller-supplied category lists.
- Fail-soft parsing means a malformed extension on one SP degrades to "no
  signal" for that SP rather than failing the request.

### Negative / costs

- The extensions are parsed on demand from raw XML each call; for hot paths a
  caller should read `EntityDescriptor::md_extensions()` once and reuse it. The
  policy map itself is built at config time, not per request.
- gamlastan still does not model `RegistrationInfo` as typed metadata fields;
  only the registration authority and entity attributes are surfaced, which is
  all attribute-release needs. Fuller `mdrpi` typing is deferred until a use
  case requires it.

### Alternatives considered

- **Pass the registration authority into every resolution method.** Rejected: it
  would break every public `ReleasePolicy` method signature; the internal
  fallback map keeps them stable.
- **Require the caller to pre-resolve the policy key.** Rejected: it pushes the
  metadata-parsing and precedence logic onto every integrator, defeating the
  point of matching pysaml2's behavior in the library.
