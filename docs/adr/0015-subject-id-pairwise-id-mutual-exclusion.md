# ADR 0015 — Prefer pairwise-id when subject-id:req is any

- **Status:** Accepted
- **Date:** 2026-06-10
- **Deciders:** gamlastan maintainers
- **Spec:** OASIS SAML V2.0 Subject Identifier Attributes Profile (`subject-id`, `pairwise-id`, and the `subject-id:req` metadata entity attribute)
- **Implementation:** `crates/gamlastan/src/idp/entity_category.rs`, `crates/gamlastan/src/idp/policy.rs`
- **Upstream reference:** pysaml2 PR [#987](https://github.com/IdentityPython/pysaml2/pull/987) ("do not assert both subject-id and pairwise-id")

## Context

The Subject Identifier Attributes Profile defines two identifiers an IdP may
assert about a subject:

- `subject-id` — a stable, non-targeted identifier;
- `pairwise-id` — a targeted, per-SP (privacy-preserving) identifier.

An SP declares which it wants via the `subject-id:req` metadata entity
attribute, whose value may be `subject-id`, `pairwise-id`, `none`, or `any`.
The profile standardizes that metadata signal, but it also says that it "does
not define specific normative behavior on the part of asserting parties in
response to this metadata".

The problem case is `any`: it means "either identifier is acceptable". If the
IdP's release policy would emit both `subject-id` and `pairwise-id` (e.g. both
appear in an entity-category attribute list, or both are individually
requested), a naive filter releases both. pysaml2 narrows that case by keeping
the more privacy-preserving `pairwise-id`.

pysaml2 fixed this in PR #987 by adding `_subject_id_or_pairwise_id()`, called
from `Policy.filter()` only when the SP's `subject_id_requirement_type()` is
`any`: when both identifiers are about to be released it drops `subject-id`,
keeping the more privacy-preserving `pairwise-id`.

## Decision

Mirror pysaml2 PR #987 as a final step of the release pipeline.

1. Model the requirement as an enum read from SP metadata:

   ```rust
     pub enum SubjectIdReq { None, SubjectId, PairwiseId, Any }
   impl SubjectIdReq {
       pub fn from_metadata_values(values: &[String]) -> Self { /* "none" | "any" | ... */ }
   }
   ```

   Callers read the `subject-id:req` entity attribute
   (`urn:oasis:names:tc:SAML:profiles:subject-id:req`) from the SP's metadata
   `EntityAttributes` — the same source already used for entity categories — and
   pass the parsed `SubjectIdReq` into the policy. The metadata value `none`
   maps to `SubjectIdReq::None`.

2. A small, reusable helper expresses the rule on the lowercased local-name set:

   ```rust
   pub fn prefer_pairwise_over_subject_id(req: SubjectIdReq, released: &mut HashSet<String>) {
       if req != SubjectIdReq::Any { return; }
       if released.contains("pairwise-id") && released.contains("subject-id") {
           released.remove("subject-id");
       }
   }
   ```

3. `ReleasePolicy::filter()` (and `restrict()`) take a `subject_id_req:
  SubjectIdReq` argument and apply the rule as **step 4**, after
   entity-category / requested-attribute filtering and IdP attribute/value
  restrictions, before the `fail_on_missing_requested` recheck. This is an
  intentionally narrow pysaml2-parity rule for `any`; non-`any` values are left
  unchanged.

`subject_id_req` is passed explicitly rather than re-derived inside the policy:
the requirement lives in the entity-wide `EntityAttributes`, not in the
role-level `SpSsoDescriptor` that `restrict()` receives, and this matches how
`sp_entity_categories` is already threaded in by the caller.

## Consequences

- When `subject-id:req` is `any` and both identifiers would be released, only
  `pairwise-id` goes out — matching pysaml2 and the privacy-preserving choice.
- Non-`any` cases remain unchanged by design. That includes explicit metadata
  value `none`, which maps to `SubjectIdReq::None`.
- `filter()` / `restrict()` gain one parameter. The only call sites today are
  tests; they pass `SubjectIdReq::None`, preserving prior behaviour.
- The decision deliberately keeps `pairwise-id` (drop `subject-id`), matching
  pysaml2 and the profile's privacy intent.

## Alternatives considered

- **Drop `pairwise-id`, keep `subject-id`.** Rejected: contradicts the profile's
  privacy intent and pysaml2's choice.
- **Apply the rule unconditionally (ignore `subject-id:req`).** Rejected:
  outside the explicit `any` case, the profile allows assertions carrying one
  or both identifier attributes and does not require asserting parties to pick
  one; the de-duplication is only justified when the SP has already said
  either identifier is acceptable.
- **Re-derive the requirement inside the policy from `SpSsoDescriptor`.**
  Rejected: the value is an entity-level `EntityAttributes` attribute, not part
  of the SSO descriptor; the caller already extracts entity attributes.

## Validation

- `test_subject_id_req_any_prefers_pairwise` — `any` + both present drops
  `subject-id`, keeps `pairwise-id` and other attributes; non-`any` keeps both.
- `test_subject_id_req_any_keeps_lone_subject_id` — `any` with only `subject-id`
  present keeps it.
- `test_subject_id_req_parsing`, `test_prefer_pairwise_over_subject_id`.
- `cargo test -p gamlastan` — 605 passing.

