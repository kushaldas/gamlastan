# ADR 0014 — Conflict-aware entity-category matcher for REFEDS Access

- **Status:** Accepted
- **Date:** 2026-06-10
- **Deciders:** gamlastan maintainers
- **Spec:** REFEDS Personalized / Pseudonymous / Anonymous Access entity categories; SAML V2.0 Metadata Extension for Entity Attributes
- **Implementation:** `crates/gamlastan/src/idp/entity_category.rs`, `crates/gamlastan/src/idp/policy.rs`
- **Upstream reference:** pysaml2 `ft-typing` / `ft-refeds_ec` branches; commit `04f841cb` ("disable handling of REFEDS access entity categories temporarily")

## Context

Entity-category release policies decide which attributes an IdP releases to an
SP based on the category URIs the SP publishes in its
`mdattr:EntityAttributes`. gamlastan ported pysaml2's release rules as
`EntityCategoryRule`s: a rule matched when *all* of its `categories` were
present, with two modifiers — `only_required` (CoCo: release only what the SP
also requires) and `no_aggregation` (on match, *replace* everything accumulated
so far instead of adding to it).

The `no_aggregation` flag was gamlastan's attempt to model the REFEDS Access
categories (personalized / pseudonymous / anonymous). It was wrong, and for the
same reason pysaml2 disabled these categories in commit `04f841cb`:

> these need to be able to be combined with other categories just not with each
> other

The REFEDS Access categories are intended to be mutually exclusive in metadata,
but the matcher still needs deterministic behavior if an SP publishes more than
one. The intended behavior is "most restrictive wins", while still combining
with non-conflicting categories (R&S, CoCo, ESI, …):

- *personalized* matches only if *pseudonymous* and *anonymous* are absent;
- *pseudonymous* matches only if *anonymous* is absent;
- *anonymous* always matches.

`no_aggregation` could not express this. It modelled the relationship as
"replace the accumulated set", so an SP carrying both R&S **and** anonymous
would have its R&S attributes wiped — even though anonymous does not conflict
with R&S. And it offered no way to say "personalized loses to anonymous when
both are present". As a result the REFEDS Access rules were shipped opt-in and
effectively unusable, mirroring pysaml2's disabled state.

pysaml2 fixed this on its `ft-typing` / `ft-refeds_ec` branches by introducing
an `EntityCategoryMatcher` with both a `required` list **and** a `conflicts`
list, loaded from a new `RESTRICTIONS` rule format per federation module. A rule
matches when every `required` category is present and **no** `conflicts`
category is present.

## Decision

Replace `no_aggregation` with a `conflicts` list on `EntityCategoryRule`,
matching pysaml2's `EntityCategoryMatcher`.

```rust
pub struct EntityCategoryRule {
    pub categories: &'static [&'static str],   // all must be present (required)
    pub attributes: &'static [&'static str],
    pub conflicts:  &'static [&'static str],   // none may be present
    pub only_required: bool,
}

impl EntityCategoryRule {
    fn matches(&self, sp_categories: &HashSet<&str>) -> bool {
        if self.conflicts.iter().any(|c| sp_categories.contains(c)) {
            return false;
        }
        self.categories.iter().all(|c| sp_categories.contains(c))
    }
}
```

The REFEDS Access rules become:

| Rule | `categories` (required) | `conflicts` |
| --- | --- | --- |
| personalized | personalized | pseudonymous, anonymous |
| pseudonymous | pseudonymous | anonymous |
| anonymous | anonymous | — |

Rule evaluation (`releasable_attributes`) no longer clears the accumulated set;
every matching rule's attributes are aggregated, and conflicting REFEDS Access
rules simply don't match. This means at most one REFEDS Access rule contributes
for a given SP, with the most restrictive declared category winning. The three
rules are now **active by default** in the `SWAMID` policy (as in pysaml2's
`ft-typing` swamid `RESTRICTIONS`), and the standalone `REFEDS_ACCESS_RULES`
policy is retained for deployments that want only those rules. They are defined
once as shared `const`s
(`REFEDS_PERSONALIZED_RULE`, …) and referenced from both.

## Consequences

- REFEDS Access categories now behave as intended: each combines with
  R&S/CoCo/ESI, and if multiple REFEDS Access categories are published the most
  restrictive one wins. The previously broken / opt-in state is gone.
- `no_aggregation` is removed from the type. It had no analogue in pysaml2 and
  modelled a relationship that does not exist; nothing else used it.
- Because the REFEDS Access rules are now in the default `SWAMID` set, an IdP
  using `SWAMID` will release REFEDS Access attributes to SPs that publish those
  categories without extra configuration.
- Behaviour change for any caller that relied on the old "anonymous wipes R&S"
  effect — that was incorrect and is intentionally dropped.

## Alternatives considered

- **Keep `no_aggregation`, add `conflicts` alongside it.** Rejected: the two
  encode contradictory mental models; `no_aggregation` was only ever a (wrong)
  stand-in for conflicts. Carrying both invites bugs.
- **Leave REFEDS Access opt-in.** Rejected: pysaml2 moved them into the active
  swamid rule set once the matcher could express them; parity and correctness
  both argue for the same here.

## Validation

- `test_refeds_access_prefers_more_restrictive_category` — declaring multiple
  REFEDS Access categories fires only the most restrictive applicable rule.
- `test_refeds_access_combines_with_other_categories` — R&S + anonymous
  aggregates both rule outputs (no longer wiped).
- `test_refeds_personalized_alone_releases_its_attributes`,
  `test_swamid_default_includes_refeds_access`.
- `cargo test -p gamlastan` — 605 passing.

