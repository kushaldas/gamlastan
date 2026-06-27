# ADR 0026 -- Runtime, owned entity-category rules and policies

- **Status:** Accepted
- **Date:** 2026-06-27
- **Deciders:** gamlastan maintainers
- **Implementation:** `crates/gamlastan/src/idp/entity_category.rs`,
  `crates/gamlastan/src/idp/policy.rs`
- **Related:** ADR 0014 (conflict-aware entity-category matcher), ADR 0008
  (IdP server infrastructure)

## Context

The entity-category attribute-release engine (ADR 0014) ships a set of
federation policies (`SWAMID`, `REFEDS`, `INCOMMON`, `EDUGAIN`,
`REFEDS_ACCESS_RULES`, `AT_EGOV_PVP2_POLICY`). They were modelled as `&'static`
data: `EntityCategoryRule` and `EntityCategoryPolicy` hold
`&'static [&'static str]` slices, and the shipped policies are `pub static`
values. This is ideal for compile-time, zero-allocation defaults.

It is also a hard wall for any caller that needs to define an entity category
the library does not ship - a deployment with a house category, or a language
binding (pygamlastan) whose users build rules at runtime from data that does not
exist at compile time. There was no way to construct an `EntityCategoryRule`
from owned `String`/`Vec<String>` data, so "bring your own entity category" was
impossible without forking the crate. `PolicyEntry::with_entity_categories` only
accepted `Vec<&'static EntityCategoryPolicy>`, propagating the `'static`
constraint into the release-policy engine.

## Decision

Add an owned, runtime-constructible mirror of the static types, keeping the
static fast path unchanged:

- `OwnedEntityCategoryRule { categories: Vec<String>, attributes: Vec<String>,
  conflicts: Vec<String>, only_required: bool }` with a builder
  (`new(categories, attributes)`, `with_conflicts`, `with_only_required`). All
  fields are public, so a caller has full control over a rule.
- `OwnedEntityCategoryPolicy { name: String, rules: Vec<OwnedEntityCategoryRule> }`
  with `new`, `with_rule`, `push_rule`, and `extend_from_static` (seed from a
  shipped policy, then append custom rules).
- `EntityCategoryRule::as_owned` / `EntityCategoryPolicy::as_owned` clone the
  static forms into the owned forms, so shipped and custom rules mix freely.
- `releasable_attributes_owned`, the owned-policy counterpart of
  `releasable_attributes`. The match/release step is shared between the two via
  a private helper, so behavior cannot drift.
- `PolicyEntry::with_owned_entity_categories` accepts owned policies;
  `with_entity_categories` keeps its `&'static` signature but now stores the
  policies in owned form internally (converting via `as_owned`). The
  `PolicyEntry.entity_categories` field became `Option<Vec<OwnedEntityCategoryPolicy>>`.

The static constants and their semantics are untouched, so existing callers and
the shipped policies are unaffected; the owned path is purely additive.

## Consequences

### Positive

- Deployments and language bindings can define arbitrary entity categories at
  runtime, with the same matching (`conflicts`, `only_required`) semantics as
  the shipped rules, and combine them with shipped policies.
- One release algorithm serves both static and owned policies (shared helper),
  so a custom rule behaves exactly like a built-in one.
- No change to the zero-allocation static defaults or to existing call sites.

### Negative / costs

- `with_entity_categories` now allocates (clones the static policies into owned
  form) at policy-construction time. This happens once at config time, not per
  request, so the cost is negligible.
- Two parallel rule/policy types exist (static and owned). The owned type is the
  one bindings use; the static type remains the ergonomic default in Rust.

### Alternatives considered

- **Make the existing types generic over `Cow<'static, str>`.** Rejected: it
  would force every shipped `static` policy and every call site to change, for
  no benefit to Rust callers, and `Cow` arrays are awkward in `const` context.
- **Only bind the shipped policies, no custom categories.** Rejected: it leaves
  "bring your own entity category" impossible, which is an explicit requirement.
