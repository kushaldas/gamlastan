# ADR 0017 - Web SSO requires audience and bearer expiry

- **Status:** Accepted
- **Date:** 2026-06-21
- **Deciders:** gamlastan maintainers
- **Spec:** SAML 2.0 Web Browser SSO Profile, SAML 2.0 Core Conditions and bearer SubjectConfirmation
- **Implementation:** `crates/gamlastan/src/security/validation.rs`

## Context

The assertion validator previously treated missing `Conditions` as success for
NotBefore, NotOnOrAfter, AudienceRestriction, OneTimeUse, and ProxyRestriction.
It also treated missing bearer `SubjectConfirmationData@NotOnOrAfter` as
success.

For Web Browser SSO this is too permissive. A bearer assertion without an
audience restriction is not clearly bound to this SP. A bearer assertion without
an expiry is harder to constrain after theft or cross-SP substitution.

## Decision

For Web Browser SSO validation:

1. Missing assertion `Conditions` fails the assertion NotOnOrAfter check.
2. Missing assertion `Conditions` fails the AudienceRestriction check.
3. Missing bearer `SubjectConfirmationData@NotOnOrAfter` fails the bearer
   confirmation expiry check.
4. Optional conditions that are not security-critical for this binding, such as
   OneTimeUse and ProxyRestriction, remain informational passes when the whole
   Conditions element is absent.

The validator still accepts an omitted NotBefore because NotBefore is an
optional lower-bound time constraint. The expiry and audience checks are the
required security controls for this Web SSO path.

## Consequences

- Assertions without an audience restriction are rejected.
- Bearer confirmations without an explicit expiry are rejected.
- Deployments that accepted unbounded or unscoped bearer assertions must fix
  their IdP configuration.
- Validation output now distinguishes missing required controls from optional
  controls that were not present.

## Validation

- `test_missing_conditions_fails_audience_and_expiry`
- `test_missing_bearer_not_on_or_after_fails`
- `cargo test -p gamlastan`

