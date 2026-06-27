# ADR 0025 -- Separate the authentication instant from the issue instant in response construction

- **Status:** Accepted
- **Date:** 2026-06-27
- **Deciders:** gamlastan maintainers
- **Issue:** [#15](https://github.com/kushaldas/gamlastan/issues/15)
- **Spec:** SAML 2.0 Core 2.7.2 (`AuthnStatement/@AuthnInstant`), Profiles 4.1.4.2
- **Implementation:** `crates/gamlastan/src/profiles/sso/{web_browser,idp}.rs`,
  `crates/gamlastan/src/profiles/swedenconnect/idp.rs`,
  `crates/gamlastan-actix/src/idp.rs`

## Context

The IdP-side response builders (`profiles::sso::idp::create_response` and
`create_unsolicited_response`, plus the Sweden Connect wrapper
`profiles::swedenconnect::idp::create_response`) took a single
`now: DateTime<Utc>` parameter and fanned it out to every time-valued field of
the generated `Response`:

- Response `IssueInstant`
- Assertion `IssueInstant`
- `Conditions/@NotBefore` and `@NotOnOrAfter`
- `SubjectConfirmationData/@NotOnOrAfter`
- `AuthnStatement/@AuthnInstant`

These collapse two semantically distinct instants:

- **Issue instant** -- when the response/assertion document is generated. Every
  validity window derives from it (the `NotOnOrAfter` values are
  `issue_instant + lifetime`).
- **Authentication instant** -- when the principal actually authenticated to the
  IdP. With Single Sign-On this can be substantially earlier than document
  generation, because an existing session is reused without re-prompting.

Conflating them forces `AuthnStatement/@AuthnInstant` to equal document issue
time. That misrepresents authentication freshness to a service provider that
makes decisions on it -- for example an SP using `RequestedAuthnContext` /
`ForceAuthn` or its own max-age policy. The library would always claim the user
had just authenticated, even when the assertion was minted from a hours-old SSO
session.

Issue #15 proposed three fixes:

1. Add an optional `authn_instant` to `ResponseOptions`.
2. Add an explicit `authn_instant` parameter to `create_response`.
3. Introduce a dedicated times struct.

## Decision

Adopt a trimmed version of option 3: replace the bare `now` parameter with a
small, two-field value type.

```rust
#[derive(Debug, Clone, Copy)]
pub struct ResponseTimes {
    pub issue_instant: DateTime<Utc>,
    pub authn_instant: DateTime<Utc>,
}

impl ResponseTimes {
    pub fn at(now: DateTime<Utc>) -> Self { /* both = now */ }
}
```

`create_response`, `create_unsolicited_response`, and the Sweden Connect wrapper
now take `times: ResponseTimes` in place of `now`. Inside `create_response`,
`times.issue_instant` drives the document/validity instants and
`times.authn_instant` drives `AuthnStatement/@AuthnInstant`.

Only the two genuinely independent instants are modelled. The derived
`NotBefore` / `NotOnOrAfter` values are deliberately NOT exposed as fields --
they remain computed from `issue_instant + lifetime` so they cannot be set
inconsistently.

To make the capability reachable through the actix integration,
`gamlastan_actix::idp::AuthnCallbackResult` gains an
`authn_instant: Option<DateTime<Utc>>`. The SSO handler builds
`ResponseTimes { issue_instant: now, authn_instant: result.authn_instant.unwrap_or(now) }`,
so a callback that reuses a session reports the real authentication time, while
`None` preserves the fresh-login behaviour.

## Consequences

- Callers that always authenticate fresh per request use
  `ResponseTimes::at(now)` and behave exactly as before. The conversion at the
  in-tree call sites (`example-idp`, the actix handler) is mechanical.
- This is a breaking API change to three public functions and one public struct.
  The project is pre-1.0 (v0.6.0) with no significant external consumers, so we
  break cleanly rather than carry an optional-field shim (option 1) that would
  split the time inputs across two locations.
- Named struct fields prevent the footgun of option 2: two adjacent
  `DateTime<Utc>` parameters on a security-sensitive constructor can be
  transposed silently, producing a wrong `AuthnInstant` -- exactly the class of
  bug this change exists to prevent.

## Alternatives considered

- **Option 1 -- optional `authn_instant` in `ResponseOptions`.** Rejected:
  `now` is already an out-of-band parameter, so the authentication time would
  live in the options bag while the issue time stays a positional argument --
  two locations for one concern. The issue author's own instinct ("does not feel
  like the right structural location") matches this.
- **Option 2 -- a second bare `authn_instant: DateTime<Utc>` parameter.**
  Rejected as the default because it places two same-typed timestamp arguments
  next to each other; a transposition compiles cleanly and silently corrupts
  `AuthnInstant`. `ResponseTimes` keeps option 2's clarity while removing that
  hazard at essentially zero extra structural cost.
- **Full option 3 -- a struct carrying every instant** (including the derived
  `NotBefore`/`NotOnOrAfter`). Rejected as over-broad: only two instants are
  independent, and exposing the derived ones invites inconsistent inputs. The
  struct can grow later if a real need appears.

## Validation

- `cargo build --workspace` -- clean.
- `cargo test -p gamlastan --lib` -- 637 passing, including the new
  `test_create_response_distinct_authn_instant` regression (a reused-session
  case asserting that document/validity instants track generation time while
  `AuthnInstant` reflects the earlier authentication time) and a tightened
  `test_create_response` (asserts `ResponseTimes::at` collapses both instants).
- `cargo test -p gamlastan-actix --lib` -- 54 passing.
