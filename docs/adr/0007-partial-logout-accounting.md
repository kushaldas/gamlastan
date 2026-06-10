# ADR 0007 — Partial logout is terminal but not counted as success

- **Status:** Accepted
- **Date:** 2026-06-10
- **Deciders:** gamlastan maintainers
- **Spec:** SAML V2.0 Profiles, section 4.4 Single Logout; `urn:oasis:names:tc:SAML:2.0:status:PartialLogout`
- **Implementation:** `crates/gamlastan/src/profiles/logout.rs`

## Context

SAML Single Logout allows a responder to return top-level `Success` together
with the second-level status code `PartialLogout`. On the wire, that means the
request was processed, but at least one participant could not be fully logged
out.

The SP-side logout orchestrator used `Status::is_success()` to drive its target
state transition. Because that helper only inspects the top-level status code,
`PartialLogout` responses were marked as `Succeeded`. That inflated
`successful_logouts` and hid a real operational failure in the orchestration
summary.

## Decision

Treat `PartialLogout` as a terminal failure for orchestration state and
progress accounting.

Specifically:

- `handle_response()` still reports the wire-level outcome through
  `LogoutResponseOutcome { success: true, partial: true }` when the response is
  top-level `Success` with `PartialLogout`.
- The target state recorded in `SpLogoutOrchestrator` becomes
  `TargetLogoutState::Failed { reason: STATUS_PARTIAL_LOGOUT }`.
- `is_complete()` continues to mean that every target reached a terminal state,
  not that every target succeeded.

This preserves the protocol signal while keeping orchestration metrics honest.

## Consequences

- `progress().successful_logouts` now counts only fully successful logout
  targets.
- A `PartialLogout` still terminates the target and does not leave the
  orchestrator waiting indefinitely.
- Existing consumers that inspect `LogoutResponseOutcome.partial` keep the
  wire-level distinction without relying on progress counters.

## Alternatives considered

- **Count `PartialLogout` as success because the top-level status is
  `Success`.** Rejected because it hides a failed logout propagation.
- **Add a third orchestrator state for partial success.** Deferred. The current
  public progress API is binary (`successful_logouts` plus
  `failed_participants`), so mapping partial to the failed bucket is the
  smallest correct behavior change.

## Validation

- Extended `test_orchestrator_partial_logout_response` to assert failed-state
  accounting.
- Re-ran `cargo test -p gamlastan test_orchestrator`.
