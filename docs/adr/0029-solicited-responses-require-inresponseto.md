# ADR 0029 - Solicited responses require a present, matching InResponseTo

- **Status:** Accepted
- **Date:** 2026-06-28
- **Deciders:** gamlastan maintainers
- **Spec:** SAML 2.0 Core / Profiles, CWE-345 / CWE-294 (capture-replay)
- **Implementation:** `crates/gamlastan/src/profiles/artifact_resolution.rs`, `crates/gamlastan/src/profiles/name_id_mgmt.rs`, `crates/gamlastan/src/profiles/name_id_mapping.rs`, `crates/gamlastan/src/profiles/assertion_query.rs`, `crates/gamlastan/src/security/validation.rs`

## Context

The security review (`report.md`, findings 8–12) found a recurring pattern in
the back-channel and SP response helpers:

```rust
if let Some(irt) = &response.in_response_to {
    if irt != expected_request_id { return Err(..); }
}
// ... proceed on success
```

When the caller passes an `expected_request_id` (a **solicited** exchange) but
the response carries **no** `InResponseTo`, the check is skipped entirely and
the response is accepted. A replayed or substituted response with the field
stripped is therefore honoured.

A related gap (finding 9) existed in the shared `AssertionValidator`: a response
that *did* carry `InResponseTo` while the SP had no matching outstanding request
(`expected_request_id = None`, e.g. a tracker miss or an expired/consumed ID)
was treated as an acceptable "unsolicited" response and passed checks 3 and 17.

## Decision

A solicited response must carry request correlation, and a dangling
correlation value must fail closed:

- The artifact, ManageNameID, NameIDMapping, and assertion-query helpers now
  require `InResponseTo` to be **present and equal** to the expected request ID.
  Absence is rejected with the helper's correlation error.
- In `AssertionValidator`, a response (check 3) or bearer
  `SubjectConfirmationData` (check 17) that carries `InResponseTo` while no
  outstanding request was found now **fails**. A genuinely unsolicited
  (IdP-initiated) response MUST NOT carry `InResponseTo`, so a dangling value
  signals a stale, replayed, or misdirected message.

Genuinely unsolicited responses (no `InResponseTo`, `expected_request_id =
None`) continue to pass.

## Consequences

- Stripping `InResponseTo` no longer bypasses correlation on solicited paths.
- The application must distinguish "intentional unsolicited SSO" (no
  `InResponseTo` present) from a request-tracker miss; the validator no longer
  silently accepts the latter.
- Integrations relying on these helpers inherit fail-closed correlation without
  additional code.

## Validation

- `test_process_artifact_response_missing_irt_rejected`
- `test_process_manage_name_id_response_missing_irt_rejected`
- `test_process_name_id_mapping_response_missing_irt_rejected`
- `test_process_query_response_missing_irt_rejected`
- `test_dangling_in_response_to_rejected`
- `cargo test -p gamlastan`
