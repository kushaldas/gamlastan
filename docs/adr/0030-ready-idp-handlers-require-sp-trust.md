# ADR 0030 - Ready-made IdP handlers require SP trust and fail closed

- **Status:** Accepted
- **Date:** 2026-06-28
- **Deciders:** gamlastan maintainers
- **Spec:** SAML 2.0 Profiles (SSO, SLO, Artifact Resolution), CWE-346 / CWE-306 / CWE-862
- **Implementation:** `crates/gamlastan-actix/src/config.rs`, `crates/gamlastan-actix/src/idp.rs`

## Context

The security review (`report.md`, findings 4, 5, 13) found that the ready-made
Actix IdP handlers acted on attacker-controllable input without binding it to
trusted SP metadata:

- **SSO** called `process_authn_request(&req, None)`, so the core profile
  trusted the request-supplied `AssertionConsumerServiceURL`. A requester could
  have a signed assertion delivered to an ACS URL they control (CWE-346).
- **Artifact resolution** consumed the one-time artifact from the store without
  authenticating the requester (CWE-306) — anyone holding an artifact could
  drain it or burn it.
- **SLO** destroyed sessions by request-supplied `NameID` after only structural
  validation, with no signature, issuer, or destination check (CWE-306/862).

`IdpConfig` carried no SP trust material, so the handlers had nothing to verify
against. The report frames these as "the deployment must wrap the handler", but
shipping insecure-by-default handlers in a library is itself the hazard.

## Decision

`IdpConfig` gains a registry of trusted SPs and the handlers fail closed when
the relevant trust material is absent:

- `IdpConfig::trusted_sps: Vec<TrustedSp>` (entityID + `SpSsoDescriptor`), with
  `with_trusted_sp`, `trusted_sp`, `verifier_for`, and `trusted_sp_verifier`
  accessors.
- `IdpConfig::sp_resolver: Option<Arc<dyn TrustedSpResolver>>` — an async
  resolver consulted when an SP is **not** statically registered. This is the
  federation/MDQ path: a deployment with an MDQ setup and no static SPs
  implements `TrustedSpResolver` over a `gamlastan_mdq::MdqClient` (which
  signature-verifies SP metadata against the federation trust anchor) and
  registers it with `with_sp_resolver`. The handlers resolve the issuer's
  metadata from the static registry first, then the resolver, and only fail
  closed when neither yields trusted metadata. `gamlastan-actix` does not depend
  on `gamlastan-mdq`; the application wires them together.
- **SSO** requires the AuthnRequest `Issuer` to be a registered trusted SP and
  passes that SP's metadata to `process_authn_request`, so a request-supplied
  ACS URL not in metadata is rejected.
- **Artifact resolution** and **SLO** require the message to be signed by a
  trusted SP (verified and bound to the message ID), with the SLO path also
  checking the issuer is trusted and the `Destination` matches the IdP's SLO
  endpoint, before any state is mutated.
- An explicit escape hatch, `allow_unauthenticated_backchannel`, lets
  deployments that authenticate the transport (e.g. mutual TLS) opt out of the
  message-signature requirement. It defaults to `false`.

## Consequences

- The ready handlers are safe by default: with no trusted SPs configured *and*
  no resolver, they refuse to issue assertions, resolve artifacts, or destroy
  sessions.
- Static deployments register their partner SPs; federation deployments register
  an MDQ-backed `TrustedSpResolver` so trust is learned dynamically — neither is
  broken by the fail-closed default.
- mTLS-fronted deployments retain a supported unauthenticated-message path via
  the explicit opt-in.

## Validation

- `test_slo_rejected_when_no_trusted_sps`,
  `test_slo_rejected_for_untrusted_issuer`
- `test_artifact_resolve_rejected_when_no_trusted_sps`
- `test_backchannel_opt_in_allows_unauthenticated`
- `test_trusted_sp_lookup`
- `cargo test -p gamlastan-actix`
