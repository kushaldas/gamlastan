# ADR 0034 - Fail-closed federation helper boundaries

- **Status:** Accepted
- **Date:** 2026-07-01
- **Deciders:** gamlastan maintainers
- **Spec:** SAML 2.0 Web Browser SSO / ECP (PAOS) / IdP Discovery Service Protocol, SAML Errata E90, CWE-79 / CWE-601 / CWE-918 / CWE-345 / CWE-384
- **Implementation:** `crates/gamlastan-mdq/src/fetch.rs`, `crates/gamlastan-mdq/src/client.rs`, `crates/gamlastan/src/security/validation.rs`, `crates/gamlastan/src/security/error.rs`, `crates/gamlastan/src/profiles/idp_discovery.rs`, `crates/gamlastan/src/profiles/sso/ecp.rs`, `crates/gamlastan/src/profiles/error.rs`, `crates/gamlastan-actix/src/sp.rs`, `crates/gamlastan-actix/src/config.rs`

## Context

A security review of the federation-facing helpers found several boundaries that
**failed open**: when an input was untrusted, absent, or only partially known,
the default behaviour was permissive rather than rejecting. Each one is reachable
from a remote party (a hostile MDQ server, a crafted SAML Response, a
DiscoveryService return URL, or a PAOS conversation partner).

- **MDQ transport followed redirects.** The default `ReqwestFetcher` used
  reqwest's default client, which follows redirect chains. A hostile or
  compromised MDQ server could 3xx the fetcher toward internal addresses
  (SSRF) instead of returning metadata.
- **Core validation accepted unusable Responses.** The validator ran the
  Section 7.2 checks without first asserting the response envelope was usable,
  so a non-`Success` status or an assertionless `<Response>` could pass through
  the response-level layer instead of being rejected up front.
- **Discovery return URLs were trusted when metadata was empty.** When no
  DiscoveryResponse endpoints were registered, a request-supplied return URL was
  accepted, letting an attacker redirect the browser to an arbitrary location
  (open redirect / phishing).
- **ECP (PAOS) responses were not correlated.** The phase-2 PAOS response's
  `refToMessageID` was neither preserved nor checked against the SP's phase-1
  `paos:Request/@messageID`, so a response from an unrelated conversation could
  be accepted.
- **The default Actix ACS success page reflected the NameID unescaped.** The
  bundled success page interpolated the subject NameID into HTML without
  escaping (reflected XSS in the default handler).
- **Request-ID replay TTL was enforced only at store time.** The in-memory
  request-ID tracker purged expired entries when a *new* ID was stored, so an
  expired ID could still be consumed if no later store had triggered a purge.

## Decision

Every boundary now fails closed by default:

- **MDQ redirects disabled.** `ReqwestFetcher` builds its client with
  `redirect::Policy::none()`; the "best-effort" fallback that silently followed
  redirects is removed. Because the hardened client is now the only path,
  construction is fallible: `ReqwestFetcher::try_default` and
  `MdqClient::try_new` return `Result`, and the convenience `Default`/`new`
  panic only under the same TLS-init failure that `reqwest::Client::new` itself
  panics on (never falling back to a redirect-following client).
- **Response-envelope checks.** The validator adds checks 33 (status is
  `Success`) and 34 (at least one plaintext/decrypted `Assertion` present); a
  response carrying only `EncryptedAssertion` reports "decrypt before
  validation" rather than "missing Assertion".
- **Discovery return URL matching.** A request-supplied return URL MUST match a
  registered DiscoveryResponse endpoint; empty metadata does not make it
  trustworthy. A non-matching URL is rejected with
  `ProfileError::DiscoveryReturnUrlNotRegistered`.
- **ECP conversation correlation.** The parsed SP-side response exposes
  `ref_to_message_id` (from the PAOS response `refToMessageID`), and
  `verify_ref_to_message_id` rejects a mismatch
  (`ProfileError::EcpMessageIdMismatch`) or an absent reference when one is
  expected (`ProfileError::EcpMissingResponseReference`).
- **NameID escaping.** The default Actix ACS success page passes the NameID
  through `escape_html_text` (escapes `& < > " '`) before interpolation.
- **Request-ID TTL at consume.** `InMemoryRequestIdTracker::consume` checks the
  entry's age against the TTL and rejects an expired ID even when no later store
  has purged it.

## Consequences

- The default MDQ fetcher no longer follows redirects; deployments that relied
  on redirect-following must supply a custom `MetadataFetcher`, and code that
  cannot tolerate a startup panic should use `try_default` / `try_new`.
- Non-`Success` and assertionless responses are rejected at the envelope layer.
- Discovery requests with an unregistered return URL are rejected instead of
  redirecting the browser to an attacker-chosen location.
- ECP responses that do not correlate to the SP's phase-1 request are rejected.
- The default ACS page is safe against a NameID-borne reflected XSS.
- An expired request ID cannot be replayed via the consume path.

## Validation

- `test_request_id_tracker_consume_rejects_expired_without_later_store`
- `test_escape_html_text_for_default_acs_page`
- `test_response_status_must_be_success`, `test_response_must_contain_assertion`,
  `test_encrypted_only_response_reports_decrypt_needed`
- `test_create_discovery_service_response_rejects_return_without_registered_endpoints`
- `test_parse_ecp_response_at_sp_exposes_and_verifies_ref_to_message_id`,
  `test_ecp_response_ref_to_message_id_required_when_expected`
- `cargo test -p gamlastan -p gamlastan-mdq -p gamlastan-actix`
