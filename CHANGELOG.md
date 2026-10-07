# Changelog

All notable changes to this repository will be documented in this file.

The project is still pre-1.0, so minor releases may include behavior changes
where needed to correct protocol handling.

## [Unreleased]

### Added

- Added `idp::orchestrator`, a new module composing the existing IdP
  primitives (`ReleasePolicy`, `IdentDb`, `AuthnBroker`, `AssertionStore`)
  into the actual SAML Web Browser SSO response-assembly flow:
  `ResponseEngine`, `check_request` (the pure ForceAuthn × IsPassive ×
  RequestedAuthnContext decision matrix), `create_authn_response` /
  `create_denial_response`, the pluggable `AttributeRelease` seam
  (`ReleasePolicy`, `PassThroughRelease`, `ChainedRelease`), and a closed
  `Denial` enum with a fixed SAML `Status` mapping, including `AuthnFailed` and
  `Cancelled` for a failed or user-cancelled login. Denials are always signed
  unconditionally. `example-idp` is rewritten onto this engine, replacing its
  hand-rolled response-assembly and NameID/authn-context negotiation code.
  With no `RequestedAuthnContext`, any session/method is accepted regardless
  of what the `AuthnBroker` happens to have registered (an inline/ad-hoc
  method never registered in the broker is not rejected just because the
  broker also has an `unspecified` baseline). `AuthnMethodRef::resolve`
  returns `Option<(String, Option<String>)>`: a `BrokerReference` naming no
  registered method resolves to `None` rather than falling back to treating
  the opaque reference string itself as the AuthnContext class ref, so a
  stale or mistyped reference can no longer become a bogus
  `AuthnContextClassRef` in a signed assertion. An `AuthnMethodRef::Inline`
  method (documented as usable without any broker registration) whose
  class ref is a literal, exact match for the request is accepted even when
  that class ref was never registered with the `AuthnBroker` -
  `check_request`'s session-reuse check and `create_authn_response`'s
  revalidation both check `Comparison="exact"` by literal match against the
  requested class refs directly, rather than requiring the broker to have a
  registration for it (which `AuthnBroker::pick`'s exact branch needs, but
  satisfying an already-resolved method's literal class ref does not).
- Added `ResponseParams::new` and `ResponseParams::from_entity`, which check
  that the SP entity descriptor is the SP the request was validated for
  (`ProfileError::SpEntityMismatch`), `new` also requires the supplied SP role to
  be one of that descriptor's own (`ProfileError::SpRoleMismatch`), and `from_entity` takes the SAML 2.0 SP
  role from that same descriptor. The descriptor's entity categories and
  `subject-id:req` decide what is released, so pairing one SP's request with
  another SP's descriptor would release attributes under the wrong policy. The
  fields are public, so `create_authn_response` and `create_denial_response`
  repeat the check; the Actix handler builds its parameters through `new`.
- Added `gamlastan-actix`'s `AuthnSubjectCallback`, a higher-level companion
  to the existing `AuthnCallback`, returning an `AuthnSubjectResult` of
  `Authenticated(AuthenticatedSubject) | Redirect(HttpResponse) |
  Deny(Denial)` for handlers built on `idp::orchestrator`. It receives the
  processed request, the parsed `&AuthnRequest`, the `&Disposition` and the
  `HttpRequest`. The parsed request carries what `ProcessedAuthnRequest`
  leaves out - `Scoping` (a proxy must enforce `ProxyCount` / `IDPList`) and the
  requested `Subject` - which a POST callback could not otherwise read, as the
  form body is already consumed. The SSO handler calls
  `idp::orchestrator::check_request` itself before invoking the callback and
  handles a `Deny` disposition directly (a signed protocol error; the callback
  is never invoked for it), so a callback cannot redirect to a login form for
  `IsPassive` or reuse a session `ForceAuthn` should have defeated.
  `AuthnCallback`, the lower-level path, is unchanged and does not receive the
  request; its documentation points to `AuthnSubjectCallback`.
- Added `ResponseOptions::authenticating_authorities` and an `impl Default`
  for `ResponseOptions`. `create_response` now writes the field into the
  `AuthnContext` instead of hardcoding an empty list, so proxying IdPs can
  name the authority they relied on (SAML Core §2.7.2.2).
- Added `ProcessedAuthnRequest::requested_sp_name_qualifier`, extracted from
  the request's `NameIDPolicy/@SPNameQualifier`, so `IdentDb::construct_nameid`
  can honour it instead of always falling back to the SP entity ID.
- Added `PolicyEntry::with_session_lifetime` / `ReleasePolicy::session_lifetime`,
  separate from the existing assertion `lifetime`, so `AuthnStatement/@SessionNotOnOrAfter`
  no longer has to collapse to the (typically much shorter) assertion validity
  window. Falls back to the assertion lifetime when unset.
- Added `EntityDescriptor::for_sp`, a convenience constructor wrapping a
  single `SpSsoDescriptor` with no extensions/organization/contacts.
- Added `gamlastan-actix`'s `EstablishedSessionCallback`, reporting whether
  the current request already carries an established IdP session (read from
  the application's own cookie/session mechanism) for
  `idp::orchestrator::check_request` to weigh against
  `ForceAuthn`/`IsPassive`/`RequestedAuthnContext` before the
  `AuthnSubjectCallback` runs.
- Added `IdpConfig::trusted_sp_entity`, returning a trusted SP's full entity
  descriptor (entity categories and other entity-level extensions), alongside
  the existing `trusted_sp` (SSO descriptor only).
- Added `idp::NameIdConstructor`, an object-safe view of
  `IdentDb::construct_nameid`, implemented for `IdentDb<S>` over any
  `IdentityStore`. `ResponseEngine` is no longer generic over `S:
  IdentityStore` — `idents` is `&dyn NameIdConstructor` — so a ready-made
  framework integration with a fixed function signature (a route handler
  registered once, not parameterized per application) can accept a
  Redis/SQL-backed `IdentDb`, not just the default in-memory store.
- Added `gamlastan-actix`'s `ResponseEngineParts`, an owned bundle of
  `ResponseEngine`'s dependencies (`Arc<ReleasePolicy>`,
  `Arc<dyn AttributeRelease>`, `Arc<dyn NameIdConstructor>`,
  `Arc<AuthnBroker>`, `Arc<SamlSigner>`, etc.), registered once as
  `web::Data<Arc<ResponseEngineParts>>`; the SSO handler builds a
  short-lived borrowed `ResponseEngine` from it per request via
  `ResponseEngineParts::engine`. Registering `ResponseEngine<'static>`
  directly would force every dependency to independently satisfy `'static`,
  which for ordinary application-owned state means leaking it. The
  `/saml/metadata` handler now also accepts `ResponseEngineParts` and
  prefers its certificate over `IdpSigningContext`/`IdpConfig` when an
  `AuthnSubjectCallback` is registered too, which is the only case in which
  the engine signs (`idp_sso` takes the policy-driven path only with both).
  Previously the metadata handler had no idea `ResponseEngineParts` existed,
  so registering only it (the documented policy-driven setup, with no
  `IdpSigningContext`) produced signed responses while metadata advertised no
  key at all - or a *different* key, if `IdpSigningContext` also happened to
  be registered with its own certificate. With parts but only the low-level
  `AuthnCallback`, responses are signed by `IdpSigningContext`, and that is the
  certificate metadata advertises.
- Added `IdentDb::with_persist_transient` (default off; see "Changed" for why
  transient NameIDs are no longer stored by default). Opting in stores each
  transient NameID so `find_local_id` resolves it, which a back-channel (SOAP)
  LogoutRequest carrying one needs. The record trait has no expiry, so the
  backend must expire them (a TTL index, a periodic purge); issuing a
  transient NameID then needs the store to be reachable. A stored transient is
  still never reused by a NameIDMapping request.
- Added `IdentityStore::find` and `IdentDb::find_nameid` (pysaml2
  `find_nameid`): the NameIDs of a user matching a `NameIdFilter` on format,
  `SPNameQualifier`, `NameQualifier` and `SPProvidedID`, where an unset field
  matches anything. `find` has a default that filters `for_user`; a backend
  overrides it to push the filter into a query. The conformance suite checks
  that an override agrees with the default's semantics.
- Added per-SP signature and digest algorithm selection. `SignatureMethod`
  (SHA-2 RSA and ECDSA), `DigestMethod` (SHA-2), `SigningPreference` and
  `SigningAlgorithms` live in `crypto`; `PolicyEntry::with_signing_preference`
  sets an SP's ordered preference. The orchestrator signs each response (and
  each denial) with the first preferred algorithm the SP also advertises in its
  metadata, else the first listed. Signatures are matched only against the
  SP's `alg:SigningMethod` entries and digests only against `alg:DigestMethod`
  (`SigningPreference::resolve` takes the two lists), so a URI placed under the
  wrong element does not count. The advertisement is untrusted: it only
  chooses among the IdP's own entries, and SHA-1, MD5 and the like are not
  representable, so neither configuration nor a peer can select them. The
  digest used to be hardcoded to SHA-256; with no preference configured the
  defaults are unchanged (the signer's method, SHA-256). Lower level:
  `sign_response_xml_with`, `signature_template_with_digest` and
  `SamlSigner::signature_method_uri_for`. An HSM-backed signer can only use its
  token's own signature algorithm, and asking for another is an error, but only
  when something is actually signed: `sign_response_xml_with`, asked to sign
  nothing, never consults the signer (the orchestrator never asks that, see
  below). The SP's advertisement is read from the entity-level
  extensions and the SAML 2.0 SP role the request was bound to, not from every
  IdP and SP role of the entity (which `EntityDescriptor::supported_algorithms`
  aggregates), so an algorithm advertised only by another role is not selected.
  With an HSM-backed signer, list only the token's signature method in a
  preference: another one makes the response (and a denial) fail with an error
  for the SPs that resolve to it, when it is signed, not at startup.
- `ident::conformance` (the reusable `IdentityStore` backend check) gains
  non-panicking entry points for callers that are not Rust tests, such as a
  language binding: `check` / `check_with` return the first violation as a
  `ConformanceError` naming the failing check, `check_one` runs a single check
  by name, `CHECKS` lists the names, and `Options::threads` sets the concurrent
  checks' thread count. `run` still panics and is unchanged for Rust tests. A
  backend call that fails is now a failed check naming the operation, and the
  concurrent-insert check no longer counts a backend failure as a lost race
  (which made a dead backend look as if it had exactly one winner). The
  concurrent get-or-insert check treats `ValueTaken` as a violation instead of
  retrying with the same candidate, which never ended against a backend that
  always reports it. The docs
  state what the suite cannot prove: its concurrent checks run on threads in
  one process, so a backend that serialises its calls can pass without having
  the constraint, and a race between separate processes is not detected. The
  module moved to `idp/ident/conformance.rs`.
- Added `AttributeConverter::from_directions`, `add_wire_to_local` and
  `add_local_to_wire`, for building a converter from independent inbound and
  outbound maps, which is the shape of a pysaml2 attribute map (`MAP["fro"]`
  and `MAP["to"]`). `add_mapping` and `from_entries` set both directions at
  once and so cannot load a map whose directions differ; such maps are real
  (a deployed eduID `saml_uri` map has 83 inbound and 99 outbound entries).
  Mirroring one would make an SP-supplied attribute name resolve to a local
  attribute it did not before, and would make the outbound name depend on
  insertion order for a map with several wire names per local name.
  `from_static` now goes through `from_directions` with identical results,
  which a test checks for every shipped map.
- A requested NameID format longer than `MAX_NAMEID_FORMAT_LEN` (256 bytes) is
  refused with `InvalidNameIDPolicy`, whatever is configured
  (`ReleasePolicy::supports_nameid_format`). Formats are short URIs, and the
  requested one is stored with each durable record, so it is bounded. The orchestrator module docs
  now list the permissive defaults to review before production (attribute
  release, NameID formats, signing with an HSM, transient NameIDs).
- Added an opt-in supported-format set for requested NameIDs:
  `PolicyEntry::with_supported_nameid_formats`,
  `ReleasePolicy::supports_nameid_format` and `ISSUABLE_NAMEID_FORMATS`. With a
  set configured, a requested `NameIDPolicy/@Format` outside it is denied with
  `InvalidNameIDPolicy` (SAML Core 3.4.1.1) before anything is minted; the SP's
  own default format is always allowed. **Without one, which is the default,
  any requested format is accepted**, as in pysaml2, which never validates it:
  an identifier is issued in whatever format was asked for, so an SP that sends
  invented format strings gets one stored record per string.
  `ISSUABLE_NAMEID_FORMATS` (transient, persistent, emailAddress, unspecified)
  is a reasonable set to pass; it leaves out `encrypted`, a request to encrypt
  the NameID, which is not supported.
- Added `AuthnRequest::requested_subject` and `requested_subject_name_id`
  (pysaml2 `Request.subject_id()`): the principal an AuthnRequest names in
  `Subject`, with an `EncryptedID` returned as such, not as "no subject". The
  orchestrator still does not compare it with the authenticated principal, as
  in pysaml2: mapping a NameID to a local user is deployment-specific (eduID's
  "re-login as the same user" and MFA step-up flows send an eppn in an
  `unspecified`-format NameID and honor it only for allowlisted SPs). A
  deployment that supports a requested subject must compare it itself.

### Changed

- **Breaking:** `ResponseOptions` gained the `authenticating_authorities`
  field. Every struct literal must add it (or use `..Default::default()`).
  External consumers with hand-built literals (e.g. tunnelbana) need a
  one-line-per-site compat patch.
- **Breaking:** `ProcessedAuthnRequest` gained
  `requested_sp_name_qualifier`, `has_name_id_policy` and
  `requested_authn_context_decl_refs`. The struct is only produced by
  `process_authn_request`, so hand-construction sites need all three fields
  added. `process_authn_request` used to discard `AuthnContextDeclRef`s, so a
  `RequestedAuthnContext` naming only declarations looked like no constraint at
  all and the engine would reuse any session or issue any class ref. An
  `AuthnMethod` carries a class ref only, so a declaration cannot be shown to be
  met: `check_request` and `create_authn_response` now deny such a request with
  `NoAuthnContext`, and `ResponseParams::requested_authn_context()` no longer
  reports it as no constraint. A `RequestedAuthnContext` element that names no
  class or declaration ref at all is malformed (the schema requires at least
  one) and is no longer collapsed into "no constraint" either:
  `process_authn_request` rejects it with
  `ProfileError::EmptyRequestedAuthnContext`, and the engine denies it with
  `NoAuthnContext` for parameters built by hand.
- **Breaking:** `gamlastan-actix`'s `TrustedSp.sp_sso: SpSsoDescriptor` field
  is now `entity: EntityDescriptor`, with no separate registration-key field:
  `IdpConfig::with_trusted_sp(entity_id, sp_sso)` is now
  `with_trusted_sp(entity: EntityDescriptor)`, keyed by the descriptor's own
  `entity_id` (wrap a bare `SpSsoDescriptor` with `EntityDescriptor::for_sp`
  at call sites that don't need entity-level extensions), so a mismatched
  call site can no longer register one issuer's authorization under a
  different entity's ACS endpoints and release policy.
  `TrustedSpResolver::resolve_sp`'s return type changed from
  `SpSsoDescriptor` to `EntityDescriptor` to match, and the handler now
  rejects a resolver response whose `entity_id` disagrees with the requested
  one. Previously the SSO handler's policy-driven path also always passed
  `sp_entity: None` to `idp::orchestrator`, so entity-category
  attribute-release policy could never engage through it; the full
  descriptor is now threaded through from trusted-SP resolution. Selecting
  the SAML 2.0 role out of a registered entity's roles (added
  `EntityDescriptor::saml2_sp_sso_descriptor`) is by `protocolSupportEnumeration`,
  not descriptor order, so metadata carrying a non-SAML-2.0 `SPSSODescriptor`
  before the SAML 2.0 one is resolved correctly. `IdpConfig::trusted_sp_verifier`
  (the aggregate verifier built from every registered trusted SP) also now
  filters each entity's roles by SAML 2.0 protocol support before collecting
  signing certificates, so a certificate published only for a non-SAML-2.0
  role can no longer become trusted for verifying SAML 2.0 messages.
- **Breaking:** `IdentityStore` is now a record-shaped backend: one record per
  (user, NameID) association (`for_user`, `user_for`, `find_durable`,
  `get_or_insert_durable`, `insert`, `replace`, `remove`, `remove_all`).
  In 0.9.x it was a plain `get`/`set`/`remove` trait; that shape is now
  `KeyValueStore` (`InMemoryKeyValueStore`), which `Eptid` uses.
  `IdentDb`'s atomicity comes from two uniqueness constraints the backend
  enforces - the NameID value is unique across all records, and among
  durable records (every format except transient) `(user, sp_name_qualifier,
  name_qualifier, format)` is unique - so two concurrent first requests for
  the same (user, SP, format) converge on one identifier instead of minting
  different ones, and a removal cannot orphan a reverse mapping because there
  is no separate reverse key.
  The constraints live in the store, so the trait has no default write
  methods (a non-atomic default would silently leave the race open on a
  multi-instance deployment) and `ident::conformance::run` is provided to
  check that a backend honours them. Both constraints hold on every write
  path, not only on `get_or_insert_durable`: `insert` and `replace` refuse
  a second durable record of the same format for the same `(user,
  sp_name_qualifier, name_qualifier)` with `InsertError::DurableExists`
  (`get_or_insert_durable` and `find_durable` take the format; `replace` now returns
  `InsertError`, and `IdentDb::store` returns `IdentError`, which gains
  `DurableExists`), and the conformance suite checks each path.
  `InMemoryIdentityStore` takes one lock per call; a Mongo/SQL-backed store
  must back the two constraints with real unique indexes (the second a
  partial unique index on `(user, sp_name_qualifier, name_qualifier, format)`
  where the format is not transient, an absent format counting as
  `unspecified`), applied to every write. A store that
  already holds several records of one format per (user, SP) - 0.9.x minted a
  new one at every login for email and unspecified - must be deduplicated
  before that index can be built.
  Migration: an external implementor of the 0.9.x trait (pygamlastan's
  `PyIdentityStore` is one) implements `KeyValueStore` for the `Eptid` cache
  and the new `IdentityStore` for `IdentDb`; code still implementing the old
  three methods as `IdentityStore` fails to compile rather than misbehaving.
- **Behaviour change:** `AuthnBroker::pick` treats every listed
  `AuthnContextClassRef` (or, failing those, `AuthnContextDeclRef`) as an
  alternative for every comparison, not just `exact`: a method qualifies if it satisfies any of them, deduplicated
  and in the request's order. Before, `minimum`, `maximum` and `better` read
  only the first ref, so `[unknown, supported]` was denied. This follows SAML
  Core 3.3.2.2.1 ("one of the authentication contexts specified") and differs
  from pysaml2, which also reads only the first; it can only accept requests
  that were refused before.
  With no `RequestedAuthnContext` and no `unspecified` method registered,
  `pick` now offers every registered method instead of none (nothing was
  requested, so all qualify).
- **Behaviour change:** `nameid-format:encrypted` is never issued, with or
  without an opt-in supported-format set: it asks for an `EncryptedID`, which the response path
  cannot produce, and a plain NameID labelled that way would break the
  requester's confidentiality requirement. A request naming it is denied with
  `InvalidNameIDPolicy`; an SP whose configured default format it is (the
  request names none) gets an error, as that is a configuration fault.
- **Behaviour change:** `SignTargets::resolve` never resolves to "sign nothing".
  The Web Browser SSO profile (SAML Profiles 4.1.4.5) requires a signed
  Response or a signed Assertion, so when the response is not to be signed the
  assertion is. A default `ReleasePolicy` (nothing configured) therefore signs
  the assertion, and the engine needs a real signing key; before, it issued an
  unsigned, forgeable response. pysaml2's default signs nothing; set
  `SignTargets::response` to sign the envelope instead.
- `check_request` does not deny a request with `NoAuthnContext` before login
  when the broker has no registrations at all (new `AuthnBroker::is_empty`) and
  the request is `exact`: an `Inline`-only deployment (a proxy) has no
  capabilities to check, so it gets `Authenticate` with no methods and
  `create_authn_response` checks the method the callback reports. `minimum`,
  `maximum` and `better` need the broker's strength ordering, so with nothing
  registered they are denied before login. A broker with registrations that
  match nothing still denies.
- A denial is a `DeniedResponse` (`xml`, `response_id`), not an
  `IssuedResponse`: `create_denial_response` and `ResponseOutcome::Denied` no
  longer carry an empty NameID and a `not_on_or_after` of "now" that an audit
  consumer could mistake for issuance data.
- `AuthnBroker::pick`'s documentation now states its real order (the request's
  class-ref order, then registration order), not "strongest first"; only
  `check_request` sorts by strength.
- `InMemoryAssertionStore` keeps both indexes under one lock, and re-storing an
  assertion ID for a different subject removes it from the old subject's index.
  Before, a lookup for the old subject returned the other subject's assertion.
- `ResponseParams::requested_authn_context` returns a constraint (not `None`)
  for a present but empty `RequestedAuthnContext`, which the engine refuses.
- `example-idp` refuses an `AuthnRequest` that names a `Subject`: it issues for
  whoever logs in and does not compare them with a requested principal.
- **Behaviour change (store contract):** `IdentityStore::replace` (and so
  `IdentDb::store`) no longer moves a record to another user. A value held by a
  different user is `InsertError::ValueTaken` (`IdentError::ValueTaken` from
  `IdentDb::store`) and left untouched; the owner can still update it in place.
  Reassigning would let the new user log in as the old one at every SP that has
  seen the value. Nothing in this crate relied on it (ManageNameID passes the
  owner it just looked up). A Mongo or SQL upsert filtered on `(value, user_id)`
  gets this from the unique index on the value; the conformance check
  `replace_upserts_by_value` now asserts it.
- Added `PolicyEntry::with_deny_unconfigured_release` (and
  `ReleasePolicy::deny_unconfigured_release`), an opt-in to fail closed on
  attribute release. **By default, as in pysaml2 and unchanged from 0.9.x, an SP
  that no attribute rule covers is released every attribute the application
  supplied**: the policy only narrows (entity categories, the attributes the SP
  requests in its metadata, attribute restrictions), so with none of those the
  application is the only filter. With the setting on, such an SP gets an
  assertion with no attribute statement; an SP covered by any rule is filtered
  as before. It resolves like the other policy settings (SP entry, registration
  authority, `default`), so it can be set globally on the `default` entry and
  overridden per SP. `PassThroughRelease` is unaffected. This default is now
  documented on `ReleasePolicy`.
- `IdentDb` gives up after 8 attempts to mint an unused NameID, with a
  `StoreError`, instead of looping forever against a backend that always reports
  `ValueTaken` or says every value is in use. Real collisions of 256-bit values
  do not occur, so this only bounds a broken backend's cost.
- `create_authn_response` resolves and checks the authentication method before
  it constructs the NameID, so a stale `BrokerReference` or a method that does
  not satisfy the request is refused before anything is stored. It also
  re-checks a reused session's absolute expiry (`authn_instant +
  session_lifetime`) at that point: a session `check_request` approved but that
  expired while the application callback ran is denied (`AuthnFailed`) instead
  of issuing an assertion whose `SessionNotOnOrAfter` is already past.
- `gamlastan-actix`'s SSO handler returns a `Configuration` error when
  `ResponseEngineParts::idp_entity_id` differs from `IdpConfig::entity_id`,
  instead of signing responses whose Issuer every SP would reject.
- **Behaviour change:** AuthnRequest parsing and processing no longer repair
  malformed input into a more permissive request. An `IDPEntry` without the
  required `ProviderID` is rejected, where it used to be dropped (shrinking a
  restrictive `IDPList`, possibly to an empty one, which reads as no
  restriction). A repeated `Subject`, `NameIDPolicy`, `Conditions`,
  `RequestedAuthnContext`, `Scoping` or `IDPList` is rejected, where only the
  first used to be read and the rest ignored. A `Subject` carrying a
  `SubjectConfirmation` is rejected with
  `ProfileError::SubjectConfirmationInAuthnRequest`, a variant that existed but
  was never raised. `ProcessedAuthnRequest` documents what it does not carry:
  `Scoping`, which a proxying IdP must read from the original request itself,
  and the principal named by `Subject`.
- **Behaviour change:** the durable NameID formats other than persistent
  (email, unspecified, and any other non-transient format) are now stable per
  `(user, SP, NameQualifier, format)`, as persistent always was: an existing
  record is returned instead of a new value being minted. 0.9.x minted and
  stored a fresh value on every call, so an email-format NameID changed at each
  login, which no SP can use to recognise a user, and the identity store grew
  with every response. `IdentityStore::get_or_insert_persistent` and
  `find_persistent` became `get_or_insert_durable` and `find_durable`
  (`find_durable` takes the format), and `InsertError::PersistentExists`
  became `DurableExists`. `AllowCreate=false` still gates only the persistent
  format.
- **Behaviour change:** `IdentDb::construct_nameid` treats a request with **no
  `NameIDPolicy` at all** as allowing the IdP to create a persistent identifier.
  0.9.x computed `AllowCreate` as `false` in that case, so an IdP whose default
  format is persistent refused every first-time user whose request omitted the
  policy with `CreateNotAllowed`. Only an explicit `NameIDPolicy` with
  `AllowCreate="false"` forbids creating one, and a policy that is present but
  omits `AllowCreate` is unchanged (`false`, the schema default). This matches
  pysaml2, whose SSO flow mints whatever `AllowCreate` says; gamlastan still
  honours an explicit `false`. It affects the persistent format only, and it
  mints a new durable identifier where an upgrade used to refuse, so check it
  if SPs omit `NameIDPolicy`. Before this PR nothing in a response path called
  `construct_nameid`, so it concerns applications that did.
- **Behaviour change:** ACS endpoint selection honours `ProtocolBinding`, as
  pysaml2 does. A `ProtocolBinding` with no URL or index picks the default
  endpoint among those registered with that binding (it used to be ignored, so
  the response went to the default endpoint in whatever binding that was; it is
  an error now if none is registered). An `AssertionConsumerServiceURL` without
  a `ProtocolBinding` uses the binding the URL is registered under, the first in
  metadata order if it is registered under several (it used to assume
  HTTP-POST, so a URL registered only under another binding failed with
  `AcsUrlMismatch`). A `ProtocolBinding` given with an index must match that
  endpoint's binding. The response still only goes to an endpoint registered in
  the SP's metadata, and a URL and an index given together still resolve by the
  URL, as in pysaml2. `ProcessedAuthnRequest::acs_binding` is the binding the
  endpoint is registered under, so it can be HTTP-Artifact or HTTP-Redirect. The
  ready Actix handler and `example-idp` deliver by HTTP-POST only, and now refuse
  a request that resolves to another binding
  (`SamlActixError::UnsupportedBinding`) instead of POSTing a Response to an
  endpoint that expects an artifact or a redirect; an application that has to
  serve such an SP uses the profile functions and delivers by `acs_binding`.
- **Breaking:** the store traits are fallible. `IdentityStore`, `KeyValueStore`
  and `AssertionStore` methods return `Result<_, StoreError>` (the two insert
  paths return `InsertError`, which separates a `ValueTaken` conflict from a
  backend failure), and `IdentDb`, `Eptid`, `get_authn_statements`,
  `create_assertion_id_request_response` and `create_authn_query_response`
  propagate it. A backend that cannot answer must return an error, never an
  empty result: reading an outage as "no record" would mint a second "stable"
  persistent NameID for a user who already has one, and make `Eptid` recompute
  a value that may differ from the one already issued. In `idp::orchestrator`
  a store failure is `Err(ProfileError::Store)`, not a signed denial, since the
  SP did not cause it. `IdentError` gains a `Store` variant.
- **Behaviour change:** `IdentDb` no longer stores transient NameIDs by
  default. 0.9.x stored every non-persistent NameID, transient ones included;
  they are one-time-use (SAML Core §8.3.7) and the default per-SP format is
  transient, so every response added a record that was never read back and the
  store grew without bound. As a result `find_local_id` on a transient NameID
  now finds nothing, which matters to a back-channel (SOAP) LogoutRequest that
  carries one; such a deployment opts in with
  `IdentDb::with_persist_transient`. Issuing a transient NameID no longer
  consults the store at all, so it does not depend on the store being
  reachable.

### Fixed

- `IdentDb::match_local_id` (persistent NameID lookup) now matches only a
  stored identifier whose own format is also `persistent`, not any
  non-transient format. Previously, a persistent-format request for a
  (user, SP) pair that already had e.g. an `email`-format identifier stored
  would return that identifier's value labeled as `persistent` instead of
  minting/reusing an actual persistent one - matching pysaml2's production
  Mongo-backed `IdentMDB.match_local_id`, which filters on
  `name_id.format == NAMEID_FORMAT_PERSISTENT` explicitly, rather than
  pysaml2's looser shelve-backed base `IdentDB`.
- **Breaking:** `AuthnBroker::pick` with `Comparison="exact"` now requires a
  literal match of one of the requested `AuthnContextClassRef` values, per
  saml-core-2.0-os 3.3.2.2.1, instead of broadening to every method
  registered at the same security level as the requested class (pysaml2's
  own `AuthnBroker` has the same broadening; gamlastan diverges from it
  here). Added `AuthnBroker::allow_exact_level_matching` to opt back into the
  looser, pysaml2-compatible behavior. The orchestrator honours the opt-in
  consistently: a same-level method that `check_request` offers is accepted by
  `create_authn_response` once the user authenticates with it, and a session it
  established is reusable, rather than being denied for not being a literal
  match.
- Closed a check-then-create race on persistent NameID minting: two concurrent
  first requests for the same (user, SP) could each find no existing
  association and mint two different "stable" persistent identifiers. The
  store's `get_or_insert_durable` is now atomic, backed by the uniqueness
  constraints described under "Changed".
- `idp::orchestrator`'s NameIDPolicy handling only honours
  `NameIDPolicy/@SPNameQualifier` when it equals the requester's own
  (verified) entity ID. Per saml-core-2.0-os 8.3.7, SPNameQualifier may
  legitimately name an affiliation the requester belongs to, but only when
  the IdP can verify that membership (`AffiliationDescriptor`), which this
  crate does not implement; honouring an arbitrary requester-supplied value
  would let one SP request another SP's persistent identifier for the same
  subject just by naming it, defeating pairwise-identifier scoping. A
  request naming a different entity is denied with `InvalidNameIdPolicy`.
- `idp::orchestrator::check_request`/`create_authn_response` now treat a
  session's `authn_instant + session_lifetime` as its real, absolute expiry:
  `check_request` refuses to reuse a session past that point (previously it
  only checked `ForceAuthn` and method satisfaction), and the assertion's
  `AuthnStatement/@SessionNotOnOrAfter` on reuse is derived from the
  session's original `authn_instant`, not `now` - otherwise every reused
  session pushed its own absolute cap further out on each SSO hop, turning
  it into an unbounded sliding window in practice. The Actix handler enforces
  this for the `AuthnSubjectCallback` path: on `ReuseSession` it takes the
  method, `authn_instant` and session index from the established session, so
  a callback returning `authn_instant: None` cannot restart the window. The
  callback must return the session's own `subject_id`: a different one is a
  `Configuration` error, not relabelled, since that would sign the session
  user's NameID over another user's attributes.

## [0.9.1] - 2026-09-29

### Changed

- Updated the coordinated `bergshamra` stack to 0.9.2 and `kryptering` to
  0.6.0, keeping the public signing backend aligned with the XML-security stack.
- Updated `base64` to 0.23.1, `md-5` to 0.11.0, and `reqwest` to 0.13.5.
- Refreshed compatible direct and transitive dependencies through `sfw`, while
  retaining Rust 1.88 support (`aes` remains at 0.9.2).

### Upgrade Notes

- Custom clients passed to `ReqwestFetcher::from_client` or
  `from_client_with_limits` must use reqwest 0.13. The default Rustls transport
  now uses platform certificate verification, following reqwest 0.13 defaults.
- Code supplying HSM signers should use the re-exported
  `gamlastan::crypto::kryptering` types or depend on kryptering 0.6 directly.

## [0.9.0] - 2026-09-03

### Added

- Added recipient-aware `ArtifactStore::store_for_recipient` and
  `resolve_and_consume_for_requester` operations. Their defaults fail closed so
  legacy stores cannot accidentally serve an artifact to the wrong SP.
- Added participant-aware session lookup and atomic removal, including SP entity
  ID, full NameID (with `SPProvidedID`), and optional SessionIndex matching.
- Added stateful LogoutRequest freshness and replay validation, configurable
  logout replay caches and maximum request ages for the ready Actix handlers,
  and the required async, fallible Actix `SloCallback` / `SpLogoutEvent`
  integration point for invalidating local SP sessions.
- Added the async, fallible Actix `SloInitiationCallback`, which derives the
  federated NameID and SessionIndex values for SP-initiated logout from the
  authenticated local application session.
- Added `SecurityConfig::allow_unsolicited_responses`. It defaults to `false`;
  deployments that intentionally support IdP-initiated SSO must opt in.

### Changed

- Upgraded the XML-security stack from `bergshamra` 0.8.0 to 0.9.0 across all
  directly used workspace crates.
- Upgraded the XML parser from `uppsala` 0.9.0 to 0.10.1, matching the version
  used by `bergshamra` 0.9.0 so the workspace resolves a single parser version.
- Refreshed compatible dependency versions in `Cargo.lock`.
- Kept `aes` at 0.9.2 because the otherwise compatible 0.9.3 patch raises its
  minimum supported Rust version to 1.89; gamlastan continues to support Rust
  1.88 as declared.
- Suppressed `RUSTSEC-2026-0258` in the CI audit gate while Actix HTTP remains
  pinned to the affected `h2` 0.3 line; the exception is scoped to that advisory
  and should be removed when Actix adopts `h2` 0.4.16 or newer.
- **Breaking:** ready Actix SP SLO routes now require an application-provided
  async `SloCallback` that returns `Result<(), SamlActixError>`; a successful
  protocol response is returned only after local session invalidation succeeds.
  Replay and correlation reservations remain consumed when the callback fails.
- **Breaking:** ready Actix SP logout initiation now requires
  `SloInitiationCallback` and `SpSigningContext` application data. Caller-supplied
  NameID and SessionIndex query parameters are ignored; the callback supplies
  the authenticated local session identity and the emitted Redirect
  LogoutRequest is signed.
- **Breaking:** `SessionParticipant` now includes `sp_provided_id`. Custom
  `SessionStore` implementations should override `get_sessions_for_participant`
  when their principal index differs from the participant NameID.
- **Breaking:** removed `IdpConfig::allow_unauthenticated_backchannel`. The
  generic bypass could not prove that a transport identity matched the claimed
  SAML Issuer; custom mutual-TLS handlers must perform that binding explicitly.
- Custom artifact stores used with the ready IdP must issue artifacts through
  `store_for_recipient` and atomically enforce the same recipient in
  `resolve_and_consume_for_requester`.

### Security

- Added a configurable signature and Reference-digest algorithm policy at every
  `SamlVerifier` boundary. The default accepts RSA/ECDSA with SHA-256, SHA-384,
  or SHA-512 and SHA-256/384/512 digests; SHA-1 and other legacy methods now
  require an exact custom allowlist or explicit `AlgorithmPolicy::permissive`.
  Bergshamra retains its full xmlsec-compatible algorithm support.
- Replaced the metadata comment/processing-instruction split-text check with a
  linear scan, preventing quadratic CPU consumption before MDQ signature
  verification while preserving legitimate structural metadata comments.
- Assertion replay entries now remain live through the complete acceptance
  window, including clock skew and future IssueInstant fallback lifetimes,
  while never outliving the bounded assertion-age window. Assertion
  IssueInstant values beyond accepted clock skew are rejected, and the
  in-memory replay cache prunes expired distinct IDs without retaining
  already-due entries that would trigger a full-map scan on every insertion.
- Artifact resolution now binds atomic lookup and consumption to the
  authenticated requesting SP, preventing a trusted peer from resolving or
  burning another SP's artifact.
- Ready IdP SLO now destroys only sessions containing the authenticated SP as an
  exact participant, with full NameID and requested SessionIndex matching.
  Omitted NameID Format and the explicit SAML `unspecified` format are treated
  as equivalent, as required by SAML Core. Matching and removal now occur in one
  store transaction or lock so a concurrent session replacement cannot be
  deleted through a stale lookup snapshot. Legacy custom stores fail closed
  until they implement atomic participant-bound removal.
- Ready SP and IdP SLO handlers now reject stale, future-dated, and replayed
  LogoutRequests using issuer-scoped replay keys. Ready SP SLO also requires
  successful local-session invalidation before reporting protocol success, and
  binds SP-initiated LogoutResponse correlation to the browser that issued the
  LogoutRequest to prevent logout CSRF across sessions.
- Ready IdP SLO accepts a valid HTTP-Redirect query signature or enveloped XML
  signature from the resolved SP metadata key and verifies every signature
  representation present.
- Ready SP-initiated logout obtains its target from the authenticated local
  session callback, requires a signing context, and emits a signed
  HTTP-Redirect LogoutRequest that the ready IdP can authenticate.
- Unsolicited SSO responses are rejected by default at the shared response
  validation boundary. Explicitly enabled unsolicited responses must still omit
  `InResponseTo` and pass all signature, audience, recipient, time, and replay
  checks.
- See ADR 0044 for the state-binding decisions and migration consequences.

## [0.8.0] - 2026-08-03

### Added

- Attack-corpus regression suite (`crates/gamlastan/tests/attack_corpus.rs` plus
  `tests/fixtures/attacks/`) replaying known-malicious SAML payloads against the
  real parse and signature-verification pipeline: DTD/XXE/entity-expansion,
  comment- and CDATA-truncation, processing-instruction injection, smuggled
  `AuthnRequest`-in-`Response`, HMAC `SignatureMethod`, and DigestValue/URI
  signature-wrapping vectors, with a legitimate-response positive control to
  prove the hardening does not over-block.
- `xml::parse_secure_metadata`: a metadata-tolerant secure parse entry point.
  It keeps every `parse_secure` guard (DTD/entity rejection, resource caps, and
  CDATA rejection) but allows XML comments and processing instructions, which
  real federation metadata aggregates (eduGAIN, InCommon) legitimately carry and
  which never invalidate an enveloped metadata signature.
- `xml::SecureParseConfig` gains `forbid_comments`, `forbid_pis`, and
  `forbid_cdata` policy flags (all default `true`) with matching
  `with_forbid_*` builders.

### Changed

- Raised the declared minimum supported Rust version from 1.75 to 1.88 to match
  the resolved Actix, bergshamra, kryptering, and time dependency graph.
- The example IdP now honors `IsPassive`, `ForceAuthn`, RequestedAuthnContext
  comparison, and requested NameID format, returning signed SAML protocol errors
  when a request cannot be satisfied. Reused sessions preserve their original
  authentication context, instant, and session index.
- The example IdP loads trusted SP metadata with `parse_secure_metadata`, so
  legitimate federation comments remain compatible with the hardened parser.
- **Breaking (operational):** the default MDQ fetch body cap dropped from
  200 MiB to 10 MiB per response, with at most 8 response bodies buffered
  concurrently. Per-entity MDQ lookups are unaffected. Deployments fetching
  large federation *aggregates* (e.g. eduGAIN, on the order of 100 MiB) through
  `ReqwestFetcher` must now opt in deliberately with
  `ReqwestFetcher::with_limits(timeout, max_body_bytes, max_concurrent_fetches)`
  or `from_client_with_limits`; the previous 200 MiB-per-request default sized
  every consumer for the worst case. Dynamically fetched MDQ metadata is also
  cached with a 1024-entry bound by default (`MdqClient::with_cache_capacity`;
  oldest fetch evicted first, zero disables caching).
- Upgraded the XML-security/crypto stack: `bergshamra` 0.7.0 → 0.8.0 and the
  direct `kryptering` dependency 0.4 → 0.5, features still mirroring bergshamra
  (`legacy`, `post-quantum`, `pkcs11`) so the shared `Signer` / `Pkcs11Signer`
  types resolve to a single instance with no version or feature drift. `uppsala`
  stays at 0.9. `Key::to_signing_key` and `sign::from_uri` now return `Result`,
  handled at the two crypto call sites.
- Metadata parsing (MDQ verify, SPID and mdui/algsupport extensions, `KeyInfo`
  extraction, Sweden Connect entity attributes) now uses `parse_secure_metadata`
  and gathers full element text (deep concatenation) instead of the first text
  node, so an allowed comment can never truncate a signed value.

### Security

- SPID and example IdP pending authentication state is TTL-bounded, capacity-
  bounded, and atomically consumed only after all terminal validation succeeds.
- The ready Actix SP binds each AuthnRequest to the initiating browser:
  `/saml/login` sets a five-minute `__Host-gamlastan_authn_state` cookie
  (Secure, HttpOnly, SameSite=None) and the ACS consumes an outstanding request
  ID only when the presenting browser holds the state it was issued with, so a
  response solicited in one browser cannot be injected into another.
  **Deployment note:** the cookie is `Secure`, so solicited logins require the
  SP to be served over HTTPS — including local development; over plain HTTP the
  cookie is never stored and every solicited response is rejected at the ACS
  with "InResponseTo does not match". Custom `RequestIdTracker` implementations
  must override `store_bound`/`consume_bound`; the defaults fail closed for the
  ready ACS flow.
- `InMemoryRequestIdTracker` is capacity-bounded (default 1024 outstanding IDs,
  configurable via `with_limits`), evicting the oldest live entry at capacity.
  The login endpoint is unauthenticated, so unbounded correlation state was a
  memory-growth vector (ADR 0041).
- Actix SLO verifies every signature representation supplied with a message; a
  valid Redirect signature can no longer mask an invalid enveloped XML-DSig.
- The SPID ACS now parses network-supplied responses exclusively through the
  secure XML boundary before typed deserialization.
- `parse_secure` now rejects XML comments, processing instructions, and CDATA
  sections anywhere in a document. Comments and CDATA both split an element's
  text into multiple nodes while canonicalizing to the same signed bytes, so a
  first-text-node reader could see a different value than the signature covered
  (the comment- and CDATA-truncation authentication-bypass class,
  CVE-2017-11427). Refusing them before any field text is extracted closes the
  bypass at the parse choke point.
- `ResponseRef::from_xml` rejects smuggled protocol *request* elements
  (`AuthnRequest`, `LogoutRequest`, `ArtifactResolve`, `AttributeQuery`,
  `AuthnQuery`, `AuthzDecisionQuery`, `AssertionIDRequest`,
  `ManageNameIDRequest`, `NameIDMappingRequest`) as direct children of a
  `<samlp:Response>` — a classic signature-wrapping / request-smuggling vector.
- XML-DSig verification rejects HMAC-based `SignatureMethod` algorithms outright
  (`SamlVerifier::set_reject_hmac_signatures`, default on): SAML IdPs sign with
  asymmetric keys, so a legitimate response is never HMAC-signed, and refusing
  HMAC closes a symmetric key-confusion class as defence in depth on top of
  `trusted_keys_only`. The detection list is kept a superset of the DSig
  backend's HMAC URIs (including `hmac-ripemd160`) so the two cannot drift. The
  `ds:Object` (E91) and HMAC structural pre-scans parse comment-tolerantly so
  comment-bearing federation metadata is not rejected during verification.

## [0.7.0] - 2026-07-06

### Added

- `profiles::sso::idp` response/assertion signing helpers: `signature_template`
  (build an empty enveloped `<ds:Signature>` template for a reference ID, with
  exclusive c14n, the enveloped-signature transform, a SHA-256 digest and the
  signing certificate in `<ds:KeyInfo>`), `sign_response_xml` (splice + sign a
  serialized `Response` - assertion, response envelope, or both, inner-to-outer),
  and `create_signed_response` (one call: `create_response` + serialize + sign).
  The signature is anchored after each element's `<saml:Issuer>`, per the SAML
  schema ordering, so callers no longer hand-roll the template and splice. See
  ADR 0033.
- Guarded PySAML2 MD5 EPTID compatibility for stock PySAML2 cutovers:
  `idp::eptid::EptidDigest::Pysaml2Md5Legacy`, `EptidOptions`, and fallible
  constructors. SHA-256 remains the default; legacy MD5 requires
  `allow_legacy_md5 = true`. See ADR 0036.
- Expanded docs.rs-facing module documentation and examples across the public
  library surface, including attribute maps, bindings, crypto, IdP helpers,
  metadata, profiles, PySAML2 compatibility, security defaults, and XML parsing.
- Security hardening documentation covering signature reference binding,
  request/response correlation, trusted SP boundaries, metadata key extraction,
  attribute-release matching, and `KeyInfo` certificate extraction.

### Changed

- `SwedenConnect` `build_authn_request` now carries the `SignMessage` /
  `SADRequest` / `PrincipalSelection` extensions on the typed request's
  `AuthnRequest::extensions` field, so serializing the request emits the
  `<saml2p:Extensions>` block in the schema-correct position (after
  `<saml:Issuer>`). The `SwedenConnectAuthnRequest::extensions_xml` field is
  removed: callers no longer splice a separate extensions string into the
  serialized XML - they just serialize and sign the request.
- `xml::SecureParseConfig` and `parse_secure_with_config`, exposing uppsala's
  parser hardening knobs (`max_depth`, `max_entity_expansion`, parse-time DTD
  rejection, and entity-declaration rejection) while keeping `parse_secure`
  fail-closed for SAML by default.
- Crypto hardening knobs for the bergshamra 0.7 stack:
  `SamlVerifier::set_require_reference_digests`,
  `SamlVerifier::set_allow_raw_inline_keyinfo_with_trust_anchors`, and
  `SamlEncryptor` / `SamlDecryptor` PBKDF2 iteration caps.
- Ready Actix IdP handlers can resolve trusted SP metadata dynamically while
  keeping the same fail-closed trust requirements as statically configured SPs.
  See ADR 0034.

### Security

- XML-DSig verification now binds verified reference IDs to the exact SAML
  object being consumed across ACS, MDQ, Sweden Connect, SPID, and example
  flows. A valid signature elsewhere in the document no longer authenticates a
  different Response or Assertion. See ADR 0028.
- Solicited SAML response processors now require present, matching
  `InResponseTo` values and reject dangling `InResponseTo` on otherwise
  unsolicited flows. This covers artifact resolution, assertion query,
  ManageNameID, NameIDMapping, Sweden Connect, and logout response handling. See
  ADR 0029.
- Ready IdP and federation helper boundaries now require the peer to resolve to
  trusted metadata before issuing assertions, destroying sessions, resolving
  artifacts, or accepting dynamically fetched entities. See ADR 0030 and
  ADR 0034.
- Metadata key extraction and input validation now fail closed for malformed
  trust-anchor fragments, self-closing `X509Data`, namespace-confused X.509
  lookalikes, duplicate Assertion IDs in SPID responses, and unsafe RelayState
  handling. See ADR 0031.
- Attribute release decisions now match on trusted SAML attribute `Name` values,
  never on SP-supplied `FriendlyName`, unless PySAML2 compatibility is
  explicitly enabled with `ReleasePolicy::allow_friendly_name_release_matching`.
  See ADR 0032.
- `SecurityConfig::require_signed_assertions`, SAML `WantAssertionsSigned`, and
  Sweden Connect `want_assertions_signed` now require the consumed Assertion's
  own verified signature. A verified Response signature no longer satisfies that
  direct assertion-signature policy. The Actix ACS helper now verifies all
  enveloped signatures so double-signed Responses still collect both Response
  and Assertion reference IDs, and Sweden Connect `verify_and_process_response`
  verifies decrypted assertion signatures after decryption. See ADR 0037.
- `parse_secure` now rejects `<!DOCTYPE>` at Uppsala parse time instead of
  parsing a bounded DTD and rejecting the resulting document afterward.
- Uppsala 0.9 includes the 0.8 reserved namespace-binding hardening, so illegal
  `xml` / `xmlns` namespace bindings are rejected by the parser instead of
  being accepted into a non-idempotent DOM.
- XML-DSig verification now keeps bergshamra 0.7's local reference-digest
  requirement enabled by default and continues to reject raw inline signing keys
  when trust anchors are configured. The default HMAC truncation floor follows
  bergshamra's hardened 160-bit policy.
- Lockfile-only `anyhow` update to 1.0.103 clears RUSTSEC-2026-0190 from
  `cargo audit --deny warnings`.

## [0.6.0] - 2026-06-28

### Added

- `idp::entity_category`: owned, runtime-constructible entity categories.
  `OwnedEntityCategoryRule` / `OwnedEntityCategoryPolicy` (with `new` /
  `with_rule` / `with_conflicts` / `with_only_required` / `extend_from_static`
  builders), `EntityCategoryRule::as_owned` / `EntityCategoryPolicy::as_owned`,
  and `releasable_attributes_owned`. Callers (including language bindings) can
  now define their own entity categories at runtime and mix them with the
  shipped policies, with identical matching semantics. The shipped `&'static`
  policies are unchanged. `PolicyEntry::with_owned_entity_categories` accepts
  them; `with_entity_categories` keeps its signature. See ADR 0026.
- Metadata extension accessors: `EntityDescriptor::registration_authority()`
  (`mdrpi:RegistrationInfo`), `entity_categories()` and
  `entity_attribute_values()` (`mdattr:EntityAttributes`), backed by the new
  `metadata::types::md_extensions::MdExtensions` (fail-soft, `parse_secure`).
- MDUI and algorithm-support metadata extensions: `MdExtensions` now also parses
  `mdui:UIInfo` (`UiInfo` / `LocalizedText` / `UiLogo`: display names,
  descriptions, information/privacy URLs, keywords, logos) and
  `alg:SigningMethod` / `alg:DigestMethod` (`signing_methods` / `digest_methods`
  / `supported_algorithms()`). `EntityDescriptor` exposes `sp_ui_info()` /
  `idp_ui_info()` (role descriptor first, then entity-level Extensions) and
  `supported_algorithms()` (aggregated across the entity and SSO roles,
  de-duplicated). Used by IdPs to display an SP's name/logo on consent screens
  and to negotiate signing/digest algorithms.
- `idp::policy::ReleasePolicy` registration-authority-based selection:
  `set_registration_authority` / `with_registration_authority` /
  `register_sp_metadata`, resolving SP entity ID > registration authority >
  default (pysaml2 `Policy.get` precedence). See ADR 0027.

### Security

- Added `gamlastan::xml::parse_secure`, a hardened parse entry point for all
  attacker-controlled XML. It is a drop-in replacement for `uppsala::parse`
  that, on top of uppsala 0.5's default resource limits, **rejects any document
  carrying a DTD (`<!DOCTYPE …>`)** so that no DTD-bearing document is accepted
  past the parse boundary — removing the XXE / entity-smuggling entry point from
  downstream SAML handling. All inbound and remote-derived parse sites were
  migrated to it: SP/IdP Actix handlers, SOAP/PAOS envelope unwrap, ECP envelope
  parsing, Sweden Connect response validation/decryption and decrypted
  assertions, IdP-discovery and PEFIM extension parsing, SPID and Sweden Connect
  metadata extensions, `KeyInfo` X.509 extraction, the standalone `ds:Object`
  signature guard, and the MDQ verifier. See ADR 0024.
- Inbound XML is now bounded by uppsala 0.5's fail-closed default limits —
  element-nesting depth (128), entity-expansion byte budget (1 MiB), and
  entity-nesting depth (256) — defeating deep-nesting stack exhaustion and
  billion-laughs / quadratic entity amplification before assertion validation
  runs. uppsala 0.5 also sanitizes serializer output (comments, PIs, CDATA,
  names, encoding, control characters). See ADR 0023.

### Changed

- Upgraded the XML/crypto stack: `uppsala` 0.4 → 0.5, `bergshamra` 0.5.1 → 0.6.0,
  and the direct `kryptering` dependency 0.3 → 0.4 with features mirroring
  bergshamra (`legacy`, `post-quantum`, `pkcs11`) so the shared `Signer` /
  `Pkcs11Signer` types resolve to a single instance with no version or feature
  drift. All are consumed from crates.io. See ADR 0023.
- Migrated `spid-sp-test` and `example-idp` off the unmaintained `rustls-pemfile`
  crate (RUSTSEC-2025-0134) to the `PemObject` API in `rustls-pki-types`, and
  dropped the `rustls-pemfile` dependency.
- IdP response builders now take a `ResponseTimes { issue_instant, authn_instant }`
  value instead of a single `now: DateTime<Utc>`. Affects
  `profiles::sso::idp::{create_response, create_unsolicited_response}` and
  `profiles::swedenconnect::idp::create_response`. Fresh-login callers use
  `ResponseTimes::at(now)` to preserve the previous behaviour.
  `gamlastan_actix::idp::AuthnCallbackResult` gains
  `authn_instant: Option<DateTime<Utc>>` (`None` means "authenticated now"), so
  a callback reusing a session reports its real authentication time. Breaking
  API change. See ADR 0025 and issue #15.

### Fixed

- IdP response construction no longer forces `AuthnStatement/@AuthnInstant` to
  equal the document issue time. The previous single-`now` builders conflated
  *when the principal authenticated* with *when the response was generated*,
  which over-reported authentication freshness to SPs that rely on it (e.g. via
  `RequestedAuthnContext` / `ForceAuthn` or a max-age policy) whenever an
  existing SSO session was reused. The two instants are now independent. See
  ADR 0025 and issue #15.
- Cleared all `cargo audit` findings: `quinn-proto` 0.11.14 → 0.11.15
  (RUSTSEC-2026-0185, remote memory exhaustion), `rand` 0.8.5 → 0.8.6 and
  0.9.2 → 0.9.4 (RUSTSEC-2026-0097), and `crypto-bigint` off the yanked 0.7.3.

## [0.5.0] - 2026-06-21

### Security

- `gamlastan-actix` ACS processing now verifies SAML Response / Assertion
  XML signatures with trusted IdP metadata keys before profile validation or
  claim extraction. Signature markup alone no longer satisfies signed-assertion
  requirements; verified XML-DSig reference IDs are bound to the parsed Response
  or Assertion used for authentication. Added regression coverage for tampered
  signed responses, signature wrapping, and hostile inline `KeyInfo`. See
  ADR 0016.
- Web SSO assertion validation now fails closed when required bearer controls
  are missing: no `Conditions` means the assertion expiry and audience checks
  fail, and bearer `SubjectConfirmationData` without `NotOnOrAfter` fails. See
  ADR 0017.
- SOAP unwrap now validates the SOAP 1.1 namespace, rejects duplicate Header /
  Body elements, and requires exactly one Body element child, closing an
  element-smuggling / wrapping confusion path. See ADR 0018.
- `gamlastan-actix` SP SLO handling now requires trusted signed LogoutRequest
  and LogoutResponse messages, verifies Redirect or XML signatures against IdP
  metadata keys, validates Issuer and Destination, and requires LogoutResponse
  `InResponseTo` to match an outstanding SP-issued LogoutRequest. See ADR 0019.
- XML Signature `ds:Object` rejection is now namespace-aware and shared by the
  verifier and security helper, so alternate XMLDSig prefixes no longer bypass
  SAML errata E91 enforcement. See ADR 0020.
- HTTP Redirect and POST bindings now reject duplicate or ambiguous
  security-sensitive parameters before decoding: duplicate `SAMLRequest`,
  `SAMLResponse`, `RelayState`, Redirect `SigAlg`, Redirect `Signature`, mixed
  request/response parameters, and Redirect `Signature` without `SigAlg`. POST
  decoding now also fails closed on invalid UTF-8 bodies and malformed
  `RelayState` URL encoding. See ADR 0021.
- Generic SP response processing now rejects opaque encrypted-only responses
  and rejects `require_encrypted_assertions` in the generic processor, which
  cannot decrypt or prove encrypted-assertion provenance. See ADR 0022.

### Changed

- `profiles::sso::sp::process_response_with_verified_signatures()` was added
  for callers that perform XML-DSig verification outside the generic SP
  processor and need to pass verified Response / Assertion IDs into validation.
- `SecurityConfig::strict()` and the ready-to-use Actix SP paths are stricter
  about signed messages, SSO bearer validity, and SLO trust/correlation.

### Fixed

- Metadata KeyDescriptor certificate extraction now handles real-world
  `KeyInfo` fragments that rely on inherited XMLDSig namespace declarations.
  The test fixture coverage includes `edugain-v2.xml`.
- POST binding `RelayState` decoding now treats `+` as a form-encoded space and
  returns URL decoding errors instead of falling back to malformed raw values.

### Documentation

- Added ADRs `0016` through `0022` documenting the security decisions from the
  SAML security audit.

### Upgrade Notes

- Direct callers of `profiles::sso::sp::process_response()` that require signed
  assertions or signed responses must either disable those requirements for a
  trusted unsigned deployment or verify the exact XML response with
  `SamlVerifier` and call `process_response_with_verified_signatures()`.
- IdP metadata used by `gamlastan-actix` SP ACS/SLO handlers must contain usable
  signing certificates for signed incoming messages.
- Tests or adapters that previously accepted duplicate SAML binding parameters,
  malformed POST bodies, malformed `RelayState`, missing Web SSO audience /
  expiry controls, unsigned SLO messages, or opaque encrypted-only generic SP
  responses must be updated to expect rejection.

## [0.4.1] - 2026-06-10

### Changed

- `idp::entity_category`: REFEDS Access categories (personalized / pseudonymous
  / anonymous) now use a conflict-aware matcher. `EntityCategoryRule` gained a
  `conflicts` field (the `no_aggregation` flag was removed), mirroring pysaml2's
  `EntityCategoryMatcher` on the `ft-typing` / `ft-refeds_ec` branches: a rule
  matches only when every required category is present and no conflicting
  category is. The three REFEDS Access rules are mutually exclusive yet combine
  with non-conflicting categories (R&S, CoCo, ESI), and are now active by
  default in the `SWAMID` policy. See ADR 0014.

### Added

- `idp::policy`: subject-id / pairwise-id mutual exclusion (pysaml2 PR #987).
  New `SubjectIdReq` (parsed from the SP's `subject-id:req` metadata entity
  attribute) and `prefer_pairwise_over_subject_id()`; `ReleasePolicy::filter()`
  and `restrict()` take a `subject_id_req` argument and drop `subject-id` when
  the requirement is `any` and both `subject-id` and `pairwise-id` would
  otherwise be released. See ADR 0015.

## [0.4.0] - 2026-06-10

### Added

- `idp` module: IdP-side server infrastructure closing the pysaml2 parity
  gaps in IdP attribute handling:
  - `idp::policy::ReleasePolicy` — per-SP attribute release policy engine
    (regex value restrictions, lifetime, NameID format, attribute NameFormat,
    sign targets incl. on-demand, `fail_on_missing_requested`, filtering
    against SP `AttributeConsumingService` required/optional attributes).
  - `idp::entity_category` — shipped entity-category release policies
    (eduGAIN CoCo v1, REFEDS R&S, InCommon R&S, SWAMID incl. CoCo v2/ESI,
    AT eGov PVP2, and opt-in REFEDS personalized/pseudonymous/anonymous
    no-aggregation rules).
  - `idp::ident::IdentDb` — identity database with transient/persistent
    NameID generation honoring `NameIDPolicy` (E14 AllowCreate, E78 stable
    persistent IDs), pluggable `IdentityStore` backend, and server-side
    ManageNameID (NewID/Terminate) and NameIDMapping semantics.
  - `idp::eptid::Eptid` — deterministic eduPersonTargetedID generation
    (SHA-256 based; values intentionally differ from pysaml2's MD5 scheme).
  - `idp::authn_broker::AuthnBroker` — RequestedAuthnContext matching with
    exact/minimum/maximum/better comparison semantics.
  - `idp::assertion_store` — issued-assertion store plus
    `create_assertion_id_request_response()` and
    `create_authn_query_response()` to serve AssertionIDRequest and
    AuthnQuery from stored assertions.
- `attribute_map` module: bidirectional wire <-> local attribute name
  conversion with shipped maps generated from pysaml2's curated collection
  (`saml_uri` with eduPerson/SCHAC/eIDAS/voPerson catalogs, `basic`,
  `shibboleth_uri`, `adfs_v1x`, `adfs_v20`), `allow_unknown_attributes`
  pass-through semantics, and eduPersonTargetedID helpers.
- `AttributeValue::NameId` / `AttributeValueRef::NameId` variants:
  NameID-valued attribute values (EPTID) now parse and serialize as
  structured `saml:NameID` elements instead of raw XML.
- `Assertion.advice` (`Advice` / `AdviceRef`): `saml:Advice` with
  AssertionIDRef/AssertionURIRef references, embedded assertions, and
  embedded encrypted assertions, fully round-tripped.
- Per-request certificate encryption (PEFIM flow):
  `crypto::encryptor::{SamlEncryptor::for_certificate,
  encrypted_data_template_for_cert, CertEncryptionOptions}` and
  `profiles::sso::idp::{encrypt_assertion_to_cert,
  encrypt_response_assertions_to_cert, add_encrypted_advice,
  assertion_to_self_contained_xml}` — encrypt assertions toward a
  certificate supplied in the AuthnRequest (e.g. `pefim:SPCertEnc`) with
  AES-256-GCM + RSA-OAEP defaults.

  Upgrade notes:

  - `Assertion`/`AssertionRef` gained an `advice` field and
    `AttributeValue`/`AttributeValueRef` gained a `NameId` variant; code
    using struct literals or exhaustive matches must add the new
    field/arm.
  - `ProfileError` gained `Crypto` and `Xml` variants.

### Changed

- Discovery Service return URL validation in `profiles::idp_discovery` now
  preserves any query string registered in metadata
  `idpdisc:DiscoveryResponse` endpoints. A caller-supplied `return` URL may
  extend the registered query string, but it may no longer replace it.

  Upgrade notes:

  - If your registered DiscoveryResponse endpoint includes fixed query
    parameters, ensure your discovery service preserves those parameters when
    echoing the `return` URL.
  - Tests and mocks that previously used the same path with different query
    values will now fail validation and should be updated.

- `profiles::logout::SpLogoutOrchestrator` now treats
  `urn:oasis:names:tc:SAML:2.0:status:PartialLogout` as a terminal non-success
  outcome for orchestration state and `progress()` accounting.

  Upgrade notes:

  - `LogoutResponseOutcome` still exposes the wire-level response as
    `success: true` and `partial: true` when the top-level SAML status is
    `Success` with `PartialLogout`.
  - `successful_logouts` now counts only fully successful participants. If you
    previously treated partial logout as a success in orchestration metrics,
    update your code to inspect `outcome.partial` or `failed_participants`.

### Fixed

- ECP envelope parsing in `profiles::sso::ecp` now verifies the SOAP 1.1
  namespace on the `Envelope`, `Header`, `Body`, and `Fault` elements
  (previously only local names were checked) and rejects SOAP Bodies with
  more than one child element, closing an element-smuggling vector.
- `profiles::logout::SpLogoutOrchestrator::handle_response()` now rejects
  LogoutResponses without an `Issuer`; previously the issuer check was
  skipped when the element was absent, allowing spoofed responses to be
  correlated solely by `InResponseTo`.
- Phase-1 ECP parsing in `profiles::sso::ecp` now rejects envelopes that omit
  the mandatory `ecp:Request` header and returns the explicit
  `ProfileError::EcpMissingRequestHeader` error variant.

  Upgrade notes:

  - Callers that pattern-match ECP parse errors should handle
    `ProfileError::EcpMissingRequestHeader` explicitly.
  - ECP phase-1 fixtures and integration tests must include both
    `paos:Request` and `ecp:Request` headers.

### Documentation

- Added ADRs `0005` through `0007` covering discovery return URL matching,
  ECP phase-1 header requirements, and partial logout accounting.

## [0.3.0] - 2026-06-10

Initial curated changelog baseline for the current workspace release.
Earlier `v0.3.0` changes were published before this file existed; consult the
Git history and GitHub release notes for the full change set.

## [0.2.0] - 2026-06-09

Historical release recorded before changelog adoption.

## [0.1.0] - 2026-06-08

Historical release recorded before changelog adoption.

[0.9.1]: https://github.com/kushaldas/gamlastan/compare/v0.9.0...v0.9.1
[0.9.0]: https://github.com/kushaldas/gamlastan/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/kushaldas/gamlastan/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/kushaldas/gamlastan/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/kushaldas/gamlastan/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/kushaldas/gamlastan/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/kushaldas/gamlastan/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/kushaldas/gamlastan/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/kushaldas/gamlastan/releases/tag/v0.3.0
[0.2.0]: https://github.com/kushaldas/gamlastan/releases/tag/v0.2.0
[0.1.0]: https://github.com/kushaldas/gamlastan/releases/tag/v0.1.0
