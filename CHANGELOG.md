# Changelog

All notable changes to this repository will be documented in this file.

The project is still pre-1.0, so minor releases may include behavior changes
where needed to correct protocol handling.

## [Unreleased]

### Changed

- Raised the minimum supported Rust version from 1.88 to 1.89. The patched
  actix-http (3.20.x) and actix-web (4.18.x), which fix RUSTSEC-2026-0446, -0447
  and -0448, require it; the lockfile now resolves them.

## [0.10.0] - 2026-11-06

This release adds the IdP response engine (`idp::orchestrator`) and reshapes the
identity store beneath it. The store, request-model and trusted-SP changes are
**breaking**; each is marked below.

### Added

- `idp::orchestrator`, composing the IdP primitives (`ReleasePolicy`, `IdentDb`,
  `AuthnBroker`, `AssertionStore`) into the SAML Web Browser SSO response flow:
  `ResponseEngine`; `check_request`, the pure ForceAuthn × IsPassive ×
  RequestedAuthnContext decision matrix; `create_authn_response` and
  `create_denial_response`; the pluggable `AttributeRelease` seam
  (`ReleasePolicy`, `PassThroughRelease`, `ChainedRelease`); and a closed `Denial`
  enum with a fixed SAML `Status` mapping, including `AuthnFailed` and
  `Cancelled`. Denials are always signed and are a `DeniedResponse` (`xml`,
  `response_id`), not an `IssuedResponse`, returned by `create_denial_response` and
  carried by `ResponseOutcome::Denied`. A store failure is
  `Err(ProfileError::Store)`, never a signed denial, since the SP did not cause
  it. `example-idp` is built on the engine.
- Authentication-method handling in the engine. With no `RequestedAuthnContext`
  any session or method is accepted, whatever the `AuthnBroker` has registered.
  `AuthnMethodRef::resolve` returns `Option<(String, Option<String>)>`: a
  `BrokerReference` naming no registered method resolves to `None` and is a
  configuration error, so a stale reference cannot become a bogus
  `AuthnContextClassRef` in a signed assertion. An `AuthnMethodRef::Inline`
  method whose class ref literally matches an `exact` request is accepted without
  a broker registration. The method is resolved and checked before the NameID is
  constructed, so a stale reference or a method that does not satisfy the request
  is refused before anything is stored. With an empty broker
  (`AuthnBroker::is_empty`, an `Inline`-only proxy) `check_request` answers an
  `exact` request with `Authenticate` and no methods and the reported method is
  checked at response time; `minimum`, `maximum` and `better` need the broker's
  strength ordering and are denied before login, as is a request that a
  non-empty broker cannot match.
- Sessions and dates in the engine. A session's `authn_instant + session_lifetime`
  is its absolute expiry: reuse is refused past it (and re-checked at response
  time, `AuthnFailed`), and `SessionNotOnOrAfter` on reuse derives from the
  original `authn_instant`, so a reused session cannot slide its own cap. Expiry
  dates are computed up front with checked arithmetic, before the NameID is
  stored: a lifetime that cannot be added to its start (the policy's lifetime,
  the application's `authn_instant`) is a `ProfileError`, not a panic, and nothing
  is stored. A date a response can carry is years 0001-9999, not `chrono`'s wider
  range: `chrono` writes later dates as `+262142-12-31...`, which is not an
  `xs:dateTime` and which `parse_datetime` rejects, and XML Schema 1.0 has no year
  zero. For the session-reuse checks an expiry that cannot be held is judged by
  direction: past the last date it has not been reached (the session is
  reusable); before the first date it long ago passed (not reusable, refused as
  expired).
- NameID policy in the engine. `NameIDPolicy/@SPNameQualifier` is honoured only
  when it equals the requester's own verified entity ID (affiliations are not
  implemented, so there is no `AffiliationDescriptor` membership to verify, and
  honouring an arbitrary value would let one SP request another's persistent
  identifier); another value is denied with
  `InvalidNameIDPolicy`. A requested format longer than `MAX_NAMEID_FORMAT_LEN`
  (256 bytes) is denied the same way. `nameid-format:encrypted` is never issued:
  it asks for an `EncryptedID`, which the response path cannot produce; a request
  naming it is denied, and an SP whose configured default it is gets an error.
  An opt-in supported-format set (`PolicyEntry::with_supported_nameid_formats`,
  `ReleasePolicy::supports_nameid_format`, `ISSUABLE_NAMEID_FORMATS`) denies a
  requested `NameIDPolicy/@Format` outside it before anything is minted; the SP's own default is
  always allowed. **Without one, which is the default, any requested format is
  accepted**, as in pysaml2, so an SP sending invented format strings gets one
  stored record per string.
- Signing in the engine. `SignTargets::resolve` never resolves to "sign nothing":
  Web Browser SSO requires a signed Response or Assertion, so a default
  `ReleasePolicy` signs the assertion and the engine needs a real signing key
  (pysaml2 signs nothing by default); set `SignTargets::response` to sign the
  envelope instead. Per-SP signature and digest selection: `SignatureMethod`
  (SHA-2 RSA and ECDSA), `DigestMethod` (SHA-2), `SigningPreference` and
  `SigningAlgorithms` in `crypto`, and `PolicyEntry::with_signing_preference`. The
  engine signs each response and denial with the first preferred algorithm the SP
  also advertises, else the first listed. Signatures are matched only against the
  SP's `alg:SigningMethod` entries and digests only against `alg:DigestMethod`
  (`SigningPreference::resolve` takes the two lists), read from the entity-level
  extensions and the SAML 2.0 SP role the request was bound to, not from every
  role (`EntityDescriptor::supported_algorithms` aggregates). The advertisement is
  untrusted: it only chooses among the IdP's own entries, and SHA-1, MD5 and the
  like are not representable. With none configured the defaults are the signer's
  method and SHA-256. Lower level: `sign_response_xml_with`,
  `signature_template_with_digest`, `SamlSigner::signature_method_uri_for`. An
  HSM-backed signer can only use its token's algorithm; asking for another is an
  error, but only when something is actually signed, so list only the token's
  method in a preference.
- Attribute release and session settings. `PolicyEntry::with_session_lifetime` and
  `ReleasePolicy::session_lifetime` separate `AuthnStatement/@SessionNotOnOrAfter`
  from the (typically much shorter) assertion lifetime, falling back to it when
  unset. `PolicyEntry::with_deny_unconfigured_release` (and
  `ReleasePolicy::deny_unconfigured_release`) is an opt-in to fail closed: **by
  default, as in pysaml2, an SP that no attribute rule covers is released every
  attribute the application supplied**, because the policy only narrows (entity
  categories, the attributes the SP requests, attribute restrictions). With it on,
  such an SP gets an assertion with no attribute statement. It resolves like the
  other policy settings (SP entry, registration authority, `default`).
  `PassThroughRelease` is unaffected.
- `ResponseParams::new` and `ResponseParams::from_entity` check that the SP
  descriptor is the SP the request was validated for
  (`ProfileError::SpEntityMismatch`); `new` also requires the supplied SP role to
  be one of that descriptor's own (`ProfileError::SpRoleMismatch`), and `from_entity` takes the
  SAML 2.0 role from it. The descriptor's entity categories and `subject-id:req`
  decide what is released, so pairing one SP's request with another's descriptor
  would release under the wrong policy. The fields are public, so
  `create_authn_response` and `create_denial_response` repeat the check.
- `gamlastan-actix`: `AuthnSubjectCallback`, returning an `AuthnSubjectResult` of
  `Authenticated(AuthenticatedSubject)`, `Redirect(HttpResponse)` or `Deny(Denial)`
  for handlers built on `idp::orchestrator`, with the
  processed request, the parsed `&AuthnRequest` (which carries `Scoping`, which a
  proxy must enforce (`ProxyCount`, `IDPList`), and the requested `Subject`), the `&Disposition` and the
  `HttpRequest`; `EstablishedSessionCallback`, reporting whether the request
  already carries an IdP session for `check_request` to weigh; and
  `ResponseEngineParts`, an owned bundle of the engine's dependencies registered
  once as `web::Data<Arc<ResponseEngineParts>>`, from which the SSO handler builds
  a borrowed `ResponseEngine` per request (`ResponseEngineParts::engine`). The SSO handler runs `check_request`
  itself and answers a `Deny` disposition directly, so a callback cannot send the
  user to a login form for `IsPassive` or reuse a session `ForceAuthn` should have
  defeated. On `ReuseSession` it takes the method, `authn_instant` and session
  index from the established session, and the callback must return the session's
  own `subject_id` (another is a `Configuration` error). It returns a
  `Configuration` error when `ResponseEngineParts::idp_entity_id` differs from
  `IdpConfig::entity_id`, and refuses an ACS that resolves to a binding other than
  HTTP-POST (`SamlActixError::UnsupportedBinding`). The `/saml/metadata` handler
  accepts `ResponseEngineParts` and advertises its certificate when an
  `AuthnSubjectCallback` is registered, the only case in which the engine signs;
  with only the low-level `AuthnCallback`, `IdpSigningContext` signs and its
  certificate is advertised. `AuthnCallback` is unchanged.
- `idp::NameIdConstructor`, an object-safe view of `IdentDb::construct_nameid`,
  so `ResponseEngine` is not generic over the store and a fixed-signature
  framework integration can take a Redis- or SQL-backed `IdentDb`.
- Identity store: `IdentityStore::find` and `IdentDb::find_nameid` (pysaml2
  `find_nameid`), the NameIDs of a user matching a `NameIdFilter` on format,
  `SPNameQualifier`, `NameQualifier` and `SPProvidedID`, where an unset field
  matches anything and a record with no `Format` is `unspecified`; `find`
  defaults to filtering `for_user` and a backend overrides it to push the filter
  into a query. `IdentDb::with_persist_transient` (default off, see Changed)
  stores transient NameIDs so `find_local_id` resolves one, which a back-channel
  LogoutRequest carrying one needs; the backend must then expire them, and issuing
  one needs the store to be reachable. A stored transient is never reused by a
  NameIDMapping request.
- Conformance suites for the pluggable backends, each a reusable check with the
  same shape (`run` panics, for Rust tests; `check`, `check_with` and `check_one`
  return the first violation as a `ConformanceError` naming the check, for callers
  that are not Rust tests such as a language binding; `CHECKS` lists the names;
  `Options::threads` sets the concurrent checks' thread count). A failing backend
  call is a failed check naming the operation, not a lost race. They cannot
  prove everything: the concurrent checks run on threads in one process, so a
  backend that serialises its calls can pass without having the constraint, and a
  race between separate processes is not detected.
  - `idp::ident::conformance` for an `IdentityStore`: value uniqueness, the
    durable `(user, SPNameQualifier, NameQualifier, format)` constraint on every
    write path, exact durable lookups, filtered `find` (a pushed-down `format = ?`
    that loses a record with no `Format` fails), `replace` semantics including
    refusing another user's value, scoped removal, and two concurrent checks.
  - `idp::ident::kv_conformance` for a `KeyValueStore` (the `Eptid` cache): an
    absent key is `Ok(None)`, values round-trip and are readable immediately,
    keys are exact, `remove` is scoped, issued values are not evicted, and
    concurrent writers read their own writes and never leave a merged value. A
    cache that loses or lags behind its writes silently issues a different
    identifier, which an SP maps to a different account.
  - `idp::assertion_store::conformance` for an `AssertionStore`: absent reads as
    absent, each ID round-trips with its validity window and authentication
    statement, subject lookup is exact, case sensitive and carries the subject,
    storing an ID again neither duplicates it nor leaves it under its old subject,
    removal clears the subject index, and concurrent stores lose nothing and leave
    an ID under one subject.
- `ResponseOptions::authenticating_authorities` and `impl Default for
  ResponseOptions`; `create_response` writes the field into the `AuthnContext`, so
  a proxying IdP can name the authority it relied on (SAML Core §2.7.2.2).
- `ProcessedAuthnRequest::requested_sp_name_qualifier` (from
  `NameIDPolicy/@SPNameQualifier`), so `IdentDb::construct_nameid` can honour it.
- `AuthnRequest::requested_subject` and `requested_subject_name_id` (pysaml2
  `Request.subject_id()`), with an `EncryptedID` returned as such. The
  orchestrator does not compare it with the authenticated principal, as in
  pysaml2: mapping a NameID to a local user is deployment-specific, so a
  deployment that supports a requested subject must compare it itself.
- `EntityDescriptor::for_sp` (wrap one `SpSsoDescriptor`) and
  `EntityDescriptor::saml2_sp_sso_descriptor` (the SAML 2.0 role, chosen by
  `protocolSupportEnumeration`, not descriptor order); `IdpConfig::trusted_sp_entity`,
  a trusted SP's full entity descriptor alongside `trusted_sp`.
- `AttributeConverter::from_directions`, `add_wire_to_local` and
  `add_local_to_wire`, for independent inbound and outbound maps, which is the
  shape of a pysaml2 attribute map (`MAP["fro"]` and `MAP["to"]`). `add_mapping`
  and `from_entries` set both directions at once and cannot load a map whose
  directions differ, and such maps are real (a deployed eduID `saml_uri` map has
  83 inbound and 99 outbound entries). Mirroring one would make an SP-supplied
  attribute name resolve to a local attribute it did not before. `from_static`
  goes through `from_directions` with identical results for every shipped map.
- A dependency-free `saml_pipeline` benchmark with deterministic signed fixtures
  and separate secure-parse, typed-extraction and verification measurements.

### Changed

- **Breaking: `IdentityStore` is a record-shaped backend**: one record per (user,
  NameID) association (`for_user`, `user_for`, `find_durable`,
  `get_or_insert_durable`, `insert`, `replace`, `remove`, `remove_all`). The 0.9.x
  `get`/`set`/`remove` shape is now `KeyValueStore` (`InMemoryKeyValueStore`),
  which `Eptid` uses. Atomicity comes from two uniqueness constraints the backend
  enforces: the NameID value is unique across all records, and among durable
  records (every format except transient) `(user, sp_name_qualifier,
  name_qualifier, format)` is unique. Two concurrent first requests for one
  (user, SP, format) therefore converge on one identifier, and a removal cannot
  orphan a reverse mapping. The trait has no default write methods (a non-atomic
  default would leave the race open on a multi-instance deployment), and both
  constraints hold on every write path: `insert` and `replace` refuse a second
  durable record of the same format for the same `(user, sp_name_qualifier,
  name_qualifier)` with `InsertError::DurableExists`. `replace` and
  `IdentDb::store` return `InsertError` and `IdentError` (which gains
  `DurableExists`); `get_or_insert_persistent` and `find_persistent` became
  `get_or_insert_durable` and `find_durable` (which takes the format), and
  `InsertError::PersistentExists` became `DurableExists`. `replace` never moves a
  record to another user: a value held by another user is `InsertError::ValueTaken`
  (`IdentError::ValueTaken` from `IdentDb::store`) and left untouched (reassigning would let the new user log in as the old one at every SP
  that has seen it), while the owner can update it in place. `InMemoryIdentityStore`
  takes one lock per call; a Mongo or SQL store must back the constraints with
  real unique indexes (the second a partial unique index on the tuple where the
  format is not transient, an absent format counting as `unspecified`), applied to
  every write, and a store that already holds several records of one format per
  (user, SP), as 0.9.x minted for email and unspecified, must be deduplicated
  before the index can be built. **Migration:** an implementor of the 0.9.x trait (pygamlastan's
  `PyIdentityStore` is one) implements `KeyValueStore` for the `Eptid` cache and the new `IdentityStore` for
  `IdentDb`; code still implementing the old three methods as `IdentityStore`
  fails to compile rather than misbehaving.
- **Breaking: the store traits are fallible.** `IdentityStore`, `KeyValueStore`
  and `AssertionStore` return `Result<_, StoreError>` (the insert paths return
  `InsertError`, which separates a `ValueTaken` conflict from a backend failure),
  and `IdentDb`, `Eptid`, `get_authn_statements`,
  `create_assertion_id_request_response` and `create_authn_query_response`
  propagate it; `IdentError` gains a `Store` variant. A backend that cannot answer
  must return an error, never an empty result: reading an outage as "no record"
  would mint a second "stable" persistent NameID for a user who has one, and make
  `Eptid` recompute a value that may differ from the one already issued.
- **Breaking: stores are verified by default** (`IdentDb::with_store_verification`,
  `Eptid::with_store_verification`; see Security). A backend whose `user_for` lags
  its writes (a read replica, an eventually consistent store) fails the first
  login that creates a NameID with a `StoreError`. Run `idp::ident::conformance`
  against the backend, read from the primary, or pass `false` for a store you
  fully trust.
- **Breaking: `ResponseOptions` gained `authenticating_authorities`**; every
  struct literal must add it or use `..Default::default()`.
- **Breaking: `ProcessedAuthnRequest` gained** `requested_sp_name_qualifier`,
  `has_name_id_policy` and `requested_authn_context_decl_refs`; it is only
  produced by `process_authn_request`, so hand-construction sites need all three.
  `process_authn_request` used to discard `AuthnContextDeclRef`s, so a
  `RequestedAuthnContext` naming only declarations looked like no constraint. An
  `AuthnMethod` carries a class ref only, so a declaration cannot be shown to be
  met: `check_request` and `create_authn_response` deny such a request with
  `NoAuthnContext`, and `ResponseParams::requested_authn_context()` reports it
  (and a present but empty element) as a constraint. A `RequestedAuthnContext`
  naming no class or declaration ref is malformed, and `process_authn_request`
  rejects it with `ProfileError::EmptyRequestedAuthnContext`.
- **Breaking: `gamlastan-actix`'s `TrustedSp.sp_sso: SpSsoDescriptor` is now
  `entity: EntityDescriptor`**, keyed by the descriptor's own `entity_id`:
  `IdpConfig::with_trusted_sp(entity)` replaces `(entity_id, sp_sso)` (wrap a bare
  `SpSsoDescriptor` with `EntityDescriptor::for_sp`), so a mismatched call site
  cannot register one issuer's authorization under another entity's ACS endpoints
  and release policy. `TrustedSpResolver::resolve_sp` returns an
  `EntityDescriptor` and the handler rejects a response whose `entity_id` differs
  from the requested one. The full descriptor is threaded through to
  `idp::orchestrator`, so entity-category release policy engages through the
  handler.
- **Breaking: `AuthnBroker::pick` with `Comparison="exact"` requires a literal
  match** of one of the requested `AuthnContextClassRef` values (saml-core-2.0-os
  3.3.2.2.1), instead of broadening to every method registered at the same
  security level (pysaml2's `AuthnBroker` does broaden; gamlastan diverges).
  `AuthnBroker::allow_exact_level_matching` opts back in, and the engine honours
  it consistently: a same-level method that `check_request` offers is accepted by
  `create_authn_response`, and a session it established is reusable. Every listed
  class ref (or, failing those, declaration ref) is an alternative for every
  comparison, not only `exact`: a method qualifies if it satisfies any of them,
  deduplicated and in the request's order, where `minimum`, `maximum` and `better`
  read only the first ref (so `[unknown, supported]` was denied); this follows the
  spec and differs from pysaml2, and it can only accept requests refused before.
  With no `RequestedAuthnContext` and no `unspecified` method registered, `pick`
  offers every registered method instead of none. Its order is the request's
  class-ref order, then registration order; only `check_request` sorts by
  strength.
- **Behaviour change:** the durable NameID formats other than persistent (email,
  unspecified, any other non-transient format) are stable per `(user, SP,
  NameQualifier, format)`, as persistent always was: an existing record is
  returned instead of a new value being minted. 0.9.x minted and stored a fresh
  value on every call, so an email-format NameID changed at each login, which no
  SP can use to recognise a user, and the store grew with every response.
  `AllowCreate=false` still gates only the persistent format.
- **Behaviour change:** `IdentDb::construct_nameid` treats a request with **no
  `NameIDPolicy` at all** as allowing the IdP to create a persistent identifier.
  0.9.x computed `AllowCreate` as `false` there, so an IdP whose default format
  is persistent refused every first-time user whose request omitted the policy
  with `CreateNotAllowed`. Only an explicit `AllowCreate="false"` forbids
  creating one, and a policy that omits `AllowCreate` is unchanged (`false`, the
  schema default). This matches pysaml2, and it mints a durable identifier where
  0.9.x refused, so check it if SPs omit `NameIDPolicy`. Nothing in 0.9.x's
  response paths called `construct_nameid`, so it concerns applications that did.
- **Behaviour change:** `IdentDb` does not store transient NameIDs by default.
  0.9.x stored every non-persistent NameID, but transient ones are one-time-use
  (SAML Core §8.3.7) and the default per-SP format is transient, so the store
  grew without bound with records never read back. `find_local_id` on a transient
  NameID finds nothing, which matters to a back-channel LogoutRequest carrying
  one; such a deployment opts in with `IdentDb::with_persist_transient`. Issuing a
  transient NameID does not consult the store at all, so it does not depend on the
  store being reachable. `IdentDb` also gives up after 8 attempts to mint an
  unused NameID, with a `StoreError`, instead of looping forever against a broken
  backend.
- **Behaviour change:** ACS endpoint selection honours `ProtocolBinding`, as
  pysaml2 does. A `ProtocolBinding` with no URL or index picks the default
  endpoint among those registered with that binding (an error if none; it used to
  be ignored). An `AssertionConsumerServiceURL` without a `ProtocolBinding` uses
  the binding the URL is registered under, the first in metadata order if several
  (it used to assume HTTP-POST, so a URL registered only under another binding
  failed with `AcsUrlMismatch`). A `ProtocolBinding` given with an index must
  match that endpoint's binding; a URL and an index together resolve by the URL.
  The response still only goes to an endpoint registered in the SP's metadata.
  `ProcessedAuthnRequest::acs_binding` is the registered binding, so it can be
  HTTP-Artifact or HTTP-Redirect. The Actix handler and `example-idp` deliver by
  HTTP-POST only and refuse a request that resolves elsewhere
  (`SamlActixError::UnsupportedBinding`); an application serving such an SP uses
  the profile functions and delivers by `acs_binding`.
- `example-idp` refuses an `AuthnRequest` that names a `Subject`: it issues for
  whoever logs in and does not compare them with a requested principal.
- Reuse one parsed document for enveloped signature policy checks and backend
  verification, eliminating two repeated top-level parses under the default
  policy, with metadata parsing rules, guard order, per-signature results and the
  original XML source for generic transform fallbacks preserved.
- The XML-security stack moves together to bergshamra 0.11.0, uppsala 0.12.0 and
  kryptering 0.7.0, with upstream canonicalization, traversal and key-reuse
  improvements. Consumers passing re-exported XML documents, keys or signers must
  use the matching dependency versions. RustCrypto, legacy algorithm support,
  post-quantum support and PKCS#11 remain enabled, and the SAML algorithm policy
  is unchanged. All workspace packages and internal requirements are 0.10.0; the
  MSRV-aware resolver is used and the Rust 1.88 minimum is kept; the lockfile has
  Rustls 0.23.46 for its security fixes and yoke-derive 0.8.4, replacing the
  yanked 0.8.3.

### Fixed

- `IdentDb::match_local_id` (persistent NameID lookup) matches only a stored
  identifier whose own format is `persistent`, not any non-transient format.
  A persistent request for a (user, SP) pair that already had, say, an
  `email`-format identifier used to return that value labelled `persistent`
  instead of minting or reusing a real one. This matches pysaml2's Mongo-backed
  `IdentMDB.match_local_id`, which filters on the format, not its looser
  shelve-backed `IdentDB`.
- A check-then-create race on persistent NameID minting is closed: two concurrent
  first requests for one (user, SP) could each find no association and mint two
  different "stable" identifiers. `get_or_insert_durable` is atomic, backed by the
  uniqueness constraints (see Changed).
- `InMemoryAssertionStore` keeps both indexes under one lock, and storing an
  assertion ID for a different subject removes it from the old subject's index; a
  lookup for the old subject used to return the other subject's assertion.
- `profiles::sso::idp::create_response` and `ReleasePolicy::not_on_or_after` do not
  panic when a lifetime cannot be added to a date (`chrono`'s `+` panics on
  overflow); both saturate at 9999-12-31T23:59:59Z, the last date an `xs:dateTime`
  can carry. `create_response` also no longer wraps an `assertion_lifetime_seconds`
  above `i64::MAX`, through the old `as i64` cast, into a negative lifetime and so
  an already-expired assertion; it saturates the same way.
- `ReleasePolicy::lifetime` reads a negative configured lifetime as zero, and so
  does `session_lifetime` (including its fallback to the assertion lifetime): a
  negative one has no meaning, and would mint an assertion that is already
  expired or a `SessionNotOnOrAfter` before the authentication time.

### Security

- **Backends are verified, not trusted.** `IdentDb` requires each record a lookup
  returns for a user (`name_ids_for`, `find_nameid`, `match_local_id`, the reads
  inside `get_nameid`) to be one the store's `user_for` attributes to that user,
  and a durable lookup to return the `(SPNameQualifier, NameQualifier, format)`
  slot asked for; otherwise `StoreError`. `find_local_id`, which the NameIDMapping
  and ManageNameID handlers act on, must be confirmed by the owner's own
  `for_user` listing. A lookup that forgot the user in its `WHERE`, a wrong index
  or a stale cache could otherwise hand one user another user's persistent
  NameID, which is account takeover at every SP that has seen it, with nothing
  written to betray it. The check is in `IdentDb`, not in each store method, so
  every lookup made through it is covered, including the default `find` and
  `find_durable` that filter `for_user`. It costs one `user_for` per record
  returned and needs `user_for` to see the store's own writes. On by default;
  `IdentDb::with_store_verification(false)` skips it for a store you fully trust.
- **The `Eptid` cache is shape-checked**: a cached value must be
  `<idp>!<sp>!<opaque>` where the opaque part has no `!` (an entity ID may
  contain one, so a longer SP ID could otherwise pass for this one), otherwise
  `StoreError`. This rejects another IdP's or SP's value and a key written by the
  wrong code. It cannot tell two right-shaped values apart: a cache shared with
  another deployment that uses the same IdP entity ID, a backup restored from one,
  and a forged value (including another user's value for the same IdP and SP) are
  not detected, and a flush is a miss, after which a changed secret or digest
  issues a different value. So the cache must stay private to this IdP and this
  secret, and must not evict. On by default;
  `Eptid::with_store_verification(false)` for a cache whose values were issued
  under an earlier IdP entity ID, or one you fully trust.
- The AssertionIDRequest and AuthnQuery helpers (`get_authn_statements`,
  `create_assertion_id_request_response`, `create_authn_query_response`) do not
  trust the `AssertionStore` to have scoped its answer: an assertion returned for
  a subject must be that subject's, and one returned for an ID must have that ID,
  otherwise `StoreError`. This binds the answer to the NameID value asked about;
  it does not authorize the requester, which stays with the responder.
- `create_authn_response` validates the authenticating authority it signs into
  `AuthenticatingAuthority` (an `xs:anyURI`), whether from an
  `AuthnMethodRef::Inline` or an `AuthnBroker` registration: an absolute URI, a
  scheme with something after it, no whitespace or control characters, at most
  1024 bytes, otherwise a `ProfileError` before anything is stored. The check is at
  response time, so the released `AuthnBroker::add` signature is unchanged.
- The engine verifies nothing about the authentication method the application
  reports: an `AuthnMethodRef::Inline` class ref satisfies an `exact`
  `RequestedAuthnContext` by matching the request, so building it from the request
  signs a context that was never established. The warning is on `Inline`, on
  `AuthenticatedSubject::authn_method` and in the `idp::orchestrator` module docs.
- **Behaviour change:** AuthnRequest parsing and processing do not repair
  malformed input into a more permissive request. An `IDPEntry` without the
  required `ProviderID` is rejected (it used to be dropped, shrinking a restrictive
  `IDPList`, possibly to an empty one, which reads as no restriction). A repeated
  `Subject`, `NameIDPolicy`, `Conditions`, `RequestedAuthnContext`, `Scoping` or
  `IDPList` is rejected (only the first used to be read). A `Subject` carrying a
  `SubjectConfirmation` is rejected with
  `ProfileError::SubjectConfirmationInAuthnRequest`, a variant that existed but was
  never raised. `ProcessedAuthnRequest` documents what it does not carry:
  `Scoping`, which a proxying IdP must read from the original request itself, and
  the principal named by `Subject`.
- `IdpConfig::trusted_sp_verifier` (the aggregate verifier built from every
  registered trusted SP) filters each entity's roles by SAML 2.0 protocol support
  before collecting signing certificates, so a certificate published only for a
  non-SAML-2.0 role cannot become trusted for verifying SAML 2.0 messages.

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
