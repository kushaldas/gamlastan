# ADR 0045 - IdP response orchestration as a crate-level engine

- **Status:** Accepted
- **Date:** 2026-09-18
- **Deciders:** gamlastan maintainers
- **Spec:** SAML V2.0 Profiles §4.1 (Web Browser SSO), SAML V2.0 Core §2.5/§2.7
- **Related:** [0008](0008-idp-server-infrastructure.md) (IdP server infrastructure),
  [0033](0033-idp-response-signing-helpers.md) (in-core signing helpers)
- **Implementation:** `crates/gamlastan/src/idp/orchestrator/`,
  `crates/gamlastan/src/idp/{ident.rs,ident/conformance.rs,policy.rs,authn_broker.rs,assertion_store.rs,eptid.rs}`,
  `crates/gamlastan/src/crypto/algorithms.rs`, `crates/gamlastan/src/profiles/sso/idp.rs`,
  `crates/gamlastan-actix/src/idp.rs`, `example-idp/src/main.rs`

## Context

ADR 0008 added `gamlastan::idp` (`policy`, `entity_category`, `ident`, `eptid`,
`authn_broker`, `assertion_store`) and deliberately stopped at the primitives, on
the stated model that an integrator wires a `ReleasePolicy`, an `IdentDb`, an
`AuthnBroker`, and an `AssertionStore`. That boundary didn't hold:
`ReleasePolicy::filter`, `IdentDb::construct_nameid`, `AuthnBroker::pick` and
`Eptid` had zero callers in any response-assembly path.

Meanwhile the consuming contract evolved to expect the primitives' outputs, not
to produce them: `gamlastan-actix`'s `AuthnCallback` returns an already-built
`name_id`, already-filtered `attributes`, and an already-matched
`authn_context_class_ref`. So the crate shipped both the policy engine and an
interface shaped around its outputs, leaving every integrator to write the same
bridge: run the release policy, construct or look up the NameID, match the
requested authn context, populate `ResponseOptions`, sign. That bridge is not
deployment-specific -- it is the SAML Web Browser SSO profile.

Two real consumers needed that bridge, wrote it independently instead of
calling into `gamlastan::idp`, and diverged. `example-idp` is the de-facto
reference implementation (honours `IsPassive`, `ForceAuthn`, ACR comparison,
signed protocol errors) but lived in example code, uncovered by the crate's
compatibility promise. SUNET's `tunnelbana` proxy hand-rolls the same path and
imports nothing from `gamlastan::idp`: its `legacy_eptid` micro-service
reimplements the MD5 construction `idp::eptid` already ships behind
`allow_legacy_md5` (ADR 0036), and its own per-SP policy map is a narrower,
weaker version of `idp::policy::ReleasePolicy` that is missing entity-category
release -- the piece that matters most for a proxy fronting SWAMID SPs.

Separately, the message-building API assumed an originating IdP only:
`create_response` hardcoded `authenticating_authorities: vec![]`, though the
core `AuthnContext` type carries it and the XML layer serialises it. A
proxying IdP is required by SAML Core §2.7.2.2 to name the authority it relied
on and could not, through this API.

## Decision

Add a response-orchestration layer to `gamlastan::idp` that composes the
existing primitives into the profile flow, and move the semantics proven in
`example-idp` into tested library code.

1. `idp::orchestrator::ResponseEngine`, given a processed `AuthnRequest`, SP
   metadata, and identity facts from the application, performs:

   | Step | Existing primitive | Fixed or injected? |
   | --- | --- | --- |
   | Release decision | `ReleasePolicy` + `EntityCategoryPolicy` | Injected (see below) |
   | NameID construction / lookup | `IdentDb` (+ `Eptid`) behind `IdentityStore` | Injected store, fixed mechanics |
   | RequestedAuthnContext match | `AuthnBroker` | Injected broker, fixed comparison semantics |
   | Request-constraint handling | `IsPassive`, `ForceAuthn`, requested NameID format, session expiry | Fixed (`check_request`) |
   | Assemble + sign | `ResponseOptions` -> `create_signed_response` (ADR 0033) | Fixed; algorithms from the per-SP `SigningPreference` |
   | Record for back-channel queries | `AssertionStore` | Injected store |

   `RequestedAuthnContext` matching for `Comparison="exact"` is a literal
   match of one of the requested `AuthnContextClassRef` values
   (saml-core-2.0-os 3.3.2.2.1), not "registered at the same security level
   as the requested class" -- pysaml2's own `AuthnBroker` has that looser
   behaviour, and gamlastan intentionally diverges from it for spec
   conformance. `AuthnBroker::allow_exact_level_matching` restores the
   pysaml2-compatible behaviour for integrators who need parity over strict
   conformance; the response and session-reuse checks honour it as well as
   `check_request`, so a method that was offered is accepted once the user
   authenticates with it. A request whose `RequestedAuthnContext` names only
   `AuthnContextDeclRef`s is denied with `NoAuthnContext`: an `AuthnMethod`
   carries a class ref only, so a declaration constraint cannot be shown to be
   met, and treating it as no constraint would reuse any session or issue any
   class ref. The same goes for a `RequestedAuthnContext` element that names
   nothing: the schema requires at least one ref, so `process_authn_request`
   rejects it (`ProfileError::EmptyRequestedAuthnContext`) and the engine
   denies it for hand-built parameters, instead of collapsing it into the same
   state as an absent element.

   NameID construction rejects a `NameIDPolicy/@SPNameQualifier` that names
   an entity other than the verified requester: per saml-core-2.0-os 8.3.7
   it may legitimately name an affiliation the requester belongs to, but
   only when the IdP can verify that membership (`AffiliationDescriptor`),
   which this crate does not implement. Honouring an arbitrary
   requester-supplied value would let one SP request another SP's pairwise
   persistent identifier for the same subject just by naming it in its own
   request -- so a mismatched qualifier is denied (`InvalidNameIdPolicy`)
   rather than passed through. Persistent NameID minting is also
   concurrency-safe, without a multi-key transaction: `IdentityStore` is a
   record-shaped trait (one record per (user, NameID) association), and
   atomicity comes from two uniqueness constraints the backend must enforce
   -- the NameID value is unique across all records, and among durable
   records (every format except transient) `(user, sp_name_qualifier,
   name_qualifier, format)` is unique -- plus single-record operations
   (`get_or_insert_durable`, `insert`, `replace`, `remove`). Two concurrent
   first requests for the same (user, SP, format) therefore converge on one
   identifier. Every durable format is stable, not only persistent: an email or
   unspecified NameID that was minted anew at each login (as 0.9.x did) cannot
   identify anyone to an SP and grows the store with every response. Nothing in this crate can detect a
   missing constraint, so the trait has no default write methods and
   `ident::conformance::run` checks that a backend honours the contract.
   Both constraints hold on every write path -- `insert` and `replace` refuse
   a second durable record of the same format for the same `(user,
   sp_name_qualifier, name_qualifier)` (`InsertError::DurableExists`) just as
   `get_or_insert_durable` returns the existing one -- and the suite checks
   each path, since a backend can guard one and forget another. `replace`
   updates a record in place for its owner but never moves it to another user
   (`ValueTaken`): reassigning a value would let the new user log in as the old
   one at every SP that has seen it.
   `InMemoryIdentityStore` takes one lock per call; a Mongo/SQL-backed store
   must back the two constraints with real unique indexes (the second a
   partial unique index on `(user, sp_name_qualifier, name_qualifier, format)`
   where the format is not transient), applied to every write. The plain
   `get`/`set`/`remove` shape remains as `KeyValueStore`, which `Eptid` uses. Every store method is
   fallible (`StoreError`; `InsertError` for the two insert paths, which also
   reports a `ValueTaken` conflict): a backend that cannot answer must not
   return an empty result, because reading an outage as "no record" would mint
   a second persistent identifier for a user who already has one. A store
   failure surfaces from the orchestrator as `Err(ProfileError::Store)`, never
   as a signed denial.

   A requested format longer than `MAX_NAMEID_FORMAT_LEN` (256 bytes) is
   refused whatever is configured, since it is stored with each durable record.

   Refusing requested NameID formats is opt-in. By default any
   `NameIDPolicy/@Format` is honoured, as in pysaml2, which never validates it
   (so an SP that sends invented format strings gets one stored record per
   string). An IdP that configures a per-SP supported set
   (`PolicyEntry::with_supported_nameid_formats`; `ISSUABLE_NAMEID_FORMATS` is
   a reasonable starting point) gets `InvalidNameIDPolicy` (SAML Core 3.4.1.1)
   for a format outside it, before anything is minted or stored; the SP's own
   default format is always allowed. Strict-by-default was considered and
   rejected: it can turn a login that works today into a denial for a
   pysaml2 deployment, for little gain.

   Transient NameIDs are one-time-use (SAML Core §8.3.7) and the default
   per-SP format is transient, so by default `IdentDb` mints them without
   storing them: storing every one would add a record per response that is
   never read back. The consequence is that `find_local_id` cannot resolve a
   transient NameID, which a back-channel (SOAP) LogoutRequest carrying one
   needs in order to find the user. A deployment that needs that opts in with
   `IdentDb::with_persist_transient`. The record trait has no expiry, so such
   a backend must expire the records itself (a TTL index, a periodic purge),
   and issuing a transient NameID then needs the store to be reachable. A
   stored transient is still never handed out again, e.g. by a NameIDMapping
   request. 0.9.x stored them, so this default is a behaviour change.

   The default release policy only narrows: with no entity categories, no
   attributes requested in the SP's metadata and no restrictions, an SP is
   released every attribute the application supplied, as in pysaml2 and as
   `ReleasePolicy::filter` already did in 0.9.x. The application is then the
   only filter. Failing closed is opt-in
   (`PolicyEntry::with_deny_unconfigured_release`), for the same reason as the
   NameID format list: a default-deny would give a deployment that sets only a
   lifetime or signing option, and relies on pysaml2's "release unless
   restricted", assertions with no attributes.

   Attribute release is a seam, not a hardwired step, because deployments
   legitimately source the released set differently: an originating IdP
   applies federation policy (`ReleasePolicy` + entity categories); a proxy
   receives attributes already filtered upstream and may add a per-requester
   layer, as tunnelbana does. Release is the `AttributeRelease` trait, with
   `ReleasePolicy` itself, `PassThroughRelease` for pre-filtered inputs, and
   `ChainedRelease` composing the two. Everything downstream of it -- NameID
   negotiation, `InResponseTo`, audience and conditions, session index and
   lifetime, `IsPassive`/`ForceAuthn` enforcement, signed protocol errors -- is
   fixed.

   A failure to satisfy a constraint produces a signed SAML protocol error (a
   closed `Denial` enum with a fixed `Status` mapping), not an
   application-level error, matching what `example-idp` did before this ADR.
   Denials always sign the Response envelope unconditionally, regardless of
   the per-SP `SignTargets` -- an unsigned denial is trivially forgeable.
   Signature and digest algorithms follow the per-SP `SigningPreference`,
   resolved against the SP's metadata advertisement but only ever among the
   IdP's own entries (the advertisement is untrusted); with none configured
   the signer's defaults (RSA-SHA256, SHA-256) apply. The advertisement is
   read from the entity-level extensions and the SAML 2.0 SP role the request
   was bound to, not from every role of the entity; signatures are matched
   against `alg:SigningMethod` entries and digests against `alg:DigestMethod`
   entries separately. The orchestrator never issues an unsigned success
   response: `SignTargets::resolve` signs the assertion when the response is
   not signed (SAML Profiles 4.1.4.5), so the default policy signs the
   assertion. An empty `AuthnBroker` means an `Inline`-only deployment with no
   capabilities to check, so for an `exact` request `check_request` leaves the
   decision to the response-time check instead of denying before login; the
   other comparisons cannot be met without the broker's strength ordering and
   are denied.

2. Invert the application contract. The application supplies what only it
   knows -- subject identifier, raw attribute values, which authentication
   method actually ran, authn instant, session index (`AuthenticatedSubject`)
   -- and the engine derives `name_id`, released `attributes`, and
   `authn_context_class_ref`. The existing `AuthnCallback`/`AuthnCallbackResult`
   remains as the lower-level escape hatch; `gamlastan-actix` gains
   `AuthnSubjectCallback`/`AuthnSubjectResult`
   (`Authenticated(AuthenticatedSubject) | Redirect(HttpResponse) |
   Deny(Denial)`) alongside it. This is additive; nothing existing breaks.

   The SSO handler calls `check_request` itself, before invoking
   `AuthnSubjectCallback`, and passes the resulting `Disposition` to the
   callback (via a new optional `EstablishedSessionCallback` reporting local
   session state, distinct from `SessionStore`, which tracks SP-participant
   state for SLO). A `Deny` disposition is handled directly as a signed
   protocol error -- the callback is never invoked for it. This is the part
   that actually inverts the contract: the callback no longer has to
   (mis)judge `ForceAuthn`/`IsPassive`/`RequestedAuthnContext` itself, it only
   supplies attributes and performs the login `check_request` says is needed.
   The callback also receives the parsed `AuthnRequest`, because the processed
   request leaves out `Scoping` and the requested `Subject` and a POST body is
   already consumed: a proxy enforces `ProxyCount`/`IDPList` there, and a
   re-login flow compares the subject. `create_authn_response` re-checks a
   reused session's absolute expiry at issuance, since the callback may have
   run past it after `check_request` approved the reuse. On a reused session the
   handler takes the method, authn instant and session index from the session
   and refuses (a `Configuration` error) a callback that names a different
   subject, instead of signing one user's NameID over another's attributes.

   `gamlastan-actix` registers the engine's dependencies as an owned
   `ResponseEngineParts` (`Arc<ReleasePolicy>`, `Arc<dyn AttributeRelease>`,
   `Arc<dyn NameIdConstructor>`, `Arc<AuthnBroker>`, `Arc<SamlSigner>`, ...)
   rather than a `ResponseEngine<'static>` directly: `ResponseEngine` borrows
   by design (a zero-cost fit for one synchronous call), but a route
   handler's signature is fixed and registered once, so requiring `'static`
   on every borrowed dependency would force ordinary application-owned state
   to be leaked. The handler builds a short-lived borrowed `ResponseEngine`
   from `ResponseEngineParts` per request.

   The `/saml/metadata` handler resolves its published signing certificate
   from `ResponseEngineParts` first (only when an `AuthnSubjectCallback` is
   registered too, which is the only case in which the engine signs), then
   `IdpSigningContext`, then `IdpConfig::signing_cert_b64`: the metadata
   handler previously knew
   nothing about `ResponseEngineParts` at all, so a deployment registering
   only it (the documented policy-driven setup) signed real responses while
   publishing no key in its own metadata, and a deployment registering both
   with different certificates published a key that never actually signs
   anything.

3. Keep deployment specifics behind the seams ADR 0008 already defined --
   `IdentityStore`, `AssertionStore`, the `AuthnCallback` escape hatch, and
   `ReleasePolicy`/`EntityCategoryPolicy` configuration. No consumer identity
   model, userdb, or federation policy choice enters the crate.

   `gamlastan-actix`'s trusted-SP registry (`IdpConfig`/`TrustedSp`/
   `TrustedSpResolver`) stores the SP's full `EntityDescriptor`, not just its
   SSO descriptor, keyed by the descriptor's own `entity_id` (no separate
   registration-key field, so the two cannot drift apart) -- entity
   categories and other entity-level extensions need to reach
   `ResponseParams::sp_entity` for the attribute-release seam to see them.
   Because that descriptor's entity categories and `subject-id:req` decide what
   is released, `ResponseParams::new` / `from_entity` check that it is the SP the
   request was validated for, and `create_authn_response` /
   `create_denial_response` repeat the check (the fields are public), so one
   SP's request cannot be released under another SP's policy.

4. In-crate module, not a new crate, consistent with ADR 0008's reasoning: it
   depends only on `gamlastan` internals.

Naming: `idp::orchestrator`, not `idp::server` -- `server` implies a stateful
daemon, a mental model that belongs one layer up in a language binding's own
`Server` facade, not in this crate. `ReleasePolicy::fail_on_missing_requested`
(already existed) now drives `Denial::MissingRequiredAttributes` when a
required attribute the SP asked for was not released, so partial-release
failure is a real protocol error rather than a silent per-integrator choice.

## Consequences

- The `gamlastan::idp` primitives acquired callers; the module is usable as a
  policy-driven IdP rather than a toolkit each integrator assembles from
  scratch.
- Response assembly -- NameID correctness, audience and conditions, what is
  signed -- is exercised by the crate's own test suite and attack corpus
  rather than reimplemented per deployment.
- `example-idp` was rewritten onto the engine: production code (excluding
  tests) shrank from 1514 to 1498 lines, with the hand-rolled
  `build_saml_response`/`build_saml_error_response`/`render_saml_response`/
  `select_authn_context`/`authn_context_satisfies` plumbing replaced by calls
  into `check_request`/`create_authn_response`/`create_denial_response`.
- A convergence path exists for tunnelbana's hand-rolled assembly and its
  `legacy_eptid` micro-service, though adopting it is not a precondition of
  this ADR.
- A second, higher-level authentication contract now needs documenting and
  supporting alongside the existing one. Mitigated by making the old path the
  explicit escape hatch.
- Opinionated ordering: the engine fixes the sequence policy -> authn
  context -> NameID -> assemble (everything that can refuse before the first
  store write). Deployments needing a different order use the
  low-level path.
- Breaking (pre-release): `ResponseOptions` gained
  `authenticating_authorities: Vec<String>` (with a new `impl Default`), and
  `ProcessedAuthnRequest` gained `requested_sp_name_qualifier`,
  `has_name_id_policy` and `requested_authn_context_decl_refs`. Every in-crate
  struct literal was fixed with
  `..Default::default()`. External consumers with hand-built
  `ResponseOptions` literals (tunnelbana: 7 sites across
  `saml2_frontend.rs`, `saml2_backend.rs`, `stepup.rs`, and four test
  files) need a one-line compat patch, prepared separately and offered to
  SUNET alongside this ADR rather than discovered via a failed build.
- Behaviour change: ACS endpoint selection honours `ProtocolBinding` as
  pysaml2 does (a binding alone narrows the default endpoint; a URL without a
  binding uses the one it is registered under instead of assuming HTTP-POST; a
  binding given with an index must agree with it). The response still goes only
  to an endpoint registered in the SP's metadata. `acs_binding` can therefore be
  Artifact or Redirect; the ready Actix handler and `example-idp` deliver by
  HTTP-POST only and refuse such a request (`UnsupportedBinding`), and an
  application that must serve it delivers by `acs_binding` itself.
- Not handled by the engine: `Scoping` and the principal named by an
  AuthnRequest `Subject`. An originating IdP can ignore `Scoping`, but a proxy
  must enforce `ProxyCount` and `IDPList` itself (SAML Core 3.4.1.2), reading
  them from the original request, since `ProcessedAuthnRequest` does not carry
  them. A `Subject` is checked only for the forbidden `SubjectConfirmation`;
  the assertion is issued for the authenticated subject whatever principal it
  names, as in pysaml2, which leaves that comparison to the application too
  (eduID's re-login and MFA step-up flows send a subject and enforce it in
  application code, for allowlisted SPs only).
  `AuthnRequest::requested_subject` reads it for an application that supports
  a requested subject, and the Actix `AuthnSubjectCallback` receives the parsed
  request so it can enforce both; `example-idp` supports neither and refuses a
  request that names a `Subject`. The request parser rejects what it used to repair: an `IDPEntry`
  without `ProviderID`, and a repeated singleton child, so what a consumer
  reads is what the SP sent.
- `AuthnBroker::pick` treats every listed class ref (else decl ref) as an
  alternative for every comparison and returns the deduplicated union in the
  request's order (SAML Core 3.3.2.2.1); pysaml2 reads only the first ref for
  `minimum`, `maximum` and `better`. `nameid-format:encrypted` is never issued
  (it asks for an `EncryptedID` the response path cannot produce), even with
  no supported-format set configured; the check is on the effective format,
  so an encrypted SP default is a configuration error. With no
  `RequestedAuthnContext` and no `unspecified` method registered, `pick`
  offers every registered method.
- Behaviour change: `SignTargets::resolve` never resolves to "sign nothing" (see
  above), so the default policy signs the assertion and the engine needs a
  signing key; pysaml2's default signs nothing. A denial is a `DeniedResponse`
  (`xml`, `response_id`), not an `IssuedResponse` with a fabricated NameID.
- Breaking (pre-release): `AuthnBroker::pick` with `Comparison="exact"`
  changed from level-based matching to literal class-ref matching (see
  above). Any integrator relying on the old broadened behaviour must pass
  `allow_exact_level_matching(true)` explicitly.
- Breaking: `IdentityStore` is now the record-shaped NameID backend; the
  get/set/remove trait of 0.9.x is `KeyValueStore` (used by `Eptid`). An
  external implementor of the old trait exists (pygamlastan's
  `PyIdentityStore`); it must implement `KeyValueStore` for the `Eptid` cache
  and the new `IdentityStore`, including the two uniqueness constraints (see
  above). Code that still implements the old methods as `IdentityStore` fails
  to compile rather than misbehaving.
- Breaking: every store method is fallible, so `IdentDb`, `Eptid` and the
  assertion-query helpers return `Result` (see above).
- Behaviour change: durable formats other than persistent (email, unspecified)
  are stable per (user, SP, format) instead of being minted anew at each login,
  as `IdentDb` always did for persistent, matching what pysaml2's server does
  by looking up an existing NameID before constructing one (see above).
- Behaviour change: a request with no `NameIDPolicy` at all no longer counts as
  `AllowCreate=false`, so the IdP may mint a persistent identifier in its default
  format; 0.9.x refused with `CreateNotAllowed`, which made a persistent-default
  IdP deny every first-time user whose request omitted the policy. An explicit
  policy with `AllowCreate="false"` still forbids creation, and a present policy
  that omits `AllowCreate` is still `false`. pysaml2's SSO flow never consults
  `AllowCreate` and always mints; gamlastan is stricter in honouring an explicit
  `false`. Persistent format only.
- Behaviour change: transient NameIDs are no longer stored by default (see
  above), so `find_local_id` on one finds nothing unless
  `IdentDb::with_persist_transient` is set.

## Alternatives considered

- **Status quo -- leave orchestration to the integrator (ADR 0008's
  position).** The bridge is not where integrators actually differ: they
  differ in identity sources and policy configuration, both already behind
  seams. What they duplicated was profile mechanics, the crate's subject
  matter, and the duplication was invisible until someone got `InResponseTo`,
  audience restriction, or NameID format subtly wrong.
- **Put the engine in a language binding.** Rejected: layering inversion.
  Orchestration is protocol logic, not language binding; placing it there
  makes it usable from one binding only, so every Rust IdP built on this
  crate re-implements it -- which tunnelbana's SAML frontend had already
  done.
- **Each deployment implements it in application code.** Rejected as a
  general answer: it puts SAML profile mechanics outside the crate whose
  subject matter they are, and makes every deployment the long-term
  maintainer of a private copy.
- **A separate `gamlastan-idp` crate.** Deferred for the reasons ADR 0008
  gave; nothing here changes that calculus.
- **Promote `example-idp` verbatim.** Rejected: it hardcoded single-instance
  choices and an in-memory session model. Its semantics were lifted; its
  structure was not.

## Validation

- `idp/orchestrator/tests.rs`: `Denial::status()` exhaustive; `AttributeRelease`
  impls incl. `ChainedRelease` ordering; the ForceAuthn/IsPassive/
  RequestedAuthnContext matrix, including refusing to reuse a session past
  its own absolute expiry (`authn_instant + session_lifetime`); NameID
  default-format fallback, `SPNameQualifier` precedence and cross-entity
  rejection, `AllowCreate=false` denial; `SessionNotOnOrAfter` on a reused
  session derived from the session's original `authn_instant`, not `now`;
  and a falsification test proving a `PassThroughRelease` + inline-authn-method
  proxy shape produces a compliant response without `ReleasePolicy::filter`
  ever running.
- `idp/ident.rs`: concurrent persistent-NameID minting for the same
  (user, SP) resolves to one identifier; concurrent persistent and durable
  non-persistent issuance don't affect each other; a store outage is an error
  and never a missing record (no second persistent identifier is minted), and
  issuing a transient NameID works while the store is down; with
  `with_persist_transient` a stored transient resolves through
  `find_local_id`, is removable, never satisfies a persistent lookup, and is
  never reused by a NameIDMapping request; `find_nameid` filters on every
  field.
- `ident::conformance`: the backend contract suite (value uniqueness,
  durable get-or-insert for persistent and email, the durable constraint on
  `insert` and `replace`, `replace` refusing another user's value, filtered
  lookup, scoped removal, and two concurrent
  checks run for both formats) passes on `InMemoryIdentityStore` and is
  verified to fail against a backend with no value uniqueness, a
  check-then-insert backend, a backend that guards only
  `get_or_insert_durable`, one that guards `insert` but not `replace`, and one
  whose `replace` reassigns a record to another user. The
  non-panicking `check` / `check_one` entry points return the
  violation, run a check by name, and report a failing backend call as a
  failed check rather than a lost race.
- `idp/orchestrator/tests.rs` (store and signing): an identity-store outage
  during NameID construction is `Err(ProfileError::Store)` and not a signed
  denial; an assertion store that cannot record is an error, not "issued";
  `Denial::AuthnFailed` / `Cancelled` are signed `Responder/AuthnFailed`
  responses; a configured `SigningPreference` is used for an issued response
  and for a denial, and the signer's defaults apply without one; a
  declaration-only or empty `RequestedAuthnContext` is denied (never treated as
  unconstrained); `allow_exact_level_matching` is consistent between
  `check_request` and the response; the advertised algorithms come from the
  entity and the requested role only; a descriptor for a different SP, or an
  SP role that is not one of the descriptor's own, is refused by
  `ResponseParams::new` and by both response paths. `gamlastan-actix`: `/saml/metadata`
  advertises the certificate of the path that signs (the engine's only with an
  `AuthnSubjectCallback`).
- `idp/orchestrator/tests.rs` (NameID formats): by default any requested
  format is accepted; with a supported set configured, an unsupported one (an
  invented one, `encrypted`, X509SubjectName) is denied with
  `InvalidNameIDPolicy` and records nothing, each issuable format is issued,
  and the SP's own default format needs no listing; an email-format NameID is the same on every login and the store
  holds one record, not one per response. `idp/ident.rs`: email and
  unspecified are stable per (user, SP, format), concurrent first requests for
  one converge, and `store` refuses a second record of a durable format.
- `profiles/sso/idp.rs` (ACS resolution): a URL registered only under a
  non-POST binding resolves without a `ProtocolBinding`; a URL registered under
  several bindings picks the first, or the requested one; the (URL, binding)
  pair and an unregistered URL are still refused; a binding alone picks the
  default of that binding and errors when none is registered; an index and a
  binding must agree.
- `crypto::algorithms` and `crypto::signer`: weak and unknown algorithm URIs
  are not representable; the first IdP preference the SP also advertises wins,
  an SP advertising nothing usable gets the IdP's first choice, and an SP
  cannot introduce an algorithm the IdP did not list; an HSM-backed signer
  refuses a signature method other than its token's. `tests/response_signing.rs`
  signs a response and its assertion with RSA-SHA512 and a SHA-512 digest, and
  with ECDSA P-256/SHA-256, P-384/SHA-384 and P-521/SHA-512 (EC fixtures), and
  verifies both signatures each time.
- Further orchestrator tests: the default policy signs the assertion; an empty
  broker defers an `exact` request to the callback and denies the other
  comparisons; the effective NameID format (a default as well as a requested
  one) cannot be `encrypted`; an authn method that is stale, unsatisfying or
  attached to an expired session is refused before anything is stored; the SP
  role must belong to the supplied entity; a denial carries no assertion data.
  `idp/authn_broker.rs`: every listed class ref is an alternative.
  `idp/assertion_store.rs`: re-storing an ID for another subject leaves the old
  subject's index. `gamlastan-actix`: the callback sees `Scoping`, a reused
  session pins subject, instant and index, and an engine whose Issuer differs
  from `IdpConfig::entity_id` is refused.
- `idp/policy.rs` / `idp/orchestrator/tests.rs`: with nothing configured every
  supplied attribute is released (pinned); `with_deny_unconfigured_release`
  releases none for an uncovered SP, is lifted by SP-requested attributes or
  restrictions, and can be overridden per SP.
- `idp/authn_broker.rs`: exact matching excludes a method registered at the
  same security level under a different, unrequested class ref by default;
  `allow_exact_level_matching` restores the old pysaml2-compatible
  broadening.
- `metadata/types/entity_descriptor.rs`: `saml2_sp_sso_descriptor` selects
  by `protocolSupportEnumeration`, skipping a non-SAML-2.0 role listed
  first in a multi-role entity.
- `tests/idp_orchestration_roundtrip.rs`: orchestrated XML through the real
  SP-side verification path, asserting `InResponseTo`, `NameID`, session
  index, `authenticating_authorities`, and `NotOnOrAfter` all survive, with
  both signatures verifying.
- `tests/idp_release_through_engine.rs`: REFEDS entity-category release
  driven through `create_authn_response`, confirming only the released
  attributes reach the signed XML.
- `tests/attack_corpus.rs` (`orchestrator_attacks`): an explicit, unrecognized
  `AttributeConsumingServiceIndex` is denied rather than silently falling
  through to "no requirements" (which would bypass that service's own
  attribute scoping); an `SPNameQualifier` XML-injection payload equal to
  the requester's own entity ID comes back escaped and inert (a qualifier
  naming a *different* entity is rejected outright before response assembly
  -- covered in `idp/orchestrator/tests.rs`); a denial's `StatusMessage`
  never echoes SP-supplied text.
- `example-idp` rewritten on the engine; all 13 of its tests pass against a
  real fixture signing key (denials now sign unconditionally, so a keyless
  test signer no longer suffices).
- `gamlastan-actix`'s `idp_sso` policy-driven path, exercised end-to-end for
  the first time (it had zero test coverage before this ADR): a callback is
  skipped entirely and a signed denial returned when `check_request` says
  `Deny`; the callback is invoked normally when authentication is needed;
  entity-category release reaches the signed response through the real
  handler (not just the core engine in isolation); a non-default
  `IdentityStore` works through `ResponseEngineParts`; a `TrustedSpResolver`
  returning a mismatched `entity_id` is rejected.
- `/saml/metadata`'s certificate resolution: `ResponseEngineParts` wins over
  `IdpSigningContext`/`IdpConfig` when present, and metadata still
  advertises a key when `ResponseEngineParts` is the only signing source
  registered (previously it advertised none).
- `cargo clippy -p gamlastan -p gamlastan-actix -p example-idp --tests -- -D
  warnings` and `cargo fmt --check` clean across all three crates.
