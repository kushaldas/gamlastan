# ADR 0004 — HSM / PKCS#11-backed signing

- **Status:** Accepted
- **Date:** 2026-06-09
- **Deciders:** gamlastan maintainers
- **Spec:** SAML V2.0 Bindings ([saml-bindings-2.0-os] §3.4.4.1 HTTP-Redirect
  `SigAlg`/`Signature`), XML-Signature Syntax and Processing
  ([xmldsig-core] §4.4 `SignatureMethod`); PKCS#11 v2.40 `C_Sign`
- **Implementation:** `crates/gamlastan/src/crypto/signer.rs`,
  `crates/gamlastan/src/crypto/mod.rs`, `crates/gamlastan/src/crypto/error.rs`,
  `crates/gamlastan-actix/src/idp.rs`
- **Related:** [ADR 0003 — Metadata accessors](0003-metadata-key-and-endpoint-accessors.md)

## Context

Production IdPs and SPs are frequently required (eIDAS, Sweden Connect, many
national federations) to keep their SAML signing key in a hardware security
module or a PKCS#11 software token, never on disk. Until now `SamlSigner` only
supported a file-based key: it wrapped a `bergshamra_keys::KeysManager` whose
private key was loaded from PEM (`loader::load_pem_auto`), and every signing
operation resolved that key into an in-memory `bergshamra_crypto::sign::SigningKey`.

The capability to avoid this already existed **below** gamlastan but was not
surfaced:

- `kryptering` 0.3 (the crypto provider beneath bergshamra, already a transitive
  dependency) ships a full PKCS#11 layer behind its `pkcs11` feature —
  `Pkcs11Provider` → `Pkcs11Session` → `Pkcs11Signer`, the last implementing the
  `kryptering::Signer` trait (`algorithm()`, `sign(&[u8]) -> Vec<u8>`).
- `bergshamra-dsig` 0.5.1 already has a first-class hook:
  `DsigContext.hsm_signer: Option<Box<dyn kryptering::Signer>>` (set via
  `with_hsm_signer`). When present, `sign()` bypasses the `KeysManager`, signs on
  the token, and cross-checks the signer's algorithm against the template's
  `<ds:SignatureMethod>` so the document can never claim an algorithm it did not
  use.

The gap was purely in gamlastan's wrapper: `SamlSigner::sign_enveloped` hardcoded
`DsigContext::new(km)` and never set `hsm_signer`, and `sign_redirect_query` only
took the in-memory `SigningKey` path. So no gamlastan consumer could use an HSM
without bypassing the library. No new bergshamra release was needed — only the
wiring.

## Decision

Surface HSM signing on `SamlSigner` and thread it through both SAML signing
paths, keeping the file-based path the default.

- **New constructor `SamlSigner::with_hsm_signer(KeysManager, Arc<dyn kryptering::Signer>)`**
  plus `is_hsm_backed()`. The signer is held as an `Arc` and adapted into the
  `Box<dyn Signer>` that `DsigContext::with_hsm_signer` consumes per call, so a
  single token session is shared across signings.

- **Enveloped path** (`sign_enveloped`): when an HSM signer is set, it is handed
  to the `DsigContext`. bergshamra-dsig does the cross-check and signs on the
  token. It also **skips populating `<ds:KeyInfo>` on the HSM path**, which is
  already how gamlastan works — the certificate is embedded in the signature
  *template* (`gamlastan-actix::signature_template`), not pulled from the
  `KeysManager`. The `KeysManager` may therefore be empty for an HSM signer.

- **Redirect path** (`sign_redirect_query`): the detached signature over the raw
  query-string bytes is produced by calling the HSM signer directly. We apply the
  **same algorithm cross-check** as the enveloped path — the signer's algorithm
  is mapped to a URI via the public `bergshamra_crypto::sign::kryptering_algorithm_uri`
  and compared against the requested `SigAlg`, so the advertised `SigAlg` can
  never disagree with the mechanism used. This is the one place gamlastan must
  enforce the invariant itself, because bergshamra-dsig is not involved in
  redirect signing.

- **`kryptering` becomes a direct dependency** of gamlastan so the shared
  `Signer` trait and algorithm types can be named and re-exported directly as
  `gamlastan::crypto::kryptering`. That keeps trait-object identity aligned with
  the bergshamra stack's resolved `kryptering` version instead of relying on a
  separate consumer dependency that could drift.

- **Convenience constructor `IdpSigningContext::from_hsm(Arc<dyn Signer>, cert_b64)`**
  in gamlastan-actix, so the IdP handlers are wired to a token without manual
  `SamlSigner` / `KeysManager` plumbing. (`IdpSigningContext::new` was added for
  the file-based path for symmetry.) The actix signing template now derives its
  XML `SignatureMethod` from the configured signer so HSM-backed IdPs are not
  pinned to RSA-SHA256 templates.

- **Metadata certificate selection** prefers the active `IdpSigningContext`
  certificate when one is registered, falling back to `IdpConfig.signing_cert_b64`
  only when metadata is generated without a signing context. This keeps the
  published `KeyDescriptor` aligned with the key that actually signs metadata
  and responses.

- A new `CryptoError::HsmError(String)` variant carries token failures.

## Alternatives considered

- **Fork or patch bergshamra to add HSM support.** Unnecessary — the
  `hsm_signer` hook and the `kryptering::Signer` trait are already published in
  0.5.1 / 0.3.0. The work was entirely gamlastan-side wiring.
- **A gamlastan-defined signing trait instead of reusing `kryptering::Signer`.**
  Rejected: it would mean an adapter at the gamlastan↔bergshamra boundary for no
  benefit, since bergshamra-dsig already speaks `kryptering::Signer`. Reusing the
  trait keeps a single signer object usable by both layers.
- **Add a second abstraction just for HSM signers in gamlastan-actix.**
  Rejected: the signer already exposes enough information to derive the XML
  `SignatureMethod`, so a separate actix-only abstraction would duplicate the
  existing `kryptering::Signer` contract.
- **Skip the redirect-binding HSM path.** Rejected — redirect-bound requests are
  common (SP-initiated SSO, SLO), and omitting it would leave a confusing
  half-supported feature. It is cheap: raw-byte signing on the token.

## Consequences

**Positive**

- IdPs/SPs can keep the signing key in an HSM with a one-line constructor change;
  the private key never leaves the token. Both enveloped and redirect signatures
  are covered.
- File-based users keep the same default API. The additional gamlastan-side HSM
  API surface does not require a different integration path for PEM-based
  deployments.
- The algorithm cross-check (enveloped via bergshamra-dsig, redirect via
  gamlastan) prevents an HSM-signed message from advertising a `SigAlg` /
  `SignatureMethod` it did not actually use.

**Negative / accepted trade-offs**

- The HSM enveloped path requires the certificate to be present in the signature
  template, because dsig does not populate `<ds:KeyInfo>` for HSM signers. This
  matches the existing `gamlastan-actix` template (which embeds `cert_b64`) but
  is a contract a custom template author must honour.
- A real token is needed to exercise the path end-to-end. The integration test
  (`crates/gamlastan/tests/hsm_signing.rs`) is `#[ignore]`d and self-skips unless
  `GAMLASTAN_PKCS11_*` is set; CI provisions a throwaway SoftHSM2 token via
  `just test-hsm` in a dedicated `hsm-tests` job.
- The current bergshamra 0.5.1 / kryptering 0.3.0 stack already resolves the
  PKCS#11 backend in normal builds, so this ADR does not claim that `cryptoki`
  disappears from file-based dependency graphs; the direct gamlastan dependency
  exists for trait/type re-export and version alignment.
- `kryptering` is now a direct (light) dependency of gamlastan, coupling it to
  that crate's 0.3 line in addition to the bergshamra 0.5 line. Acceptable: they
  release together and must already agree on the trait.

## References

- `crates/gamlastan/src/crypto/signer.rs` — `SamlSigner::with_hsm_signer`,
  `is_hsm_backed`, HSM branches in `sign_enveloped` / `sign_redirect_query`
- `crates/gamlastan/src/crypto/mod.rs` — `pub use kryptering`
- `crates/gamlastan-actix/src/idp.rs` — `IdpSigningContext::from_hsm` / `new`
- `crates/gamlastan/tests/hsm_signing.rs` — SoftHSM2 end-to-end test
- `justfile` — `install-hsm-deps`, `test-hsm`
- `.github/workflows/ci.yml` — `hsm-tests` job
- bergshamra-dsig `DsigContext::with_hsm_signer`; kryptering `pkcs11::Pkcs11Signer`
