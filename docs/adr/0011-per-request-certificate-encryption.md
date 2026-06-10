# ADR 0011 — Per-request certificate encryption (PEFIM)

- **Status:** Accepted
- **Date:** 2026-06-10
- **Deciders:** gamlastan maintainers
- **Spec:** XML Encryption 1.1; SAML V2.0 Core §2.6 (Advice); SAML V2.0 errata E93 (prefer GCM); PEFIM `SPCertEnc`
- **Implementation:** `crates/gamlastan/src/crypto/encryptor.rs`, `crates/gamlastan/src/profiles/sso/idp.rs`, `crates/gamlastan/src/profiles/error.rs`

## Context

gamlastan's existing `SamlEncryptor` encrypts toward keys held in a `KeysManager`,
which is the metadata-driven path: the recipient's certificate comes from the SP's
published metadata. The PEFIM profile (and pysaml2's `encrypt_cert_assertion` /
`encrypt_cert_advice`) needs the opposite: the SP supplies an **encryption
certificate in the AuthnRequest itself** (`pefim:SPCertEnc`), and the IdP must
encrypt **that request's** assertion toward **that request's** certificate — no
metadata lookup, a fresh session key per request.

We already parse the cert out of the request
(`profiles::pefim::first_encryption_cert_der`). What was missing: an encryptor
built from a single ad-hoc certificate, a way to encrypt a *standalone* assertion
(one not embedded in a parent document, so it has no inherited namespace
declarations), and the wiring to drop the result into a `Response` or into
encrypted `Advice`.

## Decision

Add a per-request (PEFIM) encryption path alongside the metadata path, defaulting
to authenticated encryption.

### Crypto layer (`crypto::encryptor`)

- `SamlEncryptor::for_certificate(cert_der)` — build an encryptor whose only
  transport key is the recipient certificate's RSA public key (loaded via
  `bergshamra_keys::loader`), bypassing metadata.
- `encrypted_data_template_for_cert(cert_der, &CertEncryptionOptions)` — produce the
  `<xenc:EncryptedData>` template (empty CipherValues) that `encrypt()` fills in,
  optionally embedding the recipient cert in the `EncryptedKey`'s `KeyInfo` so the
  SP can select its private key.
- `CertEncryptionOptions` defaults to **AES-256-GCM** data encryption (E93: GCM for
  built-in integrity) with **RSA-OAEP-MGF1P** key transport, exposed as
  `DEFAULT_DATA_ALGORITHM` / `DEFAULT_KEY_TRANSPORT_ALGORITHM` constants.

### Profile layer (`profiles::sso::idp`)

- `assertion_to_self_contained_xml` — serialize an assertion with all namespace
  declarations inline, so the ciphertext decrypts and parses standalone (pysaml2
  `encrypt_assertion_self_contained`).
- `encrypt_assertion_to_cert` — encrypt one assertion toward a request cert and wrap
  it in `<saml:EncryptedAssertion>`.
- `encrypt_response_assertions_to_cert` — replace every cleartext assertion in a
  `Response` with its encrypted form.
- `add_encrypted_advice` — encrypt an advice assertion and append it to the main
  assertion's `saml:Advice` (uses the `Advice` type from ADR 0010; relying parties
  that cannot process it may ignore it, per Core §2.6.1).

### Error plumbing

`ProfileError` gained `Crypto(#[from] CryptoError)` and `Xml(#[from] XmlError)` so
these functions propagate failures with `?` instead of stringly-typed `Other`.

## Consequences

- The IdP can honour `pefim:SPCertEnc` end to end: encrypt the assertion (or just
  the attribute statement, via encrypted Advice) toward a request-supplied cert.
- Defaults are authenticated (GCM) and modern (RSA-OAEP); callers can override both
  algorithm URIs and whether the cert is embedded.
- The metadata-driven `SamlEncryptor::new(keys_manager)` path is unchanged; this is
  strictly additive on the crypto side.
- **Breaking (pre-release):** `ProfileError` gained two variants, so exhaustive
  matches over it must be updated. Documented in `CHANGELOG.md`.

## Alternatives considered

- **Force the request cert into the shared `KeysManager`.** Rejected: that key is
  per-request and short-lived; mutating shared key state per request is racy and
  leaks request material into a long-lived manager. A throwaway encryptor is clean.
- **Encrypt the assertion in place (inheriting parent namespaces).** Rejected: the
  ciphertext must decrypt to a self-contained, parseable assertion; relying on
  inherited `xmlns` declarations breaks once the `EncryptedData` is relocated.
- **Default to AES-CBC for broad interop.** Rejected: E93 prefers GCM for built-in
  integrity; CBC remains reachable by overriding `data_algorithm`.

## Validation

- `tests/cert_encryption.rs` (3 integration tests) — encrypt an assertion toward a
  DER cert, decrypt with the matching private key, parse and compare; the
  self-contained-assertion-parses-standalone case; and the encrypted-Advice
  round-trip. All pass.
- `cargo test -p gamlastan` — 592 unit + 3 integration passing.

## Publication status

Unreleased; the encryption helper signatures and `CertEncryptionOptions` may still
change.
