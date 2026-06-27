# ADR 0023 - Adopt uppsala 0.5, bergshamra 0.6, and kryptering 0.4

- **Status:** Accepted
- **Date:** 2026-06-27
- **Deciders:** gamlastan maintainers
- **Spec:** SAML 2.0 Security and Privacy Considerations §6 (denial of service), OWASP XXE / "Billion Laughs"
- **Implementation:** workspace `Cargo.toml` (`[workspace.dependencies]`)

## Context

The SAML stack is built on three sibling crates maintained alongside gamlastan:

- **uppsala** — the zero-copy XML parser/DOM.
- **bergshamra** — the XML-security stack (DSig, XML-Enc, C14N, key handling).
- **kryptering** — the low-level crypto / PKCS#11 signing backend shared by
  bergshamra and re-exported by gamlastan for HSM signers.

uppsala 0.4 had **no resource limits anywhere**: no element-nesting cap, no
entity-expansion budget, no entity-nesting cap. A small hostile SAML payload
could therefore exhaust the stack (deep nesting) or amplify memory/CPU
(billion-laughs / quadratic entity blow-up) before gamlastan's own validation
ran. uppsala 0.5 closes both classes by enforcing fixed, fail-closed limits **by
default** (its security audit triages every High/Medium finding as fixed):

- element nesting depth — `DEFAULT_MAX_DEPTH = 128`
- entity-expansion byte budget — `DEFAULT_MAX_ENTITY_EXPANSION = 1 MiB`
- entity nesting depth — `DEFAULT_MAX_ENTITY_DEPTH = 256`

uppsala 0.5 additionally hardens the serializer (comment / PI / CDATA / name /
encoding / control-char sanitization), so XML the library *emits* cannot be used
for round-trip injection. bergshamra 0.6 builds on uppsala 0.5 and pulls
kryptering 0.4 / tsp-ltv 0.3.

## Decision

1. Bump `uppsala` to **0.5.0** (crates.io). gamlastan parses all inbound,
   attacker-controlled XML through `uppsala::parse`, so the new default limits
   apply automatically across the whole library — no call-site change is needed
   to gain the depth and entity-expansion defenses.

2. Bump **bergshamra** to **0.6.0** (crates.io) across its workspace crates
   (`bergshamra`, `-core`, `-dsig`, `-enc`, `-c14n`, `-crypto`, `-keys`). This
   keeps gamlastan, bergshamra, and uppsala on a single, consistent XML/crypto
   tree. (During development the dependency was briefly sourced from the local
   `../bergshamra` checkout via path dependencies; it is now consumed from
   crates.io so the workspace is publishable.)

3. Bump the direct **kryptering** dependency to **0.4.0** with
   `default-features = false, features = ["legacy", "post-quantum", "pkcs11"]`,
   mirroring bergshamra's kryptering dependency. Feature unification then
   resolves kryptering to a single instance, so gamlastan's re-exported
   `kryptering::Signer` / `Pkcs11Signer` are the same types bergshamra signs
   with — no version or feature drift. `tsp-ltv` advances to 0.3.0 transitively
   through bergshamra; gamlastan does not depend on it directly.

## Consequences

- Inbound XML is now bounded against deep-nesting stack exhaustion and
  entity-expansion amplification by default, independent of gamlastan's
  assertion validator. See [0024](0024-reject-dtd-at-saml-parse-boundary.md) for
  the complementary outright DTD rejection.
- The workspace builds entirely from published crates (uppsala 0.5.0,
  bergshamra 0.6.0, kryptering 0.4.0 on crates.io), so it is releasable without
  requiring sibling source checkouts.
- A legitimately deeper-than-128 or larger-than-1-MiB-entity document would now
  be rejected. SAML messages and metadata are wide, shallow, and DTD-free, so no
  real deployment is affected; the limits are configurable on `uppsala::Parser`
  if a workload ever needs a different bound.

## Validation

- `cargo build --workspace` and `cargo clippy --workspace --all-targets`
  (`-D warnings`) are clean against the new stack.
- `cargo test --workspace` — full suite green (635 gamlastan unit tests + the
  integration and doc tests) with no behavioral regressions from the bump.
