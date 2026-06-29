# KeyInfo X.509 certificate extraction and trust-anchor safety

This document describes, in depth, how gamlastan extracts X.509 signing
certificates from `<md:KeyDescriptor>`/`<ds:KeyInfo>` metadata, the
trust-anchor-confusion vulnerability that motivated the current rules
(security review finding **#2**), and exactly what is accepted and rejected.

It is the detailed companion to **ADR 0031**; the implementation lives in
[`crates/gamlastan/src/metadata/types/key_descriptor.rs`](../crates/gamlastan/src/metadata/types/key_descriptor.rs).

## Why this matters

A SAML entity's metadata advertises its signing certificate inside a
`KeyDescriptor`:

```xml
<md:KeyDescriptor use="signing">
  <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:X509Data>
      <ds:X509Certificate>MIID…base64 DER…</ds:X509Certificate>
    </ds:X509Data>
  </ds:KeyInfo>
</md:KeyDescriptor>
```

The certificates returned by `KeyDescriptor::x509_certificates_der()` (and the
`signing_certificates_der()` accessors that build on it) become **trust
anchors**: the SP/IdP installs them into a `KeysManager` and uses them to verify
the signatures on incoming SAML responses, assertions, and requests. Anything
that can inject DER bytes into that result set can therefore introduce a key it
controls and forge authentication.

This is **trust-anchor confusion** (CWE-345 / CWE-347). It is distinct from — but
composes with — the metadata signature-wrapping issue (finding #1, ADR 0028):
even with a correctly bound metadata signature, the key-extraction step itself
must not pick up attacker-chosen bytes.

## The vulnerability (finding #2)

The previous extractor had two weaknesses:

1. **Namespace-blind parsed path.** It accepted *any* element whose local name
   was `X509Certificate`, regardless of namespace. A lookalike bound to a
   foreign namespace was treated as a real XMLDSig certificate:

   ```xml
   <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
               xmlns:evil="urn:evil">
     <evil:X509Data>
       <evil:X509Certificate>…attacker DER…</evil:X509Certificate>
     </evil:X509Data>
   </ds:KeyInfo>
   ```

2. **Namespace-blind string fallback.** A `KeyInfo` captured as a detached
   fragment frequently inherits its namespace prefixes from ancestors in the
   metadata document and so does not parse standalone. The fallback scanned the
   raw markup for any `…:X509Certificate` tag with no namespace or structural
   checks at all.

Either path could promote a non-XMLDSig `X509Certificate` lookalike into a
trusted IdP signing key.

## The rules now enforced

A certificate is a trust-anchor candidate only when **both** hold:

1. **Namespace** — the `<X509Certificate>` element is in the XML Signature
   namespace `http://www.w3.org/2000/09/xmldsig#`, **or** is namespace-
   unqualified. Unqualified is allowed because a meaningful amount of real-world
   metadata (and the eduGAIN aggregate) emits `<KeyInfo><X509Data>
   <X509Certificate>` with no namespace declaration at all; rejecting it would
   break interoperability. An element bound to an *explicit different* namespace
   (e.g. `urn:evil`) is **rejected**.
2. **Structure** — the element is nested under an `<X509Data>` ancestor (also
   XMLDSig-or-unqualified), matching the XMLDSig schema. A bare
   `<X509Certificate>` not inside `<X509Data>` is **rejected**.

### Parsed path

When the `KeyInfo` parses as standalone XML, extraction walks the DOM and
applies both checks using resolved expanded names
(`is_xmldsig_or_unqualified` + `has_x509data_ancestor`). This is the strong,
namespace-aware path and handles the finding-#2 lookalike directly.

### Fragment fallback path

When the fragment does not parse standalone (inherited ancestor prefixes), the
namespace prefixes cannot be resolved by a parser. The fallback therefore
**anchors trust to the fragment's root element**: the deserializer only ever
produces this fragment from a genuine XMLDSig `<KeyInfo>` (it is selected by
expanded name via `find_child_element(doc, node, XMLDSIG_NS, "KeyInfo")`), so the
root's prefix *is* the prefix the original document binds to the XML Signature
namespace. A certificate is honoured only when **all** of the following hold:

1. **Same prefix as the root** — the `<X509Certificate>` uses the same prefix as
   the `<KeyInfo>` root element. A *different* prefix must resolve, via an
   ancestor declaration, to a *different* namespace — i.e. an inherited-prefix
   lookalike such as `<evil:X509Certificate>` — and is rejected.
2. **`<X509Data>` enclosure under the same prefix** — the certificate is nested
   in an `<X509Data>` element that *also* uses that prefix (prefix-exact string
   matching).
3. **No inline foreign rebinding** — neither the `<X509Certificate>` nor the
   enclosing `<X509Data>` start tag rebinds its prefix (or the default
   namespace) to a non-XMLDSig namespace inline. This closes the case where an
   attacker reuses the root's prefix but rebinds it within the fragment.

Because the root `<KeyInfo>` is *known* to be XMLDSig, requiring every trusted
`<X509Data>`/`<X509Certificate>` to share its prefix means a foreign-namespace
element — whether its binding is inline **or inherited from an ancestor** —
cannot be trusted: it would have to use a different prefix (rejected by rule 1)
or an inline rebinding (rejected by rule 3).

#### Residual limitation (stated honestly)

The fallback cannot run a full namespace-resolving parser, so it deliberately
**fails closed** on the one pathological shape it cannot disambiguate: two
*distinct* prefixes both bound to the XMLDSig namespace (e.g. `ds:KeyInfo` with a
`ds2:X509Certificate` where `ds` and `ds2` both map to xmldsig). A conformant
producer uses a single prefix, so this rejects only non-conformant input — the
safe direction. The earlier, weaker limitation (a foreign-namespace lookalike
using an *ancestor-declared* prefix could slip through) is now **closed** by the
prefix-anchoring above. The fallback remains defence-in-depth that composes with
metadata-signature verification (finding #1, ADR 0028), not a substitute for it.

## Accepted vs rejected

| `KeyInfo` shape | Result | Why |
| --- | --- | --- |
| `<ds:KeyInfo xmlns:ds=dsig><ds:X509Data><ds:X509Certificate>` | **accepted** | XMLDSig namespace, X509Data ancestor |
| `<KeyInfo><X509Data><X509Certificate>` (no namespace) | **accepted** | unqualified legacy/eduGAIN shape, X509Data ancestor |
| `<ds:KeyInfo …><evil:X509Data><evil:X509Certificate>` (`evil=urn:evil`) | **rejected** | explicit foreign namespace |
| `<ds:KeyInfo xmlns:ds=dsig><ds:X509Certificate>` (no `X509Data`) | **rejected** | missing X509Data ancestor |
| Detached fragment `<ds:KeyInfo><ds:X509Data><ds:X509Certificate>` (prefix unbound) | **accepted** | fallback: prefix matches the KeyInfo root, X509Data enclosure |
| Detached fragment with loose `<ds:X509Certificate>` (no X509Data) | **rejected** | fallback: missing X509Data enclosure |
| Detached fragment `<ds:KeyInfo><evil:X509Data><evil:X509Certificate>` (inherited `evil` prefix) | **rejected** | fallback: prefix differs from the KeyInfo root (inherited-prefix lookalike) |
| Detached fragment `<ds:KeyInfo><ds:X509Data xmlns:ds="urn:evil">…` (inline rebind) | **rejected** | fallback: inline rebinding to a foreign namespace |
| Unparseable / non-base64 content | **rejected** (empty) | cannot decode |

## Callers must fail closed on an empty result

`x509_certificates_der()` returns an **empty vector** both when there genuinely
is no certificate *and* when one was present but rejected/undecodable — the two
are deliberately indistinguishable. As documented on the method, callers using
these certificates as verification keys MUST treat an empty result as "this
descriptor yields no trust anchor" and reject the signature. **Never** branch on
`is_empty()` to skip signature verification — that would convert a rejected
lookalike into a bypass.

## Tests

- `test_x509_certificates_der_rejects_foreign_namespace_lookalike`
- `test_x509_certificates_der_requires_x509data_ancestor`
- `test_x509_certificates_der_fragment_requires_x509data`
- `test_x509_certificates_der_fragment_rejects_inherited_foreign_prefix`
  (inherited-prefix lookalike, fallback path)
- `test_x509_certificates_der_fragment_rejects_inline_rebound_prefix`
  (inline foreign rebinding, fallback path)
- `test_x509_certificates_der_fragment_accepts_matching_prefix`
  (legitimate inherited-prefix fragment still works)
- `test_x509_certificates_der_extraction`,
  `test_x509_certificates_der_multiline_default_ns_and_empty` (accepted shapes)
- `test_x509_certificates_der_edugain_fragment_without_inline_namespace`
  (real eduGAIN fragment still works)
- `cargo test -p gamlastan key_descriptor`

## Related

- **ADR 0031** — Fail-closed metadata key extraction and input validation.
- **ADR 0028** / finding #1 — metadata signature must bind to the consumed
  descriptor; composes with this control.
- [`docs/security-hardening.md`](security-hardening.md) — overview of all
  hardening controls.
