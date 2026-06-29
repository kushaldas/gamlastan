// XML escaping for the hand-written Sweden Connect extension fragments
// (PrincipalSelection, SignMessage, SADRequest, metadata builders).
//
// These fragments are namespace-qualified element snippets meant to be embedded
// inside `<saml2p:Extensions>` or `<md:Extensions>` containers. They are kept as
// strings (matching the existing `Extensions { raw_xml }` representation) rather
// than going through the typed SAML serializer.
//
// Escaping reuses bergshamra's canonical C14N entity escapers rather than a local
// copy. `escape_attr` escapes `& < "` (plus tab/nl/cr); `escape_text` escapes
// `& < >`. Both produce well-formed XML for double-quoted attribute values and
// element text respectively - `>` and `'` are legal unescaped inside a
// double-quoted attribute, so they are intentionally left as-is.
pub(crate) use bergshamra_c14n::escape::{escape_attr, escape_text};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_attr() {
        // The characters that could break out of a double-quoted attribute value
        // (`"`, `&`, `<`) are escaped.
        assert_eq!(escape_attr(r#"a"b&c<d"#), "a&quot;b&amp;c&lt;d");
    }

    #[test]
    fn test_escape_text() {
        assert_eq!(escape_text("a&b<c>d"), "a&amp;b&lt;c&gt;d");
        // Quotes are left intact in text content.
        assert_eq!(escape_text(r#""x""#), r#""x""#);
    }
}
