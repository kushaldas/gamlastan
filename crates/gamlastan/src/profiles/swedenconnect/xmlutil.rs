// Minimal XML escaping helpers for the hand-written Sweden Connect extension
// fragments (PrincipalSelection, SignMessage, SADRequest, metadata builders).
//
// These fragments are namespace-qualified element snippets meant to be embedded
// inside `<saml2p:Extensions>` or `<md:Extensions>` containers. They are kept as
// strings (matching the existing `Extensions { raw_xml }` representation) rather
// than going through the typed SAML serializer.

/// Escape a string for use inside an XML attribute value (double-quoted).
pub(crate) fn escape_attr(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

/// Escape a string for use as XML element text content.
pub(crate) fn escape_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_attr() {
        assert_eq!(escape_attr("a\"b&c<d>'"), "a&quot;b&amp;c&lt;d&gt;&apos;");
    }

    #[test]
    fn test_escape_text() {
        assert_eq!(escape_text("a&b<c>d"), "a&amp;b&lt;c&gt;d");
        // Quotes are left intact in text content.
        assert_eq!(escape_text("\"x\""), "\"x\"");
    }
}
