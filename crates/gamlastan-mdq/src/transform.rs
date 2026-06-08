//! EntityID → request-path transform and `xs:duration` parsing.

use std::fmt::Write as _;
use std::time::Duration;

use gamlastan::crypto::digest::sha1;

use crate::error::MdqError;

/// How an entityID is encoded into the MDQ request path.
///
/// Per the MDQ specification, an MDQ server identifies an entity either by the
/// (percent-encoded) entityID itself, or by the `{sha1}`-prefixed hex SHA-1 of
/// the entityID. Different deployments accept different forms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MdqTransform {
    /// Percent-encode the raw entityID (the default; matches most MDQ servers).
    #[default]
    UrlEncoded,
    /// Use the `{sha1}` transform: `"{sha1}" + hex(sha1(entityID))` (pyFF/thiss.io).
    Sha1,
}

/// Build the full MDQ request URL for an entityID.
///
/// `server_url` must already end with `/`.
pub fn request_path(server_url: &str, entity_id: &str, transform: MdqTransform) -> String {
    let raw = match transform {
        MdqTransform::UrlEncoded => entity_id.to_string(),
        MdqTransform::Sha1 => format!("{{sha1}}{}", hex_lower(&sha1(entity_id.as_bytes()))),
    };
    format!("{server_url}{}", percent_encode(&raw))
}

/// Lowercase hex encoding of a byte slice.
fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Percent-encode a string for use as a single URL path segment.
///
/// Keeps the RFC 3986 unreserved set (`A-Z a-z 0-9 - _ . ~`) and encodes
/// everything else as `%XX` (uppercase hex), e.g. `:` → `%3A`, `/` → `%2F`,
/// `{` → `%7B`.
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => {
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    out
}

/// Parse the `xs:duration` subset used by SAML `cacheDuration` into a
/// [`Duration`].
///
/// Supports `P[nY][nM][nD][T[nH][nM][nS]]` with non-negative values; the
/// seconds component may be fractional. Years are approximated as 365 days and
/// months as 30 days (calendar-exact lengths are undefined for a cache hint).
/// Negative durations and weeks (`W`, not part of `xs:duration`) are rejected.
pub fn parse_xs_duration(s: &str) -> Result<Duration, MdqError> {
    let bad = || MdqError::BadDuration(s.to_string());

    let mut chars = s.chars();
    if chars.next() != Some('P') {
        return Err(bad());
    }

    let mut secs: f64 = 0.0;
    let mut in_time = false;
    let mut num = String::new();
    let mut saw_component = false;

    for c in chars {
        match c {
            'T' => {
                if in_time || !num.is_empty() {
                    return Err(bad());
                }
                in_time = true;
            }
            '0'..='9' | '.' => num.push(c),
            unit => {
                if num.is_empty() {
                    return Err(bad());
                }
                let value: f64 = num.parse().map_err(|_| bad())?;
                num.clear();
                saw_component = true;
                let unit_secs = match (in_time, unit) {
                    (false, 'Y') => 365.0 * 86_400.0,
                    (false, 'M') => 30.0 * 86_400.0,
                    (false, 'D') => 86_400.0,
                    (true, 'H') => 3_600.0,
                    (true, 'M') => 60.0,
                    (true, 'S') => 1.0,
                    _ => return Err(bad()),
                };
                secs += value * unit_secs;
            }
        }
    }

    if !num.is_empty() || !saw_component || !secs.is_finite() || secs < 0.0 {
        return Err(bad());
    }

    // `Duration::from_secs_f64` panics if `secs` overflows `Duration`; a crafted
    // `cacheDuration` (e.g. "P10000000000000000000Y") yields a finite-but-huge
    // value that passes the checks above, so use the fallible constructor.
    Duration::try_from_secs_f64(secs).map_err(|_| bad())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_encoded_transform() {
        let url = request_path(
            "https://mdq.example.org/",
            "https://idp.example.com/idp",
            MdqTransform::UrlEncoded,
        );
        assert_eq!(
            url,
            "https://mdq.example.org/https%3A%2F%2Fidp.example.com%2Fidp"
        );
        // The host label survives because '.' is unreserved.
        assert!(url.contains("idp.example.com"));
    }

    #[test]
    fn sha1_transform() {
        let url = request_path(
            "https://mdq.example.org/",
            "https://idp.example.com/idp",
            MdqTransform::Sha1,
        );
        // sha1("https://idp.example.com/idp") hex, with the braces encoded.
        assert!(url.starts_with("https://mdq.example.org/%7Bsha1%7D"));
        let hex = url.rsplit("%7D").next().unwrap();
        assert_eq!(hex.len(), 40);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn duration_seconds() {
        assert_eq!(
            parse_xs_duration("PT604800S").unwrap(),
            Duration::from_secs(604_800)
        );
        assert_eq!(
            parse_xs_duration("PT3600S").unwrap(),
            Duration::from_secs(3_600)
        );
    }

    #[test]
    fn duration_compound() {
        assert_eq!(
            parse_xs_duration("P7D").unwrap(),
            Duration::from_secs(7 * 86_400)
        );
        assert_eq!(
            parse_xs_duration("PT1H").unwrap(),
            Duration::from_secs(3_600)
        );
        assert_eq!(
            parse_xs_duration("PT1H30M").unwrap(),
            Duration::from_secs(5_400)
        );
        assert_eq!(
            parse_xs_duration("P1DT2H3M4S").unwrap(),
            Duration::from_secs(86_400 + 7_200 + 180 + 4)
        );
    }

    #[test]
    fn duration_fractional_seconds() {
        assert_eq!(
            parse_xs_duration("PT1.5S").unwrap(),
            Duration::from_secs_f64(1.5)
        );
    }

    #[test]
    fn duration_invalid() {
        for s in [
            "",
            "P",
            "PT",
            "7D",
            "P-1D",
            "PT1W",
            "PTS",
            "P1H",
            "garbage",
            // Finite but overflows `Duration` — must error, not panic.
            "P10000000000000000000Y",
            "PT1000000000000000000000S",
        ] {
            assert!(parse_xs_duration(s).is_err(), "{s} should be invalid");
        }
    }
}
