// SAML 2.0 DateTime wrappers and helpers

use crate::error::CoreError;
use chrono::{DateTime, Utc};
use std::fmt;

/// Parse an xs:dateTime string into a `DateTime<Utc>`.
///
/// SAML timestamps use the xs:dateTime format, which is a subset of ISO 8601.
/// Examples: "2024-01-15T10:30:00Z", "2024-01-15T10:30:00.123Z"
pub fn parse_saml_datetime(s: &str) -> Result<DateTime<Utc>, CoreError> {
    // Try RFC 3339 first (which is what most SAML implementations produce)
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Ok(dt.with_timezone(&Utc));
    }

    // Try without timezone (assume UTC)
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S") {
        return Ok(dt.and_utc());
    }

    // Try with fractional seconds but no timezone
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f") {
        return Ok(dt.and_utc());
    }

    Err(CoreError::InvalidDateTime(s.to_string()))
}

/// Format a `DateTime<Utc>` as an xs:dateTime string for SAML messages.
///
/// Produces format like "2024-01-15T10:30:00Z" (no fractional seconds).
pub fn format_saml_datetime(dt: &DateTime<Utc>) -> String {
    dt.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// A SAML DateTime value that preserves the original string representation.
///
/// Borrowed variant for zero-copy parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SamlDateTimeRef<'a> {
    /// The parsed datetime value.
    pub value: DateTime<Utc>,
    /// The original string representation from the XML document.
    pub raw: &'a str,
}

impl<'a> SamlDateTimeRef<'a> {
    /// Parse a SAML datetime string.
    pub fn parse(s: &'a str) -> Result<Self, CoreError> {
        let value = parse_saml_datetime(s)?;
        Ok(SamlDateTimeRef { value, raw: s })
    }

    /// Convert to an owned SamlDateTime.
    pub fn to_owned(&self) -> SamlDateTime {
        SamlDateTime { value: self.value }
    }
}

impl<'a> fmt::Display for SamlDateTimeRef<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.raw)
    }
}

/// Owned SAML DateTime value for construction and storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SamlDateTime {
    /// The datetime value.
    pub value: DateTime<Utc>,
}

impl SamlDateTime {
    /// Create a new SamlDateTime from a `DateTime<Utc>`.
    pub fn new(value: DateTime<Utc>) -> Self {
        SamlDateTime { value }
    }

    /// Get the current UTC time as a SamlDateTime.
    pub fn now() -> Self {
        SamlDateTime { value: Utc::now() }
    }

    /// Format as an xs:dateTime string.
    pub fn to_saml_string(&self) -> String {
        format_saml_datetime(&self.value)
    }
}

impl fmt::Display for SamlDateTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", format_saml_datetime(&self.value))
    }
}

/// Check if a datetime is within a validity window, accounting for clock skew.
///
/// Returns `true` if `not_before - skew <= now <= not_on_or_after + skew`.
pub fn is_within_validity_window(
    now: DateTime<Utc>,
    not_before: Option<DateTime<Utc>>,
    not_on_or_after: Option<DateTime<Utc>>,
    clock_skew_seconds: i64,
) -> bool {
    let skew = chrono::Duration::seconds(clock_skew_seconds);

    if let Some(nb) = not_before {
        if now < nb - skew {
            return false;
        }
    }

    if let Some(noa) = not_on_or_after {
        if now >= noa + skew {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_saml_datetime_rfc3339() {
        let dt = parse_saml_datetime("2024-01-15T10:30:00Z").unwrap();
        assert_eq!(dt.year(), 2024);
        assert_eq!(dt.month(), 1);
        assert_eq!(dt.day(), 15);
        assert_eq!(dt.hour(), 10);
        assert_eq!(dt.minute(), 30);
        assert_eq!(dt.second(), 0);
    }

    #[test]
    fn test_parse_saml_datetime_with_fractional() {
        let dt = parse_saml_datetime("2024-01-15T10:30:00.123Z").unwrap();
        assert_eq!(dt.year(), 2024);
    }

    #[test]
    fn test_parse_saml_datetime_with_offset() {
        let dt = parse_saml_datetime("2024-01-15T10:30:00+00:00").unwrap();
        assert_eq!(dt.year(), 2024);
    }

    #[test]
    fn test_parse_saml_datetime_invalid() {
        assert!(parse_saml_datetime("not-a-date").is_err());
        assert!(parse_saml_datetime("").is_err());
    }

    #[test]
    fn test_format_saml_datetime() {
        let dt = parse_saml_datetime("2024-01-15T10:30:00Z").unwrap();
        let formatted = format_saml_datetime(&dt);
        assert_eq!(formatted, "2024-01-15T10:30:00Z");
    }

    #[test]
    fn test_saml_datetime_ref_roundtrip() {
        let s = "2024-01-15T10:30:00Z";
        let dt_ref = SamlDateTimeRef::parse(s).unwrap();
        assert_eq!(dt_ref.raw, s);
        let owned = dt_ref.to_owned();
        assert_eq!(owned.value, dt_ref.value);
    }

    #[test]
    fn test_saml_datetime_now() {
        let now = SamlDateTime::now();
        let s = now.to_saml_string();
        assert!(s.ends_with('Z'));
        // Should be parseable
        parse_saml_datetime(&s).unwrap();
    }

    #[test]
    fn test_is_within_validity_window() {
        use chrono::TimeZone;

        let now = Utc.with_ymd_and_hms(2024, 1, 15, 12, 0, 0).unwrap();
        let not_before = Utc.with_ymd_and_hms(2024, 1, 15, 11, 0, 0).unwrap();
        let not_on_or_after = Utc.with_ymd_and_hms(2024, 1, 15, 13, 0, 0).unwrap();

        // Within window
        assert!(is_within_validity_window(
            now,
            Some(not_before),
            Some(not_on_or_after),
            0
        ));

        // Before window
        let early = Utc.with_ymd_and_hms(2024, 1, 15, 10, 0, 0).unwrap();
        assert!(!is_within_validity_window(
            early,
            Some(not_before),
            Some(not_on_or_after),
            0
        ));

        // After window
        let late = Utc.with_ymd_and_hms(2024, 1, 15, 14, 0, 0).unwrap();
        assert!(!is_within_validity_window(
            late,
            Some(not_before),
            Some(not_on_or_after),
            0
        ));

        // Clock skew allows early
        assert!(is_within_validity_window(
            early,
            Some(not_before),
            Some(not_on_or_after),
            3600
        ));

        // No bounds
        assert!(is_within_validity_window(now, None, None, 0));
    }

    use chrono::Datelike;
    use chrono::Timelike;
}
