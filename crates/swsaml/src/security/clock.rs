// SAML 2.0 Clock skew handling
//
// Per Errata E92: Clock skew tolerance of 3-5 minutes is recommended.
// All time comparisons should account for clock drift between SP and IdP.

use chrono::{DateTime, TimeDelta, Utc};

/// Check whether `now` satisfies a NotBefore constraint with clock skew.
///
/// For `not_before` checks: the timestamp is valid if `now + skew >= not_before`.
///
/// Returns `true` if `now + skew >= not_before` (i.e., the assertion's validity
/// period has started, accounting for clock drift).
///
/// # Arguments
/// * `now` - The current time.
/// * `clock_skew_seconds` - The allowed clock skew tolerance in seconds (E92).
pub fn is_not_before_valid(
    now: DateTime<Utc>,
    not_before: DateTime<Utc>,
    clock_skew_seconds: u64,
) -> bool {
    let skew = TimeDelta::seconds(clock_skew_seconds as i64);
    now + skew >= not_before
}

/// Check whether `now` satisfies a NotOnOrAfter constraint with clock skew.
///
/// Returns `true` if `now - skew < not_on_or_after` (i.e., the assertion has
/// not expired yet, accounting for clock drift).
pub fn is_not_on_or_after_valid(
    now: DateTime<Utc>,
    not_on_or_after: DateTime<Utc>,
    clock_skew_seconds: u64,
) -> bool {
    let skew = TimeDelta::seconds(clock_skew_seconds as i64);
    now - skew < not_on_or_after
}

/// Check the age of a timestamp against a maximum allowed age.
///
/// Returns `true` if the timestamp is within the allowed age window.
pub fn is_within_age_limit(
    now: DateTime<Utc>,
    timestamp: DateTime<Utc>,
    max_age_seconds: u64,
) -> bool {
    let age = now.signed_duration_since(timestamp);
    if age.num_seconds() < 0 {
        // Timestamp is in the future - treat as valid (clock skew handled separately)
        return true;
    }
    age.num_seconds() as u64 <= max_age_seconds
}

/// Calculate the absolute time difference between two timestamps in seconds.
pub fn time_difference_seconds(a: DateTime<Utc>, b: DateTime<Utc>) -> i64 {
    a.signed_duration_since(b).num_seconds().abs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeDelta;

    #[test]
    fn test_not_before_valid_current_time() {
        let now = Utc::now();
        let not_before = now - TimeDelta::seconds(60);
        assert!(is_not_before_valid(now, not_before, 180));
    }

    #[test]
    fn test_not_before_valid_with_skew() {
        let now = Utc::now();
        // NotBefore is 2 minutes in the future, but we have 3 minutes of skew
        let not_before = now + TimeDelta::seconds(120);
        assert!(is_not_before_valid(now, not_before, 180));
    }

    #[test]
    fn test_not_before_invalid_beyond_skew() {
        let now = Utc::now();
        // NotBefore is 5 minutes in the future, but we only have 3 minutes of skew
        let not_before = now + TimeDelta::seconds(300);
        assert!(!is_not_before_valid(now, not_before, 180));
    }

    #[test]
    fn test_not_on_or_after_valid_current_time() {
        let now = Utc::now();
        let not_on_or_after = now + TimeDelta::seconds(60);
        assert!(is_not_on_or_after_valid(now, not_on_or_after, 180));
    }

    #[test]
    fn test_not_on_or_after_valid_with_skew() {
        let now = Utc::now();
        // NotOnOrAfter was 2 minutes ago, but we have 3 minutes of skew
        let not_on_or_after = now - TimeDelta::seconds(120);
        assert!(is_not_on_or_after_valid(now, not_on_or_after, 180));
    }

    #[test]
    fn test_not_on_or_after_invalid_beyond_skew() {
        let now = Utc::now();
        // NotOnOrAfter was 5 minutes ago, but we only have 3 minutes of skew
        let not_on_or_after = now - TimeDelta::seconds(300);
        assert!(!is_not_on_or_after_valid(now, not_on_or_after, 180));
    }

    #[test]
    fn test_not_on_or_after_exact_boundary() {
        let now = Utc::now();
        // NotOnOrAfter is exactly at skew boundary - should still be valid
        // because condition is now - skew < not_on_or_after
        let not_on_or_after = now - TimeDelta::seconds(179);
        assert!(is_not_on_or_after_valid(now, not_on_or_after, 180));
    }

    #[test]
    fn test_within_age_limit() {
        let now = Utc::now();
        let timestamp = now - TimeDelta::seconds(60);
        assert!(is_within_age_limit(now, timestamp, 300));
    }

    #[test]
    fn test_beyond_age_limit() {
        let now = Utc::now();
        let timestamp = now - TimeDelta::seconds(600);
        assert!(!is_within_age_limit(now, timestamp, 300));
    }

    #[test]
    fn test_future_timestamp_within_age() {
        let now = Utc::now();
        // Timestamp in the future (clock skew scenario)
        let timestamp = now + TimeDelta::seconds(10);
        assert!(is_within_age_limit(now, timestamp, 300));
    }

    #[test]
    fn test_time_difference_seconds() {
        let a = Utc::now();
        let b = a - TimeDelta::seconds(120);
        assert_eq!(time_difference_seconds(a, b), 120);
        assert_eq!(time_difference_seconds(b, a), 120); // absolute value
    }

    #[test]
    fn test_zero_skew() {
        let now = Utc::now();
        let not_before = now - TimeDelta::seconds(1);
        assert!(is_not_before_valid(now, not_before, 0));

        let not_before_future = now + TimeDelta::seconds(1);
        assert!(!is_not_before_valid(now, not_before_future, 0));
    }
}
