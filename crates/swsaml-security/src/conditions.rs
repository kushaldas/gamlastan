// SAML 2.0 Conditions processing
//
// Handles NotBefore/NotOnOrAfter, OneTimeUse, and ProxyRestriction conditions.
// Time comparisons use clock skew tolerance from E92.

use chrono::{DateTime, Utc};

use swsaml_core::assertion::conditions::{Conditions, ConditionsRef};

use crate::clock::{is_not_before_valid, is_not_on_or_after_valid};
use crate::error::ValidationCheck;

/// Validate the time-based conditions (NotBefore, NotOnOrAfter) on owned Conditions.
///
/// Returns a list of validation checks for these conditions.
pub fn validate_time_conditions(
    conditions: &Conditions,
    now: DateTime<Utc>,
    clock_skew_seconds: u64,
) -> Vec<ValidationCheck> {
    let mut checks = Vec::new();

    // Check 9: NotBefore valid with clock skew (E92)
    if let Some(not_before) = conditions.not_before {
        if is_not_before_valid(now, not_before, clock_skew_seconds) {
            checks.push(ValidationCheck::pass(9, "NotBefore valid"));
        } else {
            checks.push(ValidationCheck::fail(
                9,
                "NotBefore valid",
                format!(
                    "Current time {} is before NotBefore {} (skew: {}s)",
                    now, not_before, clock_skew_seconds
                ),
            ));
        }
    } else {
        checks.push(ValidationCheck::pass(9, "NotBefore valid"));
    }

    // Check 10: NotOnOrAfter valid with clock skew (E92)
    if let Some(not_on_or_after) = conditions.not_on_or_after {
        if is_not_on_or_after_valid(now, not_on_or_after, clock_skew_seconds) {
            checks.push(ValidationCheck::pass(10, "NotOnOrAfter valid"));
        } else {
            checks.push(ValidationCheck::fail(
                10,
                "NotOnOrAfter valid",
                format!(
                    "Current time {} is at or after NotOnOrAfter {} (skew: {}s)",
                    now, not_on_or_after, clock_skew_seconds
                ),
            ));
        }
    } else {
        checks.push(ValidationCheck::pass(10, "NotOnOrAfter valid"));
    }

    checks
}

/// Validate the time-based conditions on borrowed Conditions.
pub fn validate_time_conditions_ref(
    conditions: &ConditionsRef<'_>,
    now: DateTime<Utc>,
    clock_skew_seconds: u64,
) -> Vec<ValidationCheck> {
    let mut checks = Vec::new();

    if let Some(not_before) = conditions.not_before {
        if is_not_before_valid(now, not_before, clock_skew_seconds) {
            checks.push(ValidationCheck::pass(9, "NotBefore valid"));
        } else {
            checks.push(ValidationCheck::fail(
                9,
                "NotBefore valid",
                format!(
                    "Current time {} is before NotBefore {} (skew: {}s)",
                    now, not_before, clock_skew_seconds
                ),
            ));
        }
    } else {
        checks.push(ValidationCheck::pass(9, "NotBefore valid"));
    }

    if let Some(not_on_or_after) = conditions.not_on_or_after {
        if is_not_on_or_after_valid(now, not_on_or_after, clock_skew_seconds) {
            checks.push(ValidationCheck::pass(10, "NotOnOrAfter valid"));
        } else {
            checks.push(ValidationCheck::fail(
                10,
                "NotOnOrAfter valid",
                format!(
                    "Current time {} is at or after NotOnOrAfter {} (skew: {}s)",
                    now, not_on_or_after, clock_skew_seconds
                ),
            ));
        }
    } else {
        checks.push(ValidationCheck::pass(10, "NotOnOrAfter valid"));
    }

    checks
}

/// Check the OneTimeUse condition.
///
/// Returns check 12. The caller is responsible for using the replay cache
/// to enforce the one-time-use semantics.
pub fn check_one_time_use(one_time_use: bool) -> ValidationCheck {
    // This check just records whether the condition is present.
    // Actual enforcement is done by the replay cache in the validator.
    if one_time_use {
        ValidationCheck::pass(12, "OneTimeUse condition noted")
    } else {
        ValidationCheck::pass(12, "OneTimeUse condition")
    }
}

/// Check the ProxyRestriction condition.
///
/// `proxy_count` is the current proxy depth. If the condition specifies a
/// maximum count, the current depth must not exceed it.
pub fn check_proxy_restriction(
    proxy_restriction_count: Option<u32>,
    current_proxy_depth: u32,
) -> ValidationCheck {
    match proxy_restriction_count {
        Some(limit) => {
            if current_proxy_depth <= limit {
                ValidationCheck::pass(13, "ProxyRestriction count")
            } else {
                ValidationCheck::fail(
                    13,
                    "ProxyRestriction count",
                    format!(
                        "Proxy depth {} exceeds restriction limit {}",
                        current_proxy_depth, limit
                    ),
                )
            }
        }
        None => ValidationCheck::pass(13, "ProxyRestriction count"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeDelta;

    #[test]
    fn test_valid_time_conditions() {
        let now = Utc::now();
        let conditions = Conditions {
            not_before: Some(now - TimeDelta::seconds(60)),
            not_on_or_after: Some(now + TimeDelta::seconds(300)),
            audience_restrictions: vec![],
            one_time_use: false,
            proxy_restriction: None,
        };
        let checks = validate_time_conditions(&conditions, now, 180);
        assert!(checks.iter().all(|c| c.passed));
    }

    #[test]
    fn test_not_before_failed() {
        let now = Utc::now();
        let conditions = Conditions {
            not_before: Some(now + TimeDelta::seconds(300)), // 5 min in future
            not_on_or_after: None,
            audience_restrictions: vec![],
            one_time_use: false,
            proxy_restriction: None,
        };
        let checks = validate_time_conditions(&conditions, now, 180); // only 3 min skew
        let not_before_check = checks.iter().find(|c| c.check_number == 9).unwrap();
        assert!(!not_before_check.passed);
    }

    #[test]
    fn test_not_on_or_after_expired() {
        let now = Utc::now();
        let conditions = Conditions {
            not_before: None,
            not_on_or_after: Some(now - TimeDelta::seconds(300)), // 5 min ago
            audience_restrictions: vec![],
            one_time_use: false,
            proxy_restriction: None,
        };
        let checks = validate_time_conditions(&conditions, now, 180); // only 3 min skew
        let noa_check = checks.iter().find(|c| c.check_number == 10).unwrap();
        assert!(!noa_check.passed);
    }

    #[test]
    fn test_no_time_conditions() {
        let now = Utc::now();
        let conditions = Conditions {
            not_before: None,
            not_on_or_after: None,
            audience_restrictions: vec![],
            one_time_use: false,
            proxy_restriction: None,
        };
        let checks = validate_time_conditions(&conditions, now, 180);
        assert!(checks.iter().all(|c| c.passed));
    }

    #[test]
    fn test_proxy_restriction_within_limit() {
        let check = check_proxy_restriction(Some(5), 3);
        assert!(check.passed);
    }

    #[test]
    fn test_proxy_restriction_exceeded() {
        let check = check_proxy_restriction(Some(2), 5);
        assert!(!check.passed);
    }

    #[test]
    fn test_proxy_restriction_no_limit() {
        let check = check_proxy_restriction(None, 100);
        assert!(check.passed);
    }

    #[test]
    fn test_one_time_use_present() {
        let check = check_one_time_use(true);
        assert!(check.passed);
    }

    #[test]
    fn test_ref_time_conditions() {
        let now = Utc::now();
        let conditions = ConditionsRef {
            not_before: Some(now - TimeDelta::seconds(60)),
            not_on_or_after: Some(now + TimeDelta::seconds(300)),
            audience_restrictions: vec![],
            one_time_use: false,
            proxy_restriction: None,
        };
        let checks = validate_time_conditions_ref(&conditions, now, 180);
        assert!(checks.iter().all(|c| c.passed));
    }
}
