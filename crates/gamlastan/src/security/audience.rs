// SAML 2.0 Audience restriction evaluation
//
// Per Errata E46:
// - Within a single AudienceRestriction, ANY matching audience satisfies it (OR).
// - Multiple AudienceRestriction elements must ALL be satisfied (AND).
//
// This module re-exports and extends the core audience evaluation functions
// for use in the security validation context.

use crate::core::assertion::conditions::{
    AudienceRestriction, AudienceRestrictionRef, Conditions, ConditionsRef,
};

/// Evaluate audience restrictions from owned Conditions against an SP entity ID.
///
/// Per E46:
/// - If no restrictions present, returns `true` (no audience constraint).
/// - ALL restrictions must be satisfied (AND across restrictions).
/// - Within each restriction, ANY audience match satisfies it (OR within restriction).
pub fn evaluate_audience(conditions: &Conditions, sp_entity_id: &str) -> bool {
    evaluate_audience_restrictions(&conditions.audience_restrictions, sp_entity_id)
}

/// Evaluate audience restrictions from borrowed Conditions against an SP entity ID.
pub fn evaluate_audience_ref(conditions: &ConditionsRef<'_>, sp_entity_id: &str) -> bool {
    evaluate_audience_restrictions_ref(&conditions.audience_restrictions, sp_entity_id)
}

/// Evaluate a slice of owned AudienceRestriction elements.
///
/// Per E46: AND across multiple restrictions, OR within each.
pub fn evaluate_audience_restrictions(
    restrictions: &[AudienceRestriction],
    sp_entity_id: &str,
) -> bool {
    if restrictions.is_empty() {
        return true;
    }
    restrictions.iter().all(|r| r.matches(sp_entity_id))
}

/// Evaluate a slice of borrowed AudienceRestriction elements.
pub fn evaluate_audience_restrictions_ref(
    restrictions: &[AudienceRestrictionRef<'_>],
    sp_entity_id: &str,
) -> bool {
    if restrictions.is_empty() {
        return true;
    }
    restrictions.iter().all(|r| r.matches(sp_entity_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_restrictions_passes() {
        assert!(evaluate_audience_restrictions(
            &[],
            "https://sp.example.com"
        ));
    }

    #[test]
    fn test_single_restriction_match() {
        let restrictions = vec![AudienceRestriction {
            audiences: vec!["https://sp.example.com".to_string()],
        }];
        assert!(evaluate_audience_restrictions(
            &restrictions,
            "https://sp.example.com"
        ));
    }

    #[test]
    fn test_single_restriction_no_match() {
        let restrictions = vec![AudienceRestriction {
            audiences: vec!["https://other.example.com".to_string()],
        }];
        assert!(!evaluate_audience_restrictions(
            &restrictions,
            "https://sp.example.com"
        ));
    }

    #[test]
    fn test_or_within_restriction() {
        let restrictions = vec![AudienceRestriction {
            audiences: vec![
                "https://sp1.example.com".to_string(),
                "https://sp2.example.com".to_string(),
            ],
        }];
        // Either audience should match (OR)
        assert!(evaluate_audience_restrictions(
            &restrictions,
            "https://sp1.example.com"
        ));
        assert!(evaluate_audience_restrictions(
            &restrictions,
            "https://sp2.example.com"
        ));
        assert!(!evaluate_audience_restrictions(
            &restrictions,
            "https://sp3.example.com"
        ));
    }

    #[test]
    fn test_and_across_restrictions() {
        let restrictions = vec![
            AudienceRestriction {
                audiences: vec![
                    "https://sp.example.com".to_string(),
                    "https://partner.example.com".to_string(),
                ],
            },
            AudienceRestriction {
                audiences: vec!["https://sp.example.com".to_string()],
            },
        ];
        // Must match both restrictions
        assert!(evaluate_audience_restrictions(
            &restrictions,
            "https://sp.example.com"
        ));
        // partner matches first but not second
        assert!(!evaluate_audience_restrictions(
            &restrictions,
            "https://partner.example.com"
        ));
    }

    #[test]
    fn test_evaluate_audience_from_conditions() {
        let conditions = Conditions {
            not_before: None,
            not_on_or_after: None,
            audience_restrictions: vec![AudienceRestriction {
                audiences: vec!["https://sp.example.com".to_string()],
            }],
            one_time_use: false,
            proxy_restriction: None,
        };
        assert!(evaluate_audience(&conditions, "https://sp.example.com"));
        assert!(!evaluate_audience(&conditions, "https://evil.example.com"));
    }

    #[test]
    fn test_evaluate_audience_from_conditions_no_restrictions() {
        let conditions = Conditions {
            not_before: None,
            not_on_or_after: None,
            audience_restrictions: vec![],
            one_time_use: false,
            proxy_restriction: None,
        };
        assert!(evaluate_audience(&conditions, "https://sp.example.com"));
    }

    #[test]
    fn test_ref_evaluation() {
        let restrictions = vec![AudienceRestrictionRef {
            audiences: vec!["https://sp.example.com"],
        }];
        assert!(evaluate_audience_restrictions_ref(
            &restrictions,
            "https://sp.example.com"
        ));
        assert!(!evaluate_audience_restrictions_ref(
            &restrictions,
            "https://other.example.com"
        ));
    }
}
