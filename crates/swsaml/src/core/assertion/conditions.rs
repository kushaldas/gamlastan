// SAML 2.0 Conditions types
//
// Per Errata:
// - E46: AudienceRestriction - OR within each, AND across multiple

use chrono::{DateTime, Utc};

/// Borrowed Conditions element.
#[derive(Debug, Clone, PartialEq)]
pub struct ConditionsRef<'a> {
    /// Earliest time the assertion is valid.
    pub not_before: Option<DateTime<Utc>>,
    /// Time at which the assertion expires.
    pub not_on_or_after: Option<DateTime<Utc>>,
    /// Audience restrictions. Per E46: OR within each, AND across multiple.
    pub audience_restrictions: Vec<AudienceRestrictionRef<'a>>,
    /// OneTimeUse condition.
    pub one_time_use: bool,
    /// Proxy restriction.
    pub proxy_restriction: Option<ProxyRestrictionRef<'a>>,
}

impl<'a> ConditionsRef<'a> {
    /// Convert to an owned Conditions.
    pub fn to_owned(&self) -> Conditions {
        Conditions {
            not_before: self.not_before,
            not_on_or_after: self.not_on_or_after,
            audience_restrictions: self
                .audience_restrictions
                .iter()
                .map(|ar| ar.to_owned())
                .collect(),
            one_time_use: self.one_time_use,
            proxy_restriction: self.proxy_restriction.as_ref().map(|pr| pr.to_owned()),
        }
    }
}

/// Owned Conditions element.
#[derive(Debug, Clone, PartialEq)]
pub struct Conditions {
    /// Earliest time the assertion is valid.
    pub not_before: Option<DateTime<Utc>>,
    /// Time at which the assertion expires.
    pub not_on_or_after: Option<DateTime<Utc>>,
    /// Audience restrictions. Per E46: OR within each, AND across multiple.
    pub audience_restrictions: Vec<AudienceRestriction>,
    /// OneTimeUse condition.
    pub one_time_use: bool,
    /// Proxy restriction.
    pub proxy_restriction: Option<ProxyRestriction>,
}

/// Borrowed AudienceRestriction.
/// Per E46: Within a single AudienceRestriction, any matching audience satisfies it (OR).
/// Multiple AudienceRestriction elements must all be satisfied (AND).
#[derive(Debug, Clone, PartialEq)]
pub struct AudienceRestrictionRef<'a> {
    /// The audience URIs. Match is OR within this restriction.
    pub audiences: Vec<&'a str>,
}

impl<'a> AudienceRestrictionRef<'a> {
    /// Convert to an owned AudienceRestriction.
    pub fn to_owned(&self) -> AudienceRestriction {
        AudienceRestriction {
            audiences: self.audiences.iter().map(|a| a.to_string()).collect(),
        }
    }

    /// Check if the given entity ID matches this restriction.
    /// Returns true if any audience in this restriction matches (OR logic per E46).
    pub fn matches(&self, entity_id: &str) -> bool {
        self.audiences.contains(&entity_id)
    }
}

/// Owned AudienceRestriction.
#[derive(Debug, Clone, PartialEq)]
pub struct AudienceRestriction {
    /// The audience URIs.
    pub audiences: Vec<String>,
}

impl AudienceRestriction {
    /// Check if the given entity ID matches this restriction.
    pub fn matches(&self, entity_id: &str) -> bool {
        self.audiences.iter().any(|a| a == entity_id)
    }
}

/// Borrowed ProxyRestriction.
#[derive(Debug, Clone, PartialEq)]
pub struct ProxyRestrictionRef<'a> {
    /// The maximum number of times the assertion may be proxied.
    pub count: Option<u32>,
    /// The set of audiences to which proxying is permitted.
    pub audiences: Vec<&'a str>,
}

impl<'a> ProxyRestrictionRef<'a> {
    /// Convert to an owned ProxyRestriction.
    pub fn to_owned(&self) -> ProxyRestriction {
        ProxyRestriction {
            count: self.count,
            audiences: self.audiences.iter().map(|a| a.to_string()).collect(),
        }
    }
}

/// Owned ProxyRestriction.
#[derive(Debug, Clone, PartialEq)]
pub struct ProxyRestriction {
    /// The maximum number of times the assertion may be proxied.
    pub count: Option<u32>,
    /// The set of audiences to which proxying is permitted.
    pub audiences: Vec<String>,
}

/// Evaluate audience restrictions per E46 semantics.
///
/// - If no restrictions present, returns `true`.
/// - ALL restrictions must be satisfied (AND).
/// - Within each restriction, ANY audience match satisfies it (OR).
pub fn evaluate_audience_restrictions(
    restrictions: &[AudienceRestriction],
    sp_entity_id: &str,
) -> bool {
    if restrictions.is_empty() {
        return true;
    }
    restrictions.iter().all(|r| r.matches(sp_entity_id))
}

/// Evaluate borrowed audience restrictions per E46 semantics.
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
    fn test_audience_restriction_or_within() {
        let ar = AudienceRestriction {
            audiences: vec![
                "https://sp1.example.com".to_string(),
                "https://sp2.example.com".to_string(),
            ],
        };
        // Either audience should match (OR)
        assert!(ar.matches("https://sp1.example.com"));
        assert!(ar.matches("https://sp2.example.com"));
        assert!(!ar.matches("https://sp3.example.com"));
    }

    #[test]
    fn test_audience_restriction_and_across() {
        let restrictions = vec![
            AudienceRestriction {
                audiences: vec!["https://sp.example.com".to_string()],
            },
            AudienceRestriction {
                audiences: vec!["https://sp.example.com".to_string()],
            },
        ];
        // Both must be satisfied (AND)
        assert!(evaluate_audience_restrictions(
            &restrictions,
            "https://sp.example.com"
        ));
    }

    #[test]
    fn test_audience_restriction_and_across_fail() {
        let restrictions = vec![
            AudienceRestriction {
                audiences: vec!["https://sp.example.com".to_string()],
            },
            AudienceRestriction {
                audiences: vec!["https://other.example.com".to_string()],
            },
        ];
        // Second restriction fails
        assert!(!evaluate_audience_restrictions(
            &restrictions,
            "https://sp.example.com"
        ));
    }

    #[test]
    fn test_audience_restriction_empty() {
        assert!(evaluate_audience_restrictions(
            &[],
            "https://sp.example.com"
        ));
    }

    #[test]
    fn test_conditions_ref_to_owned() {
        let cond = ConditionsRef {
            not_before: None,
            not_on_or_after: None,
            audience_restrictions: vec![AudienceRestrictionRef {
                audiences: vec!["https://sp.example.com"],
            }],
            one_time_use: false,
            proxy_restriction: None,
        };
        let owned = cond.to_owned();
        assert_eq!(owned.audience_restrictions.len(), 1);
        assert!(owned.audience_restrictions[0].matches("https://sp.example.com"));
    }
}
