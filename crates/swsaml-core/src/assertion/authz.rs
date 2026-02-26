// SAML 2.0 AuthzDecisionStatement types
//
// Per Errata:
// - E13: Indeterminate added to DecisionType

/// Decision type for authorization decisions.
/// Per E13: includes Indeterminate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DecisionType {
    /// Access is permitted.
    Permit,
    /// Access is denied.
    Deny,
    /// Decision is indeterminate. Per E13.
    Indeterminate,
}

impl DecisionType {
    /// Get the string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            DecisionType::Permit => "Permit",
            DecisionType::Deny => "Deny",
            DecisionType::Indeterminate => "Indeterminate",
        }
    }
}

impl std::str::FromStr for DecisionType {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Permit" => Ok(DecisionType::Permit),
            "Deny" => Ok(DecisionType::Deny),
            "Indeterminate" => Ok(DecisionType::Indeterminate),
            _ => Err(()),
        }
    }
}

/// Borrowed Action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActionRef<'a> {
    /// The action namespace URI.
    pub namespace: &'a str,
    /// The action value.
    pub value: &'a str,
}

impl<'a> ActionRef<'a> {
    /// Convert to owned.
    pub fn to_owned(&self) -> Action {
        Action {
            namespace: self.namespace.to_string(),
            value: self.value.to_string(),
        }
    }
}

/// Owned Action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Action {
    /// The action namespace URI.
    pub namespace: String,
    /// The action value.
    pub value: String,
}

/// Borrowed Evidence (contains assertion references or assertions).
#[derive(Debug, Clone, PartialEq)]
pub struct EvidenceRef<'a> {
    /// Assertion ID references.
    pub assertion_id_refs: Vec<&'a str>,
    /// Assertion URI references.
    pub assertion_uri_refs: Vec<&'a str>,
}

impl<'a> EvidenceRef<'a> {
    /// Convert to owned.
    pub fn to_owned(&self) -> Evidence {
        Evidence {
            assertion_id_refs: self
                .assertion_id_refs
                .iter()
                .map(|s| s.to_string())
                .collect(),
            assertion_uri_refs: self
                .assertion_uri_refs
                .iter()
                .map(|s| s.to_string())
                .collect(),
        }
    }
}

/// Owned Evidence.
#[derive(Debug, Clone, PartialEq)]
pub struct Evidence {
    /// Assertion ID references.
    pub assertion_id_refs: Vec<String>,
    /// Assertion URI references.
    pub assertion_uri_refs: Vec<String>,
}

/// Borrowed AuthzDecisionStatement.
#[derive(Debug, Clone, PartialEq)]
pub struct AuthzDecisionStatementRef<'a> {
    /// The resource URI.
    pub resource: &'a str,
    /// The authorization decision.
    pub decision: DecisionType,
    /// Actions being authorized.
    pub actions: Vec<ActionRef<'a>>,
    /// Supporting evidence.
    pub evidence: Option<EvidenceRef<'a>>,
}

impl<'a> AuthzDecisionStatementRef<'a> {
    /// Convert to owned.
    pub fn to_owned(&self) -> AuthzDecisionStatement {
        AuthzDecisionStatement {
            resource: self.resource.to_string(),
            decision: self.decision,
            actions: self.actions.iter().map(|a| a.to_owned()).collect(),
            evidence: self.evidence.as_ref().map(|e| e.to_owned()),
        }
    }
}

/// Owned AuthzDecisionStatement.
#[derive(Debug, Clone, PartialEq)]
pub struct AuthzDecisionStatement {
    /// The resource URI.
    pub resource: String,
    /// The authorization decision.
    pub decision: DecisionType,
    /// Actions being authorized.
    pub actions: Vec<Action>,
    /// Supporting evidence.
    pub evidence: Option<Evidence>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decision_type_roundtrip() {
        for dt in &[
            DecisionType::Permit,
            DecisionType::Deny,
            DecisionType::Indeterminate,
        ] {
            assert_eq!(dt.as_str().parse::<DecisionType>(), Ok(*dt));
        }
    }

    #[test]
    fn test_decision_type_invalid() {
        assert!("Unknown".parse::<DecisionType>().is_err());
    }

    #[test]
    fn test_authz_decision_statement_ref_to_owned() {
        let stmt = AuthzDecisionStatementRef {
            resource: "https://sp.example.com/resource",
            decision: DecisionType::Permit,
            actions: vec![ActionRef {
                namespace: "urn:oasis:names:tc:SAML:1.0:action:rwedc",
                value: "Read",
            }],
            evidence: None,
        };
        let owned = stmt.to_owned();
        assert_eq!(owned.resource, "https://sp.example.com/resource");
        assert_eq!(owned.decision, DecisionType::Permit);
        assert_eq!(owned.actions.len(), 1);
    }
}
