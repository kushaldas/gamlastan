// SAML 2.0 AuthnStatement types
//
// Per Errata:
// - E79: SessionNotOnOrAfter = upper bound

use chrono::{DateTime, Utc};

/// Borrowed AuthnStatement.
#[derive(Debug, Clone, PartialEq)]
pub struct AuthnStatementRef<'a> {
    /// Time of authentication.
    pub authn_instant: DateTime<Utc>,
    /// Unique index for this session at the IdP.
    pub session_index: Option<&'a str>,
    /// Upper bound on session lifetime. Per E79: this is an upper bound.
    pub session_not_on_or_after: Option<DateTime<Utc>>,
    /// Subject locality information.
    pub subject_locality: Option<SubjectLocalityRef<'a>>,
    /// Authentication context.
    pub authn_context: AuthnContextRef<'a>,
}

impl<'a> AuthnStatementRef<'a> {
    /// Convert to an owned AuthnStatement.
    pub fn to_owned(&self) -> AuthnStatement {
        AuthnStatement {
            authn_instant: self.authn_instant,
            session_index: self.session_index.map(str::to_string),
            session_not_on_or_after: self.session_not_on_or_after,
            subject_locality: self.subject_locality.as_ref().map(|sl| sl.to_owned()),
            authn_context: self.authn_context.to_owned(),
        }
    }
}

/// Owned AuthnStatement.
#[derive(Debug, Clone, PartialEq)]
pub struct AuthnStatement {
    /// Time of authentication.
    pub authn_instant: DateTime<Utc>,
    /// Unique index for this session at the IdP.
    pub session_index: Option<String>,
    /// Upper bound on session lifetime. Per E79.
    pub session_not_on_or_after: Option<DateTime<Utc>>,
    /// Subject locality information.
    pub subject_locality: Option<SubjectLocality>,
    /// Authentication context.
    pub authn_context: AuthnContext,
}

/// Borrowed SubjectLocality.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubjectLocalityRef<'a> {
    /// IP address of the system from which the subject was authenticated.
    pub address: Option<&'a str>,
    /// DNS name of the system from which the subject was authenticated.
    pub dns_name: Option<&'a str>,
}

impl<'a> SubjectLocalityRef<'a> {
    /// Convert to owned.
    pub fn to_owned(&self) -> SubjectLocality {
        SubjectLocality {
            address: self.address.map(str::to_string),
            dns_name: self.dns_name.map(str::to_string),
        }
    }
}

/// Owned SubjectLocality.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectLocality {
    /// IP address.
    pub address: Option<String>,
    /// DNS name.
    pub dns_name: Option<String>,
}

/// Borrowed AuthnContext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthnContextRef<'a> {
    /// The authentication context class reference URI.
    pub authn_context_class_ref: Option<&'a str>,
    /// Authentication context declaration reference URI.
    pub authn_context_decl_ref: Option<&'a str>,
    /// Authenticating authorities.
    pub authenticating_authorities: Vec<&'a str>,
}

impl<'a> AuthnContextRef<'a> {
    /// Convert to owned.
    pub fn to_owned(&self) -> AuthnContext {
        AuthnContext {
            authn_context_class_ref: self.authn_context_class_ref.map(str::to_string),
            authn_context_decl_ref: self.authn_context_decl_ref.map(str::to_string),
            authenticating_authorities: self
                .authenticating_authorities
                .iter()
                .map(|a| a.to_string())
                .collect(),
        }
    }
}

/// Owned AuthnContext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthnContext {
    /// The authentication context class reference URI.
    pub authn_context_class_ref: Option<String>,
    /// Authentication context declaration reference URI.
    pub authn_context_decl_ref: Option<String>,
    /// Authenticating authorities.
    pub authenticating_authorities: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::constants::AUTHN_CONTEXT_PASSWORD_PROTECTED_TRANSPORT;
    use chrono::Utc;

    #[test]
    fn test_authn_statement_ref_to_owned() {
        let now = Utc::now();
        let stmt_ref = AuthnStatementRef {
            authn_instant: now,
            session_index: Some("_session_1"),
            session_not_on_or_after: None,
            subject_locality: Some(SubjectLocalityRef {
                address: Some("192.168.1.1"),
                dns_name: Some("client.example.com"),
            }),
            authn_context: AuthnContextRef {
                authn_context_class_ref: Some(AUTHN_CONTEXT_PASSWORD_PROTECTED_TRANSPORT),
                authn_context_decl_ref: None,
                authenticating_authorities: vec![],
            },
        };
        let owned = stmt_ref.to_owned();
        assert_eq!(owned.authn_instant, now);
        assert_eq!(owned.session_index.as_deref(), Some("_session_1"));
        assert_eq!(
            owned.authn_context.authn_context_class_ref.as_deref(),
            Some(AUTHN_CONTEXT_PASSWORD_PROTECTED_TRANSPORT)
        );
        assert_eq!(
            owned.subject_locality.as_ref().unwrap().address.as_deref(),
            Some("192.168.1.1")
        );
    }
}
