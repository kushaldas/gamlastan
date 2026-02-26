// SAML 2.0 Request types

use chrono::{DateTime, Utc};

use crate::core::assertion::conditions::{Conditions, ConditionsRef};
use crate::core::assertion::issuer::{Issuer, IssuerRef};
use crate::core::assertion::name_id::{NameIdPolicy, NameIdPolicyRef};
use crate::core::assertion::subject::{Subject, SubjectRef};
use crate::core::identifiers::SamlVersion;

/// Borrowed RequestBase - common fields for all SAML request messages.
#[derive(Debug, Clone, PartialEq)]
pub struct RequestBaseRef<'a> {
    /// Unique identifier for the request.
    pub id: &'a str,
    /// SAML version.
    pub version: SamlVersion,
    /// Time the request was issued.
    pub issue_instant: DateTime<Utc>,
    /// The intended destination URI.
    pub destination: Option<&'a str>,
    /// Consent URI.
    pub consent: Option<&'a str>,
    /// The request issuer.
    pub issuer: Option<IssuerRef<'a>>,
    /// Whether a digital signature is present.
    pub has_signature: bool,
}

impl<'a> RequestBaseRef<'a> {
    /// Convert to owned.
    pub fn to_owned(&self) -> RequestBase {
        RequestBase {
            id: self.id.to_string(),
            version: self.version,
            issue_instant: self.issue_instant,
            destination: self.destination.map(str::to_string),
            consent: self.consent.map(str::to_string),
            issuer: self.issuer.as_ref().map(|i| i.to_owned()),
            has_signature: self.has_signature,
        }
    }
}

/// Owned RequestBase.
#[derive(Debug, Clone, PartialEq)]
pub struct RequestBase {
    /// Unique identifier for the request.
    pub id: String,
    /// SAML version.
    pub version: SamlVersion,
    /// Time the request was issued.
    pub issue_instant: DateTime<Utc>,
    /// The intended destination URI.
    pub destination: Option<String>,
    /// Consent URI.
    pub consent: Option<String>,
    /// The request issuer.
    pub issuer: Option<Issuer>,
    /// Whether a digital signature is present.
    pub has_signature: bool,
}

/// AuthnRequest comparison type for RequestedAuthnContext.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthnContextComparison {
    Exact,
    Minimum,
    Maximum,
    Better,
}

impl AuthnContextComparison {
    /// Get string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            AuthnContextComparison::Exact => "exact",
            AuthnContextComparison::Minimum => "minimum",
            AuthnContextComparison::Maximum => "maximum",
            AuthnContextComparison::Better => "better",
        }
    }
}

impl std::str::FromStr for AuthnContextComparison {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "exact" => Ok(AuthnContextComparison::Exact),
            "minimum" => Ok(AuthnContextComparison::Minimum),
            "maximum" => Ok(AuthnContextComparison::Maximum),
            "better" => Ok(AuthnContextComparison::Better),
            _ => Err(()),
        }
    }
}

/// Borrowed RequestedAuthnContext.
#[derive(Debug, Clone, PartialEq)]
pub struct RequestedAuthnContextRef<'a> {
    /// Authentication context class references.
    pub authn_context_class_refs: Vec<&'a str>,
    /// Authentication context declaration references.
    pub authn_context_decl_refs: Vec<&'a str>,
    /// Comparison type (default: exact).
    pub comparison: AuthnContextComparison,
}

impl<'a> RequestedAuthnContextRef<'a> {
    /// Convert to owned.
    pub fn to_owned(&self) -> RequestedAuthnContext {
        RequestedAuthnContext {
            authn_context_class_refs: self
                .authn_context_class_refs
                .iter()
                .map(|s| s.to_string())
                .collect(),
            authn_context_decl_refs: self
                .authn_context_decl_refs
                .iter()
                .map(|s| s.to_string())
                .collect(),
            comparison: self.comparison,
        }
    }
}

/// Owned RequestedAuthnContext.
#[derive(Debug, Clone, PartialEq)]
pub struct RequestedAuthnContext {
    pub authn_context_class_refs: Vec<String>,
    pub authn_context_decl_refs: Vec<String>,
    pub comparison: AuthnContextComparison,
}

/// Borrowed Scoping.
#[derive(Debug, Clone, PartialEq)]
pub struct ScopingRef<'a> {
    /// Maximum number of proxying hops.
    pub proxy_count: Option<u32>,
    /// List of IdP entity IDs.
    pub idp_list: Vec<&'a str>,
    /// Requester IDs.
    pub requester_ids: Vec<&'a str>,
}

impl<'a> ScopingRef<'a> {
    /// Convert to owned.
    pub fn to_owned(&self) -> Scoping {
        Scoping {
            proxy_count: self.proxy_count,
            idp_list: self.idp_list.iter().map(|s| s.to_string()).collect(),
            requester_ids: self.requester_ids.iter().map(|s| s.to_string()).collect(),
        }
    }
}

/// Owned Scoping.
#[derive(Debug, Clone, PartialEq)]
pub struct Scoping {
    pub proxy_count: Option<u32>,
    pub idp_list: Vec<String>,
    pub requester_ids: Vec<String>,
}

/// Borrowed AuthnRequest.
#[derive(Debug, Clone, PartialEq)]
pub struct AuthnRequestRef<'a> {
    /// Common request fields.
    pub base: RequestBaseRef<'a>,
    /// Subject (MUST NOT contain SubjectConfirmation per profile).
    pub subject: Option<SubjectRef<'a>>,
    /// Name ID policy.
    pub name_id_policy: Option<NameIdPolicyRef<'a>>,
    /// Conditions requested.
    pub conditions: Option<ConditionsRef<'a>>,
    /// Requested authentication context.
    pub requested_authn_context: Option<RequestedAuthnContextRef<'a>>,
    /// Scoping.
    pub scoping: Option<ScopingRef<'a>>,
    /// Force re-authentication.
    pub force_authn: Option<bool>,
    /// Passive authentication requested.
    pub is_passive: Option<bool>,
    /// Index of the ACS endpoint (from SP metadata).
    pub assertion_consumer_service_index: Option<u16>,
    /// URL of the ACS endpoint (alternative to index).
    pub assertion_consumer_service_url: Option<&'a str>,
    /// Protocol binding for the response.
    pub protocol_binding: Option<&'a str>,
    /// Index of the AttributeConsumingService.
    pub attribute_consuming_service_index: Option<u16>,
    /// Human-readable name of the SP.
    pub provider_name: Option<&'a str>,
}

impl<'a> AuthnRequestRef<'a> {
    /// Convert to owned.
    pub fn to_owned(&self) -> AuthnRequest {
        AuthnRequest {
            base: self.base.to_owned(),
            subject: self.subject.as_ref().map(|s| s.to_owned()),
            name_id_policy: self.name_id_policy.as_ref().map(|n| n.to_owned()),
            conditions: self.conditions.as_ref().map(|c| c.to_owned()),
            requested_authn_context: self.requested_authn_context.as_ref().map(|r| r.to_owned()),
            scoping: self.scoping.as_ref().map(|s| s.to_owned()),
            force_authn: self.force_authn,
            is_passive: self.is_passive,
            assertion_consumer_service_index: self.assertion_consumer_service_index,
            assertion_consumer_service_url: self.assertion_consumer_service_url.map(str::to_string),
            protocol_binding: self.protocol_binding.map(str::to_string),
            attribute_consuming_service_index: self.attribute_consuming_service_index,
            provider_name: self.provider_name.map(str::to_string),
        }
    }
}

/// Owned AuthnRequest.
#[derive(Debug, Clone, PartialEq)]
pub struct AuthnRequest {
    /// Common request fields.
    pub base: RequestBase,
    /// Subject (MUST NOT contain SubjectConfirmation per profile).
    pub subject: Option<Subject>,
    /// Name ID policy.
    pub name_id_policy: Option<NameIdPolicy>,
    /// Conditions requested.
    pub conditions: Option<Conditions>,
    /// Requested authentication context.
    pub requested_authn_context: Option<RequestedAuthnContext>,
    /// Scoping.
    pub scoping: Option<Scoping>,
    /// Force re-authentication.
    pub force_authn: Option<bool>,
    /// Passive authentication requested.
    pub is_passive: Option<bool>,
    /// Index of the ACS endpoint (from SP metadata).
    pub assertion_consumer_service_index: Option<u16>,
    /// URL of the ACS endpoint (alternative to index).
    pub assertion_consumer_service_url: Option<String>,
    /// Protocol binding for the response.
    pub protocol_binding: Option<String>,
    /// Index of the AttributeConsumingService.
    pub attribute_consuming_service_index: Option<u16>,
    /// Human-readable name of the SP.
    pub provider_name: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::constants::*;

    #[test]
    fn test_authn_request_ref_to_owned() {
        let now = chrono::Utc::now();
        let req = AuthnRequestRef {
            base: RequestBaseRef {
                id: "_req_123",
                version: SamlVersion::V2_0,
                issue_instant: now,
                destination: Some("https://idp.example.com/sso"),
                consent: None,
                issuer: Some(IssuerRef {
                    value: "https://sp.example.com",
                    format: None,
                    name_qualifier: None,
                    sp_name_qualifier: None,
                }),
                has_signature: false,
            },
            subject: None,
            name_id_policy: Some(NameIdPolicyRef {
                format: Some(NAMEID_PERSISTENT),
                sp_name_qualifier: None,
                allow_create: true,
            }),
            conditions: None,
            requested_authn_context: None,
            scoping: None,
            force_authn: Some(false),
            is_passive: Some(false),
            assertion_consumer_service_index: None,
            assertion_consumer_service_url: Some("https://sp.example.com/acs"),
            protocol_binding: Some(BINDING_HTTP_POST),
            attribute_consuming_service_index: None,
            provider_name: Some("Example SP"),
        };

        let owned = req.to_owned();
        assert_eq!(owned.base.id, "_req_123");
        assert_eq!(
            owned.base.destination.as_deref(),
            Some("https://idp.example.com/sso")
        );
        assert!(owned.name_id_policy.as_ref().unwrap().allow_create);
        assert_eq!(
            owned.assertion_consumer_service_url.as_deref(),
            Some("https://sp.example.com/acs")
        );
        assert_eq!(owned.protocol_binding.as_deref(), Some(BINDING_HTTP_POST));
    }

    #[test]
    fn test_authn_context_comparison() {
        assert_eq!(
            "exact".parse::<AuthnContextComparison>(),
            Ok(AuthnContextComparison::Exact)
        );
        assert_eq!(
            "minimum".parse::<AuthnContextComparison>(),
            Ok(AuthnContextComparison::Minimum)
        );
        assert!("invalid".parse::<AuthnContextComparison>().is_err());
    }
}
