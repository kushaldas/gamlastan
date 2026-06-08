// Level of Assurance / authentication context handling (sections 5.3.1, 5.4.4, 6.3.4).

use crate::core::protocol::request::{AuthnContextComparison, RequestedAuthnContext};

use super::constants;
use super::error::SwedenConnectError;

/// A Level of Assurance authentication context recognised by the framework.
///
/// This is a convenience over the raw URI constants; unknown URIs can always be
/// passed through directly as strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LevelOfAssurance {
    /// LoA 1.
    Loa1,
    /// LoA 2.
    Loa2,
    /// LoA 3.
    Loa3,
    /// LoA 4.
    Loa4,
    /// LoA 2, non-resident.
    Loa2NonResident,
    /// LoA 3, non-resident.
    Loa3NonResident,
    /// LoA 4, non-resident.
    Loa4NonResident,
    /// Uncertified (self-declared) LoA 3.
    UncertifiedLoa3,
    /// eIDAS low (non-notified).
    EidasLow,
    /// eIDAS substantial (non-notified).
    EidasSubstantial,
    /// eIDAS high (non-notified).
    EidasHigh,
    /// eIDAS low (notified).
    EidasNfLow,
    /// eIDAS substantial (notified).
    EidasNfSubstantial,
    /// eIDAS high (notified).
    EidasNfHigh,
}

impl LevelOfAssurance {
    /// The authentication context class URI for this Level of Assurance.
    pub fn as_uri(self) -> &'static str {
        match self {
            LevelOfAssurance::Loa1 => constants::LOA1,
            LevelOfAssurance::Loa2 => constants::LOA2,
            LevelOfAssurance::Loa3 => constants::LOA3,
            LevelOfAssurance::Loa4 => constants::LOA4,
            LevelOfAssurance::Loa2NonResident => constants::LOA2_NONRESIDENT,
            LevelOfAssurance::Loa3NonResident => constants::LOA3_NONRESIDENT,
            LevelOfAssurance::Loa4NonResident => constants::LOA4_NONRESIDENT,
            LevelOfAssurance::UncertifiedLoa3 => constants::UNCERTIFIED_LOA3,
            LevelOfAssurance::EidasLow => constants::EIDAS_LOW,
            LevelOfAssurance::EidasSubstantial => constants::EIDAS_SUBSTANTIAL,
            LevelOfAssurance::EidasHigh => constants::EIDAS_HIGH,
            LevelOfAssurance::EidasNfLow => constants::EIDAS_NF_LOW,
            LevelOfAssurance::EidasNfSubstantial => constants::EIDAS_NF_SUBSTANTIAL,
            LevelOfAssurance::EidasNfHigh => constants::EIDAS_NF_HIGH,
        }
    }

    /// Parse a Level of Assurance from its authentication context class URI.
    pub fn from_uri(uri: &str) -> Option<Self> {
        let v = match uri {
            constants::LOA1 => LevelOfAssurance::Loa1,
            constants::LOA2 => LevelOfAssurance::Loa2,
            constants::LOA3 => LevelOfAssurance::Loa3,
            constants::LOA4 => LevelOfAssurance::Loa4,
            constants::LOA2_NONRESIDENT => LevelOfAssurance::Loa2NonResident,
            constants::LOA3_NONRESIDENT => LevelOfAssurance::Loa3NonResident,
            constants::LOA4_NONRESIDENT => LevelOfAssurance::Loa4NonResident,
            constants::UNCERTIFIED_LOA3 => LevelOfAssurance::UncertifiedLoa3,
            constants::EIDAS_LOW => LevelOfAssurance::EidasLow,
            constants::EIDAS_SUBSTANTIAL => LevelOfAssurance::EidasSubstantial,
            constants::EIDAS_HIGH => LevelOfAssurance::EidasHigh,
            constants::EIDAS_NF_LOW => LevelOfAssurance::EidasNfLow,
            constants::EIDAS_NF_SUBSTANTIAL => LevelOfAssurance::EidasNfSubstantial,
            constants::EIDAS_NF_HIGH => LevelOfAssurance::EidasNfHigh,
            _ => return None,
        };
        Some(v)
    }
}

/// Build a `<saml2p:RequestedAuthnContext>` with `Comparison="exact"`, as
/// mandated by section 5.3.1.
///
/// The profile forbids any comparison other than `exact`, so this constructor
/// always uses exact matching.
pub fn requested_authn_context<S: AsRef<str>>(loas: &[S]) -> RequestedAuthnContext {
    RequestedAuthnContext {
        authn_context_class_refs: loas.iter().map(|s| s.as_ref().to_string()).collect(),
        authn_context_decl_refs: vec![],
        comparison: AuthnContextComparison::Exact,
    }
}

/// Validate the authentication context class reference returned in an assertion
/// against the ones requested, per section 6.3.4.
///
/// - If `requested` is non-empty, `received` MUST be present and MUST equal one
///   of the requested URIs, otherwise the assertion is rejected.
/// - If `requested` is empty, any `received` URI is accepted (the SP must be
///   prepared to receive any URI declared by the IdP in its metadata).
pub fn validate_authn_context(
    received: Option<&str>,
    requested: &[String],
) -> Result<(), SwedenConnectError> {
    let received = received.ok_or(SwedenConnectError::MissingAuthnContextClassRef)?;

    if requested.is_empty() {
        return Ok(());
    }

    if requested.iter().any(|r| r == received) {
        Ok(())
    } else {
        Err(SwedenConnectError::LevelOfAssuranceMismatch {
            received: received.to_string(),
            requested: requested.to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_loa_uri_roundtrip() {
        for loa in [
            LevelOfAssurance::Loa1,
            LevelOfAssurance::Loa3,
            LevelOfAssurance::EidasNfSubstantial,
            LevelOfAssurance::UncertifiedLoa3,
        ] {
            assert_eq!(LevelOfAssurance::from_uri(loa.as_uri()), Some(loa));
        }
        assert_eq!(
            LevelOfAssurance::from_uri("http://example.com/unknown"),
            None
        );
    }

    #[test]
    fn test_requested_authn_context_is_exact() {
        let ctx = requested_authn_context(&[constants::LOA3, constants::EIDAS_NF_SUBSTANTIAL]);
        assert_eq!(ctx.comparison, AuthnContextComparison::Exact);
        assert_eq!(ctx.authn_context_class_refs.len(), 2);
    }

    #[test]
    fn test_validate_authn_context_match() {
        let requested = vec![constants::LOA3.to_string()];
        assert!(validate_authn_context(Some(constants::LOA3), &requested).is_ok());
    }

    #[test]
    fn test_validate_authn_context_mismatch() {
        let requested = vec![constants::LOA3.to_string()];
        let err = validate_authn_context(Some(constants::LOA2), &requested).unwrap_err();
        assert!(matches!(
            err,
            SwedenConnectError::LevelOfAssuranceMismatch { .. }
        ));
    }

    #[test]
    fn test_validate_authn_context_missing() {
        let requested = vec![constants::LOA3.to_string()];
        assert!(matches!(
            validate_authn_context(None, &requested),
            Err(SwedenConnectError::MissingAuthnContextClassRef)
        ));
    }

    #[test]
    fn test_validate_authn_context_no_request_accepts_any() {
        assert!(validate_authn_context(Some(constants::LOA4), &[]).is_ok());
        // But a totally absent context is still rejected.
        assert!(validate_authn_context(None, &[]).is_err());
    }
}
