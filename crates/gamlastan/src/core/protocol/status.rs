// SAML 2.0 Status types
//
// Per Errata:
// - E65: Second-level status codes are optional

/// Borrowed Status.
#[derive(Debug, Clone, PartialEq)]
pub struct StatusRef<'a> {
    /// The status code.
    pub status_code: StatusCodeRef<'a>,
    /// Optional status message.
    pub status_message: Option<&'a str>,
    /// Optional status detail (raw XML).
    pub status_detail: Option<&'a str>,
}

impl<'a> StatusRef<'a> {
    /// Convert to owned.
    pub fn to_owned(&self) -> Status {
        Status {
            status_code: self.status_code.to_owned(),
            status_message: self.status_message.map(str::to_string),
            status_detail: self.status_detail.map(str::to_string),
        }
    }

    /// Check if this status indicates success.
    pub fn is_success(&self) -> bool {
        self.status_code.is_success()
    }
}

/// Owned Status.
#[derive(Debug, Clone, PartialEq)]
pub struct Status {
    /// The status code.
    pub status_code: StatusCode,
    /// Optional status message.
    pub status_message: Option<String>,
    /// Optional status detail (raw XML).
    pub status_detail: Option<String>,
}

impl Status {
    /// Create a success status.
    pub fn success() -> Self {
        Status {
            status_code: StatusCode::success(),
            status_message: None,
            status_detail: None,
        }
    }

    /// Check if this status indicates success.
    pub fn is_success(&self) -> bool {
        self.status_code.is_success()
    }

    /// Create a requester error status.
    pub fn requester(message: Option<String>) -> Self {
        Status {
            status_code: StatusCode::requester(),
            status_message: message,
            status_detail: None,
        }
    }

    /// Create a responder error status.
    pub fn responder(message: Option<String>) -> Self {
        Status {
            status_code: StatusCode::responder(),
            status_message: message,
            status_detail: None,
        }
    }

    /// Create a status with a nested sub-status code.
    pub fn with_sub_status(top_level: &str, sub: &str, message: Option<String>) -> Self {
        Status {
            status_code: StatusCode {
                value: top_level.to_string(),
                sub_status: Some(Box::new(StatusCode {
                    value: sub.to_string(),
                    sub_status: None,
                })),
            },
            status_message: message,
            status_detail: None,
        }
    }
}

/// Borrowed StatusCode.
/// Per E65: The second-level status code is optional.
#[derive(Debug, Clone, PartialEq)]
pub struct StatusCodeRef<'a> {
    /// The top-level status code URI.
    pub value: &'a str,
    /// Optional second-level status code. Per E65: this is optional.
    pub sub_status: Option<Box<StatusCodeRef<'a>>>,
}

impl<'a> StatusCodeRef<'a> {
    /// Convert to owned.
    pub fn to_owned(&self) -> StatusCode {
        StatusCode {
            value: self.value.to_string(),
            sub_status: self
                .sub_status
                .as_ref()
                .map(|s| Box::new(StatusCodeRef::to_owned(s))),
        }
    }

    /// Check if this status code indicates success.
    pub fn is_success(&self) -> bool {
        self.value == crate::core::constants::STATUS_SUCCESS
    }
}

/// Owned StatusCode.
#[derive(Debug, Clone, PartialEq)]
pub struct StatusCode {
    /// The top-level status code URI.
    pub value: String,
    /// Optional second-level status code.
    pub sub_status: Option<Box<StatusCode>>,
}

impl StatusCode {
    /// Create a success status code.
    pub fn success() -> Self {
        StatusCode {
            value: crate::core::constants::STATUS_SUCCESS.to_string(),
            sub_status: None,
        }
    }

    /// Check if this status code indicates success.
    pub fn is_success(&self) -> bool {
        self.value == crate::core::constants::STATUS_SUCCESS
    }

    /// Create a requester error status code.
    pub fn requester() -> Self {
        StatusCode {
            value: crate::core::constants::STATUS_REQUESTER.to_string(),
            sub_status: None,
        }
    }

    /// Create a responder error status code.
    pub fn responder() -> Self {
        StatusCode {
            value: crate::core::constants::STATUS_RESPONDER.to_string(),
            sub_status: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::constants::*;

    #[test]
    fn test_status_success() {
        let status = Status::success();
        assert!(status.is_success());
        assert!(status.status_message.is_none());
    }

    #[test]
    fn test_status_code_with_sub_status() {
        let code = StatusCode {
            value: STATUS_REQUESTER.to_string(),
            sub_status: Some(Box::new(StatusCode {
                value: STATUS_INVALID_NAMEID_POLICY.to_string(),
                sub_status: None,
            })),
        };
        assert!(!code.is_success());
        assert!(code.sub_status.is_some());
        assert_eq!(
            code.sub_status.as_ref().unwrap().value,
            STATUS_INVALID_NAMEID_POLICY
        );
    }

    #[test]
    fn test_status_ref_to_owned() {
        let status_ref = StatusRef {
            status_code: StatusCodeRef {
                value: STATUS_RESPONDER,
                sub_status: Some(Box::new(StatusCodeRef {
                    value: STATUS_AUTHN_FAILED,
                    sub_status: None,
                })),
            },
            status_message: Some("Authentication failed"),
            status_detail: None,
        };
        assert!(!status_ref.is_success());
        let owned = status_ref.to_owned();
        assert_eq!(owned.status_code.value, STATUS_RESPONDER);
        assert_eq!(
            owned.status_message.as_deref(),
            Some("Authentication failed")
        );
    }

    #[test]
    fn test_status_requester() {
        let status = Status::requester(Some("bad request".to_string()));
        assert!(!status.is_success());
        assert_eq!(status.status_code.value, STATUS_REQUESTER);
        assert_eq!(status.status_message.as_deref(), Some("bad request"));
    }

    #[test]
    fn test_status_responder() {
        let status = Status::responder(None);
        assert!(!status.is_success());
        assert_eq!(status.status_code.value, STATUS_RESPONDER);
        assert!(status.status_message.is_none());
    }

    #[test]
    fn test_status_with_sub_status() {
        let status = Status::with_sub_status(
            STATUS_RESPONDER,
            STATUS_AUTHN_FAILED,
            Some("authn failed".to_string()),
        );
        assert!(!status.is_success());
        assert_eq!(status.status_code.value, STATUS_RESPONDER);
        assert_eq!(
            status.status_code.sub_status.as_ref().unwrap().value,
            STATUS_AUTHN_FAILED
        );
        assert_eq!(status.status_message.as_deref(), Some("authn failed"));
    }

    #[test]
    fn test_status_code_requester() {
        let code = StatusCode::requester();
        assert!(!code.is_success());
        assert_eq!(code.value, STATUS_REQUESTER);
        assert!(code.sub_status.is_none());
    }

    #[test]
    fn test_status_code_responder() {
        let code = StatusCode::responder();
        assert!(!code.is_success());
        assert_eq!(code.value, STATUS_RESPONDER);
        assert!(code.sub_status.is_none());
    }
}
