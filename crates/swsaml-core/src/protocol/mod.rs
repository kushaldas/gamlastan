// Protocol module - SAML 2.0 protocol message types

pub mod artifact;
pub mod logout;
pub mod name_id_mapping;
pub mod name_id_mgmt;
pub mod query;
pub mod request;
pub mod response;
pub mod status;

// Re-exports
pub use artifact::{ArtifactResolve, ArtifactResolveRef, ArtifactResponse, ArtifactResponseRef};
pub use logout::{LogoutRequest, LogoutRequestRef, LogoutResponse, LogoutResponseRef};
pub use name_id_mapping::{
    NameIdMappingRequest, NameIdMappingRequestRef, NameIdMappingResponse, NameIdMappingResponseRef,
};
pub use name_id_mgmt::{
    ManageNameIdRequest, ManageNameIdRequestRef, ManageNameIdResponse, ManageNameIdResponseRef,
};
pub use query::{
    AssertionIdRequest, AssertionIdRequestRef, AttributeQuery, AttributeQueryRef, AuthnQuery,
    AuthnQueryRef, AuthzDecisionQuery, AuthzDecisionQueryRef,
};
pub use request::{
    AuthnRequest, AuthnRequestRef, RequestBase, RequestBaseRef, RequestedAuthnContext,
    RequestedAuthnContextRef, Scoping, ScopingRef,
};
pub use response::{Response, ResponseBase, ResponseBaseRef, ResponseRef};
pub use status::{Status, StatusCode, StatusCodeRef, StatusRef};
