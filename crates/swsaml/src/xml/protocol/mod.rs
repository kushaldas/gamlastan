// SamlDeserialize and SamlSerialize implementations for protocol types.
//
// Covers: StatusCode, Status, AuthnRequest, Response,
//         LogoutRequest, LogoutResponse,
//         ArtifactResolve, ArtifactResponse,
//         ManageNameIdRequest, ManageNameIdResponse,
//         NameIdMappingRequest, NameIdMappingResponse,
//         AssertionIdRequest, AuthnQuery, AttributeQuery, AuthzDecisionQuery.

pub mod deserialize;
pub mod serialize;
