// IdP-side server infrastructure.
//
// These modules cover what pysaml2's `Server` class provides beyond
// message construction:
// - `policy`: per-SP attribute release policy engine
// - `entity_category`: shipped federation release policies (REFEDS R&S,
//   CoCo v1/v2, eduGAIN, SWAMID, InCommon, AT eGov)
// - `ident`: identity database — NameID generation/management, ManageNameID
//   and NameIDMapping server-side semantics
// - `eptid`: deterministic eduPersonTargetedID generation
// - `authn_broker`: RequestedAuthnContext -> authentication method matching
// - `assertion_store`: issued-assertion store serving AssertionIDRequest
//   and AuthnQuery

pub mod assertion_store;
pub mod authn_broker;
pub mod entity_category;
pub mod eptid;
pub mod ident;
pub mod policy;

pub use assertion_store::{AssertionStore, InMemoryAssertionStore};
pub use authn_broker::{AuthnBroker, AuthnMethod};
pub use eptid::Eptid;
pub use ident::{IdentDb, IdentError, IdentityStore, InMemoryIdentityStore};
pub use policy::{PolicyEntry, PolicyError, ReleasePolicy, SignTargets};
