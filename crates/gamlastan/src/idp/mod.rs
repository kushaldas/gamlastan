//! IdP-side server infrastructure.
//!
//! The [`profiles::sso::idp`](crate::profiles::sso::idp) module builds and
//! signs protocol messages. This module contains the stateful and policy-driven
//! pieces an IdP needs around those messages:
//!
//! - [`policy`] - per-SP attribute release, assertion lifetime, NameID format,
//!   and signing target decisions;
//! - [`entity_category`] - shipped REFEDS/SWAMID/eduGAIN/InCommon/CoCo release
//!   rules keyed on SP metadata entity categories;
//! - [`ident`] - NameID generation and storage, including transient and
//!   persistent identifiers plus ManageNameID/NameIDMapping semantics;
//! - [`eptid`] - deterministic `eduPersonTargetedID` generation, including a
//!   guarded PySAML2 MD5 migration mode;
//! - [`authn_broker`] - matching `RequestedAuthnContext` against available
//!   authentication methods;
//! - [`assertion_store`] - storing issued assertions so back-channel
//!   AssertionIDRequest and AuthnQuery messages can be answered.
//!
//! # Deployment Model
//!
//! The in-memory stores are correct for tests and single-process examples, but
//! production IdPs that run more than one process should implement
//! [`IdentityStore`] and [`AssertionStore`] over shared storage such as Redis,
//! SQL, or another durable backend. The policy and matching logic are
//! independent of that storage choice.
//!
//! # Attribute Release Example
//!
//! ```
//! use gamlastan::core::assertion::attribute::{Attribute, AttributeValue};
//! use gamlastan::idp::entity_category::SubjectIdReq;
//! use gamlastan::idp::{PolicyEntry, ReleasePolicy};
//!
//! let default_entry = PolicyEntry::new()
//!     .with_attribute_restrictions(&[("mail", None)])?;
//! let policy = ReleasePolicy::with_default(default_entry);
//!
//! let attributes = vec![
//!     Attribute {
//!         name: "mail".to_string(),
//!         name_format: None,
//!         friendly_name: None,
//!         values: vec![AttributeValue::String("alice@example.org".to_string())],
//!     },
//!     Attribute {
//!         name: "displayName".to_string(),
//!         name_format: None,
//!         friendly_name: None,
//!         values: vec![AttributeValue::String("Alice Example".to_string())],
//!     },
//! ];
//!
//! let released = policy.filter(
//!     attributes,
//!     "https://sp.example.org/metadata",
//!     &[],
//!     &[],
//!     &[],
//!     SubjectIdReq::None,
//! )?;
//!
//! assert_eq!(released.len(), 1);
//! assert_eq!(released[0].name, "mail");
//!
//! # Ok::<(), gamlastan::idp::PolicyError>(())
//! ```
//!
//! # Identifier Example
//!
//! ```
//! use gamlastan::idp::Eptid;
//!
//! let eptid = Eptid::new("deployment-secret");
//! let name_id = eptid.name_id(
//!     "https://idp.example.org/metadata",
//!     "https://sp.example.org/metadata",
//!     "alice",
//! );
//!
//! assert_eq!(
//!     name_id.sp_name_qualifier.as_deref(),
//!     Some("https://sp.example.org/metadata")
//! );
//! ```

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
