// SAML 2.0 Security validation library
//
// Comprehensive security validation for SAML assertions and responses.
// Implements the 32-check validation checklist per the specification.
//
// Key errata implemented:
// - E14: AllowCreate = create OR associate
// - E46: AudienceRestriction - OR within, AND across
// - E78: Persistent IDs never reassigned
// - E79: SessionNotOnOrAfter = upper bound
// - E81: Any signature algorithm supported
// - E90: RelayState XSS/CSRF sanitization
// - E91: Reject ds:Object in signatures
// - E92: Clock skew 3-5 min configurable
// - E93: CBC needs integrity, prefer GCM

pub mod audience;
pub mod clock;
pub mod conditions;
pub mod config;
pub mod destination;
pub mod error;
pub mod name_id;
pub mod recipient;
pub mod relay_state;
pub mod replay;
pub mod signature;
pub mod validation;

// Re-exports for convenience
pub use config::SecurityConfig;
pub use error::{SecurityError, ValidationCheck, ValidationResult};
pub use replay::{InMemoryReplayCache, ReplayCache};
pub use validation::{AssertionValidator, ValidationParams};
