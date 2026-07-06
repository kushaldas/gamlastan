//! SAML 2.0 security validation.
//!
//! This module contains the checks that must run before an SP or proxy trusts
//! claims from a SAML response: destination and recipient matching, audience
//! restrictions, assertion time windows, replay detection, signature provenance,
//! RelayState sanitization, persistent identifier reassignment checks, and
//! related SAML errata.
//!
//! # What This Module Does
//!
//! [`AssertionValidator`] evaluates a response and records every applicable
//! check in a [`ValidationResult`]. It does not short-circuit after the first
//! failure, so callers can log a full diagnostic set while still treating any
//! failed required check as a rejected response.
//!
//! Signature cryptography itself is performed by [`crate::crypto`]. Pass the
//! verified signed IDs and response-signature status into
//! [`validation::ValidationParams`] so this layer can bind those cryptographic
//! facts to the assertion/response you are about to consume.
//!
//! # Key Errata and Defaults
//!
//! - E14: `AllowCreate` means create or associate.
//! - E46: audience restrictions are OR within one restriction and AND across
//!   multiple restrictions.
//! - E78: persistent IDs must not be reassigned.
//! - E79: `SessionNotOnOrAfter` is an upper bound.
//! - E90: RelayState is length-limited and sanitized.
//! - E91: signatures containing `ds:Object` are rejected.
//! - E92: clock skew is configurable; the default is 180 seconds.
//! - E93: CBC-mode encryption requires integrity protection.
//!
//! # Example: Configure a Validator
//!
//! ```
//! use gamlastan::security::{AssertionValidator, InMemoryReplayCache, SecurityConfig};
//!
//! let config = SecurityConfig::new();
//! let replay_cache = InMemoryReplayCache::new();
//! let validator = AssertionValidator::new(&config)
//!     .with_replay_cache(&replay_cache);
//!
//! assert_eq!(config.clock_skew_seconds, 180);
//! # let _ = validator;
//! ```
//!
//! # Deployment Notes
//!
//! Use [`SecurityConfig::strict`] for deployments that require signed responses,
//! signed assertions, encrypted assertions, and client address checks. The
//! in-memory replay cache is suitable for a single process; distributed SPs and
//! proxies should implement [`ReplayCache`] over shared storage so assertion IDs
//! cannot be replayed across instances.

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
