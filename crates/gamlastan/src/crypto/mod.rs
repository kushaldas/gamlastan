//! # gamlastan::crypto
//!
//! Cryptographic abstraction layer for SAML 2.0, backed by `bergshamra`.
//!
//! This crate wraps the bergshamra XML security library to provide SAML-specific
//! operations including:
//!
//! - **Signing** - Enveloped XML-DSig signatures for assertions, responses, and metadata
//! - **Verification** - XML-DSig signature verification with E91 ds:Object rejection
//! - **Encryption** - XML Encryption for EncryptedAssertion, EncryptedID, EncryptedAttribute
//! - **Decryption** - XML Decryption of encrypted SAML elements
//! - **Digest** - Hash computation for artifact SourceID and reference digests
//! - **Key management** - SAML-specific key manager builders
//! - **Canonicalization** - Re-exported C14N from bergshamra
//! - **Configuration** - Algorithm preferences and security policy
//!
//! ## Errata Compliance
//!
//! - **E81**: Any algorithm supported by bergshamra is allowed
//! - **E91**: Reject signatures containing `<ds:Object>` elements
//! - **E93**: Prefer GCM modes over CBC for built-in integrity protection

pub mod config;
pub mod decryptor;
pub mod digest;
pub mod encryptor;
pub mod error;
pub mod keys;
pub mod signer;
pub mod verifier;

// Re-export the primary types for convenience.
pub use config::CryptoConfig;
pub use decryptor::SamlDecryptor;
pub use encryptor::SamlEncryptor;
pub use error::CryptoError;
pub use signer::SamlSigner;
pub use verifier::SamlVerifier;

// Re-export bergshamra types needed by consumers.
pub use bergshamra_c14n::{self, C14nMode};
pub use bergshamra_dsig::{VerifiedReference, VerifyResult};
pub use bergshamra_keys::{build_x509_key_info, build_x509_key_info_from_der};
pub use bergshamra_keys::{Key, KeyData, KeyUsage, KeysManager};

/// Re-exported canonicalization function from bergshamra.
///
/// Used for HTTP Redirect binding signature construction and metadata signing.
pub fn canonicalize(
    xml: &str,
    mode: C14nMode,
    inclusive_prefixes: &[String],
) -> Result<Vec<u8>, CryptoError> {
    Ok(bergshamra_c14n::canonicalize(
        xml,
        mode,
        None,
        inclusive_prefixes,
    )?)
}

/// Convenience: exclusive canonicalization (the most common mode for SAML).
pub fn exc_c14n(xml: &str, inclusive_prefixes: &[String]) -> Result<Vec<u8>, CryptoError> {
    canonicalize(xml, C14nMode::Exclusive, inclusive_prefixes)
}
