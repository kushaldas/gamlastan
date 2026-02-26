// swsaml-crypto keys - SAML key management re-exports and helpers.
//
// Re-exports bergshamra key types and provides SAML-specific key builder functions.

use bergshamra_keys::{KeyUsage, KeysManager};

use crate::crypto::error::CryptoError;

// Re-export the key types that consumers of swsaml-crypto need.
pub use bergshamra_crypto::sign::SigningKey;
pub use bergshamra_keys::{self, loader, KeyData};

/// Build a KeysManager for a SAML Service Provider.
///
/// Sets up the key manager with:
/// - The SP's private key for signing requests
/// - The IdP's certificate for verifying signatures
pub fn build_sp_keys_manager(
    private_key_pem: &[u8],
    idp_certificate_pem: &[u8],
) -> Result<KeysManager, CryptoError> {
    let mut km = KeysManager::new();

    // SP's signing key
    let sp_key =
        loader::load_pem_auto(private_key_pem, None).map_err(CryptoError::BergshamraError)?;
    let mut sp_key = sp_key;
    sp_key.usage = KeyUsage::Sign;
    km.add_key(sp_key);

    // IdP's verification certificate (trusted)
    km.add_trusted_cert(idp_certificate_pem.to_vec());

    Ok(km)
}

/// Build a KeysManager for a SAML Identity Provider.
///
/// Sets up the key manager with:
/// - The IdP's private key for signing assertions and responses
/// - Optionally, SP certificates for encryption
pub fn build_idp_keys_manager(private_key_pem: &[u8]) -> Result<KeysManager, CryptoError> {
    let mut km = KeysManager::new();

    // IdP's signing key
    let idp_key =
        loader::load_pem_auto(private_key_pem, None).map_err(CryptoError::BergshamraError)?;
    let mut idp_key = idp_key;
    idp_key.usage = KeyUsage::Sign;
    km.add_key(idp_key);

    Ok(km)
}
