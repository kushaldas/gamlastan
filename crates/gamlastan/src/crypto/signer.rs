// gamlastan crypto signer - SAML signing operations wrapping bergshamra::dsig.

use std::sync::Arc;

use bergshamra_dsig::{sign::sign, DsigContext};
use bergshamra_keys::{KeyUsage, KeysManager};
use kryptering::{SignatureAlgorithm, Signer};

use crate::crypto::error::CryptoError;

const DEFAULT_SIGNATURE_METHOD_URI: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

/// SAML-specific signer that wraps bergshamra's XML Digital Signature support.
///
/// Provides two signing modes:
/// - Enveloped signature: for signing assertions, responses, and metadata
/// - Redirect query signature: detached signature for HTTP Redirect binding
///
/// ## File-based vs HSM-backed signing
///
/// By default ([`new`](Self::new)) the private key lives in the [`KeysManager`]
/// (loaded from a PEM file). For HSM / PKCS#11 deployments, construct the signer
/// with [`with_hsm_signer`](Self::with_hsm_signer): the private key then never
/// leaves the token and every signing operation is delegated to the HSM.
///
/// When an HSM signer is set:
/// - **Enveloped path** — bergshamra-dsig bypasses the `KeysManager` for the
///   signature and, crucially, also skips populating `<ds:KeyInfo>`. The X.509
///   certificate that lands in `<KeyInfo>` therefore has to be carried by the
///   signature *template* (which is how `gamlastan-actix::signature_template`
///   already works — it embeds `cert_b64`). The `KeysManager` passed here may be
///   empty in that case.
/// - **Redirect path** — the detached signature is produced by calling the HSM
///   signer directly over the raw query-string bytes; the `KeysManager` is not
///   consulted.
pub struct SamlSigner {
    keys_manager: KeysManager,
    /// Optional HSM/PKCS#11-backed signer. When present, all signing is
    /// delegated to it and `keys_manager` is used only as a fallback container
    /// (it is not consulted for the cryptographic operation itself).
    hsm_signer: Option<Arc<dyn Signer>>,
}

/// Adapter that lets a shared `Arc<dyn Signer>` be handed to bergshamra-dsig,
/// whose [`DsigContext::with_hsm_signer`] consumes a fresh `Box<dyn Signer>` per
/// call. Cloning the `Arc` is cheap and keeps a single token session alive.
struct SharedSigner(Arc<dyn Signer>);

impl Signer for SharedSigner {
    fn algorithm(&self) -> SignatureAlgorithm {
        self.0.algorithm()
    }

    fn sign(&self, data: &[u8]) -> kryptering::Result<Vec<u8>> {
        self.0.sign(data)
    }
}

impl SamlSigner {
    /// Create a new file-based SAML signer with the given key manager.
    pub fn new(keys_manager: KeysManager) -> Self {
        Self {
            keys_manager,
            hsm_signer: None,
        }
    }

    /// Create an HSM-backed SAML signer.
    ///
    /// The `signer` is any [`kryptering::Signer`] — typically a
    /// `kryptering::pkcs11::Pkcs11Signer` bound to a private key on a PKCS#11
    /// token (SoftHSM2, a network HSM, Kryoptic, etc.). The private key never
    /// leaves the token.
    ///
    /// `keys_manager` may be empty when the signature template already carries
    /// the certificate (the common case — see the type-level docs); pass a
    /// cert-bearing manager only if you rely on dsig auto-populating an empty
    /// `<ds:X509Certificate/>`, which it does **not** do on the HSM path.
    ///
    /// ```no_run
    /// # use std::sync::Arc;
    /// # use std::path::Path;
    /// use gamlastan::crypto::{KeysManager, SamlSigner};
    /// use kryptering::pkcs11::{Pkcs11Provider, Pkcs11Signer};
    /// use kryptering::SignatureAlgorithm;
    ///
    /// let provider = Pkcs11Provider::new(Path::new("/usr/lib/softhsm/libsofthsm2.so"))?;
    /// let session = provider.open_session("1234")?;
    /// let pkcs11_signer = Pkcs11Signer::new(
    ///     &session,
    ///     "saml-signing-key",
    ///     SignatureAlgorithm::RsaPkcs1v15(kryptering::HashAlgorithm::Sha256),
    /// )?;
    ///
    /// // The KeysManager can be empty: the cert comes from the signature template.
    /// let signer = SamlSigner::with_hsm_signer(KeysManager::new(), Arc::new(pkcs11_signer));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn with_hsm_signer(keys_manager: KeysManager, signer: Arc<dyn Signer>) -> Self {
        Self {
            keys_manager,
            hsm_signer: Some(signer),
        }
    }

    /// Returns `true` if this signer delegates to an HSM/PKCS#11 backend.
    pub fn is_hsm_backed(&self) -> bool {
        self.hsm_signer.is_some()
    }

    /// Return the XML-DSig `SignatureMethod` URI to place in a signature template.
    ///
    /// File-based signing keeps the existing actix behavior of defaulting to
    /// RSA-SHA256. HSM-backed signing derives the URI from the token signer's
    /// configured algorithm so the template cannot advertise a mismatched
    /// `SignatureMethod`.
    pub fn signature_method_uri(&self) -> Result<&'static str, CryptoError> {
        if let Some(signer) = &self.hsm_signer {
            return bergshamra_crypto::sign::kryptering_algorithm_uri(signer.algorithm())
                .ok_or_else(|| {
                    CryptoError::UnsupportedAlgorithm(
                        "No XML-DSig SignatureMethod URI mapping exists for the configured HSM signer algorithm".to_string(),
                    )
                });
        }

        Ok(DEFAULT_SIGNATURE_METHOD_URI)
    }

    /// Sign a SAML message with an enveloped signature.
    ///
    /// The input XML must contain an empty `<ds:Signature>` template element
    /// specifying the desired signature algorithm and canonicalization method.
    /// Returns the signed XML string with the populated signature.
    ///
    /// Used for: assertion signing, response signing, metadata signing.
    ///
    /// When this signer is HSM-backed, the template must also already contain
    /// the `<ds:X509Certificate>` content, because bergshamra-dsig does not
    /// populate `<ds:KeyInfo>` from the `KeysManager` on the HSM path.
    pub fn sign_enveloped(&self, xml_with_template: &str) -> Result<String, CryptoError> {
        let mut ctx = DsigContext::new(self.keys_manager.clone());
        if let Some(signer) = &self.hsm_signer {
            ctx = ctx.with_hsm_signer(Box::new(SharedSigner(Arc::clone(signer))));
        }
        let signed = sign(&ctx, xml_with_template)?;
        Ok(signed)
    }

    /// Sign bytes for HTTP Redirect binding (detached signature).
    ///
    /// This creates a signature over the query string bytes using the specified
    /// algorithm, as required by the SAML HTTP Redirect binding.
    ///
    /// The query string must be constructed as:
    /// `SAMLRequest=value&RelayState=value&SigAlg=value` (URL-encoded values).
    ///
    /// When this signer is HSM-backed the signature is produced on the token.
    /// The HSM signer's configured algorithm is cross-checked against
    /// `algorithm_uri` (the `SigAlg` the message will advertise) so the emitted
    /// `SigAlg` can never disagree with the mechanism actually used — mirroring
    /// the guard bergshamra-dsig applies on the enveloped path.
    pub fn sign_redirect_query(
        &self,
        query_string: &[u8],
        algorithm_uri: &str,
    ) -> Result<Vec<u8>, CryptoError> {
        if let Some(signer) = &self.hsm_signer {
            let declared = bergshamra_crypto::sign::kryptering_algorithm_uri(signer.algorithm());
            if declared != Some(algorithm_uri) {
                return Err(CryptoError::UnsupportedAlgorithm(format!(
                    "HSM signer algorithm (SigAlg {}) does not match requested SigAlg {}",
                    declared.unwrap_or("<unmapped>"),
                    algorithm_uri,
                )));
            }
            return signer
                .sign(query_string)
                .map_err(|e| CryptoError::HsmError(e.to_string()));
        }

        let sig_alg = bergshamra_crypto::sign::from_uri(algorithm_uri)
            .map_err(CryptoError::BergshamraError)?;
        let key = self
            .keys_manager
            .find_by_usage(KeyUsage::Sign)
            .ok_or_else(|| CryptoError::KeyNotFound("No signing key found".to_string()))?;
        let signing_key = key.to_signing_key().ok_or_else(|| {
            CryptoError::KeyNotFound("Key cannot be used for signing".to_string())
        })?;
        let signature = sig_alg
            .sign(&signing_key, query_string)
            .map_err(CryptoError::BergshamraError)?;
        Ok(signature)
    }

    /// Get a reference to the underlying keys manager.
    pub fn keys_manager(&self) -> &KeysManager {
        &self.keys_manager
    }
}
