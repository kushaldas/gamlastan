// gamlastan crypto configuration types.
//
// Defines algorithm preferences and security policy for SAML crypto operations.

/// Algorithm preferences and security policy for SAML operations.
///
/// These defaults follow SAML errata recommendations:
/// - E81: algorithm support is extensible, while verification applies a local policy
/// - E91: reject signatures containing ds:Object elements
/// - E93: prefer GCM modes over CBC for built-in integrity protection
#[derive(Debug, Clone)]
pub struct CryptoConfig {
    /// Preferred signature algorithm URI for signing operations.
    /// Default: RSA-SHA256.
    pub preferred_signature_algorithm: String,

    /// Preferred digest algorithm URI.
    /// Default: SHA-256.
    pub preferred_digest_algorithm: String,

    /// Preferred encryption algorithm URI for data encryption.
    /// Default: AES-256-GCM (per E93: prefer GCM for integrity).
    pub preferred_encryption_algorithm: String,

    /// Preferred key wrap algorithm URI.
    /// Default: AES-256-KW.
    pub preferred_key_wrap_algorithm: String,

    /// Whether to reject signatures containing ds:Object elements (per E91).
    /// Default: true.
    pub reject_ds_object: bool,

    /// Minimum HMAC output length (in bits) to prevent truncation attacks
    /// (CVE-2009-0217). Default: 160 bits.
    pub hmac_min_output_length: usize,

    /// Require every XML-DSig reference digest to be verified locally.
    /// Default: true.
    pub require_reference_digests: bool,

    /// Allow raw inline KeyValue / DEREncodedKeyValue signatures even when
    /// trust anchors are configured. Default: false.
    pub allow_raw_inline_keyinfo_with_trust_anchors: bool,

    /// Maximum XML Encryption PBKDF2 iterations accepted from XML-controlled
    /// parameters. Default matches bergshamra.
    pub max_pbkdf2_iterations: u32,
}

/// Local allowlist for algorithms accepted while verifying SAML signatures.
///
/// The default permits RSA and ECDSA signatures with SHA-256, SHA-384, or
/// SHA-512, and reference digests with SHA-256, SHA-384, or SHA-512. This is a
/// SAML policy layered above bergshamra: the lower-level XML-DSig library keeps
/// its broader algorithm support for xmlsec interoperability tests.
///
/// Use [`AlgorithmPolicy::permissive`] only for explicit legacy or non-SAML
/// interoperability. HMAC remains independently prohibited by
/// [`SamlVerifier`](crate::crypto::SamlVerifier) unless its HMAC guard is also
/// disabled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlgorithmPolicy {
    // None means backend-compatible/unrestricted. Some(empty) intentionally
    // denies every algorithm rather than acting as an accidental opt-out.
    allowed_signature_algorithms: Option<Vec<String>>,
    allowed_digest_algorithms: Option<Vec<String>>,
}

impl Default for AlgorithmPolicy {
    fn default() -> Self {
        use bergshamra_core::algorithm;

        Self::allow_only(
            [
                algorithm::RSA_SHA256,
                algorithm::RSA_SHA384,
                algorithm::RSA_SHA512,
                algorithm::ECDSA_SHA256,
                algorithm::ECDSA_SHA384,
                algorithm::ECDSA_SHA512,
            ],
            [algorithm::SHA256, algorithm::SHA384, algorithm::SHA512],
        )
    }
}

impl AlgorithmPolicy {
    /// Construct the secure default SAML algorithm policy.
    pub fn new() -> Self {
        Self::default()
    }

    /// Accept any signature and digest algorithm supported by bergshamra.
    ///
    /// This preserves the old verification behavior for legacy XML security
    /// interoperability. It is not recommended for production SAML deployments.
    pub fn permissive() -> Self {
        Self {
            allowed_signature_algorithms: None,
            allowed_digest_algorithms: None,
        }
    }

    /// Construct a policy containing exactly the supplied allowlists.
    ///
    /// Empty iterators deny all algorithms of the corresponding kind.
    pub fn allow_only<S, D, SI, DI>(signature_algorithms: S, digest_algorithms: D) -> Self
    where
        S: IntoIterator<Item = SI>,
        D: IntoIterator<Item = DI>,
        SI: Into<String>,
        DI: Into<String>,
    {
        Self {
            allowed_signature_algorithms: Some(
                signature_algorithms.into_iter().map(Into::into).collect(),
            ),
            allowed_digest_algorithms: Some(
                digest_algorithms.into_iter().map(Into::into).collect(),
            ),
        }
    }

    /// Replace the signature algorithm allowlist.
    ///
    /// An empty iterator denies every signature algorithm.
    pub fn with_signature_algorithms<I, T>(mut self, algorithms: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        self.allowed_signature_algorithms = Some(algorithms.into_iter().map(Into::into).collect());
        self
    }

    /// Replace the reference digest algorithm allowlist.
    ///
    /// An empty iterator denies every reference digest algorithm.
    pub fn with_digest_algorithms<I, T>(mut self, algorithms: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        self.allowed_digest_algorithms = Some(algorithms.into_iter().map(Into::into).collect());
        self
    }

    /// Return the signature allowlist, or `None` for backend-compatible mode.
    pub fn allowed_signature_algorithms(&self) -> Option<&[String]> {
        self.allowed_signature_algorithms.as_deref()
    }

    /// Return the reference digest allowlist, or `None` for backend-compatible mode.
    pub fn allowed_digest_algorithms(&self) -> Option<&[String]> {
        self.allowed_digest_algorithms.as_deref()
    }

    /// Return whether a signature method URI is accepted by this policy.
    pub fn allows_signature_algorithm(&self, uri: &str) -> bool {
        self.allowed_signature_algorithms
            .as_ref()
            .is_none_or(|allowed| allowed.iter().any(|candidate| candidate == uri))
    }

    /// Return whether a reference digest method URI is accepted by this policy.
    pub fn allows_digest_algorithm(&self, uri: &str) -> bool {
        self.allowed_digest_algorithms
            .as_ref()
            .is_none_or(|allowed| allowed.iter().any(|candidate| candidate == uri))
    }

    pub(crate) fn is_permissive(&self) -> bool {
        self.allowed_signature_algorithms.is_none() && self.allowed_digest_algorithms.is_none()
    }
}

impl Default for CryptoConfig {
    fn default() -> Self {
        CryptoConfig {
            preferred_signature_algorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
                .to_string(),
            preferred_digest_algorithm: "http://www.w3.org/2001/04/xmlenc#sha256".to_string(),
            preferred_encryption_algorithm: "http://www.w3.org/2009/xmlenc11#aes256-gcm"
                .to_string(),
            preferred_key_wrap_algorithm: "http://www.w3.org/2001/04/xmlenc#kw-aes256".to_string(),
            reject_ds_object: true,
            hmac_min_output_length: 160,
            require_reference_digests: true,
            allow_raw_inline_keyinfo_with_trust_anchors: false,
            max_pbkdf2_iterations: bergshamra_enc::context::DEFAULT_MAX_PBKDF2_ITERATIONS,
        }
    }
}

impl CryptoConfig {
    /// Create a new CryptoConfig with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a configuration that prefers RSA-SHA256 signing.
    pub fn rsa_sha256() -> Self {
        Self::default()
    }

    /// Create a configuration that prefers ECDSA-P256-SHA256 signing.
    pub fn ecdsa_p256_sha256() -> Self {
        CryptoConfig {
            preferred_signature_algorithm: "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
                .to_string(),
            ..Self::default()
        }
    }
}
