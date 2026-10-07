// XML-DSig algorithm choices for signing a response, and the per-SP preference
// that resolves to one.
//
// An IdP signs with RSA-SHA256 and a SHA-256 digest unless told otherwise. An
// SP can advertise the algorithms it supports in its metadata
// (`alg:SigningMethod` / `alg:DigestMethod`), and an IdP often wants to honour
// that - but only within a set it already considers acceptable. These types
// keep that set closed: the enums below are the only algorithms gamlastan will
// put into a signature template, and `SigningPreference::resolve` never picks
// something outside the IdP's own list.

/// A signature algorithm gamlastan will emit in a `<ds:SignatureMethod>`.
///
/// Deliberately limited to SHA-2 based RSA PKCS#1 v1.5 and ECDSA. SHA-1, MD5,
/// RIPEMD-160 and the rest are not representable, so no configuration or peer
/// advertisement can select them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignatureMethod {
    /// `rsa-sha256`
    RsaSha256,
    /// `rsa-sha384`
    RsaSha384,
    /// `rsa-sha512`
    RsaSha512,
    /// `ecdsa-sha256`
    EcdsaSha256,
    /// `ecdsa-sha384`
    EcdsaSha384,
    /// `ecdsa-sha512`
    EcdsaSha512,
}

impl SignatureMethod {
    /// The XML-DSig algorithm URI.
    pub fn uri(self) -> &'static str {
        match self {
            SignatureMethod::RsaSha256 => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            SignatureMethod::RsaSha384 => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
            SignatureMethod::RsaSha512 => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
            SignatureMethod::EcdsaSha256 => "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
            SignatureMethod::EcdsaSha384 => "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384",
            SignatureMethod::EcdsaSha512 => "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512",
        }
    }

    /// The method for an algorithm URI, or `None` if gamlastan does not emit it
    /// (including every weak or unknown algorithm).
    pub fn from_uri(uri: &str) -> Option<Self> {
        [
            SignatureMethod::RsaSha256,
            SignatureMethod::RsaSha384,
            SignatureMethod::RsaSha512,
            SignatureMethod::EcdsaSha256,
            SignatureMethod::EcdsaSha384,
            SignatureMethod::EcdsaSha512,
        ]
        .into_iter()
        .find(|m| m.uri() == uri)
    }
}

/// A digest algorithm gamlastan will emit in a `<ds:DigestMethod>`. SHA-2 only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DigestMethod {
    /// SHA-256
    Sha256,
    /// SHA-384
    Sha384,
    /// SHA-512
    Sha512,
}

impl DigestMethod {
    /// The XML-DSig algorithm URI.
    pub fn uri(self) -> &'static str {
        match self {
            DigestMethod::Sha256 => "http://www.w3.org/2001/04/xmlenc#sha256",
            DigestMethod::Sha384 => "http://www.w3.org/2001/04/xmldsig-more#sha384",
            DigestMethod::Sha512 => "http://www.w3.org/2001/04/xmlenc#sha512",
        }
    }

    /// The method for an algorithm URI, or `None` if gamlastan does not emit it
    /// (including SHA-1 and every unknown algorithm).
    pub fn from_uri(uri: &str) -> Option<Self> {
        [
            DigestMethod::Sha256,
            DigestMethod::Sha384,
            DigestMethod::Sha512,
        ]
        .into_iter()
        .find(|m| m.uri() == uri)
    }
}

/// The algorithms for one signing operation. `None` means "the signer's
/// default" (RSA-SHA256 for a key-backed signer, the token's algorithm for an
/// HSM signer; SHA-256 for the digest).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SigningAlgorithms {
    /// Signature method override.
    pub signature: Option<SignatureMethod>,
    /// Digest method override.
    pub digest: Option<DigestMethod>,
}

/// An IdP's ordered preference for signature and digest algorithms, resolved
/// per response against what the SP advertises.
///
/// For each kind the first entry the SP also advertises wins; if the SP
/// advertises none of them (or nothing at all), the first entry wins. An empty
/// list leaves that kind at the signer's default.
///
/// # HSM-backed signers
///
/// An HSM token can sign with only its own algorithm, and a response resolved to
/// any other signature method fails with an error (denials included), for
/// that SP only. So with an HSM list **only the token's signature method**, or
/// leave the signature list empty: an entry the token cannot produce breaks
/// every SP that advertises nothing if it is listed first, and every SP that
/// advertises it otherwise. Digest methods are not affected. The check happens
/// when a response is signed, not at startup.
///
/// # Security
///
/// The SP's advertisement is an **untrusted** claim copied from its metadata.
/// It only ever chooses *among the IdP's own entries*: it can never add an
/// algorithm, and an SP that advertises only weak algorithms just gets the
/// IdP's first choice. Because the lists hold [`SignatureMethod`] and
/// [`DigestMethod`], weak algorithms cannot be configured either.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SigningPreference {
    signature: Vec<SignatureMethod>,
    digest: Vec<DigestMethod>,
}

impl SigningPreference {
    /// An empty preference: signer defaults for both.
    pub fn new() -> Self {
        Self::default()
    }

    /// Signature methods, most preferred first.
    pub fn with_signature_methods(mut self, methods: Vec<SignatureMethod>) -> Self {
        self.signature = methods;
        self
    }

    /// Digest methods, most preferred first.
    pub fn with_digest_methods(mut self, methods: Vec<DigestMethod>) -> Self {
        self.digest = methods;
        self
    }

    /// Resolve against the algorithm URIs an SP advertises in its metadata:
    /// `alg:SigningMethod` URIs for the signature, `alg:DigestMethod` URIs for
    /// the digest. Each kind is matched only against its own list, so a URI
    /// the SP placed under the wrong element does not count.
    pub fn resolve(
        &self,
        sp_signature_methods: &[String],
        sp_digest_methods: &[String],
    ) -> SigningAlgorithms {
        fn pick<T: Copy>(
            preferred: &[T],
            uri: impl Fn(T) -> &'static str,
            advertised: &[String],
        ) -> Option<T> {
            preferred
                .iter()
                .copied()
                .find(|m| advertised.iter().any(|a| a == uri(*m)))
                .or_else(|| preferred.first().copied())
        }
        SigningAlgorithms {
            signature: pick(&self.signature, SignatureMethod::uri, sp_signature_methods),
            digest: pick(&self.digest, DigestMethod::uri, sp_digest_methods),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    impl SigningPreference {
        /// Resolve against one mixed list, standing in for both kinds.
        fn resolve_flat(&self, all: &[String]) -> SigningAlgorithms {
            self.resolve(all, all)
        }
    }

    fn adv(uris: &[&str]) -> Vec<String> {
        uris.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn uris_round_trip() {
        for m in [
            SignatureMethod::RsaSha256,
            SignatureMethod::RsaSha384,
            SignatureMethod::RsaSha512,
            SignatureMethod::EcdsaSha256,
            SignatureMethod::EcdsaSha384,
            SignatureMethod::EcdsaSha512,
        ] {
            assert_eq!(SignatureMethod::from_uri(m.uri()), Some(m));
        }
        for m in [
            DigestMethod::Sha256,
            DigestMethod::Sha384,
            DigestMethod::Sha512,
        ] {
            assert_eq!(DigestMethod::from_uri(m.uri()), Some(m));
        }
    }

    #[test]
    fn weak_and_unknown_algorithms_are_not_representable() {
        for uri in [
            "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
            "http://www.w3.org/2001/04/xmldsig-more#rsa-md5",
            "http://www.w3.org/2001/04/xmldsig-more#rsa-ripemd160",
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha224",
            "urn:evil",
            "",
        ] {
            assert_eq!(SignatureMethod::from_uri(uri), None, "{uri}");
        }
        for uri in [
            "http://www.w3.org/2000/09/xmldsig#sha1",
            "http://www.w3.org/2001/04/xmldsig-more#sha224",
            "urn:evil",
            "",
        ] {
            assert_eq!(DigestMethod::from_uri(uri), None, "{uri}");
        }
    }

    #[test]
    fn an_empty_preference_leaves_the_signer_default() {
        let resolved =
            SigningPreference::new().resolve_flat(&adv(&[SignatureMethod::RsaSha512.uri()]));
        assert_eq!(resolved, SigningAlgorithms::default());
    }

    #[test]
    fn the_first_preference_the_sp_also_advertises_wins() {
        let pref = SigningPreference::new()
            .with_signature_methods(vec![
                SignatureMethod::RsaSha512,
                SignatureMethod::RsaSha384,
                SignatureMethod::RsaSha256,
            ])
            .with_digest_methods(vec![DigestMethod::Sha512, DigestMethod::Sha256]);
        let resolved = pref.resolve_flat(&adv(&[
            SignatureMethod::RsaSha256.uri(),
            SignatureMethod::RsaSha384.uri(),
            DigestMethod::Sha256.uri(),
        ]));
        assert_eq!(resolved.signature, Some(SignatureMethod::RsaSha384));
        assert_eq!(resolved.digest, Some(DigestMethod::Sha256));
    }

    #[test]
    fn an_sp_advertising_nothing_usable_gets_the_idps_first_choice() {
        let pref = SigningPreference::new()
            .with_signature_methods(vec![SignatureMethod::RsaSha512, SignatureMethod::RsaSha256])
            .with_digest_methods(vec![DigestMethod::Sha512]);
        for advertised in [
            adv(&[]),
            adv(&["http://www.w3.org/2000/09/xmldsig#rsa-sha1"]),
            adv(&["urn:evil"]),
        ] {
            let resolved = pref.resolve_flat(&advertised);
            assert_eq!(resolved.signature, Some(SignatureMethod::RsaSha512));
            assert_eq!(resolved.digest, Some(DigestMethod::Sha512));
        }
    }

    #[test]
    fn the_sp_cannot_add_an_algorithm_the_idp_did_not_list() {
        // The IdP only accepts SHA-256; the SP advertises SHA-512 (and weak
        // SHA-1). The advertisement picks among the IdP's entries only.
        let pref = SigningPreference::new()
            .with_signature_methods(vec![SignatureMethod::RsaSha256])
            .with_digest_methods(vec![DigestMethod::Sha256]);
        let resolved = pref.resolve_flat(&adv(&[
            SignatureMethod::RsaSha512.uri(),
            DigestMethod::Sha512.uri(),
            "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        ]));
        assert_eq!(resolved.signature, Some(SignatureMethod::RsaSha256));
        assert_eq!(resolved.digest, Some(DigestMethod::Sha256));
    }

    #[test]
    fn a_uri_under_the_wrong_advertisement_does_not_count() {
        let pref = SigningPreference::new()
            .with_signature_methods(vec![SignatureMethod::RsaSha512, SignatureMethod::RsaSha256])
            .with_digest_methods(vec![DigestMethod::Sha512, DigestMethod::Sha256]);
        // The SP lists the signature URIs only as digest methods and vice
        // versa: neither kind has a usable advertisement, so each falls back
        // to the IdP's first choice rather than the swapped entries.
        let resolved = pref.resolve(
            &adv(&[DigestMethod::Sha256.uri()]),
            &adv(&[SignatureMethod::RsaSha256.uri()]),
        );
        assert_eq!(resolved.signature, Some(SignatureMethod::RsaSha512));
        assert_eq!(resolved.digest, Some(DigestMethod::Sha512));
        // Correctly placed, they are honoured.
        let resolved = pref.resolve(
            &adv(&[SignatureMethod::RsaSha256.uri()]),
            &adv(&[DigestMethod::Sha256.uri()]),
        );
        assert_eq!(resolved.signature, Some(SignatureMethod::RsaSha256));
        assert_eq!(resolved.digest, Some(DigestMethod::Sha256));
    }
}
