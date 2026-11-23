// gamlastan crypto transform policy - which Reference transforms and URIs a
// SAML signature may use.

use bergshamra_core::algorithm;

/// How a signature's `Reference/@URI` may address its target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReferenceUris {
    /// A same-document reference only: the empty URI (the document root) or
    /// `#id`. This is what SAML signatures use. XPointer expressions
    /// (`#xpointer(...)`), external URIs, schemes and file names are refused
    /// before the verifier reads anything.
    SameDocument,
    /// Any URI bergshamra can resolve, including relative file names resolved
    /// against the working directory. For explicit non-SAML interoperability.
    Any,
}

/// Local policy for the `Reference` elements of a signature, checked before the
/// verifier processes them.
///
/// SAML Core 5.4 limits a signature to a same-document reference with an
/// enveloped-signature transform and exclusive canonicalization. The XML-DSig
/// verifier underneath (bergshamra) is a general library and supports many more
/// transforms, including XPath filters that can narrow what a signature covers,
/// and it can read a relative file named by a `Reference URI`. A reference
/// whose URI points at the signed element still passes a check that only looks
/// at the URI and the digest. This policy closes that gap, in the same place and
/// with the same shape as [`AlgorithmPolicy`](crate::crypto::AlgorithmPolicy).
///
/// The default ([`TransformPolicy::saml`]) allows only `enveloped-signature` and
/// exclusive canonicalization (with and without comments) as transforms,
/// same-document reference URIs, and at most 8 references and 8 transforms per
/// reference. Use [`TransformPolicy::permissive`] only for explicit legacy or
/// non-SAML interoperability, or widen the default with the `with_*` builders.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransformPolicy {
    // None means unrestricted. Some(empty) denies every transform.
    allowed_transforms: Option<Vec<String>>,
    reference_uris: ReferenceUris,
    require_single_reference: bool,
    max_references: Option<usize>,
    max_transforms_per_reference: Option<usize>,
}

/// Default limit on `Reference` elements per signature and on `Transform`
/// elements per reference. SAML uses one reference with two transforms.
const DEFAULT_LIMIT: usize = 8;

impl Default for TransformPolicy {
    fn default() -> Self {
        Self::saml()
    }
}

impl TransformPolicy {
    /// The SAML profile: `enveloped-signature` and exclusive canonicalization
    /// (with and without comments), same-document reference URIs, and generous
    /// limits. This is the default.
    pub fn saml() -> Self {
        Self {
            allowed_transforms: Some(vec![
                algorithm::ENVELOPED_SIGNATURE.to_string(),
                algorithm::EXC_C14N.to_string(),
                algorithm::EXC_C14N_WITH_COMMENTS.to_string(),
            ]),
            reference_uris: ReferenceUris::SameDocument,
            require_single_reference: false,
            max_references: Some(DEFAULT_LIMIT),
            max_transforms_per_reference: Some(DEFAULT_LIMIT),
        }
    }

    /// Accept any transform and reference URI bergshamra supports, with no
    /// limits. This preserves the old verification behavior and is not
    /// recommended for production SAML deployments.
    pub fn permissive() -> Self {
        Self {
            allowed_transforms: None,
            reference_uris: ReferenceUris::Any,
            require_single_reference: false,
            max_references: None,
            max_transforms_per_reference: None,
        }
    }

    /// Replace the transform allowlist with exactly the supplied algorithm
    /// URIs. An empty iterator denies every transform. Order and duplicates are
    /// ignored.
    pub fn with_transforms<I, T>(mut self, transforms: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        let mut transforms: Vec<String> = transforms.into_iter().map(Into::into).collect();
        transforms.sort_unstable();
        transforms.dedup();
        self.allowed_transforms = Some(transforms);
        self
    }

    /// Allow any transform (the transform allowlist is lifted; the URI rule and
    /// the limits are unchanged).
    pub fn with_any_transform(mut self) -> Self {
        self.allowed_transforms = None;
        self
    }

    /// Set how a `Reference/@URI` may address its target.
    pub fn with_reference_uris(mut self, reference_uris: ReferenceUris) -> Self {
        self.reference_uris = reference_uris;
        self
    }

    /// Require exactly one `Reference` per signature (SAML Core 5.4.2).
    /// Off by default: the request or assertion binding already needs one
    /// reference that covers the message.
    pub fn with_require_single_reference(mut self, require: bool) -> Self {
        self.require_single_reference = require;
        self
    }

    /// Set the maximum number of `Reference` elements per signature, or `None`
    /// for no limit.
    pub fn with_max_references(mut self, max: Option<usize>) -> Self {
        self.max_references = max;
        self
    }

    /// Set the maximum number of `Transform` elements per reference, or `None`
    /// for no limit.
    pub fn with_max_transforms_per_reference(mut self, max: Option<usize>) -> Self {
        self.max_transforms_per_reference = max;
        self
    }

    /// The transform allowlist, or `None` when any transform is accepted.
    pub fn allowed_transforms(&self) -> Option<&[String]> {
        self.allowed_transforms.as_deref()
    }

    /// How a `Reference/@URI` may address its target.
    pub fn reference_uris(&self) -> ReferenceUris {
        self.reference_uris
    }

    /// Whether exactly one `Reference` is required per signature.
    pub fn requires_single_reference(&self) -> bool {
        self.require_single_reference
    }

    /// Return whether a transform algorithm URI is accepted by this policy.
    pub fn allows_transform(&self, uri: &str) -> bool {
        self.allowed_transforms
            .as_ref()
            .is_none_or(|allowed| allowed.iter().any(|candidate| candidate == uri))
    }

    /// Return whether a `Reference/@URI` value is accepted by this policy.
    ///
    /// Under [`ReferenceUris::SameDocument`] that is the empty URI or `#` plus
    /// an identifier. A fragment that is an XPointer expression
    /// (`#xpointer(...)`) is not accepted.
    pub fn allows_reference_uri(&self, uri: &str) -> bool {
        match self.reference_uris {
            ReferenceUris::Any => true,
            ReferenceUris::SameDocument => {
                uri.is_empty()
                    || uri
                        .strip_prefix('#')
                        .is_some_and(|id| !id.is_empty() && !id.contains('('))
            }
        }
    }

    pub(crate) fn max_references(&self) -> Option<usize> {
        self.max_references
    }

    pub(crate) fn max_transforms_per_reference(&self) -> Option<usize> {
        self.max_transforms_per_reference
    }

    pub(crate) fn is_permissive(&self) -> bool {
        *self == Self::permissive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_is_the_saml_profile() {
        let policy = TransformPolicy::default();
        assert_eq!(policy, TransformPolicy::saml());
        for uri in [
            algorithm::ENVELOPED_SIGNATURE,
            algorithm::EXC_C14N,
            algorithm::EXC_C14N_WITH_COMMENTS,
        ] {
            assert!(policy.allows_transform(uri), "{uri}");
        }
        for uri in [
            algorithm::XPATH,
            algorithm::XPATH2,
            algorithm::XSLT,
            algorithm::BASE64,
            algorithm::C14N,
            algorithm::C14N_WITH_COMMENTS,
        ] {
            assert!(!policy.allows_transform(uri), "{uri}");
        }
    }

    #[test]
    fn same_document_uris_are_empty_or_a_fragment_id() {
        let policy = TransformPolicy::saml();
        for uri in ["", "#_req1", "#a"] {
            assert!(policy.allows_reference_uri(uri), "{uri:?}");
        }
        for uri in [
            "#",
            "#xpointer(id('x'))",
            "#xpointer(/)",
            "Cargo.toml",
            "../Cargo.toml",
            "/etc/hostname",
            "cid:attachment",
            "https://example.test/doc.xml#_req1",
            "file:///etc/hostname",
        ] {
            assert!(!policy.allows_reference_uri(uri), "{uri:?}");
        }
    }

    #[test]
    fn permissive_accepts_everything_and_is_recognized_as_permissive() {
        let policy = TransformPolicy::permissive();
        assert!(policy.is_permissive());
        assert!(!TransformPolicy::saml().is_permissive());
        assert!(policy.allows_transform(algorithm::XPATH));
        assert!(policy.allows_reference_uri("Cargo.toml"));
        assert_eq!(policy.max_references(), None);
        assert_eq!(policy.max_transforms_per_reference(), None);
    }

    #[test]
    fn builders_adjust_one_setting_at_a_time() {
        let widened = TransformPolicy::saml().with_transforms([
            algorithm::ENVELOPED_SIGNATURE,
            algorithm::EXC_C14N,
            algorithm::C14N,
        ]);
        assert!(widened.allows_transform(algorithm::C14N));
        assert!(!widened.allows_transform(algorithm::XPATH));
        assert!(!widened.allows_reference_uri("Cargo.toml"));

        let none = TransformPolicy::saml().with_transforms(Vec::<String>::new());
        assert!(!none.allows_transform(algorithm::ENVELOPED_SIGNATURE));

        let any = TransformPolicy::saml().with_any_transform();
        assert!(any.allows_transform(algorithm::XPATH));
        assert!(!any.allows_reference_uri("Cargo.toml"));
        assert!(!any.is_permissive());

        let files = TransformPolicy::saml().with_reference_uris(ReferenceUris::Any);
        assert!(files.allows_reference_uri("Cargo.toml"));
        assert!(!files.allows_transform(algorithm::XPATH));
    }
}
