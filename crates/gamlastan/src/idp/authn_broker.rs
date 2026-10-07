// AuthnBroker: map a RequestedAuthnContext to registered authentication
// methods (pysaml2 `AuthnBroker` equivalent).
//
// Methods are registered with an AuthnContext class ref, an opaque
// method identifier (URL, handler name, ...) and a numeric security
// level. `pick()` honors the request's Comparison attribute:
// - exact:   methods whose class ref is literally one of the requested
//            ones (saml-core-2.0-os 3.3.2.2.1), unless
//            `AuthnBroker::allow_exact_level_matching` restores pysaml2's looser,
//            level-based "exact" (see that method's docs)
// - minimum: methods at that level or higher
// - maximum: methods at that level or lower
// - better:  methods at a strictly higher level
//
// Minimum/maximum/better matching is level-based across *all* registered
// methods, seeded by the level registered for the requested class ref —
// pysaml2 semantics.

use crate::core::constants;
use crate::core::protocol::request::{AuthnContextComparison, RequestedAuthnContext};

/// A registered authentication method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthnMethod {
    /// The AuthnContext class ref this method satisfies.
    pub class_ref: String,
    /// Opaque identifier of the authentication mechanism
    /// (e.g. a login URL or handler name).
    pub method: String,
    /// Security level; higher is stronger, 0 is lowest.
    pub level: u32,
    /// The authenticating authority to report, if not this IdP.
    pub authn_authority: Option<String>,
    /// Unique reference for this registration.
    pub reference: String,
}

/// The broker (pysaml2 `AuthnBroker`).
#[derive(Debug, Default)]
pub struct AuthnBroker {
    methods: Vec<AuthnMethod>,
    next: usize,
    /// pysaml2-compatibility switch for `exact` matching. Default `false`
    /// (the secure, spec-compliant default): per saml-core-2.0-os
    /// 3.3.2.2.1, `Comparison="exact"` requires the resulting AuthnContext
    /// to be a literal match of one of the requested class refs, not just
    /// registered at the same security level. pysaml2's own `AuthnBroker`
    /// (and gamlastan's, before this switch) instead broadens "exact" to
    /// every method at the same level as the requested class, which can
    /// hand back — and let the orchestrator accept — a class ref the SP
    /// never listed. Set `true` to restore that looser pysaml2 behaviour.
    allow_exact_level_matching: bool,
}

impl AuthnBroker {
    /// Create an empty broker.
    pub fn new() -> Self {
        AuthnBroker::default()
    }

    /// Whether no method is registered.
    pub fn is_empty(&self) -> bool {
        self.methods.is_empty()
    }

    /// Restore pysaml2's looser `exact` semantics (matching by security
    /// level rather than literal class-ref membership). See
    /// [`AuthnBroker`]'s field docs for why the default (`false`) differs
    /// from pysaml2.
    pub fn allow_exact_level_matching(mut self, enable: bool) -> Self {
        self.allow_exact_level_matching = enable;
        self
    }

    /// Register an authentication method; returns its unique reference.
    pub fn add(
        &mut self,
        class_ref: impl Into<String>,
        method: impl Into<String>,
        level: u32,
        authn_authority: Option<&str>,
    ) -> String {
        self.next += 1;
        let reference = self.next.to_string();
        self.methods.push(AuthnMethod {
            class_ref: class_ref.into(),
            method: method.into(),
            level,
            authn_authority: authn_authority.map(str::to_string),
            reference: reference.clone(),
        });
        reference
    }

    /// Register with a caller-chosen reference; fails when the reference
    /// is already taken.
    pub fn add_with_reference(
        &mut self,
        class_ref: impl Into<String>,
        method: impl Into<String>,
        level: u32,
        authn_authority: Option<&str>,
        reference: impl Into<String>,
    ) -> Result<(), String> {
        let reference = reference.into();
        if self.methods.iter().any(|m| m.reference == reference) {
            return Err(format!("reference is not unique: {reference}"));
        }
        self.methods.push(AuthnMethod {
            class_ref: class_ref.into(),
            method: method.into(),
            level,
            authn_authority: authn_authority.map(str::to_string),
            reference,
        });
        Ok(())
    }

    /// Look up a method by its reference (pysaml2 `broker[ref]`).
    pub fn get(&self, reference: &str) -> Option<&AuthnMethod> {
        self.methods.iter().find(|m| m.reference == reference)
    }

    /// The first method registered for a class ref
    /// (pysaml2 `get_authn_by_accr`).
    pub fn get_by_class_ref(&self, class_ref: &str) -> Option<&AuthnMethod> {
        self.methods.iter().find(|m| m.class_ref == class_ref)
    }

    fn satisfies(comparison: AuthnContextComparison, base: u32, level: u32) -> bool {
        match comparison {
            AuthnContextComparison::Exact => level == base,
            AuthnContextComparison::Minimum => level >= base,
            AuthnContextComparison::Maximum => level <= base,
            AuthnContextComparison::Better => level > base,
        }
    }

    fn pick_by_class_ref(
        &self,
        class_ref: &str,
        comparison: AuthnContextComparison,
    ) -> Vec<&AuthnMethod> {
        let same_class: Vec<&AuthnMethod> = self
            .methods
            .iter()
            .filter(|m| m.class_ref == class_ref)
            .collect();
        if same_class.is_empty() {
            return vec![];
        }

        // Per saml-core-2.0-os 3.3.2.2.1, "exact" requires a literal match
        // of one of the requested class refs - not "same security level as
        // some method registered under that class ref", which is what the
        // level-threshold walk below computes. Skip it entirely unless
        // pysaml2 compat is requested.
        if comparison == AuthnContextComparison::Exact && !self.allow_exact_level_matching {
            return same_class;
        }

        // Seed level: the strongest level satisfying the comparison among
        // the methods registered for the requested class.
        let mut base = same_class[0].level;
        for m in &same_class[1..] {
            if Self::satisfies(comparison, base, m.level) {
                base = m.level;
            }
        }

        let mut result: Vec<&AuthnMethod> = Vec::new();
        // For "better" the requested class itself never qualifies.
        if comparison != AuthnContextComparison::Better {
            result.extend(same_class.iter().copied());
        }
        for m in &self.methods {
            if m.class_ref == class_ref {
                continue;
            }
            if Self::satisfies(comparison, base, m.level) && !result.contains(&m) {
                result.push(m);
            }
        }
        result
    }

    /// Find the authentication methods satisfying a request
    /// (pysaml2 `pick()`), in the request's class-ref order and, within one
    /// ref, registration order. This is **not** sorted by strength: a weaker
    /// method registered first is returned first. [`check_request`](crate::idp::orchestrator::check_request)
    /// sorts its `Authenticate` methods strongest first, so use that if the
    /// first entry should be the strongest.
    ///
    /// With no RequestedAuthnContext the `unspecified` class is matched
    /// with `minimum` comparison. If no `unspecified` method is registered
    /// there is no baseline to compare against, and since nothing was
    /// requested every registered method qualifies, so all are returned (in
    /// registration order).
    pub fn pick(&self, requested: Option<&RequestedAuthnContext>) -> Vec<&AuthnMethod> {
        let Some(req) = requested else {
            let picked = self.pick_by_class_ref(
                constants::AUTHN_CONTEXT_UNSPECIFIED,
                AuthnContextComparison::Minimum,
            );
            if picked.is_empty() {
                return self.methods.iter().collect();
            }
            return picked;
        };

        // The listed refs are alternatives (saml-core-2.0-os 3.3.2.2.1:
        // "one of the authentication contexts specified"), for every
        // comparison: a method qualifies if it satisfies any of them. The
        // result keeps the request's order, so earlier refs are preferred.
        let comparison = req.comparison;
        let refs = if !req.authn_context_class_refs.is_empty() {
            &req.authn_context_class_refs
        } else {
            &req.authn_context_decl_refs
        };
        let mut result: Vec<&AuthnMethod> = Vec::new();
        for class_ref in refs {
            for m in self.pick_by_class_ref(class_ref, comparison) {
                if !result.contains(&m) {
                    result.push(m);
                }
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn requested(class_refs: &[&str], comparison: AuthnContextComparison) -> RequestedAuthnContext {
        RequestedAuthnContext {
            authn_context_class_refs: class_refs.iter().map(|s| s.to_string()).collect(),
            authn_context_decl_refs: vec![],
            comparison,
        }
    }

    fn broker() -> AuthnBroker {
        let mut b = AuthnBroker::new();
        b.add(constants::AUTHN_CONTEXT_UNSPECIFIED, "/login/any", 0, None);
        b.add(
            constants::AUTHN_CONTEXT_PASSWORD,
            "/login/password",
            1,
            None,
        );
        b.add(
            constants::AUTHN_CONTEXT_PASSWORD_PROTECTED_TRANSPORT,
            "/login/ppt",
            2,
            None,
        );
        b.add(constants::AUTHN_CONTEXT_X509, "/login/cert", 3, None);
        b
    }

    #[test]
    fn test_exact_match() {
        let b = broker();
        let picked = b.pick(Some(&requested(
            &[constants::AUTHN_CONTEXT_PASSWORD],
            AuthnContextComparison::Exact,
        )));
        assert_eq!(picked.len(), 1);
        assert_eq!(picked[0].method, "/login/password");
    }

    #[test]
    fn test_exact_excludes_same_level_other_class_by_default() {
        // Per saml-core-2.0-os 3.3.2.2.1, "exact" must be a literal match of
        // a requested class ref: a method at the same security level but a
        // different, unrequested class ref must not be offered.
        let mut b = broker();
        b.add("urn:example:otp", "/login/otp", 2, None);
        let picked = b.pick(Some(&requested(
            &[constants::AUTHN_CONTEXT_PASSWORD_PROTECTED_TRANSPORT],
            AuthnContextComparison::Exact,
        )));
        let methods: Vec<_> = picked.iter().map(|m| m.method.as_str()).collect();
        assert_eq!(methods, vec!["/login/ppt"]);
    }

    #[test]
    fn test_exact_includes_same_level_other_class_with_pysaml2_compat() {
        // The opt-in restores pysaml2's own (spec-noncompliant) broadening.
        let mut b = broker().allow_exact_level_matching(true);
        b.add("urn:example:otp", "/login/otp", 2, None);
        let picked = b.pick(Some(&requested(
            &[constants::AUTHN_CONTEXT_PASSWORD_PROTECTED_TRANSPORT],
            AuthnContextComparison::Exact,
        )));
        let methods: Vec<_> = picked.iter().map(|m| m.method.as_str()).collect();
        assert_eq!(methods, vec!["/login/ppt", "/login/otp"]);
    }

    #[test]
    fn test_minimum_includes_stronger() {
        let b = broker();
        let picked = b.pick(Some(&requested(
            &[constants::AUTHN_CONTEXT_PASSWORD],
            AuthnContextComparison::Minimum,
        )));
        let methods: Vec<_> = picked.iter().map(|m| m.method.as_str()).collect();
        assert_eq!(
            methods,
            vec!["/login/password", "/login/ppt", "/login/cert"]
        );
    }

    #[test]
    fn test_maximum_includes_weaker() {
        let b = broker();
        let picked = b.pick(Some(&requested(
            &[constants::AUTHN_CONTEXT_PASSWORD_PROTECTED_TRANSPORT],
            AuthnContextComparison::Maximum,
        )));
        let methods: Vec<_> = picked.iter().map(|m| m.method.as_str()).collect();
        assert_eq!(methods, vec!["/login/ppt", "/login/any", "/login/password"]);
    }

    #[test]
    fn test_better_strictly_stronger_excludes_requested() {
        let b = broker();
        let picked = b.pick(Some(&requested(
            &[constants::AUTHN_CONTEXT_PASSWORD],
            AuthnContextComparison::Better,
        )));
        let methods: Vec<_> = picked.iter().map(|m| m.method.as_str()).collect();
        assert_eq!(methods, vec!["/login/ppt", "/login/cert"]);
    }

    #[test]
    fn every_listed_class_ref_is_an_alternative_for_every_comparison() {
        let b = broker();
        let unknown = "urn:example:unknown";
        for comparison in [
            AuthnContextComparison::Exact,
            AuthnContextComparison::Minimum,
            AuthnContextComparison::Maximum,
            AuthnContextComparison::Better,
        ] {
            // An unknown first ref must not hide a satisfiable second one.
            let single = b.pick(Some(&requested(
                &[constants::AUTHN_CONTEXT_PASSWORD],
                comparison,
            )));
            let listed = b.pick(Some(&requested(
                &[unknown, constants::AUTHN_CONTEXT_PASSWORD],
                comparison,
            )));
            assert_eq!(listed, single, "{comparison:?}");
        }
        // The union is deduplicated and keeps the request's order.
        let picked = b.pick(Some(&requested(
            &[
                constants::AUTHN_CONTEXT_X509,
                constants::AUTHN_CONTEXT_PASSWORD,
            ],
            AuthnContextComparison::Minimum,
        )));
        let methods: Vec<&str> = picked.iter().map(|m| m.method.as_str()).collect();
        assert_eq!(methods.first(), Some(&"/login/cert"));
        assert!(methods.contains(&"/login/password"));
        assert_eq!(
            methods.len(),
            methods
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len()
        );
    }

    #[test]
    fn test_no_request_defaults_to_unspecified_minimum() {
        let b = broker();
        let picked = b.pick(None);
        // unspecified at level 0, minimum: everything qualifies
        assert_eq!(picked.len(), 4);
        assert_eq!(picked[0].method, "/login/any");
    }

    #[test]
    fn no_request_without_an_unspecified_baseline_offers_every_method() {
        let mut b = AuthnBroker::new();
        b.add(
            constants::AUTHN_CONTEXT_PASSWORD,
            "/login/password",
            1,
            None,
        );
        b.add(constants::AUTHN_CONTEXT_X509, "/login/cert", 3, None);
        let picked = b.pick(None);
        let methods: Vec<&str> = picked.iter().map(|m| m.method.as_str()).collect();
        assert_eq!(methods, ["/login/password", "/login/cert"]);
        // Nothing registered stays empty.
        assert!(AuthnBroker::new().pick(None).is_empty());
    }

    #[test]
    fn test_unknown_class_ref_empty() {
        let b = broker();
        let picked = b.pick(Some(&requested(
            &["urn:example:unknown"],
            AuthnContextComparison::Exact,
        )));
        assert!(picked.is_empty());
    }

    #[test]
    fn test_exact_multiple_class_refs_concatenated() {
        let b = broker();
        let picked = b.pick(Some(&requested(
            &[
                constants::AUTHN_CONTEXT_PASSWORD,
                constants::AUTHN_CONTEXT_X509,
            ],
            AuthnContextComparison::Exact,
        )));
        let methods: Vec<_> = picked.iter().map(|m| m.method.as_str()).collect();
        assert_eq!(methods, vec!["/login/password", "/login/cert"]);
    }

    #[test]
    fn test_duplicate_reference_rejected() {
        let mut b = AuthnBroker::new();
        b.add_with_reference("a", "m1", 0, None, "ref1").unwrap();
        assert!(b.add_with_reference("b", "m2", 0, None, "ref1").is_err());
        assert_eq!(b.get("ref1").unwrap().method, "m1");
    }

    #[test]
    fn test_authn_authority_carried() {
        let mut b = AuthnBroker::new();
        b.add("a", "m", 1, Some("https://upstream.example.com"));
        let m = b.get_by_class_ref("a").unwrap();
        assert_eq!(
            m.authn_authority.as_deref(),
            Some("https://upstream.example.com")
        );
    }
}
