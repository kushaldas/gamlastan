// AuthnBroker: map a RequestedAuthnContext to registered authentication
// methods (pysaml2 `AuthnBroker` equivalent).
//
// Methods are registered with an AuthnContext class ref, an opaque
// method identifier (URL, handler name, ...) and a numeric security
// level. `pick()` honors the request's Comparison attribute:
// - exact:   methods at exactly the level of the requested class
// - minimum: methods at that level or higher
// - maximum: methods at that level or lower
// - better:  methods at a strictly higher level
//
// Matching is level-based across *all* registered methods, seeded by the
// level registered for the requested class ref — pysaml2 semantics.

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
}

impl AuthnBroker {
    /// Create an empty broker.
    pub fn new() -> Self {
        AuthnBroker::default()
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
    /// (pysaml2 `pick()`), strongest preference first.
    ///
    /// With no RequestedAuthnContext the `unspecified` class is matched
    /// with `minimum` comparison.
    pub fn pick(&self, requested: Option<&RequestedAuthnContext>) -> Vec<&AuthnMethod> {
        let Some(req) = requested else {
            return self.pick_by_class_ref(
                constants::AUTHN_CONTEXT_UNSPECIFIED,
                AuthnContextComparison::Minimum,
            );
        };

        let comparison = req.comparison;
        if !req.authn_context_class_refs.is_empty() {
            if comparison == AuthnContextComparison::Exact {
                let mut result: Vec<&AuthnMethod> = Vec::new();
                for class_ref in &req.authn_context_class_refs {
                    for m in self.pick_by_class_ref(class_ref, comparison) {
                        if !result.contains(&m) {
                            result.push(m);
                        }
                    }
                }
                result
            } else {
                self.pick_by_class_ref(&req.authn_context_class_refs[0], comparison)
            }
        } else if !req.authn_context_decl_refs.is_empty() {
            self.pick_by_class_ref(&req.authn_context_decl_refs[0], comparison)
        } else {
            vec![]
        }
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
    fn test_exact_includes_same_level_other_class() {
        let mut b = broker();
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
    fn test_no_request_defaults_to_unspecified_minimum() {
        let b = broker();
        let picked = b.pick(None);
        // unspecified at level 0, minimum: everything qualifies
        assert_eq!(picked.len(), 4);
        assert_eq!(picked[0].method, "/login/any");
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
