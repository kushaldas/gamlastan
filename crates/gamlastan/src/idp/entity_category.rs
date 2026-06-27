// Entity-category attribute release policies (ported from pysaml2).
//
// Each federation module ships release rules keyed on entity-category URIs
// (as published in the SP's metadata `mdattr:EntityAttributes` under
// `http://macedir.org/entity-category`). A rule releases its attribute list
// when *all* of its category URIs are present on the SP; the empty category
// list means "always released".
//
// Rule modifiers (per pysaml2):
// - `only_required`: release only the subset of the list the SP also marks
//   as required in its AttributeConsumingService (CoCo semantics).
// - `conflicts`: the rule does *not* match if any of these category URIs is
//   also present on the SP. This is how the REFEDS Access categories
//   (personalized / pseudonymous / anonymous) are expressed: each may be
//   combined with *other* categories (R&S, CoCo, …), and if an SP publishes
//   multiple access categories the most restrictive declared rule wins.
//   pysaml2 introduced this `required` + `conflicts` matcher on its
//   `ft-typing` / `ft-refeds_ec` branches after finding that the previous
//   "replace the accumulated set" model could not express these categories
//   (commit 04f841cb temporarily disabled them). See ADR 0014.

use std::collections::HashSet;

/// A single release rule.
#[derive(Debug, Clone, Copy)]
pub struct EntityCategoryRule {
    /// Category URIs that must *all* be present on the SP. Empty = always.
    pub categories: &'static [&'static str],
    /// Local (friendly) attribute names released by this rule.
    pub attributes: &'static [&'static str],
    /// Category URIs that must *not* be present on the SP for this rule to
    /// match (pysaml2's `EntityCategoryMatcher.conflicts`).
    pub conflicts: &'static [&'static str],
    /// Release only attributes the SP also requires (CoCo).
    pub only_required: bool,
}

impl EntityCategoryRule {
    /// Whether this rule matches the SP's set of entity categories: every
    /// `categories` URI present and no `conflicts` URI present
    /// (pysaml2 `EntityCategoryMatcher.matches`).
    fn matches(&self, sp_categories: &HashSet<&str>) -> bool {
        if self.conflicts.iter().any(|c| sp_categories.contains(c)) {
            return false;
        }
        self.categories.iter().all(|c| sp_categories.contains(c))
    }
}

/// A federation's set of release rules.
#[derive(Debug, Clone, Copy)]
pub struct EntityCategoryPolicy {
    /// Short name of the policy (e.g. `"swamid"`).
    pub name: &'static str,
    /// The rules, evaluated in order.
    pub rules: &'static [EntityCategoryRule],
}

impl EntityCategoryRule {
    /// Clone this static rule into an owned, runtime-mutable
    /// [`OwnedEntityCategoryRule`].
    pub fn as_owned(&self) -> OwnedEntityCategoryRule {
        OwnedEntityCategoryRule {
            categories: self.categories.iter().map(|s| s.to_string()).collect(),
            attributes: self.attributes.iter().map(|s| s.to_string()).collect(),
            conflicts: self.conflicts.iter().map(|s| s.to_string()).collect(),
            only_required: self.only_required,
        }
    }
}

impl EntityCategoryPolicy {
    /// Clone this static policy into an owned, runtime-mutable
    /// [`OwnedEntityCategoryPolicy`] (e.g. to extend a shipped policy such as
    /// [`SWAMID`] with deployment-specific rules).
    pub fn as_owned(&self) -> OwnedEntityCategoryPolicy {
        OwnedEntityCategoryPolicy {
            name: self.name.to_string(),
            rules: self
                .rules
                .iter()
                .map(EntityCategoryRule::as_owned)
                .collect(),
        }
    }
}

/// Owned, runtime-constructible counterpart of [`EntityCategoryRule`].
///
/// The shipped rules and policies are `&'static` so they can live in `const`
/// data with zero allocation. Callers that need to define their *own* entity
/// categories at runtime - notably language bindings that receive the rule from
/// outside Rust - build this owned form instead. Matching and release semantics
/// are identical to [`EntityCategoryRule`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedEntityCategoryRule {
    /// Category URIs that must *all* be present on the SP. Empty = always.
    pub categories: Vec<String>,
    /// Local (friendly) attribute names released by this rule.
    pub attributes: Vec<String>,
    /// Category URIs that must *not* be present on the SP for this rule to match.
    pub conflicts: Vec<String>,
    /// Release only attributes the SP also requires (CoCo).
    pub only_required: bool,
}

impl OwnedEntityCategoryRule {
    /// A rule releasing `attributes` when all of `categories` are present.
    pub fn new(
        categories: impl IntoIterator<Item = impl Into<String>>,
        attributes: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        OwnedEntityCategoryRule {
            categories: categories.into_iter().map(Into::into).collect(),
            attributes: attributes.into_iter().map(Into::into).collect(),
            conflicts: Vec::new(),
            only_required: false,
        }
    }

    /// Set the conflicting categories (rule does not match if any is present).
    pub fn with_conflicts(
        mut self,
        conflicts: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.conflicts = conflicts.into_iter().map(Into::into).collect();
        self
    }

    /// Release only the subset of `attributes` the SP also marks as required.
    pub fn with_only_required(mut self, only_required: bool) -> Self {
        self.only_required = only_required;
        self
    }

    fn matches(&self, sp_categories: &HashSet<&str>) -> bool {
        if self
            .conflicts
            .iter()
            .any(|c| sp_categories.contains(c.as_str()))
        {
            return false;
        }
        self.categories
            .iter()
            .all(|c| sp_categories.contains(c.as_str()))
    }
}

/// Owned, runtime-constructible counterpart of [`EntityCategoryPolicy`].
///
/// Build one with [`OwnedEntityCategoryPolicy::new`] plus
/// [`OwnedEntityCategoryPolicy::with_rule`], or start from a shipped policy via
/// [`EntityCategoryPolicy::as_owned`] and append rules. Evaluate with
/// [`releasable_attributes_owned`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OwnedEntityCategoryPolicy {
    /// Short name of the policy (e.g. `"swamid-local"`).
    pub name: String,
    /// The rules, evaluated in order.
    pub rules: Vec<OwnedEntityCategoryRule>,
}

impl OwnedEntityCategoryPolicy {
    /// An empty policy with the given name.
    pub fn new(name: impl Into<String>) -> Self {
        OwnedEntityCategoryPolicy {
            name: name.into(),
            rules: Vec::new(),
        }
    }

    /// Append a rule (builder form).
    pub fn with_rule(mut self, rule: OwnedEntityCategoryRule) -> Self {
        self.rules.push(rule);
        self
    }

    /// Append a rule (mutating form).
    pub fn push_rule(&mut self, rule: OwnedEntityCategoryRule) {
        self.rules.push(rule);
    }

    /// Append every rule from a shipped static policy, so a deployment can start
    /// from e.g. [`SWAMID`] and add its own categories on top.
    pub fn extend_from_static(mut self, policy: &EntityCategoryPolicy) -> Self {
        self.rules
            .extend(policy.rules.iter().map(EntityCategoryRule::as_owned));
        self
    }
}

// ── Category URIs ───────────────────────────────────────────────────────────

/// GÉANT Data Protection Code of Conduct v1.
pub const COCO_V1: &str = "http://www.geant.net/uri/dataprotection-code-of-conduct/v1";
/// REFEDS Data Protection Code of Conduct v2.
pub const COCO_V2: &str = "https://refeds.org/category/code-of-conduct/v2";
/// REFEDS Research & Scholarship.
pub const REFEDS_RESEARCH_AND_SCHOLARSHIP: &str =
    "http://refeds.org/category/research-and-scholarship";
/// InCommon Research & Scholarship.
pub const INCOMMON_RESEARCH_AND_SCHOLARSHIP: &str =
    "http://id.incommon.org/category/research-and-scholarship";
/// MyAcademicID European Student Identifier.
pub const MYACADEMICID_ESI: &str = "https://myacademicid.org/entity-categories/esi";
/// REFEDS Personalized Access.
pub const REFEDS_PERSONALIZED: &str = "https://refeds.org/category/personalized";
/// REFEDS Pseudonymous Access.
pub const REFEDS_PSEUDONYMOUS: &str = "https://refeds.org/category/pseudonymous";
/// REFEDS Anonymous Access.
pub const REFEDS_ANONYMOUS: &str = "https://refeds.org/category/anonymous";
/// SWAMID research-and-education (deprecated 2021-03-31).
pub const SWAMID_RESEARCH_AND_EDUCATION: &str =
    "http://www.swamid.se/category/research-and-education";
/// SWAMID SFS 1993:1153 (deprecated 2021-03-31).
pub const SWAMID_SFS_1993_1153: &str = "http://www.swamid.se/category/sfs-1993-1153";
/// SWAMID EU adequate protection (deprecated 2021-03-31).
pub const SWAMID_EU: &str = "http://www.swamid.se/category/eu-adequate-protection";
/// SWAMID NREN service (deprecated 2021-03-31).
pub const SWAMID_NREN: &str = "http://www.swamid.se/category/nren-service";
/// SWAMID HEI service (deprecated 2021-03-31).
pub const SWAMID_HEI: &str = "http://www.swamid.se/category/hei-service";
/// Austrian e-government PVP2 token.
pub const AT_EGOV_PVP2: &str = "http://www.ref.gv.at/ns/names/agiz/pvp/egovtoken";
/// Austrian e-government PVP2 charge token.
pub const AT_EGOV_PVP2_CHARGE: &str = "http://www.ref.gv.at/ns/names/agiz/pvp/egovtoken-charge";

// ── Subject identifier profile (subject-id / pairwise-id) ────────────────────

/// The `subject-id` attribute (OASIS Subject Identifiers profile).
pub const SUBJECT_ID_ATTR: &str = "urn:oasis:names:tc:SAML:attribute:subject-id";
/// The `pairwise-id` attribute (OASIS Subject Identifiers profile).
pub const PAIRWISE_ID_ATTR: &str = "urn:oasis:names:tc:SAML:attribute:pairwise-id";
/// The `subject-id:req` SP metadata entity attribute that declares which
/// subject identifier(s) an SP requests.
pub const SUBJECT_ID_REQ_ATTR: &str = "urn:oasis:names:tc:SAML:profiles:subject-id:req";

/// An SP's requested subject identifier, read from the `subject-id:req`
/// entity attribute in its metadata (pysaml2 `subject_id_requirement_type`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SubjectIdReq {
    /// No subject identifier requested: either no `subject-id:req` entity
    /// attribute was declared or the SP explicitly used the metadata value
    /// `none`.
    #[default]
    None,
    /// `subject-id` — only the non-pairwise subject identifier.
    SubjectId,
    /// `pairwise-id` — only the pairwise subject identifier.
    PairwiseId,
    /// `any` — either subject identifier is acceptable.
    Any,
}

impl SubjectIdReq {
    /// Parse the `subject-id:req` value as published in SP metadata. Unknown
    /// values (and the empty set) map to [`SubjectIdReq::None`]; the first
    /// recognized value wins, case-insensitively. The metadata value `none`
    /// also maps to [`SubjectIdReq::None`].
    pub fn from_metadata_values(values: &[String]) -> Self {
        for value in values {
            let normalized = value.trim().to_ascii_lowercase();
            match normalized.as_str() {
                "any" => return SubjectIdReq::Any,
                "none" => return SubjectIdReq::None,
                "subject-id" => return SubjectIdReq::SubjectId,
                "pairwise-id" => return SubjectIdReq::PairwiseId,
                _ => continue,
            }
        }
        SubjectIdReq::None
    }
}

/// pysaml2 PR #987 ("do not assert both subject-id and pairwise-id"): when an
/// SP requests subject-id with requirement `any` and *both* `subject-id` and
/// `pairwise-id` would be released, drop `subject-id` and keep only the more
/// privacy-preserving `pairwise-id`. Operates on the lowercased local-name
/// release set. This is intentionally scoped to `subject-id:req=any`; the
/// profile standardizes the metadata signal but does not define asserting-party
/// behavior for other values. See ADR 0015.
pub fn prefer_pairwise_over_subject_id(req: SubjectIdReq, released: &mut HashSet<String>) {
    if req != SubjectIdReq::Any {
        return;
    }
    if released.contains("pairwise-id") && released.contains("subject-id") {
        released.remove("subject-id");
    }
}

// ── Attribute lists ─────────────────────────────────────────────────────────

const COCO_V1_ATTRIBUTES: &[&str] = &[
    "eduPersonPrincipalName",
    "eduPersonScopedAffiliation",
    "eduPersonAffiliation",
    "mail",
    "displayName",
    "cn",
    "schacHomeOrganization",
];

const REFEDS_RS_ATTRIBUTES: &[&str] = &[
    "eduPersonPrincipalName",
    "eduPersonScopedAffiliation",
    "mail",
    "givenName",
    "sn",
    "displayName",
];

const SWAMID_NAME_ORG_OTHER: &[&str] = &[
    // NAME
    "givenName",
    "displayName",
    "sn",
    "cn",
    // STATIC_ORG_INFO
    "c",
    "o",
    "co",
    "norEduOrgAcronym",
    "schacHomeOrganization",
    "schacHomeOrganizationType",
    // OTHER
    "eduPersonPrincipalName",
    "eduPersonScopedAffiliation",
    "mail",
    "eduPersonAssurance",
];

const SWAMID_R_AND_S: &[&str] = &[
    "eduPersonPrincipalName",
    "eduPersonUniqueID",
    "mail",
    "displayName",
    "givenName",
    "sn",
    "eduPersonAssurance",
    "eduPersonScopedAffiliation",
];

const GEANT_COCO: &[&str] = &[
    "pairwise-id",
    "subject-id",
    "eduPersonTargetedID",
    "eduPersonPrincipalName",
    "eduPersonOrcid",
    "norEduPersonNIN",
    "personalIdentityNumber",
    "schacDateOfBirth",
    "mail",
    "mailLocalAddress",
    "displayName",
    "cn",
    "givenName",
    "sn",
    "norEduPersonLegalName",
    "eduPersonAssurance",
    "eduPersonScopedAffiliation",
    "eduPersonAffiliation",
    "o",
    "norEduOrgAcronym",
    "c",
    "co",
    "schacHomeOrganization",
    "schacHomeOrganizationType",
];

const ESI_ATTRIBUTES: &[&str] = &["schacPersonalUniqueCode"];

const ESI_AND_COCO: &[&str] = &[
    "schacPersonalUniqueCode",
    "pairwise-id",
    "subject-id",
    "eduPersonTargetedID",
    "eduPersonPrincipalName",
    "eduPersonOrcid",
    "norEduPersonNIN",
    "personalIdentityNumber",
    "schacDateOfBirth",
    "mail",
    "mailLocalAddress",
    "displayName",
    "cn",
    "givenName",
    "sn",
    "norEduPersonLegalName",
    "eduPersonAssurance",
    "eduPersonScopedAffiliation",
    "eduPersonAffiliation",
    "o",
    "norEduOrgAcronym",
    "c",
    "co",
    "schacHomeOrganization",
    "schacHomeOrganizationType",
];

const REFEDS_PERSONALIZED_ACCESS: &[&str] = &[
    "subject-id",
    "mail",
    "displayName",
    "givenName",
    "sn",
    "eduPersonScopedAffiliation",
    "eduPersonAssurance",
    "schacHomeOrganization",
];

const REFEDS_PSEUDONYMOUS_ACCESS: &[&str] = &[
    "pairwise-id",
    "eduPersonScopedAffiliation",
    "eduPersonAssurance",
    "schacHomeOrganization",
];

const REFEDS_ANONYMOUS_ACCESS: &[&str] = &["eduPersonScopedAffiliation", "schacHomeOrganization"];

const EGOVTOKEN: &[&str] = &[
    "PVP-VERSION",
    "PVP-PRINCIPAL-NAME",
    "PVP-GIVENNAME",
    "PVP-BIRTHDATE",
    "PVP-USERID",
    "PVP-GID",
    "PVP-BPK",
    "PVP-MAIL",
    "PVP-TEL",
    "PVP-PARTICIPANT-ID",
    "PVP-PARTICIPANT-OKZ",
    "PVP-OU-OKZ",
    "PVP-OU",
    "PVP-OU-GV-OU-ID",
    "PVP-FUNCTION",
    "PVP-ROLES",
];

const CHARGEATTR: &[&str] = &[
    "PVP-INVOICE-RECPT-ID",
    "PVP-COST-CENTER-ID",
    "PVP-CHARGE-CODE",
];

// ── Shipped policies ────────────────────────────────────────────────────────

/// eduGAIN / GÉANT CoCo v1 release policy (ported from pysaml2's edugain policy).
pub static EDUGAIN: EntityCategoryPolicy = EntityCategoryPolicy {
    name: "edugain",
    rules: &[
        EntityCategoryRule {
            categories: &[],
            attributes: &["eduPersonTargetedID"],
            only_required: false,
            conflicts: &[],
        },
        EntityCategoryRule {
            categories: &[COCO_V1],
            attributes: COCO_V1_ATTRIBUTES,
            only_required: true,
            conflicts: &[],
        },
    ],
};

/// REFEDS Research & Scholarship release policy (ported from pysaml2's refeds policy).
pub static REFEDS: EntityCategoryPolicy = EntityCategoryPolicy {
    name: "refeds",
    rules: &[
        EntityCategoryRule {
            categories: &[],
            attributes: &["eduPersonTargetedID"],
            only_required: false,
            conflicts: &[],
        },
        EntityCategoryRule {
            categories: &[REFEDS_RESEARCH_AND_SCHOLARSHIP],
            attributes: REFEDS_RS_ATTRIBUTES,
            only_required: false,
            conflicts: &[],
        },
    ],
};

/// InCommon Research & Scholarship release policy (ported from pysaml2's incommon policy).
pub static INCOMMON: EntityCategoryPolicy = EntityCategoryPolicy {
    name: "incommon",
    rules: &[
        EntityCategoryRule {
            categories: &[],
            attributes: &["eduPersonTargetedID"],
            only_required: false,
            conflicts: &[],
        },
        EntityCategoryRule {
            categories: &[INCOMMON_RESEARCH_AND_SCHOLARSHIP],
            attributes: REFEDS_RS_ATTRIBUTES,
            only_required: false,
            conflicts: &[],
        },
    ],
};

/// SWAMID release policy (ported from pysaml2's swamid policy).
///
/// As on pysaml2's `ft-typing` / `ft-refeds_ec` branches, the REFEDS
/// personalized/pseudonymous/anonymous access rules are part of the default
/// rule set. They are conflict-aware, so they never combine with one another;
/// if an SP publishes multiple REFEDS Access categories, the most restrictive
/// declared rule wins. [`REFEDS_ACCESS_RULES`] exposes just those three for
/// deployments that want them in isolation.
pub static SWAMID: EntityCategoryPolicy = EntityCategoryPolicy {
    name: "swamid",
    rules: &[
        EntityCategoryRule {
            categories: &[SWAMID_SFS_1993_1153],
            attributes: &["norEduPersonNIN", "eduPersonAssurance"],
            only_required: false,
            conflicts: &[],
        },
        EntityCategoryRule {
            categories: &[SWAMID_RESEARCH_AND_EDUCATION, SWAMID_EU],
            attributes: SWAMID_NAME_ORG_OTHER,
            only_required: false,
            conflicts: &[],
        },
        EntityCategoryRule {
            categories: &[SWAMID_RESEARCH_AND_EDUCATION, SWAMID_NREN],
            attributes: SWAMID_NAME_ORG_OTHER,
            only_required: false,
            conflicts: &[],
        },
        EntityCategoryRule {
            categories: &[SWAMID_RESEARCH_AND_EDUCATION, SWAMID_HEI],
            attributes: SWAMID_NAME_ORG_OTHER,
            only_required: false,
            conflicts: &[],
        },
        EntityCategoryRule {
            categories: &[REFEDS_RESEARCH_AND_SCHOLARSHIP],
            attributes: SWAMID_R_AND_S,
            only_required: false,
            conflicts: &[],
        },
        EntityCategoryRule {
            categories: &[COCO_V1],
            attributes: GEANT_COCO,
            only_required: true,
            conflicts: &[],
        },
        EntityCategoryRule {
            categories: &[COCO_V2],
            attributes: GEANT_COCO,
            only_required: true,
            conflicts: &[],
        },
        EntityCategoryRule {
            categories: &[MYACADEMICID_ESI],
            attributes: ESI_ATTRIBUTES,
            only_required: false,
            conflicts: &[],
        },
        EntityCategoryRule {
            categories: &[MYACADEMICID_ESI, COCO_V1],
            attributes: ESI_AND_COCO,
            only_required: true,
            conflicts: &[],
        },
        EntityCategoryRule {
            categories: &[MYACADEMICID_ESI, COCO_V2],
            attributes: ESI_AND_COCO,
            only_required: true,
            conflicts: &[],
        },
        // REFEDS Access categories (pysaml2 swamid `RESTRICTIONS`): active by
        // default now that the matcher understands `conflicts`.
        REFEDS_PERSONALIZED_RULE,
        REFEDS_PSEUDONYMOUS_RULE,
        REFEDS_ANONYMOUS_RULE,
    ],
};

// REFEDS Access category rules (pysaml2 swamid `RESTRICTIONS`). Each requires
// its own category and *conflicts* with the more restrictive ones, so at most
// one access rule contributes even if an SP publishes multiple access
// categories, while each still combines with R&S, CoCo, etc. (see ADR 0014).
// Defined as shared consts so they appear both standalone in
// [`REFEDS_ACCESS_RULES`] and folded into the default [`SWAMID`] policy.
const REFEDS_PERSONALIZED_RULE: EntityCategoryRule = EntityCategoryRule {
    categories: &[REFEDS_PERSONALIZED],
    attributes: REFEDS_PERSONALIZED_ACCESS,
    conflicts: &[REFEDS_PSEUDONYMOUS, REFEDS_ANONYMOUS],
    only_required: false,
};

const REFEDS_PSEUDONYMOUS_RULE: EntityCategoryRule = EntityCategoryRule {
    categories: &[REFEDS_PSEUDONYMOUS],
    attributes: REFEDS_PSEUDONYMOUS_ACCESS,
    conflicts: &[REFEDS_ANONYMOUS],
    only_required: false,
};

const REFEDS_ANONYMOUS_RULE: EntityCategoryRule = EntityCategoryRule {
    categories: &[REFEDS_ANONYMOUS],
    attributes: REFEDS_ANONYMOUS_ACCESS,
    conflicts: &[],
    only_required: false,
};

/// REFEDS personalized / pseudonymous / anonymous access rules as a standalone
/// policy.
///
/// pysaml2 originally shipped these disabled inside the swamid module ("until
/// we can figure out how to handle them") because its old model could not
/// combine them with other categories without also combining them with each
/// other. With the conflict-aware matcher they are now active by default in
/// [`SWAMID`]; this standalone policy remains for deployments that want only
/// the REFEDS Access rules. If an SP publishes multiple REFEDS Access
/// categories, the most restrictive declared rule wins (personalized yields to
/// pseudonymous/anonymous; pseudonymous yields to anonymous), and the winning
/// rule still aggregates with non-conflicting categories.
pub static REFEDS_ACCESS_RULES: EntityCategoryPolicy = EntityCategoryPolicy {
    name: "refeds-access",
    rules: &[
        REFEDS_PERSONALIZED_RULE,
        REFEDS_PSEUDONYMOUS_RULE,
        REFEDS_ANONYMOUS_RULE,
    ],
};

/// Austrian e-government PVP2 release policy (ported from pysaml2's at_egov_pvp2 policy).
pub static AT_EGOV_PVP2_POLICY: EntityCategoryPolicy = EntityCategoryPolicy {
    name: "at_egov_pvp2",
    rules: &[
        EntityCategoryRule {
            categories: &[AT_EGOV_PVP2],
            attributes: EGOVTOKEN,
            only_required: false,
            conflicts: &[],
        },
        EntityCategoryRule {
            categories: &[AT_EGOV_PVP2_CHARGE],
            attributes: CHARGEATTR,
            only_required: false,
            conflicts: &[],
        },
    ],
};

// ── Rule evaluation ─────────────────────────────────────────────────────────

/// Compute the set of releasable local attribute names (lowercased) for an SP
/// (pysaml2 `Policy.get_entity_categories` / `post_entity_categories`).
///
/// - `sp_entity_categories`: the category URIs from the SP's metadata
///   `EntityAttributes`.
/// - `required_local_names`: lowercased local names of the attributes the SP
///   marks as required (consulted by `only_required` rules).
pub fn releasable_attributes(
    policies: &[&EntityCategoryPolicy],
    sp_entity_categories: &[String],
    required_local_names: &[String],
) -> HashSet<String> {
    let ecs: HashSet<&str> = sp_entity_categories.iter().map(String::as_str).collect();
    let mut released: HashSet<String> = HashSet::new();

    for policy in policies {
        for rule in policy.rules {
            if !rule.matches(&ecs) {
                continue;
            }
            release_rule_attributes(
                rule.attributes.iter().copied(),
                rule.categories.is_empty(),
                rule.only_required,
                required_local_names,
                &mut released,
            );
        }
    }

    released
}

/// As [`releasable_attributes`], but over owned, runtime-built policies
/// ([`OwnedEntityCategoryPolicy`]). Mix shipped policies in by converting them
/// with [`EntityCategoryPolicy::as_owned`].
///
/// Accepts anything iterable over `&OwnedEntityCategoryPolicy`, so a caller
/// holding a `&[OwnedEntityCategoryPolicy]` (e.g. the resolved policy set in
/// `ReleasePolicy::filter`) passes it directly with no per-call allocation.
pub fn releasable_attributes_owned<'a, I>(
    policies: I,
    sp_entity_categories: &[String],
    required_local_names: &[String],
) -> HashSet<String>
where
    I: IntoIterator<Item = &'a OwnedEntityCategoryPolicy>,
{
    let ecs: HashSet<&str> = sp_entity_categories.iter().map(String::as_str).collect();
    let mut released: HashSet<String> = HashSet::new();

    for policy in policies {
        for rule in &policy.rules {
            if !rule.matches(&ecs) {
                continue;
            }
            release_rule_attributes(
                rule.attributes.iter().map(String::as_str),
                rule.categories.is_empty(),
                rule.only_required,
                required_local_names,
                &mut released,
            );
        }
    }

    released
}

/// Shared release step for a matched rule: insert the lowercased attribute
/// names, honoring `only_required` (the always-release rule with an empty
/// category list is exempt, per pysaml2).
fn release_rule_attributes<'a>(
    attributes: impl Iterator<Item = &'a str>,
    categories_empty: bool,
    only_required: bool,
    required_local_names: &[String],
    released: &mut HashSet<String>,
) {
    for attr in attributes {
        let attr = attr.to_lowercase();
        if !only_required || categories_empty || required_local_names.contains(&attr) {
            released.insert(attr);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cats(uris: &[&str]) -> Vec<String> {
        uris.iter().map(|s| s.to_string()).collect()
    }

    fn lower(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| s.to_lowercase()).collect()
    }

    #[test]
    fn test_refeds_rs_release() {
        let released =
            releasable_attributes(&[&REFEDS], &cats(&[REFEDS_RESEARCH_AND_SCHOLARSHIP]), &[]);
        assert!(released.contains("mail"));
        assert!(released.contains("edupersonprincipalname"));
        // the "" rule always releases eduPersonTargetedID
        assert!(released.contains("edupersontargetedid"));
    }

    #[test]
    fn test_no_category_only_default_rule() {
        let released = releasable_attributes(&[&REFEDS], &[], &[]);
        assert_eq!(released.len(), 1);
        assert!(released.contains("edupersontargetedid"));
    }

    #[test]
    fn test_coco_only_required() {
        // CoCo releases only what the SP requires
        let released = releasable_attributes(
            &[&EDUGAIN],
            &cats(&[COCO_V1]),
            &lower(&["mail", "displayName"]),
        );
        assert!(released.contains("mail"));
        assert!(released.contains("displayname"));
        assert!(!released.contains("cn"));
        assert!(!released.contains("edupersonaffiliation"));
    }

    #[test]
    fn test_swamid_tuple_key_requires_both() {
        // research-and-education alone releases nothing from the pair rules
        let released =
            releasable_attributes(&[&SWAMID], &cats(&[SWAMID_RESEARCH_AND_EDUCATION]), &[]);
        assert!(released.is_empty());

        let released = releasable_attributes(
            &[&SWAMID],
            &cats(&[SWAMID_RESEARCH_AND_EDUCATION, SWAMID_EU]),
            &[],
        );
        assert!(released.contains("givenname"));
        assert!(released.contains("schachomeorganization"));
    }

    #[test]
    fn test_refeds_access_combines_with_other_categories() {
        // R&S plus anonymous access: anonymous does *not* conflict with R&S,
        // so both rules contribute (it no longer wipes the R&S attributes).
        let released = releasable_attributes(
            &[&REFEDS, &REFEDS_ACCESS_RULES],
            &cats(&[REFEDS_RESEARCH_AND_SCHOLARSHIP, REFEDS_ANONYMOUS]),
            &[],
        );
        // anonymous access attributes
        assert!(released.contains("edupersonscopedaffiliation"));
        assert!(released.contains("schachomeorganization"));
        // R&S attributes are still present (aggregated, not replaced)
        assert!(released.contains("mail"));
        assert!(released.contains("givenname"));
    }

    #[test]
    fn test_refeds_access_prefers_more_restrictive_category() {
        // personalized yields to pseudonymous: only the pseudonymous rule
        // contributes.
        let released = releasable_attributes(
            &[&REFEDS_ACCESS_RULES],
            &cats(&[REFEDS_PERSONALIZED, REFEDS_PSEUDONYMOUS]),
            &[],
        );
        assert!(!released.contains("subject-id"));
        assert!(!released.contains("displayname"));
        assert!(released.contains("pairwise-id"));
        assert!(released.contains("edupersonscopedaffiliation"));

        // personalized also yields to anonymous.
        let released = releasable_attributes(
            &[&REFEDS_ACCESS_RULES],
            &cats(&[REFEDS_PERSONALIZED, REFEDS_ANONYMOUS]),
            &[],
        );
        // personalized-only attributes must not leak.
        assert!(!released.contains("subject-id"));
        assert!(!released.contains("displayname"));
        assert!(!released.contains("givenname"));
        // anonymous attributes are released.
        assert!(released.contains("edupersonscopedaffiliation"));
        assert!(released.contains("schachomeorganization"));

        // pseudonymous yields to anonymous.
        let released = releasable_attributes(
            &[&REFEDS_ACCESS_RULES],
            &cats(&[REFEDS_PSEUDONYMOUS, REFEDS_ANONYMOUS]),
            &[],
        );
        assert!(!released.contains("pairwise-id"));
        assert!(released.contains("edupersonscopedaffiliation"));
    }

    #[test]
    fn test_refeds_personalized_alone_releases_its_attributes() {
        let released =
            releasable_attributes(&[&REFEDS_ACCESS_RULES], &cats(&[REFEDS_PERSONALIZED]), &[]);
        assert!(released.contains("subject-id"));
        assert!(released.contains("displayname"));
        assert!(released.contains("edupersonscopedaffiliation"));
    }

    #[test]
    fn test_swamid_default_includes_refeds_access() {
        // The REFEDS access rules are now part of the default SWAMID policy.
        let released = releasable_attributes(&[&SWAMID], &cats(&[REFEDS_PSEUDONYMOUS]), &[]);
        assert!(released.contains("pairwise-id"));
        assert!(released.contains("schachomeorganization"));
    }

    #[test]
    fn test_subject_id_req_parsing() {
        assert_eq!(
            SubjectIdReq::from_metadata_values(&["any".to_string()]),
            SubjectIdReq::Any
        );
        assert_eq!(
            SubjectIdReq::from_metadata_values(&[" Any ".to_string()]),
            SubjectIdReq::Any
        );
        assert_eq!(
            SubjectIdReq::from_metadata_values(&["none".to_string()]),
            SubjectIdReq::None
        );
        assert_eq!(
            SubjectIdReq::from_metadata_values(&["pairwise-id".to_string()]),
            SubjectIdReq::PairwiseId
        );
        assert_eq!(
            SubjectIdReq::from_metadata_values(&["SUBJECT-ID".to_string()]),
            SubjectIdReq::SubjectId
        );
        assert_eq!(SubjectIdReq::from_metadata_values(&[]), SubjectIdReq::None);
        assert_eq!(
            SubjectIdReq::from_metadata_values(&["bogus".to_string()]),
            SubjectIdReq::None
        );
    }

    #[test]
    fn test_prefer_pairwise_over_subject_id() {
        // req == any and both present: subject-id dropped.
        let mut set: HashSet<String> = ["subject-id", "pairwise-id", "mail"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        prefer_pairwise_over_subject_id(SubjectIdReq::Any, &mut set);
        assert!(!set.contains("subject-id"));
        assert!(set.contains("pairwise-id"));
        assert!(set.contains("mail"));

        // req != any: no change even if both present.
        let mut set: HashSet<String> = ["subject-id", "pairwise-id"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        prefer_pairwise_over_subject_id(SubjectIdReq::None, &mut set);
        assert!(set.contains("subject-id"));
        assert!(set.contains("pairwise-id"));

        // only subject-id present: kept (nothing to prefer).
        let mut set: HashSet<String> = ["subject-id"].iter().map(|s| s.to_string()).collect();
        prefer_pairwise_over_subject_id(SubjectIdReq::Any, &mut set);
        assert!(set.contains("subject-id"));
    }

    #[test]
    fn test_at_egov() {
        let released = releasable_attributes(&[&AT_EGOV_PVP2_POLICY], &cats(&[AT_EGOV_PVP2]), &[]);
        assert!(released.contains("pvp-mail"));
        assert!(!released.contains("pvp-charge-code"));
    }

    #[test]
    fn test_owned_custom_category() {
        let policy =
            OwnedEntityCategoryPolicy::new("custom").with_rule(OwnedEntityCategoryRule::new(
                ["https://example.org/category/staff"],
                ["mail", "displayName"],
            ));
        let released = releasable_attributes_owned(
            [&policy],
            &cats(&["https://example.org/category/staff"]),
            &[],
        );
        assert!(released.contains("mail"));
        assert!(released.contains("displayname"));

        // Category absent: nothing released.
        let released = releasable_attributes_owned([&policy], &[], &[]);
        assert!(released.is_empty());
    }

    #[test]
    fn test_owned_matches_static_swamid() {
        // Converting a shipped policy to owned yields identical releases.
        let owned = SWAMID.as_owned();
        let cats_v = cats(&[REFEDS_PSEUDONYMOUS]);
        let from_static = releasable_attributes(&[&SWAMID], &cats_v, &[]);
        let from_owned = releasable_attributes_owned([&owned], &cats_v, &[]);
        assert_eq!(from_static, from_owned);
        assert!(from_owned.contains("pairwise-id"));
    }

    #[test]
    fn test_owned_conflicts_and_only_required() {
        let policy = OwnedEntityCategoryPolicy::new("c")
            .with_rule(OwnedEntityCategoryRule::new(["A"], ["mail", "sn"]).with_only_required(true))
            .with_rule(OwnedEntityCategoryRule::new(["A"], ["displayName"]).with_conflicts(["B"]));

        // only_required keeps just the requested "mail"; conflict B absent so
        // the displayName rule fires.
        let released = releasable_attributes_owned([&policy], &cats(&["A"]), &lower(&["mail"]));
        assert!(released.contains("mail"));
        assert!(!released.contains("sn"));
        assert!(released.contains("displayname"));

        // Conflict B present suppresses the displayName rule.
        let released =
            releasable_attributes_owned([&policy], &cats(&["A", "B"]), &lower(&["mail"]));
        assert!(released.contains("mail"));
        assert!(!released.contains("displayname"));
    }

    #[test]
    fn test_extend_from_static_then_custom() {
        let policy = OwnedEntityCategoryPolicy::new("swamid-local")
            .extend_from_static(&SWAMID)
            .with_rule(OwnedEntityCategoryRule::new(
                ["https://eduid.se/category/local"],
                ["eduidLocalAttr"],
            ));
        let released = releasable_attributes_owned(
            [&policy],
            &cats(&[
                REFEDS_RESEARCH_AND_SCHOLARSHIP,
                "https://eduid.se/category/local",
            ]),
            &[],
        );
        assert!(released.contains("mail")); // inherited from SWAMID R&S
        assert!(released.contains("eduidlocalattr")); // from the custom rule
    }
}
