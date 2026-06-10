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
// - `no_aggregation`: when the rule matches, its list *replaces* everything
//   accumulated so far instead of adding to it (REFEDS anonymous /
//   pseudonymous / personalized access semantics).

use std::collections::HashSet;

/// A single release rule.
#[derive(Debug, Clone, Copy)]
pub struct EntityCategoryRule {
    /// Category URIs that must *all* be present on the SP. Empty = always.
    pub categories: &'static [&'static str],
    /// Local (friendly) attribute names released by this rule.
    pub attributes: &'static [&'static str],
    /// Release only attributes the SP also requires (CoCo).
    pub only_required: bool,
    /// On match, replace the accumulated release set instead of extending it.
    pub no_aggregation: bool,
}

/// A federation's set of release rules.
#[derive(Debug, Clone, Copy)]
pub struct EntityCategoryPolicy {
    /// Short name of the policy (e.g. `"swamid"`).
    pub name: &'static str,
    /// The rules, evaluated in order.
    pub rules: &'static [EntityCategoryRule],
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
            no_aggregation: false,
        },
        EntityCategoryRule {
            categories: &[COCO_V1],
            attributes: COCO_V1_ATTRIBUTES,
            only_required: true,
            no_aggregation: false,
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
            no_aggregation: false,
        },
        EntityCategoryRule {
            categories: &[REFEDS_RESEARCH_AND_SCHOLARSHIP],
            attributes: REFEDS_RS_ATTRIBUTES,
            only_required: false,
            no_aggregation: false,
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
            no_aggregation: false,
        },
        EntityCategoryRule {
            categories: &[INCOMMON_RESEARCH_AND_SCHOLARSHIP],
            attributes: REFEDS_RS_ATTRIBUTES,
            only_required: false,
            no_aggregation: false,
        },
    ],
};

/// SWAMID release policy (ported from pysaml2's swamid policy).
///
/// Like pysaml2, the REFEDS personalized/pseudonymous/anonymous access
/// no-aggregation rules are *not* part of the default rule set; see
/// [`REFEDS_ACCESS_RULES`] to opt in.
pub static SWAMID: EntityCategoryPolicy = EntityCategoryPolicy {
    name: "swamid",
    rules: &[
        EntityCategoryRule {
            categories: &[SWAMID_SFS_1993_1153],
            attributes: &["norEduPersonNIN", "eduPersonAssurance"],
            only_required: false,
            no_aggregation: false,
        },
        EntityCategoryRule {
            categories: &[SWAMID_RESEARCH_AND_EDUCATION, SWAMID_EU],
            attributes: SWAMID_NAME_ORG_OTHER,
            only_required: false,
            no_aggregation: false,
        },
        EntityCategoryRule {
            categories: &[SWAMID_RESEARCH_AND_EDUCATION, SWAMID_NREN],
            attributes: SWAMID_NAME_ORG_OTHER,
            only_required: false,
            no_aggregation: false,
        },
        EntityCategoryRule {
            categories: &[SWAMID_RESEARCH_AND_EDUCATION, SWAMID_HEI],
            attributes: SWAMID_NAME_ORG_OTHER,
            only_required: false,
            no_aggregation: false,
        },
        EntityCategoryRule {
            categories: &[REFEDS_RESEARCH_AND_SCHOLARSHIP],
            attributes: SWAMID_R_AND_S,
            only_required: false,
            no_aggregation: false,
        },
        EntityCategoryRule {
            categories: &[COCO_V1],
            attributes: GEANT_COCO,
            only_required: true,
            no_aggregation: false,
        },
        EntityCategoryRule {
            categories: &[COCO_V2],
            attributes: GEANT_COCO,
            only_required: true,
            no_aggregation: false,
        },
        EntityCategoryRule {
            categories: &[MYACADEMICID_ESI],
            attributes: ESI_ATTRIBUTES,
            only_required: false,
            no_aggregation: false,
        },
        EntityCategoryRule {
            categories: &[MYACADEMICID_ESI, COCO_V1],
            attributes: ESI_AND_COCO,
            only_required: true,
            no_aggregation: false,
        },
        EntityCategoryRule {
            categories: &[MYACADEMICID_ESI, COCO_V2],
            attributes: ESI_AND_COCO,
            only_required: true,
            no_aggregation: false,
        },
    ],
};

/// REFEDS personalized / pseudonymous / anonymous access rules.
///
/// pysaml2 ships these disabled inside the swamid module ("until we can
/// figure out how to handle them"); they are exposed here as a standalone
/// policy so deployments can opt in. Ordered least to most restrictive; each
/// is a no-aggregation rule (on match it replaces the accumulated set).
pub static REFEDS_ACCESS_RULES: EntityCategoryPolicy = EntityCategoryPolicy {
    name: "refeds-access",
    rules: &[
        EntityCategoryRule {
            categories: &[REFEDS_PERSONALIZED],
            attributes: REFEDS_PERSONALIZED_ACCESS,
            only_required: false,
            no_aggregation: true,
        },
        EntityCategoryRule {
            categories: &[REFEDS_PSEUDONYMOUS],
            attributes: REFEDS_PSEUDONYMOUS_ACCESS,
            only_required: false,
            no_aggregation: true,
        },
        EntityCategoryRule {
            categories: &[REFEDS_ANONYMOUS],
            attributes: REFEDS_ANONYMOUS_ACCESS,
            only_required: false,
            no_aggregation: true,
        },
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
            no_aggregation: false,
        },
        EntityCategoryRule {
            categories: &[AT_EGOV_PVP2_CHARGE],
            attributes: CHARGEATTR,
            only_required: false,
            no_aggregation: false,
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
            let matches = rule.categories.iter().all(|c| ecs.contains(c));
            if !matches {
                continue;
            }
            let attrs: Vec<String> = rule
                .attributes
                .iter()
                .map(|a| a.to_lowercase())
                .filter(|a| {
                    // The always-release rule (empty category list) is not
                    // subject to only_required in pysaml2.
                    !rule.only_required
                        || rule.categories.is_empty()
                        || required_local_names.contains(a)
                })
                .collect();
            if !attrs.is_empty() && rule.no_aggregation {
                released.clear();
            }
            released.extend(attrs);
        }
    }

    released
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
    fn test_no_aggregation_replaces() {
        // R&S plus anonymous access: the no-aggregation anonymous rule wipes
        // the accumulated R&S attributes.
        let released = releasable_attributes(
            &[&REFEDS, &REFEDS_ACCESS_RULES],
            &cats(&[REFEDS_RESEARCH_AND_SCHOLARSHIP, REFEDS_ANONYMOUS]),
            &[],
        );
        assert_eq!(
            released,
            ["edupersonscopedaffiliation", "schachomeorganization"]
                .iter()
                .map(|s| s.to_string())
                .collect()
        );
    }

    #[test]
    fn test_at_egov() {
        let released = releasable_attributes(&[&AT_EGOV_PVP2_POLICY], &cats(&[AT_EGOV_PVP2]), &[]);
        assert!(released.contains("pvp-mail"));
        assert!(!released.contains("pvp-charge-code"));
    }
}
