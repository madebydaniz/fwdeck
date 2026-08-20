//! Version-derived firewalld syntax and semantic capabilities. Unknown or
//! malformed versions stay unknown so evaluators can fail closed.

/// Whether the current firewalld version provides a capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeatureSupport {
    /// The reported version includes the capability.
    Supported,
    /// The reported version predates the capability.
    Unsupported,
    /// No usable version was reported.
    Unknown,
}

/// Whether a capability controls accepted syntax or evaluation semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SemanticCapabilityKind {
    /// The version can represent and configure the feature.
    Syntax,
    /// The version changes how an otherwise valid configuration is evaluated.
    Behavior,
}

/// Versioned firewalld capabilities used by observation and evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewalldFeature {
    /// Policy objects and their ingress/egress bindings.
    PolicyObjects,
    /// Independent zone ingress and egress classification priorities.
    ZonePriorities,
    /// Explicit priorities in rich-rule syntax.
    RichRulePriorities,
    /// Per-zone forwarding between members of the same zone.
    IntraZoneForwarding,
    /// Shipped and newly created zones enable intra-zone forwarding by default.
    IntraZoneForwardingDefaultEnabled,
    /// The default zone target is terminal and behaves like reject except for ICMP.
    DefaultTargetRejectSemantics,
    /// Zone ICMP blocks and inversion affect input traffic only.
    IcmpBlocksInputOnly,
    /// Positive-priority policies run immediately before the zone target.
    PositivePolicyPriorityBeforeZoneTarget,
    /// Predefined, interoperable collections of policy objects.
    PolicySets,
}

/// Immutable capability lookup derived from one reported firewalld version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SemanticCapabilityMatrix {
    version: Option<FirewalldVersion>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct FirewalldVersion {
    major: u64,
    minor: u64,
    patch: u64,
}

impl FirewalldVersion {
    const fn new(major: u64, minor: u64, patch: u64) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }
}

impl SemanticCapabilityMatrix {
    /// Parses one reported version once for all later capability queries.
    #[must_use]
    pub fn from_reported_version(version: Option<&str>) -> Self {
        Self {
            version: version.and_then(parse_version),
        }
    }

    /// Resolves a feature without guessing when the reported version is unusable.
    #[must_use]
    pub fn support(self, feature: FirewalldFeature) -> FeatureSupport {
        let Some(version) = self.version else {
            return FeatureSupport::Unknown;
        };
        if version >= feature.minimum() {
            FeatureSupport::Supported
        } else {
            FeatureSupport::Unsupported
        }
    }
}

impl FirewalldFeature {
    /// Exhaustive capability set used by fixtures and evaluator audits.
    pub const ALL: [Self; 9] = [
        Self::PolicyObjects,
        Self::ZonePriorities,
        Self::RichRulePriorities,
        Self::IntraZoneForwarding,
        Self::IntraZoneForwardingDefaultEnabled,
        Self::DefaultTargetRejectSemantics,
        Self::IcmpBlocksInputOnly,
        Self::PositivePolicyPriorityBeforeZoneTarget,
        Self::PolicySets,
    ];

    /// Whether this capability adds syntax or changes evaluation behavior.
    #[must_use]
    pub const fn kind(self) -> SemanticCapabilityKind {
        match self {
            Self::PolicyObjects
            | Self::ZonePriorities
            | Self::RichRulePriorities
            | Self::IntraZoneForwarding
            | Self::PolicySets => SemanticCapabilityKind::Syntax,
            Self::IntraZoneForwardingDefaultEnabled
            | Self::DefaultTargetRejectSemantics
            | Self::IcmpBlocksInputOnly
            | Self::PositivePolicyPriorityBeforeZoneTarget => SemanticCapabilityKind::Behavior,
        }
    }

    /// Minimum stable upstream version carrying this syntax or behavior.
    #[must_use]
    pub const fn minimum_version(self) -> &'static str {
        match self {
            Self::RichRulePriorities => "0.7.0",
            Self::PolicyObjects | Self::IntraZoneForwarding => "0.9.0",
            Self::IntraZoneForwardingDefaultEnabled
            | Self::DefaultTargetRejectSemantics
            | Self::IcmpBlocksInputOnly
            | Self::PositivePolicyPriorityBeforeZoneTarget => "1.0.0",
            Self::ZonePriorities => "2.0.0",
            Self::PolicySets => "2.4.0",
        }
    }

    /// Resolves support directly from a reported daemon/client version.
    #[must_use]
    pub fn support_for(self, version: Option<&str>) -> FeatureSupport {
        SemanticCapabilityMatrix::from_reported_version(version).support(self)
    }

    const fn minimum(self) -> FirewalldVersion {
        match self {
            Self::RichRulePriorities => FirewalldVersion::new(0, 7, 0),
            Self::PolicyObjects | Self::IntraZoneForwarding => FirewalldVersion::new(0, 9, 0),
            Self::IntraZoneForwardingDefaultEnabled
            | Self::DefaultTargetRejectSemantics
            | Self::IcmpBlocksInputOnly
            | Self::PositivePolicyPriorityBeforeZoneTarget => FirewalldVersion::new(1, 0, 0),
            Self::ZonePriorities => FirewalldVersion::new(2, 0, 0),
            Self::PolicySets => FirewalldVersion::new(2, 4, 0),
        }
    }
}

fn parse_version(raw: &str) -> Option<FirewalldVersion> {
    let raw = raw.trim();
    let raw = raw.strip_prefix('v').unwrap_or(raw);
    let suffix_start = raw
        .char_indices()
        .find_map(|(index, character)| {
            (!character.is_ascii_digit() && character != '.').then_some(index)
        })
        .unwrap_or(raw.len());
    let (core, suffix) = raw.split_at(suffix_start);
    if !valid_distro_suffix(suffix) {
        return None;
    }

    let mut parts = core.split('.');
    let major = parse_component(parts.next()?)?;
    let minor = parse_component(parts.next()?)?;
    let patch = match parts.next() {
        Some(patch) => parse_component(patch)?,
        None => 0,
    };
    if parts.next().is_some() {
        return None;
    }
    Some(FirewalldVersion::new(major, minor, patch))
}

fn parse_component(raw: &str) -> Option<u64> {
    (!raw.is_empty() && raw.chars().all(|character| character.is_ascii_digit()))
        .then(|| raw.parse().ok())
        .flatten()
}

fn valid_distro_suffix(suffix: &str) -> bool {
    if suffix.is_empty() {
        return true;
    }
    let mut characters = suffix.chars();
    let Some(delimiter @ ('-' | '+')) = characters.next() else {
        return false;
    };
    let Some(first) = characters.next() else {
        return false;
    };
    if delimiter == '-' && !first.is_ascii_digit() {
        return false;
    }
    let normalized = suffix.to_ascii_lowercase();
    if ["rc", "alpha", "beta", "pre"]
        .into_iter()
        .any(|marker| normalized.contains(marker))
    {
        return false;
    }
    (first.is_ascii_alphanumeric())
        && characters.all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-' | '+' | '~')
        })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use serde::Deserialize;

    use super::*;

    #[derive(Debug, Deserialize)]
    struct ThresholdManifest {
        reviewed_on: String,
        features: Vec<ThresholdRow>,
    }

    #[derive(Debug, Deserialize)]
    struct ThresholdRow {
        feature: String,
        kind: String,
        minimum: String,
        source: String,
    }

    fn fixture() -> ThresholdManifest {
        serde_json::from_str(include_str!(
            "../../tests/fixtures/traffic_testing/capability_thresholds.json"
        ))
        .expect("capability threshold fixture must be valid")
    }

    fn feature_for(name: &str) -> FirewalldFeature {
        match name {
            "policy_objects" => FirewalldFeature::PolicyObjects,
            "zone_priorities" => FirewalldFeature::ZonePriorities,
            "rich_rule_priorities" => FirewalldFeature::RichRulePriorities,
            "intra_zone_forwarding" => FirewalldFeature::IntraZoneForwarding,
            "intra_zone_forwarding_default_enabled" => {
                FirewalldFeature::IntraZoneForwardingDefaultEnabled
            }
            "default_target_reject_semantics" => FirewalldFeature::DefaultTargetRejectSemantics,
            "icmp_blocks_input_only" => FirewalldFeature::IcmpBlocksInputOnly,
            "positive_policy_priority_before_zone_target" => {
                FirewalldFeature::PositivePolicyPriorityBeforeZoneTarget
            }
            "policy_sets" => FirewalldFeature::PolicySets,
            other => panic!("unknown fixture feature {other}"),
        }
    }

    #[test]
    fn every_threshold_is_exactly_version_gated() {
        let cases = [
            (FirewalldFeature::PolicyObjects, "0.8.99", "0.9.0", "0.9.1"),
            (FirewalldFeature::ZonePriorities, "1.3.99", "2.0.0", "2.0.1"),
            (
                FirewalldFeature::RichRulePriorities,
                "0.6.99",
                "0.7.0",
                "0.7.1",
            ),
            (
                FirewalldFeature::IntraZoneForwarding,
                "0.8.99",
                "0.9.0",
                "0.9.1",
            ),
            (
                FirewalldFeature::IntraZoneForwardingDefaultEnabled,
                "0.9.99",
                "1.0.0",
                "1.0.1",
            ),
            (
                FirewalldFeature::DefaultTargetRejectSemantics,
                "0.9.99",
                "1.0.0",
                "1.0.1",
            ),
            (
                FirewalldFeature::IcmpBlocksInputOnly,
                "0.9.99",
                "1.0.0",
                "1.0.1",
            ),
            (
                FirewalldFeature::PositivePolicyPriorityBeforeZoneTarget,
                "0.9.99",
                "1.0.0",
                "1.0.1",
            ),
            (FirewalldFeature::PolicySets, "2.3.99", "2.4.0", "2.4.1"),
        ];

        for (feature, before, at, after) in cases {
            assert_eq!(
                feature.support_for(Some(before)),
                FeatureSupport::Unsupported
            );
            assert_eq!(feature.support_for(Some(at)), FeatureSupport::Supported);
            assert_eq!(feature.support_for(Some(after)), FeatureSupport::Supported);
        }
    }

    #[test]
    fn syntax_and_behavior_capabilities_are_explicit() {
        assert_eq!(
            FirewalldFeature::PolicyObjects.kind(),
            SemanticCapabilityKind::Syntax
        );
        assert_eq!(
            FirewalldFeature::ZonePriorities.kind(),
            SemanticCapabilityKind::Syntax
        );
        assert_eq!(
            FirewalldFeature::RichRulePriorities.kind(),
            SemanticCapabilityKind::Syntax
        );
        assert_eq!(
            FirewalldFeature::IntraZoneForwarding.kind(),
            SemanticCapabilityKind::Syntax
        );
        assert_eq!(
            FirewalldFeature::PolicySets.kind(),
            SemanticCapabilityKind::Syntax
        );
        assert_eq!(
            FirewalldFeature::DefaultTargetRejectSemantics.kind(),
            SemanticCapabilityKind::Behavior
        );
        assert_eq!(
            FirewalldFeature::IcmpBlocksInputOnly.kind(),
            SemanticCapabilityKind::Behavior
        );
    }

    #[test]
    fn supported_distro_suffixes_and_documented_patch_default_parse() {
        let feature = FirewalldFeature::PolicySets;
        for version in [
            "2.4",
            "v2.4.0",
            "2.4.0-1.fc42",
            "2.4.0-1.el9",
            "2.4.0+deb12u1",
        ] {
            assert_eq!(
                feature.support_for(Some(version)),
                FeatureSupport::Supported
            );
        }
    }

    #[test]
    fn missing_malformed_and_prerelease_versions_stay_unknown() {
        for feature in FirewalldFeature::ALL {
            assert_eq!(feature.support_for(None), FeatureSupport::Unknown);
            for version in [
                "",
                "unknown",
                "2",
                "2.",
                ".4.0",
                "2.4x",
                "2.4.0.1",
                "2.4.0-",
                "2.4.0-rc1",
                "2.4.0-0.rc1",
            ] {
                assert_eq!(
                    feature.support_for(Some(version)),
                    FeatureSupport::Unknown,
                    "{feature:?} accepted malformed version {version:?}"
                );
            }
        }
    }

    #[test]
    fn one_matrix_reuses_the_parsed_version_for_every_query() {
        let matrix = SemanticCapabilityMatrix::from_reported_version(Some("1.0.0-1.el9"));

        assert_eq!(
            matrix.support(FirewalldFeature::PolicyObjects),
            FeatureSupport::Supported
        );
        assert_eq!(
            matrix.support(FirewalldFeature::ZonePriorities),
            FeatureSupport::Unsupported
        );
        assert_eq!(
            matrix.support(FirewalldFeature::DefaultTargetRejectSemantics),
            FeatureSupport::Supported
        );
        assert_eq!(
            matrix.support(FirewalldFeature::PolicySets),
            FeatureSupport::Unsupported
        );
    }

    #[test]
    fn reviewed_fixture_and_exhaustive_code_matrix_cannot_drift() {
        let fixture = fixture();
        assert_eq!(fixture.reviewed_on, "2026-08-21");
        assert_eq!(fixture.features.len(), FirewalldFeature::ALL.len());

        let mut seen = Vec::with_capacity(FirewalldFeature::ALL.len());
        for row in fixture.features {
            let feature = feature_for(&row.feature);
            assert!(
                !seen.contains(&feature),
                "duplicate fixture row {feature:?}"
            );
            seen.push(feature);
            assert_eq!(feature.minimum_version(), row.minimum);
            assert_eq!(
                feature.kind(),
                match row.kind.as_str() {
                    "syntax" => SemanticCapabilityKind::Syntax,
                    "behavior" => SemanticCapabilityKind::Behavior,
                    other => panic!("unknown fixture kind {other}"),
                }
            );
            assert!(row.source.starts_with("https://firewalld.org/"));
        }
        assert!(
            FirewalldFeature::ALL
                .into_iter()
                .all(|feature| seen.contains(&feature))
        );
    }
}
