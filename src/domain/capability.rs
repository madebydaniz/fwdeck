//! Version-derived firewalld feature support. Unknown or malformed versions
//! stay unknown so callers can fail closed instead of guessing.

/// Whether the current firewalld version can provide a feature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeatureSupport {
    /// The reported version includes the feature.
    Supported,
    /// The reported version predates the feature.
    Unsupported,
    /// No usable version was reported.
    Unknown,
}

/// Features whose availability changes across supported firewalld versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewalldFeature {
    /// Predefined policy sets (`--policy-set`), introduced in firewalld 2.4.0.
    PolicySets,
}

impl FirewalldFeature {
    /// Minimum stable firewalld version carrying this feature.
    #[must_use]
    pub const fn minimum_version(self) -> &'static str {
        match self {
            Self::PolicySets => "2.4.0",
        }
    }

    /// Resolves support from the daemon/client version string.
    #[must_use]
    pub fn support_for(self, version: Option<&str>) -> FeatureSupport {
        let Some(current) = version.and_then(parse_version) else {
            return FeatureSupport::Unknown;
        };
        let minimum = match self {
            Self::PolicySets => (2, 4, 0),
        };
        if current >= minimum {
            FeatureSupport::Supported
        } else {
            FeatureSupport::Unsupported
        }
    }
}

fn parse_version(raw: &str) -> Option<(u64, u64, u64)> {
    let raw = raw.trim().strip_prefix('v').unwrap_or(raw.trim());
    let mut parts = raw.split('.');
    let major = numeric_prefix(parts.next()?)?;
    let minor = numeric_prefix(parts.next()?)?;
    let patch = parts.next().and_then(numeric_prefix).unwrap_or(0);
    Some((major, minor, patch))
}

fn numeric_prefix(raw: &str) -> Option<u64> {
    let digits: String = raw.chars().take_while(char::is_ascii_digit).collect();
    (!digits.is_empty()).then(|| digits.parse().ok()).flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_sets_are_gated_at_2_4_0() {
        let feature = FirewalldFeature::PolicySets;
        assert_eq!(
            feature.support_for(Some("2.3.1")),
            FeatureSupport::Unsupported
        );
        assert_eq!(
            feature.support_for(Some("2.4.0")),
            FeatureSupport::Supported
        );
        assert_eq!(
            feature.support_for(Some("v3.0.0")),
            FeatureSupport::Supported
        );
    }

    #[test]
    fn missing_or_malformed_versions_stay_unknown() {
        let feature = FirewalldFeature::PolicySets;
        assert_eq!(feature.support_for(None), FeatureSupport::Unknown);
        assert_eq!(
            feature.support_for(Some("unknown")),
            FeatureSupport::Unknown
        );
    }
}
