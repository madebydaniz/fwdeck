//! Derived views of predefined firewalld policy sets. Firewalld exposes set
//! mutations but no separate list API, so membership is derived from the
//! policy names returned by the existing policy snapshot.

use std::collections::BTreeMap;

use super::{PolicyDetails, PolicyName, PolicySetName};

/// Policy sets currently shipped and documented by upstream firewalld.
pub const KNOWN_POLICY_SETS: &[&str] = &["gateway"];
/// Exact member manifest documented for the upstream gateway policy set.
pub const GATEWAY_POLICY_MEMBERS: &[&str] = &[
    "gateway-dmz-to-HOST",
    "gateway-lan-to-work",
    "gateway-lan-to-world",
    "gateway-lan-to-HOST",
    "gateway-world-to-HOST",
];

/// Aggregate administrative state of one policy-set scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicySetState {
    /// No member policies were observed in this scope.
    Absent,
    /// Some, but not all, verified member policies were observed.
    Partial,
    /// Every observed member may activate.
    Enabled,
    /// Every observed member is administratively disabled.
    Disabled,
    /// Member policies disagree about their administrative state.
    Mixed,
}

impl PolicySetState {
    /// Stable operator-facing label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::Partial => "partial",
            Self::Enabled => "enabled",
            Self::Disabled => "disabled",
            Self::Mixed => "mixed",
        }
    }

    /// Whether this scope already has the requested state.
    #[must_use]
    pub const fn matches(self, enabled: bool) -> Option<bool> {
        match self {
            Self::Absent | Self::Partial => None,
            Self::Enabled => Some(enabled),
            Self::Disabled => Some(!enabled),
            Self::Mixed => Some(false),
        }
    }
}

/// One scope's member policies and aggregate state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicySetScope {
    /// Deterministically ordered member policy names.
    pub members: Vec<PolicyName>,
    /// Aggregate administrative state.
    pub state: PolicySetState,
}

impl PolicySetScope {
    fn from_policies(name: &PolicySetName, policies: &BTreeMap<PolicyName, PolicyDetails>) -> Self {
        let manifest = manifest(name);
        let prefix = format!("{}-", name.as_str());
        let members: Vec<_> = policies
            .keys()
            .filter(|policy| policy.as_str().starts_with(&prefix))
            .cloned()
            .collect();
        let manifest_complete = members.len() == manifest.len()
            && manifest.iter().all(|member| {
                PolicyName::parse(member)
                    .ok()
                    .is_some_and(|member| policies.contains_key(&member))
            });
        let disabled = members
            .iter()
            .filter(|policy| {
                policies
                    .get(*policy)
                    .is_some_and(|details| details.disabled)
            })
            .count();
        let state = match (members.len(), manifest_complete, disabled) {
            (0, _, _) => PolicySetState::Absent,
            (_, false, _) => PolicySetState::Partial,
            (total, true, 0) if total > 0 => PolicySetState::Enabled,
            (total, true, count) if total == count => PolicySetState::Disabled,
            _ => PolicySetState::Mixed,
        };
        Self { members, state }
    }
}

fn manifest(name: &PolicySetName) -> &'static [&'static str] {
    match name.as_str() {
        "gateway" => GATEWAY_POLICY_MEMBERS,
        _ => &[],
    }
}

/// Runtime and permanent state of one predefined policy set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicySetDetails {
    /// Validated set name used by `--policy-set`.
    pub name: PolicySetName,
    /// Live member policies.
    pub runtime: PolicySetScope,
    /// On-disk member policies.
    pub permanent: PolicySetScope,
}

impl PolicySetDetails {
    /// Derives a set from the policy snapshot.
    #[must_use]
    pub fn from_snapshot(snapshot: &super::FirewallSnapshot, name: PolicySetName) -> Self {
        Self {
            runtime: PolicySetScope::from_policies(&name, &snapshot.policies.runtime),
            permanent: PolicySetScope::from_policies(&name, &snapshot.policies.permanent),
            name,
        }
    }

    /// Whether `FWDeck` has an upstream manifest for this set.
    #[must_use]
    pub fn is_known(name: &PolicySetName) -> bool {
        KNOWN_POLICY_SETS.contains(&name.as_str())
    }

    /// All known set manifests, including absent ones so the UI can report a
    /// partial/missing installation honestly.
    #[must_use]
    pub fn known(snapshot: &super::FirewallSnapshot) -> Vec<Self> {
        KNOWN_POLICY_SETS
            .iter()
            .filter_map(|name| PolicySetName::parse(name).ok())
            .map(|name| Self::from_snapshot(snapshot, name))
            .collect()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::domain::mock;

    #[test]
    fn derives_scoped_gateway_members_and_mixed_state() {
        let mut snapshot = mock::sample().unwrap();
        for (index, name) in GATEWAY_POLICY_MEMBERS.iter().enumerate() {
            let name = PolicyName::parse(name).unwrap();
            let mut policy = PolicyDetails::empty(name.clone());
            policy.disabled = index == 0;
            snapshot
                .policies
                .runtime
                .insert(name.clone(), policy.clone());
            snapshot.policies.permanent.insert(name, policy);
        }

        let set =
            PolicySetDetails::from_snapshot(&snapshot, PolicySetName::parse("gateway").unwrap());
        assert_eq!(set.runtime.members.len(), GATEWAY_POLICY_MEMBERS.len());
        assert_eq!(set.runtime.state, PolicySetState::Mixed);
        assert_eq!(set.permanent.state, PolicySetState::Mixed);
    }

    #[test]
    fn partial_manifest_is_not_treated_as_safe_state() {
        let mut snapshot = mock::sample().unwrap();
        let name = PolicyName::parse(GATEWAY_POLICY_MEMBERS[0]).unwrap();
        let policy = PolicyDetails::empty(name.clone());
        snapshot.policies.runtime.insert(name, policy);

        let set =
            PolicySetDetails::from_snapshot(&snapshot, PolicySetName::parse("gateway").unwrap());
        assert_eq!(set.runtime.state, PolicySetState::Partial);
        assert_eq!(set.runtime.state.matches(true), None);
    }

    #[test]
    fn unexpected_prefixed_member_requires_a_manifest_update() {
        let mut snapshot = mock::sample().unwrap();
        for member in GATEWAY_POLICY_MEMBERS
            .iter()
            .copied()
            .chain(["gateway-new-upstream-member"])
        {
            let name = PolicyName::parse(member).unwrap();
            snapshot
                .policies
                .runtime
                .insert(name.clone(), PolicyDetails::empty(name));
        }

        let set =
            PolicySetDetails::from_snapshot(&snapshot, PolicySetName::parse("gateway").unwrap());
        assert_eq!(set.runtime.state, PolicySetState::Partial);
        assert!(
            set.runtime
                .members
                .iter()
                .any(|member| member.as_str() == "gateway-new-upstream-member")
        );
    }
}
