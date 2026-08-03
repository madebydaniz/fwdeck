//! Typed dependency edges from policy objects to zones and services.
//! Consumers use this graph for impact previews and fail-closed validation.

use std::collections::BTreeSet;

use super::{ConfigurationTarget, FirewallSnapshot, PolicyName, ServiceName};

/// The resource and direction referenced by one policy edge.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum PolicyDependencyResource {
    /// Traffic entering the policy from this zone.
    IngressZone(String),
    /// Traffic leaving the policy toward this zone.
    EgressZone(String),
    /// A service allowed by the policy.
    Service(ServiceName),
}

/// One typed policy dependency edge.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PolicyDependency {
    /// Policy that owns the reference.
    pub policy: PolicyName,
    /// Referenced resource and its role.
    pub resource: PolicyDependencyResource,
}

/// Deduplicated policy dependency graph for one configuration target.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PolicyDependencyGraph {
    dependencies: BTreeSet<PolicyDependency>,
}

impl PolicyDependencyGraph {
    /// Builds the graph from the selected snapshot configuration. Selecting
    /// both configurations returns the union, deduplicated by typed edge.
    #[must_use]
    pub fn from_snapshot(snapshot: &FirewallSnapshot, target: ConfigurationTarget) -> Self {
        let mut graph = Self::default();
        match target {
            ConfigurationTarget::Runtime => {
                graph.extend(snapshot.policies.runtime.values());
            }
            ConfigurationTarget::Permanent => {
                graph.extend(snapshot.policies.permanent.values());
            }
            ConfigurationTarget::RuntimeAndPermanent => {
                graph.extend(snapshot.policies.runtime.values());
                graph.extend(snapshot.policies.permanent.values());
            }
        }
        graph
    }

    fn extend<'a>(&mut self, policies: impl Iterator<Item = &'a super::PolicyDetails>) {
        for policy in policies {
            for zone in &policy.ingress_zones {
                self.dependencies.insert(PolicyDependency {
                    policy: policy.name.clone(),
                    resource: PolicyDependencyResource::IngressZone(zone.clone()),
                });
            }
            for zone in &policy.egress_zones {
                self.dependencies.insert(PolicyDependency {
                    policy: policy.name.clone(),
                    resource: PolicyDependencyResource::EgressZone(zone.clone()),
                });
            }
            for service in &policy.services {
                self.dependencies.insert(PolicyDependency {
                    policy: policy.name.clone(),
                    resource: PolicyDependencyResource::Service(service.clone()),
                });
            }
        }
    }

    /// All dependency edges in deterministic order.
    pub fn dependencies(&self) -> impl Iterator<Item = &PolicyDependency> {
        self.dependencies.iter()
    }

    /// Edges that reference a concrete zone as ingress or egress.
    pub fn references_zone<'a>(
        &'a self,
        zone: &'a str,
    ) -> impl Iterator<Item = &'a PolicyDependency> {
        self.dependencies.iter().filter(move |dependency| {
            matches!(
                &dependency.resource,
                PolicyDependencyResource::IngressZone(name)
                    | PolicyDependencyResource::EgressZone(name)
                    if name == zone
            )
        })
    }

    /// Edges that reference a service.
    pub fn references_service<'a>(
        &'a self,
        service: &'a ServiceName,
    ) -> impl Iterator<Item = &'a PolicyDependency> {
        self.dependencies.iter().filter(move |dependency| {
            matches!(
                &dependency.resource,
                PolicyDependencyResource::Service(name) if name == service
            )
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::domain::mock;

    #[test]
    fn graph_indexes_policy_zone_and_service_edges() {
        let snapshot = mock::sample().unwrap();
        let graph = PolicyDependencyGraph::from_snapshot(&snapshot, ConfigurationTarget::Permanent);
        let service = ServiceName::parse("http").unwrap();

        assert!(
            graph
                .references_zone("public")
                .any(|edge| edge.policy.as_str() == "mypolicy")
        );
        assert!(
            graph
                .references_service(&service)
                .any(|edge| edge.policy.as_str() == "mypolicy")
        );
        assert!(graph.dependencies().any(|edge| matches!(
            &edge.resource,
            PolicyDependencyResource::EgressZone(zone) if zone == "ANY"
        )));
    }

    #[test]
    fn both_target_deduplicates_identical_edges() {
        let snapshot = mock::sample().unwrap();
        let graph = PolicyDependencyGraph::from_snapshot(
            &snapshot,
            ConfigurationTarget::RuntimeAndPermanent,
        );

        assert_eq!(graph.dependencies().count(), 3);
    }
}
