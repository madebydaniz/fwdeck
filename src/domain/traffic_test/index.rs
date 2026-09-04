//! Immutable, target-specific lookup structure for native traffic evaluation.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use super::{EvaluationTarget, RulePriority};
use crate::domain::{
    ConfigurationTarget, FirewallSnapshot, InterfaceName, PolicyDetails, PolicyName, ServiceName,
    ServiceResolution, SnapshotSection, SourceAddress, ZoneDetails, ZoneName,
    resolve_service_includes,
};

/// Exact binding evidence used to classify ingress traffic.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum IndexedZoneBindingKind {
    /// Source address or CIDR binding.
    Source(SourceAddress),
    /// Network-interface binding.
    Interface(InterfaceName),
}

/// One target-specific zone binding with its classification priority.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct IndexedZoneBinding {
    ingress_priority: RulePriority,
    zone: ZoneName,
    kind: IndexedZoneBindingKind,
}

impl IndexedZoneBinding {
    /// Returns the zone's signed ingress priority.
    #[must_use]
    pub const fn ingress_priority(&self) -> RulePriority {
        self.ingress_priority
    }

    /// Returns the bound zone.
    #[must_use]
    pub const fn zone(&self) -> &ZoneName {
        &self.zone
    }

    /// Returns source or interface binding evidence.
    #[must_use]
    pub const fn kind(&self) -> &IndexedZoneBindingKind {
        &self.kind
    }
}

/// Precomputed immutable view of one authoritative snapshot target.
#[derive(Debug, Clone)]
pub struct TrafficEvaluationIndex {
    snapshot: Arc<FirewallSnapshot>,
    target: EvaluationTarget,
    zone_order: Vec<ZoneName>,
    zone_bindings: Vec<IndexedZoneBinding>,
    policy_order: Vec<PolicyName>,
    services: BTreeMap<ServiceName, ServiceResolution>,
}

impl TrafficEvaluationIndex {
    /// Builds deterministic lookups without changing the authoritative snapshot.
    #[must_use]
    pub fn new(snapshot: Arc<FirewallSnapshot>, target: EvaluationTarget) -> Self {
        let zones = zones_for(&snapshot, target);
        let policies = policies_for(&snapshot, target);

        let mut zone_order: Vec<ZoneName> = zones.keys().cloned().collect();
        zone_order.sort_by(|left, right| {
            zones[left]
                .ingress_priority
                .cmp(&zones[right].ingress_priority)
                .then_with(|| left.cmp(right))
        });

        let mut zone_bindings = Vec::new();
        for zone in zones.values() {
            zone_bindings.extend(
                zone.sources
                    .iter()
                    .cloned()
                    .map(|source| IndexedZoneBinding {
                        ingress_priority: zone.ingress_priority,
                        zone: zone.name.clone(),
                        kind: IndexedZoneBindingKind::Source(source),
                    }),
            );
            zone_bindings.extend(zone.interfaces.iter().cloned().map(|interface| {
                IndexedZoneBinding {
                    ingress_priority: zone.ingress_priority,
                    zone: zone.name.clone(),
                    kind: IndexedZoneBindingKind::Interface(interface),
                }
            }));
        }
        zone_bindings.sort();

        let mut policy_order: Vec<PolicyName> = policies.keys().cloned().collect();
        policy_order.sort_by(|left, right| {
            policies[left]
                .priority
                .cmp(&policies[right].priority)
                .then_with(|| left.cmp(right))
        });

        let mut referenced_services = BTreeSet::new();
        referenced_services.extend(
            zones
                .values()
                .flat_map(|zone| zone.services.iter().cloned()),
        );
        referenced_services.extend(
            policies
                .values()
                .flat_map(|policy| policy.services.iter().cloned()),
        );
        let services = referenced_services
            .into_iter()
            .map(|name| {
                let resolution = resolve_service_includes(&name, &snapshot.service_definitions);
                (name, resolution)
            })
            .collect();

        Self {
            snapshot,
            target,
            zone_order,
            zone_bindings,
            policy_order,
            services,
        }
    }

    /// Returns the exact runtime or permanent target represented by the index.
    #[must_use]
    pub const fn target(&self) -> EvaluationTarget {
        self.target
    }

    /// Returns the same authoritative snapshot allocation supplied at construction.
    #[must_use]
    pub const fn snapshot_arc(&self) -> &Arc<FirewallSnapshot> {
        &self.snapshot
    }

    /// Returns target-specific zones by stable identity.
    #[must_use]
    pub fn zones(&self) -> &BTreeMap<ZoneName, ZoneDetails> {
        zones_for(&self.snapshot, self.target)
    }

    /// Returns one target-specific zone.
    #[must_use]
    pub fn zone(&self, name: &ZoneName) -> Option<&ZoneDetails> {
        self.zones().get(name)
    }

    /// Returns zone identities sorted by ingress priority then name.
    #[must_use]
    pub fn zone_order(&self) -> &[ZoneName] {
        &self.zone_order
    }

    /// Returns source and interface bindings in deterministic priority order.
    #[must_use]
    pub fn zone_bindings(&self) -> &[IndexedZoneBinding] {
        &self.zone_bindings
    }

    /// Returns target-specific policies by stable identity.
    #[must_use]
    pub fn policies(&self) -> &BTreeMap<PolicyName, PolicyDetails> {
        policies_for(&self.snapshot, self.target)
    }

    /// Returns one target-specific policy.
    #[must_use]
    pub fn policy(&self, name: &PolicyName) -> Option<&PolicyDetails> {
        self.policies().get(name)
    }

    /// Returns policy identities sorted by signed priority then name.
    #[must_use]
    pub fn policy_order(&self) -> &[PolicyName] {
        &self.policy_order
    }

    /// Returns pre-expanded effective service semantics and typed failures.
    #[must_use]
    pub fn service(&self, name: &ServiceName) -> Option<&ServiceResolution> {
        self.services.get(name)
    }

    /// Returns all target-referenced pre-expanded services.
    #[must_use]
    pub const fn services(&self) -> &BTreeMap<ServiceName, ServiceResolution> {
        &self.services
    }

    /// Whether one required snapshot section is complete for this exact target.
    #[must_use]
    pub fn section_is_complete(&self, section: SnapshotSection) -> bool {
        self.snapshot
            .section_is_complete(section, configuration_target(self.target))
    }

    /// Preserves raw direct-rule evidence for strict-truth checks.
    #[must_use]
    pub fn direct_rules(&self) -> &[String] {
        &self.snapshot.direct_rules
    }

    /// Whether rules outside the modeled zone/policy path may intersect traffic.
    #[must_use]
    pub fn has_direct_rules(&self) -> bool {
        !self.direct_rules().is_empty()
    }
}

fn zones_for(
    snapshot: &FirewallSnapshot,
    target: EvaluationTarget,
) -> &BTreeMap<ZoneName, ZoneDetails> {
    match target {
        EvaluationTarget::Runtime => &snapshot.runtime,
        EvaluationTarget::Permanent => &snapshot.permanent,
    }
}

fn policies_for(
    snapshot: &FirewallSnapshot,
    target: EvaluationTarget,
) -> &BTreeMap<PolicyName, PolicyDetails> {
    match target {
        EvaluationTarget::Runtime => &snapshot.policies.runtime,
        EvaluationTarget::Permanent => &snapshot.policies.permanent,
    }
}

const fn configuration_target(target: EvaluationTarget) -> ConfigurationTarget {
    match target {
        EvaluationTarget::Runtime => ConfigurationTarget::Runtime,
        EvaluationTarget::Permanent => ConfigurationTarget::Permanent,
    }
}
