//! Pure target-specific projection of reviewed firewall operations.

use std::collections::BTreeMap;
use std::sync::Arc;

use super::{
    CandidateIdentity, EvaluationPlanId, EvaluationSnapshotIdentity, EvaluationTarget,
    MutationIntentId, OrderedOperationDigest,
};
use crate::domain::{
    ActiveZone, AffectedObject, ConfigurationTarget, DegradedSection, FirewallOperation,
    FirewallSnapshot, OperationEffectSupport, OperationTargetSequence, PolicyDetails, PolicyName,
    PolicySetDetails, ServiceDefinition, ServiceName, TrafficDimension, UnsupportedOperationReason,
    ZoneDetails, ZoneName,
};

/// One traffic-relevant operation whose target state cannot be represented exactly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectionUnknownEffect {
    operation_index: usize,
    reason: UnsupportedOperationReason,
    object: AffectedObject,
    dimensions: Vec<TrafficDimension>,
}

impl ProjectionUnknownEffect {
    /// Returns the zero-based position in the reviewed operation sequence.
    #[must_use]
    pub const fn operation_index(&self) -> usize {
        self.operation_index
    }

    /// Returns why this operation cannot be projected exactly.
    #[must_use]
    pub const fn reason(&self) -> UnsupportedOperationReason {
        self.reason
    }

    /// Returns the affected firewall object.
    #[must_use]
    pub const fn object(&self) -> &AffectedObject {
        &self.object
    }

    /// Returns the traffic dimensions that may have changed.
    #[must_use]
    pub fn dimensions(&self) -> &[TrafficDimension] {
        &self.dimensions
    }
}

/// One immutable target-specific candidate plus any typed uncertainty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateProjection {
    identity: CandidateIdentity,
    snapshot: Arc<FirewallSnapshot>,
    unknown_effects: Vec<ProjectionUnknownEffect>,
}

impl CandidateProjection {
    /// Returns the candidate correlation identity.
    #[must_use]
    pub const fn identity(&self) -> CandidateIdentity {
        self.identity
    }

    /// Returns the projected target-specific snapshot.
    #[must_use]
    pub fn snapshot(&self) -> &FirewallSnapshot {
        &self.snapshot
    }

    /// Returns the immutable projected snapshot allocation.
    #[must_use]
    pub const fn snapshot_arc(&self) -> &Arc<FirewallSnapshot> {
        &self.snapshot
    }

    /// Returns operations that prevent an exact verdict for affected scenarios.
    #[must_use]
    pub fn unknown_effects(&self) -> &[ProjectionUnknownEffect] {
        &self.unknown_effects
    }

    /// Whether every traffic-relevant effect was represented exactly.
    #[must_use]
    pub fn is_exact(&self) -> bool {
        self.unknown_effects.is_empty()
    }
}

/// Candidate projection failed before a target snapshot could be produced.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CandidateProjectionError {
    /// An operation sequence could not be encoded for identity correlation.
    #[error("failed to encode operation {operation_index} for candidate identity")]
    OperationEncoding {
        /// Zero-based operation position.
        operation_index: usize,
    },
    /// A zone mutation referenced no object in one required scope.
    #[error("zone `{zone}` is missing from the {target} candidate")]
    MissingZone {
        /// Required target.
        target: &'static str,
        /// Missing identity.
        zone: ZoneName,
    },
    /// A policy mutation referenced no object in one required scope.
    #[error("policy `{policy}` is missing from the {target} candidate")]
    MissingPolicy {
        /// Required target.
        target: &'static str,
        /// Missing identity.
        policy: PolicyName,
    },
    /// A service-definition mutation referenced no permanent object.
    #[error("service definition `{service}` is missing from the permanent candidate")]
    MissingServiceDefinition {
        /// Missing identity.
        service: ServiceName,
    },
    /// A lifecycle operation would overwrite an existing object.
    #[error("{kind} `{name}` already exists in the permanent candidate")]
    ObjectAlreadyExists {
        /// Object family.
        kind: &'static str,
        /// Stable object name.
        name: String,
    },
}

/// Pure candidate projection entry point.
pub struct CandidateProjector;

impl CandidateProjector {
    /// Applies ordered operations to a private clone and emits one exact target view.
    pub fn project(
        base: &Arc<FirewallSnapshot>,
        base_snapshot_identity: EvaluationSnapshotIdentity,
        mutation_intent_id: MutationIntentId,
        plan_id: Option<EvaluationPlanId>,
        target: EvaluationTarget,
        operations: &[FirewallOperation],
    ) -> Result<CandidateProjection, CandidateProjectionError> {
        let operation_bytes = operations
            .iter()
            .enumerate()
            .map(|(operation_index, operation)| {
                serde_json::to_vec(operation)
                    .map_err(|_| CandidateProjectionError::OperationEncoding { operation_index })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let digest =
            OrderedOperationDigest::from_ordered_bytes(operation_bytes.iter().map(Vec::as_slice));
        let identity = CandidateIdentity::new(
            base_snapshot_identity,
            mutation_intent_id,
            plan_id,
            target,
            digest,
        );

        let mut state = ProjectionState::new(base);
        for (operation_index, operation) in operations.iter().enumerate() {
            state.apply(operation_index, operation)?;
        }

        let (snapshot, unknown_effects) = state.finish(base, target);
        Ok(CandidateProjection {
            identity,
            snapshot: Arc::new(snapshot),
            unknown_effects,
        })
    }
}

struct ProjectionState {
    snapshot: FirewallSnapshot,
    service_definitions_runtime: BTreeMap<ServiceName, ServiceDefinition>,
    service_definitions_permanent: BTreeMap<ServiceName, ServiceDefinition>,
    available_services_runtime: Vec<ServiceName>,
    available_services_permanent: Vec<ServiceName>,
    unknown_runtime: Vec<ProjectionUnknownEffect>,
    unknown_permanent: Vec<ProjectionUnknownEffect>,
    degraded_runtime: Vec<DegradedSection>,
    degraded_permanent: Vec<DegradedSection>,
}

impl ProjectionState {
    fn new(base: &FirewallSnapshot) -> Self {
        Self {
            snapshot: base.clone(),
            service_definitions_runtime: base.service_definitions.clone(),
            service_definitions_permanent: base.service_definitions.clone(),
            available_services_runtime: base.available_services.clone(),
            available_services_permanent: base.available_services.clone(),
            unknown_runtime: Vec::new(),
            unknown_permanent: Vec::new(),
            degraded_runtime: degraded_for(base, ConfigurationTarget::Runtime),
            degraded_permanent: degraded_for(base, ConfigurationTarget::Permanent),
        }
    }

    fn apply(
        &mut self,
        operation_index: usize,
        operation: &FirewallOperation,
    ) -> Result<(), CandidateProjectionError> {
        let effect = operation.effect();
        match effect.support {
            OperationEffectSupport::UnsupportedRelevant(reason) => {
                let marker = ProjectionUnknownEffect {
                    operation_index,
                    reason,
                    object: effect.object,
                    dimensions: effect.dimensions,
                };
                self.mark_unknown(effect.targets, marker);
                return Ok(());
            }
            OperationEffectSupport::TrafficIrrelevant(_) => return Ok(()),
            OperationEffectSupport::GlobalTransform => {
                self.apply_global(operation);
                return Ok(());
            }
            OperationEffectSupport::SupportedExact
            | OperationEffectSupport::SupportedAtEvaluationInstant => {}
        }

        self.apply_exact(operation)
    }

    fn mark_unknown(&mut self, targets: OperationTargetSequence, marker: ProjectionUnknownEffect) {
        match targets {
            OperationTargetSequence::Runtime => self.unknown_runtime.push(marker),
            OperationTargetSequence::Permanent => self.unknown_permanent.push(marker),
            OperationTargetSequence::RuntimeThenPermanent
            | OperationTargetSequence::RuntimeAndPermanent => {
                self.unknown_runtime.push(marker.clone());
                self.unknown_permanent.push(marker);
            }
            OperationTargetSequence::RuntimeFromPermanent => {
                self.unknown_runtime = self.unknown_permanent.clone();
            }
            OperationTargetSequence::PermanentFromRuntime => {
                self.unknown_permanent = self.unknown_runtime.clone();
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    fn apply_exact(
        &mut self,
        operation: &FirewallOperation,
    ) -> Result<(), CandidateProjectionError> {
        match operation {
            FirewallOperation::AddService {
                zone,
                service,
                target,
            } => self.edit_zones(*target, zone, |details| {
                push_unique(&mut details.services, service.clone());
            })?,
            FirewallOperation::AddTemporaryService { zone, service, .. } => {
                self.edit_zones(ConfigurationTarget::Runtime, zone, |details| {
                    push_unique(&mut details.services, service.clone());
                })?;
            }
            FirewallOperation::RemoveService {
                zone,
                service,
                target,
            } => self.edit_zones(*target, zone, |details| {
                details.services.retain(|entry| entry != service);
            })?,
            FirewallOperation::AddPort { zone, port, target } => {
                self.edit_zones(*target, zone, |details| {
                    push_unique(&mut details.ports, *port);
                })?;
            }
            FirewallOperation::RemovePort { zone, port, target } => {
                self.edit_zones(*target, zone, |details| {
                    details.ports.retain(|entry| entry != port);
                })?;
            }
            FirewallOperation::SetDefaultZone { zone } => {
                self.snapshot.default_zone.clone_from(zone);
            }
            FirewallOperation::SetMasquerade {
                zone,
                enabled,
                target,
            } => self.edit_zones(*target, zone, |details| details.masquerade = *enabled)?,
            FirewallOperation::SetZoneTarget { zone, zone_target } => {
                self.edit_zones(ConfigurationTarget::Permanent, zone, |details| {
                    details.target = *zone_target;
                })?;
            }
            FirewallOperation::AddSourcePort { zone, port, target } => {
                self.edit_zones(*target, zone, |details| {
                    push_unique(&mut details.source_ports, *port);
                })?;
            }
            FirewallOperation::RemoveSourcePort { zone, port, target } => {
                self.edit_zones(*target, zone, |details| {
                    details.source_ports.retain(|entry| entry != port);
                })?;
            }
            FirewallOperation::AddProtocol {
                zone,
                protocol,
                target,
            } => self.edit_zones(*target, zone, |details| {
                push_unique(&mut details.protocols, protocol.clone());
            })?,
            FirewallOperation::RemoveProtocol {
                zone,
                protocol,
                target,
            } => self.edit_zones(*target, zone, |details| {
                details.protocols.retain(|entry| entry != protocol);
            })?,
            FirewallOperation::SetForward {
                zone,
                enabled,
                target,
            } => self.edit_zones(*target, zone, |details| details.forward = *enabled)?,
            FirewallOperation::SetIcmpBlockInversion {
                zone,
                enabled,
                target,
            } => self.edit_zones(*target, zone, |details| {
                details.icmp_block_inversion = *enabled;
            })?,
            FirewallOperation::AddForwardPort {
                zone,
                forward,
                target,
            } => self.edit_zones(*target, zone, |details| {
                push_unique(&mut details.forward_ports, forward.clone());
            })?,
            FirewallOperation::RemoveForwardPort {
                zone,
                forward,
                target,
            } => self.edit_zones(*target, zone, |details| {
                details.forward_ports.retain(|entry| entry != forward);
            })?,
            FirewallOperation::AddRichRule { zone, rule, target } => {
                self.edit_zones(*target, zone, |details| {
                    push_unique(&mut details.rich_rules, rule.clone());
                })?;
            }
            FirewallOperation::RemoveRichRule { zone, rule, target } => {
                self.edit_zones(*target, zone, |details| {
                    details.rich_rules.retain(|entry| entry != rule);
                })?;
            }
            FirewallOperation::AddInterface {
                zone,
                interface,
                target,
            } => self.edit_zones(*target, zone, |details| {
                push_unique(&mut details.interfaces, interface.clone());
            })?,
            FirewallOperation::RemoveInterface {
                zone,
                interface,
                target,
            } => self.edit_zones(*target, zone, |details| {
                details.interfaces.retain(|entry| entry != interface);
            })?,
            FirewallOperation::AddSource {
                zone,
                source,
                target,
            } => self.edit_zones(*target, zone, |details| {
                push_unique(&mut details.sources, source.clone());
            })?,
            FirewallOperation::RemoveSource {
                zone,
                source,
                target,
            } => self.edit_zones(*target, zone, |details| {
                details.sources.retain(|entry| entry != source);
            })?,
            FirewallOperation::AddIcmpBlock { zone, icmp, target } => {
                self.edit_zones(*target, zone, |details| {
                    push_unique(&mut details.icmp_blocks, icmp.clone());
                })?;
            }
            FirewallOperation::RemoveIcmpBlock { zone, icmp, target } => {
                self.edit_zones(*target, zone, |details| {
                    details.icmp_blocks.retain(|entry| entry != icmp);
                })?;
            }
            FirewallOperation::CreateService { service } => {
                if self.service_definitions_permanent.contains_key(service) {
                    return Err(CandidateProjectionError::ObjectAlreadyExists {
                        kind: "service definition",
                        name: service.to_string(),
                    });
                }
                self.service_definitions_permanent
                    .insert(service.clone(), ServiceDefinition::default());
                push_unique(&mut self.available_services_permanent, service.clone());
            }
            FirewallOperation::DeleteService { service } => {
                if self.service_definitions_permanent.remove(service).is_none() {
                    return Err(CandidateProjectionError::MissingServiceDefinition {
                        service: service.clone(),
                    });
                }
                self.available_services_permanent
                    .retain(|entry| entry != service);
            }
            FirewallOperation::AddServicePort { service, port } => {
                let definition = self
                    .service_definitions_permanent
                    .get_mut(service)
                    .ok_or_else(|| CandidateProjectionError::MissingServiceDefinition {
                        service: service.clone(),
                    })?;
                push_unique(&mut definition.ports, *port);
            }
            FirewallOperation::RemoveServicePort { service, port } => {
                let definition = self
                    .service_definitions_permanent
                    .get_mut(service)
                    .ok_or_else(|| CandidateProjectionError::MissingServiceDefinition {
                        service: service.clone(),
                    })?;
                definition.ports.retain(|entry| entry != port);
            }
            FirewallOperation::CreatePolicy { policy } => {
                if self.snapshot.policies.permanent.contains_key(policy) {
                    return Err(CandidateProjectionError::ObjectAlreadyExists {
                        kind: "policy",
                        name: policy.to_string(),
                    });
                }
                self.snapshot
                    .policies
                    .permanent
                    .insert(policy.clone(), PolicyDetails::empty(policy.clone()));
            }
            FirewallOperation::DeletePolicy { policy } => {
                self.require_policy(ConfigurationTarget::Permanent, policy)?;
                self.snapshot.policies.permanent.remove(policy);
            }
            FirewallOperation::SetPolicyTarget {
                policy,
                policy_target,
            } => self.edit_policies(ConfigurationTarget::Permanent, policy, |details| {
                details.target = *policy_target;
            })?,
            FirewallOperation::AddPolicyIngressZone { policy, zone } => {
                self.edit_policies(ConfigurationTarget::Permanent, policy, |details| {
                    push_unique(&mut details.ingress_zones, zone.clone());
                })?;
            }
            FirewallOperation::AddPolicyEgressZone { policy, zone } => {
                self.edit_policies(ConfigurationTarget::Permanent, policy, |details| {
                    push_unique(&mut details.egress_zones, zone.clone());
                })?;
            }
            FirewallOperation::AddPolicyService {
                policy,
                service,
                target,
            } => self.edit_policies(*target, policy, |details| {
                push_unique(&mut details.services, service.clone());
            })?,
            FirewallOperation::RemovePolicyService {
                policy,
                service,
                target,
            } => self.edit_policies(*target, policy, |details| {
                details.services.retain(|entry| entry != service);
            })?,
            FirewallOperation::SetPolicySetEnabled {
                policy_set,
                enabled,
                target,
            } => self.edit_policy_set(*target, policy_set, *enabled),
            FirewallOperation::CreateZone { zone } => {
                if self.snapshot.permanent.contains_key(zone) {
                    return Err(CandidateProjectionError::ObjectAlreadyExists {
                        kind: "zone",
                        name: zone.to_string(),
                    });
                }
                self.snapshot
                    .permanent
                    .insert(zone.clone(), ZoneDetails::empty(zone.clone()));
            }
            FirewallOperation::DeleteZone { zone } => {
                self.require_zone(ConfigurationTarget::Permanent, zone)?;
                self.snapshot.permanent.remove(zone);
            }
            FirewallOperation::SetPanicMode { enabled } => {
                self.snapshot.status.panic_mode = *enabled;
            }
            FirewallOperation::MigrateDirectRule { .. }
            | FirewallOperation::CreateIpSet { .. }
            | FirewallOperation::DeleteIpSet { .. }
            | FirewallOperation::AddIpSetEntry { .. }
            | FirewallOperation::RemoveIpSetEntry { .. }
            | FirewallOperation::RuntimeToPermanent
            | FirewallOperation::SetLogDenied { .. }
            | FirewallOperation::Reload => unreachable!("handled by effect metadata"),
        }
        Ok(())
    }

    fn apply_global(&mut self, operation: &FirewallOperation) {
        match operation {
            FirewallOperation::Reload | FirewallOperation::SetLogDenied { .. } => {
                self.snapshot.runtime = self.snapshot.permanent.clone();
                self.snapshot.policies.runtime = self.snapshot.policies.permanent.clone();
                self.snapshot.ipsets.runtime = self.snapshot.ipsets.permanent.clone();
                self.service_definitions_runtime = self.service_definitions_permanent.clone();
                self.available_services_runtime = self.available_services_permanent.clone();
                self.unknown_runtime = self.unknown_permanent.clone();
                self.degraded_runtime = self.degraded_permanent.clone();
                self.rebuild_active();
                self.refresh_runtime_policy_activity();
            }
            FirewallOperation::RuntimeToPermanent => {
                self.snapshot.permanent = self.snapshot.runtime.clone();
                self.snapshot.policies.permanent = self.snapshot.policies.runtime.clone();
                for policy in self.snapshot.policies.permanent.values_mut() {
                    policy.active = false;
                }
                self.snapshot.ipsets.permanent = self.snapshot.ipsets.runtime.clone();
                self.service_definitions_permanent = self.service_definitions_runtime.clone();
                self.available_services_permanent = self.available_services_runtime.clone();
                self.unknown_permanent = self.unknown_runtime.clone();
                self.degraded_permanent = self.degraded_runtime.clone();
            }
            _ => unreachable!("global effect metadata must match a global operation"),
        }
    }

    fn edit_zones(
        &mut self,
        target: ConfigurationTarget,
        zone: &ZoneName,
        mut edit: impl FnMut(&mut ZoneDetails),
    ) -> Result<(), CandidateProjectionError> {
        if matches!(
            target,
            ConfigurationTarget::Runtime | ConfigurationTarget::RuntimeAndPermanent
        ) {
            let details = self.snapshot.runtime.get_mut(zone).ok_or_else(|| {
                CandidateProjectionError::MissingZone {
                    target: "runtime",
                    zone: zone.clone(),
                }
            })?;
            edit(details);
            self.sync_active_zone(zone);
        }
        if matches!(
            target,
            ConfigurationTarget::Permanent | ConfigurationTarget::RuntimeAndPermanent
        ) {
            let details = self.snapshot.permanent.get_mut(zone).ok_or_else(|| {
                CandidateProjectionError::MissingZone {
                    target: "permanent",
                    zone: zone.clone(),
                }
            })?;
            edit(details);
        }
        Ok(())
    }

    fn edit_policies(
        &mut self,
        target: ConfigurationTarget,
        policy: &PolicyName,
        mut edit: impl FnMut(&mut PolicyDetails),
    ) -> Result<(), CandidateProjectionError> {
        if matches!(
            target,
            ConfigurationTarget::Runtime | ConfigurationTarget::RuntimeAndPermanent
        ) {
            let details = self
                .snapshot
                .policies
                .runtime
                .get_mut(policy)
                .ok_or_else(|| CandidateProjectionError::MissingPolicy {
                    target: "runtime",
                    policy: policy.clone(),
                })?;
            edit(details);
        }
        if matches!(
            target,
            ConfigurationTarget::Permanent | ConfigurationTarget::RuntimeAndPermanent
        ) {
            let details = self
                .snapshot
                .policies
                .permanent
                .get_mut(policy)
                .ok_or_else(|| CandidateProjectionError::MissingPolicy {
                    target: "permanent",
                    policy: policy.clone(),
                })?;
            edit(details);
        }
        Ok(())
    }

    fn edit_policy_set(
        &mut self,
        target: ConfigurationTarget,
        policy_set: &crate::domain::PolicySetName,
        enabled: bool,
    ) {
        let set = PolicySetDetails::from_snapshot(&self.snapshot, policy_set.clone());
        if matches!(
            target,
            ConfigurationTarget::Runtime | ConfigurationTarget::RuntimeAndPermanent
        ) {
            for name in &set.runtime.members {
                if let Some(policy) = self.snapshot.policies.runtime.get_mut(name) {
                    policy.disabled = !enabled;
                }
            }
        }
        if matches!(
            target,
            ConfigurationTarget::Permanent | ConfigurationTarget::RuntimeAndPermanent
        ) {
            for name in &set.permanent.members {
                if let Some(policy) = self.snapshot.policies.permanent.get_mut(name) {
                    policy.disabled = !enabled;
                }
            }
        }
    }

    fn require_zone(
        &self,
        target: ConfigurationTarget,
        zone: &ZoneName,
    ) -> Result<(), CandidateProjectionError> {
        let (label, exists) = match target {
            ConfigurationTarget::Runtime => ("runtime", self.snapshot.runtime.contains_key(zone)),
            ConfigurationTarget::Permanent => {
                ("permanent", self.snapshot.permanent.contains_key(zone))
            }
            ConfigurationTarget::RuntimeAndPermanent => (
                "runtime + permanent",
                self.snapshot.runtime.contains_key(zone)
                    && self.snapshot.permanent.contains_key(zone),
            ),
        };
        exists
            .then_some(())
            .ok_or_else(|| CandidateProjectionError::MissingZone {
                target: label,
                zone: zone.clone(),
            })
    }

    fn require_policy(
        &self,
        target: ConfigurationTarget,
        policy: &PolicyName,
    ) -> Result<(), CandidateProjectionError> {
        let (label, exists) = match target {
            ConfigurationTarget::Runtime => (
                "runtime",
                self.snapshot.policies.runtime.contains_key(policy),
            ),
            ConfigurationTarget::Permanent => (
                "permanent",
                self.snapshot.policies.permanent.contains_key(policy),
            ),
            ConfigurationTarget::RuntimeAndPermanent => (
                "runtime + permanent",
                self.snapshot.policies.runtime.contains_key(policy)
                    && self.snapshot.policies.permanent.contains_key(policy),
            ),
        };
        exists
            .then_some(())
            .ok_or_else(|| CandidateProjectionError::MissingPolicy {
                target: label,
                policy: policy.clone(),
            })
    }

    fn sync_active_zone(&mut self, zone: &ZoneName) {
        let Some(details) = self.snapshot.runtime.get(zone) else {
            self.snapshot.active.remove(zone);
            return;
        };
        if details.interfaces.is_empty() && details.sources.is_empty() {
            self.snapshot.active.remove(zone);
        } else {
            self.snapshot.active.insert(
                zone.clone(),
                ActiveZone {
                    interfaces: details.interfaces.clone(),
                    sources: details.sources.clone(),
                },
            );
        }
    }

    fn rebuild_active(&mut self) {
        self.snapshot.active = self
            .snapshot
            .runtime
            .iter()
            .filter(|(_, details)| !details.interfaces.is_empty() || !details.sources.is_empty())
            .map(|(name, details)| {
                (
                    name.clone(),
                    ActiveZone {
                        interfaces: details.interfaces.clone(),
                        sources: details.sources.clone(),
                    },
                )
            })
            .collect();
    }

    fn refresh_runtime_policy_activity(&mut self) {
        let active_zones = self.snapshot.active.clone();
        let has_active_zone = !active_zones.is_empty();
        for policy in self.snapshot.policies.runtime.values_mut() {
            let side_active = |zones: &[String]| {
                zones.iter().any(|zone| {
                    zone == "HOST"
                        || (zone == "ANY" && has_active_zone)
                        || ZoneName::parse(zone).is_ok_and(|zone| active_zones.contains_key(&zone))
                })
            };
            policy.active = side_active(&policy.ingress_zones) && side_active(&policy.egress_zones);
        }
    }

    fn finish(
        self,
        base: &FirewallSnapshot,
        target: EvaluationTarget,
    ) -> (FirewallSnapshot, Vec<ProjectionUnknownEffect>) {
        let mut candidate = base.clone();
        candidate.default_zone = self.snapshot.default_zone;
        match target {
            EvaluationTarget::Runtime => {
                candidate.runtime = self.snapshot.runtime;
                candidate.active = self.snapshot.active;
                candidate.policies.runtime = self.snapshot.policies.runtime;
                candidate.ipsets.runtime = self.snapshot.ipsets.runtime;
                candidate.status.panic_mode = self.snapshot.status.panic_mode;
                candidate.service_definitions = self.service_definitions_runtime;
                candidate.available_services = self.available_services_runtime;
                candidate.degraded = normalize_degraded(self.degraded_runtime, target);
                (candidate, self.unknown_runtime)
            }
            EvaluationTarget::Permanent => {
                candidate.permanent = self.snapshot.permanent;
                candidate.policies.permanent = self.snapshot.policies.permanent;
                candidate.ipsets.permanent = self.snapshot.ipsets.permanent;
                candidate.service_definitions = self.service_definitions_permanent;
                candidate.available_services = self.available_services_permanent;
                candidate.degraded = normalize_degraded(self.degraded_permanent, target);
                (candidate, self.unknown_permanent)
            }
        }
    }
}

fn degraded_for(snapshot: &FirewallSnapshot, target: ConfigurationTarget) -> Vec<DegradedSection> {
    snapshot
        .degraded
        .iter()
        .filter(|record| {
            record.target.is_none()
                || record.target == Some(target)
                || record.target == Some(ConfigurationTarget::RuntimeAndPermanent)
        })
        .cloned()
        .collect()
}

fn normalize_degraded(
    records: Vec<DegradedSection>,
    target: EvaluationTarget,
) -> Vec<DegradedSection> {
    let target = match target {
        EvaluationTarget::Runtime => ConfigurationTarget::Runtime,
        EvaluationTarget::Permanent => ConfigurationTarget::Permanent,
    };
    records
        .into_iter()
        .map(|mut record| {
            if record.target.is_some() {
                record.target = Some(target);
            }
            record
        })
        .collect()
}

fn push_unique<T: PartialEq>(values: &mut Vec<T>, value: T) {
    if !values.contains(&value) {
        values.push(value);
    }
}
