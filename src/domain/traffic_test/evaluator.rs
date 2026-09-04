//! Pure, fail-closed evaluation for the initial host-ingress traffic path.

use std::collections::BTreeSet;
use std::net::IpAddr;

use super::{
    EvaluationContext, EvaluationTarget, FirewallDecision, IndexedZoneBindingKind,
    TrafficConnectionState, TrafficDestination, TrafficDirection, TrafficEvaluationIndex,
    TrafficExpectation, TrafficReportError, TrafficScenario, TrafficTestResult, TrafficTestStatus,
    TrafficTraceOutcome, TrafficTraceStage, TrafficTraceStep, TrafficTransport,
    TrafficValidationError, UnknownReason,
};
use crate::domain::{
    FeatureSupport, FirewalldFeature, PolicyDetails, PortSelector, Protocol, ServiceDefinition,
    SnapshotSection, SourceAddress, TraceObjectRef, ZoneDetails, ZoneName, ZoneTarget,
};

/// Failure to evaluate an invalid input contract or construct a bounded result.
#[derive(Debug, thiserror::Error)]
pub enum TrafficEvaluationError {
    /// The scenario bypassed suite validation or was mutated after validation.
    #[error("invalid traffic scenario: {0}")]
    InvalidScenario(#[from] TrafficValidationError),
    /// The evaluation identity or bounded report contract was invalid.
    #[error("invalid traffic evaluation contract: {0}")]
    Report(#[from] TrafficReportError),
}

/// Evaluates one validated scenario against one immutable target-specific index.
pub fn evaluate_scenario(
    index: &TrafficEvaluationIndex,
    scenario: &TrafficScenario,
    context: &EvaluationContext,
) -> Result<TrafficTestResult, TrafficEvaluationError> {
    scenario.validate()?;
    context.validate()?;

    let mut trace = vec![TrafficTraceStep::new(
        TrafficTraceStage::ScenarioNormalization,
        TrafficTraceOutcome::Matched,
    )];
    if context.target != index.target() {
        return unknown(
            scenario,
            trace,
            TrafficTraceStage::IdentityCheck,
            UnknownReason::StaleSnapshot,
        );
    }
    trace.push(TrafficTraceStep::new(
        TrafficTraceStage::IdentityCheck,
        TrafficTraceOutcome::Matched,
    ));

    if scenario.direction != TrafficDirection::ToHost {
        return unknown(
            scenario,
            trace,
            TrafficTraceStage::PathResolution,
            UnknownReason::UnsupportedDirection,
        );
    }
    if scenario.connection_state != TrafficConnectionState::New {
        return unknown(
            scenario,
            trace,
            TrafficTraceStage::PathResolution,
            UnknownReason::UnsupportedConnectionState,
        );
    }
    trace.push(TrafficTraceStep::new(
        TrafficTraceStage::PathResolution,
        TrafficTraceOutcome::Selected,
    ));

    if !index.section_is_complete(SnapshotSection::Zones)
        || !index.snapshot_arc().status.daemon_running
    {
        return unknown_with_object(
            scenario,
            trace,
            TrafficTraceStage::CompletenessCheck,
            UnknownReason::IncompleteSnapshot,
            TraceObjectRef::SnapshotSection(SnapshotSection::Zones),
        );
    }
    trace.push(
        TrafficTraceStep::new(
            TrafficTraceStage::CompletenessCheck,
            TrafficTraceOutcome::Matched,
        )
        .with_object(TraceObjectRef::SnapshotSection(SnapshotSection::Zones)),
    );

    if index.target() == EvaluationTarget::Runtime && index.snapshot_arc().status.panic_mode {
        return finish(scenario, trace, FirewallDecision::Block, None);
    }

    let selected_zone = match resolve_ingress(index, scenario, &mut trace) {
        Ok(zone) => zone,
        Err(reason) => {
            return unknown(
                scenario,
                trace,
                TrafficTraceStage::IngressResolution,
                reason,
            );
        }
    };

    evaluate_selected_zone(index, scenario, selected_zone, trace)
}

fn evaluate_selected_zone(
    index: &TrafficEvaluationIndex,
    scenario: &TrafficScenario,
    selected_zone: ZoneName,
    mut trace: Vec<TrafficTraceStep>,
) -> Result<TrafficTestResult, TrafficEvaluationError> {
    let Some(zone) = index.zone(&selected_zone) else {
        return unknown_with_object(
            scenario,
            trace,
            TrafficTraceStage::CompletenessCheck,
            UnknownReason::IncompleteSnapshot,
            TraceObjectRef::Zone(selected_zone),
        );
    };

    if !index.section_is_complete(SnapshotSection::DirectRules) {
        return unknown_with_object(
            scenario,
            trace,
            TrafficTraceStage::CompletenessCheck,
            UnknownReason::IncompleteSnapshot,
            TraceObjectRef::SnapshotSection(SnapshotSection::DirectRules),
        );
    }
    if index.has_direct_rules() {
        return unknown_with_object(
            scenario,
            trace,
            TrafficTraceStage::PathResolution,
            UnknownReason::ExternalRulesOutsideModel,
            TraceObjectRef::DirectRule { index: 0 },
        );
    }

    if !index.section_is_complete(SnapshotSection::Policies) {
        return unknown_with_object(
            scenario,
            trace,
            TrafficTraceStage::CompletenessCheck,
            UnknownReason::IncompleteSnapshot,
            TraceObjectRef::SnapshotSection(SnapshotSection::Policies),
        );
    }
    if let Some(policy) = index
        .policies()
        .values()
        .find(|policy| policy_may_apply(policy, &selected_zone, index.target()))
    {
        return unknown_with_object(
            scenario,
            trace,
            TrafficTraceStage::PolicyEvaluation,
            UnknownReason::UnsupportedPolicyFeature,
            TraceObjectRef::Policy(policy.name.clone()),
        );
    }

    if !zone.rich_rules.is_empty() {
        return unknown_with_object(
            scenario,
            trace,
            TrafficTraceStage::RichRuleEvaluation,
            UnknownReason::UnsupportedRichRule,
            TraceObjectRef::RichRule {
                zone: selected_zone,
                index: 0,
            },
        );
    }

    match evaluate_zone(index, scenario, zone, &mut trace) {
        ZoneOutcome::Decision(decision) => finish(scenario, trace, decision, None),
        ZoneOutcome::Unknown(reason) => {
            unknown(scenario, trace, TrafficTraceStage::ZoneEvaluation, reason)
        }
    }
}

fn resolve_ingress(
    index: &TrafficEvaluationIndex,
    scenario: &TrafficScenario,
    trace: &mut Vec<TrafficTraceStep>,
) -> Result<ZoneName, UnknownReason> {
    if let Some(explicit) = &scenario.ingress_zone {
        if index.zone(explicit).is_none() {
            return Err(UnknownReason::IncompleteSnapshot);
        }
        push_selected_zone(trace, explicit);
        return Ok(explicit.clone());
    }

    let has_ipset_binding = index.zone_bindings().iter().any(|binding| {
        matches!(
            binding.kind(),
            IndexedZoneBindingKind::Source(SourceAddress::IpSet(_))
        )
    });
    if has_ipset_binding {
        return Err(UnknownReason::CapabilityUnavailable);
    }

    if let Some(selected) = resolve_source_zone(index, scenario, trace)? {
        return Ok(selected);
    }
    if let Some(selected) = resolve_interface_zone(index, scenario, trace)? {
        return Ok(selected);
    }

    let selected = index.snapshot_arc().default_zone.clone();
    if index.zone(&selected).is_none() {
        return Err(UnknownReason::IncompleteSnapshot);
    }
    push_selected_zone(trace, &selected);
    Ok(selected)
}

fn resolve_source_zone(
    index: &TrafficEvaluationIndex,
    scenario: &TrafficScenario,
    trace: &mut Vec<TrafficTraceStep>,
) -> Result<Option<ZoneName>, UnknownReason> {
    let source_matches: Vec<(i16, u8, ZoneName)> = index
        .zone_bindings()
        .iter()
        .filter_map(|binding| {
            let IndexedZoneBindingKind::Source(source) = binding.kind() else {
                return None;
            };
            source_binding_specificity(source, &scenario.source).map(|specificity| {
                (
                    binding.ingress_priority().get(),
                    specificity,
                    binding.zone().clone(),
                )
            })
        })
        .collect();
    let Some(priority) = source_matches
        .iter()
        .map(|(priority, _, _)| *priority)
        .min()
    else {
        return Ok(None);
    };
    let distinct_priorities: BTreeSet<i16> = source_matches
        .iter()
        .map(|(candidate, _, _)| *candidate)
        .collect();
    if distinct_priorities.len() > 1 {
        require_capability(index, FirewalldFeature::ZonePriorities, trace)?;
    }
    let Some(specificity) = source_matches
        .iter()
        .filter(|(candidate, _, _)| *candidate == priority)
        .map(|(_, specificity, _)| *specificity)
        .max()
    else {
        return Err(UnknownReason::AmbiguousIngressZone);
    };
    let zones: BTreeSet<ZoneName> = source_matches
        .into_iter()
        .filter(|(candidate_priority, candidate_specificity, _)| {
            *candidate_priority == priority && *candidate_specificity == specificity
        })
        .map(|(_, _, zone)| zone)
        .collect();
    let selected = exactly_one_zone(zones)?;
    push_selected_zone(trace, &selected);
    Ok(Some(selected))
}

fn resolve_interface_zone(
    index: &TrafficEvaluationIndex,
    scenario: &TrafficScenario,
    trace: &mut Vec<TrafficTraceStep>,
) -> Result<Option<ZoneName>, UnknownReason> {
    if let Some(interface) = &scenario.ingress_interface {
        let interface_matches: Vec<(i16, ZoneName)> = index
            .zone_bindings()
            .iter()
            .filter_map(|binding| match binding.kind() {
                IndexedZoneBindingKind::Interface(candidate) if candidate == interface => {
                    Some((binding.ingress_priority().get(), binding.zone().clone()))
                }
                _ => None,
            })
            .collect();
        let Some(priority) = interface_matches
            .iter()
            .map(|(priority, _)| *priority)
            .min()
        else {
            return Ok(None);
        };
        let distinct_priorities: BTreeSet<i16> = interface_matches
            .iter()
            .map(|(candidate, _)| *candidate)
            .collect();
        if distinct_priorities.len() > 1 {
            require_capability(index, FirewalldFeature::ZonePriorities, trace)?;
        }
        let zones: BTreeSet<ZoneName> = interface_matches
            .into_iter()
            .filter(|(candidate, _)| *candidate == priority)
            .map(|(_, zone)| zone)
            .collect();
        let selected = exactly_one_zone(zones)?;
        push_selected_zone(trace, &selected);
        return Ok(Some(selected));
    }
    Ok(None)
}

fn exactly_one_zone(zones: BTreeSet<ZoneName>) -> Result<ZoneName, UnknownReason> {
    if zones.len() != 1 {
        return Err(UnknownReason::AmbiguousIngressZone);
    }
    zones
        .into_iter()
        .next()
        .ok_or(UnknownReason::AmbiguousIngressZone)
}

fn push_selected_zone(trace: &mut Vec<TrafficTraceStep>, selected: &ZoneName) {
    trace.push(
        TrafficTraceStep::new(
            TrafficTraceStage::IngressResolution,
            TrafficTraceOutcome::Selected,
        )
        .with_object(TraceObjectRef::Zone(selected.clone())),
    );
}

fn require_capability(
    index: &TrafficEvaluationIndex,
    feature: FirewalldFeature,
    trace: &mut Vec<TrafficTraceStep>,
) -> Result<(), UnknownReason> {
    match feature.support_for(index.snapshot_arc().status.version.as_deref()) {
        FeatureSupport::Supported => {
            trace.push(TrafficTraceStep::new(
                TrafficTraceStage::CapabilityCheck,
                TrafficTraceOutcome::Matched,
            ));
            Ok(())
        }
        FeatureSupport::Unsupported => {
            trace.push(TrafficTraceStep::new(
                TrafficTraceStage::CapabilityCheck,
                TrafficTraceOutcome::Unknown(UnknownReason::VersionUnsupported),
            ));
            Err(UnknownReason::VersionUnsupported)
        }
        FeatureSupport::Unknown => {
            trace.push(TrafficTraceStep::new(
                TrafficTraceStage::CapabilityCheck,
                TrafficTraceOutcome::Unknown(UnknownReason::CapabilityUnavailable),
            ));
            Err(UnknownReason::CapabilityUnavailable)
        }
    }
}

fn policy_may_apply(
    policy: &PolicyDetails,
    ingress_zone: &ZoneName,
    target: EvaluationTarget,
) -> bool {
    let enabled = !policy.disabled && (target == EvaluationTarget::Permanent || policy.active);
    enabled
        && policy
            .ingress_zones
            .iter()
            .any(|zone| zone == "ANY" || zone == ingress_zone.as_str())
        && policy
            .egress_zones
            .iter()
            .any(|zone| zone == "HOST" || zone == "ANY")
}

enum ZoneOutcome {
    Decision(FirewallDecision),
    Unknown(UnknownReason),
}

fn evaluate_zone(
    index: &TrafficEvaluationIndex,
    scenario: &TrafficScenario,
    zone: &ZoneDetails,
    trace: &mut Vec<TrafficTraceStep>,
) -> ZoneOutcome {
    if let TrafficTransport::Icmp { icmp_type } = &scenario.transport {
        let blocked = if zone.icmp_block_inversion {
            !zone.icmp_blocks.contains(icmp_type)
        } else {
            zone.icmp_blocks.contains(icmp_type)
        };
        trace.push(
            TrafficTraceStep::new(
                TrafficTraceStage::ZoneEvaluation,
                if blocked {
                    TrafficTraceOutcome::Decision(FirewallDecision::Block)
                } else {
                    TrafficTraceOutcome::Decision(FirewallDecision::Allow)
                },
            )
            .with_object(TraceObjectRef::Zone(zone.name.clone())),
        );
        return ZoneOutcome::Decision(if blocked {
            FirewallDecision::Block
        } else {
            FirewallDecision::Allow
        });
    }

    if zone_port_match(zone, scenario) {
        trace.push(zone_decision_step(zone, FirewallDecision::Allow));
        return ZoneOutcome::Decision(FirewallDecision::Allow);
    }

    if !zone.services.is_empty() {
        if !index.section_is_complete(SnapshotSection::Services)
            || !index.section_is_complete(SnapshotSection::ServiceDefinitions)
        {
            return ZoneOutcome::Unknown(UnknownReason::IncompleteSnapshot);
        }
        for service_name in &zone.services {
            let Some(resolution) = index.service(service_name) else {
                return ZoneOutcome::Unknown(UnknownReason::IncompleteServiceDefinition);
            };
            if !resolution.failures.is_empty() {
                return ZoneOutcome::Unknown(UnknownReason::IncompleteServiceDefinition);
            }
            match service_match(&resolution.effective, scenario) {
                ServiceMatch::Matched => {
                    trace.push(
                        TrafficTraceStep::new(
                            TrafficTraceStage::ServiceExpansion,
                            TrafficTraceOutcome::Expanded,
                        )
                        .with_object(TraceObjectRef::Service(service_name.clone())),
                    );
                    trace.push(zone_decision_step(zone, FirewallDecision::Allow));
                    return ZoneOutcome::Decision(FirewallDecision::Allow);
                }
                ServiceMatch::Unknown => {
                    return ZoneOutcome::Unknown(UnknownReason::UnsupportedServiceFeature);
                }
                ServiceMatch::NotMatched => {}
            }
        }
    }

    let decision = match zone.target {
        ZoneTarget::Accept => FirewallDecision::Allow,
        ZoneTarget::Drop | ZoneTarget::Reject => FirewallDecision::Block,
        ZoneTarget::Default => {
            if let Err(reason) =
                require_capability(index, FirewalldFeature::DefaultTargetRejectSemantics, trace)
            {
                return ZoneOutcome::Unknown(reason);
            }
            FirewallDecision::Block
        }
    };
    trace.push(
        TrafficTraceStep::new(
            TrafficTraceStage::TargetEvaluation,
            TrafficTraceOutcome::Decision(decision),
        )
        .with_object(TraceObjectRef::Zone(zone.name.clone())),
    );
    ZoneOutcome::Decision(decision)
}

fn zone_port_match(zone: &ZoneDetails, scenario: &TrafficScenario) -> bool {
    match &scenario.transport {
        TrafficTransport::Tcp | TrafficTransport::Udp => {
            let Some(protocol) = transport_protocol(&scenario.transport) else {
                return false;
            };
            let destination_match = scenario.destination_port.is_some_and(|query| {
                zone.ports
                    .iter()
                    .any(|rule| rule.protocol == protocol && selector_covers(rule.port, query))
            });
            let source_match = scenario.source_port.is_some_and(|query| {
                zone.source_ports
                    .iter()
                    .any(|rule| rule.protocol == protocol && selector_covers(rule.port, query))
            });
            destination_match || source_match
        }
        TrafficTransport::RawProtocol { protocol } => zone.protocols.contains(protocol),
        TrafficTransport::Icmp { .. } => false,
    }
}

enum ServiceMatch {
    Matched,
    NotMatched,
    Unknown,
}

fn service_match(definition: &ServiceDefinition, scenario: &TrafficScenario) -> ServiceMatch {
    let primitive_matches = match &scenario.transport {
        TrafficTransport::Tcp | TrafficTransport::Udp => {
            let Some(protocol) = transport_protocol(&scenario.transport) else {
                return ServiceMatch::Unknown;
            };
            let destination_match = scenario.destination_port.is_some_and(|query| {
                definition
                    .ports
                    .iter()
                    .any(|rule| rule.protocol == protocol && selector_covers(rule.port, query))
            });
            let source_match = scenario.source_port.is_some_and(|query| {
                definition
                    .source_ports
                    .iter()
                    .any(|rule| rule.protocol == protocol && selector_covers(rule.port, query))
            });
            destination_match || source_match
        }
        TrafficTransport::RawProtocol { protocol } => definition.protocols.contains(protocol),
        TrafficTransport::Icmp { .. } => false,
    };
    if !primitive_matches {
        return ServiceMatch::NotMatched;
    }
    if !definition.helpers.is_empty() || !definition.modules.is_empty() {
        return ServiceMatch::Unknown;
    }

    let Some(family) = scenario.source.family() else {
        return ServiceMatch::Unknown;
    };
    let destinations: Vec<&SourceAddress> = definition
        .destinations
        .iter()
        .filter(|destination| destination.family == family)
        .map(|destination| &destination.address)
        .collect();
    if destinations.is_empty() {
        return ServiceMatch::Matched;
    }
    let TrafficDestination::Address(candidate) = &scenario.destination else {
        return ServiceMatch::Unknown;
    };
    if destinations
        .into_iter()
        .any(|destination| source_selector_covered(destination, candidate))
    {
        ServiceMatch::Matched
    } else {
        ServiceMatch::NotMatched
    }
}

fn transport_protocol(transport: &TrafficTransport) -> Option<Protocol> {
    match transport {
        TrafficTransport::Tcp => Some(Protocol::Tcp),
        TrafficTransport::Udp => Some(Protocol::Udp),
        TrafficTransport::Icmp { .. } | TrafficTransport::RawProtocol { .. } => None,
    }
}

fn source_binding_specificity(binding: &SourceAddress, candidate: &SourceAddress) -> Option<u8> {
    match (binding, candidate) {
        (
            SourceAddress::Ip {
                addr: binding_address,
                prefix: binding_prefix,
            },
            SourceAddress::Ip {
                addr: candidate_address,
                prefix: candidate_prefix,
            },
        ) => {
            let binding_prefix = binding_prefix.unwrap_or_else(|| max_prefix(*binding_address));
            let candidate_prefix =
                candidate_prefix.unwrap_or_else(|| max_prefix(*candidate_address));
            (binding_prefix <= candidate_prefix
                && cidr_contains(*binding_address, binding_prefix, *candidate_address))
            .then_some(binding_prefix)
        }
        (SourceAddress::Mac(_) | SourceAddress::IpSet(_), _)
        | (SourceAddress::Ip { .. }, SourceAddress::Mac(_) | SourceAddress::IpSet(_)) => None,
    }
}

fn source_selector_covered(binding: &SourceAddress, candidate: &SourceAddress) -> bool {
    source_binding_specificity(binding, candidate).is_some()
}

const fn max_prefix(address: IpAddr) -> u8 {
    if address.is_ipv4() { 32 } else { 128 }
}

fn cidr_contains(network: IpAddr, prefix: u8, candidate: IpAddr) -> bool {
    match (network, candidate) {
        (IpAddr::V4(network), IpAddr::V4(candidate)) => {
            masked_equal(&network.octets(), &candidate.octets(), prefix)
        }
        (IpAddr::V6(network), IpAddr::V6(candidate)) => {
            masked_equal(&network.octets(), &candidate.octets(), prefix)
        }
        _ => false,
    }
}

fn masked_equal(network: &[u8], candidate: &[u8], prefix: u8) -> bool {
    let full_bytes = usize::from(prefix / 8);
    let remaining_bits = prefix % 8;
    if network.get(..full_bytes) != candidate.get(..full_bytes) {
        return false;
    }
    if remaining_bits == 0 {
        return true;
    }
    let mask = u8::MAX << (8 - remaining_bits);
    network
        .get(full_bytes)
        .zip(candidate.get(full_bytes))
        .is_some_and(|(left, right)| left & mask == right & mask)
}

fn selector_covers(rule: PortSelector, query: PortSelector) -> bool {
    let (rule_start, rule_end) = selector_bounds(rule);
    let (query_start, query_end) = selector_bounds(query);
    rule_start <= query_start && query_end <= rule_end
}

const fn selector_bounds(selector: PortSelector) -> (u16, u16) {
    match selector {
        PortSelector::Single(port) => (port.get(), port.get()),
        PortSelector::Range(range) => (range.start().get(), range.end().get()),
    }
}

fn zone_decision_step(zone: &ZoneDetails, decision: FirewallDecision) -> TrafficTraceStep {
    TrafficTraceStep::new(
        TrafficTraceStage::ZoneEvaluation,
        TrafficTraceOutcome::Decision(decision),
    )
    .with_object(TraceObjectRef::Zone(zone.name.clone()))
}

fn unknown(
    scenario: &TrafficScenario,
    mut trace: Vec<TrafficTraceStep>,
    stage: TrafficTraceStage,
    reason: UnknownReason,
) -> Result<TrafficTestResult, TrafficEvaluationError> {
    trace.push(TrafficTraceStep::new(
        stage,
        TrafficTraceOutcome::Unknown(reason),
    ));
    finish(scenario, trace, FirewallDecision::Unknown, Some(reason))
}

fn unknown_with_object(
    scenario: &TrafficScenario,
    mut trace: Vec<TrafficTraceStep>,
    stage: TrafficTraceStage,
    reason: UnknownReason,
    object: TraceObjectRef,
) -> Result<TrafficTestResult, TrafficEvaluationError> {
    trace.push(
        TrafficTraceStep::new(stage, TrafficTraceOutcome::Unknown(reason)).with_object(object),
    );
    finish(scenario, trace, FirewallDecision::Unknown, Some(reason))
}

fn finish(
    scenario: &TrafficScenario,
    mut trace: Vec<TrafficTraceStep>,
    decision: FirewallDecision,
    reason: Option<UnknownReason>,
) -> Result<TrafficTestResult, TrafficEvaluationError> {
    let status = TrafficTestStatus::from_decision(decision, scenario.expectation);
    trace.push(TrafficTraceStep::new(
        TrafficTraceStage::Decision,
        TrafficTraceOutcome::Decision(decision),
    ));
    trace.push(TrafficTraceStep::new(
        TrafficTraceStage::ExpectationComparison,
        comparison_outcome(decision, scenario.expectation),
    ));
    trace.push(TrafficTraceStep::new(
        TrafficTraceStage::Status,
        TrafficTraceOutcome::Status(status),
    ));
    Ok(TrafficTestResult::new(
        scenario.id.clone(),
        scenario.expectation,
        decision,
        reason,
        trace,
    )?)
}

fn comparison_outcome(
    decision: FirewallDecision,
    expectation: TrafficExpectation,
) -> TrafficTraceOutcome {
    match decision {
        FirewallDecision::Unknown => TrafficTraceOutcome::Continued,
        FirewallDecision::Allow if expectation == TrafficExpectation::Allow => {
            TrafficTraceOutcome::Matched
        }
        FirewallDecision::Block if expectation == TrafficExpectation::Block => {
            TrafficTraceOutcome::Matched
        }
        FirewallDecision::Allow | FirewallDecision::Block => TrafficTraceOutcome::NotMatched,
    }
}
