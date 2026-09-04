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
    AddressFamily, FeatureSupport, FirewalldFeature, PolicyDetails, PolicyTarget, PortSelector,
    Protocol, RichRule, RichRuleAction, RichRuleAnalysis, RichRuleExpression, ServiceDefinition,
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
    let policies = applicable_policies(index, &selected_zone);
    if !policies.is_empty()
        && let Err(reason) = require_capability(index, FirewalldFeature::PolicyObjects, &mut trace)
    {
        return unknown(scenario, trace, TrafficTraceStage::PolicyEvaluation, reason);
    }
    if let Some(policy) = policies.iter().find(|policy| policy.priority == 0) {
        return unknown_with_object(
            scenario,
            trace,
            TrafficTraceStage::PolicyEvaluation,
            UnknownReason::UnsupportedPolicyFeature,
            TraceObjectRef::Policy(policy.name.clone()),
        );
    }

    match evaluate_policy_range(
        index,
        scenario,
        &policies,
        PolicyRange::Negative,
        &mut trace,
    ) {
        PathOutcome::Decision(decision) => return finish(scenario, trace, decision, None),
        PathOutcome::Unknown(reason) => {
            return unknown(scenario, trace, TrafficTraceStage::PolicyEvaluation, reason);
        }
        PathOutcome::Continue => {}
    }

    match evaluate_zone_before_target(index, scenario, zone, &mut trace) {
        PathOutcome::Decision(decision) => return finish(scenario, trace, decision, None),
        PathOutcome::Unknown(reason) => {
            return unknown(scenario, trace, TrafficTraceStage::ZoneEvaluation, reason);
        }
        PathOutcome::Continue => {}
    }

    evaluate_after_zone(index, scenario, zone, &policies, trace)
}

fn evaluate_after_zone(
    index: &TrafficEvaluationIndex,
    scenario: &TrafficScenario,
    zone: &ZoneDetails,
    policies: &[&PolicyDetails],
    mut trace: Vec<TrafficTraceStep>,
) -> Result<TrafficTestResult, TrafficEvaluationError> {
    if policies.iter().any(|policy| policy.priority > 0)
        && let Err(reason) = require_capability(
            index,
            FirewalldFeature::PositivePolicyPriorityBeforeZoneTarget,
            &mut trace,
        )
    {
        return unknown(scenario, trace, TrafficTraceStage::PolicyEvaluation, reason);
    }
    let outcome =
        evaluate_policy_range(index, scenario, policies, PolicyRange::Positive, &mut trace);
    match outcome {
        PathOutcome::Decision(decision) => finish(scenario, trace, decision, None),
        PathOutcome::Unknown(reason) => {
            unknown(scenario, trace, TrafficTraceStage::PolicyEvaluation, reason)
        }
        PathOutcome::Continue => match zone_target_decision(index, scenario, zone, &mut trace) {
            PathOutcome::Decision(decision) => finish(scenario, trace, decision, None),
            PathOutcome::Unknown(reason) => {
                unknown(scenario, trace, TrafficTraceStage::TargetEvaluation, reason)
            }
            PathOutcome::Continue => unreachable!("zone targets are terminal"),
        },
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
        && policy.egress_zones.iter().any(|zone| zone == "HOST")
}

fn applicable_policies<'a>(
    index: &'a TrafficEvaluationIndex,
    selected_zone: &ZoneName,
) -> Vec<&'a PolicyDetails> {
    index
        .policy_order()
        .iter()
        .filter_map(|name| index.policy(name))
        .filter(|policy| policy_may_apply(policy, selected_zone, index.target()))
        .collect()
}

enum PathOutcome {
    Decision(FirewallDecision),
    Continue,
    Unknown(UnknownReason),
}

#[derive(Clone, Copy)]
enum PolicyRange {
    Negative,
    Positive,
}

impl PolicyRange {
    const fn contains(self, priority: i32) -> bool {
        match self {
            Self::Negative => priority < 0,
            Self::Positive => priority > 0,
        }
    }
}

fn policy_shape_supported(policy: &PolicyDetails) -> bool {
    let ingress_any = policy.ingress_zones.iter().any(|zone| zone == "ANY");
    let egress_host = policy.egress_zones.iter().any(|zone| zone == "HOST");
    policy.priority != 0
        && i16::try_from(policy.priority).is_ok()
        && !policy.masquerade
        && policy.forward_ports.is_empty()
        && (!ingress_any || policy.ingress_zones.len() == 1)
        && (!egress_host || policy.egress_zones.len() == 1)
}

fn evaluate_policy_range(
    index: &TrafficEvaluationIndex,
    scenario: &TrafficScenario,
    policies: &[&PolicyDetails],
    range: PolicyRange,
    trace: &mut Vec<TrafficTraceStep>,
) -> PathOutcome {
    let filtered: Vec<&PolicyDetails> = policies
        .iter()
        .copied()
        .filter(|policy| range.contains(policy.priority))
        .collect();
    let mut offset = 0;
    while offset < filtered.len() {
        let priority = filtered[offset].priority;
        let end = filtered[offset..]
            .iter()
            .position(|policy| policy.priority != priority)
            .map_or(filtered.len(), |relative| offset + relative);
        let mut group_decision = None;
        for policy in &filtered[offset..end] {
            match evaluate_policy(index, scenario, policy, trace) {
                PathOutcome::Decision(decision) => {
                    if group_decision.is_some_and(|previous| previous != decision) {
                        return PathOutcome::Unknown(UnknownReason::ConflictingEqualPriorityRules);
                    }
                    group_decision = Some(decision);
                }
                PathOutcome::Unknown(reason) => return PathOutcome::Unknown(reason),
                PathOutcome::Continue => {}
            }
        }
        if let Some(decision) = group_decision {
            return PathOutcome::Decision(decision);
        }
        offset = end;
    }
    PathOutcome::Continue
}

fn evaluate_policy(
    index: &TrafficEvaluationIndex,
    scenario: &TrafficScenario,
    policy: &PolicyDetails,
    trace: &mut Vec<TrafficTraceStep>,
) -> PathOutcome {
    if !policy_shape_supported(policy) {
        trace.push(
            TrafficTraceStep::new(
                TrafficTraceStage::PolicyEvaluation,
                TrafficTraceOutcome::Unknown(UnknownReason::UnsupportedPolicyFeature),
            )
            .with_object(TraceObjectRef::Policy(policy.name.clone())),
        );
        return PathOutcome::Unknown(UnknownReason::UnsupportedPolicyFeature);
    }
    trace.push(
        TrafficTraceStep::new(
            TrafficTraceStage::PolicyEvaluation,
            TrafficTraceOutcome::Matched,
        )
        .with_object(TraceObjectRef::Policy(policy.name.clone())),
    );
    let owner = RichRuleOwner::Policy(&policy.name);
    let rich_rules = match analyze_rich_rules(&policy.rich_rules) {
        Ok(rules) => rules,
        Err(failure) => {
            push_rich_analysis_failure(trace, owner, failure);
            return PathOutcome::Unknown(UnknownReason::UnsupportedRichRule);
        }
    };
    if rich_rules
        .iter()
        .any(|(_, expression)| expression.priority.get() != 0)
        && let Err(reason) = require_capability(index, FirewalldFeature::RichRulePriorities, trace)
    {
        return PathOutcome::Unknown(reason);
    }
    for phase in [RichRulePhase::Negative, RichRulePhase::ZeroDeny] {
        match evaluate_rich_phase(index, scenario, &rich_rules, phase, owner, trace) {
            PathOutcome::Continue => {}
            terminal => return terminal,
        }
    }
    if let TrafficTransport::Icmp { icmp_type } = &scenario.transport
        && policy.icmp_blocks.contains(icmp_type)
    {
        trace.push(policy_decision_step(policy, FirewallDecision::Block));
        return PathOutcome::Decision(FirewallDecision::Block);
    }
    match evaluate_rich_phase(
        index,
        scenario,
        &rich_rules,
        RichRulePhase::ZeroAllow,
        owner,
        trace,
    ) {
        PathOutcome::Continue => {}
        terminal => return terminal,
    }
    let primitives = PrimitiveRules {
        ports: &policy.ports,
        source_ports: &policy.source_ports,
        protocols: &policy.protocols,
        services: &policy.services,
        object: TraceObjectRef::Policy(policy.name.clone()),
        stage: TrafficTraceStage::PolicyEvaluation,
    };
    match evaluate_primitives(index, scenario, primitives, trace) {
        PathOutcome::Continue => {}
        terminal => return terminal,
    }
    match evaluate_rich_phase(
        index,
        scenario,
        &rich_rules,
        RichRulePhase::Positive,
        owner,
        trace,
    ) {
        PathOutcome::Continue => {}
        terminal => return terminal,
    }
    let outcome = match policy.target {
        PolicyTarget::Continue => TrafficTraceOutcome::Continued,
        PolicyTarget::Accept => TrafficTraceOutcome::Decision(FirewallDecision::Allow),
        PolicyTarget::Reject | PolicyTarget::Drop => {
            TrafficTraceOutcome::Decision(FirewallDecision::Block)
        }
    };
    trace.push(
        TrafficTraceStep::new(TrafficTraceStage::TargetEvaluation, outcome)
            .with_object(TraceObjectRef::Policy(policy.name.clone())),
    );
    match policy.target {
        PolicyTarget::Continue => PathOutcome::Continue,
        PolicyTarget::Accept => PathOutcome::Decision(FirewallDecision::Allow),
        PolicyTarget::Reject | PolicyTarget::Drop => PathOutcome::Decision(FirewallDecision::Block),
    }
}

fn evaluate_zone_before_target(
    index: &TrafficEvaluationIndex,
    scenario: &TrafficScenario,
    zone: &ZoneDetails,
    trace: &mut Vec<TrafficTraceStep>,
) -> PathOutcome {
    let owner = RichRuleOwner::Zone(&zone.name);
    let rich_rules = match analyze_rich_rules(&zone.rich_rules) {
        Ok(rules) => rules,
        Err(failure) => {
            push_rich_analysis_failure(trace, owner, failure);
            return PathOutcome::Unknown(UnknownReason::UnsupportedRichRule);
        }
    };
    if rich_rules
        .iter()
        .any(|(_, expression)| expression.priority.get() != 0)
        && let Err(reason) = require_capability(index, FirewalldFeature::RichRulePriorities, trace)
    {
        return PathOutcome::Unknown(reason);
    }
    for phase in [RichRulePhase::Negative, RichRulePhase::ZeroDeny] {
        match evaluate_rich_phase(index, scenario, &rich_rules, phase, owner, trace) {
            PathOutcome::Continue => {}
            terminal => return terminal,
        }
    }
    if let TrafficTransport::Icmp { icmp_type } = &scenario.transport {
        let blocked = if zone.icmp_block_inversion {
            !zone.icmp_blocks.contains(icmp_type)
        } else {
            zone.icmp_blocks.contains(icmp_type)
        };
        if blocked {
            trace.push(zone_decision_step(zone, FirewallDecision::Block));
            return PathOutcome::Decision(FirewallDecision::Block);
        }
    }
    match evaluate_rich_phase(
        index,
        scenario,
        &rich_rules,
        RichRulePhase::ZeroAllow,
        owner,
        trace,
    ) {
        PathOutcome::Continue => {}
        terminal => return terminal,
    }
    let primitives = PrimitiveRules {
        ports: &zone.ports,
        source_ports: &zone.source_ports,
        protocols: &zone.protocols,
        services: &zone.services,
        object: TraceObjectRef::Zone(zone.name.clone()),
        stage: TrafficTraceStage::ZoneEvaluation,
    };
    match evaluate_primitives(index, scenario, primitives, trace) {
        PathOutcome::Continue => {}
        terminal => return terminal,
    }
    evaluate_rich_phase(
        index,
        scenario,
        &rich_rules,
        RichRulePhase::Positive,
        owner,
        trace,
    )
}

fn zone_target_decision(
    index: &TrafficEvaluationIndex,
    scenario: &TrafficScenario,
    zone: &ZoneDetails,
    trace: &mut Vec<TrafficTraceStep>,
) -> PathOutcome {
    let decision = match zone.target {
        ZoneTarget::Accept => FirewallDecision::Allow,
        ZoneTarget::Drop | ZoneTarget::Reject => FirewallDecision::Block,
        ZoneTarget::Default => {
            if let Err(reason) =
                require_capability(index, FirewalldFeature::DefaultTargetRejectSemantics, trace)
            {
                return PathOutcome::Unknown(reason);
            }
            if matches!(scenario.transport, TrafficTransport::Icmp { .. }) {
                FirewallDecision::Allow
            } else {
                FirewallDecision::Block
            }
        }
    };
    trace.push(
        TrafficTraceStep::new(
            TrafficTraceStage::TargetEvaluation,
            TrafficTraceOutcome::Decision(decision),
        )
        .with_object(TraceObjectRef::Zone(zone.name.clone())),
    );
    PathOutcome::Decision(decision)
}

fn primitive_port_match(
    ports: &[crate::domain::PortSpec],
    source_ports: &[crate::domain::PortSpec],
    protocols: &[crate::domain::IpProtocol],
    scenario: &TrafficScenario,
) -> bool {
    match &scenario.transport {
        TrafficTransport::Tcp | TrafficTransport::Udp => {
            let Some(protocol) = transport_protocol(&scenario.transport) else {
                return false;
            };
            let destination_match = scenario.destination_port.is_some_and(|query| {
                ports
                    .iter()
                    .any(|rule| rule.protocol == protocol && selector_covers(rule.port, query))
            });
            let source_match = scenario.source_port.is_some_and(|query| {
                source_ports
                    .iter()
                    .any(|rule| rule.protocol == protocol && selector_covers(rule.port, query))
            });
            destination_match || source_match
        }
        TrafficTransport::RawProtocol { protocol } => protocols.contains(protocol),
        TrafficTransport::Icmp { .. } => false,
    }
}

struct PrimitiveRules<'a> {
    ports: &'a [crate::domain::PortSpec],
    source_ports: &'a [crate::domain::PortSpec],
    protocols: &'a [crate::domain::IpProtocol],
    services: &'a [crate::domain::ServiceName],
    object: TraceObjectRef,
    stage: TrafficTraceStage,
}

fn evaluate_primitives(
    index: &TrafficEvaluationIndex,
    scenario: &TrafficScenario,
    rules: PrimitiveRules<'_>,
    trace: &mut Vec<TrafficTraceStep>,
) -> PathOutcome {
    if primitive_port_match(rules.ports, rules.source_ports, rules.protocols, scenario) {
        trace.push(
            TrafficTraceStep::new(
                rules.stage,
                TrafficTraceOutcome::Decision(FirewallDecision::Allow),
            )
            .with_object(rules.object),
        );
        return PathOutcome::Decision(FirewallDecision::Allow);
    }
    if rules.services.is_empty() {
        return PathOutcome::Continue;
    }
    if !index.section_is_complete(SnapshotSection::Services)
        || !index.section_is_complete(SnapshotSection::ServiceDefinitions)
    {
        return PathOutcome::Unknown(UnknownReason::IncompleteSnapshot);
    }
    for service_name in rules.services {
        let Some(resolution) = index.service(service_name) else {
            return PathOutcome::Unknown(UnknownReason::IncompleteServiceDefinition);
        };
        if !resolution.failures.is_empty() {
            return PathOutcome::Unknown(UnknownReason::IncompleteServiceDefinition);
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
                trace.push(
                    TrafficTraceStep::new(
                        rules.stage,
                        TrafficTraceOutcome::Decision(FirewallDecision::Allow),
                    )
                    .with_object(rules.object.clone()),
                );
                return PathOutcome::Decision(FirewallDecision::Allow);
            }
            ServiceMatch::Unknown => {
                return PathOutcome::Unknown(UnknownReason::UnsupportedServiceFeature);
            }
            ServiceMatch::NotMatched => {}
        }
    }
    PathOutcome::Continue
}

type AnalyzedRichRules = Vec<(u32, RichRuleExpression)>;

#[derive(Clone, Copy)]
struct RichRuleAnalysisFailure {
    index: Option<u32>,
}

fn analyze_rich_rules(rules: &[RichRule]) -> Result<AnalyzedRichRules, RichRuleAnalysisFailure> {
    rules
        .iter()
        .enumerate()
        .map(|(index, rule)| {
            let stable_index =
                u32::try_from(index).map_err(|_| RichRuleAnalysisFailure { index: None })?;
            match rule.analyze() {
                RichRuleAnalysis::Supported(expression) => Ok((stable_index, *expression)),
                RichRuleAnalysis::Unsupported(_) | RichRuleAnalysis::Malformed(_) => {
                    Err(RichRuleAnalysisFailure {
                        index: Some(stable_index),
                    })
                }
            }
        })
        .collect()
}

#[derive(Clone, Copy)]
enum RichRuleOwner<'a> {
    Zone(&'a ZoneName),
    Policy(&'a crate::domain::PolicyName),
}

impl RichRuleOwner<'_> {
    fn object(self, index: u32) -> TraceObjectRef {
        match self {
            Self::Zone(zone) => TraceObjectRef::RichRule {
                zone: zone.clone(),
                index,
            },
            Self::Policy(policy) => TraceObjectRef::PolicyRichRule {
                policy: policy.clone(),
                index,
            },
        }
    }
}

fn push_rich_analysis_failure(
    trace: &mut Vec<TrafficTraceStep>,
    owner: RichRuleOwner<'_>,
    failure: RichRuleAnalysisFailure,
) {
    let step = TrafficTraceStep::new(
        TrafficTraceStage::RichRuleEvaluation,
        TrafficTraceOutcome::Unknown(UnknownReason::UnsupportedRichRule),
    );
    trace.push(match failure.index {
        Some(index) => step.with_object(owner.object(index)),
        None => step,
    });
}

#[derive(Clone, Copy)]
enum RichRulePhase {
    Negative,
    ZeroDeny,
    ZeroAllow,
    Positive,
}

impl RichRulePhase {
    const fn includes(self, expression: &RichRuleExpression) -> bool {
        let priority = expression.priority.get();
        match self {
            Self::Negative => priority < 0,
            Self::ZeroDeny => {
                priority == 0
                    && matches!(
                        expression.action,
                        RichRuleAction::Reject | RichRuleAction::Drop
                    )
            }
            Self::ZeroAllow => priority == 0 && matches!(expression.action, RichRuleAction::Accept),
            Self::Positive => priority > 0,
        }
    }
}

fn evaluate_rich_phase(
    index: &TrafficEvaluationIndex,
    scenario: &TrafficScenario,
    rules: &AnalyzedRichRules,
    phase: RichRulePhase,
    owner: RichRuleOwner<'_>,
    trace: &mut Vec<TrafficTraceStep>,
) -> PathOutcome {
    let mut candidates: Vec<&(u32, RichRuleExpression)> = rules
        .iter()
        .filter(|(_, expression)| phase.includes(expression))
        .collect();
    candidates.sort_by_key(|(index, expression)| (expression.priority, *index));
    let mut offset = 0;
    while offset < candidates.len() {
        let priority = candidates[offset].1.priority;
        let end = candidates[offset..]
            .iter()
            .position(|(_, expression)| expression.priority != priority)
            .map_or(candidates.len(), |relative| offset + relative);
        let mut group_decision = None;
        for (rule_index, expression) in &candidates[offset..end] {
            let object = owner.object(*rule_index);
            match rich_expression_match(index, expression, scenario) {
                RichMatch::Matched => {
                    let decision = rich_action_decision(expression.action);
                    trace.push(
                        TrafficTraceStep::new(
                            TrafficTraceStage::RichRuleEvaluation,
                            TrafficTraceOutcome::Decision(decision),
                        )
                        .with_object(object),
                    );
                    if group_decision.is_some_and(|previous| previous != decision) {
                        return PathOutcome::Unknown(UnknownReason::ConflictingEqualPriorityRules);
                    }
                    group_decision = Some(decision);
                }
                RichMatch::NotMatched => trace.push(
                    TrafficTraceStep::new(
                        TrafficTraceStage::RichRuleEvaluation,
                        TrafficTraceOutcome::NotMatched,
                    )
                    .with_object(object),
                ),
                RichMatch::Unknown(reason) => return PathOutcome::Unknown(reason),
            }
        }
        if let Some(decision) = group_decision {
            return PathOutcome::Decision(decision);
        }
        offset = end;
    }
    PathOutcome::Continue
}

const fn rich_action_decision(action: RichRuleAction) -> FirewallDecision {
    match action {
        RichRuleAction::Accept => FirewallDecision::Allow,
        RichRuleAction::Reject | RichRuleAction::Drop => FirewallDecision::Block,
    }
}

fn rich_expression_match(
    index: &TrafficEvaluationIndex,
    expression: &RichRuleExpression,
    scenario: &TrafficScenario,
) -> RichMatch {
    let Some(family) = scenario.source.family() else {
        return RichMatch::Unknown(UnknownReason::CapabilityUnavailable);
    };
    if expression.family.is_some_and(|expected| expected != family) {
        return RichMatch::NotMatched;
    }
    if let Some(source) = &expression.source {
        let matches = source_selector_covered(&source.address, &scenario.source);
        if matches == source.inverted {
            return RichMatch::NotMatched;
        }
    }
    if let Some(destination) = &expression.destination {
        let TrafficDestination::Address(candidate) = &scenario.destination else {
            return RichMatch::Unknown(UnknownReason::CapabilityUnavailable);
        };
        let matches = source_selector_covered(&destination.address, candidate);
        if matches == destination.inverted {
            return RichMatch::NotMatched;
        }
    }
    if let Some(rule) = expression.destination_port {
        let Some(protocol) = transport_protocol(&scenario.transport) else {
            return RichMatch::NotMatched;
        };
        let matched = scenario
            .destination_port
            .is_some_and(|query| rule.protocol == protocol && selector_covers(rule.port, query));
        return if matched {
            RichMatch::Matched
        } else {
            RichMatch::NotMatched
        };
    }
    if let Some(rule) = expression.source_port {
        let Some(protocol) = transport_protocol(&scenario.transport) else {
            return RichMatch::NotMatched;
        };
        let matched = scenario
            .source_port
            .is_some_and(|query| rule.protocol == protocol && selector_covers(rule.port, query));
        return if matched {
            RichMatch::Matched
        } else {
            RichMatch::NotMatched
        };
    }
    if let Some(service_name) = &expression.service {
        if !index.section_is_complete(SnapshotSection::Services)
            || !index.section_is_complete(SnapshotSection::ServiceDefinitions)
        {
            return RichMatch::Unknown(UnknownReason::IncompleteSnapshot);
        }
        let Some(resolution) = index.service(service_name) else {
            return RichMatch::Unknown(UnknownReason::IncompleteServiceDefinition);
        };
        if !resolution.failures.is_empty() {
            return RichMatch::Unknown(UnknownReason::IncompleteServiceDefinition);
        }
        return match service_match(&resolution.effective, scenario) {
            ServiceMatch::Matched => RichMatch::Matched,
            ServiceMatch::NotMatched => RichMatch::NotMatched,
            ServiceMatch::Unknown => RichMatch::Unknown(UnknownReason::UnsupportedServiceFeature),
        };
    }
    if let Some(protocol) = &expression.protocol {
        return if scenario_protocol(scenario)
            .is_some_and(|candidate| candidate == protocol.as_str())
        {
            RichMatch::Matched
        } else {
            RichMatch::NotMatched
        };
    }
    RichMatch::Matched
}

fn scenario_protocol(scenario: &TrafficScenario) -> Option<&str> {
    match &scenario.transport {
        TrafficTransport::Tcp => Some("tcp"),
        TrafficTransport::Udp => Some("udp"),
        TrafficTransport::RawProtocol { protocol } => Some(protocol.as_str()),
        TrafficTransport::Icmp { .. } => scenario.source.family().map(|family| match family {
            AddressFamily::Ipv4 => "icmp",
            AddressFamily::Ipv6 => "ipv6-icmp",
        }),
    }
}

enum ServiceMatch {
    Matched,
    NotMatched,
    Unknown,
}

enum RichMatch {
    Matched,
    NotMatched,
    Unknown(UnknownReason),
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

fn policy_decision_step(policy: &PolicyDetails, decision: FirewallDecision) -> TrafficTraceStep {
    TrafficTraceStep::new(
        TrafficTraceStage::PolicyEvaluation,
        TrafficTraceOutcome::Decision(decision),
    )
    .with_object(TraceObjectRef::Policy(policy.name.clone()))
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
