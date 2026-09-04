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
    AddressFamily, FeatureSupport, FirewalldFeature, ForwardPort, IpProtocol, PolicyDetails,
    PolicyTarget, PortSelector, Protocol, RichRule, RichRuleAction, RichRuleAnalysis,
    RichRuleExpression, ServiceDefinition, ServiceResolution, SnapshotSection, SourceAddress,
    TraceObjectRef, ZoneDetails, ZoneName, ZoneTarget,
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
    if let TrafficTransport::RawProtocol { protocol } = &scenario.transport
        && matches!(
            known_protocol_number(protocol.as_str()),
            None | Some(1 | 6 | 17 | 58)
        )
    {
        return unknown(
            scenario,
            trace,
            TrafficTraceStage::PathResolution,
            UnknownReason::CapabilityUnavailable,
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
    if forward_ports_may_intersect(&zone.forward_ports, scenario) {
        return unknown_with_object(
            scenario,
            trace,
            TrafficTraceStage::PathResolution,
            UnknownReason::CapabilityUnavailable,
            TraceObjectRef::Zone(zone.name.clone()),
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

    let has_unverifiable_binding = index.zone_bindings().iter().any(|binding| {
        matches!(
            binding.kind(),
            IndexedZoneBindingKind::Source(SourceAddress::IpSet(_) | SourceAddress::Mac(_))
        )
    });
    if has_unverifiable_binding {
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
    let mut source_matches = Vec::new();
    let mut has_partial = false;
    for binding in index.zone_bindings() {
        let IndexedZoneBindingKind::Source(source) = binding.kind() else {
            continue;
        };
        match source_selector_match(source, &scenario.source) {
            SelectorMatch::Matched => {
                if let Some(specificity) = source_binding_specificity(source, &scenario.source) {
                    source_matches.push((
                        binding.ingress_priority().get(),
                        specificity,
                        binding.zone().clone(),
                    ));
                }
            }
            SelectorMatch::Partial => has_partial = true,
            SelectorMatch::NotMatched => {}
        }
    }
    if has_partial {
        return Err(UnknownReason::CapabilityUnavailable);
    }
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

fn primitive_match(
    ports: &[crate::domain::PortSpec],
    source_ports: &[crate::domain::PortSpec],
    protocols: &[IpProtocol],
    scenario: &TrafficScenario,
) -> SelectorMatch {
    let mut result = SelectorMatch::NotMatched;
    if matches!(
        scenario.transport,
        TrafficTransport::Tcp | TrafficTransport::Udp
    ) {
        let Some(protocol) = transport_protocol(&scenario.transport) else {
            return SelectorMatch::Partial;
        };
        if let Some(query) = scenario.destination_port {
            for rule in ports.iter().filter(|rule| rule.protocol == protocol) {
                result = result.or(selector_match(rule.port, query));
            }
        }
        for rule in source_ports.iter().filter(|rule| rule.protocol == protocol) {
            result = result.or(match scenario.source_port {
                Some(query) => selector_match(rule.port, query),
                None => SelectorMatch::Partial,
            });
        }
    }
    for protocol in protocols {
        result = result.or(protocol_match(protocol, scenario));
    }
    result
}

fn forward_ports_may_intersect(forward_ports: &[ForwardPort], scenario: &TrafficScenario) -> bool {
    match &scenario.transport {
        TrafficTransport::Tcp | TrafficTransport::Udp => {
            let Some(protocol) = transport_protocol(&scenario.transport) else {
                return false;
            };
            scenario.destination_port.is_some_and(|query| {
                forward_ports.iter().any(|forward| {
                    forward.protocol == protocol
                        && selector_match(forward.port, query) != SelectorMatch::NotMatched
                })
            })
        }
        TrafficTransport::RawProtocol { .. } | TrafficTransport::Icmp { .. } => false,
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
    match primitive_match(rules.ports, rules.source_ports, rules.protocols, scenario) {
        SelectorMatch::Matched => {
            trace.push(
                TrafficTraceStep::new(
                    rules.stage,
                    TrafficTraceOutcome::Decision(FirewallDecision::Allow),
                )
                .with_object(rules.object),
            );
            return PathOutcome::Decision(FirewallDecision::Allow);
        }
        SelectorMatch::Partial => {
            return PathOutcome::Unknown(UnknownReason::CapabilityUnavailable);
        }
        SelectorMatch::NotMatched => {}
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
        match service_resolution_match(index, resolution, scenario) {
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
            ServiceMatch::Unknown(reason) => {
                return PathOutcome::Unknown(reason);
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
    let mut result = SelectorMatch::Matched;
    if let Some(source) = &expression.source {
        let matched = source_selector_match(&source.address, &scenario.source);
        result = result.and(if source.inverted {
            matched.inverted()
        } else {
            matched
        });
        if result == SelectorMatch::NotMatched {
            return RichMatch::NotMatched;
        }
    }
    if let Some(destination) = &expression.destination {
        let matched = match &scenario.destination {
            TrafficDestination::Address(candidate) => {
                source_selector_match(&destination.address, candidate)
            }
            TrafficDestination::LocalHost => SelectorMatch::Partial,
        };
        result = result.and(if destination.inverted {
            matched.inverted()
        } else {
            matched
        });
        if result == SelectorMatch::NotMatched {
            return RichMatch::NotMatched;
        }
    }
    if let Some(rule) = expression.destination_port {
        let Some(protocol) = transport_protocol(&scenario.transport) else {
            return RichMatch::NotMatched;
        };
        let matched = if rule.protocol == protocol {
            scenario
                .destination_port
                .map_or(SelectorMatch::Partial, |query| {
                    selector_match(rule.port, query)
                })
        } else {
            SelectorMatch::NotMatched
        };
        result = result.and(matched);
    }
    if let Some(rule) = expression.source_port {
        let Some(protocol) = transport_protocol(&scenario.transport) else {
            return RichMatch::NotMatched;
        };
        let matched = if rule.protocol == protocol {
            scenario
                .source_port
                .map_or(SelectorMatch::Partial, |query| {
                    selector_match(rule.port, query)
                })
        } else {
            SelectorMatch::NotMatched
        };
        result = result.and(matched);
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
        let matched = match service_resolution_match(index, resolution, scenario) {
            ServiceMatch::Matched => SelectorMatch::Matched,
            ServiceMatch::NotMatched => SelectorMatch::NotMatched,
            ServiceMatch::Unknown(reason) => return RichMatch::Unknown(reason),
        };
        result = result.and(matched);
    }
    if let Some(protocol) = &expression.protocol {
        result = result.and(protocol_match(protocol, scenario));
    }
    match result {
        SelectorMatch::Matched => RichMatch::Matched,
        SelectorMatch::NotMatched => RichMatch::NotMatched,
        SelectorMatch::Partial => RichMatch::Unknown(UnknownReason::CapabilityUnavailable),
    }
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

fn protocol_match(rule: &IpProtocol, scenario: &TrafficScenario) -> SelectorMatch {
    if scenario_protocol(scenario).is_some_and(|candidate| candidate == rule.as_str()) {
        return SelectorMatch::Matched;
    }
    match (
        known_protocol_number(rule.as_str()),
        scenario_protocol_number(scenario),
    ) {
        (Some(rule), Some(candidate)) if rule == candidate => SelectorMatch::Matched,
        (Some(_), Some(_)) => SelectorMatch::NotMatched,
        _ => SelectorMatch::Partial,
    }
}

fn scenario_protocol_number(scenario: &TrafficScenario) -> Option<u8> {
    match &scenario.transport {
        TrafficTransport::Tcp => Some(6),
        TrafficTransport::Udp => Some(17),
        TrafficTransport::Icmp { .. } => scenario.source.family().map(|family| match family {
            AddressFamily::Ipv4 => 1,
            AddressFamily::Ipv6 => 58,
        }),
        TrafficTransport::RawProtocol { protocol } => known_protocol_number(protocol.as_str()),
    }
}

fn known_protocol_number(raw: &str) -> Option<u8> {
    match raw {
        "icmp" => Some(1),
        "igmp" => Some(2),
        "tcp" => Some(6),
        "udp" => Some(17),
        "gre" => Some(47),
        "esp" => Some(50),
        "ah" => Some(51),
        "ipv6-icmp" | "icmpv6" => Some(58),
        numeric => numeric.parse().ok(),
    }
}

enum ServiceMatch {
    Matched,
    NotMatched,
    Unknown(UnknownReason),
}

enum RichMatch {
    Matched,
    NotMatched,
    Unknown(UnknownReason),
}

fn service_resolution_match(
    index: &TrafficEvaluationIndex,
    resolution: &ServiceResolution,
    scenario: &TrafficScenario,
) -> ServiceMatch {
    let mut result = ServiceMatch::NotMatched;
    for name in &resolution.services {
        let Some(definition) = index.service_definition(name) else {
            return ServiceMatch::Unknown(UnknownReason::IncompleteServiceDefinition);
        };
        match service_definition_match(definition, scenario) {
            ServiceMatch::Matched => return ServiceMatch::Matched,
            ServiceMatch::Unknown(reason) => result = ServiceMatch::Unknown(reason),
            ServiceMatch::NotMatched => {}
        }
    }
    result
}

fn service_definition_match(
    definition: &ServiceDefinition,
    scenario: &TrafficScenario,
) -> ServiceMatch {
    let primitive = primitive_match(
        &definition.ports,
        &definition.source_ports,
        &definition.protocols,
        scenario,
    );
    if primitive == SelectorMatch::NotMatched {
        return ServiceMatch::NotMatched;
    }

    if matches!(scenario.destination, TrafficDestination::LocalHost)
        && scenario.source.family().is_some_and(|family| {
            definition
                .destinations
                .iter()
                .any(|destination| destination.family == family)
        })
    {
        return ServiceMatch::Unknown(UnknownReason::UnsupportedServiceFeature);
    }

    let destination = service_destination_match(definition, scenario);
    let matched = primitive.and(destination);
    if matched == SelectorMatch::NotMatched {
        return ServiceMatch::NotMatched;
    }
    if !definition.helpers.is_empty() || !definition.modules.is_empty() {
        return ServiceMatch::Unknown(UnknownReason::UnsupportedServiceFeature);
    }
    match matched {
        SelectorMatch::Matched => ServiceMatch::Matched,
        SelectorMatch::NotMatched => ServiceMatch::NotMatched,
        SelectorMatch::Partial => ServiceMatch::Unknown(UnknownReason::CapabilityUnavailable),
    }
}

fn service_destination_match(
    definition: &ServiceDefinition,
    scenario: &TrafficScenario,
) -> SelectorMatch {
    if definition.destinations.is_empty() {
        return SelectorMatch::Matched;
    }
    let Some(family) = scenario.source.family() else {
        return SelectorMatch::Partial;
    };
    let matching_family: Vec<&SourceAddress> = definition
        .destinations
        .iter()
        .filter(|destination| destination.family == family)
        .map(|destination| &destination.address)
        .collect();
    if matching_family.is_empty() {
        return SelectorMatch::NotMatched;
    }
    let TrafficDestination::Address(candidate) = &scenario.destination else {
        return SelectorMatch::Partial;
    };
    matching_family
        .into_iter()
        .fold(SelectorMatch::NotMatched, |result, destination| {
            result.or(source_selector_match(destination, candidate))
        })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SelectorMatch {
    Matched,
    NotMatched,
    Partial,
}

impl SelectorMatch {
    const fn and(self, other: Self) -> Self {
        match (self, other) {
            (Self::NotMatched, _) | (_, Self::NotMatched) => Self::NotMatched,
            (Self::Matched, Self::Matched) => Self::Matched,
            (Self::Matched | Self::Partial, Self::Matched | Self::Partial) => Self::Partial,
        }
    }

    const fn or(self, other: Self) -> Self {
        match (self, other) {
            (Self::Matched, _) | (_, Self::Matched) => Self::Matched,
            (Self::Partial, _) | (_, Self::Partial) => Self::Partial,
            (Self::NotMatched, Self::NotMatched) => Self::NotMatched,
        }
    }

    const fn inverted(self) -> Self {
        match self {
            Self::Matched => Self::NotMatched,
            Self::NotMatched => Self::Matched,
            Self::Partial => Self::Partial,
        }
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

fn source_selector_match(binding: &SourceAddress, candidate: &SourceAddress) -> SelectorMatch {
    let (
        SourceAddress::Ip {
            addr: binding_address,
            prefix: binding_prefix,
        },
        SourceAddress::Ip {
            addr: candidate_address,
            prefix: candidate_prefix,
        },
    ) = (binding, candidate)
    else {
        return SelectorMatch::Partial;
    };
    if binding_address.is_ipv4() != candidate_address.is_ipv4() {
        return SelectorMatch::NotMatched;
    }
    let binding_prefix = binding_prefix.unwrap_or_else(|| max_prefix(*binding_address));
    let candidate_prefix = candidate_prefix.unwrap_or_else(|| max_prefix(*candidate_address));
    if binding_prefix <= candidate_prefix
        && cidr_contains(*binding_address, binding_prefix, *candidate_address)
    {
        SelectorMatch::Matched
    } else if candidate_prefix < binding_prefix
        && cidr_contains(*candidate_address, candidate_prefix, *binding_address)
    {
        SelectorMatch::Partial
    } else {
        SelectorMatch::NotMatched
    }
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

fn selector_match(rule: PortSelector, query: PortSelector) -> SelectorMatch {
    let (rule_start, rule_end) = selector_bounds(rule);
    let (query_start, query_end) = selector_bounds(query);
    if rule_start <= query_start && query_end <= rule_end {
        SelectorMatch::Matched
    } else if rule_end < query_start || query_end < rule_start {
        SelectorMatch::NotMatched
    } else {
        SelectorMatch::Partial
    }
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
    TrafficTestResult::new(
        scenario.id.clone(),
        scenario.expectation,
        decision,
        reason,
        trace,
    )
    .map_err(TrafficEvaluationError::from)
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

#[cfg(test)]
#[path = "evaluator_private_tests.rs"]
mod private_tests;
