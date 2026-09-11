//! Capture-scoped scenario inputs and immutable, identity-safe result evidence.

use super::TrafficPresentation;
use crate::application::{EvaluationState, SuiteState};
use crate::domain::{
    EvaluationContext, TraceObjectRef, TrafficDestination, TrafficDirection, TrafficScenario,
    TrafficScenarioId, TrafficSuite, TrafficTestReport, TrafficTestResult, TrafficTraceOutcome,
    TrafficTraceStage, TrafficTransport, UnknownReason,
};
use crate::ui::details::DetailsContent;

type Lines = Vec<(String, String)>;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests;

pub(super) fn build(view: &TrafficPresentation, id: &TrafficScenarioId) -> Option<DetailsContent> {
    let SuiteState::Available(suite) = &view.suite else {
        return None;
    };
    let scenario = suite.scenarios.iter().find(|scenario| &scenario.id == id)?;
    let mut lines = summary(view, scenario);
    lines.extend(inputs(scenario));
    lines.extend(technical(view, suite, scenario));
    current_result(&mut lines, view, scenario);
    let primary_history = match &view.evaluation {
        EvaluationState::Stale(report) => Some(report),
        EvaluationState::Completed(report) if !view.report_is_current(report) => Some(report),
        _ => None,
    };
    if let Some(report) = primary_history.or(view.stale_report.as_ref()) {
        lines.push((String::new(), String::new()));
        lines.push((
            "Historical evidence / trace".into(),
            "Not current evidence".into(),
        ));
        historical_result(&mut lines, suite, id, report);
    }
    Some(DetailsContent {
        title: "Traffic scenario".into(),
        lines,
    })
}

fn optional(value: Option<&impl std::fmt::Display>) -> String {
    value.map_or_else(|| "-".into(), ToString::to_string)
}

fn summary(view: &TrafficPresentation, scenario: &TrafficScenario) -> Lines {
    let (actual, status) = view.outcome(scenario);
    let reason = if scenario.enabled {
        match &view.evaluation {
            EvaluationState::Completed(report) if view.report_is_current(report) => report
                .results()
                .iter()
                .find(|result| result.scenario_id() == &scenario.id)
                .map_or_else(
                    || "No matching current result".into(),
                    result_summary_reason,
                ),
            EvaluationState::Completed(_) | EvaluationState::Stale(_) => {
                "Captured result is historical, not current evidence".into()
            }
            EvaluationState::Failed { reason, .. } => failure_reason(reason).into(),
            EvaluationState::Cancelled { reason, .. } => cancellation_reason(*reason).into(),
            EvaluationState::Queued(_) => "Evaluation queued".into(),
            EvaluationState::Running(_) => "Evaluation running".into(),
            EvaluationState::NotRun if view.stale_report.is_some() => {
                "Historical result exists but is not current evidence".into()
            }
            EvaluationState::NotRun => "-".into(),
        }
    } else {
        "Scenario disabled; it is not evaluated".into()
    };
    let next = if !scenario.enabled {
        "Enable and explicitly save the scenario before evaluating"
    } else if status == "Queued" || status == "Running" {
        "Wait for the captured configuration evaluation to finish"
    } else if status.starts_with("Failed") || status == "Cancelled" {
        "Resolve the reason, then evaluate again against current evidence"
    } else if status == "Stale" {
        "Evaluate again against the current suite, target and authoritative snapshot"
    } else if actual == "-" {
        "Run configuration evaluation when the suite and snapshot are ready"
    } else {
        "Review the ordered trace; live connectivity remains NOT VERIFIED"
    };
    vec![
        (
            "Summary".into(),
            "Configuration only; live connectivity: NOT VERIFIED".into(),
        ),
        ("Status".into(), status),
        ("Target".into(), format!("{:?}", view.target)),
        (
            "Expected outcome".into(),
            format!("{:?}", scenario.expectation),
        ),
        ("Current outcome".into(), actual),
        ("Reason".into(), reason),
        ("Next action".into(), next.into()),
    ]
}

fn result_summary_reason(result: &TrafficTestResult) -> String {
    if let Some(reason) = result.unknown_reason() {
        return unknown(reason).into();
    }
    if result.status() == crate::domain::TrafficTestStatus::Fail {
        return format!(
            "Expected {:?} but configuration evaluates {:?}",
            result.expectation(),
            result.decision()
        );
    }
    "-".into()
}

pub(in crate::ui) fn inputs(scenario: &TrafficScenario) -> Lines {
    vec![
        (String::new(), String::new()),
        (
            "Scenario inputs".into(),
            "Current captured scenario inputs".into(),
        ),
        ("Name".into(), scenario.name.clone()),
        (
            "Enabled".into(),
            if scenario.enabled { "yes" } else { "no" }.into(),
        ),
        (
            "Direction".into(),
            match scenario.direction {
                TrafficDirection::ToHost => "To host",
                TrafficDirection::FromHost => "From host",
                TrafficDirection::Forwarded => "Forwarded",
            }
            .into(),
        ),
        ("Source".into(), scenario.source.to_string()),
        (
            "Ingress interface / zone".into(),
            format!(
                "{} / {}",
                optional(scenario.ingress_interface.as_ref()),
                optional(scenario.ingress_zone.as_ref())
            ),
        ),
        (
            "Destination".into(),
            match &scenario.destination {
                TrafficDestination::LocalHost => "Local host".into(),
                TrafficDestination::Address(address) => address.to_string(),
            },
        ),
        (
            "Egress interface / zone".into(),
            format!(
                "{} / {}",
                optional(scenario.egress_interface.as_ref()),
                optional(scenario.egress_zone.as_ref())
            ),
        ),
        (
            "Transport".into(),
            match &scenario.transport {
                TrafficTransport::Tcp => "TCP".into(),
                TrafficTransport::Udp => "UDP".into(),
                TrafficTransport::Icmp { icmp_type } => format!("ICMP: {icmp_type}"),
                TrafficTransport::RawProtocol { protocol } => format!("IP protocol: {protocol}"),
            },
        ),
        (
            "Source / destination ports".into(),
            format!(
                "{} / {}",
                optional(scenario.source_port.as_ref()),
                optional(scenario.destination_port.as_ref())
            ),
        ),
        (
            "Connection state".into(),
            format!("{:?}", scenario.connection_state),
        ),
        ("Severity".into(), format!("{:?}", scenario.severity)),
        (
            "Note".into(),
            scenario.note.clone().unwrap_or_else(|| "-".into()),
        ),
    ]
}

fn technical(
    view: &TrafficPresentation,
    suite: &TrafficSuite,
    scenario: &TrafficScenario,
) -> Lines {
    let mut lines = vec![
        (String::new(), String::new()),
        ("Technical details".into(), "Identity and safety metadata".into()),
        ("Captured at opening".into(), "Immutable details; not refreshed. Current labels refer only to this captured observation, not live state. Reopen after changes.".into()),
        ("Evaluation".into(), "Configuration evaluation; Live connectivity: NOT VERIFIED".into()),
        ("Scenario ID".into(), scenario.id.to_string()),
        ("Required safety gate".into(), format!("{}; not enforced in Phase 2", scenario.required_safety_gate)),
        ("Suite".into(), format!("{} revision {}", suite.id, suite.revision.get())),
        ("Suite name".into(), suite.name.clone()),
    ];
    if let Some(identity) = view.current_snapshot {
        lines.push((
            "Current authoritative snapshot".into(),
            format!(
                "refresh {} / generation {}",
                identity.refresh_id().get(),
                identity.generation().get()
            ),
        ));
    }
    lines
}

fn current_result(lines: &mut Lines, view: &TrafficPresentation, scenario: &TrafficScenario) {
    match &view.evaluation {
        EvaluationState::Completed(report) if view.report_is_current(report) => {
            lines.push((
                "Current context".into(),
                format!("Captured-current: {}", context(report.context())),
            ));
            if scenario.enabled
                && let Some(result) = report
                    .results()
                    .iter()
                    .find(|result| result.scenario_id() == &scenario.id)
            {
                lines.push((
                    "Current result (captured)".into(),
                    "Matches the captured suite, revision, target and observation".into(),
                ));
                result_lines(lines, result);
                return;
            }
        }
        EvaluationState::Queued(context)
        | EvaluationState::Running(context)
        | EvaluationState::Failed { context, .. }
        | EvaluationState::Cancelled { context, .. } => {
            lines.push(("Run context (captured)".into(), self::context(context)));
        }
        _ => {}
    }
    if let EvaluationState::Failed { reason, .. } = &view.evaluation {
        lines.push(("Failure reason".into(), failure_reason(reason).into()));
    }
    if let EvaluationState::Cancelled { reason, .. } = &view.evaluation {
        lines.push((
            "Cancellation reason".into(),
            cancellation_reason(*reason).into(),
        ));
    }
    lines.push((
        "Result unavailable".into(),
        if scenario.enabled {
            "No matching completed current result; no decision or trace is available"
        } else {
            "Scenario disabled; not evaluated in the current suite"
        }
        .into(),
    ));
}

fn failure_reason(reason: &crate::application::WorkspaceFailure) -> &'static str {
    match reason {
        crate::application::WorkspaceFailure::Busy => "Busy",
        crate::application::WorkspaceFailure::Closed => "Coordinator closed",
        crate::application::WorkspaceFailure::EvaluationLimitExceeded => {
            "Evaluation limit exceeded"
        }
        crate::application::WorkspaceFailure::EvaluationFailed => "Evaluation failed",
        crate::application::WorkspaceFailure::WorkerFailed => "Worker failed",
    }
}

fn cancellation_reason(reason: crate::application::TrafficTestCancellationReason) -> &'static str {
    match reason {
        crate::application::TrafficTestCancellationReason::Superseded => "Superseded",
        crate::application::TrafficTestCancellationReason::StaleContext => "Stale context",
        crate::application::TrafficTestCancellationReason::Shutdown => "Shutdown",
    }
}

fn historical_result(
    lines: &mut Lines,
    suite: &TrafficSuite,
    id: &TrafficScenarioId,
    report: &TrafficTestReport,
) {
    lines.push((
        "Historical context (not current evidence)".into(),
        context(report.context()),
    ));
    if report.context().suite_id == suite.id
        && let Some(result) = report
            .results()
            .iter()
            .find(|result| result.scenario_id() == id)
    {
        lines.push(("Historical result (not current evidence)".into(), "Original scenario inputs were not retained. The current inputs above are not a historical input snapshot.".into()));
        result_lines(lines, result);
    } else {
        lines.push((
            "Historical result unavailable".into(),
            "No matching historical result for this suite and scenario".into(),
        ));
    }
}

fn context(context: &EvaluationContext) -> String {
    format!(
        "run {} / suite {} / revision {} / target {:?} / snapshot refresh {} / generation {} / phase {:?}",
        context.run_id.get(),
        context.suite_id,
        context.suite_revision.get(),
        context.target,
        context.authoritative_snapshot.refresh_id(),
        context.authoritative_snapshot.generation(),
        context.phase
    )
}

pub(in crate::ui) fn result_lines(lines: &mut Lines, result: &TrafficTestResult) {
    lines.push((
        "Result expectation".into(),
        format!("{:?}", result.expectation()),
    ));
    lines.push(("Result decision".into(), format!("{:?}", result.decision())));
    lines.push(("Result status".into(), format!("{:?}", result.status())));
    if let Some(reason) = result.unknown_reason() {
        lines.push(("Unknown reason".into(), unknown(reason).into()));
        if let Some(step) = result
            .trace()
            .iter()
            .find(|step| step.outcome() == TrafficTraceOutcome::Unknown(reason))
        {
            lines.push(("Blocked stage".into(), stage(step.stage()).into()));
        } else {
            lines.push((
                "Blocked stage unavailable".into(),
                "Not recorded in the result trace".into(),
            ));
        }
    }
    for (index, step) in result.trace().iter().enumerate() {
        let mut value = format!("{}: {}", stage(step.stage()), outcome(step.outcome()));
        if let Some(reference) = step.object() {
            value.push_str("; ");
            value.push_str(&object(reference));
        }
        lines.push((format!("Trace {}", index + 1), value));
    }
}

fn stage(stage: TrafficTraceStage) -> &'static str {
    match stage {
        TrafficTraceStage::ScenarioNormalization => "Scenario normalization",
        TrafficTraceStage::IdentityCheck => "Identity check",
        TrafficTraceStage::CapabilityCheck => "Capability check",
        TrafficTraceStage::CompletenessCheck => "Completeness check",
        TrafficTraceStage::IngressResolution => "Ingress resolution",
        TrafficTraceStage::EgressResolution => "Egress resolution",
        TrafficTraceStage::PathResolution => "Path resolution",
        TrafficTraceStage::ServiceExpansion => "Service expansion",
        TrafficTraceStage::PolicyEvaluation => "Policy evaluation",
        TrafficTraceStage::RichRuleEvaluation => "Rich rule evaluation",
        TrafficTraceStage::ZoneEvaluation => "Zone evaluation",
        TrafficTraceStage::TargetEvaluation => "Target evaluation",
        TrafficTraceStage::Decision => "Decision",
        TrafficTraceStage::ExpectationComparison => "Expectation comparison",
        TrafficTraceStage::Status => "Status",
    }
}

fn outcome(outcome: TrafficTraceOutcome) -> String {
    match outcome {
        TrafficTraceOutcome::Matched => "Matched".into(),
        TrafficTraceOutcome::NotMatched => "Not matched".into(),
        TrafficTraceOutcome::Selected => "Selected".into(),
        TrafficTraceOutcome::Expanded => "Expanded".into(),
        TrafficTraceOutcome::Continued => "Continued".into(),
        TrafficTraceOutcome::Decision(decision) => format!("{decision:?}"),
        TrafficTraceOutcome::Status(status) => format!("{status:?}"),
        TrafficTraceOutcome::Unknown(reason) => format!("Unknown — {}", unknown(reason)),
    }
}

fn object(object: &TraceObjectRef) -> String {
    match object {
        TraceObjectRef::SnapshotSection(section) => {
            format!("snapshot section: {}", section.label())
        }
        TraceObjectRef::Zone(zone) => format!("zone: {zone}"),
        TraceObjectRef::Policy(policy) => format!("policy: {policy}"),
        TraceObjectRef::Service(service) => format!("service: {service}"),
        TraceObjectRef::RichRule { zone, index } => {
            format!("zone: {zone}; rich rule index: {index}")
        }
        TraceObjectRef::PolicyRichRule { policy, index } => {
            format!("policy: {policy}; rich rule index: {index}")
        }
        TraceObjectRef::DirectRule { index } => format!("direct rule index: {index}"),
    }
}

fn unknown(reason: UnknownReason) -> &'static str {
    match reason {
        UnknownReason::IncompleteSnapshot => "Incomplete snapshot",
        UnknownReason::UnsupportedRichRule => "Unsupported rich rule",
        UnknownReason::UnsupportedPolicyFeature => "Unsupported policy feature",
        UnknownReason::AmbiguousIngressZone => "Ambiguous ingress zone",
        UnknownReason::AmbiguousEgressZone => "Ambiguous egress zone",
        UnknownReason::MissingRouteData => "Missing route data",
        UnknownReason::UnsupportedStagedOperation => "Unsupported staged operation",
        UnknownReason::RelevantDirectRuleUnsupported => "Relevant direct rule unsupported",
        UnknownReason::StaleSnapshot => "Stale snapshot",
        UnknownReason::StalePlan => "Stale plan",
        UnknownReason::CapabilityUnavailable => "Capability unavailable",
        UnknownReason::VersionUnsupported => "Version unsupported",
        UnknownReason::ConflictingEqualPriorityRules => "Conflicting equal-priority rules",
        UnknownReason::IncompleteServiceDefinition => "Incomplete service definition",
        UnknownReason::UnsupportedServiceFeature => "Unsupported service feature",
        UnknownReason::UnsupportedConnectionState => "Unsupported connection state",
        UnknownReason::UnsupportedDirection => "Unsupported direction",
        UnknownReason::UnsupportedOperationEffect => "Unsupported operation effect",
        UnknownReason::ExternalRulesOutsideModel => "External rules outside model",
        UnknownReason::RollbackGuaranteeUnavailable => "Rollback guarantee unavailable",
    }
}
