use super::super::*;
use crate::domain::*;

fn presentation(trace: Vec<TrafficTraceStep>) -> TrafficPresentation {
    let mut view = TrafficPresentation::from_workspace(&tests::completed_workspace());
    let EvaluationState::Completed(report) = &view.evaluation else {
        panic!("missing report")
    };
    let result = TrafficTestResult::new(
        TrafficScenarioId::parse("case-0").unwrap(),
        TrafficExpectation::Allow,
        FirewallDecision::Unknown,
        Some(UnknownReason::IncompleteSnapshot),
        trace,
    )
    .unwrap();
    view.evaluation = EvaluationState::Completed(Arc::new(
        TrafficTestReport::new(report.context().clone(), vec![result]).unwrap(),
    ));
    view
}

fn lines(view: &TrafficPresentation) -> Vec<(String, String)> {
    view.details(&TrafficScenarioId::parse("case-0").unwrap())
        .unwrap()
        .lines
}

#[test]
fn current_details_preserve_ordered_typed_trace_and_unknown_stage() {
    let view = presentation(vec![
        TrafficTraceStep::new(
            TrafficTraceStage::CompletenessCheck,
            TrafficTraceOutcome::Unknown(UnknownReason::IncompleteSnapshot),
        )
        .with_object(TraceObjectRef::Zone(ZoneName::parse("public").unwrap())),
        TrafficTraceStep::new(
            TrafficTraceStage::Decision,
            TrafficTraceOutcome::Decision(FirewallDecision::Unknown),
        ),
        TrafficTraceStep::new(
            TrafficTraceStage::Status,
            TrafficTraceOutcome::Status(TrafficTestStatus::Indeterminate),
        ),
    ]);
    let lines = lines(&view);
    assert!(lines.contains(&("Unknown reason".into(), "Incomplete snapshot".into())));
    assert!(lines.contains(&("Blocked stage".into(), "Completeness check".into())));
    let trace: Vec<_> = lines
        .iter()
        .filter(|(label, _)| label.starts_with("Trace "))
        .map(|(_, value)| value.as_str())
        .collect();
    assert_eq!(
        trace,
        [
            "Completeness check: Unknown — Incomplete snapshot; zone: public",
            "Decision: Unknown",
            "Status: Indeterminate"
        ]
    );
}

#[test]
fn summary_precedes_inputs_and_technical_evidence() {
    let lines = lines(&presentation(vec![]));
    let summary = lines.iter().position(|(key, _)| key == "Summary").unwrap();
    let inputs = lines
        .iter()
        .position(|(key, _)| key == "Scenario inputs")
        .unwrap();
    let technical = lines
        .iter()
        .position(|(key, _)| key == "Technical details")
        .unwrap();
    assert!(summary < inputs && inputs < technical);
    assert_eq!(
        lines[summary].1,
        "Configuration only; live connectivity: NOT VERIFIED"
    );
    for label in [
        "Status",
        "Target",
        "Expected outcome",
        "Current outcome",
        "Next action",
    ] {
        assert!(lines[summary..inputs].iter().any(|(key, _)| key == label));
    }
}

#[test]
fn current_fail_summary_explains_expectation_mismatch() {
    let mut view = presentation(vec![]);
    let EvaluationState::Completed(report) = &view.evaluation else {
        unreachable!()
    };
    let result = TrafficTestResult::new(
        TrafficScenarioId::parse("case-0").unwrap(),
        TrafficExpectation::Allow,
        FirewallDecision::Block,
        None,
        vec![],
    )
    .unwrap();
    view.evaluation = EvaluationState::Completed(Arc::new(
        TrafficTestReport::new(report.context().clone(), vec![result]).unwrap(),
    ));
    let text = lines(&view);
    assert!(text.contains(&(
        "Reason".into(),
        "Expected Allow but configuration evaluates Block".into()
    )));
}

#[test]
fn in_progress_and_terminal_errors_have_summary_reasons_and_next_actions() {
    let base = presentation(vec![]);
    let EvaluationState::Completed(report) = &base.evaluation else {
        unreachable!()
    };
    let context = report.context().clone();
    for (evaluation, reason, next) in [
        (
            EvaluationState::Queued(context.clone()),
            "Evaluation queued",
            "Wait for the captured configuration evaluation to finish",
        ),
        (
            EvaluationState::Failed {
                context: context.clone(),
                reason: crate::application::WorkspaceFailure::WorkerFailed,
            },
            "Worker failed",
            "Resolve the reason, then evaluate again against current evidence",
        ),
        (
            EvaluationState::Cancelled {
                context,
                reason: crate::application::TrafficTestCancellationReason::StaleContext,
            },
            "Stale context",
            "Resolve the reason, then evaluate again against current evidence",
        ),
    ] {
        let mut view = base.clone();
        view.evaluation = evaluation;
        let text = lines(&view);
        assert!(text.contains(&("Reason".into(), reason.into())));
        assert!(text.contains(&("Next action".into(), next.into())));
    }
}

#[test]
fn current_inputs_are_complete_and_without_debug_wrappers() {
    let lines = lines(&presentation(vec![]));
    assert!(lines.contains(&("Enabled".into(), "yes".into())));
    assert!(lines.contains(&("Destination".into(), "Local host".into())));
    assert!(lines.contains(&("Source / destination ports".into(), "- / 22".into())));
    assert!(lines.iter().any(|(key, value)| key == "Current context"
        && value.contains("phase Current")
        && value.contains("snapshot refresh 1 / generation 1")));
}

#[test]
fn mismatched_completed_identity_is_historical_not_current() {
    for mismatch in 0..6 {
        let mut view = presentation(vec![TrafficTraceStep::new(
            TrafficTraceStage::Decision,
            TrafficTraceOutcome::Decision(FirewallDecision::Unknown),
        )]);
        match mismatch {
            0 => {
                let SuiteState::Available(suite) = &mut view.suite else {
                    unreachable!()
                };
                Arc::make_mut(suite).id = TrafficSuiteId::parse("other").unwrap();
            }
            1 => {
                let SuiteState::Available(suite) = &mut view.suite else {
                    unreachable!()
                };
                Arc::make_mut(suite).revision = TrafficSuiteRevision::new(2).unwrap();
            }
            2 => view.target = EvaluationTarget::Permanent,
            3 => view.current_snapshot = None,
            4 => view.authoritative = false,
            _ => {
                view.current_snapshot = Some(crate::application::SnapshotIdentity::new(
                    crate::application::RefreshId::new(99),
                    crate::application::SnapshotGeneration::new(std::num::NonZeroU64::MIN),
                ));
            }
        }
        assert_eq!(view.rows()[0][4], "Stale", "mismatch {mismatch}");
        let text = lines(&view);
        assert!(!text.iter().any(|(key, _)| key == "Current context"));
        assert!(
            text.iter()
                .any(|(key, _)| key.starts_with("Historical context"))
        );
        if mismatch == 0 {
            assert!(!text.iter().any(|(key, _)| key.starts_with("Trace ")));
            assert!(
                text.iter().any(|(_, value)| value
                    == "No matching historical result for this suite and scenario")
            );
        } else {
            assert!(
                text.iter()
                    .any(|(_, value)| value.contains("Original scenario inputs were not retained"))
            );
        }
    }
}

#[test]
fn history_uses_exact_scenario_and_its_own_expectation() {
    let mut view = presentation(vec![]);
    let EvaluationState::Completed(report) = view.evaluation.clone() else {
        unreachable!()
    };
    view.stale_report = Some(report.clone());
    view.evaluation = EvaluationState::NotRun;
    let SuiteState::Available(suite) = &mut view.suite else {
        unreachable!()
    };
    let suite = Arc::make_mut(suite);
    suite.revision = TrafficSuiteRevision::new(2).unwrap();
    suite.scenarios[0].expectation = TrafficExpectation::Block;
    let text = lines(&view);
    assert!(text.contains(&("Expected outcome".into(), "Block".into())));
    assert!(text.contains(&("Result expectation".into(), "Allow".into())));
    let SuiteState::Available(suite) = &mut view.suite else {
        unreachable!()
    };
    Arc::make_mut(suite).scenarios[0].id = TrafficScenarioId::parse("replacement").unwrap();
    let text = view
        .details(&TrafficScenarioId::parse("replacement").unwrap())
        .unwrap()
        .lines;
    assert!(!text.iter().any(|(key, _)| key == "Result decision"));
    assert!(
        text.iter()
            .any(|(_, value)| value == "No matching historical result for this suite and scenario")
    );
}

#[test]
fn no_result_states_never_fabricate_decision_or_unknown_stage() {
    let base = presentation(vec![]);
    let EvaluationState::Completed(report) = &base.evaluation else {
        unreachable!()
    };
    let context = report.context().clone();
    for evaluation in [
        EvaluationState::NotRun,
        EvaluationState::Queued(context.clone()),
        EvaluationState::Running(context.clone()),
        EvaluationState::Failed {
            context: context.clone(),
            reason: crate::application::WorkspaceFailure::WorkerFailed,
        },
        EvaluationState::Cancelled {
            context: context.clone(),
            reason: crate::application::TrafficTestCancellationReason::Superseded,
        },
        EvaluationState::Completed(Arc::new(
            TrafficTestReport::new(context.clone(), vec![]).unwrap(),
        )),
    ] {
        let mut view = base.clone();
        view.evaluation = evaluation;
        let text = lines(&view);
        assert!(
            text.iter().any(|(key, _)| key == "Result unavailable"),
            "{:?}",
            view.evaluation
        );
        assert!(
            !text
                .iter()
                .any(|(key, _)| key == "Blocked stage" || key == "Result decision")
        );
        if matches!(view.evaluation, EvaluationState::Cancelled { .. }) {
            assert!(text.contains(&("Cancellation reason".into(), "Superseded".into())));
        }
        if matches!(view.evaluation, EvaluationState::Failed { .. }) {
            assert!(text.contains(&("Failure reason".into(), "Worker failed".into())));
        }
    }
    let text = base
        .details(&TrafficScenarioId::parse("case-1").unwrap())
        .unwrap()
        .lines;
    assert!(text.iter().any(|(key, _)| key == "Result unavailable"));
    assert!(!text.iter().any(|(key, _)| key == "Result decision"));
}

#[test]
fn open_details_remain_explicitly_capture_scoped_after_presentation_changes() {
    let mut state = tests::state();
    state.traffic = presentation(vec![]);
    let action = crate::ui::keymap::translate(
        &state,
        crossterm::event::KeyEvent::from(crossterm::event::KeyCode::Enter),
    )
    .unwrap();
    crate::ui::update::update(&mut state, action);
    let before = state.overlays.last().cloned();
    let mut replacement = state.traffic.clone();
    replacement.evaluation = EvaluationState::NotRun;
    replacement.current_snapshot = None;
    crate::ui::update::update(
        &mut state,
        crate::ui::action::UiAction::TrafficPresented(replacement),
    );
    assert_eq!(state.overlays.last(), before.as_ref());
    let Some(crate::ui::overlays::Overlay::Details(content)) = state.overlays.last() else {
        panic!("missing details")
    };
    let captured = content
        .lines
        .iter()
        .find(|(key, _)| key == "Captured at opening")
        .unwrap();
    assert!(captured.1.contains("not refreshed"));
    assert!(captured.1.contains("Current labels"));
}

#[test]
fn maximum_trace_wraps_long_reference_and_scrolls_to_final_status() {
    use crate::ui::{action::UiAction, overlays::Overlay};
    let name = format!("{}LONG_REF_END", "evidence".repeat(6));
    let mut trace = vec![
        TrafficTraceStep::new(
            TrafficTraceStage::IdentityCheck,
            TrafficTraceOutcome::Matched
        );
        MAX_TRACE_STEPS - 2
    ];
    trace.push(
        TrafficTraceStep::new(
            TrafficTraceStage::ServiceExpansion,
            TrafficTraceOutcome::Expanded,
        )
        .with_object(TraceObjectRef::Service(ServiceName::parse(&name).unwrap())),
    );
    trace.push(TrafficTraceStep::new(
        TrafficTraceStage::Status,
        TrafficTraceOutcome::Status(TrafficTestStatus::Indeterminate),
    ));
    let view = presentation(trace);
    let content = view
        .details(&TrafficScenarioId::parse("case-0").unwrap())
        .unwrap();
    assert_eq!(
        content
            .lines
            .iter()
            .filter(|(key, _)| key.starts_with("Trace "))
            .count(),
        MAX_TRACE_STEPS
    );
    assert!(content.lines.iter().any(|(_, value)| value.contains(&name)));
    for width in [80, 160] {
        let mut state = tests::state();
        state.traffic = view.clone();
        state.overlays.push(Overlay::Details(content.clone()));
        let theme = crate::ui::theme::Theme::detect(crate::ui::theme::Variant::Mono, false);
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(width, 24)).unwrap();
        crate::ui::update::update(&mut state, UiAction::ScrollOverlay(i32::MAX));
        terminal
            .draw(|frame| crate::ui::render::render(frame, &mut state, &theme))
            .unwrap();
        let text: String = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(ratatui::buffer::Cell::symbol)
            .collect();
        assert!(
            text.contains("LONG_REF_END"),
            "reference tail clipped at {width}"
        );
        assert!(
            text.contains("Status: Indeterminate"),
            "final status unreachable at {width}"
        );
    }
}

#[test]
#[allow(clippy::too_many_lines)] // Exhaustive stage, outcome and object evidence matrix.
fn every_stage_outcome_and_object_has_readable_ordered_evidence() {
    let stages = [
        TrafficTraceStage::ScenarioNormalization,
        TrafficTraceStage::IdentityCheck,
        TrafficTraceStage::CapabilityCheck,
        TrafficTraceStage::CompletenessCheck,
        TrafficTraceStage::IngressResolution,
        TrafficTraceStage::EgressResolution,
        TrafficTraceStage::PathResolution,
        TrafficTraceStage::ServiceExpansion,
        TrafficTraceStage::PolicyEvaluation,
        TrafficTraceStage::RichRuleEvaluation,
        TrafficTraceStage::ZoneEvaluation,
        TrafficTraceStage::TargetEvaluation,
        TrafficTraceStage::Decision,
        TrafficTraceStage::ExpectationComparison,
        TrafficTraceStage::Status,
    ];
    let labels = [
        "Scenario normalization",
        "Identity check",
        "Capability check",
        "Completeness check",
        "Ingress resolution",
        "Egress resolution",
        "Path resolution",
        "Service expansion",
        "Policy evaluation",
        "Rich rule evaluation",
        "Zone evaluation",
        "Target evaluation",
        "Decision",
        "Expectation comparison",
        "Status",
    ];
    let references = [
        (
            TraceObjectRef::SnapshotSection(SnapshotSection::Services),
            "snapshot section: services",
        ),
        (
            TraceObjectRef::Zone(ZoneName::parse("public").unwrap()),
            "zone: public",
        ),
        (
            TraceObjectRef::Policy(PolicyName::parse("trusted").unwrap()),
            "policy: trusted",
        ),
        (
            TraceObjectRef::Service(ServiceName::parse("ssh").unwrap()),
            "service: ssh",
        ),
        (
            TraceObjectRef::RichRule {
                zone: ZoneName::parse("public").unwrap(),
                index: 7,
            },
            "zone: public; rich rule index: 7",
        ),
        (
            TraceObjectRef::PolicyRichRule {
                policy: PolicyName::parse("trusted").unwrap(),
                index: 8,
            },
            "policy: trusted; rich rule index: 8",
        ),
        (
            TraceObjectRef::DirectRule { index: 9 },
            "direct rule index: 9",
        ),
    ];
    let outcomes = [
        (TrafficTraceOutcome::Matched, "Matched"),
        (TrafficTraceOutcome::NotMatched, "Not matched"),
        (TrafficTraceOutcome::Selected, "Selected"),
        (TrafficTraceOutcome::Expanded, "Expanded"),
        (TrafficTraceOutcome::Continued, "Continued"),
        (
            TrafficTraceOutcome::Decision(FirewallDecision::Allow),
            "Allow",
        ),
        (TrafficTraceOutcome::Status(TrafficTestStatus::Pass), "Pass"),
        (
            TrafficTraceOutcome::Unknown(UnknownReason::MissingRouteData),
            "Unknown — Missing route data",
        ),
    ];
    let trace = stages
        .iter()
        .enumerate()
        .map(|(i, stage)| {
            TrafficTraceStep::new(*stage, outcomes[i % outcomes.len()].0)
                .with_object(references[i % references.len()].0.clone())
        })
        .collect();
    let text = lines(&presentation(trace));
    let trace: Vec<_> = text
        .iter()
        .filter(|(key, _)| key.starts_with("Trace "))
        .collect();
    assert_eq!(
        trace.len(),
        stages.len(),
        "every stage must retain its trace"
    );
    for (i, (label, value)) in trace.iter().enumerate() {
        assert_eq!(label, &format!("Trace {}", i + 1));
        assert_eq!(
            value,
            &format!(
                "{}: {}; {}",
                labels[i],
                outcomes[i % outcomes.len()].1,
                references[i % references.len()].1
            )
        );
    }
}

#[test]
fn unrecorded_unknown_stage_is_explicitly_absent() {
    let text = lines(&presentation(vec![]));
    assert!(text.contains(&(
        "Blocked stage unavailable".into(),
        "Not recorded in the result trace".into()
    )));
    assert!(!text.iter().any(|(key, _)| key == "Blocked stage"));
}

#[test]
fn historical_allow_pass_never_becomes_current_evidence() {
    let mut view = presentation(vec![]);
    let EvaluationState::Completed(report) = &view.evaluation else {
        unreachable!()
    };
    let result = TrafficTestResult::new(
        TrafficScenarioId::parse("case-0").unwrap(),
        TrafficExpectation::Allow,
        FirewallDecision::Allow,
        None,
        vec![],
    )
    .unwrap();
    view.evaluation = EvaluationState::Stale(Arc::new(
        TrafficTestReport::new(report.context().clone(), vec![result]).unwrap(),
    ));
    let text = lines(&view);
    assert!(text.contains(&("Status".into(), "Stale".into())));
    assert!(text.contains(&("Current outcome".into(), "-".into())));
    assert!(text.contains(&("Result decision".into(), "Allow".into())));
    assert!(text.contains(&("Result status".into(), "Pass".into())));
    assert!(
        text.iter()
            .position(|(key, _)| key.starts_with("Historical result ("))
            < text.iter().position(|(key, _)| key == "Result decision")
    );
}

#[test]
fn current_result_requires_phase_and_snapshot_generation_match() {
    for phase_mismatch in [false, true] {
        let mut view = presentation(vec![]);
        let EvaluationState::Completed(report) = &view.evaluation else {
            unreachable!()
        };
        let mut context = report.context().clone();
        if phase_mismatch {
            context.phase = EvaluationPhase::PostApply;
            context.mutation_intent_id = Some(MutationIntentId::new(8).unwrap());
        } else {
            context.authoritative_snapshot = EvaluationSnapshotIdentity::new(1, 2).unwrap();
        }
        view.evaluation = EvaluationState::Completed(Arc::new(
            TrafficTestReport::new(context, report.results().to_vec()).unwrap(),
        ));
        assert_eq!(view.rows()[0][4], "Stale");
        assert!(!lines(&view).iter().any(|(key, _)| key == "Current context"));
    }
}

#[test]
fn concrete_inputs_keep_typed_values_without_option_or_newtype_wrappers() {
    let mut view = presentation(vec![]);
    let SuiteState::Available(suite) = &mut view.suite else {
        unreachable!()
    };
    let scenario = &mut Arc::make_mut(suite).scenarios[0];
    scenario.ingress_interface = Some(InterfaceName::parse("eth0").unwrap());
    scenario.ingress_zone = Some(ZoneName::parse("public").unwrap());
    scenario.egress_interface = Some(InterfaceName::parse("eth1").unwrap());
    scenario.egress_zone = Some(ZoneName::parse("trusted").unwrap());
    scenario.destination =
        TrafficDestination::Address(SourceAddress::parse("198.51.100.2").unwrap());
    scenario.source_port = Some("1024-2048".parse().unwrap());
    scenario.note = Some("Operator note".into());
    let text = lines(&view);
    for pair in [
        ("Ingress interface / zone", "eth0 / public"),
        ("Egress interface / zone", "eth1 / trusted"),
        ("Destination", "198.51.100.2"),
        ("Source / destination ports", "1024-2048 / 22"),
        ("Note", "Operator note"),
    ] {
        assert!(text.contains(&(pair.0.into(), pair.1.into())));
    }
    for (transport, expected) in [
        (TrafficTransport::Udp, "UDP"),
        (
            TrafficTransport::Icmp {
                icmp_type: IcmpType::parse("echo-request").unwrap(),
            },
            "ICMP: echo-request",
        ),
        (
            TrafficTransport::RawProtocol {
                protocol: IpProtocol::parse("gre").unwrap(),
            },
            "IP protocol: gre",
        ),
    ] {
        let SuiteState::Available(suite) = &mut view.suite else {
            unreachable!()
        };
        Arc::make_mut(suite).scenarios[0].transport = transport;
        assert!(lines(&view).contains(&("Transport".into(), expected.into())));
    }
}
