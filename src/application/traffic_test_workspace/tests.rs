use std::sync::atomic::AtomicU64;

use super::*;
use crate::application::RefreshId;
use crate::application::observation::SnapshotPublisher;
use crate::config::Config;
use crate::domain::{
    CandidateIdentity, EvaluationPlanId, EvaluationSnapshotIdentity, FirewallDecision,
    InterfaceName, MutationIntentId, OrderedOperationDigest, PortSelector, SourceAddress,
    TrafficConnectionState, TrafficDestination, TrafficDirection, TrafficExpectation,
    TrafficScenario, TrafficScenarioId, TrafficSeverity, TrafficSuiteId, TrafficSuiteRevision,
    TrafficTestResult, TrafficTestRunId, TrafficTransport, UnknownReason,
};

fn scenario(id: &str, enabled: bool, expectation: TrafficExpectation) -> TrafficScenario {
    TrafficScenario {
        id: TrafficScenarioId::parse(id).unwrap(),
        name: id.to_owned(),
        enabled,
        direction: TrafficDirection::ToHost,
        source: SourceAddress::parse("192.0.2.0/24").unwrap(),
        ingress_interface: Some(InterfaceName::parse("eth0").unwrap()),
        ingress_zone: None,
        destination: TrafficDestination::LocalHost,
        egress_interface: None,
        egress_zone: None,
        transport: TrafficTransport::Tcp,
        destination_port: Some("22".parse::<PortSelector>().unwrap()),
        source_port: None,
        connection_state: TrafficConnectionState::New,
        expectation,
        severity: TrafficSeverity::Critical,
        required_safety_gate: true,
        note: None,
    }
}

fn suite() -> Arc<TrafficSuite> {
    Arc::new(TrafficSuite {
        id: TrafficSuiteId::parse("default").unwrap(),
        name: "Default checks".to_owned(),
        revision: TrafficSuiteRevision::new(1).unwrap(),
        scenarios: vec![
            scenario("enabled", true, TrafficExpectation::Allow),
            scenario("disabled", false, TrafficExpectation::Block),
        ],
    })
}

fn invalid_suite() -> Arc<TrafficSuite> {
    let mut invalid = suite().as_ref().clone();
    invalid.name = " ".to_owned();
    Arc::new(invalid)
}

fn observation(generation: u64) -> ObservedSnapshot {
    let mut publisher = SnapshotPublisher::new();
    let snapshot = Arc::new(crate::domain::mock::sample().unwrap());
    let mut observed = publisher
        .publish(RefreshId::new(10), Arc::clone(&snapshot))
        .unwrap();
    for current in 2..=generation {
        observed = publisher
            .publish(RefreshId::new(current + 10), Arc::clone(&snapshot))
            .unwrap();
    }
    observed
}

fn ready_workspace() -> (TrafficTestWorkspace, PreparedTrafficEvaluation) {
    let mut workspace = TrafficTestWorkspace::new(false);
    workspace.replace_suite(suite()).unwrap();
    workspace.observe(observation(1));
    let prepared = workspace.prepare_evaluation().unwrap();
    (workspace, prepared)
}

fn result(
    id: &str,
    expectation: TrafficExpectation,
    decision: FirewallDecision,
) -> TrafficTestResult {
    TrafficTestResult::new(
        TrafficScenarioId::parse(id).unwrap(),
        expectation,
        decision,
        (decision == FirewallDecision::Unknown).then_some(UnknownReason::IncompleteSnapshot),
        Vec::new(),
    )
    .unwrap()
}

fn report(context: EvaluationContext, results: Vec<TrafficTestResult>) -> Arc<TrafficTestReport> {
    Arc::new(TrafficTestReport::new(context, results).unwrap())
}

#[test]
fn construction_has_no_implicit_work_and_selects_mode_target() {
    let online = TrafficTestWorkspace::new(false);
    assert_eq!(online.target(), EvaluationTarget::Runtime);
    assert!(matches!(online.suite_state(), SuiteState::NotLoaded));
    assert!(online.observation().is_none());
    assert!(matches!(online.evaluation_state(), EvaluationState::NotRun));
    assert_eq!(
        TrafficTestWorkspace::new(true).target(),
        EvaluationTarget::Permanent
    );
}

#[test]
fn load_tokens_are_unique_and_only_active_completion_is_accepted() {
    let mut workspace = TrafficTestWorkspace::new(false);
    let old = workspace.begin_load().unwrap();
    let active = workspace.begin_load().unwrap();
    assert_ne!(old, active);
    assert!(!workspace.finish_load(old, SuiteLoadOutcome::Missing));
    assert!(matches!(workspace.suite_state(), SuiteState::Loading(token) if *token == active));
    assert!(workspace.finish_load(active, SuiteLoadOutcome::Missing));
    assert!(!workspace.finish_load(active, SuiteLoadOutcome::Available(suite())));
}

#[test]
fn every_load_outcome_is_explicit_and_invalid_content_is_failure() {
    let cases = [
        (SuiteLoadOutcome::UnsupportedSchema(8), "unsupported"),
        (
            SuiteLoadOutcome::Failed(SuiteLoadFailure::Storage),
            "failed",
        ),
        (SuiteLoadOutcome::Available(invalid_suite()), "invalid"),
        (SuiteLoadOutcome::Available(suite()), "available"),
    ];
    for (outcome, expected) in cases {
        let mut workspace = TrafficTestWorkspace::new(false);
        let token = workspace.begin_load().unwrap();
        assert!(workspace.finish_load(token, outcome));
        assert!(match (workspace.suite_state(), expected) {
            (SuiteState::UnsupportedSchema(8), "unsupported")
            | (SuiteState::Failed(SuiteLoadFailure::Storage), "failed")
            | (SuiteState::Failed(SuiteLoadFailure::InvalidSuite), "invalid")
            | (SuiteState::Available(_), "available") => true,
            _ => false,
        });
    }
}

#[test]
fn replacement_validates_before_change_and_content_change_invalidates() {
    let (mut workspace, _) = ready_workspace();
    let prior = workspace.suite_state().clone();
    assert_eq!(
        workspace.replace_suite(invalid_suite()),
        Err(WorkspaceError::InvalidSuite)
    );
    assert!(
        matches!((&prior, workspace.suite_state()), (SuiteState::Available(a), SuiteState::Available(b)) if a == b)
    );
    assert!(!workspace.replace_suite(suite()).unwrap());
    assert!(matches!(
        workspace.evaluation_state(),
        EvaluationState::Queued(_)
    ));
    let mut changed = suite().as_ref().clone();
    changed.name = "Changed content".to_owned();
    assert!(workspace.replace_suite(Arc::new(changed)).unwrap());
    assert!(matches!(
        workspace.evaluation_state(),
        EvaluationState::NotRun
    ));
}

#[test]
fn read_only_configuration_does_not_gate_local_replacement() {
    for read_only in [false, true] {
        let mut config = Config::default();
        config.read_only = read_only;
        let mut workspace = TrafficTestWorkspace::new(config.offline);
        assert_eq!(workspace.replace_suite(suite()), Ok(true));
    }
}

#[test]
fn observation_uses_generation_high_water_across_clear_and_invalidates() {
    let (mut workspace, _) = ready_workspace();
    assert!(!workspace.observe(observation(1)));
    assert!(matches!(
        workspace.evaluation_state(),
        EvaluationState::Queued(_)
    ));
    assert!(workspace.observe(observation(2)));
    assert!(matches!(
        workspace.evaluation_state(),
        EvaluationState::NotRun
    ));
    workspace.clear_observation();
    assert!(workspace.observation().is_none());
    assert!(!workspace.observe(observation(2)));
    assert!(workspace.observe(observation(3)));
}

#[test]
fn target_rejects_runtime_offline_without_state_change_and_invalidates_changes() {
    let mut offline = TrafficTestWorkspace::new(true);
    assert_eq!(
        offline.set_target(EvaluationTarget::Runtime),
        Err(WorkspaceError::RuntimeUnavailableOffline)
    );
    assert_eq!(offline.target(), EvaluationTarget::Permanent);
    let (mut online, _) = ready_workspace();
    assert_eq!(online.set_target(EvaluationTarget::Permanent), Ok(true));
    assert!(matches!(online.evaluation_state(), EvaluationState::NotRun));
    assert_eq!(online.set_target(EvaluationTarget::Permanent), Ok(false));
}

#[test]
fn preparation_requires_inputs_and_binds_immutable_identity() {
    let mut workspace = TrafficTestWorkspace::new(false);
    assert_eq!(
        workspace.prepare_evaluation().unwrap_err(),
        WorkspaceError::SuiteUnavailable
    );
    workspace.replace_suite(suite()).unwrap();
    assert_eq!(
        workspace.prepare_evaluation().unwrap_err(),
        WorkspaceError::ObservationUnavailable
    );
    let observed = observation(7);
    let identity = observed.identity();
    workspace.observe(observed);
    let prepared = workspace.prepare_evaluation().unwrap();
    assert_eq!(prepared.context().suite_id, suite().id);
    assert_eq!(prepared.context().suite_revision, suite().revision);
    assert_eq!(prepared.context().phase, EvaluationPhase::Current);
    assert_eq!(prepared.context().target, EvaluationTarget::Runtime);
    assert_eq!(
        prepared.context().authoritative_snapshot.refresh_id(),
        identity.refresh_id().get()
    );
    assert_eq!(prepared.context().authoritative_snapshot.generation(), 7);
    assert!(prepared.context().base_snapshot.is_none());
    assert_eq!(prepared.observation().identity(), identity);
}

#[test]
fn prepared_work_keeps_original_suite_and_observation_allocations() {
    let mut workspace = TrafficTestWorkspace::new(false);
    let original_suite = suite();
    let original_observation = observation(1);
    let original_snapshot = Arc::clone(original_observation.snapshot_arc());
    workspace
        .replace_suite(Arc::clone(&original_suite))
        .unwrap();
    workspace.observe(original_observation);
    let prepared = workspace.prepare_evaluation().unwrap();

    let mut replacement = original_suite.as_ref().clone();
    replacement.name = "Replacement".to_owned();
    workspace.replace_suite(Arc::new(replacement)).unwrap();
    workspace.observe(observation(2));

    assert!(Arc::ptr_eq(prepared.suite(), &original_suite));
    assert!(Arc::ptr_eq(
        prepared.observation().snapshot_arc(),
        &original_snapshot
    ));
    assert_eq!(prepared.observation().identity().generation().get(), 1);
}

#[test]
fn process_wide_ids_do_not_repeat_across_workspaces_and_overflow_fails_closed() {
    let (_, first) = ready_workspace();
    let (_, second) = ready_workspace();
    assert_ne!(first.context().run_id, second.context().run_id);
    let local = AtomicU64::new(u64::MAX - 1);
    assert_eq!(allocate(&local), Ok(u64::MAX));
    assert_eq!(allocate(&local), Err(WorkspaceError::IdentityExhausted));
}

#[test]
fn lifecycle_accepts_only_ordered_matching_events_and_unknown_is_completed() {
    let (mut workspace, prepared) = ready_workspace();
    let context = prepared.context().clone();
    let finished = TrafficTestEvent::EvaluationFinished {
        report: report(
            context.clone(),
            vec![result(
                "enabled",
                TrafficExpectation::Allow,
                FirewallDecision::Unknown,
            )],
        ),
    };
    assert_eq!(
        workspace.ingest_event(finished),
        Err(WorkspaceEventError::InvalidTransition)
    );
    workspace
        .ingest_event(TrafficTestEvent::EvaluationStarted {
            context: context.clone(),
        })
        .unwrap();
    workspace
        .ingest_event(TrafficTestEvent::EvaluationFinished {
            report: report(
                context.clone(),
                vec![result(
                    "enabled",
                    TrafficExpectation::Allow,
                    FirewallDecision::Unknown,
                )],
            ),
        })
        .unwrap();
    assert!(
        matches!(workspace.evaluation_state(), EvaluationState::Completed(done) if done.summary().indeterminate == 1)
    );
    assert_eq!(
        workspace.ingest_event(TrafficTestEvent::EvaluationFailed {
            context,
            reason: TrafficTestFailureReason::WorkerFailed
        }),
        Err(WorkspaceEventError::InvalidTransition)
    );
}

#[test]
fn context_mismatch_and_terminal_duplicates_never_change_state() {
    let (mut workspace, prepared) = ready_workspace();
    let mut mismatch = prepared.context().clone();
    mismatch.target = EvaluationTarget::Permanent;
    assert_eq!(
        workspace.ingest_event(TrafficTestEvent::EvaluationStarted { context: mismatch }),
        Err(WorkspaceEventError::ContextMismatch)
    );
    let context = prepared.context().clone();
    workspace
        .ingest_event(TrafficTestEvent::EvaluationCancelled {
            context: context.clone(),
            reason: TrafficTestCancellationReason::StaleContext,
        })
        .unwrap();
    assert_eq!(
        workspace.ingest_event(TrafficTestEvent::EvaluationCancelled {
            context,
            reason: TrafficTestCancellationReason::Shutdown
        }),
        Err(WorkspaceEventError::InvalidTransition)
    );
}

#[test]
fn every_context_identity_field_participates_in_event_matching() {
    let (mut workspace, prepared) = ready_workspace();
    let active = prepared.context().clone();
    let snapshot = EvaluationSnapshotIdentity::new(99, 99).unwrap();
    let mutation = MutationIntentId::new(99).unwrap();
    let plan = EvaluationPlanId::new(99);
    let candidate = CandidateIdentity::new(
        snapshot,
        mutation,
        Some(plan),
        active.target,
        OrderedOperationDigest::from_ordered_bytes([b"different".as_slice()]),
    );
    let mut mismatches = Vec::new();
    macro_rules! mismatch {
        ($field:ident, $value:expr) => {{
            let mut context = active.clone();
            context.$field = $value;
            mismatches.push(context);
        }};
    }
    mismatch!(
        run_id,
        TrafficTestRunId::new(active.run_id.get() + 10_000).unwrap()
    );
    mismatch!(suite_id, TrafficSuiteId::parse("other").unwrap());
    mismatch!(suite_revision, TrafficSuiteRevision::new(2).unwrap());
    mismatch!(phase, EvaluationPhase::PostApply);
    mismatch!(target, EvaluationTarget::Permanent);
    mismatch!(authoritative_snapshot, snapshot);
    mismatch!(base_snapshot, Some(snapshot));
    mismatch!(mutation_intent_id, Some(mutation));
    mismatch!(plan_id, Some(plan));
    mismatch!(candidate_identity, Some(candidate));

    for mismatch in mismatches {
        assert_eq!(
            workspace.ingest_event(TrafficTestEvent::EvaluationStarted { context: mismatch }),
            Err(WorkspaceEventError::ContextMismatch)
        );
        assert!(matches!(
            workspace.evaluation_state(),
            EvaluationState::Queued(_)
        ));
    }
}

#[test]
fn report_must_match_enabled_scenarios_in_order_id_and_expectation() {
    let malformed = [
        Vec::new(),
        vec![result(
            "disabled",
            TrafficExpectation::Block,
            FirewallDecision::Block,
        )],
        vec![result(
            "enabled",
            TrafficExpectation::Block,
            FirewallDecision::Block,
        )],
        vec![
            result(
                "enabled",
                TrafficExpectation::Allow,
                FirewallDecision::Allow,
            ),
            result(
                "disabled",
                TrafficExpectation::Block,
                FirewallDecision::Block,
            ),
        ],
    ];
    for results in malformed {
        let (mut workspace, prepared) = ready_workspace();
        let context = prepared.context().clone();
        workspace
            .ingest_event(TrafficTestEvent::EvaluationStarted {
                context: context.clone(),
            })
            .unwrap();
        assert_eq!(
            workspace.ingest_event(TrafficTestEvent::EvaluationFinished {
                report: report(context, results)
            }),
            Err(WorkspaceEventError::MalformedReport)
        );
    }
}

#[test]
fn submission_failure_only_resolves_matching_queued_run() {
    let (mut workspace, first) = ready_workspace();
    let first_context = first.context().clone();
    workspace
        .ingest_event(TrafficTestEvent::EvaluationStarted {
            context: first_context.clone(),
        })
        .unwrap();
    assert_eq!(
        workspace.resolve_submission_failure(first_context, &TrafficTestSubmissionError::Busy),
        Err(WorkspaceEventError::InvalidTransition)
    );
    workspace.observe(observation(2));
    let newer = workspace.prepare_evaluation().unwrap().context().clone();
    let mut old = newer.clone();
    old.run_id = first.context().run_id;
    assert_eq!(
        workspace.resolve_submission_failure(old, &TrafficTestSubmissionError::Closed),
        Err(WorkspaceEventError::ContextMismatch)
    );
    workspace
        .resolve_submission_failure(newer, &TrafficTestSubmissionError::Closed)
        .unwrap();
    assert!(matches!(
        workspace.evaluation_state(),
        EvaluationState::Failed {
            reason: WorkspaceFailure::Closed,
            ..
        }
    ));
}

#[test]
fn completed_report_becomes_single_stale_report_after_invalidation_and_fresh_run() {
    let (mut workspace, prepared) = ready_workspace();
    let context = prepared.context().clone();
    workspace
        .ingest_event(TrafficTestEvent::EvaluationStarted {
            context: context.clone(),
        })
        .unwrap();
    workspace
        .ingest_event(TrafficTestEvent::EvaluationFinished {
            report: report(
                context,
                vec![result(
                    "enabled",
                    TrafficExpectation::Allow,
                    FirewallDecision::Allow,
                )],
            ),
        })
        .unwrap();
    workspace.observe(observation(2));
    assert!(matches!(
        workspace.evaluation_state(),
        EvaluationState::Stale(_)
    ));
    assert!(workspace.stale_report().is_some());
    let fresh = workspace.prepare_evaluation().unwrap();
    assert!(workspace.stale_report().is_some());
    assert_eq!(workspace.active_context(), Some(fresh.context()));
}

#[test]
fn worker_error_is_bounded_and_cancellation_resolves_running() {
    let (mut workspace, prepared) = ready_workspace();
    workspace
        .ingest_event(TrafficTestEvent::EvaluationFailed {
            context: prepared.context().clone(),
            reason: TrafficTestFailureReason::EvaluationFailed("sensitive".repeat(100)),
        })
        .unwrap();
    assert!(matches!(
        workspace.evaluation_state(),
        EvaluationState::Failed {
            reason: WorkspaceFailure::EvaluationFailed,
            ..
        }
    ));
    workspace.observe(observation(2));
    let context = workspace.prepare_evaluation().unwrap().context().clone();
    workspace
        .ingest_event(TrafficTestEvent::EvaluationStarted {
            context: context.clone(),
        })
        .unwrap();
    workspace
        .ingest_event(TrafficTestEvent::EvaluationCancelled {
            context,
            reason: TrafficTestCancellationReason::Shutdown,
        })
        .unwrap();
    assert!(matches!(
        workspace.evaluation_state(),
        EvaluationState::Cancelled { .. }
    ));
}
