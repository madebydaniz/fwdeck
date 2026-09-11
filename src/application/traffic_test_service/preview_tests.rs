use super::*;
use crate::application::{TrafficPreviewFailure, TrafficPreviewRequest, TrafficPreviewState};
use crate::config::AuditRetentionConfig;
use crate::domain::*;
use crate::infrastructure::audit::traffic::FileTrafficAuditSink;

#[path = "preview_tests/refresh_tests.rs"]
mod refresh_tests;

fn changed_observation(generation: u64) -> ObservedSnapshot {
    let observed = observation(generation);
    let mut snapshot = observed.snapshot().clone();
    snapshot.default_zone = ZoneName::parse("drop").unwrap();
    ObservedSnapshot::new(observed.identity(), Arc::new(snapshot))
}

fn request(
    service: &TrafficTestService<MemoryStorage>,
    target: ConfigurationTarget,
) -> TrafficPreviewRequest {
    TrafficPreviewRequest {
        operations: vec![FirewallOperation::RemoveService {
            zone: ZoneName::parse("public").unwrap(),
            service: ServiceName::parse("ssh").unwrap(),
            target,
        }],
        observation: service.workspace().observation().unwrap().clone(),
        plan_id: None,
    }
}
async fn ready() -> TrafficTestService<MemoryStorage> {
    let mut service =
        TrafficTestService::new(false, Arc::new(MemoryStorage::available(scenario_suite())));
    load(&mut service).await;
    service.observe(observation(1)).unwrap();
    service
}
async fn complete(service: &mut TrafficTestService<MemoryStorage>) {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while matches!(
            service.preview_state(),
            TrafficPreviewState::Preparing(_) | TrafficPreviewState::Running(_)
        ) {
            service.next_event().await.unwrap();
        }
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn traffic_preview_both_targets_complete_and_base_unchanged() {
    let mut service = ready().await;
    let input = request(&service, ConfigurationTarget::RuntimeAndPermanent);
    let base = input.observation.clone();
    service.try_preview(input).unwrap();
    complete(&mut service).await;
    let TrafficPreviewState::Completed(e) = service.preview_state() else {
        panic!("{:?}", service.preview_state());
    };
    assert_eq!(e.pairs.len(), 2);
    let ids: std::collections::BTreeSet<_> = e
        .pairs
        .iter()
        .flat_map(|p| [p.before_context.run_id, p.after_context.run_id])
        .collect();
    assert_eq!(ids.len(), 4);
    assert!(
        e.pairs
            .iter()
            .all(|p| p.counts.is_some() && p.before_context.mutation_intent_id.is_none())
    );
    assert_eq!(service.workspace().observation(), Some(&base));
    assert!(matches!(
        service.workspace().evaluation_state(),
        EvaluationState::NotRun
    ));
    service.shutdown().await.unwrap();
}
#[tokio::test]
async fn traffic_preview_rejection_retains_completed_and_new_intent_replaces_it() {
    let mut service = ready().await;
    service
        .try_preview(request(&service, ConfigurationTarget::Runtime))
        .unwrap();
    complete(&mut service).await;
    let old = service.preview_state().evidence().unwrap().intent_id;
    let mut invalid = request(&service, ConfigurationTarget::Runtime);
    invalid.operations.clear();
    assert_eq!(
        service.try_preview(invalid),
        Err(TrafficServiceError::Preview(
            TrafficPreviewFailure::EmptyOperations
        ))
    );
    assert!(matches!(
        service.preview_state(),
        TrafficPreviewState::Completed(_)
    ));
    service
        .try_preview(request(&service, ConfigurationTarget::Runtime))
        .unwrap();
    assert_ne!(service.preview_state().evidence().unwrap().intent_id, old);
    service.cancel_preview().unwrap();
    assert!(matches!(
        service.preview_state(),
        TrafficPreviewState::Stale(_)
    ));
    service.next_event().await.unwrap();
    assert!(matches!(
        service.preview_state(),
        TrafficPreviewState::Stale(_)
    ));
    service.shutdown().await.unwrap();
}
#[tokio::test]
async fn traffic_preview_observe_clear_save_load_and_normal_evaluation_invalidate() {
    for action in 0..5 {
        let mut service = ready().await;
        service
            .try_preview(request(&service, ConfigurationTarget::Runtime))
            .unwrap();
        complete(&mut service).await;
        match action {
            0 => {
                service.observe(changed_observation(2)).unwrap();
            }
            1 => service.clear_observation().unwrap(),
            2 => service.try_save(scenario_suite()).unwrap(),
            3 => {
                service.try_load().unwrap();
            }
            _ => service.try_evaluate().unwrap(),
        }
        assert!(matches!(
            service.preview_state(),
            TrafficPreviewState::Stale(_)
        ));
        service.shutdown().await.unwrap();
    }
}
#[tokio::test]
async fn traffic_preview_offline_and_disabled_are_explicit() {
    let mut service =
        TrafficTestService::new(true, Arc::new(MemoryStorage::available(scenario_suite())));
    load(&mut service).await;
    service.observe(observation(1)).unwrap();
    assert_eq!(
        service.try_preview(request(&service, ConfigurationTarget::Runtime)),
        Err(TrafficServiceError::Preview(
            TrafficPreviewFailure::OfflineTarget
        ))
    );
    service
        .try_preview(request(&service, ConfigurationTarget::Permanent))
        .unwrap();
    complete(&mut service).await;
    assert!(matches!(
        service.preview_state(),
        TrafficPreviewState::Completed(_)
    ));
    service.workspace.replace_suite(suite(1)).unwrap();
    assert_eq!(
        service.try_preview(request(&service, ConfigurationTarget::Permanent)),
        Err(TrafficServiceError::Preview(
            TrafficPreviewFailure::NoEnabledScenarios
        ))
    );
    service.shutdown().await.unwrap();
}
#[tokio::test]
async fn traffic_preview_projection_failure_is_partial_unavailable() {
    let mut service = ready().await;
    let mut input = request(&service, ConfigurationTarget::Runtime);
    input.operations = vec![FirewallOperation::RemoveService {
        zone: ZoneName::parse("missing-zone").unwrap(),
        service: ServiceName::parse("ssh").unwrap(),
        target: ConfigurationTarget::Runtime,
    }];
    service.try_preview(input).unwrap();
    complete(&mut service).await;
    let TrafficPreviewState::Failed { evidence, reason } = service.preview_state() else {
        panic!("expected failure");
    };
    assert_eq!(*reason, TrafficPreviewFailure::Projection);
    assert!(evidence.pairs[0].before.is_some());
    assert!(evidence.pairs[0].counts.is_none());
    service.shutdown().await.unwrap();
}
#[test]
fn traffic_preview_comparison_uses_evaluated_projected_evidence() {
    let suite = scenario_suite();
    let mut snapshot = crate::domain::mock::sample().unwrap();
    snapshot.direct_rules.clear();
    snapshot.degraded.clear();
    snapshot.policies.runtime.clear();
    snapshot.policies.permanent.clear();
    snapshot.runtime.retain(|zone, _| zone.as_str() == "public");
    snapshot.permanent = snapshot.runtime.clone();
    for zone in snapshot
        .runtime
        .values_mut()
        .chain(snapshot.permanent.values_mut())
    {
        zone.rich_rules.clear();
        zone.ports.clear();
        zone.services.clear();
        zone.target = ZoneTarget::Drop;
        zone.services.push(ServiceName::parse("ssh").unwrap());
    }
    let base = Arc::new(snapshot);
    let base_id = EvaluationSnapshotIdentity::new(1, 1).unwrap();
    let projection = CandidateProjector::project(
        &base,
        base_id,
        MutationIntentId::new(1).unwrap(),
        None,
        EvaluationTarget::Runtime,
        &[FirewallOperation::RemoveService {
            zone: ZoneName::parse("public").unwrap(),
            service: ServiceName::parse("ssh").unwrap(),
            target: ConfigurationTarget::Runtime,
        }],
    )
    .unwrap();
    let before = EvaluationContext {
        run_id: TrafficTestRunId::new(1).unwrap(),
        suite_id: suite.id.clone(),
        suite_revision: suite.revision,
        phase: EvaluationPhase::Current,
        target: EvaluationTarget::Runtime,
        authoritative_snapshot: base_id,
        base_snapshot: None,
        mutation_intent_id: None,
        plan_id: None,
        candidate_identity: None,
    };
    let after = EvaluationContext {
        run_id: TrafficTestRunId::new(2).unwrap(),
        phase: EvaluationPhase::StagedCandidate,
        base_snapshot: Some(base_id),
        mutation_intent_id: Some(MutationIntentId::new(1).unwrap()),
        candidate_identity: Some(projection.identity()),
        ..before.clone()
    };
    let run = |context: &EvaluationContext, snapshot: Arc<FirewallSnapshot>| {
        TrafficTestReport::new(
            context.clone(),
            suite
                .scenarios
                .iter()
                .map(|s| {
                    evaluate_scenario(
                        &TrafficEvaluationIndex::new(snapshot.clone(), context.target),
                        s,
                        context,
                    )
                    .unwrap()
                })
                .collect(),
        )
        .unwrap()
    };
    let a = run(&before, base);
    let b = run(&after, Arc::clone(projection.snapshot_arc()));
    assert_eq!(a.results()[0].status(), TrafficTestStatus::Pass);
    assert_eq!(b.results()[0].status(), TrafficTestStatus::Fail);
    assert_eq!(
        compare_traffic_reports(&suite, &before, &after, &a, &b)
            .unwrap()
            .regressions,
        1
    );
    assert_eq!(
        traffic_change(b.results()[0].status(), a.results()[0].status()).unwrap(),
        TrafficChange::Improvement
    );
    assert_eq!(
        traffic_change(
            TrafficTestStatus::Indeterminate,
            TrafficTestStatus::Indeterminate
        )
        .unwrap(),
        TrafficChange::Unchanged
    );
    assert!(traffic_change(TrafficTestStatus::Stale, TrafficTestStatus::Pass).is_err());
    let missing = TrafficTestReport::new(after.clone(), vec![]).unwrap();
    assert!(compare_traffic_reports(&suite, &before, &after, &a, &missing).is_err());
    let mut wrong = after.clone();
    wrong.target = EvaluationTarget::Permanent;
    assert!(compare_traffic_reports(&suite, &before, &wrong, &a, &b).is_err());
}

#[tokio::test]
async fn traffic_preview_late_duplicate_reports_cannot_replace_new_intent() {
    let mut service = ready().await;
    service
        .try_preview(request(&service, ConfigurationTarget::Runtime))
        .unwrap();
    complete(&mut service).await;
    let old = Arc::clone(
        service.preview_state().evidence().unwrap().pairs[0]
            .after
            .as_ref()
            .unwrap(),
    );
    service
        .try_preview(request(&service, ConfigurationTarget::Runtime))
        .unwrap();
    let intent = service.preview_state().evidence().unwrap().intent_id;
    assert!(matches!(
        service.ingest(TrafficTestEvent::EvaluationFinished {
            report: Arc::clone(&old)
        }),
        TrafficServiceEvent::Evaluation(Err(_))
    ));
    assert_eq!(
        service.preview_state().evidence().unwrap().intent_id,
        intent
    );
    complete(&mut service).await;
    assert!(matches!(
        service.ingest(TrafficTestEvent::EvaluationFinished { report: old }),
        TrafficServiceEvent::Evaluation(Err(_))
    ));
    assert!(matches!(
        service.preview_state(),
        TrafficPreviewState::Completed(_)
    ));
    service.shutdown().await.unwrap();
}

#[tokio::test]
async fn traffic_preview_matching_malformed_and_duplicate_start_are_rejected() {
    let mut service = ready().await;
    service
        .try_preview(request(&service, ConfigurationTarget::Runtime))
        .unwrap();
    let context = service.preview_batch.as_ref().unwrap().context().clone();
    let started = || TrafficTestEvent::EvaluationStarted {
        context: context.clone(),
    };
    assert!(matches!(
        service.ingest(started()),
        TrafficServiceEvent::Evaluation(Ok(()))
    ));
    assert!(matches!(
        service.ingest(started()),
        TrafficServiceEvent::Evaluation(Err(WorkspaceEventError::InvalidTransition))
    ));
    let report = Arc::new(TrafficTestReport::new(context, vec![]).unwrap());
    assert!(matches!(
        service.ingest(TrafficTestEvent::EvaluationFinished { report }),
        TrafficServiceEvent::Evaluation(Err(WorkspaceEventError::MalformedReport))
    ));
    assert!(matches!(
        service.preview_state(),
        TrafficPreviewState::Failed {
            reason: TrafficPreviewFailure::InvalidEvidence,
            ..
        }
    ));
    service.shutdown().await.unwrap();
}

#[tokio::test]
async fn traffic_preview_active_supersession_rejects_old_terminal_events() {
    for action in 0..6 {
        let mut service = ready().await;
        service
            .try_preview(request(&service, ConfigurationTarget::Runtime))
            .unwrap();
        while !matches!(service.preview_state(), TrafficPreviewState::Running(_)) {
            service.next_event().await.unwrap();
        }
        let old_context = service.preview_batch.as_ref().unwrap().context().clone();
        match action {
            0 => {
                service.observe(changed_observation(2)).unwrap();
            }
            1 => service.clear_observation().unwrap(),
            2 => service.try_save(scenario_suite()).unwrap(),
            3 => {
                service.try_load().unwrap();
            }
            4 => service.try_evaluate().unwrap(),
            _ => service
                .try_preview(request(&service, ConfigurationTarget::Runtime))
                .unwrap(),
        }
        assert!(matches!(
            service.ingest(TrafficTestEvent::EvaluationStarted {
                context: old_context
            }),
            TrafficServiceEvent::Evaluation(Err(_))
        ));
        if action == 5 {
            assert!(matches!(
                service.preview_state(),
                TrafficPreviewState::Preparing(_)
            ));
        } else {
            assert!(matches!(
                service.preview_state(),
                TrafficPreviewState::Stale(_)
            ));
        }
        service.shutdown().await.unwrap();
    }
}

#[tokio::test]
async fn traffic_preview_lifecycle_effect_targets_and_order_are_bound() {
    for (operation, target) in [
        (FirewallOperation::Reload, EvaluationTarget::Runtime),
        (
            FirewallOperation::RuntimeToPermanent,
            EvaluationTarget::Permanent,
        ),
        (
            FirewallOperation::SetLogDenied {
                value: LogDenied::All,
            },
            EvaluationTarget::Runtime,
        ),
    ] {
        let mut service = ready().await;
        let mut input = request(&service, ConfigurationTarget::Runtime);
        input.operations = vec![operation];
        service.try_preview(input).unwrap();
        complete(&mut service).await;
        let evidence = service.preview_state().evidence().unwrap();
        assert_eq!(evidence.pairs.len(), 1);
        assert_eq!(evidence.pairs[0].target, target);
        service.shutdown().await.unwrap();
    }
    let mut service = ready().await;
    let mut input = request(&service, ConfigurationTarget::Runtime);
    input.operations.push(FirewallOperation::RuntimeToPermanent);
    input.plan_id = Some(crate::application::PlanId::new(42));
    service.try_preview(input.clone()).unwrap();
    let first = service.preview_state().evidence().unwrap().pairs[0]
        .after_context
        .candidate_identity
        .unwrap();
    complete(&mut service).await;
    input.operations.reverse();
    service.try_preview(input).unwrap();
    let second = service.preview_state().evidence().unwrap().pairs[0]
        .after_context
        .candidate_identity
        .unwrap();
    assert_ne!(
        first.ordered_operation_digest(),
        second.ordered_operation_digest()
    );
    assert_eq!(second.plan_id(), Some(EvaluationPlanId::new(42)));
    service.shutdown().await.unwrap();
}

#[tokio::test]
async fn traffic_preview_stale_review_is_distinct_from_missing_suite() {
    let mut service = ready().await;
    let input = request(&service, ConfigurationTarget::Runtime);
    service.observe(observation(2)).unwrap();
    assert_eq!(
        service.try_preview(input),
        Err(TrafficServiceError::Preview(
            TrafficPreviewFailure::StaleObservation
        ))
    );
    service.shutdown().await.unwrap();
}

#[tokio::test]
async fn traffic_preview_file_audit_batch_cancel_and_duplicates_are_private() {
    let mut suite = (*scenario_suite()).clone();
    suite.name = "PRIVATE_SUITE_NAME".into();
    suite.scenarios[0].name = "PRIVATE_SCENARIO_NAME".into();
    suite.scenarios[0].note = Some("PRIVATE_NOTE".into());
    let source = suite.scenarios[0].source.to_string();
    let root = std::env::temp_dir().join(format!(
        "fwdeck-preview-audit-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let sink = Arc::new(FileTrafficAuditSink::new(
        Some(root.clone()),
        AuditRetentionConfig {
            max_files: 2,
            max_file_size: 1024 * 1024,
        },
    ));
    let mut service = TrafficTestService::with_audit_sink(
        false,
        Arc::new(MemoryStorage::available(Arc::new(suite))),
        sink,
    );
    load(&mut service).await;
    service.observe(observation(1)).unwrap();
    service
        .try_preview(request(&service, ConfigurationTarget::RuntimeAndPermanent))
        .unwrap();
    service.observe(observation(2)).unwrap();
    complete(&mut service).await;
    service.observe(observation(3)).unwrap();
    let TrafficPreviewState::Completed(evidence) = service.preview_state().clone() else {
        panic!("preview did not complete");
    };
    let expected = evidence
        .pairs
        .iter()
        .flat_map(|p| [&p.before_context, &p.after_context])
        .map(|c| serde_json::to_value(c).unwrap())
        .collect::<Vec<_>>();
    for pair in &evidence.pairs {
        for report in [&pair.before, &pair.after] {
            assert!(matches!(
                service.ingest(TrafficTestEvent::EvaluationFinished {
                    report: report.as_ref().unwrap().clone(),
                }),
                TrafficServiceEvent::Evaluation(Err(_))
            ));
        }
    }
    service
        .try_preview(request(&service, ConfigurationTarget::RuntimeAndPermanent))
        .unwrap();
    let cancelled = service.preview_batch.as_ref().unwrap().context().clone();
    service.cancel_preview().unwrap();
    service.cancel_preview().unwrap();
    assert!(matches!(
        service.ingest(TrafficTestEvent::EvaluationCancelled {
            context: cancelled.clone(),
            reason: crate::application::TrafficTestCancellationReason::StaleContext,
        }),
        TrafficServiceEvent::Evaluation(Err(_))
    ));
    service.shutdown().await.unwrap();
    let raw = std::fs::read_to_string(root.join("traffic-audit/audit.jsonl")).unwrap();
    let records = raw
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        records.len(),
        5,
        "four completed runs and only the admitted cancelled run"
    );
    for (record, context) in records.iter().zip(expected) {
        assert_eq!(record["context"], context);
        assert_eq!(record["outcome"], "completed");
        assert_eq!(record["configuration_only"], true);
        assert_eq!(record["live_connectivity_verified"], false);
    }
    assert_eq!(
        records[4]["context"],
        serde_json::to_value(cancelled).unwrap()
    );
    assert_eq!(records[4]["outcome"], "cancelled");
    assert_eq!(records[4]["reason"], "stale_context");
    for secret in [
        "PRIVATE_SUITE_NAME",
        "PRIVATE_SCENARIO_NAME",
        "PRIVATE_NOTE",
        &source,
        "RemoveService",
        "remove_service",
        "\"trace\"",
    ] {
        assert!(!raw.contains(secret), "private input leaked into audit");
    }
    std::fs::remove_dir_all(root).unwrap();
}
