#![allow(clippy::panic, clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fwdeck::application::{
    TRAFFIC_TEST_CANCELLATION_INTERVAL, TRAFFIC_TEST_EVENT_CAPACITY,
    TRAFFIC_TEST_PENDING_CONTEXT_CAPACITY, TRAFFIC_TEST_REQUEST_CAPACITY, TrafficScenarioEvaluator,
    TrafficTestCancellationReason, TrafficTestCoordinator, TrafficTestEvaluationRequest,
    TrafficTestEvent, TrafficTestFailureReason, TrafficTestShutdownError,
    TrafficTestSubmissionError,
};
use fwdeck::domain::{
    CandidateIdentity, EvaluationContext, EvaluationPhase, EvaluationPlanId,
    EvaluationSnapshotIdentity, EvaluationTarget, FirewallSnapshot, FirewallStatus, LogDenied,
    MutationIntentId, NetfilterBackend, OrderedOperationDigest, Scoped, SourceAddress,
    TrafficConnectionState, TrafficDestination, TrafficDirection, TrafficEvaluationError,
    TrafficEvaluationIndex, TrafficExpectation, TrafficScenario, TrafficScenarioId,
    TrafficSeverity, TrafficSuite, TrafficSuiteId, TrafficSuiteRevision, TrafficTestResult,
    TrafficTestRunId, TrafficTransport, ZoneDetails, ZoneName, ZoneTarget, evaluate_scenario,
};

struct ControlledEvaluator {
    block_call: AtomicUsize,
    release_first: AtomicBool,
    calls: AtomicUsize,
    active: AtomicUsize,
    max_active: AtomicUsize,
    calls_by_run: Mutex<BTreeMap<u64, usize>>,
}

impl Default for ControlledEvaluator {
    fn default() -> Self {
        Self {
            block_call: AtomicUsize::new(usize::MAX),
            release_first: AtomicBool::new(false),
            calls: AtomicUsize::new(0),
            active: AtomicUsize::new(0),
            max_active: AtomicUsize::new(0),
            calls_by_run: Mutex::new(BTreeMap::new()),
        }
    }
}

impl ControlledEvaluator {
    fn blocking_first() -> Arc<Self> {
        Self::blocking_call(0)
    }

    fn blocking_call(call: usize) -> Arc<Self> {
        Arc::new(Self {
            block_call: AtomicUsize::new(call),
            ..Self::default()
        })
    }

    fn release(&self) {
        self.release_first.store(true, Ordering::Release);
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::Acquire)
    }

    fn calls_for(&self, run_id: u64) -> usize {
        *self.calls_by_run.lock().unwrap().get(&run_id).unwrap_or(&0)
    }

    fn max_active(&self) -> usize {
        self.max_active.load(Ordering::Acquire)
    }
}

impl TrafficScenarioEvaluator for ControlledEvaluator {
    fn evaluate(
        &self,
        index: &TrafficEvaluationIndex,
        scenario: &TrafficScenario,
        context: &EvaluationContext,
    ) -> Result<TrafficTestResult, TrafficEvaluationError> {
        let call = self.calls.fetch_add(1, Ordering::AcqRel);
        *self
            .calls_by_run
            .lock()
            .unwrap()
            .entry(context.run_id.get())
            .or_default() += 1;

        let active = self.active.fetch_add(1, Ordering::AcqRel) + 1;
        self.max_active.fetch_max(active, Ordering::AcqRel);
        if call == self.block_call.load(Ordering::Acquire) {
            while !self.release_first.load(Ordering::Acquire) {
                std::thread::yield_now();
            }
        }
        let result = evaluate_scenario(index, scenario, context);
        self.active.fetch_sub(1, Ordering::AcqRel);
        result
    }
}

fn public() -> ZoneName {
    ZoneName::parse("public").unwrap()
}

fn snapshot() -> Arc<FirewallSnapshot> {
    let mut zone = ZoneDetails::empty(public());
    zone.target = ZoneTarget::Accept;
    Arc::new(FirewallSnapshot {
        status: FirewallStatus {
            daemon_running: true,
            version: Some("2.4.0".to_owned()),
            backend: NetfilterBackend::Nftables,
            log_denied: LogDenied::Off,
            panic_mode: false,
        },
        default_zone: public(),
        active: BTreeMap::new(),
        runtime: BTreeMap::from([(public(), zone.clone())]),
        permanent: BTreeMap::from([(public(), zone)]),
        ipsets: Scoped::default(),
        service_definitions: BTreeMap::new(),
        available_services: Vec::new(),
        policies: Scoped::default(),
        direct_rules: Vec::new(),
        degraded: Vec::new(),
    })
}

fn scenario(index: usize) -> TrafficScenario {
    TrafficScenario {
        id: TrafficScenarioId::parse(&format!("scenario-{index}")).unwrap(),
        name: format!("Scenario {index}"),
        enabled: true,
        direction: TrafficDirection::ToHost,
        source: SourceAddress::parse("192.0.2.10").unwrap(),
        ingress_interface: None,
        ingress_zone: Some(public()),
        destination: TrafficDestination::LocalHost,
        egress_interface: None,
        egress_zone: None,
        transport: TrafficTransport::Tcp,
        destination_port: Some("22".parse().unwrap()),
        source_port: None,
        connection_state: TrafficConnectionState::default(),
        expectation: TrafficExpectation::Allow,
        severity: TrafficSeverity::Critical,
        required_safety_gate: true,
        note: None,
    }
}

fn suite(id: &str, revision: u64, scenario_count: usize) -> Arc<TrafficSuite> {
    Arc::new(TrafficSuite {
        id: TrafficSuiteId::parse(id).unwrap(),
        name: format!("Suite {id}"),
        revision: TrafficSuiteRevision::new(revision).unwrap(),
        scenarios: (0..scenario_count).map(scenario).collect(),
    })
}

fn current_context(
    run_id: u64,
    suite_id: &str,
    revision: u64,
    snapshot_refresh: u64,
    target: EvaluationTarget,
) -> EvaluationContext {
    EvaluationContext {
        run_id: TrafficTestRunId::new(run_id).unwrap(),
        suite_id: TrafficSuiteId::parse(suite_id).unwrap(),
        suite_revision: TrafficSuiteRevision::new(revision).unwrap(),
        phase: EvaluationPhase::Current,
        target,
        authoritative_snapshot: EvaluationSnapshotIdentity::new(snapshot_refresh, 1).unwrap(),
        base_snapshot: None,
        mutation_intent_id: None,
        plan_id: None,
        candidate_identity: None,
    }
}

fn staged_context(
    run_id: u64,
    mutation_id: u64,
    plan_id: Option<u64>,
    digest: &[u8],
) -> EvaluationContext {
    let authoritative_snapshot = EvaluationSnapshotIdentity::new(10, 1).unwrap();
    let mutation_intent_id = MutationIntentId::new(mutation_id).unwrap();
    let plan_id = plan_id.map(EvaluationPlanId::new);
    let target = EvaluationTarget::Runtime;
    EvaluationContext {
        run_id: TrafficTestRunId::new(run_id).unwrap(),
        suite_id: TrafficSuiteId::parse("candidate").unwrap(),
        suite_revision: TrafficSuiteRevision::new(1).unwrap(),
        phase: EvaluationPhase::StagedCandidate,
        target,
        authoritative_snapshot,
        base_snapshot: Some(authoritative_snapshot),
        mutation_intent_id: Some(mutation_intent_id),
        plan_id,
        candidate_identity: Some(CandidateIdentity::new(
            authoritative_snapshot,
            mutation_intent_id,
            plan_id,
            target,
            OrderedOperationDigest::from_ordered_bytes([digest]),
        )),
    }
}

fn request(context: EvaluationContext, scenario_count: usize) -> TrafficTestEvaluationRequest {
    let suite = suite(
        context.suite_id.as_str(),
        context.suite_revision.get(),
        scenario_count,
    );
    let index = TrafficEvaluationIndex::new(snapshot(), context.target);
    TrafficTestEvaluationRequest::new(context, suite, index).unwrap()
}

async fn next_event(coordinator: &mut TrafficTestCoordinator) -> TrafficTestEvent {
    tokio::time::timeout(Duration::from_secs(1), coordinator.next_event())
        .await
        .unwrap()
        .unwrap()
}

async fn wait_for_calls(evaluator: &ControlledEvaluator, expected: usize) {
    for _ in 0..10_000 {
        if evaluator.calls() >= expected {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("evaluator did not reach {expected} calls");
}

#[tokio::test(start_paused = true)]
async fn channels_are_bounded_at_eight_and_saturate() {
    let evaluator = Arc::new(ControlledEvaluator::default());
    let mut coordinator = TrafficTestCoordinator::spawn_with_evaluator(evaluator);

    assert_eq!(
        coordinator.request_capacity_limit(),
        TRAFFIC_TEST_REQUEST_CAPACITY
    );
    assert_eq!(
        coordinator.result_capacity_limit(),
        TRAFFIC_TEST_EVENT_CAPACITY
    );

    for run_id in 1..=TRAFFIC_TEST_REQUEST_CAPACITY {
        let id = format!("queued-{run_id}");
        coordinator
            .try_evaluate(request(
                current_context(
                    u64::try_from(run_id).unwrap(),
                    &id,
                    1,
                    1,
                    EvaluationTarget::Runtime,
                ),
                1,
            ))
            .unwrap();
    }
    assert_eq!(coordinator.remaining_request_capacity(), 0);
    assert_eq!(
        coordinator.try_evaluate(request(
            current_context(20, "overflow", 1, 1, EvaluationTarget::Runtime),
            1,
        )),
        Err(TrafficTestSubmissionError::Busy)
    );

    while coordinator.remaining_result_capacity() > 0 {
        tokio::task::yield_now().await;
    }
    assert_eq!(coordinator.remaining_result_capacity(), 0);

    coordinator.shutdown().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn only_one_run_is_active_globally() {
    let evaluator = ControlledEvaluator::blocking_first();
    let mut coordinator = TrafficTestCoordinator::spawn_with_evaluator(evaluator.clone());
    coordinator
        .try_evaluate(request(
            current_context(1, "first", 1, 1, EvaluationTarget::Runtime),
            1,
        ))
        .unwrap();
    assert!(matches!(
        next_event(&mut coordinator).await,
        TrafficTestEvent::EvaluationStarted { .. }
    ));
    wait_for_calls(&evaluator, 1).await;

    coordinator
        .try_evaluate(request(
            current_context(2, "second", 1, 1, EvaluationTarget::Runtime),
            1,
        ))
        .unwrap();
    for _ in 0..32 {
        tokio::task::yield_now().await;
    }
    assert_eq!(evaluator.calls(), 1);
    assert_eq!(evaluator.max_active(), 1);

    evaluator.release();
    assert!(matches!(
        next_event(&mut coordinator).await,
        TrafficTestEvent::EvaluationFinished { .. }
    ));
    assert!(matches!(
        next_event(&mut coordinator).await,
        TrafficTestEvent::EvaluationStarted { context }
            if context.suite_id.as_str() == "second"
    ));
    assert!(matches!(
        next_event(&mut coordinator).await,
        TrafficTestEvent::EvaluationFinished { .. }
    ));
    assert_eq!(evaluator.max_active(), 1);
    coordinator.shutdown().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn pending_requests_coalesce_to_the_latest_context() {
    let evaluator = ControlledEvaluator::blocking_first();
    let mut coordinator = TrafficTestCoordinator::spawn_with_evaluator(evaluator.clone());
    coordinator
        .try_evaluate(request(
            current_context(1, "active", 1, 1, EvaluationTarget::Runtime),
            1,
        ))
        .unwrap();
    let _ = next_event(&mut coordinator).await;
    wait_for_calls(&evaluator, 1).await;

    coordinator
        .try_evaluate(request(
            current_context(2, "pending", 1, 1, EvaluationTarget::Runtime),
            1,
        ))
        .unwrap();
    coordinator
        .try_evaluate(request(
            current_context(3, "pending", 2, 1, EvaluationTarget::Runtime),
            1,
        ))
        .unwrap();
    for _ in 0..32 {
        tokio::task::yield_now().await;
    }

    evaluator.release();
    let _ = next_event(&mut coordinator).await;
    let started = next_event(&mut coordinator).await;
    assert!(matches!(
        started,
        TrafficTestEvent::EvaluationStarted { context }
            if context.run_id.get() == 3 && context.suite_revision.get() == 2
    ));
    let _ = next_event(&mut coordinator).await;
    assert_eq!(evaluator.calls_for(2), 0);
    assert_eq!(evaluator.calls_for(3), 1);
    coordinator.shutdown().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn ninth_pending_context_is_rejected_without_evicting_existing_work() {
    let evaluator = ControlledEvaluator::blocking_first();
    let mut coordinator = TrafficTestCoordinator::spawn_with_evaluator(evaluator.clone());
    coordinator
        .try_evaluate(request(
            current_context(1, "active", 1, 1, EvaluationTarget::Runtime),
            1,
        ))
        .unwrap();
    let _ = next_event(&mut coordinator).await;
    wait_for_calls(&evaluator, 1).await;

    for index in 0..TRAFFIC_TEST_PENDING_CONTEXT_CAPACITY {
        let id = format!("pending-{index}");
        coordinator
            .try_evaluate(request(
                current_context(
                    u64::try_from(index + 2).unwrap(),
                    &id,
                    1,
                    1,
                    EvaluationTarget::Runtime,
                ),
                1,
            ))
            .unwrap();
    }
    while coordinator.remaining_request_capacity() != TRAFFIC_TEST_REQUEST_CAPACITY {
        tokio::task::yield_now().await;
    }
    coordinator
        .try_evaluate(request(
            current_context(50, "pending-overflow", 1, 1, EvaluationTarget::Runtime),
            1,
        ))
        .unwrap();

    let event = next_event(&mut coordinator).await;
    assert!(matches!(
        event,
        TrafficTestEvent::EvaluationFailed {
            context,
            reason: TrafficTestFailureReason::Busy,
        } if context.run_id.get() == 50
    ));

    evaluator.release();
    coordinator.shutdown().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn rejected_active_replacement_does_not_stale_the_accepted_active_run() {
    let evaluator = ControlledEvaluator::blocking_first();
    let mut coordinator = TrafficTestCoordinator::spawn_with_evaluator(evaluator.clone());
    coordinator
        .try_evaluate(request(
            current_context(1, "active", 1, 1, EvaluationTarget::Runtime),
            1,
        ))
        .unwrap();
    let _ = next_event(&mut coordinator).await;
    wait_for_calls(&evaluator, 1).await;

    for index in 0..TRAFFIC_TEST_PENDING_CONTEXT_CAPACITY {
        let id = format!("replacement-pending-{index}");
        coordinator
            .try_evaluate(request(
                current_context(
                    u64::try_from(index + 2).unwrap(),
                    &id,
                    1,
                    1,
                    EvaluationTarget::Runtime,
                ),
                1,
            ))
            .unwrap();
    }
    while coordinator.remaining_request_capacity() != TRAFFIC_TEST_REQUEST_CAPACITY {
        tokio::task::yield_now().await;
    }
    coordinator
        .try_evaluate(request(
            current_context(50, "active", 1, 2, EvaluationTarget::Runtime),
            1,
        ))
        .unwrap();

    let rejected = next_event(&mut coordinator).await;
    assert!(matches!(
        rejected,
        TrafficTestEvent::EvaluationFailed {
            context,
            reason: TrafficTestFailureReason::Busy,
        } if context.run_id.get() == 50
    ));

    evaluator.release();
    let terminal = next_event(&mut coordinator).await;
    assert!(matches!(
        terminal,
        TrafficTestEvent::EvaluationFinished { report }
            if report.context().run_id.get() == 1
    ));
    coordinator.shutdown().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn superseded_work_checks_cancellation_at_the_thirty_two_scenario_boundary() {
    let evaluator = ControlledEvaluator::blocking_first();
    let mut coordinator = TrafficTestCoordinator::spawn_with_evaluator(evaluator.clone());
    coordinator
        .try_evaluate(request(
            current_context(1, "same", 1, 1, EvaluationTarget::Runtime),
            64,
        ))
        .unwrap();
    let _ = next_event(&mut coordinator).await;
    wait_for_calls(&evaluator, 1).await;

    coordinator
        .try_evaluate(request(
            current_context(2, "same", 1, 2, EvaluationTarget::Runtime),
            64,
        ))
        .unwrap();
    for _ in 0..32 {
        tokio::task::yield_now().await;
    }
    evaluator.release();

    let event = next_event(&mut coordinator).await;
    assert!(matches!(
        event,
        TrafficTestEvent::EvaluationCancelled {
            context,
            reason: TrafficTestCancellationReason::Superseded,
        } if context.run_id.get() == 1
    ));
    assert!(evaluator.calls_for(1) <= TRAFFIC_TEST_CANCELLATION_INTERVAL);
    coordinator.shutdown().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn deadline_fails_without_publishing_a_partial_report() {
    let evaluator = ControlledEvaluator::blocking_first();
    let mut coordinator = TrafficTestCoordinator::spawn_with_evaluator(evaluator.clone());
    coordinator
        .try_evaluate(request(
            current_context(1, "deadline", 1, 1, EvaluationTarget::Runtime),
            64,
        ))
        .unwrap();
    let _ = next_event(&mut coordinator).await;
    wait_for_calls(&evaluator, 1).await;

    tokio::time::advance(Duration::from_secs(2)).await;
    tokio::task::yield_now().await;
    evaluator.release();

    let event = next_event(&mut coordinator).await;
    assert!(matches!(
        event,
        TrafficTestEvent::EvaluationFailed {
            reason: TrafficTestFailureReason::EvaluationLimitExceeded,
            ..
        }
    ));
    coordinator.shutdown().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn every_identity_change_prevents_stale_publication() {
    let cases = [
        (
            current_context(1, "current", 1, 10, EvaluationTarget::Runtime),
            current_context(1, "current", 1, 11, EvaluationTarget::Runtime),
        ),
        (
            current_context(1, "current", 1, 10, EvaluationTarget::Runtime),
            current_context(1, "current", 2, 10, EvaluationTarget::Runtime),
        ),
        (
            current_context(1, "current", 1, 10, EvaluationTarget::Runtime),
            current_context(1, "current", 1, 10, EvaluationTarget::Permanent),
        ),
        (
            staged_context(1, 1, Some(1), b"a"),
            staged_context(1, 2, Some(1), b"a"),
        ),
        (
            staged_context(1, 1, Some(1), b"a"),
            staged_context(1, 1, Some(2), b"a"),
        ),
        (
            staged_context(1, 1, Some(1), b"a"),
            staged_context(1, 1, Some(1), b"b"),
        ),
    ];

    for (original, changed) in cases {
        let evaluator = ControlledEvaluator::blocking_first();
        let mut coordinator = TrafficTestCoordinator::spawn_with_evaluator(evaluator.clone());
        coordinator.try_evaluate(request(original, 1)).unwrap();
        let _ = next_event(&mut coordinator).await;
        wait_for_calls(&evaluator, 1).await;

        coordinator.try_invalidate(changed).unwrap();
        for _ in 0..32 {
            tokio::task::yield_now().await;
        }
        evaluator.release();

        let event = next_event(&mut coordinator).await;
        assert!(matches!(
            event,
            TrafficTestEvent::EvaluationCancelled {
                reason: TrafficTestCancellationReason::StaleContext,
                ..
            }
        ));
        coordinator.shutdown().await.unwrap();
    }
}

#[tokio::test(start_paused = true)]
async fn queued_invalidation_wins_over_a_backpressured_completed_report() {
    let evaluator = ControlledEvaluator::blocking_call(3);
    let mut coordinator = TrafficTestCoordinator::spawn_with_evaluator(evaluator.clone());
    for run_id in 1..=5 {
        let id = format!("fill-{run_id}");
        coordinator
            .try_evaluate(request(
                current_context(run_id, &id, 1, 1, EvaluationTarget::Runtime),
                1,
            ))
            .unwrap();
    }
    wait_for_calls(&evaluator, 4).await;

    for index in 0..TRAFFIC_TEST_PENDING_CONTEXT_CAPACITY {
        let id = format!("backpressure-pending-{index}");
        loop {
            match coordinator.try_evaluate(request(
                current_context(
                    u64::try_from(index + 20).unwrap(),
                    &id,
                    1,
                    1,
                    EvaluationTarget::Runtime,
                ),
                1,
            )) {
                Ok(()) => break,
                Err(TrafficTestSubmissionError::Busy) => tokio::task::yield_now().await,
                Err(error) => panic!("unexpected submission error: {error}"),
            }
        }
    }
    while coordinator.remaining_request_capacity() != TRAFFIC_TEST_REQUEST_CAPACITY {
        tokio::task::yield_now().await;
    }
    coordinator
        .try_evaluate(request(
            current_context(50, "backpressure-overflow", 1, 1, EvaluationTarget::Runtime),
            1,
        ))
        .unwrap();
    while coordinator.remaining_result_capacity() > 0 {
        tokio::task::yield_now().await;
    }

    coordinator
        .try_invalidate(current_context(
            4,
            "fill-4",
            1,
            2,
            EvaluationTarget::Runtime,
        ))
        .unwrap();
    evaluator.release();
    std::thread::sleep(Duration::from_millis(10));

    for _ in 0..TRAFFIC_TEST_EVENT_CAPACITY {
        let _ = next_event(&mut coordinator).await;
    }
    let mut event = next_event(&mut coordinator).await;
    while event.context().run_id.get() != 4 {
        event = next_event(&mut coordinator).await;
    }
    assert!(
        matches!(
            &event,
            TrafficTestEvent::EvaluationCancelled {
                context,
                reason: TrafficTestCancellationReason::StaleContext,
            } if context.run_id.get() == 4
        ),
        "unexpected event: {event:?}"
    );
    coordinator.shutdown().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn shutdown_cancels_and_joins_the_owned_worker_within_the_deadline() {
    let evaluator = ControlledEvaluator::blocking_first();
    let mut coordinator = TrafficTestCoordinator::spawn_with_evaluator(evaluator.clone());
    coordinator
        .try_evaluate(request(
            current_context(1, "shutdown", 1, 1, EvaluationTarget::Runtime),
            64,
        ))
        .unwrap();
    let _ = next_event(&mut coordinator).await;
    wait_for_calls(&evaluator, 1).await;

    let release = evaluator.clone();
    let release_task = tokio::spawn(async move {
        tokio::task::yield_now().await;
        release.release();
    });
    coordinator.shutdown().await.unwrap();
    release_task.await.unwrap();
    assert!(evaluator.calls_for(1) <= TRAFFIC_TEST_CANCELLATION_INTERVAL);
}

#[tokio::test(start_paused = true)]
async fn shutdown_timeout_retains_the_worker_handle_for_a_later_join() {
    let evaluator = ControlledEvaluator::blocking_first();
    let mut coordinator = TrafficTestCoordinator::spawn_with_evaluator(evaluator.clone());
    coordinator
        .try_evaluate(request(
            current_context(1, "shutdown-timeout", 1, 1, EvaluationTarget::Runtime),
            64,
        ))
        .unwrap();
    let _ = next_event(&mut coordinator).await;
    wait_for_calls(&evaluator, 1).await;

    let mut shutdown = Box::pin(coordinator.shutdown());
    tokio::select! {
        biased;
        result = &mut shutdown => panic!("shutdown completed before deadline: {result:?}"),
        () = tokio::task::yield_now() => {}
    }
    tokio::time::advance(Duration::from_secs(2)).await;
    assert_eq!(
        shutdown.await,
        Err(TrafficTestShutdownError::DeadlineExceeded)
    );
    evaluator.release();
    coordinator.shutdown().await.unwrap();
    assert!(evaluator.calls_for(1) <= TRAFFIC_TEST_CANCELLATION_INTERVAL);
}
