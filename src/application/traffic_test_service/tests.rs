use super::*;
use crate::application::{SuiteState, traffic_test_storage::*};
use crate::domain::TrafficSuite;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

#[derive(Default)]
struct FakeStorage {
    calls: AtomicUsize,
}
impl TrafficSuiteStorage for FakeStorage {
    type Version = u64;
    fn load_default(&self) -> Result<LoadedTrafficSuite<u64>, TrafficStorageError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(LoadedTrafficSuite::Missing)
    }
    fn save_default(
        &self,
        _: &TrafficSuite,
        _: TrafficSaveExpectation<u64>,
    ) -> Result<LoadedTrafficSuite<u64>, TrafficStorageError> {
        panic!("unexpected save")
    }
}

#[tokio::test(flavor = "current_thread")]
async fn missing_load_does_not_create_suite() {
    let store = Arc::new(FakeStorage::default());
    let mut service = TrafficTestService::new(false, Arc::clone(&store));
    assert_eq!(store.calls.load(Ordering::SeqCst), 0);
    service.try_load().unwrap();
    service.next_event().await.unwrap();
    assert!(matches!(
        service.workspace().suite_state(),
        SuiteState::Missing
    ));
    assert_eq!(store.calls.load(Ordering::SeqCst), 1);
    service.shutdown().await.unwrap();
}

use crate::application::{
    EvaluationState, RefreshId, TrafficScenarioEvaluator, WorkspaceFailure,
    observation::SnapshotPublisher,
};
use crate::domain::{
    EvaluationContext, EvaluationTarget, FirewallDecision, TrafficEvaluationError,
    TrafficEvaluationIndex, TrafficScenario, TrafficSuiteId, TrafficSuiteRevision,
    TrafficTestResult,
};
use std::{collections::VecDeque, sync::Mutex};

type Response = Result<LoadedTrafficSuite<u64>, TrafficStorageError>;
enum Action {
    Return(Response),
    Panic,
    Block {
        entered: tokio::sync::oneshot::Sender<()>,
        release: std::sync::mpsc::Receiver<()>,
        result: Response,
    },
}
#[derive(Default)]
struct MemoryStorage {
    loaded: Mutex<Option<Arc<TrafficSuite>>>,
    fingerprint: std::sync::atomic::AtomicU64,
    expectations: Mutex<Vec<TrafficSaveExpectation<u64>>>,
    loads: AtomicUsize,
    saves: AtomicUsize,
    load_actions: Mutex<VecDeque<Action>>,
    save_actions: Mutex<VecDeque<Action>>,
}
impl MemoryStorage {
    fn available(suite: Arc<TrafficSuite>) -> Self {
        Self {
            loaded: Mutex::new(Some(suite)),
            fingerprint: std::sync::atomic::AtomicU64::new(41),
            ..Self::default()
        }
    }
    fn action(action: Action) -> Response {
        match action {
            Action::Return(result) => result,
            Action::Panic => panic!("fixture panic"),
            Action::Block {
                entered,
                release,
                result,
            } => {
                entered.send(()).unwrap();
                release.recv().unwrap();
                result
            }
        }
    }
}
impl TrafficSuiteStorage for MemoryStorage {
    type Version = u64;
    fn load_default(&self) -> Response {
        self.loads.fetch_add(1, Ordering::SeqCst);
        let action = self.load_actions.lock().unwrap().pop_front();
        if let Some(action) = action {
            return Self::action(action);
        }
        Ok(self
            .loaded
            .lock()
            .unwrap()
            .clone()
            .map_or(LoadedTrafficSuite::Missing, |suite| {
                LoadedTrafficSuite::Available {
                    suite,
                    fingerprint: self.fingerprint.load(Ordering::SeqCst),
                }
            }))
    }
    fn save_default(
        &self,
        suite: &TrafficSuite,
        expected: TrafficSaveExpectation<u64>,
    ) -> Response {
        self.saves.fetch_add(1, Ordering::SeqCst);
        self.expectations.lock().unwrap().push(expected);
        let action = self.save_actions.lock().unwrap().pop_front();
        if let Some(action) = action {
            return Self::action(action);
        }
        let suite = Arc::new(suite.clone());
        *self.loaded.lock().unwrap() = Some(Arc::clone(&suite));
        Ok(LoadedTrafficSuite::Available {
            suite,
            fingerprint: self.fingerprint.fetch_add(1, Ordering::SeqCst) + 1,
        })
    }
}
fn suite(revision: u64) -> Arc<TrafficSuite> {
    Arc::new(TrafficSuite {
        id: TrafficSuiteId::parse("default").unwrap(),
        name: "Default checks".into(),
        revision: TrafficSuiteRevision::new(revision).unwrap(),
        scenarios: vec![],
    })
}

#[tokio::test(flavor = "current_thread")]
async fn exact_storage_version_flows_through_create_update_and_reload() {
    let storage = Arc::new(MemoryStorage::default());
    let mut service = TrafficTestService::new(false, Arc::clone(&storage));
    load(&mut service).await;
    service.try_save(suite(1)).unwrap();
    service.next_event().await.unwrap();
    assert_eq!(storage.fingerprint.load(Ordering::SeqCst), 1);

    load(&mut service).await;
    service.try_save(suite(1)).unwrap();
    service.next_event().await.unwrap();
    assert_eq!(storage.fingerprint.load(Ordering::SeqCst), 2);

    service.try_save(suite(2)).unwrap();
    service.next_event().await.unwrap();
    assert_eq!(storage.fingerprint.load(Ordering::SeqCst), 3);

    storage.fingerprint.store(99, Ordering::SeqCst);
    load(&mut service).await;
    service.try_save(suite(3)).unwrap();
    service.next_event().await.unwrap();
    assert_eq!(storage.fingerprint.load(Ordering::SeqCst), 100);

    let recorded: Vec<_> = storage
        .expectations
        .lock()
        .unwrap()
        .iter()
        .map(|expected| match expected {
            TrafficSaveExpectation::Missing => None,
            TrafficSaveExpectation::Existing {
                revision,
                fingerprint,
            } => Some((revision.get(), *fingerprint)),
        })
        .collect();
    assert_eq!(
        recorded,
        vec![None, Some((1, 1)), Some((2, 2)), Some((3, 99))]
    );
    service.shutdown().await.unwrap();
}
async fn load(service: &mut TrafficTestService<MemoryStorage>) {
    service.try_load().unwrap();
    assert!(matches!(
        service.next_event().await,
        Some(TrafficServiceEvent::Loaded(_))
    ));
}
fn observation(generation: u64) -> ObservedSnapshot {
    let mut publisher = SnapshotPublisher::new();
    let snapshot = Arc::new(crate::domain::mock::sample().unwrap());
    let mut observation = publisher
        .publish(RefreshId::new(1), Arc::clone(&snapshot))
        .unwrap();
    for n in 2..=generation {
        observation = publisher
            .publish(RefreshId::new(n), Arc::clone(&snapshot))
            .unwrap();
    }
    observation
}
fn block(
    result: Response,
) -> (
    Action,
    tokio::sync::oneshot::Receiver<()>,
    std::sync::mpsc::Sender<()>,
) {
    let (entered, waiting) = tokio::sync::oneshot::channel();
    let (release, blocked) = std::sync::mpsc::channel();
    (
        Action::Block {
            entered,
            release: blocked,
            result,
        },
        waiting,
        release,
    )
}

#[tokio::test(flavor = "current_thread")]
async fn explicit_create_then_reload_and_revision_bump_preserve_draft() {
    let storage = Arc::new(MemoryStorage::default());
    let mut service = TrafficTestService::new(true, Arc::clone(&storage));
    assert_eq!(
        service.try_save(suite(1)),
        Err(TrafficServiceError::Unavailable)
    );
    load(&mut service).await;
    service.try_save(suite(1)).unwrap();
    assert!(matches!(
        service.workspace().suite_state(),
        SuiteState::Missing
    ));
    assert!(matches!(
        service.next_event().await,
        Some(TrafficServiceEvent::Saved { result: Ok(()), .. })
    ));
    load(&mut service).await;
    let mut edit = suite(1).as_ref().clone();
    edit.name = "Edited name".into();
    let draft = Arc::new(edit);
    service.try_save(Arc::clone(&draft)).unwrap();
    service.next_event().await.unwrap();
    let SuiteState::Available(stored) = service.workspace().suite_state() else {
        panic!("missing suite")
    };
    assert_eq!(stored.revision.get(), 2);
    assert_eq!(stored.name, draft.name);
    assert_eq!(draft.revision.get(), 1);
    service.shutdown().await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn invalid_identity_content_revision_and_exhaustion_do_not_write() {
    let storage = Arc::new(MemoryStorage::default());
    let mut service = TrafficTestService::new(false, Arc::clone(&storage));
    load(&mut service).await;
    let mut invalid = suite(1).as_ref().clone();
    invalid.id = TrafficSuiteId::parse("other").unwrap();
    assert_eq!(
        service.try_save(Arc::new(invalid)),
        Err(TrafficServiceError::InvalidSuite)
    );
    let mut invalid = suite(1).as_ref().clone();
    invalid.name.clear();
    assert_eq!(
        service.try_save(Arc::new(invalid)),
        Err(TrafficServiceError::InvalidSuite)
    );
    assert_eq!(
        service.try_save(suite(2)),
        Err(TrafficServiceError::InvalidSuite)
    );
    *storage.loaded.lock().unwrap() = Some(suite(u64::MAX));
    load(&mut service).await;
    assert_eq!(
        service.try_save(suite(1)),
        Err(TrafficServiceError::InvalidSuite)
    );
    assert_eq!(
        service.try_save(suite(u64::MAX)),
        Err(TrafficServiceError::IdentityExhausted)
    );
    assert_eq!(storage.saves.load(Ordering::SeqCst), 0);
    service.shutdown().await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn conflicts_retain_exact_draft_and_revoke_overwrite_until_reload() {
    let storage = Arc::new(MemoryStorage::available(suite(1)));
    storage
        .save_actions
        .lock()
        .unwrap()
        .push_back(Action::Return(Err(TrafficStorageError::Conflict)));
    let mut service = TrafficTestService::new(false, Arc::clone(&storage));
    load(&mut service).await;
    let draft = suite(1);
    service.try_save(Arc::clone(&draft)).unwrap();
    service.next_event().await.unwrap();
    let TrafficSaveState::Failed {
        draft: retained,
        error,
    } = service.save_state()
    else {
        panic!("save not failed")
    };
    assert!(Arc::ptr_eq(retained, &draft));
    assert_eq!(*error, TrafficStorageError::Conflict);
    assert_eq!(
        service.try_save(Arc::clone(&draft)),
        Err(TrafficServiceError::Unavailable)
    );
    load(&mut service).await;
    service.try_save(draft).unwrap();
    service.next_event().await.unwrap();
    service.shutdown().await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn unsupported_and_malformed_loads_never_establish_save_authority() {
    let storage = Arc::new(MemoryStorage::default());
    let mut invalid = suite(1).as_ref().clone();
    invalid.id = TrafficSuiteId::parse("other").unwrap();
    storage.load_actions.lock().unwrap().extend([
        Action::Return(Ok(LoadedTrafficSuite::UnsupportedSchema(99))),
        Action::Return(Ok(LoadedTrafficSuite::Available {
            suite: Arc::new(invalid),
            fingerprint: 1,
        })),
        Action::Return(Err(TrafficStorageError::InvalidData)),
    ]);
    let mut service = TrafficTestService::new(false, Arc::clone(&storage));
    for _ in 0..3 {
        load(&mut service).await;
        assert_eq!(
            service.try_save(suite(1)),
            Err(TrafficServiceError::Unavailable)
        );
    }
    service.shutdown().await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn invalid_save_success_variants_retain_draft_without_trusting_version() {
    let storage = Arc::new(MemoryStorage::available(suite(1)));
    storage.save_actions.lock().unwrap().extend([
        Action::Return(Ok(LoadedTrafficSuite::Missing)),
        Action::Return(Ok(LoadedTrafficSuite::UnsupportedSchema(99))),
        Action::Return(Ok(LoadedTrafficSuite::Available {
            suite: suite(1),
            fingerprint: 2,
        })),
    ]);
    let mut service = TrafficTestService::new(false, Arc::clone(&storage));
    for _ in 0..3 {
        load(&mut service).await;
        service.try_save(suite(1)).unwrap();
        assert!(matches!(
            service.next_event().await,
            Some(TrafficServiceEvent::Saved {
                result: Err(TrafficStorageError::WorkerFailed),
                ..
            })
        ));
        assert_eq!(
            service.try_save(suite(1)),
            Err(TrafficServiceError::Unavailable)
        );
        let SuiteState::Available(loaded) = service.workspace().suite_state() else {
            panic!("lost suite")
        };
        assert_eq!(loaded.revision.get(), 1);
    }
    service.shutdown().await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn load_and_save_panics_are_owned_and_typed() {
    for saving in [false, true] {
        let storage = Arc::new(MemoryStorage::default());
        let mut service = TrafficTestService::new(false, Arc::clone(&storage));
        if saving {
            load(&mut service).await;
            storage
                .save_actions
                .lock()
                .unwrap()
                .push_back(Action::Panic);
            service.try_save(suite(1)).unwrap();
        } else {
            storage
                .load_actions
                .lock()
                .unwrap()
                .push_back(Action::Panic);
            service.try_load().unwrap();
        }
        let event = service.next_event().await.unwrap();
        assert!(matches!(
            event,
            TrafficServiceEvent::Loaded(Err(TrafficStorageError::WorkerFailed))
                | TrafficServiceEvent::Saved {
                    result: Err(TrafficStorageError::WorkerFailed),
                    ..
                }
        ));
        assert_eq!(
            service.shutdown().await,
            Err(TrafficServiceShutdownError::WorkerFailed)
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn blocked_storage_keeps_executor_freshness_and_poll_cancellation_live() {
    let storage = Arc::new(MemoryStorage::default());
    let (action, entered, release) = block(Ok(LoadedTrafficSuite::Missing));
    storage.load_actions.lock().unwrap().push_back(action);
    let mut service = TrafficTestService::new(false, storage);
    service.try_load().unwrap();
    entered.await.unwrap();
    let state = service.workspace().suite_state().clone();
    assert_eq!(service.try_load().unwrap_err(), TrafficServiceError::Busy);
    assert_eq!(service.try_save(suite(1)), Err(TrafficServiceError::Busy));
    assert_eq!(service.try_evaluate(), Err(TrafficServiceError::Busy));
    assert_eq!(service.workspace().suite_state(), &state);
    tokio::spawn(async {
        tokio::task::yield_now().await;
        42
    })
    .await
    .unwrap();
    service.observe(observation(1)).unwrap();
    service.set_target(EvaluationTarget::Permanent).unwrap();
    {
        let event = service.next_event();
        tokio::pin!(event);
        assert!(
            std::future::poll_fn(|cx| std::task::Poll::Ready(event.as_mut().poll(cx)))
                .await
                .is_pending()
        );
    }
    release.send(()).unwrap();
    assert!(matches!(
        service.next_event().await,
        Some(TrafficServiceEvent::Loaded(Ok(())))
    ));
    assert_eq!(service.workspace().target(), EvaluationTarget::Permanent);
    service.shutdown().await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn stale_index_is_discarded_and_real_coordinator_completes() {
    let storage = Arc::new(MemoryStorage::available(suite(1)));
    let mut service = TrafficTestService::new(false, storage);
    load(&mut service).await;
    service.observe(observation(1)).unwrap();
    service.try_evaluate().unwrap();
    service.observe(observation(2)).unwrap();
    assert!(matches!(
        service.next_event().await,
        Some(TrafficServiceEvent::ObsoleteIndex)
    ));
    service.try_evaluate().unwrap();
    assert!(matches!(
        service.next_event().await,
        Some(TrafficServiceEvent::EvaluationSubmitted(Ok(())))
    ));
    for _ in 0..2 {
        service.next_event().await.unwrap();
    }
    assert!(matches!(
        service.workspace().evaluation_state(),
        EvaluationState::Completed(_)
    ));
    service.shutdown().await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn coordinator_busy_cancellation_does_not_undo_freshness() {
    let storage = Arc::new(MemoryStorage::available(suite(1)));
    let mut service = TrafficTestService::new(false, storage);
    load(&mut service).await;
    service.observe(observation(1)).unwrap();
    let prepared = service.workspace.prepare_evaluation().unwrap();
    for _ in 0..8 {
        service
            .coordinator
            .try_invalidate(prepared.context().clone())
            .unwrap();
    }
    assert_eq!(
        service.observe(observation(2)),
        Err(TrafficServiceError::Busy)
    );
    assert_eq!(
        service
            .workspace()
            .observation()
            .unwrap()
            .identity()
            .generation()
            .get(),
        2
    );
    assert!(service.workspace().active_context().is_none());
    service.shutdown().await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn closed_lane_is_terminal_but_storage_remains_usable() {
    let storage = Arc::new(MemoryStorage::default());
    let mut coordinator = TrafficTestCoordinator::spawn();
    coordinator.shutdown().await.unwrap();
    let mut service = TrafficTestService::with_coordinator(false, storage, coordinator);
    assert!(matches!(
        service.next_event().await,
        Some(TrafficServiceEvent::CoordinatorClosed)
    ));
    assert!(service.next_event().await.is_none());
    assert_eq!(service.try_evaluate(), Err(TrafficServiceError::Closed));
    load(&mut service).await;
    service.try_save(suite(1)).unwrap();
    service.next_event().await.unwrap();
    service.shutdown().await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn shutdown_timeout_retains_write_and_retry_installs_truthful_result() {
    let storage = Arc::new(MemoryStorage::default());
    let (action, entered, release) = block(Ok(LoadedTrafficSuite::Available {
        suite: suite(1),
        fingerprint: 42,
    }));
    storage.save_actions.lock().unwrap().push_back(action);
    let mut service = TrafficTestService::new(false, storage);
    load(&mut service).await;
    service.try_save(suite(1)).unwrap();
    entered.await.unwrap();
    assert_eq!(
        service.shutdown().await,
        Err(TrafficServiceShutdownError::DeadlineExceeded)
    );
    assert!(service.job.is_some());
    assert_eq!(service.try_load().unwrap_err(), TrafficServiceError::Closed);
    release.send(()).unwrap();
    service.shutdown().await.unwrap();
    assert!(matches!(service.save_state(), TrafficSaveState::Saved(_)));
    assert!(matches!(
        service.workspace().suite_state(),
        SuiteState::Available(_)
    ));
    assert!(service.job.is_none());
}

fn scenario_suite() -> Arc<TrafficSuite> {
    use crate::domain::*;
    let mut suite = suite(1).as_ref().clone();
    suite.scenarios.push(TrafficScenario {
        id: TrafficScenarioId::parse("ssh").unwrap(),
        name: "SSH".into(),
        enabled: true,
        direction: TrafficDirection::ToHost,
        source: SourceAddress::parse("192.0.2.1").unwrap(),
        ingress_interface: None,
        ingress_zone: None,
        destination: TrafficDestination::LocalHost,
        egress_interface: None,
        egress_zone: None,
        transport: TrafficTransport::Tcp,
        destination_port: Some("22".parse().unwrap()),
        source_port: None,
        connection_state: TrafficConnectionState::New,
        expectation: TrafficExpectation::Allow,
        severity: TrafficSeverity::Critical,
        required_safety_gate: true,
        note: Some("Keep note".into()),
    });
    Arc::new(suite)
}

struct MalformedEvaluator;
impl TrafficScenarioEvaluator for MalformedEvaluator {
    fn evaluate(
        &self,
        _: &TrafficEvaluationIndex,
        scenario: &TrafficScenario,
        _: &EvaluationContext,
    ) -> Result<TrafficTestResult, TrafficEvaluationError> {
        Ok(TrafficTestResult::new(
            crate::domain::TrafficScenarioId::parse("foreign").unwrap(),
            scenario.expectation,
            FirewallDecision::Allow,
            None,
            vec![],
        )
        .unwrap())
    }
}

#[tokio::test(flavor = "current_thread")]
async fn malformed_matching_report_becomes_worker_failure() {
    let storage = Arc::new(MemoryStorage::available(scenario_suite()));
    let coordinator = TrafficTestCoordinator::spawn_with_evaluator(Arc::new(MalformedEvaluator));
    let mut service = TrafficTestService::with_coordinator(false, storage, coordinator);
    load(&mut service).await;
    service.observe(observation(1)).unwrap();
    service.try_evaluate().unwrap();
    for _ in 0..3 {
        service.next_event().await.unwrap();
    }
    assert!(matches!(
        service.workspace().evaluation_state(),
        EvaluationState::Failed {
            reason: WorkspaceFailure::WorkerFailed,
            ..
        }
    ));
    service.shutdown().await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn native_unknown_is_completed_not_coerced_to_allow() {
    let storage = Arc::new(MemoryStorage::available(scenario_suite()));
    let mut service = TrafficTestService::new(false, storage);
    load(&mut service).await;
    let mut publisher = SnapshotPublisher::new();
    let mut snapshot = crate::domain::mock::sample().unwrap();
    snapshot
        .direct_rules
        .push("ipv4 filter INPUT 0 -j DROP".into());
    let observed = publisher
        .publish(RefreshId::new(1), Arc::new(snapshot))
        .unwrap();
    service.observe(observed).unwrap();
    service.try_evaluate().unwrap();
    for _ in 0..3 {
        service.next_event().await.unwrap();
    }
    let EvaluationState::Completed(report) = service.workspace().evaluation_state() else {
        panic!("not completed")
    };
    assert_eq!(report.results()[0].decision(), FirewallDecision::Unknown);
    service.shutdown().await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn index_uses_prepared_snapshot_and_busy_submission_is_terminal() {
    let storage = Arc::new(MemoryStorage::available(suite(1)));
    let mut service = TrafficTestService::new(false, storage);
    load(&mut service).await;
    let original = observation(1);
    service.observe(original.clone()).unwrap();
    service.try_evaluate().unwrap();
    let mut job = service.job.take().unwrap();
    let output = (&mut job.task).await;
    let context = match &job.kind {
        JobKind::Index(context) => context.clone(),
        _ => panic!("wrong job"),
    };
    for _ in 0..8 {
        service.coordinator.try_invalidate(context.clone()).unwrap();
    }
    let event = service.finish_job(job.kind, output);
    assert!(matches!(
        event,
        TrafficServiceEvent::EvaluationSubmitted(Err(TrafficServiceError::Busy))
    ));
    assert!(matches!(
        service.workspace().evaluation_state(),
        EvaluationState::Failed {
            reason: WorkspaceFailure::Busy,
            ..
        }
    ));
    service.shutdown().await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn prepared_index_keeps_original_evidence_after_update() {
    let storage = Arc::new(MemoryStorage::available(suite(1)));
    let mut service = TrafficTestService::new(false, storage);
    load(&mut service).await;
    service.observe(observation(1)).unwrap();
    service.try_evaluate().unwrap();
    let mut job = service.job.take().unwrap();
    service.set_target(EvaluationTarget::Permanent).unwrap();
    service.observe(observation(2)).unwrap();
    let output = (&mut job.task).await;
    let Ok(JobOutput::Index(Ok(ref request))) = output else {
        panic!("missing request")
    };
    assert_eq!(request.context().target, EvaluationTarget::Runtime);
    assert_eq!(request.context().authoritative_snapshot.generation(), 1);
    assert!(matches!(
        service.finish_job(job.kind, output),
        TrafficServiceEvent::ObsoleteIndex
    ));
    service.shutdown().await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn index_panic_is_terminal_and_owned() {
    let storage = Arc::new(MemoryStorage::available(suite(1)));
    let mut service = TrafficTestService::new(false, storage);
    load(&mut service).await;
    service.observe(observation(1)).unwrap();
    let prepared = service.workspace.prepare_evaluation().unwrap();
    service.job = Some(Job {
        kind: JobKind::Index(prepared.context().clone()),
        task: tokio::task::spawn_blocking(|| panic!("index fixture panic")),
    });
    service.next_event().await.unwrap();
    assert!(matches!(
        service.workspace().evaluation_state(),
        EvaluationState::Failed {
            reason: WorkspaceFailure::WorkerFailed,
            ..
        }
    ));
    assert_eq!(
        service.shutdown().await,
        Err(TrafficServiceShutdownError::WorkerFailed)
    );
}

#[tokio::test(flavor = "current_thread")]
async fn old_terminal_after_save_cannot_replace_new_suite_evidence() {
    let storage = Arc::new(MemoryStorage::available(suite(1)));
    let mut service = TrafficTestService::new(false, storage);
    load(&mut service).await;
    service.observe(observation(1)).unwrap();
    let prepared = service.workspace.prepare_evaluation().unwrap();
    service.ingest(TrafficTestEvent::EvaluationStarted {
        context: prepared.context().clone(),
    });
    service.try_save(suite(1)).unwrap();
    service.next_event().await.unwrap();
    let report = Arc::new(
        crate::domain::TrafficTestReport::new(prepared.context().clone(), vec![]).unwrap(),
    );
    assert!(matches!(
        service.ingest(TrafficTestEvent::EvaluationFinished { report }),
        TrafficServiceEvent::Evaluation(Err(_))
    ));
    assert!(service.workspace().active_context().is_none());
    let SuiteState::Available(saved) = service.workspace().suite_state() else {
        panic!("missing saved")
    };
    assert_eq!(saved.revision.get(), 2);
    service.shutdown().await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn real_adapter_and_native_coordinator_complete_owned_round_trip() {
    use crate::infrastructure::traffic_test_storage::DefaultTrafficSuiteStorage;
    struct Root(std::path::PathBuf);
    impl Drop for Root {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let root =
        Root(std::env::temp_dir().join(format!("fwdeck-service-seam-{}", std::process::id())));
    assert!(!root.0.exists());
    let storage = Arc::new(DefaultTrafficSuiteStorage::new(&root.0));
    let mut service = TrafficTestService::new(false, storage);
    service.try_load().unwrap();
    assert!(matches!(
        service.next_event().await,
        Some(TrafficServiceEvent::Loaded(Ok(())))
    ));
    assert!(matches!(
        service.workspace().suite_state(),
        SuiteState::Missing
    ));
    assert!(!root.0.exists());
    let draft = scenario_suite();
    service.try_save(Arc::clone(&draft)).unwrap();
    assert!(matches!(
        service.next_event().await,
        Some(TrafficServiceEvent::Saved { result: Ok(()), .. })
    ));
    service.try_load().unwrap();
    service.next_event().await.unwrap();
    assert_eq!(
        service.workspace().suite_state(),
        &SuiteState::Available(Arc::clone(&draft))
    );
    let observed = observation(1);
    service.observe(observed.clone()).unwrap();
    service.try_evaluate().unwrap();
    let context = service.workspace().active_context().unwrap().clone();
    for _ in 0..3 {
        service.next_event().await.unwrap();
    }
    let EvaluationState::Completed(report) = service.workspace().evaluation_state() else {
        panic!("not completed")
    };
    assert_eq!(report.context(), &context);
    assert_eq!(context.suite_revision, draft.revision);
    assert_eq!(report.results()[0].scenario_id(), &draft.scenarios[0].id);
    assert_eq!(
        context.authoritative_snapshot.generation(),
        observed.identity().generation().get()
    );
    service.shutdown().await.unwrap();
}
