use super::*;
use crate::{application::*, config::Config, domain::TrafficSuite};
use futures_util::StreamExt;
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Default)]
struct Storage {
    loads: AtomicUsize,
    block: std::sync::Mutex<Option<std::sync::mpsc::Receiver<()>>>,
    available: bool,
}
impl TrafficSuiteStorage for Storage {
    type Version = u64;
    fn load_default(&self) -> Result<LoadedTrafficSuite<u64>, TrafficStorageError> {
        self.loads.fetch_add(1, Ordering::SeqCst);
        if let Some(block) = self.block.lock().unwrap().take() {
            block.recv().unwrap();
        }
        if self.available {
            return Ok(LoadedTrafficSuite::Available {
                suite: Arc::new(TrafficSuite {
                    id: crate::domain::TrafficSuiteId::parse("default").unwrap(),
                    name: "Checks".into(),
                    revision: crate::domain::TrafficSuiteRevision::new(1).unwrap(),
                    scenarios: vec![],
                }),
                fingerprint: 1,
            });
        }
        Ok(LoadedTrafficSuite::Missing)
    }
    fn save_default(
        &self,
        _: &TrafficSuite,
        _: TrafficSaveExpectation<u64>,
    ) -> Result<LoadedTrafficSuite<u64>, TrafficStorageError> {
        panic!("saving is out of scope")
    }
}

fn observe(state: &mut UiState) {
    state.traffic_observation = Some(ObservedSnapshot::new(
        SnapshotIdentity::new(
            RefreshId::new(1),
            SnapshotGeneration::new(std::num::NonZeroU64::MIN),
        ),
        Arc::new(crate::domain::mock::sample().unwrap()),
    ));
}

#[tokio::test]
async fn unavailable_config_directory_does_not_construct_a_service() {
    let mut shell = TrafficShell::<Storage>::new(None);
    let state = UiState::new(&Config::default(), "test".into(), false, None);
    let action = shell.route(&Effect::TrafficLoad, &state).unwrap();
    assert!(
        matches!(action,UiAction::TrafficPresented(ref p) if p.error.as_deref().is_some_and(|error|error.contains("config directory unavailable")))
    );
    assert!(shell.service.is_none());
    assert!(!shell.armed());
}

#[tokio::test]
async fn shutdown_retains_and_joins_blocked_storage_across_deadline() {
    let (release, blocked) = std::sync::mpsc::channel();
    let storage = Arc::new(Storage {
        block: std::sync::Mutex::new(Some(blocked)),
        ..Default::default()
    });
    let mut shell = TrafficShell::new(Some(storage));
    let state = UiState::new(&Config::default(), "test".into(), false, None);
    shell.route(&Effect::TrafficLoad, &state).unwrap();
    assert_eq!(
        shell.service.as_mut().unwrap().shutdown().await,
        Err(TrafficServiceShutdownError::DeadlineExceeded)
    );
    assert!(shell.service.is_some());
    release.send(()).unwrap();
    shell.shutdown().await.unwrap();
    assert!(matches!(
        shell.service.as_ref().unwrap().workspace().suite_state(),
        SuiteState::Missing
    ));
}

#[tokio::test]
async fn readonly_evaluates_and_offline_keeps_permanent_target() {
    for offline in [false, true] {
        let storage = Arc::new(Storage {
            available: true,
            ..Default::default()
        });
        let mut shell = TrafficShell::new(Some(storage));
        let mut state = UiState::new(
            &Config {
                offline,
                ..Default::default()
            },
            "test".into(),
            false,
            None,
        );
        state.read_only = true;
        observe(&mut state);
        shell.route(&Effect::TrafficLoad, &state).unwrap();
        let action = shell.next_action().await.unwrap();
        crate::ui::update::update(&mut state, action);
        let action = shell.route(&Effect::TrafficEvaluate, &state).unwrap();
        assert!(
            matches!(action,UiAction::TrafficPresented(ref p) if matches!(p.evaluation,EvaluationState::Queued(_)))
        );
        for _ in 0..3 {
            let action =
                tokio::time::timeout(std::time::Duration::from_secs(2), shell.next_action())
                    .await
                    .unwrap()
                    .unwrap();
            crate::ui::update::update(&mut state, action);
        }
        assert!(matches!(
            state.traffic.evaluation,
            EvaluationState::Completed(_)
        ));
        if offline {
            assert_eq!(
                state.traffic.target,
                crate::domain::EvaluationTarget::Permanent
            );
            let action = shell
                .route(
                    &Effect::TrafficTarget(crate::domain::EvaluationTarget::Runtime),
                    &state,
                )
                .unwrap();
            assert!(
                matches!(action,UiAction::TrafficPresented(ref p) if p.target == crate::domain::EvaluationTarget::Permanent && p.error.is_some())
            );
        }
        shell.shutdown().await.unwrap();
    }
}

#[tokio::test]
async fn closed_lane_disarms_and_explicit_reload_rearms() {
    let storage = Arc::new(Storage::default());
    let mut coordinator = TrafficTestCoordinator::spawn();
    coordinator.shutdown().await.unwrap();
    let mut shell = TrafficShell::new(Some(Arc::clone(&storage)));
    shell.service = Some(TrafficTestService::with_coordinator(
        false,
        storage,
        coordinator,
    ));
    let state = UiState::new(&Config::default(), "test".into(), false, None);
    shell.route(&Effect::TrafficLoad, &state).unwrap();
    for _ in 0..2 {
        shell.next_action().await.unwrap();
    }
    assert!(shell.next_action().await.is_none());
    assert!(!shell.armed());
    let action = shell.route(&Effect::TrafficLoad, &state).unwrap();
    assert!(
        matches!(action,UiAction::TrafficPresented(ref p) if matches!(p.suite,SuiteState::Loading(_)))
    );
    assert!(shell.armed());
    assert!(shell.next_action().await.is_some());
    shell.shutdown().await.unwrap();
}

#[tokio::test]
async fn production_lane_services_input_tick_and_engine_while_storage_is_blocked() {
    use crate::ui::{action::UiAction, outbox::EngineOutbox};
    use std::time::Duration;
    let (release, blocked) = std::sync::mpsc::channel();
    let storage = Arc::new(Storage {
        block: std::sync::Mutex::new(Some(blocked)),
        ..Default::default()
    });
    let mut shell = TrafficShell::new(Some(Arc::clone(&storage)));
    let mut state = UiState::new(&Config::default(), "test".into(), false, None);
    let mut outbox = EngineOutbox::new();
    let _ = crate::ui::process_action_worklist_with_traffic(
        &mut state,
        &mut outbox,
        std::collections::VecDeque::from([UiAction::SwitchView(
            crate::ui::views::ViewId::TrafficTests,
        )]),
        Config::default().retention,
        &mut shell,
    )
    .await;
    assert!(matches!(state.traffic.suite, SuiteState::Loading(_)));
    let action = shell.route(&Effect::TrafficLoad, &state).unwrap();
    assert!(
        matches!(action,UiAction::TrafficPresented(ref p) if p.error.as_deref().is_some_and(|error|error.contains("busy")))
    );
    let (requests, _request_rx) = tokio::sync::mpsc::channel(1);
    let (manual_refreshes, _manual_rx) = tokio::sync::mpsc::channel(1);
    let (rollbacks, _rollback_rx) = tokio::sync::mpsc::channel(1);
    let (events_tx, events) = tokio::sync::mpsc::channel(1);
    let (refresh_priority, _priority_rx) = refresh_priority_channel();
    let mut engine = EngineHandle {
        requests,
        manual_refreshes,
        rollbacks,
        events,
        refresh_priority,
    };
    let ctrl_c = std::future::pending::<std::io::Result<()>>();
    tokio::pin!(ctrl_c);
    let (_logs_tx, mut logs) = tokio::sync::mpsc::channel(1);
    let mut tick = tokio::time::interval(Duration::from_millis(1));
    let mut input = futures_util::stream::iter([Ok(crossterm::event::Event::Key(
        crossterm::event::KeyEvent::from(crossterm::event::KeyCode::Down),
    ))])
    .chain(futures_util::stream::pending());
    events_tx
        .send(EngineEvent::OperationFinished(Box::new(OperationResult {
            op_id: 1,
            outcome: crate::application::ports::OperationOutcome::Applied {
                operation: crate::domain::FirewallOperation::Reload,
                steps: vec![],
            },
            rollback: None,
            guard_warning: None,
            completed_rollback: Some(crate::application::ports::RollbackGuardId::new(1)),
        })))
        .await
        .unwrap();
    let mut alive = true;
    let mut specific = None;
    let mut logs_alive = true;
    let mut batch = Vec::new();
    let mut input_seen = false;
    let mut tick_seen = false;
    let mut engine_seen = false;
    for _ in 0..30 {
        let action = tokio::time::timeout(
            Duration::from_secs(1),
            crate::ui::next_event_loop_action_with_traffic(
                ctrl_c.as_mut(),
                &mut engine,
                &mut outbox,
                &mut tick,
                &mut input,
                &state,
                &mut alive,
                &mut specific,
                &mut logs,
                &mut logs_alive,
                &mut batch,
                &mut shell,
            ),
        )
        .await
        .unwrap()
        .unwrap();
        input_seen |= matches!(action, Some(UiAction::MoveSelection(1)));
        tick_seen |= matches!(action, Some(UiAction::Tick));
        engine_seen |= matches!(action, Some(UiAction::OperationFinished(ref result)) if result.completed_rollback.is_some());
        if input_seen && tick_seen && engine_seen {
            break;
        }
    }
    release.send(()).unwrap();
    shell.next_action().await.unwrap();
    shell.shutdown().await.unwrap();
    assert!(input_seen && tick_seen && engine_seen);
}

#[tokio::test]
async fn shell_is_lazy_and_explicit_load_publishes_loading() {
    let storage = Arc::new(Storage::default());
    let mut shell = TrafficShell::new(Some(Arc::clone(&storage)));
    let state = UiState::new(&Config::default(), "test".into(), false, None);
    assert!(shell.service.is_none());
    assert_eq!(storage.loads.load(Ordering::SeqCst), 0);
    let publication = shell.route(&Effect::TrafficLoad, &state);
    assert!(
        matches!(publication,Some(UiAction::TrafficPresented(ref p)) if matches!(p.suite,SuiteState::Loading(_))),
        "accepted load must publish Loading"
    );
    shell.service.as_mut().unwrap().shutdown().await.unwrap();
}
