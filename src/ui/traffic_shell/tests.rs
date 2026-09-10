use super::*;
use crate::{application::*, config::Config, domain::TrafficSuite};
use futures_util::StreamExt;
use std::sync::atomic::{AtomicUsize, Ordering};

mod delivery;

static EDIT_SEQUENCE: AtomicUsize = AtomicUsize::new(0);
#[tokio::test]
async fn traffic_shell_audit_failure_survives_unrelated_presentation_and_success() {
    use crate::application::traffic_test_audit::*;
    struct FailOnce(AtomicUsize);
    impl TrafficAuditSink for FailOnce {
        fn append(&self, _: &TrafficAuditSummary) -> Result<(), TrafficAuditError> {
            if self.0.fetch_add(1, Ordering::Relaxed) == 0 {
                Err(TrafficAuditError::Persistence)
            } else {
                Ok(())
            }
        }
    }
    let sink = Arc::new(FailOnce(AtomicUsize::new(0)));
    let mut shell = TrafficShell::with_audit(
        Some(Arc::new(Storage {
            available: true,
            ..Default::default()
        })),
        sink.clone(),
    );
    let mut state = UiState::new(&Config::default(), "test".into(), false, None);
    observe(&mut state);
    shell.route(&Effect::TrafficLoad, &state).unwrap();
    let action = shell.next_action().await.unwrap();
    crate::ui::update::update(&mut state, action);
    for _ in 0..2 {
        let before = sink.0.load(Ordering::Relaxed);
        shell.route(&Effect::TrafficEvaluate, &state).unwrap();
        loop {
            let action = shell.next_action().await.unwrap();
            crate::ui::update::update(&mut state, action);
            if sink.0.load(Ordering::Relaxed) > before
                && shell
                    .service
                    .as_ref()
                    .unwrap()
                    .audit_status()
                    .failure
                    .is_some()
                && shell
                    .service
                    .as_ref()
                    .unwrap()
                    .workspace()
                    .active_context()
                    .is_none()
            {
                break;
            }
        }
        let action = shell
            .route(
                &Effect::TrafficTarget(crate::domain::EvaluationTarget::Permanent),
                &state,
            )
            .unwrap();
        crate::ui::update::update(&mut state, action);
        assert_eq!(
            state.traffic.audit.failure,
            Some(TrafficAuditError::Persistence)
        );
    }
    assert_eq!(
        shell.shutdown().await,
        Err(TrafficServiceShutdownError::AuditFailed)
    );
}
#[tokio::test]
async fn traffic_shell_injected_audit_is_lazy_and_records_evaluation() {
    use crate::infrastructure::{
        audit::traffic::FileTrafficAuditSink, traffic_test_storage::DefaultTrafficSuiteStorage,
    };
    let root = EditRoot::new();
    let audit_root = root.0.join("state");
    let storage = Arc::new(DefaultTrafficSuiteStorage::new(&root.0.join("config")));
    let sink = Arc::new(FileTrafficAuditSink::new(
        Some(audit_root.clone()),
        Config::default().retention.audit,
    ));
    let mut shell = TrafficShell::with_audit(Some(storage), sink);
    let mut state = UiState::new(&Config::default(), "test".into(), false, None);
    assert!(!audit_root.exists());
    shell.route(&Effect::TrafficLoad, &state).unwrap();
    let action = shell.next_action().await.unwrap();
    crate::ui::update::update(&mut state, action);
    assert!(!audit_root.exists());
    let effect = local_candidate(&mut state, false);
    let action = shell.route(&effect, &state).unwrap();
    crate::ui::update::update(&mut state, action);
    let action = shell.next_action().await.unwrap();
    crate::ui::update::update(&mut state, action);
    assert!(!audit_root.exists());
    let observed = ObservedSnapshot::new(
        SnapshotIdentity::new(
            RefreshId::new(1),
            SnapshotGeneration::new(std::num::NonZeroU64::MIN),
        ),
        Arc::new(crate::domain::mock::sample().unwrap()),
    );
    shell
        .route(&Effect::TrafficObserve(Some(observed)), &state)
        .unwrap();
    shell.route(&Effect::TrafficEvaluate, &state).unwrap();
    shell.shutdown().await.unwrap();
    assert!(audit_root.join("traffic-audit/audit.jsonl").is_file());
}
struct EditRoot(std::path::PathBuf);
impl EditRoot {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
            "fwdeck-p24-shell-{}-{}",
            std::process::id(),
            EDIT_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        )))
    }
}
impl Drop for EditRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn local_candidate(state: &mut UiState, edit: bool) -> Effect {
    use crate::ui::{
        overlays::Overlay,
        traffic_test_form::{EditAction as A, Template},
    };
    state.view = crate::ui::views::ViewId::TrafficTests;
    crate::ui::update::update(
        state,
        UiAction::TrafficEdit(if edit { A::Edit } else { A::New(Template::Ssh) }),
    );
    let Some(Overlay::TrafficForm(editor)) = state.overlays.last_mut() else {
        panic!("editor missing")
    };
    editor.draft.source = "203.0.113.8".into();
    if edit {
        editor.draft.name = "Edited SSH scenario".into();
    }
    crate::ui::update::update(state, UiAction::TrafficEdit(A::Review));
    let effects = crate::ui::update::update(state, UiAction::TrafficEdit(A::Save));
    assert!(matches!(effects.as_slice(), [Effect::TrafficSave(_)]));
    effects.into_iter().next().unwrap()
}

#[tokio::test]
async fn traffic_shell_reviewed_create_edit_reload_uses_service_revision() {
    use crate::infrastructure::traffic_test_storage::DefaultTrafficSuiteStorage;
    let root = EditRoot::new();
    assert!(!root.0.exists());
    let storage = Arc::new(DefaultTrafficSuiteStorage::new(&root.0));
    let mut shell = TrafficShell::new(Some(storage));
    let mut state = UiState::new(&Config::default(), "test".into(), false, None);
    state.read_only = true;
    let action = shell.route(&Effect::TrafficLoad, &state).unwrap();
    crate::ui::update::update(&mut state, action);
    let action = shell.next_action().await.unwrap();
    crate::ui::update::update(&mut state, action);
    assert!(!root.0.exists(), "load must not create suite files");
    for (edit, revision) in [(false, 1), (true, 2)] {
        let effect = local_candidate(&mut state, edit);
        let Effect::TrafficSave(candidate) = &effect else {
            unreachable!()
        };
        assert_eq!(candidate.revision.get(), 1);
        let routed = shell.route(&effect, &state);
        assert!(
            routed.is_some(),
            "reviewed save must route through the shell"
        );
        crate::ui::update::update(&mut state, routed.unwrap());
        let action = shell.next_action().await.unwrap();
        crate::ui::update::update(&mut state, action);
        assert!(state.overlays.is_empty());
        let SuiteState::Available(saved) = &state.traffic.suite else {
            panic!("saved suite unavailable")
        };
        let mut expected = (**candidate).clone();
        expected.revision = crate::domain::TrafficSuiteRevision::new(revision).unwrap();
        assert_eq!(**saved, expected);
        let action = shell.route(&Effect::TrafficLoad, &state).unwrap();
        crate::ui::update::update(&mut state, action);
        let action = shell.next_action().await.unwrap();
        crate::ui::update::update(&mut state, action);
        assert!(
            matches!(&state.traffic.suite, SuiteState::Available(suite) if **suite == expected)
        );
    }
    shell.shutdown().await.unwrap();
}

#[tokio::test]
async fn traffic_shell_conflict_retains_candidate_and_requires_explicit_discard_reload() {
    use crate::{
        infrastructure::traffic_test_storage::DefaultTrafficSuiteStorage,
        ui::{
            overlays::Overlay,
            traffic_test_form::{EditAction as A, Stage},
        },
    };
    let root = EditRoot::new();
    let storage = Arc::new(DefaultTrafficSuiteStorage::new(&root.0));
    let mut shell = TrafficShell::new(Some(Arc::clone(&storage)));
    let mut state = UiState::new(&Config::default(), "test".into(), false, None);
    shell.route(&Effect::TrafficLoad, &state).unwrap();
    let action = shell.next_action().await.unwrap();
    crate::ui::update::update(&mut state, action);
    let effect = local_candidate(&mut state, false);
    let Effect::TrafficSave(candidate) = &effect else {
        unreachable!()
    };
    storage
        .save_default(candidate, TrafficSaveExpectation::Missing)
        .unwrap();
    let routed = shell.route(&effect, &state);
    assert!(routed.is_some(), "reviewed save must route");
    let action = routed.unwrap();
    crate::ui::update::update(&mut state, action);
    let action = shell.next_action().await.unwrap();
    crate::ui::update::update(&mut state, action);
    let Some(Overlay::TrafficForm(editor)) = state.overlays.last() else {
        panic!("failed draft lost")
    };
    assert_eq!(editor.stage, Stage::Failed);
    assert!(Arc::ptr_eq(editor.candidate.as_ref().unwrap(), candidate));
    assert!(crate::ui::update::update(&mut state, UiAction::TrafficEdit(A::Save)).is_empty());
    let rejection = shell.route(&effect, &state).unwrap();
    assert!(
        matches!(rejection, UiAction::TrafficSaveRejected(_, ref error) if error.contains("unavailable"))
    );
    assert!(crate::ui::update::update(&mut state, UiAction::TrafficReload).is_empty());
    let effects = crate::ui::update::update(&mut state, UiAction::TrafficEdit(A::Discard));
    assert_eq!(effects, vec![Effect::TrafficLoad]);
    let action = shell.route(&effects[0], &state).unwrap();
    crate::ui::update::update(&mut state, action);
    let action = shell.next_action().await.unwrap();
    crate::ui::update::update(&mut state, action);
    assert!(matches!(state.traffic.suite, SuiteState::Available(_)));
    shell.shutdown().await.unwrap();
}

#[tokio::test]
async fn traffic_shell_save_busy_is_visible_and_accepted_save_rearms_closed_lane() {
    use crate::infrastructure::traffic_test_storage::DefaultTrafficSuiteStorage;
    let root = EditRoot::new();
    let storage = Arc::new(DefaultTrafficSuiteStorage::new(&root.0));
    let mut coordinator = TrafficTestCoordinator::spawn();
    coordinator.shutdown().await.unwrap();
    let mut shell = TrafficShell::new(Some(Arc::clone(&storage)));
    shell.service = Some(TrafficTestService::with_coordinator(
        false,
        storage,
        coordinator,
    ));
    let mut state = UiState::new(&Config::default(), "test".into(), false, None);
    shell.route(&Effect::TrafficLoad, &state).unwrap();
    for _ in 0..2 {
        let action = shell.next_action().await.unwrap();
        crate::ui::update::update(&mut state, action);
    }
    assert!(shell.next_action().await.is_none());
    assert!(!shell.armed());
    let effect = local_candidate(&mut state, false);
    let routed = shell.route(&effect, &state);
    assert!(
        routed.is_some(),
        "save must be routed even after the event lane closes"
    );
    let action = routed.unwrap();
    crate::ui::update::update(&mut state, action);
    assert!(shell.armed(), "accepted save must rearm event polling");
    let rejection = shell.route(&effect, &state).unwrap();
    assert!(
        matches!(rejection, UiAction::TrafficSaveRejected(_, ref error) if error.contains("busy"))
    );
    let action = shell.next_action().await.unwrap();
    crate::ui::update::update(&mut state, action);
    assert!(state.overlays.is_empty());
    shell.shutdown().await.unwrap();
}

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
