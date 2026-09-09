use super::*;
use crate::{
    application::{RefreshScheduleObservation, RefreshTrigger},
    domain::{EvaluationTarget, TrafficSuiteId, TrafficSuiteRevision},
    infrastructure::{
        audit::traffic::FileTrafficAuditSink, traffic_test_storage::DefaultTrafficSuiteStorage,
    },
    ui::{overlays::Overlay, traffic_test_form::EditAction, views::ViewId},
};
use std::{collections::VecDeque, num::NonZeroU64, sync::Arc, time::Duration};

fn dispatch(
    shell: &mut TrafficShell<DefaultTrafficSuiteStorage>,
    state: &mut UiState,
    action: UiAction,
) {
    let mut actions = VecDeque::from([action]);
    while let Some(action) = actions.pop_front() {
        for effect in crate::ui::update::update(state, action) {
            assert!(
                matches!(
                    effect,
                    Effect::TrafficSave(_)
                        | Effect::TrafficLoad
                        | Effect::TrafficEvaluate
                        | Effect::TrafficTarget(_)
                        | Effect::TrafficObserve(_)
                ),
                "traffic workflow emitted engine or mutation effect: {effect:?}"
            );
            if let Some(action) = shell.route(&effect, state) {
                actions.push_back(action);
            }
        }
    }
    assert!(
        state.read_only,
        "local workflow must preserve read-only mode"
    );
}

async fn wait_until(
    shell: &mut TrafficShell<DefaultTrafficSuiteStorage>,
    state: &mut UiState,
    ready: impl Fn(&UiState) -> bool,
) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while !ready(state) {
        let action = tokio::time::timeout_at(deadline, shell.next_action())
            .await
            .unwrap()
            .unwrap();
        dispatch(shell, state, action);
    }
}

fn completed_report(state: &UiState) -> Arc<crate::domain::TrafficTestReport> {
    let EvaluationState::Completed(report) = &state.traffic.evaluation else {
        panic!("traffic evaluation did not complete")
    };
    Arc::clone(report)
}

fn detail<'a>(content: &'a crate::ui::details::DetailsContent, label: &str) -> &'a str {
    let Some((_, value)) = content.lines.iter().find(|(key, _)| key == label) else {
        panic!("missing detail label {label}")
    };
    value
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn real_shell_delivers_reviewed_reload_evaluation_staleness_and_audit_workflow() {
    let root = EditRoot::new();
    let config_root = root.0.join("config");
    let state_root = root.0.join("state");
    let suite_path = config_root.join("traffic-tests/default.toml");
    let audit_path = state_root.join("traffic-audit/audit.jsonl");
    let storage = Arc::new(DefaultTrafficSuiteStorage::new(&config_root));
    let sink = Arc::new(FileTrafficAuditSink::new(
        Some(state_root),
        Config::default().retention.audit,
    ));
    let mut shell = TrafficShell::with_audit(Some(storage), sink);
    let mut state = UiState::new(&Config::default(), "test".into(), false, None);
    state.read_only = true;
    observe(&mut state);

    dispatch(&mut shell, &mut state, UiAction::OpenPalette);
    for character in "go to traffic tests".chars() {
        dispatch(&mut shell, &mut state, UiAction::PaletteInput(character));
    }
    assert!(matches!(
        crate::ui::palette::filtered(&state).first(),
        Some(command) if command.action == UiAction::SwitchView(ViewId::TrafficTests)
    ));
    dispatch(&mut shell, &mut state, UiAction::PaletteExecute);
    assert_eq!(state.view, ViewId::TrafficTests);
    wait_until(&mut shell, &mut state, |state| {
        matches!(state.traffic.suite, SuiteState::Missing)
    })
    .await;
    assert!(!suite_path.exists(), "explicit missing load created a file");

    let effect = local_candidate(&mut state, false);
    let Effect::TrafficSave(candidate) = &effect else {
        unreachable!()
    };
    let scenario_id = candidate.scenarios[0].id.clone();
    let action = shell.route(&effect, &state).unwrap();
    dispatch(&mut shell, &mut state, action);
    wait_until(&mut shell, &mut state, |state| {
        matches!(state.traffic.save, TrafficSaveState::Saved(_))
    })
    .await;
    assert!(suite_path.is_file());
    dispatch(&mut shell, &mut state, UiAction::TrafficReload);
    wait_until(&mut shell, &mut state, |state| {
        matches!(state.traffic.suite, SuiteState::Available(_))
    })
    .await;
    let SuiteState::Available(reloaded) = &state.traffic.suite else {
        unreachable!()
    };
    assert_eq!(reloaded.revision.get(), 1);
    assert_eq!(reloaded.scenarios[0].id, scenario_id);

    dispatch(&mut shell, &mut state, UiAction::TrafficEvaluate);
    wait_until(&mut shell, &mut state, |state| {
        matches!(state.traffic.evaluation, EvaluationState::Completed(_))
    })
    .await;
    let runtime_report = completed_report(&state);
    assert_eq!(runtime_report.context().target, EvaluationTarget::Runtime);
    assert_eq!(runtime_report.context().suite_revision.get(), 1);
    assert_eq!(
        runtime_report.context().authoritative_snapshot.refresh_id(),
        1
    );
    assert_eq!(
        runtime_report.context().authoritative_snapshot.generation(),
        1
    );
    dispatch(&mut shell, &mut state, UiAction::ActivateRow);
    let Some(Overlay::Details(runtime_details)) = state.overlays.last() else {
        panic!("runtime details did not open")
    };
    assert_eq!(detail(runtime_details, "Target"), "Runtime");
    assert_eq!(
        detail(runtime_details, "Status"),
        format!("{:?}", runtime_report.results()[0].status())
    );
    assert!(
        detail(runtime_details, "Current context")
            .contains(&format!("run {}", runtime_report.context().run_id.get()))
    );
    dispatch(&mut shell, &mut state, UiAction::CloseOverlay);

    dispatch(&mut shell, &mut state, UiAction::TrafficToggleTarget);
    assert_eq!(state.traffic.target, EvaluationTarget::Permanent);
    assert!(matches!(
        state.traffic.evaluation,
        EvaluationState::Stale(_)
    ));
    dispatch(&mut shell, &mut state, UiAction::TrafficEvaluate);
    wait_until(&mut shell, &mut state, |state| {
        matches!(state.traffic.evaluation, EvaluationState::Completed(_))
    })
    .await;
    let previous = completed_report(&state);
    assert_eq!(previous.context().target, EvaluationTarget::Permanent);
    assert_ne!(previous.context().run_id, runtime_report.context().run_id);

    let refresh_id = RefreshId::new(2);
    dispatch(
        &mut shell,
        &mut state,
        UiAction::RefreshStarted {
            id: refresh_id,
            trigger: RefreshTrigger::Manual,
        },
    );
    let changed = ObservedSnapshot::new(
        SnapshotIdentity::new(
            refresh_id,
            SnapshotGeneration::new(NonZeroU64::new(2).unwrap()),
        ),
        Arc::new(crate::domain::mock::sample().unwrap()),
    );
    dispatch(
        &mut shell,
        &mut state,
        UiAction::RefreshCompleted {
            schedule: RefreshScheduleObservation {
                id: refresh_id,
                trigger: RefreshTrigger::Manual,
                merged_manual_requests: 0,
                coalesced_periodic_ticks: 0,
            },
            result: Ok(changed),
            observation: crate::domain::RefreshObservation::total_only(Duration::ZERO),
        },
    );
    assert!(matches!(
        state.traffic.evaluation,
        EvaluationState::Stale(_)
    ));
    assert_eq!(state.traffic.rows()[0][4], "Stale");
    assert_eq!(
        state
            .traffic
            .stale_report
            .as_ref()
            .map(|report| report.context()),
        Some(previous.context())
    );

    dispatch(&mut shell, &mut state, UiAction::TrafficEvaluate);
    wait_until(&mut shell, &mut state, |state| {
        matches!(state.traffic.evaluation, EvaluationState::Completed(_))
    })
    .await;
    let current = completed_report(&state);
    assert_ne!(current.context().run_id, previous.context().run_id);
    assert_eq!(current.context().suite_revision.get(), 1);
    assert_eq!(current.context().target, EvaluationTarget::Permanent);
    assert_eq!(current.context().authoritative_snapshot.refresh_id(), 2);
    assert_eq!(current.context().authoritative_snapshot.generation(), 2);
    assert_eq!(
        state.traffic.rows()[0][4],
        format!("{:?}", current.results()[0].status())
    );
    dispatch(&mut shell, &mut state, UiAction::ActivateRow);
    let Some(Overlay::Details(current_details)) = state.overlays.last() else {
        panic!("current details did not open")
    };
    assert_eq!(
        detail(current_details, "Status"),
        format!("{:?}", current.results()[0].status())
    );
    assert!(
        detail(current_details, "Current context")
            .contains(&format!("run {}", current.context().run_id.get()))
    );
    dispatch(&mut shell, &mut state, UiAction::CloseOverlay);

    let theme = crate::ui::theme::Theme::detect(crate::ui::theme::Variant::Mono, false);
    let mut terminal = ratatui::Terminal::new(ratatui::backend::TestBackend::new(120, 40)).unwrap();
    terminal
        .draw(|frame| crate::ui::render::render(frame, &mut state, &theme))
        .unwrap();
    let rendered: String = terminal
        .backend()
        .buffer()
        .content()
        .iter()
        .map(ratatui::buffer::Cell::symbol)
        .collect();
    assert!(rendered.contains("Traffic Tests"));
    assert!(rendered.contains(&format!("{:?}", current.results()[0].status())));

    shell.shutdown().await.unwrap();
    let audit = std::fs::read_to_string(audit_path).unwrap();
    let records: Vec<serde_json::Value> = audit
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(records.len(), 3);
    assert!(records.iter().all(|record| {
        record["outcome"] == "completed"
            && record["configuration_only"] == true
            && record["live_connectivity_verified"] == false
    }));
}

#[tokio::test]
async fn real_shell_preserves_malformed_and_future_default_suite_bytes() {
    for (bytes, future) in [
        ("schema_version = 1\nname = [", false),
        (
            "schema_version = 999\nid = 'default'\nname = 'Future'\nrevision = 9\n",
            true,
        ),
    ] {
        let root = EditRoot::new();
        let config_root = root.0.join("config");
        let suite_path = config_root.join("traffic-tests/default.toml");
        std::fs::create_dir_all(suite_path.parent().unwrap()).unwrap();
        std::fs::write(&suite_path, bytes).unwrap();
        let storage = Arc::new(DefaultTrafficSuiteStorage::new(&config_root));
        let mut shell = TrafficShell::new(Some(storage));
        let mut state = UiState::new(&Config::default(), "test".into(), false, None);
        state.read_only = true;

        dispatch(
            &mut shell,
            &mut state,
            UiAction::SwitchView(ViewId::TrafficTests),
        );
        wait_until(&mut shell, &mut state, |state| {
            !matches!(state.traffic.suite, SuiteState::Loading(_))
        })
        .await;
        if future {
            assert!(matches!(
                state.traffic.suite,
                SuiteState::UnsupportedSchema(999)
            ));
        } else {
            assert!(matches!(state.traffic.suite, SuiteState::Failed(_)));
        }
        dispatch(
            &mut shell,
            &mut state,
            UiAction::TrafficEdit(EditAction::New(crate::ui::traffic_test_form::Template::Ssh)),
        );
        assert!(state.overlays.is_empty());
        let candidate = Arc::new(TrafficSuite {
            id: TrafficSuiteId::parse("default").unwrap(),
            name: "Replacement".into(),
            revision: TrafficSuiteRevision::new(1).unwrap(),
            scenarios: Vec::new(),
        });
        let rejected = shell
            .route(&Effect::TrafficSave(candidate), &state)
            .unwrap();
        dispatch(&mut shell, &mut state, rejected);
        assert_eq!(std::fs::read_to_string(&suite_path).unwrap(), bytes);
        shell.shutdown().await.unwrap();
    }
}
