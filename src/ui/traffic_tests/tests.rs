use super::*;
use crate::{
    config::Config,
    domain::*,
    ui::{state::UiState, views::ViewId},
};

fn suite() -> Arc<TrafficSuite> {
    Arc::new(TrafficSuite {
        id: TrafficSuiteId::parse("default").unwrap(),
        name: "Default checks".into(),
        revision: TrafficSuiteRevision::new(1).unwrap(),
        scenarios: (0..16)
            .map(|index| TrafficScenario {
                id: TrafficScenarioId::parse(&format!("case-{index}")).unwrap(),
                name: format!("Case {index:02} long configuration evaluation scenario name"),
                enabled: index != 1,
                direction: TrafficDirection::ToHost,
                source: SourceAddress::parse("192.0.2.0/24").unwrap(),
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
                note: None,
            })
            .collect(),
    })
}

fn state() -> UiState {
    let mut state = UiState::new(&Config::default(), "test".into(), false, None);
    state.view = ViewId::TrafficTests;
    state.traffic.suite = SuiteState::Available(suite());
    state
}

#[test]
fn pre_run_details_show_current_snapshot_identity_separately_from_history() {
    use crate::application::{ObservedSnapshot, RefreshId, SnapshotGeneration, SnapshotIdentity};
    let mut workspace = TrafficTestWorkspace::new(false);
    workspace.replace_suite(suite()).unwrap();
    let observed = ObservedSnapshot::new(
        SnapshotIdentity::new(
            RefreshId::new(42),
            SnapshotGeneration::new(std::num::NonZeroU64::new(2).unwrap()),
        ),
        Arc::new(crate::domain::mock::sample().unwrap()),
    );
    workspace.observe(observed.clone());
    let presentation = TrafficPresentation::from_workspace(&workspace);
    let details = presentation
        .details(&TrafficScenarioId::parse("case-0").unwrap())
        .unwrap();
    assert!(
        details
            .lines
            .iter()
            .any(|(label, value)| label == "Current authoritative snapshot"
                && value == "refresh 42 / generation 2")
    );
    assert!(
        !details
            .lines
            .iter()
            .any(|(label, _)| label.contains("Historical"))
    );
    let mut workspace = completed_workspace();
    workspace.observe(observed);
    let details = TrafficPresentation::from_workspace(&workspace)
        .details(&TrafficScenarioId::parse("case-0").unwrap())
        .unwrap();
    assert!(
        details
            .lines
            .iter()
            .any(|(label, value)| label == "Current authoritative snapshot"
                && value == "refresh 42 / generation 2")
    );
    assert!(
        details
            .lines
            .iter()
            .any(|(label, value)| label.contains("Historical context")
                && value.contains("generation: 1"))
    );
}

#[test]
fn shared_header_and_help_describe_the_contextual_reload_key() {
    let theme = crate::ui::theme::Theme::detect(crate::ui::theme::Variant::Mono, false);
    let mut state = state();
    for (view, header_hint, help_hint) in [
        (ViewId::Zones, "refresh", "refresh data now"),
        (
            ViewId::TrafficTests,
            "reload suite",
            "reload default traffic suite",
        ),
    ] {
        state.view = view;
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(160, 50)).unwrap();
        terminal
            .draw(|frame| {
                crate::ui::components::render_header(
                    frame,
                    ratatui::layout::Rect::new(0, 0, 160, 5),
                    &state,
                    &theme,
                );
            })
            .unwrap();
        let text: String = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(ratatui::buffer::Cell::symbol)
            .collect();
        assert!(
            text.contains(header_hint),
            "missing header hint {header_hint}"
        );
        state.overlays = vec![crate::ui::overlays::Overlay::Help];
        let mut found = false;
        for scroll in (0..200).step_by(10) {
            state.overlay_scroll = scroll;
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
            found |= text.contains(help_hint);
            if view == ViewId::TrafficTests {
                assert!(!text.contains("refresh data now"));
            }
        }
        assert!(found, "missing help hint {help_hint}");
        state.overlays.clear();
    }
}

fn completed_workspace() -> TrafficTestWorkspace {
    use crate::application::{
        ObservedSnapshot, RefreshId, SnapshotGeneration, SnapshotIdentity, TrafficTestEvent,
    };
    let mut workspace = TrafficTestWorkspace::new(false);
    workspace.replace_suite(suite()).unwrap();
    workspace.observe(ObservedSnapshot::new(
        SnapshotIdentity::new(
            RefreshId::new(1),
            SnapshotGeneration::new(std::num::NonZeroU64::MIN),
        ),
        Arc::new(crate::domain::mock::sample().unwrap()),
    ));
    let prepared = workspace.prepare_evaluation().unwrap();
    workspace
        .ingest_event(TrafficTestEvent::EvaluationStarted {
            context: prepared.context().clone(),
        })
        .unwrap();
    let results = prepared
        .suite()
        .scenarios
        .iter()
        .filter(|scenario| scenario.enabled)
        .map(|scenario| {
            TrafficTestResult::new(
                scenario.id.clone(),
                scenario.expectation,
                if scenario.id.as_str() == "case-0" {
                    FirewallDecision::Unknown
                } else {
                    FirewallDecision::Allow
                },
                if scenario.id.as_str() == "case-0" {
                    Some(UnknownReason::UnsupportedDirection)
                } else {
                    None
                },
                vec![],
            )
            .unwrap()
        })
        .collect();
    let report = Arc::new(TrafficTestReport::new(prepared.context().clone(), results).unwrap());
    workspace
        .ingest_event(TrafficTestEvent::EvaluationFinished { report })
        .unwrap();
    workspace
}

#[test]
fn native_results_match_exact_ids_and_retained_history_is_never_current_pass() {
    let mut workspace = completed_workspace();
    let presentation = TrafficPresentation::from_workspace(&workspace);
    assert_eq!(presentation.rows()[0][4], "Indeterminate");
    assert_eq!(presentation.rows()[1][4], "NotRun (disabled)");
    assert_eq!(presentation.rows()[2][4], "Pass");
    workspace.set_target(EvaluationTarget::Permanent).unwrap();
    let presentation = TrafficPresentation::from_workspace(&workspace);
    assert_eq!(presentation.rows()[2][4], "Stale");
    let mut changed = suite().as_ref().clone();
    changed.scenarios[2].name = "changed name".into();
    changed.scenarios[2].expectation = TrafficExpectation::Block;
    workspace.replace_suite(Arc::new(changed)).unwrap();
    let mut presentation = TrafficPresentation::from_workspace(&workspace);
    presentation.evaluation = EvaluationState::NotRun;
    assert!(presentation.stale_report.is_some());
    assert_eq!(
        presentation.rows()[2][4],
        "Stale",
        "retained report must be explicitly historical"
    );
}

#[test]
fn request_errors_are_visible_with_an_available_suite() {
    let mut state = state();
    state.traffic.error = Some("traffic test service is busy".into());
    let theme = crate::ui::theme::Theme::detect(crate::ui::theme::Variant::Mono, false);
    let mut terminal = ratatui::Terminal::new(ratatui::backend::TestBackend::new(80, 24)).unwrap();
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
    assert!(text.contains("traffic test service is busy"));
}

#[test]
fn missing_loading_future_malformed_and_unavailable_are_readable() {
    let mut workspace = TrafficTestWorkspace::new(false);
    let token = workspace.begin_load().unwrap();
    let cases = [
        (SuiteState::Loading(token), "Loading default suite"),
        (SuiteState::Missing, "No file was created"),
        (SuiteState::UnsupportedSchema(99), "future schema 99"),
        (
            SuiteState::Failed(crate::application::SuiteLoadFailure::InvalidSuite),
            "InvalidSuite",
        ),
        (
            SuiteState::Failed(crate::application::SuiteLoadFailure::Storage),
            "Storage",
        ),
    ];
    for (suite, expected) in cases {
        let mut state = state();
        state.traffic.suite = suite;
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(80, 24)).unwrap();
        let theme = crate::ui::theme::Theme::detect(crate::ui::theme::Variant::Mono, false);
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
        assert!(text.contains(expected), "missing {expected}");
        assert!(!text.contains("create key"));
    }
}

#[test]
fn details_scroll_to_final_note_and_keep_historical_context_while_queued() {
    let mut workspace = completed_workspace();
    workspace.set_target(EvaluationTarget::Permanent).unwrap();
    workspace.prepare_evaluation().unwrap();
    let mut state = state();
    state.traffic = TrafficPresentation::from_workspace(&workspace);
    let content = state
        .traffic
        .details(&TrafficScenarioId::parse("case-0").unwrap())
        .unwrap();
    assert!(
        content
            .lines
            .iter()
            .any(|(label, _)| label.contains("Historical context")),
        "queued work must retain labeled historical identity"
    );
    let mut content = content;
    content.lines.push((
        "Note".into(),
        format!("{} END_OF_NOTE", "long operator context ".repeat(100)),
    ));
    state
        .overlays
        .push(crate::ui::overlays::Overlay::Details(content));
    crate::ui::update::update(
        &mut state,
        crate::ui::action::UiAction::ScrollOverlay(i32::MAX),
    );
    let theme = crate::ui::theme::Theme::detect(crate::ui::theme::Variant::Mono, false);
    let mut terminal = ratatui::Terminal::new(ratatui::backend::TestBackend::new(80, 24)).unwrap();
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
    assert!(text.contains("END_OF_NOTE"));
}

#[test]
fn every_selected_row_keeps_complete_metadata_visible_across_navigation_filter_resize() {
    let mut state = native_render_state();
    let theme = crate::ui::theme::Theme::detect(crate::ui::theme::Variant::Mono, false);
    for (width, height) in [(80, 24), (120, 40), (160, 50), (80, 24)] {
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| crate::ui::render::render(frame, &mut state, &theme))
            .unwrap();
        assert_selected_card(terminal.backend().buffer(), &state);
        for selected in (0..16).chain((0..16).rev()).chain([15]) {
            let delta = selected - i32::try_from(state.view_state().selected).unwrap();
            crate::ui::update::update(
                &mut state,
                crate::ui::action::UiAction::MoveSelection(delta),
            );
            terminal
                .draw(|frame| crate::ui::render::render(frame, &mut state, &theme))
                .unwrap();
            assert_selected_card(terminal.backend().buffer(), &state);
        }
        state.view_state_mut().filter = "Case 15".into();
        crate::ui::update::update(&mut state, crate::ui::action::UiAction::SelectLast);
        terminal
            .draw(|frame| crate::ui::render::render(frame, &mut state, &theme))
            .unwrap();
        assert_selected_card(terminal.backend().buffer(), &state);
        crate::ui::update::update(&mut state, crate::ui::action::UiAction::ClearFilter);
        assert_eq!(state.view_state().selected, 15);
        terminal
            .draw(|frame| crate::ui::render::render(frame, &mut state, &theme))
            .unwrap();
        assert_selected_card(terminal.backend().buffer(), &state);
    }
}

fn native_render_state() -> UiState {
    use crate::application::{
        ObservedSnapshot, RefreshId, SnapshotGeneration, SnapshotIdentity, TrafficTestEvent,
    };
    let mut suite = suite().as_ref().clone();
    for (index, scenario) in suite.scenarios.iter_mut().enumerate() {
        scenario.name = format!("Case {index:02} {}", "N".repeat(MAX_TRAFFIC_NAME_BYTES - 8));
        assert_eq!(scenario.name.len(), MAX_TRAFFIC_NAME_BYTES);
        scenario.enabled = true;
        scenario.direction = if index % 2 == 0 {
            TrafficDirection::FromHost
        } else {
            TrafficDirection::ToHost
        };
        scenario.expectation = if index % 2 == 0 {
            TrafficExpectation::Block
        } else {
            TrafficExpectation::Allow
        };
        scenario.severity = if index % 2 == 0 {
            TrafficSeverity::Critical
        } else {
            TrafficSeverity::Advisory
        };
        scenario.ingress_zone = Some(ZoneName::parse("trusted").unwrap());
    }
    suite.validate().unwrap();
    let mut snapshot = crate::domain::mock::sample().unwrap();
    snapshot.direct_rules.clear();
    let snapshot = Arc::new(snapshot);
    let mut workspace = TrafficTestWorkspace::new(false);
    workspace.replace_suite(Arc::new(suite)).unwrap();
    workspace.observe(ObservedSnapshot::new(
        SnapshotIdentity::new(
            RefreshId::new(1),
            SnapshotGeneration::new(std::num::NonZeroU64::MIN),
        ),
        Arc::clone(&snapshot),
    ));
    let prepared = workspace.prepare_evaluation().unwrap();
    let index = TrafficEvaluationIndex::new(snapshot, EvaluationTarget::Runtime);
    let results = prepared
        .suite()
        .scenarios
        .iter()
        .map(|scenario| evaluate_scenario(&index, scenario, prepared.context()).unwrap())
        .collect();
    let report = Arc::new(TrafficTestReport::new(prepared.context().clone(), results).unwrap());
    assert_eq!(
        report.results()[0].status(),
        TrafficTestStatus::Indeterminate
    );
    assert_eq!(report.results()[0].decision(), FirewallDecision::Unknown);
    assert_eq!(report.results()[1].status(), TrafficTestStatus::Pass);
    assert_eq!(report.results()[1].decision(), FirewallDecision::Allow);
    workspace
        .ingest_event(TrafficTestEvent::EvaluationStarted {
            context: prepared.context().clone(),
        })
        .unwrap();
    workspace
        .ingest_event(TrafficTestEvent::EvaluationFinished { report })
        .unwrap();
    let mut state = state();
    state.traffic = TrafficPresentation::from_workspace(&workspace);
    state
}

fn assert_selected_card(buffer: &ratatui::buffer::Buffer, state: &UiState) {
    let width = buffer.area.width;
    let left = if width >= state.sidebar_width + 40 {
        state.sidebar_width + 1
    } else {
        1
    };
    let lines: Vec<String> = (11..buffer.area.height.saturating_sub(2))
        .map(|y| (left..width - 1).map(|x| buffer[(x, y)].symbol()).collect())
        .collect();
    let start = lines
        .iter()
        .position(|line| line.starts_with("> "))
        .unwrap_or_else(|| panic!("selected marker missing inside traffic body"));
    let end = lines
        .iter()
        .enumerate()
        .skip(start + 1)
        .find(|(_, line)| {
            line.trim_start().starts_with("NAME: Case ") || line.trim_start().starts_with("Case ")
        })
        .map_or(lines.len(), |(index, _)| index);
    let card = lines[start..end].join("\n");
    let header: String = (left..width - 1)
        .map(|x| buffer[(x, 11)].symbol())
        .collect();
    let columns = if header.contains("DIRECTION") {
        Some(
            ViewId::TrafficTests
                .columns()
                .iter()
                .map(|label| header.find(label).unwrap())
                .collect::<Vec<_>>(),
        )
    } else {
        None
    };
    let selected = state.view_state().selected;
    for (index, field) in state.visible_rows()[selected].cells().iter().enumerate() {
        let text = columns.as_ref().map_or_else(
            || card.clone(),
            |columns| {
                let from = columns[index];
                let to = columns.get(index + 1).copied().unwrap_or(header.len());
                lines[start..end]
                    .iter()
                    .map(|line| line.chars().skip(from).take(to - from).collect::<String>())
                    .collect::<String>()
            },
        );
        let normalized: String = text
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect();
        let expected: String = field
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect();
        assert!(
            normalized.contains(&expected),
            "selected card missing {field:?} at {}x{}: {card}",
            width,
            buffer.area.height
        );
    }
    assert_eq!(
        card.matches("Case ").count(),
        1,
        "neighbor leaked into selected-card assertions"
    );
}

#[test]
fn details_open_without_firewall_and_show_scenario_inputs() {
    let mut state = state();
    let action = crate::ui::keymap::translate(
        &state,
        crossterm::event::KeyEvent::from(crossterm::event::KeyCode::Enter),
    )
    .unwrap();
    crate::ui::update::update(&mut state, action);
    let Some(crate::ui::overlays::Overlay::Details(content)) = state.overlays.last() else {
        panic!("traffic details missing")
    };
    assert!(
        content
            .lines
            .iter()
            .any(|(_, value)| value.contains("192.0.2.0/24"))
    );
    assert!(
        content
            .lines
            .iter()
            .any(|(_, value)| value.contains("NOT VERIFIED"))
    );
}

#[test]
fn projection_uses_real_suite_before_firewall_snapshot() {
    let state = state();
    let rows = state.visible_rows();
    assert_eq!(rows.len(), 16);
    assert_eq!(rows[0].cells().len(), 7);
    assert_eq!(rows[1][4], "NotRun (disabled)");
    assert_eq!(rows[0][4], "NotRun");
}

#[test]
fn render_always_discloses_configuration_only_without_firewall() {
    let mut state = state();
    let theme = crate::ui::theme::Theme::detect(crate::ui::theme::Variant::Mono, false);
    for (width, height) in [(80, 24), (120, 40), (160, 50)] {
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(width, height)).unwrap();
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
        assert!(text.contains("Configuration evaluation"));
        assert!(text.contains("Live connectivity: NOT VERIFIED"));
        assert!(text.contains("not enforced in Phase 2"));
    }
}
