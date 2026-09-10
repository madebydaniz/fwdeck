use super::*;
use crate::domain::*;
use crate::ui::{
    action::{Effect, UiAction},
    keymap,
    overlays::{Confirmation, Overlay},
    update::update,
};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

mod refresh_tests;

struct PreviewStorage {
    suite: Option<Arc<TrafficSuite>>,
    future: bool,
    loads: AtomicUsize,
}
impl TrafficSuiteStorage for PreviewStorage {
    type Version = u64;
    fn load_default(&self) -> Result<LoadedTrafficSuite<u64>, TrafficStorageError> {
        self.loads.fetch_add(1, Ordering::SeqCst);
        if self.future {
            return Ok(LoadedTrafficSuite::UnsupportedSchema(99));
        }
        Ok(self
            .suite
            .clone()
            .map_or(LoadedTrafficSuite::Missing, |suite| {
                LoadedTrafficSuite::Available {
                    suite,
                    fingerprint: 1,
                }
            }))
    }
    fn save_default(
        &self,
        _: &TrafficSuite,
        _: TrafficSaveExpectation<u64>,
    ) -> Result<LoadedTrafficSuite<u64>, TrafficStorageError> {
        panic!("preview must never save")
    }
}
fn suite() -> Arc<TrafficSuite> {
    Arc::new(TrafficSuite {
        id: TrafficSuiteId::parse("default").unwrap(),
        name: "Checks".into(),
        revision: TrafficSuiteRevision::new(1).unwrap(),
        scenarios: vec![TrafficScenario {
            id: TrafficScenarioId::parse("ssh").unwrap(),
            name: "SSH доступ".into(),
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
            note: None,
        }],
    })
}
fn operation() -> FirewallOperation {
    FirewallOperation::RemoveService {
        zone: ZoneName::parse("public").unwrap(),
        service: ServiceName::parse("ssh").unwrap(),
        target: ConfigurationTarget::RuntimeAndPermanent,
    }
}
fn review() -> UiState {
    let mut s = UiState::new(&Config::default(), "test".into(), false, None);
    observe(&mut s);
    s.snapshot = s
        .traffic_observation
        .as_ref()
        .map(|o| o.snapshot_arc().clone());
    s.overlays.push(Overlay::Confirm(Confirmation {
        title: "Remove SSH".into(),
        body: vec!["review".into()],
        on_confirm: UiAction::ApplyOperation(MutationRequest::new(
            operation(),
            s.snapshot.clone().unwrap(),
        )),
    }));
    s
}
fn preview(s: &UiState) -> &crate::ui::traffic_preview::Preview {
    s.overlays
        .iter()
        .find_map(|o| match o {
            Overlay::TrafficPreview(p) => Some(p.as_ref()),
            _ => None,
        })
        .unwrap()
}
fn route(shell: &mut TrafficShell<PreviewStorage>, state: &mut UiState, effects: Vec<Effect>) {
    for effect in effects {
        assert!(!matches!(
            effect,
            Effect::Apply(_) | Effect::ApplyPlan(_) | Effect::TrafficSave(_)
        ));
        if let Some(a) = shell.route(&effect, state) {
            update(state, a);
        }
    }
}
async fn completed(shell: &mut TrafficShell<PreviewStorage>, state: &mut UiState) {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while !matches!(
            preview(state).publication.state,
            TrafficPreviewState::Completed(_) | TrafficPreviewState::Failed { .. }
        ) && preview(state).publication.error.is_none()
        {
            let a = shell.next_action().await.unwrap();
            let effects = update(state, a);
            route(shell, state, effects);
        }
    })
    .await
    .unwrap();
}
fn storage(suite: Option<Arc<TrafficSuite>>, future: bool) -> Arc<PreviewStorage> {
    Arc::new(PreviewStorage {
        suite,
        future,
        loads: AtomicUsize::new(0),
    })
}
#[test]
fn traffic_preview_scoped_key_and_exact_review_only() {
    let mut s = review();
    let parent = s.overlays.clone();
    assert_eq!(
        keymap::translate(&s, KeyEvent::new(KeyCode::Char('p'), KeyModifiers::NONE)),
        Some(UiAction::PreviewTraffic)
    );
    let effects = update(&mut s, UiAction::PreviewTraffic);
    assert!(
        matches!(&effects[..], [Effect::TrafficPreview(r)] if r.operations == vec![operation()])
    );
    assert_eq!(
        update(&mut s, UiAction::CloseOverlay),
        vec![Effect::TrafficPreviewCancel]
    );
    assert_eq!(s.overlays, parent);
    s.overlays = vec![Overlay::Confirm(Confirmation {
        title: "Quit".into(),
        body: vec![],
        on_confirm: UiAction::QuitConfirmed,
    })];
    assert_eq!(
        keymap::translate(&s, KeyEvent::new(KeyCode::Char('p'), KeyModifiers::NONE)),
        None
    );
    assert!(update(&mut s, UiAction::PreviewTraffic).is_empty());
    s.overlays = vec![Overlay::Palette(crate::ui::palette::PaletteState::default())];
    for ch in ['p', 'پ'] {
        assert_eq!(
            keymap::translate(&s, KeyEvent::new(KeyCode::Char(ch), KeyModifiers::NONE)),
            Some(UiAction::PaletteInput(ch))
        );
    }
    s.overlays = vec![Overlay::Form(crate::ui::overlays::FormState {
        kind: crate::ui::overlays::FormKind::AddService,
        buffer: String::new(),
    })];
    assert_eq!(
        keymap::translate(&s, KeyEvent::new(KeyCode::Char('p'), KeyModifiers::NONE)),
        Some(UiAction::FormInput('p'))
    );
}
#[test]
fn traffic_preview_staged_read_only_and_no_confirm_preserve_intent() {
    let mut s = review();
    s.overlays.clear();
    s.staged = vec![operation()];
    s.read_only = true;
    s.confirm_destructive = false;
    let staged = s.staged.clone();
    assert_eq!(
        crate::ui::traffic_preview::staged_availability(&s),
        crate::ui::palette::Availability::Enabled
    );
    let effects = update(&mut s, UiAction::PreviewStagedTraffic);
    assert!(
        matches!(&effects[..], [Effect::TrafficPreview(r)] if r.plan_id.is_some() && r.operations == staged)
    );
    assert_eq!(s.staged, staged);
    update(&mut s, UiAction::CloseOverlay);
    assert_eq!(s.staged, staged);
    s.read_only = false;
    assert!(matches!(
        &update(&mut s, UiAction::RequestOperation(operation()))[..],
        [Effect::TrafficObserve(None), Effect::Apply(_)]
    ));
}
#[test]
fn traffic_preview_plan_confirmation_retains_exact_order_and_id() {
    let mut s = review();
    let plan = MutationPlan::new(
        PlanId::new(47),
        vec![operation(), FirewallOperation::Reload],
        s.snapshot.clone().unwrap(),
    );
    s.overlays = vec![Overlay::Confirm(Confirmation {
        title: "Plan".into(),
        body: vec![],
        on_confirm: UiAction::ApplyPlanConfirmed(plan.clone()),
    })];
    assert!(
        matches!(&update(&mut s, UiAction::PreviewTraffic)[..], [Effect::TrafficPreview(r)] if r.plan_id == Some(plan.id) && r.operations == plan.operations)
    );
    update(&mut s, UiAction::CloseOverlay);
    assert!(
        matches!(&s.overlays[..], [Overlay::Confirm(c)] if c.on_confirm == UiAction::ApplyPlanConfirmed(plan))
    );
}
#[test]
fn traffic_preview_changed_review_and_staged_intent_cancel() {
    let mut s = review();
    update(&mut s, UiAction::PreviewTraffic);
    s.overlays.remove(0);
    assert_eq!(
        update(&mut s, UiAction::Tick),
        vec![Effect::TrafficPreviewCancel]
    );
    assert!(preview(&s).invalidated);
    s.overlays.clear();
    s.staged = vec![operation()];
    update(&mut s, UiAction::PreviewStagedTraffic);
    s.staged.clear();
    assert_eq!(
        update(&mut s, UiAction::Tick),
        vec![Effect::TrafficPreviewCancel]
    );
}
#[test]
fn traffic_preview_stale_before_p_and_disabled_palette_reasons() {
    let mut s = review();
    let other = Arc::new((**s.snapshot.as_ref().unwrap()).clone());
    s.traffic_observation = Some(ObservedSnapshot::new(
        s.traffic_observation.as_ref().unwrap().identity(),
        other,
    ));
    assert!(update(&mut s, UiAction::PreviewTraffic).is_empty());
    assert_eq!(s.overlays.len(), 1);
    s.staged = vec![operation()];
    assert!(
        matches!(crate::ui::traffic_preview::staged_availability(&s), crate::ui::palette::Availability::Disabled(reason) if reason.contains("stale"))
    );
    s.snapshot = s
        .traffic_observation
        .as_ref()
        .map(|o| o.snapshot_arc().clone());
    s.offline = true;
    assert!(
        matches!(crate::ui::traffic_preview::staged_availability(&s), crate::ui::palette::Availability::Disabled(reason) if reason.contains("offline"))
    );
    s.staged.clear();
    assert!(matches!(
        crate::ui::traffic_preview::staged_availability(&s),
        crate::ui::palette::Availability::Disabled("no staged operations")
    ));
}
#[tokio::test]
async fn traffic_preview_lazy_both_targets_details_and_responsive_final_trace() {
    let store = storage(Some(suite()), false);
    let mut shell = TrafficShell::new(Some(store.clone()));
    let mut s = review();
    let effects = update(&mut s, UiAction::PreviewTraffic);
    route(&mut shell, &mut s, effects);
    assert!(preview(&s).publication.loading);
    completed(&mut shell, &mut s).await;
    assert!(preview(&s).current(), "{}", preview(&s).status());
    let e = preview(&s).publication.state.evidence().unwrap();
    assert_eq!(e.pairs.len(), 2);
    assert_eq!(store.loads.load(Ordering::SeqCst), 1);
    let content = preview(&s).content();
    assert!(content.lines.iter().any(|(k, _)| k == "Runtime"));
    assert!(content.lines.iter().any(|(k, _)| k == "Permanent"));
    assert!(
        content
            .lines
            .iter()
            .any(|(_, v)| v.contains("Before:") && v.contains("After:") && v.contains("Change:"))
    );
    let details = preview(&s).details().unwrap();
    assert!(details.lines.iter().any(|(k, _)| k == "Before"));
    assert!(details.lines.iter().any(|(k, _)| k == "After"));
    let last = details.lines.last().unwrap().1.clone();
    let theme = crate::ui::theme::Theme::new(crate::ui::theme::Variant::Dracula, true, true);
    for (width, height) in [(80, 24), (120, 40), (160, 50)] {
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|f| crate::ui::overlays::render(f, &mut s, &theme, f.area()))
            .unwrap();
        let text: String = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(ratatui::buffer::Cell::symbol)
            .collect();
        assert!(text.contains("Traffic impact preview"));
        update(&mut s, UiAction::PreviewDetails);
        update(&mut s, UiAction::ScrollOverlay(i32::MAX));
        terminal
            .draw(|f| crate::ui::overlays::render(f, &mut s, &theme, f.area()))
            .unwrap();
        let text: String = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(ratatui::buffer::Cell::symbol)
            .collect();
        assert!(
            text.contains(&last),
            "final trace missing at {width}x{height}: {last}"
        );
        assert!(update(&mut s, UiAction::CloseOverlay).is_empty());
        assert!(preview(&s).current());
    }
    update(&mut s, UiAction::PreviewDetails);
    s.traffic_observation = None;
    let effects = update(&mut s, UiAction::Tick);
    route(&mut shell, &mut s, effects);
    assert!(
        matches!(s.overlays.last(), Some(Overlay::TrafficPreviewDetails(d)) if d.lines[0].1.contains("Stale"))
    );
    assert!(preview(&s).publication.state.evidence().is_some());
    update(&mut s, UiAction::CloseOverlay);
    assert!(preview(&s).invalidated);
    let effects = update(&mut s, UiAction::CloseOverlay);
    route(&mut shell, &mut s, effects);
    assert!(matches!(s.overlays.last(), Some(Overlay::Confirm(_))));
    shell.shutdown().await.unwrap();
}
#[tokio::test]
async fn traffic_preview_missing_future_and_empty_suite_never_saves_or_reloads() {
    for (suite, future, expected) in [
        (None, false, "No default suite"),
        (None, true, "future schema"),
        (
            Some(Arc::new(TrafficSuite {
                scenarios: vec![],
                ..(*suite()).clone()
            })),
            false,
            "no enabled",
        ),
    ] {
        let store = storage(suite, future);
        let mut shell = TrafficShell::new(Some(store.clone()));
        let mut s = review();
        let effects = update(&mut s, UiAction::PreviewTraffic);
        route(&mut shell, &mut s, effects);
        completed(&mut shell, &mut s).await;
        assert!(
            preview(&s).status().contains(expected),
            "{}",
            preview(&s).status()
        );
        let effects = update(&mut s, UiAction::CloseOverlay);
        route(&mut shell, &mut s, effects);
        let effects = update(&mut s, UiAction::PreviewTraffic);
        route(&mut shell, &mut s, effects);
        assert!(preview(&s).status().contains(expected));
        assert_eq!(store.loads.load(Ordering::SeqCst), 1);
        shell.shutdown().await.unwrap();
    }
}
#[tokio::test]
async fn traffic_preview_close_during_load_rejects_late_publication_for_same_intent() {
    let store = storage(Some(suite()), false);
    let mut shell = TrafficShell::new(Some(store));
    let mut s = review();
    let effects = update(&mut s, UiAction::PreviewTraffic);
    route(&mut shell, &mut s, effects);
    let old_owner = preview(&s).request.clone();
    let effects = update(&mut s, UiAction::CloseOverlay);
    route(&mut shell, &mut s, effects);
    let effects = update(&mut s, UiAction::PreviewTraffic);
    route(&mut shell, &mut s, effects);
    assert!(!Arc::ptr_eq(&old_owner, &preview(&s).request));
    let mut late = s.traffic.clone();
    late.preview.owner = Some(old_owner);
    late.preview.error = Some("OLD RESULT".into());
    update(&mut s, UiAction::TrafficPresented(late));
    assert!(!preview(&s).status().contains("OLD RESULT"));
    completed(&mut shell, &mut s).await;
    assert!(preview(&s).current());
    shell.shutdown().await.unwrap();
}

#[tokio::test]
async fn traffic_preview_busy_does_not_reload_or_attach_old_evidence() {
    let store = storage(Some(suite()), false);
    let mut shell = TrafficShell::new(Some(store.clone()));
    let mut s = review();
    let action = shell.route(&Effect::TrafficLoad, &s).unwrap();
    update(&mut s, action);
    let action = shell.next_action().await.unwrap();
    update(&mut s, action);
    shell.route(&Effect::TrafficEvaluate, &s).unwrap();
    let effects = update(&mut s, UiAction::PreviewTraffic);
    route(&mut shell, &mut s, effects);
    assert!(preview(&s).status().contains("busy"));
    assert!(preview(&s).publication.state.evidence().is_none());
    assert_eq!(store.loads.load(Ordering::SeqCst), 1);
    shell.shutdown().await.unwrap();
}
#[tokio::test]
async fn traffic_preview_stale_service_observation_never_reloads() {
    let store = storage(Some(suite()), false);
    let mut shell = TrafficShell::new(Some(store.clone()));
    let mut s = review();
    shell.route(&Effect::TrafficLoad, &s).unwrap();
    shell.next_action().await.unwrap();
    let other = ObservedSnapshot::new(
        SnapshotIdentity::new(
            RefreshId::new(2),
            SnapshotGeneration::new(std::num::NonZeroU64::new(2).unwrap()),
        ),
        Arc::new((**s.snapshot.as_ref().unwrap()).clone()),
    );
    shell
        .route(&Effect::TrafficObserve(Some(other)), &s)
        .unwrap();
    let effects = update(&mut s, UiAction::PreviewTraffic);
    route(&mut shell, &mut s, effects);
    assert!(preview(&s).status().contains("observation is stale"));
    assert!(!shell.pending_preview);
    assert_eq!(store.loads.load(Ordering::SeqCst), 1);
    shell.shutdown().await.unwrap();
}
#[tokio::test]
async fn traffic_preview_offline_and_pending_close_are_explicit() {
    let mut shell = TrafficShell::new(Some(storage(Some(suite()), false)));
    let mut s = review();
    s.offline = true;
    let effects = update(&mut s, UiAction::PreviewTraffic);
    route(&mut shell, &mut s, effects);
    completed(&mut shell, &mut s).await;
    assert!(preview(&s).status().contains("offline"));
    shell.shutdown().await.unwrap();
    let mut shell = TrafficShell::new(Some(storage(Some(suite()), false)));
    let mut s = review();
    let effects = update(&mut s, UiAction::PreviewTraffic);
    route(&mut shell, &mut s, effects);
    let effects = update(&mut s, UiAction::CloseOverlay);
    route(&mut shell, &mut s, effects);
    let a = shell.next_action().await.unwrap();
    update(&mut s, a);
    assert!(matches!(
        shell.service.as_ref().unwrap().preview_state(),
        TrafficPreviewState::Idle
    ));
    assert!(matches!(s.overlays.last(), Some(Overlay::Confirm(_))));
    shell.shutdown().await.unwrap();
}

#[tokio::test]
async fn traffic_preview_selected_row_remains_visible_at_responsive_sizes() {
    let mut many = (*suite()).clone();
    let template = many.scenarios[0].clone();
    many.scenarios = (0..30)
        .map(|i| TrafficScenario {
            id: TrafficScenarioId::parse(&format!("ssh-{i}")).unwrap(),
            name: format!("SSH check {i:02}"),
            ..template.clone()
        })
        .collect();
    let mut shell = TrafficShell::new(Some(storage(Some(Arc::new(many)), false)));
    let mut state = review();
    let effects = update(&mut state, UiAction::PreviewTraffic);
    route(&mut shell, &mut state, effects);
    completed(&mut shell, &mut state).await;
    assert!(preview(&state).current());
    let theme = crate::ui::theme::Theme::new(crate::ui::theme::Variant::Dracula, true, true);
    for (width, height) in [(80, 24), (120, 40), (160, 50)] {
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(width, height)).unwrap();
        for (delta, selected, name) in [
            (i32::MAX, 59, "SSH check 29"),
            (i32::MIN, 0, "SSH check 00"),
        ] {
            update(&mut state, UiAction::PreviewMove(delta));
            terminal
                .draw(|f| crate::ui::overlays::render(f, &mut state, &theme, f.area()))
                .unwrap();
            assert_eq!(preview(&state).selected, selected);
            let text: String = terminal
                .backend()
                .buffer()
                .content()
                .iter()
                .map(ratatui::buffer::Cell::symbol)
                .collect();
            assert!(
                text.contains(&format!("> {name}")),
                "selected row missing at {width}x{height}: {text}"
            );
            for label in ["Before:", "After:", "Change:"] {
                assert!(text.contains(label), "{label} missing at {width}x{height}");
            }
        }
    }
    shell.shutdown().await.unwrap();
}
