use super::*;
use crate::{
    application::SuiteState,
    config::Config,
    domain::*,
    ui::{
        overlays::Overlay,
        traffic_test_form::{Draft, EditAction as A, Editor, Stage, Template},
        views::ViewId,
    },
};
use std::sync::Arc;

fn state() -> UiState {
    let mut state = UiState::new(&Config::default(), "test".into(), false, None);
    state.view = ViewId::TrafficTests;
    state.traffic.suite = SuiteState::Missing;
    state
}
fn act(state: &mut UiState, action: A) -> Vec<Effect> {
    crate::ui::update::update(state, UiAction::TrafficEdit(action))
}
fn editor(state: &UiState) -> &Editor {
    let Some(Overlay::TrafficForm(editor)) = state.overlays.last() else {
        panic!("traffic editor must remain open")
    };
    editor
}
fn editor_mut(state: &mut UiState) -> &mut Editor {
    let Some(Overlay::TrafficForm(editor)) = state.overlays.last_mut() else {
        panic!("traffic editor must remain open")
    };
    editor
}
fn valid_editor(state: &mut UiState) {
    act(state, A::New(Template::Ssh));
    editor_mut(state).draft.source = "203.0.113.8".into();
}
fn loaded() -> UiState {
    let mut state = state();
    let mut draft = Draft::template(Template::Ssh);
    draft.source = "203.0.113.8".into();
    state.traffic.suite = SuiteState::Available(Arc::new(TrafficSuite {
        id: TrafficSuiteId::parse("default").unwrap(),
        name: "Default traffic tests".into(),
        revision: TrafficSuiteRevision::new(1).unwrap(),
        scenarios: vec![
            draft
                .scenario(TrafficScenarioId::parse("scenario-1").unwrap())
                .unwrap(),
        ],
    }));
    state
}

#[test]
fn traffic_edit_new_invalid_review_cancel_and_explicit_save() {
    let mut state = state();
    state.read_only = true;
    assert!(act(&mut state, A::New(Template::Ssh)).is_empty());
    assert_eq!(editor(&state).draft.name, "Keep SSH access");
    assert!(act(&mut state, A::Save).is_empty());
    assert!(act(&mut state, A::Review).is_empty());
    assert!(editor(&state).error.is_some());
    editor_mut(&mut state).draft.source = "203.0.113.8".into();
    assert!(act(&mut state, A::Review).is_empty());
    assert_eq!(editor(&state).stage, Stage::Review);
    act(&mut state, A::Cancel);
    assert_eq!(editor(&state).stage, Stage::Draft);
    act(&mut state, A::Review);
    let effects = act(&mut state, A::Save);
    assert!(
        matches!(effects.as_slice(), [Effect::TrafficSave(candidate)] if candidate.id.as_str() == "default" && candidate.revision.get() == 1)
    );
    assert_eq!(editor(&state).stage, Stage::Pending);
    let retained = editor(&state).clone();
    for action in [A::Input('x'), A::New(Template::Custom), A::Save, A::Cancel] {
        assert!(act(&mut state, action).is_empty());
    }
    assert_eq!(editor(&state), &retained);
}

#[test]
fn traffic_edit_discard_guards_close_quit_switch_reload_and_control_keys() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    for action in [
        UiAction::CloseOverlay,
        UiAction::Quit,
        UiAction::SwitchView(ViewId::Zones),
        UiAction::TrafficReload,
        UiAction::ReloadRequested,
        UiAction::OpenGlobalSearch,
    ] {
        let mut state = state();
        valid_editor(&mut state);
        let draft = editor(&state).draft.clone();
        assert!(crate::ui::update::update(&mut state, action).is_empty());
        assert!(editor(&state).discard.is_some());
        act(&mut state, A::Keep);
        assert_eq!(editor(&state).draft, draft);
    }
    for key in ['r', 'f'] {
        let mut state = state();
        valid_editor(&mut state);
        let action = crate::ui::keymap::translate(
            &state,
            KeyEvent::new(KeyCode::Char(key), KeyModifiers::CONTROL),
        )
        .unwrap();
        assert!(crate::ui::update::update(&mut state, action).is_empty());
        assert!(editor(&state).discard.is_some());
    }
    let mut state = state();
    valid_editor(&mut state);
    crate::ui::update::update(&mut state, UiAction::TrafficReload);
    assert_eq!(act(&mut state, A::Discard), vec![Effect::TrafficLoad]);
    assert!(state.overlays.is_empty());
    valid_editor(&mut state);
    assert_eq!(
        crate::ui::update::update(&mut state, UiAction::QuitConfirmed),
        vec![Effect::Quit]
    );
}

#[test]
fn traffic_edit_delete_and_toggle_require_review_and_preserve_order() {
    for action in [A::Delete, A::Toggle] {
        let mut state = loaded();
        let SuiteState::Available(base) = state.traffic.suite.clone() else {
            unreachable!()
        };
        assert!(act(&mut state, action.clone()).is_empty());
        assert_eq!(editor(&state).stage, Stage::Review);
        let effects = act(&mut state, A::Save);
        let [Effect::TrafficSave(candidate)] = effects.as_slice() else {
            panic!("only local save allowed")
        };
        assert_eq!(candidate.revision, base.revision);
        if action == A::Delete {
            assert!(candidate.scenarios.is_empty());
        } else {
            assert!(!candidate.scenarios[0].enabled);
            assert_eq!(candidate.scenarios[0].id, base.scenarios[0].id);
        }
    }
}

#[test]
fn traffic_edit_load_states_block_forms_and_global_actions_cannot_bypass_modal() {
    for suite in [
        SuiteState::NotLoaded,
        SuiteState::UnsupportedSchema(99),
        SuiteState::Failed(crate::application::SuiteLoadFailure::InvalidSuite),
    ] {
        let mut state = state();
        state.traffic.suite = suite;
        assert!(act(&mut state, A::New(Template::Custom)).is_empty());
        assert!(state.overlays.is_empty());
        assert!(state.traffic.error.is_some());
    }
    let mut state = state();
    valid_editor(&mut state);
    let before = editor(&state).clone();
    for action in [
        UiAction::OpenPalette,
        UiAction::ConfirmStage,
        UiAction::AddEntry,
        UiAction::DeleteEntry,
        UiAction::TrafficEvaluate,
    ] {
        assert!(crate::ui::update::update(&mut state, action).is_empty());
        assert_eq!(editor(&state), &before);
    }
}

#[test]
fn traffic_edit_keyboard_and_palette_expose_local_reviewed_actions() {
    use crossterm::event::{KeyCode as K, KeyEvent};
    let mut state = loaded();
    for (key, action) in [
        (K::Char('a'), A::New(Template::Custom)),
        (K::Char('E'), A::Edit),
        (K::Char('d'), A::Delete),
        (K::Char(' '), A::Toggle),
    ] {
        assert_eq!(
            crate::ui::keymap::translate(&state, KeyEvent::from(key)),
            Some(UiAction::TrafficEdit(action))
        );
    }
    let commands = crate::ui::palette::catalog(&state);
    for template in [
        Template::Ssh,
        Template::AllowService,
        Template::BlockAccess,
        Template::Custom,
    ] {
        assert!(commands.iter().any(|command| command.action
            == UiAction::TrafficEdit(A::New(template))
            && command.availability == crate::ui::palette::Availability::Enabled));
    }
    valid_editor(&mut state);
    for (key, action) in [
        (K::Tab, A::Move(1)),
        (K::BackTab, A::Move(-1)),
        (K::Right, A::Cycle(1)),
        (K::Enter, A::Review),
        (K::Char('y'), A::Input('y')),
    ] {
        assert_eq!(
            crate::ui::keymap::translate(&state, KeyEvent::from(key)),
            Some(UiAction::TrafficEdit(action))
        );
    }
    act(&mut state, A::Review);
    assert_eq!(
        crate::ui::keymap::translate(&state, KeyEvent::from(K::Char('y'))),
        Some(UiAction::TrafficEdit(A::Save))
    );
    assert_eq!(
        crate::ui::keymap::translate(&state, KeyEvent::from(K::End)),
        Some(UiAction::TrafficEdit(A::Scroll(i32::MAX)))
    );
}

#[test]
fn traffic_edit_save_completion_matches_exact_candidate_and_failed_draft_needs_reload() {
    use crate::application::{TrafficSaveState as S, TrafficStorageError};
    let mut state = state();
    valid_editor(&mut state);
    act(&mut state, A::Review);
    act(&mut state, A::Save);
    let candidate = editor(&state).candidate.clone().unwrap();
    let mut presentation = state.traffic.clone();
    presentation.save = S::Saved(Arc::clone(&candidate));
    crate::ui::update::update(&mut state, UiAction::TrafficPresented(presentation.clone()));
    assert_eq!(
        editor(&state).stage,
        Stage::Pending,
        "unaccepted saved publication cannot close editor"
    );
    presentation.save = S::Saving(Arc::clone(&candidate));
    crate::ui::update::update(&mut state, UiAction::TrafficPresented(presentation.clone()));
    assert!(
        editor(&state).accepted,
        "matching accepted candidate must be correlated"
    );
    presentation.save = S::Failed {
        draft: Arc::clone(&candidate),
        error: TrafficStorageError::Conflict,
    };
    editor_mut(&mut state).scroll = 100;
    crate::ui::update::update(&mut state, UiAction::TrafficPresented(presentation));
    assert_eq!(editor(&state).stage, Stage::Failed);
    assert_eq!(
        editor(&state).scroll,
        0,
        "failed save must expose its error at the top"
    );
    assert!(Arc::ptr_eq(
        editor(&state).candidate.as_ref().unwrap(),
        &candidate
    ));
    assert!(editor(&state).error.as_deref().unwrap().contains("reload"));
    for action in [A::Save, A::Review, A::Input('x')] {
        assert!(act(&mut state, action).is_empty());
    }
    crate::ui::update::update(&mut state, UiAction::TrafficReload);
    assert!(editor(&state).discard.is_some());
    act(&mut state, A::Keep);
    assert_eq!(editor(&state).stage, Stage::Failed);
}

#[test]
fn traffic_edit_matching_success_closes_only_pending_editor() {
    use crate::application::TrafficSaveState as S;
    let mut state = loaded();
    act(&mut state, A::Edit);
    act(&mut state, A::Input('!'));
    act(&mut state, A::Review);
    act(&mut state, A::Save);
    let candidate = editor(&state).candidate.clone().unwrap();
    let mut presentation = state.traffic.clone();
    presentation.save = S::Saving(Arc::clone(&candidate));
    crate::ui::update::update(&mut state, UiAction::TrafficPresented(presentation.clone()));
    let mut unrelated = (*candidate).clone();
    unrelated.name = "Unrelated".into();
    presentation.save = S::Saved(Arc::new(unrelated));
    crate::ui::update::update(&mut state, UiAction::TrafficPresented(presentation.clone()));
    assert_eq!(editor(&state).stage, Stage::Pending);
    let mut persisted = (*candidate).clone();
    persisted.revision = TrafficSuiteRevision::new(2).unwrap();
    presentation.save = S::Saved(Arc::new(persisted));
    crate::ui::update::update(&mut state, UiAction::TrafficPresented(presentation));
    assert!(
        state.overlays.is_empty(),
        "matching persisted save must close the editor"
    );
}

#[test]
fn traffic_edit_failed_save_cannot_be_reopened_without_reload() {
    use crate::application::{TrafficSaveState, TrafficStorageError};
    let mut state = loaded();
    let SuiteState::Available(base) = state.traffic.suite.clone() else {
        unreachable!()
    };
    state.traffic.save = TrafficSaveState::Failed {
        draft: base,
        error: TrafficStorageError::Conflict,
    };
    assert!(act(&mut state, A::New(Template::Ssh)).is_empty());
    assert!(
        state.overlays.is_empty(),
        "failed authority must block new editors until reload"
    );
}

#[test]
fn traffic_edit_missing_suite_has_actionable_create_hint() {
    let state = state();
    assert!(
        state.traffic.message().contains("a new"),
        "missing suite must advertise unsaved creation"
    );
}

#[test]
fn traffic_edit_validation_failure_returns_focus_to_visible_error() {
    let mut state = state();
    valid_editor(&mut state);
    editor_mut(&mut state).draft.source = "invalid".into();
    editor_mut(&mut state).draft.focus = editor(&state).draft.fields().len() - 1;
    act(&mut state, A::Review);
    assert_eq!(
        editor(&state).draft.focus,
        0,
        "validation error must not be hidden above the focused note"
    );
}

#[test]
fn traffic_edit_creation_completion_uses_original_save_context_not_unrelated_suite() {
    use crate::application::TrafficSaveState as S;
    let mut state = state();
    valid_editor(&mut state);
    act(&mut state, A::Review);
    act(&mut state, A::Save);
    let candidate = editor(&state).candidate.clone().unwrap();
    let mut presentation = state.traffic.clone();
    presentation.save = S::Saving(Arc::clone(&candidate));
    crate::ui::update::update(&mut state, UiAction::TrafficPresented(presentation.clone()));
    presentation.suite = SuiteState::Available(Arc::clone(&candidate));
    crate::ui::update::update(&mut state, UiAction::TrafficPresented(presentation.clone()));
    assert_eq!(editor(&state).stage, Stage::Pending);
    presentation.save = S::Saved(candidate);
    crate::ui::update::update(&mut state, UiAction::TrafficPresented(presentation));
    assert!(
        state.overlays.is_empty(),
        "matching creation completion must use captured save context"
    );
}

fn retained(state: &UiState) -> &Editor {
    state
        .overlays
        .iter()
        .find_map(|overlay| match overlay {
            Overlay::TrafficForm(editor) => Some(editor.as_ref()),
            _ => None,
        })
        .unwrap()
}

fn cover_with_operation_result(state: &mut UiState, kind: usize) -> Overlay {
    use crate::application::{
        api::OperationResult,
        ports::{OperationOutcome, RollbackGuardId},
    };
    let operation = FirewallOperation::Reload;
    let outcome = match kind {
        0 => OperationOutcome::Failed {
            operation,
            steps: Vec::new(),
        },
        1 => OperationOutcome::PartiallyApplied {
            operation,
            steps: Vec::new(),
            rollback_hint: None,
        },
        _ => OperationOutcome::Indeterminate {
            operation,
            steps: Vec::new(),
        },
    };
    let effects = crate::ui::update::update(
        state,
        UiAction::OperationFinished(Box::new(OperationResult {
            op_id: 99,
            outcome,
            rollback: None,
            guard_warning: None,
            completed_rollback: Some(RollbackGuardId::new(99)),
        })),
    );
    assert!(matches!(
        effects.as_slice(),
        [Effect::RecordAudit { op_id: 99, .. }]
    ));
    assert_eq!(state.overlays.len(), 2);
    let details = state.overlays.last().unwrap().clone();
    assert!(matches!(details, Overlay::Details(_)));
    details
}

fn conflicting_actions(state: &UiState) -> Vec<UiAction> {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    let mut actions = vec![
        UiAction::Quit,
        UiAction::SwitchView(ViewId::Zones),
        UiAction::TrafficReload,
    ];
    for key in ['r', 'f'] {
        actions.push(
            crate::ui::keymap::translate(
                state,
                KeyEvent::new(KeyCode::Char(key), KeyModifiers::CONTROL),
            )
            .unwrap(),
        );
    }
    actions
}

#[test]
fn traffic_edit_covered_dirty_draft_guards_real_background_outcomes() {
    for kind in 0..3 {
        let mut state = state();
        valid_editor(&mut state);
        let draft = editor(&state).draft.clone();
        let details = cover_with_operation_result(&mut state, kind);
        for action in conflicting_actions(&state) {
            assert!(
                crate::ui::update::update(&mut state, action).is_empty(),
                "covered dirty editor allowed conflicting effect"
            );
            assert!(
                retained(&state).discard.is_some(),
                "covered dirty editor must request explicit discard"
            );
            assert_eq!(retained(&state).draft, draft);
            assert_eq!(state.overlays.last(), Some(&details));
            act(&mut state, A::Keep);
            assert!(retained(&state).discard.is_none());
        }
        assert!(crate::ui::update::update(&mut state, UiAction::CloseOverlay).is_empty());
        assert_eq!(editor(&state).draft, draft);
    }
}

#[test]
fn traffic_edit_covered_pending_blocks_conflicts_but_allows_details_and_emergency_exit() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    for kind in 0..3 {
        let mut state = state();
        valid_editor(&mut state);
        act(&mut state, A::Review);
        act(&mut state, A::Save);
        let pending = editor(&state).clone();
        let details = cover_with_operation_result(&mut state, kind);
        for action in conflicting_actions(&state) {
            assert!(
                crate::ui::update::update(&mut state, action).is_empty(),
                "covered pending editor allowed conflicting effect"
            );
            assert_eq!(retained(&state), &pending);
            assert_eq!(state.overlays.last(), Some(&details));
        }
        crate::ui::update::update(&mut state, UiAction::ScrollOverlay(1));
        assert_eq!(state.overlay_scroll, 1);
        let emergency = crate::ui::keymap::translate(
            &state,
            KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
        )
        .unwrap();
        assert_eq!(
            crate::ui::update::update(&mut state, emergency),
            vec![Effect::Quit]
        );
        crate::ui::update::update(&mut state, UiAction::CloseOverlay);
        assert_eq!(editor(&state), &pending);
    }
}

#[test]
fn traffic_edit_covered_save_completion_removes_only_owner_or_retains_exact_failure() {
    use crate::application::{TrafficSaveState as S, TrafficStorageError};
    for kind in 0..3 {
        for fail in [false, true] {
            let mut state = state();
            valid_editor(&mut state);
            act(&mut state, A::Review);
            act(&mut state, A::Save);
            let pending = editor(&state).clone();
            let candidate = pending.candidate.clone().unwrap();
            let details = cover_with_operation_result(&mut state, kind);
            let mut presentation = state.traffic.clone();
            presentation.save = S::Saving(Arc::clone(&candidate));
            crate::ui::update::update(&mut state, UiAction::TrafficPresented(presentation.clone()));
            assert!(
                retained(&state).accepted,
                "covered Saving must reach its owner"
            );
            let mut unrelated = (*candidate).clone();
            unrelated.name = "unrelated".into();
            presentation.save = S::Saved(Arc::new(unrelated));
            crate::ui::update::update(&mut state, UiAction::TrafficPresented(presentation.clone()));
            assert_eq!(retained(&state).stage, Stage::Pending);
            presentation.save = if fail {
                S::Failed {
                    draft: Arc::clone(&candidate),
                    error: TrafficStorageError::Conflict,
                }
            } else {
                S::Saved(candidate.clone())
            };
            crate::ui::update::update(&mut state, UiAction::TrafficPresented(presentation));
            assert_eq!(
                state.overlays.last(),
                Some(&details),
                "completion must preserve unrelated Details"
            );
            if fail {
                let editor = retained(&state);
                assert_eq!(
                    editor.stage,
                    Stage::Failed,
                    "covered failed save remained pending"
                );
                assert_eq!(editor.draft, pending.draft);
                assert!(Arc::ptr_eq(editor.candidate.as_ref().unwrap(), &candidate));
                assert!(editor.error.as_deref().unwrap().contains("reload"));
            } else {
                assert_eq!(
                    state.overlays,
                    vec![details],
                    "success must remove only the matching covered editor"
                );
            }
            crate::ui::update::update(&mut state, UiAction::CloseOverlay);
            assert!(state.overlays.iter().all(|overlay| !matches!(overlay, Overlay::TrafficForm(editor) if editor.stage == Stage::Pending)), "Details dismissal exposed permanently Pending editor");
        }
    }
}

#[test]
fn traffic_edit_covered_rejection_and_discard_target_only_editor() {
    let mut state = state();
    valid_editor(&mut state);
    act(&mut state, A::Review);
    act(&mut state, A::Save);
    let pending = editor(&state).clone();
    let candidate = pending.candidate.clone().unwrap();
    let details = cover_with_operation_result(&mut state, 0);
    crate::ui::update::update(
        &mut state,
        UiAction::TrafficSaveRejected(candidate.clone(), "service busy".into()),
    );
    assert_eq!(
        retained(&state).stage,
        Stage::Failed,
        "covered rejection must reach exact pending editor"
    );
    assert_eq!(retained(&state).draft, pending.draft);
    assert!(Arc::ptr_eq(
        retained(&state).candidate.as_ref().unwrap(),
        &candidate
    ));
    assert!(
        retained(&state)
            .error
            .as_deref()
            .unwrap()
            .contains("service busy")
    );
    assert!(crate::ui::update::update(&mut state, UiAction::TrafficReload).is_empty());
    assert!(retained(&state).discard.is_some());
    assert_eq!(act(&mut state, A::Discard), vec![Effect::TrafficLoad]);
    assert_eq!(
        state.overlays,
        vec![details],
        "discard must not remove unrelated Details"
    );
}

#[test]
fn traffic_edit_covered_editor_does_not_interrupt_existing_rollback_tick() {
    use crate::{application::ports::RollbackGuardId, ui::state::PendingRollback};
    let mut state = state();
    valid_editor(&mut state);
    act(&mut state, A::Review);
    act(&mut state, A::Save);
    let pending = editor(&state).clone();
    let details = cover_with_operation_result(&mut state, 2);
    let id = RollbackGuardId::new(100);
    state.pending_rollback.push(PendingRollback {
        id,
        forward: FirewallOperation::Reload,
        inverse: FirewallOperation::Reload,
        deadline_tick: state.tick + 1,
        description: "Existing rollback".into(),
        watchdog_unit: None,
    });
    let effects = crate::ui::update::update(&mut state, UiAction::Tick);
    assert!(
        effects.iter().any(
            |effect| matches!(effect, Effect::ApplyRollback { id: actual, .. } if *actual == id)
        )
    );
    assert!(state.pending_rollback.is_empty());
    assert_eq!(retained(&state), &pending);
    assert_eq!(state.overlays.last(), Some(&details));
}
