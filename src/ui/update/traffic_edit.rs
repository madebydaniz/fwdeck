//! Local reviewed edit lifecycle; no filesystem and no firewall operations.

use crate::ui::{
    action::{Effect, UiAction},
    state::UiState,
};
use crate::{
    application::SuiteState,
    domain::{TrafficSuite, TrafficSuiteId, TrafficSuiteRevision},
    ui::{
        overlays::Overlay,
        traffic_test_form::{self, Draft, EditAction as A, EditKind, Editor, Stage},
        views::{RowId, ViewId},
    },
};
use std::sync::Arc;

pub(super) fn guard(state: &mut UiState, action: &UiAction) -> Option<Vec<Effect>> {
    let Some(Overlay::TrafficForm(editor)) = state.overlays.last_mut() else {
        return None;
    };
    if matches!(
        action,
        UiAction::QuitConfirmed
            | UiAction::Tick
            | UiAction::Resize(_, _)
            | UiAction::TrafficPresented(_)
            | UiAction::TrafficSaveRejected(_, _)
            | UiAction::RefreshStarted { .. }
            | UiAction::RefreshOverviewReady { .. }
            | UiAction::RefreshCompleted { .. }
            | UiAction::RefreshCancelled { .. }
            | UiAction::EngineOutboxChanged { .. }
            | UiAction::EngineStopped(_)
            | UiAction::ManualDemandRejected { .. }
            | UiAction::LogsReceived(_)
            | UiAction::OperationFinished(_)
            | UiAction::PlanFinished { .. }
    ) {
        return None;
    }
    if editor.stage == Stage::Pending {
        return Some(Vec::new());
    }
    if matches!(action, UiAction::TrafficEdit(_)) {
        return None;
    }
    if matches!(
        action,
        UiAction::CloseOverlay
            | UiAction::Quit
            | UiAction::SwitchView(_)
            | UiAction::TrafficReload
            | UiAction::ReloadRequested
            | UiAction::OpenGlobalSearch
    ) {
        if *action == UiAction::CloseOverlay
            && editor.stage == Stage::Review
            && editor.kind == EditKind::Form
        {
            editor.stage = Stage::Draft;
            editor.scroll = 0;
        } else if editor.dirty || editor.stage == Stage::Failed {
            editor.discard = Some(Box::new(action.clone()));
        } else {
            state.overlays.pop();
            if *action != UiAction::CloseOverlay {
                return Some(super::update(state, action.clone()));
            }
        }
    }
    Some(Vec::new())
}

pub(super) fn update(state: &mut UiState, action: UiAction) -> Vec<Effect> {
    if let UiAction::TrafficSaveRejected(candidate, error) = &action {
        reject(state, candidate, error);
        return Vec::new();
    }
    let UiAction::TrafficEdit(action) = action else {
        return Vec::new();
    };
    if matches!(action, A::New(_) | A::Edit | A::Delete | A::Toggle) {
        if !state.overlays.is_empty() || state.view != ViewId::TrafficTests {
            return Vec::new();
        }
        match open(state, &action) {
            Ok(editor) => state.overlays.push(Overlay::TrafficForm(Box::new(editor))),
            Err(error) => state.traffic.error = Some(error),
        }
        return Vec::new();
    }
    let Some(Overlay::TrafficForm(editor)) = state.overlays.last_mut() else {
        return Vec::new();
    };
    if editor.discard.is_some() {
        match action {
            A::Keep | A::Cancel => editor.discard = None,
            A::Discard => {
                let next = editor.discard.take();
                state.overlays.pop();
                if let Some(next) = next
                    && *next != UiAction::CloseOverlay
                {
                    return super::update(state, *next);
                }
            }
            _ => {}
        }
        return Vec::new();
    }
    match action {
        A::Cancel => {
            return super::update(state, UiAction::CloseOverlay);
        }
        A::Review if editor.stage == Stage::Draft => {
            match traffic_test_form::prepare(&editor.base, &editor.draft) {
                Ok(candidate) => {
                    editor.candidate = Some(Arc::new(candidate));
                    editor.stage = Stage::Review;
                    editor.scroll = 0;
                    editor.error = None;
                }
                Err(error) => {
                    editor.error = Some(error);
                    editor.draft.focus = 0;
                }
            }
        }
        A::Save if editor.stage == Stage::Review => {
            if let Some(candidate) = &editor.candidate {
                editor.stage = Stage::Pending;
                editor.accepted = false;
                editor.dirty = true;
                return vec![Effect::TrafficSave(Arc::clone(candidate))];
            }
        }
        A::Move(delta) if editor.stage == Stage::Draft => {
            let count = editor.draft.fields().len();
            editor.draft.focus = if delta < 0 {
                (editor.draft.focus + count - 1) % count
            } else {
                (editor.draft.focus + 1) % count
            };
        }
        A::Cycle(delta) if editor.stage == Stage::Draft => {
            editor.draft.cycle(delta);
            editor.dirty = true;
        }
        A::Input(character) if editor.stage == Stage::Draft => {
            editor.draft.input(character);
            editor.dirty = true;
        }
        A::Backspace if editor.stage == Stage::Draft => {
            editor.draft.backspace();
            editor.dirty = true;
        }
        A::Scroll(delta) if editor.stage != Stage::Draft => {
            editor.scroll = u16::try_from(i32::from(editor.scroll).saturating_add(delta).max(0))
                .unwrap_or(u16::MAX);
        }
        _ => {}
    }
    Vec::new()
}

fn reject(state: &mut UiState, candidate: &Arc<TrafficSuite>, error: &str) {
    state.traffic.error = Some(error.to_owned());
    if let Some(Overlay::TrafficForm(editor)) = state.overlays.last_mut()
        && editor.stage == Stage::Pending
        && editor
            .candidate
            .as_ref()
            .is_some_and(|pending| Arc::ptr_eq(pending, candidate))
    {
        editor.error = Some(format!(
            "{error}. Discard the retained draft and reload the default suite before another save."
        ));
        if !editor.accepted {
            editor.stage = Stage::Failed;
            editor.scroll = 0;
        }
    }
}

fn open(state: &UiState, action: &A) -> Result<Editor, String> {
    if matches!(
        state.traffic.save,
        crate::application::TrafficSaveState::Failed { .. }
    ) {
        return Err("Previous save failed; reload the default suite (r) before editing".into());
    }
    let base = match &state.traffic.suite {
        SuiteState::Available(suite) => Arc::clone(suite),
        SuiteState::Missing => Arc::new(TrafficSuite {
            id: TrafficSuiteId::parse("default").map_err(|error| error.to_string())?,
            name: "Default traffic tests".into(),
            revision: TrafficSuiteRevision::new(1).map_err(|error| error.to_string())?,
            scenarios: Vec::new(),
        }),
        _ => {
            return Err(format!(
                "{} Load/reload the default suite (r) before editing.",
                state.traffic.message()
            ));
        }
    };
    let (draft, kind, dirty) = if let A::New(template) = action {
        if base.scenarios.len() >= crate::domain::MAX_SCENARIOS_PER_SUITE {
            return Err("Suite already contains 1000 scenarios".into());
        }
        (Draft::template(*template), EditKind::Form, true)
    } else {
        let Some(RowId::TrafficScenario(id)) = super::selected_row_id(state) else {
            return Err("Select a scenario first".into());
        };
        let scenario = base
            .scenarios
            .iter()
            .find(|scenario| scenario.id == id)
            .ok_or("Select a scenario first")?;
        let mut draft = Draft::edit(scenario);
        let kind = match action {
            A::Delete => EditKind::Delete,
            A::Toggle => {
                draft.enabled = !draft.enabled;
                EditKind::Toggle
            }
            _ => EditKind::Form,
        };
        (draft, kind, kind != EditKind::Form)
    };
    let candidate = match kind {
        EditKind::Form => None,
        EditKind::Toggle => Some(Arc::new(traffic_test_form::prepare(&base, &draft)?)),
        EditKind::Delete => {
            let mut candidate = (*base).clone();
            if let Some(original) = &draft.original {
                candidate
                    .scenarios
                    .retain(|scenario| scenario.id != original.id);
            }
            Some(Arc::new(candidate))
        }
    };
    Ok(Editor {
        creating_suite: matches!(state.traffic.suite, SuiteState::Missing),
        base,
        draft,
        stage: if kind == EditKind::Form {
            Stage::Draft
        } else {
            Stage::Review
        },
        kind,
        candidate,
        dirty,
        accepted: false,
        error: None,
        discard: None,
        scroll: 0,
    })
}

pub(super) fn reconcile(
    state: &mut UiState,
    presentation: &crate::ui::traffic_tests::TrafficPresentation,
) {
    use crate::application::TrafficSaveState as S;
    let Some(Overlay::TrafficForm(editor)) = state.overlays.last_mut() else {
        return;
    };
    if editor.stage != Stage::Pending {
        return;
    }
    let Some(candidate) = &editor.candidate else {
        return;
    };
    match &presentation.save {
        S::Saving(draft) if Arc::ptr_eq(draft, candidate) => editor.accepted = true,
        S::Failed { draft, error } if Arc::ptr_eq(draft, candidate) => {
            editor.stage = Stage::Failed;
            editor.scroll = 0;
            editor.error = Some(format!(
                "{error}. Save authority revoked; discard this retained draft and reload the default suite before another save."
            ));
        }
        S::Saved(saved) if editor.accepted => {
            let mut expected = (**candidate).clone();
            let revision = if editor.creating_suite {
                Some(1)
            } else {
                candidate.revision.get().checked_add(1)
            };
            if let Some(revision) =
                revision.and_then(|revision| TrafficSuiteRevision::new(revision).ok())
            {
                expected.revision = revision;
                if **saved == expected {
                    state.overlays.pop();
                }
            }
        }
        _ => {}
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests;
