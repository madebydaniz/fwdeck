//! Preview admission and captured-review ownership. No mutation effects.
use crate::application::TrafficPreviewRequest;
use crate::ui::{
    action::{Effect, UiAction},
    overlays::Overlay,
    state::{ToastKind, UiState},
    traffic_preview::{Preview, Publication},
};
use std::sync::Arc;

pub(super) fn open(state: &mut UiState, staged: bool) -> Vec<Effect> {
    if state
        .overlays
        .iter()
        .any(|o| matches!(o, Overlay::TrafficPreview(_)))
    {
        return Vec::new();
    }
    let (operations, expected, plan_id, parent) = if staged {
        if let crate::ui::palette::Availability::Disabled(reason) =
            crate::ui::traffic_preview::staged_availability(state)
        {
            state.toast(ToastKind::Warning, reason);
            return Vec::new();
        }
        let Some(snapshot) = state.snapshot.clone() else {
            return Vec::new();
        };
        let (ops, _, rejected) = super::plans::prepare(&state.staged, &snapshot);
        if !rejected.is_empty() || ops.is_empty() {
            state.toast(
                ToastKind::Warning,
                if ops.is_empty() && rejected.is_empty() {
                    "Preview unavailable: plan already satisfied".into()
                } else {
                    format!("Preview unavailable: {}", rejected.join("; "))
                },
            );
            return Vec::new();
        }
        let Some(id) = state.allocate_plan_id() else {
            return Vec::new();
        };
        (ops, snapshot, Some(id), None)
    } else {
        let Some(Overlay::Confirm(c)) = state.overlays.last() else {
            return Vec::new();
        };
        match &c.on_confirm {
            UiAction::ApplyOperation(r) => (
                vec![r.operation.clone()],
                r.expected.clone(),
                None,
                Some(c.clone()),
            ),
            UiAction::ApplyPlanConfirmed(p) => (
                p.operations.clone(),
                p.expected.clone(),
                Some(p.id),
                Some(c.clone()),
            ),
            _ => return Vec::new(),
        }
    };
    let Some(observation) = state
        .traffic_observation
        .as_ref()
        .filter(|o| Arc::ptr_eq(o.snapshot_arc(), &expected))
        .cloned()
    else {
        state.toast(
            ToastKind::Warning,
            "Preview unavailable: reviewed observation is stale; reopen the review",
        );
        return Vec::new();
    };
    let request = Arc::new(TrafficPreviewRequest {
        operations,
        observation,
        plan_id,
    });
    state
        .overlays
        .push(Overlay::TrafficPreview(Box::new(Preview {
            request: request.clone(),
            parent,
            staged: staged.then(|| state.staged.clone()),
            publication: Publication::default(),
            selected: 0,
            selection_changed: false,
            invalidated: false,
        })));
    state.overlay_scroll = 0;
    vec![Effect::TrafficPreview(request)]
}

pub(super) fn reconcile(state: &mut UiState) {
    for overlay in &mut state.overlays {
        if let Overlay::TrafficPreview(preview) = overlay
            && state
                .traffic
                .preview
                .owner
                .as_ref()
                .is_some_and(|o| Arc::ptr_eq(o, &preview.request))
            && !preview.invalidated
        {
            preview.publication = (*state.traffic.preview).clone();
        }
    }
}

pub(super) fn owner(state: &UiState) -> Option<Arc<TrafficPreviewRequest>> {
    state.overlays.iter().find_map(|o| {
        if let Overlay::TrafficPreview(p) = o {
            Some(p.request.clone())
        } else {
            None
        }
    })
}

pub(super) fn invalidate_changed(state: &mut UiState) -> bool {
    let Some(index) = state
        .overlays
        .iter()
        .position(|o| matches!(o, Overlay::TrafficPreview(_)))
    else {
        return false;
    };
    let Overlay::TrafficPreview(p) = &state.overlays[index] else {
        return false;
    };
    let changed = !p.invalidated
        && (state.traffic_observation.as_ref().is_none_or(|o| {
            o.identity() != p.request.observation.identity()
                || !Arc::ptr_eq(o.snapshot_arc(), p.request.observation.snapshot_arc())
        }) || p.staged.as_ref().is_some_and(|s| s != &state.staged)
            || p.parent.as_ref().is_some_and(|parent| {
                index == 0
                    || !matches!(&state.overlays[index - 1], Overlay::Confirm(c) if c == parent)
            }));
    if changed && let Overlay::TrafficPreview(p) = &mut state.overlays[index] {
        p.invalidated = true;
    }
    let invalid = matches!(&state.overlays[index], Overlay::TrafficPreview(p) if p.invalidated || matches!(p.publication.state, crate::application::TrafficPreviewState::Stale(_)));
    if invalid {
        for overlay in &mut state.overlays[index + 1..] {
            if let Overlay::TrafficPreviewDetails(details) = overlay
                && let Some((_, status)) = details.lines.first_mut()
            {
                *status = "Stale — captured evidence retained; current preview invalidated".into();
            }
        }
    }
    changed
}

pub(super) fn move_selection(state: &mut UiState, delta: i32) {
    if let Some(Overlay::TrafficPreview(p)) = state.overlays.last_mut() {
        p.selection_changed = true;
        p.selected = p
            .selected
            .saturating_add_signed(delta as isize)
            .min(p.row_count().saturating_sub(1));
    }
}
pub(super) fn details(state: &mut UiState) {
    if let Some(Overlay::TrafficPreview(p)) = state.overlays.last()
        && let Some(details) = p.details()
    {
        state.overlays.push(Overlay::TrafficPreviewDetails(details));
        state.overlay_scroll = 0;
    }
}
