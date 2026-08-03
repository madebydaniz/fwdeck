//! Operation outcomes: audit recording, result toasts, and the rollback
//! dead-man's switch (arm, fire).

use crate::application::api::RollbackRegistration;
use crate::application::ports::OperationOutcome;
use crate::ui::action::Effect;
use crate::ui::details;
use crate::ui::overlays::Overlay;
use crate::ui::state::{ToastKind, UiState};

pub(super) fn operation_finished(
    state: &mut UiState,
    op_id: u64,
    outcome: OperationOutcome,
    rollback: Option<RollbackRegistration>,
    guard_warning: Option<String>,
) -> Vec<Effect> {
    state.push_audit(crate::ui::state::AuditEntry {
        tick: state.tick,
        description: outcome.operation().describe(),
        target: outcome.operation().target().label(),
        status: match outcome {
            OperationOutcome::Applied { .. } => "applied",
            OperationOutcome::PartiallyApplied { .. } => "partial",
            OperationOutcome::Failed { .. } => "failed",
            OperationOutcome::Indeterminate { .. } => "unknown",
        },
        error: outcome.first_error().map(ToString::to_string),
    });
    let mut effects = Vec::new();
    if let Some(warning) = guard_warning {
        state.toast(ToastKind::Warning, warning);
    }
    match &outcome {
        OperationOutcome::Applied { operation, .. } => {
            state.toast(ToastKind::Success, operation.success_message());
            // Queue for postcondition verification — every applied op in a
            // plan is checked, not just the last.
            state.verify_next_refresh.push(operation.clone());
        }
        OperationOutcome::PartiallyApplied { .. } => {
            state.toast(
                ToastKind::Error,
                "PARTIAL FAILURE — runtime and permanent are out of sync",
            );
            state
                .overlays
                .push(Overlay::Details(details::for_outcome(&outcome)));
        }
        OperationOutcome::Indeterminate { .. } => {
            // A timeout is not a failure: the change may have landed after
            // the response was lost. Never auto-retry the forward mutation;
            // retain its pre-armed, idempotent connectivity rollback.
            state.toast(
                ToastKind::Warning,
                "OUTCOME UNKNOWN (timeout) — refreshing; verify before retrying",
            );
            state
                .overlays
                .push(Overlay::Details(details::for_outcome(&outcome)));
        }
        OperationOutcome::Failed { .. } => {
            let message = outcome
                .first_error()
                .map_or_else(|| "operation failed".to_owned(), ToString::to_string);
            state.toast(ToastKind::Error, message);
            state
                .overlays
                .push(Overlay::Details(details::for_outcome(&outcome)));
        }
    }
    if !matches!(outcome, OperationOutcome::Failed { .. })
        && let Some(rollback) = rollback
    {
        state
            .pending_rollback
            .push(crate::ui::state::PendingRollback {
                id: rollback.id,
                forward: outcome.operation().clone(),
                inverse: rollback.inverse,
                deadline_tick: state.tick + state.rollback_ticks,
                description: outcome.operation().describe(),
                watchdog_unit: rollback.watchdog_unit,
            });
    }
    // The durable JSONL write happens in the shell, not the reducer.
    effects.push(Effect::RecordAudit { op_id, outcome });
    effects
}

/// Fires **every** armed inverse now (newest first) and clears the pending
/// rollbacks — the explicit "undo now" path (`u`).
pub(super) fn fire_rollback(state: &mut UiState) -> Vec<Effect> {
    if state.pending_rollback.is_empty() {
        // `u` only reverts an active countdown. Say so, and point at the real
        // undo — otherwise it silently does nothing and reads as broken.
        state.toast(
            ToastKind::Info,
            "nothing to roll back — no countdown active; use the palette (:) \
             › Undo last operation",
        );
        return Vec::new();
    }
    let pending: Vec<_> = state.pending_rollback.drain(..).collect();
    fire_pending(state, pending)
}

/// Fires only the armed rollbacks whose own deadline has passed, retaining the
/// rest so each countdown honors its independent deadline (a newer, still-live
/// rollback is not cut short by an older one expiring).
pub(super) fn fire_expired_rollbacks(state: &mut UiState) -> Vec<Effect> {
    let now = state.tick;
    let (expired, live): (Vec<_>, Vec<_>) = state
        .pending_rollback
        .drain(..)
        .partition(|pending| now >= pending.deadline_tick);
    state.pending_rollback = live;
    fire_pending(state, expired)
}

/// Executes the given armed inverses newest first (unwinding in reverse order).
fn fire_pending(
    state: &mut UiState,
    pending: Vec<crate::ui::state::PendingRollback>,
) -> Vec<Effect> {
    let mut effects = Vec::new();
    for pending in pending.into_iter().rev() {
        state.toast(
            ToastKind::Warning,
            format!("rolling back: {}", pending.description),
        );
        effects.push(Effect::ApplyRollback {
            id: pending.id,
            operation: pending.inverse,
            watchdog_unit: pending.watchdog_unit,
        });
    }
    effects
}
