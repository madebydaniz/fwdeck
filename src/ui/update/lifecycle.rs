//! Operation outcomes: audit recording, result toasts, and the rollback
//! dead-man's switch (arm, fire).

use crate::application::ports::OperationOutcome;
use crate::domain::FirewallOperation;
use crate::ui::action::Effect;
use crate::ui::details;
use crate::ui::overlays::Overlay;
use crate::ui::state::{ToastKind, UiState};

pub(super) fn operation_finished(
    state: &mut UiState,
    op_id: u64,
    outcome: OperationOutcome,
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
    // The rollback is pre-armed before the apply (see `pre_arm_rollback`), so
    // this only reacts to the outcome — it never arms.
    let mut effects = Vec::new();
    match &outcome {
        OperationOutcome::Applied { operation, .. } => {
            state.toast(ToastKind::Success, operation.success_message());
            // Queue for postcondition verification — every applied op in a
            // plan is checked, not just the last.
            state.verify_next_refresh.push(operation.clone());
            // The change landed: the pre-armed countdown and watchdog stand.
        }
        OperationOutcome::PartiallyApplied { .. } => {
            state.toast(
                ToastKind::Error,
                "PARTIAL FAILURE — runtime and permanent are out of sync",
            );
            state
                .overlays
                .push(Overlay::Details(details::for_outcome(&outcome)));
            // Runtime changed → keep the rollback armed so the operator can revert.
        }
        OperationOutcome::Indeterminate { .. } => {
            // A timeout is not a failure: the change may have landed after
            // the response was lost. Never auto-retry, never auto-invert.
            state.toast(
                ToastKind::Warning,
                "OUTCOME UNKNOWN (timeout) — refreshing; verify before retrying",
            );
            state
                .overlays
                .push(Overlay::Details(details::for_outcome(&outcome)));
            // The change MAY have landed → keep the rollback armed, don't retract.
        }
        OperationOutcome::Failed { operation, .. } => {
            let message = outcome
                .first_error()
                .map_or_else(|| "operation failed".to_owned(), ToString::to_string);
            state.toast(ToastKind::Error, message);
            state
                .overlays
                .push(Overlay::Details(details::for_outcome(&outcome)));
            // A clean failure applied nothing, so a pre-armed watchdog would
            // fire an inverse against an unchanged firewall — retract it.
            effects.extend(retract_pending_rollback(state, operation));
        }
    }
    // The durable JSONL write happens in the shell, not the reducer.
    effects.push(Effect::RecordAudit { op_id, outcome });
    effects
}

/// Pre-arms the dead-man's switch for a risky, reversible operation **before**
/// it is applied. Arming first is the whole point: if the process is killed
/// mid-apply, the out-of-process watchdog still fires the inverse — and the
/// inverse restores the pre-apply state, which is exactly where we still are if
/// the apply never landed. The caller dispatches the returned effect (an
/// `ArmWatchdog`, if systemd is usable) ahead of `Effect::Apply`.
pub(super) fn pre_arm_rollback(state: &mut UiState, operation: &FirewallOperation) -> Vec<Effect> {
    if state.rollback_ticks == 0 {
        return Vec::new();
    }
    if operation.connectivity_warning().is_none() {
        return Vec::new();
    }
    let Some(inverse) = operation.inverse() else {
        return Vec::new();
    };
    // The out-of-process net fires with a grace margin after the in-process
    // deadline (which disarms it on the happy path first).
    let delay_secs = state.rollback_ticks / 4 + 15;
    let unit = format!("fwdeck-rollback-{}-{}", std::process::id(), state.tick);
    // The watchdog restores RUNTIME connectivity: a single command, and exactly
    // the scope that can lock you out. (The in-process `inverse` above also
    // reverts the permanent config; the watchdog deliberately does not.)
    let args = operation.inverse_runtime().and_then(|runtime_inverse| {
        crate::infrastructure::firewalld::command::plan(
            &runtime_inverse,
            crate::infrastructure::process::DEFAULT_TIMEOUT,
        )
        .into_iter()
        .next()
        .map(|planned| planned.request.args)
    });
    let effect = args.map(|args| Effect::ArmWatchdog {
        unit: unit.clone(),
        delay_secs,
        args,
    });
    state
        .pending_rollback
        .push(crate::ui::state::PendingRollback {
            forward: operation.clone(),
            inverse,
            deadline_tick: state.tick + state.rollback_ticks,
            description: operation.describe(),
            watchdog_unit: effect.is_some().then_some(unit),
        });
    effect.into_iter().collect()
}

/// Retracts a pre-armed rollback whose operation did not apply: drops the
/// pending entry and disarms its watchdog so no stale inverse can fire.
fn retract_pending_rollback(state: &mut UiState, operation: &FirewallOperation) -> Vec<Effect> {
    let mut effects = Vec::new();
    state.pending_rollback.retain(|pending| {
        if &pending.forward == operation {
            if let Some(unit) = &pending.watchdog_unit {
                effects.push(Effect::DisarmWatchdog { unit: unit.clone() });
            }
            false
        } else {
            true
        }
    });
    effects
}

/// Executes every armed inverse (newest first — unwinding in reverse order)
/// and clears the pending rollbacks.
pub(super) fn fire_rollback(state: &mut UiState) -> Vec<Effect> {
    if state.pending_rollback.is_empty() {
        return Vec::new();
    }
    let pending: Vec<_> = state.pending_rollback.drain(..).collect();
    let mut effects = Vec::new();
    for pending in pending.into_iter().rev() {
        state.toast(
            ToastKind::Warning,
            format!("rolling back: {}", pending.description),
        );
        // We are handling it in-process — the watchdog must not double-fire.
        if let Some(unit) = pending.watchdog_unit {
            effects.push(Effect::DisarmWatchdog { unit });
        }
        effects.push(Effect::Apply(pending.inverse));
    }
    effects
}
