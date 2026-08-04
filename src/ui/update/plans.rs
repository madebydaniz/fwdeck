//! Staged-plan lifecycle: apply, drift sync, snapshot restore, and export.

use crate::application::MutationPlan;
use crate::domain::{ConfigurationTarget, FirewallOperation};
use crate::ui::action::{Effect, UiAction};
use crate::ui::overlays::{Confirmation, Overlay};
use crate::ui::state::{ToastKind, UiState};

use super::{blocked_read_only, blocked_stale, plan_details};

pub(super) fn apply_staged_plan(state: &mut UiState) -> Vec<Effect> {
    if blocked_read_only(state) || blocked_stale(state) {
        return Vec::new();
    }
    if state.staged.is_empty() {
        state.toast(ToastKind::Info, "no staged operations");
        return Vec::new();
    }
    let Some(snapshot) = state.snapshot.clone() else {
        state.toast(ToastKind::Warning, "no firewall data yet — refresh first");
        return Vec::new();
    };

    // Re-check each edit against the *current* snapshot (state may have drifted
    // since staging), keeping "already satisfied" (a genuine no-op) distinct
    // from "invalid" (a real error that must never be silently swallowed).
    let mut satisfied = 0usize;
    let mut ops: Vec<FirewallOperation> = Vec::new();
    let mut rejected: Vec<String> = Vec::new();
    for op in &state.staged {
        let narrowed = op.narrowed_for(&snapshot);
        match narrowed.validate(&snapshot) {
            Ok(()) => ops.push(narrowed),
            Err(crate::domain::OperationError::NothingToDo(_)) => satisfied += 1,
            Err(err) => rejected.push(format!("{}: {err}", narrowed.describe())),
        }
    }
    if !rejected.is_empty() {
        // A validation failure is not "already satisfied": stop, name the
        // offenders, and leave the whole plan staged for the operator to fix.
        let detail = rejected.join("; ");
        state.toast(
            ToastKind::Error,
            format!(
                "plan not applied — {} operation(s) invalid: {detail}",
                rejected.len()
            ),
        );
        return Vec::new();
    }

    if ops.is_empty() {
        state.staged.clear();
        state.toast(ToastKind::Info, "plan already satisfied — nothing to apply");
        return Vec::new();
    }

    // Route the whole batch through the same confirmation + dead-man's switch as
    // a single op. Staged plans, restores and bulk deletes are the flows most
    // likely to cut a remote admin off, so they must NOT skip the safety net.
    if state.confirm_destructive {
        let body = plan_confirm_body(state, &ops, satisfied);
        state.overlays.push(Overlay::Confirm(Confirmation {
            title: "Apply staged plan".to_owned(),
            body,
            on_confirm: UiAction::ApplyPlanConfirmed(MutationPlan::new(ops, snapshot)),
        }));
        return Vec::new();
    }
    apply_plan_now(state, MutationPlan::new(ops, snapshot))
}

/// Applies a validated, confirmed plan: clears the staging area and dispatches
/// the batch. The engine arms the dead-man's switch immediately before each
/// individual item, so future fail-fast items can never own a live inverse.
pub(super) fn apply_plan_now(state: &mut UiState, plan: MutationPlan) -> Vec<Effect> {
    state.staged.clear();
    state.toast(
        ToastKind::Info,
        format!("applying {} operation(s)", plan.operations.len()),
    );
    // The engine executes sequentially, stops on the first failure (fail-fast),
    // and refreshes once at the end. This is NOT atomic — a mid-plan failure
    // leaves earlier operations applied and re-stages the rest.
    vec![Effect::ApplyPlan(plan)]
}

/// Builds the confirmation body for a staged plan, surfacing per-batch
/// connectivity and SSH-lockout risk the same way the single-op confirm does.
fn plan_confirm_body(state: &UiState, ops: &[FirewallOperation], satisfied: usize) -> Vec<String> {
    let mut body = vec![format!("apply {} staged operation(s)", ops.len())];
    if satisfied > 0 {
        body.push(format!("({satisfied} already satisfied, skipped)"));
    }
    let risky = ops
        .iter()
        .filter(|op| op.connectivity_warning().is_some())
        .count();
    if risky > 0 {
        body.push(format!(
            "⚠ {risky} operation(s) may cut existing connections"
        ));
        if state.ssh_session {
            // Precise when a risky op touches the effective SSH zone; a blanket
            // warning otherwise — mirroring the single-op confirm.
            match state.ssh_zone_with_reason() {
                Some((ssh_zone, reason))
                    if ops.iter().any(|op| {
                        op.connectivity_warning().is_some()
                            && op.zone().is_some_and(|z| *z == ssh_zone)
                    }) =>
                {
                    body.push(format!(
                        "⚠ zone `{ssh_zone}` protects your SSH session ({reason}) — \
                         you may cut your own connection"
                    ));
                }
                _ => body.push(
                    "⚠ SSH session detected — verify this plan cannot cut your connection"
                        .to_owned(),
                ),
            }
        }
        if state.rollback_ticks > 0 {
            body.push(format!(
                "a rollback countdown will arm for the {risky} risky change(s)"
            ));
        }
    }
    for op in ops.iter().take(8) {
        body.push(format!("  · {}", op.describe()));
    }
    if ops.len() > 8 {
        body.push(format!("  · … and {} more", ops.len() - 8));
    }
    body
}

/// Stages permanent-scoped operations that bring the permanent config in line
/// with the current runtime — per-attribute drift repair the operator reviews
/// before applying (narrower and more visible than a blanket
/// runtime-to-permanent).
pub(super) fn stage_drift_sync(state: &mut UiState) -> Vec<Effect> {
    if blocked_read_only(state) {
        return Vec::new();
    }
    let Some(current) = state.snapshot.clone() else {
        state.toast(ToastKind::Warning, "no firewall data yet — refresh first");
        return Vec::new();
    };
    // Target = today's snapshot with the permanent config replaced by runtime:
    // the restore differ then emits exactly the permanent-scoped repairs.
    let mut target = (*current).clone();
    target.permanent = target.runtime.clone();
    let plan: Vec<FirewallOperation> = crate::domain::restore::plan(&current, &target)
        .into_iter()
        .filter(|op| op.target() == ConfigurationTarget::Permanent)
        .collect();
    if plan.is_empty() {
        state.toast(
            ToastKind::Info,
            "no drift — permanent already matches runtime",
        );
        return Vec::new();
    }
    let count = plan.len();
    state.staged = plan;
    state.toast(
        ToastKind::Success,
        format!("staged {count} drift repair(s) — review, then apply"),
    );
    state.overlays.push(Overlay::Details(plan_details(state)));
    Vec::new()
}

/// Requests a snapshot load off the event-loop thread. The diff + staging
/// happens in [`snapshot_loaded`] once the read returns, so the reducer stays
/// pure and a slow (NFS) state dir can't freeze the UI.
pub(super) fn restore_snapshot(state: &mut UiState, name: &str) -> Vec<Effect> {
    if state.snapshot.is_none() {
        state.toast(ToastKind::Warning, "no current state to restore against");
        return Vec::new();
    }
    vec![Effect::LoadSnapshotForRestore(name.trim().to_owned())]
}

/// Requests a snapshot load for a read-only diff (off-thread). Unlike restore,
/// the result never stages a plan — it only opens a diff overlay.
pub(super) fn diff_snapshot(state: &mut UiState, name: &str) -> Vec<Effect> {
    if state.snapshot.is_none() {
        state.toast(ToastKind::Warning, "no current state to diff against");
        return Vec::new();
    }
    state.overlays.pop(); // close the filename form
    vec![Effect::LoadSnapshotForDiff(name.trim().to_owned())]
}

/// Handles a completed diff-snapshot load: diffs it against the current state
/// and shows a read-only overlay. Never stages or applies.
pub(super) fn snapshot_diff_loaded(
    state: &mut UiState,
    name: &str,
    result: Result<Box<crate::domain::FirewallSnapshot>, String>,
) -> Vec<Effect> {
    let Some(current) = state.snapshot.clone() else {
        state.toast(ToastKind::Warning, "no current state to diff against");
        return Vec::new();
    };
    let snapshot = match result {
        Ok(snapshot) => snapshot,
        Err(err) => {
            state.toast(
                ToastKind::Error,
                format!("snapshot load failed ({name}): {err}"),
            );
            return Vec::new();
        }
    };
    // Ops that transform the saved snapshot into the current state = how the
    // live firewall differs from that snapshot.
    let ops = crate::domain::restore::plan(&snapshot, &current);
    let content =
        crate::ui::details::diff(format!("Diff vs snapshot `{name}` ({})", ops.len()), &ops);
    state.overlays.push(Overlay::Details(content));
    Vec::new()
}

/// Handles a completed snapshot load: diffs it against the current state and
/// stages the resulting plan for review. Never applies directly.
pub(super) fn snapshot_loaded(
    state: &mut UiState,
    name: &str,
    result: Result<Box<crate::domain::FirewallSnapshot>, String>,
) -> Vec<Effect> {
    let Some(current) = state.snapshot.clone() else {
        state.toast(ToastKind::Warning, "no current state to restore against");
        return Vec::new();
    };
    let target = match result {
        Ok(target) => target,
        Err(err) => {
            state.toast(
                ToastKind::Error,
                format!("snapshot load failed ({name}): {err}"),
            );
            return Vec::new();
        }
    };
    let plan = crate::domain::restore::plan(&current, &target);
    if plan.is_empty() {
        state.toast(
            ToastKind::Info,
            "already matches that snapshot — nothing to restore",
        );
        return Vec::new();
    }
    let count = plan.len();
    state.staged = plan;
    state.toast(
        ToastKind::Success,
        format!("staged {count} operation(s) — review, then apply"),
    );
    // Open the plan right away: restore review must be zero-friction.
    state.overlays.push(Overlay::Details(plan_details(state)));
    Vec::new()
}

pub(super) fn export_plan(
    state: &mut UiState,
    format: crate::infrastructure::firewalld::command::ExportFormat,
) -> Vec<Effect> {
    if state.staged.is_empty() {
        state.toast(ToastKind::Info, "no staged operations to export");
        return Vec::new();
    }
    let rendered = format.render(&state.staged);
    vec![Effect::ExportPlan(format, rendered)]
}
