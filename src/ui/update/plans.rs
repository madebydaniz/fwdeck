//! Staged-plan lifecycle: apply, drift sync, snapshot restore, and export.

use crate::domain::{ConfigurationTarget, FirewallOperation};
use crate::ui::action::Effect;
use crate::ui::overlays::Overlay;
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
    // Without a snapshot there is nothing to re-validate against (the
    // never-refreshed case; a failed refresh is already caught by
    // blocked_stale). Apply the staged plan as-is.
    let Some(snapshot) = state.snapshot.clone() else {
        let ops: Vec<FirewallOperation> = state.staged.drain(..).collect();
        state.toast(
            ToastKind::Info,
            format!("applying {} staged operation(s)", ops.len()),
        );
        return vec![Effect::ApplyPlan(ops)];
    };

    // Re-check each edit against the *current* snapshot (state may have drifted
    // since staging), classifying into three buckets — crucially keeping
    // "already satisfied" (a genuine no-op) distinct from "invalid" (a real
    // error that must never be silently swallowed as satisfied).
    let mut ops: Vec<FirewallOperation> = Vec::new();
    let mut satisfied = 0usize;
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

    // Everything validated; the no-ops are safe to drop. Commit the drain now.
    state.staged.clear();
    if ops.is_empty() {
        state.toast(ToastKind::Info, "plan already satisfied — nothing to apply");
        return Vec::new();
    }
    let mut message = format!("applying {} staged operation(s)", ops.len());
    if satisfied > 0 {
        use std::fmt::Write as _;
        let _ = write!(message, " ({satisfied} already satisfied, skipped)");
    }
    state.toast(ToastKind::Info, message);
    // The engine executes sequentially, stops on the first failure (fail-fast),
    // and refreshes once at the end. Note: this is NOT atomic — a mid-plan
    // failure leaves earlier operations applied and re-stages the rest.
    vec![Effect::ApplyPlan(ops)]
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
