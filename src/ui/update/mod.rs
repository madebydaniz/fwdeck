//! The pure reducer: `(state, action) -> effects`. No I/O, no rendering —
//! fully testable without a terminal.

mod forms;
mod lifecycle;
mod plans;
mod rows;

use crate::domain::{ConfigurationTarget, FirewallOperation, ZoneName};

use super::action::{Effect, UiAction};
use super::details;
use super::overlays::{Confirmation, DetailsContent, FormKind, FormState, Overlay};
use super::palette::{self, Availability};
use super::search;
use super::state::{InputMode, ToastKind, UiState};
use super::views::ViewId;

use forms::{form_submit, rich_builder_commit};
use lifecycle::{fire_expired_rollbacks, fire_rollback};
use plans::{apply_plan_now, apply_staged_plan, export_plan, stage_drift_sync};
use rows::{activate_row, clone_entry, delete_entry, toggle_mark, yank_row};

// fixed page size; wire to the rendered table height if it ever matters.
const PAGE_JUMP: i32 = 10;

/// Applies one [`UiAction`] to the state and returns the side effects the
/// shell must execute (engine requests, clipboard, file writes). This is the
/// only place UI state changes; keeping it pure is what makes every keystroke
/// unit-testable.
#[allow(clippy::too_many_lines)] // one arm per action; splitting hurts readability
pub fn update(state: &mut UiState, action: UiAction) -> Vec<Effect> {
    match action {
        UiAction::Quit => return vec![Effect::Quit],
        UiAction::Tick => {
            state.tick += 1;
            state.prune_toasts();
            // Fire only the rollbacks whose own deadline has passed; a newer,
            // still-live countdown keeps ticking (`fire_expired_rollbacks`
            // retains it).
            if state
                .pending_rollback
                .iter()
                .any(|pending| state.tick >= pending.deadline_tick)
            {
                return fire_expired_rollbacks(state);
            }
        }
        UiAction::Resize(w, h) => state.size = (w, h),
        UiAction::SwitchView(view) => {
            state.view = view;
            state.mode = InputMode::Normal;
            state.views[view.index()].filter.clear();
            state.views[view.index()].marked.clear();
            clamp_selection(state);
        }
        UiAction::MoveSelection(delta) => move_selection(state, delta),
        UiAction::Page(direction) => move_selection(state, direction * PAGE_JUMP),
        UiAction::SelectFirst => state.view_state_mut().selected = 0,
        UiAction::SelectLast => {
            let last = state.visible_rows().len().saturating_sub(1);
            state.view_state_mut().selected = last;
        }
        UiAction::OpenPalette => {
            state
                .overlays
                .push(Overlay::Palette(palette::PaletteState::default()));
        }
        UiAction::PaletteInput(c) => {
            if let Some(Overlay::Palette(palette_state)) = state.overlays.last_mut() {
                palette_state.query.push(c);
                palette_state.selected = 0;
            }
        }
        UiAction::PaletteBackspace => {
            if let Some(Overlay::Palette(palette_state)) = state.overlays.last_mut() {
                palette_state.query.pop();
                palette_state.selected = 0;
            }
        }
        UiAction::PaletteMove(delta) => {
            let len = palette::filtered(state).len();
            if let Some(Overlay::Palette(palette_state)) = state.overlays.last_mut() {
                palette_state.selected = step(palette_state.selected, delta, len);
            }
        }
        UiAction::PaletteExecute => return execute_palette(state),
        UiAction::OpenGlobalSearch => {
            state
                .overlays
                .push(Overlay::GlobalSearch(search::GlobalSearchState::default()));
        }
        UiAction::GlobalSearchInput(c) => {
            if let Some(Overlay::GlobalSearch(search_state)) = state.overlays.last_mut() {
                search_state.query.push(c);
                search_state.selected = 0;
            }
        }
        UiAction::GlobalSearchBackspace => {
            if let Some(Overlay::GlobalSearch(search_state)) = state.overlays.last_mut() {
                search_state.query.pop();
                search_state.selected = 0;
            }
        }
        UiAction::GlobalSearchMove(delta) => {
            let query = match state.overlays.last() {
                Some(Overlay::GlobalSearch(s)) => s.query.clone(),
                _ => String::new(),
            };
            let len = search::hits(state, &query).len();
            if let Some(Overlay::GlobalSearch(search_state)) = state.overlays.last_mut() {
                search_state.selected = step(search_state.selected, delta, len);
            }
        }
        UiAction::GlobalSearchExecute => return execute_global_search(state),
        UiAction::EnterFilterMode => state.mode = InputMode::Filter,
        UiAction::InputChar(c) => {
            if state.mode == InputMode::Filter {
                edit_filter(state, |filter| filter.push(c));
            }
        }
        UiAction::InputBackspace => {
            if state.mode == InputMode::Filter {
                edit_filter(state, |filter| {
                    filter.pop();
                });
            }
        }
        UiAction::InputSubmit => {
            if state.mode == InputMode::Filter {
                state.mode = InputMode::Normal;
            }
        }
        UiAction::InputCancel => {
            if state.mode == InputMode::Filter {
                state.view_state_mut().filter.clear();
                state.mode = InputMode::Normal;
                clamp_selection(state);
            }
        }
        UiAction::OpenHelp => {
            if state.overlays.is_empty() {
                state.overlays.push(Overlay::Help);
            }
        }
        UiAction::CloseOverlay => {
            state.overlays.pop();
            state.overlay_scroll = 0;
        }
        UiAction::ScrollOverlay(delta) => {
            // Saturating add; the renderer clamps the upper bound to the
            // content and writes the clamped value back (i32::MIN/MAX = home/end).
            let next = i32::from(state.overlay_scroll).saturating_add(delta);
            state.overlay_scroll = u16::try_from(next.max(0)).unwrap_or(u16::MAX);
        }
        UiAction::ConfirmAccept => {
            if let Some(Overlay::Confirm(confirmation)) = state.overlays.pop() {
                return update(state, confirmation.on_confirm);
            }
        }
        UiAction::ConfirmStage => {
            if let Some(Overlay::Confirm(confirmation)) = state.overlays.pop()
                && let UiAction::ApplyOperation(operation) = confirmation.on_confirm
            {
                state.toast(ToastKind::Info, format!("staged: {}", operation.describe()));
                state.staged.push(operation);
            }
        }
        UiAction::KeepChanges => {
            if !state.pending_rollback.is_empty() {
                let kept: Vec<_> = state.pending_rollback.drain(..).collect();
                // Every kept, reversible change joins the undo stack (oldest
                // first) now that its countdown is resolved, so undo can revert
                // them newest-first.
                for pending in &kept {
                    if pending.forward.inverse().is_some() {
                        state.push_undo(pending.forward.clone());
                    }
                }
                // Cancel the out-of-process watchdogs along with the countdown.
                let disarms: Vec<Effect> = kept
                    .into_iter()
                    .filter_map(|pending| pending.watchdog_unit)
                    .map(|unit| Effect::DisarmWatchdog { unit })
                    .collect();
                state.toast(ToastKind::Success, "changes kept");
                return disarms;
            }
            // `y` only confirms an active countdown; say so rather than no-op.
            state.toast(ToastKind::Info, "no rollback countdown to keep");
        }
        UiAction::RollbackNow => return fire_rollback(state),
        UiAction::ShowAudit => state.overlays.push(Overlay::Details(audit_details(state))),
        UiAction::BrowseServices => {
            if let Some(snapshot) = state.snapshot.clone() {
                state
                    .overlays
                    .push(Overlay::Details(details::service_catalog(&snapshot)));
            } else {
                state.toast(ToastKind::Info, "no data yet");
            }
        }
        UiAction::BrowsePolicies => {
            if let Some(snapshot) = state.snapshot.clone() {
                state
                    .overlays
                    .push(Overlay::Details(details::policy_browse(&snapshot)));
            } else {
                state.toast(ToastKind::Info, "no data yet");
            }
        }
        UiAction::ShowDrift => {
            if let Some(snapshot) = state.snapshot.clone() {
                state
                    .overlays
                    .push(Overlay::Details(details::drift_workspace(&snapshot)));
            } else {
                state.toast(ToastKind::Info, "no data yet");
            }
        }
        UiAction::ShowSessionDiff => {
            match (state.session_baseline.clone(), state.snapshot.clone()) {
                (Some(baseline), Some(current)) => {
                    // Ops that transform the baseline into now = what changed.
                    let ops = crate::domain::restore::plan(&baseline, &current);
                    let content = details::diff(
                        format!("Session diff — changes since startup ({})", ops.len()),
                        &ops,
                    );
                    state.overlays.push(Overlay::Details(content));
                }
                _ => state.toast(ToastKind::Info, "no baseline yet — refresh first"),
            }
        }
        UiAction::ShowSnapshotDiff => {
            if state.snapshot.is_none() {
                state.toast(ToastKind::Info, "no current state yet — refresh first");
            } else {
                state.overlays.push(Overlay::Form(FormState {
                    kind: FormKind::DiffSnapshot,
                    buffer: String::new(),
                }));
            }
        }
        UiAction::SnapshotDiffLoaded { name, result } => {
            return plans::snapshot_diff_loaded(state, &name, result);
        }
        UiAction::ShowCounters => {
            state.toast(ToastKind::Info, "reading nft counters…");
            return vec![Effect::LoadCounters];
        }
        UiAction::CountersLoaded(result) => match result {
            Ok(counters) => {
                state
                    .overlays
                    .push(Overlay::Details(details::counters(&counters)));
            }
            Err(err) => state.toast(ToastKind::Error, format!("counters unavailable: {err}")),
        },
        UiAction::StageDriftSync => return stage_drift_sync(state),
        UiAction::UndoLastOperation => {
            let Some(last) = state.undo_stack.pop() else {
                state.toast(ToastKind::Info, "nothing to undo in this session");
                return Vec::new();
            };
            let Some(inverse) = last.inverse() else {
                state.toast(ToastKind::Info, "the last operation has no inverse");
                return Vec::new();
            };
            // Defensive: if this op were somehow still armed, disarm it so the
            // deadline and watchdog can't fire the same inverse a second time.
            let mut effects: Vec<Effect> = Vec::new();
            state.pending_rollback.retain(|pending| {
                if pending.forward == last {
                    if let Some(unit) = &pending.watchdog_unit {
                        effects.push(Effect::DisarmWatchdog { unit: unit.clone() });
                    }
                    false
                } else {
                    true
                }
            });
            // Undo is just another reviewed mutation: validation + confirmation.
            effects.extend(request_operation(state, inverse));
            return effects;
        }
        UiAction::SaveSnapshot => match state.snapshot.clone() {
            Some(snapshot) => return vec![Effect::SaveSnapshot(snapshot)],
            None => state.toast(ToastKind::Info, "no data to snapshot yet"),
        },
        // The listing read happens off the event-loop thread; the result comes
        // back as SnapshotsListed.
        UiAction::BrowseSnapshots => return vec![Effect::ListSnapshots],
        UiAction::SnapshotsListed(entries) => {
            let mut lines: Vec<(String, String)> = entries
                .iter()
                .map(|entry| (entry.name.clone(), format!("{} bytes", entry.bytes)))
                .collect();
            if lines.is_empty() {
                lines.push(("snapshots".to_owned(), "none saved yet".to_owned()));
            }
            state.overlays.push(Overlay::Details(DetailsContent {
                title: format!("Saved snapshots ({})", entries.len()),
                lines,
            }));
        }
        UiAction::SnapshotLoaded { name, result } => {
            return plans::snapshot_loaded(state, &name, result);
        }
        UiAction::ShowStagedPlan => state.overlays.push(Overlay::Details(plan_details(state))),
        UiAction::ApplyStagedPlan => return apply_staged_plan(state),
        // The confirmed apply of a staged plan (carried by the plan confirm's
        // on_confirm): arms the dead-man's switch, then dispatches the batch.
        UiAction::ApplyPlanConfirmed(ops) => return apply_plan_now(state, ops),
        UiAction::DiscardStagedPlan => {
            let count = state.staged.len();
            state.staged.clear();
            state.toast(
                ToastKind::Info,
                format!("discarded {count} staged operation(s)"),
            );
        }
        UiAction::ExportStagedPlan(format) => return export_plan(state, format),
        UiAction::YankRow => return yank_row(state),
        UiAction::ActivateRow => activate_row(state),
        UiAction::InspectZone => inspect_zone(state),
        UiAction::ShowErrorDetails => {
            if let Some(error) = &state.backend_error {
                let content = details::for_error(error);
                state.overlays.push(Overlay::Details(content));
            } else {
                state.toast(ToastKind::Info, "no backend error to inspect");
            }
        }
        UiAction::ClearFilter => {
            state.view_state_mut().filter.clear();
            clamp_selection(state);
        }
        UiAction::RefreshRequested => return vec![Effect::Refresh],
        UiAction::ReloadRequested => {
            return request_operation(state, FirewallOperation::Reload);
        }
        UiAction::ToggleConfigView => {
            state.config_view = if state.config_view == ConfigurationTarget::Permanent {
                ConfigurationTarget::Runtime
            } else {
                ConfigurationTarget::Permanent
            };
            clamp_selection(state);
        }
        UiAction::AddEntry => match state.view {
            ViewId::Services => return update(state, UiAction::OpenForm(FormKind::AddService)),
            ViewId::Ports => return update(state, UiAction::OpenForm(FormKind::AddPort)),
            ViewId::Forwarding => {
                return update(state, UiAction::OpenForm(FormKind::AddForwardPort));
            }
            ViewId::RichRules => return update(state, UiAction::OpenForm(FormKind::AddRichRule)),
            ViewId::Interfaces => {
                return update(state, UiAction::OpenForm(FormKind::AddInterface));
            }
            ViewId::Sources => return update(state, UiAction::OpenForm(FormKind::AddSource)),
            ViewId::Zones => return update(state, UiAction::OpenForm(FormKind::CreateZone)),
            ViewId::IpSets => {
                // With a selected set, `a` adds an entry; otherwise create a set.
                let kind = if state.visible_rows().is_empty() {
                    FormKind::CreateIpSet
                } else {
                    FormKind::AddIpSetEntry
                };
                return update(state, UiAction::OpenForm(kind));
            }
            ViewId::Direct | ViewId::Logs => {
                state.toast(ToastKind::Info, "no add action on this view");
            }
        },
        UiAction::DeleteEntry => return delete_entry(state),
        UiAction::ToggleMark => toggle_mark(state),
        UiAction::ToggleMasqueradeRequested => return toggle_masquerade(state),
        UiAction::ToggleForwardRequested => return toggle_forward(state),
        UiAction::ToggleIcmpBlockInversionRequested => return toggle_icmp_block_inversion(state),
        UiAction::SetDefaultZoneRequested => return set_default_zone(state),
        UiAction::OpenForm(kind) => {
            state.overlays.push(Overlay::Form(FormState {
                kind,
                buffer: String::new(),
            }));
        }
        UiAction::OpenFormPrefilled(kind, buffer) => {
            state
                .overlays
                .push(Overlay::Form(FormState { kind, buffer }));
        }
        UiAction::CloneEntry => return clone_entry(state),
        UiAction::FormInput(c) => {
            if let Some(Overlay::Form(form)) = state.overlays.last_mut() {
                form.buffer.push(c);
            }
        }
        UiAction::FormBackspace => {
            if let Some(Overlay::Form(form)) = state.overlays.last_mut() {
                form.buffer.pop();
            }
        }
        UiAction::FormSubmit => return form_submit(state),
        UiAction::OpenRichBuilder => {
            if state.effective_zone().is_some() {
                state.overlays.push(Overlay::RichBuilder(
                    super::rich_builder::RichBuilder::default(),
                ));
            } else {
                state.toast(ToastKind::Info, "no zone context yet");
            }
        }
        UiAction::RichBuilderInput(c) => {
            if let Some(Overlay::RichBuilder(builder)) = state.overlays.last_mut() {
                builder.buffer.push(c);
            }
        }
        UiAction::RichBuilderBackspace => {
            if let Some(Overlay::RichBuilder(builder)) = state.overlays.last_mut() {
                builder.buffer.pop();
            }
        }
        UiAction::RichBuilderCommit => return rich_builder_commit(state),
        UiAction::RequestOperation(operation) => return request_operation(state, operation),
        UiAction::ApplyOperation(operation) => {
            state.toast(
                ToastKind::Info,
                format!("applying: {}", operation.describe()),
            );
            // Pre-arm the rollback BEFORE the apply, so a crash or SIGKILL
            // between here and a successful arm still reverts. The ArmWatchdog
            // effect is ordered ahead of Apply and dispatched first by the shell.
            let mut effects = lifecycle::pre_arm_rollback(state, &operation);
            effects.push(Effect::Apply(operation));
            return effects;
        }
        UiAction::OperationFinished { op_id, outcome } => {
            return lifecycle::operation_finished(state, op_id, outcome);
        }
        UiAction::PlanFinished { applied, remaining } => {
            if remaining.is_empty() {
                state.toast(
                    ToastKind::Success,
                    format!("plan complete — {applied} operation(s) applied"),
                );
            } else {
                let count = remaining.len();
                // Nothing is lost: unexecuted operations go back to staging.
                state.staged = remaining;
                state.toast(
                    ToastKind::Error,
                    format!("plan halted after {applied} applied — {count} operation(s) re-staged"),
                );
            }
        }
        UiAction::LogsReceived(entries) => {
            state.push_log_entries(entries);
            if state.view == ViewId::Logs {
                clamp_selection(state);
            }
        }
        UiAction::RefreshStarted => {
            state.refreshing = true;
            state.refresh_started_tick = Some(state.tick);
        }
        UiAction::RefreshCompleted(result) => {
            state.refreshing = false;
            // 250 ms tick granularity is plenty for a health metric.
            if let Some(started) = state.refresh_started_tick.take() {
                state.last_refresh_ms = Some(state.tick.saturating_sub(started) * 250);
            }
            match result {
                Ok(snapshot) => {
                    state.backend_error = None;
                    // Postcondition check: EVERY operation applied since the
                    // last refresh must actually be visible in this fresh
                    // snapshot — in a multi-step plan, not just the last one.
                    for applied in std::mem::take(&mut state.verify_next_refresh) {
                        if applied.postcondition_holds(&snapshot) == Some(false) {
                            state.toast(
                                ToastKind::Warning,
                                format!(
                                    "applied but NOT observed in the new snapshot: {} — \
                                     state may have changed underneath",
                                    applied.describe()
                                ),
                            );
                        } else if applied.inverse().is_some()
                            && !state
                                .pending_rollback
                                .iter()
                                .any(|pending| pending.forward == applied)
                        {
                            // Verified, reversible, and NOT under an armed
                            // rollback → pushed onto the undo stack in apply
                            // order, so undo pops the most recent change first.
                            // An armed op is handled by the countdown, not undo;
                            // it only joins the stack once "Keep changes"
                            // resolves it (see KeepChanges).
                            state.push_undo(applied);
                        }
                    }
                    // The first successful snapshot becomes the session
                    // baseline the "session diff" compares against.
                    if state.session_baseline.is_none() {
                        state.session_baseline = Some(std::sync::Arc::clone(&snapshot));
                    }
                    state.snapshot = Some(snapshot);
                    clamp_selection(state);
                }
                // Keep the stale snapshot: outdated data plus a visible error
                // beats an empty screen.
                Err(error) => state.backend_error = Some(error),
            }
        }
    }
    Vec::new()
}

/// Jumps to the selected global-search hit: switches to its view, clears that
/// view's filter so the row is visible, and selects it.
fn execute_global_search(state: &mut UiState) -> Vec<Effect> {
    let (query, selected) = match state.overlays.last() {
        Some(Overlay::GlobalSearch(s)) => (s.query.clone(), s.selected),
        _ => return Vec::new(),
    };
    let all_hits = search::hits(state, &query);
    let Some(hit) = all_hits.get(selected.min(all_hits.len().saturating_sub(1))) else {
        state.toast(ToastKind::Info, "no matches");
        return Vec::new();
    };
    let (view, row) = (hit.view, hit.row);
    state.overlays.pop();
    state.view = view;
    state.mode = InputMode::Normal;
    state.views[view.index()].filter.clear();
    state.views[view.index()].marked.clear();
    state.view_state_mut().selected = row;
    clamp_selection(state);
    Vec::new()
}

fn execute_palette(state: &mut UiState) -> Vec<Effect> {
    let commands = palette::filtered(state);
    let Some(palette_state) = state.palette() else {
        return Vec::new();
    };
    let Some(command) = commands.get(palette_state.selected.min(commands.len().saturating_sub(1)))
    else {
        return Vec::new();
    };
    match command.availability {
        Availability::Disabled(reason) => {
            // Keep the palette open so the operator can pick something else.
            state.toast(ToastKind::Warning, reason);
            Vec::new()
        }
        Availability::Enabled => {
            let action = command.action.clone();
            state.overlays.pop();
            update(state, action)
        }
    }
}

fn inspect_zone(state: &mut UiState) {
    let content = state.snapshot.clone().and_then(|snapshot| {
        state
            .effective_zone()
            .and_then(|zone| details::for_zone(&snapshot, &zone))
    });
    match content {
        Some(content) => state.overlays.push(Overlay::Details(content)),
        None => state.toast(ToastKind::Info, "no zone data yet"),
    }
}

/// Zone context for zone-scoped mutations: the selected row on the Zones view,
/// otherwise the effective zone.
fn zone_for_action(state: &UiState) -> Option<ZoneName> {
    if state.view == ViewId::Zones {
        let rows = state.visible_rows();
        if let Some(Ok(zone)) = rows
            .get(state.view_state().selected)
            .and_then(|row| row.first())
            .map(|name| ZoneName::parse(name))
        {
            return Some(zone);
        }
    }
    state.effective_zone()
}

/// Narrows the configured target to where the entry actually exists, so
/// removing a runtime-only entry never issues a doomed `--permanent` call.
fn target_for_scope(scope: &str, default: ConfigurationTarget) -> ConfigurationTarget {
    super::views::Scope::parse(scope).target_or(default)
}

/// The single read-only gate for mutation entry points: toasts and reports
/// `true` when mutations are disabled, so no caller can fork the wording.
fn blocked_read_only(state: &mut UiState) -> bool {
    if state.read_only {
        state.toast(
            ToastKind::Warning,
            "read-only mode — mutations are disabled",
        );
    }
    state.read_only
}

/// Stale-data gate: when the last refresh failed, the on-screen snapshot no
/// longer reflects the daemon, so validating or narrowing a mutation against it
/// is unsafe. Blocks until a refresh succeeds (which clears `backend_error`).
/// The dead-man's-switch rollback deliberately bypasses this — it must revert
/// even while refreshes are failing.
fn blocked_stale(state: &mut UiState) -> bool {
    let Some(error) = state.backend_error.as_ref().map(ToString::to_string) else {
        return false;
    };
    state.toast(
        ToastKind::Warning,
        format!("stale data — last refresh failed ({error}); refresh (ctrl-r) before mutating"),
    );
    true
}

/// The currently selected row of the visible (filtered) table, cloned out.
fn selected_row(state: &UiState) -> Option<Vec<String>> {
    let mut rows = state.visible_rows();
    let index = state.view_state().selected;
    (index < rows.len()).then(|| rows.swap_remove(index))
}

fn toggle_masquerade(state: &mut UiState) -> Vec<Effect> {
    let (Some(zone), Some(snapshot)) = (zone_for_action(state), state.snapshot.clone()) else {
        state.toast(ToastKind::Info, "no zone data yet");
        return Vec::new();
    };
    let enabled = snapshot
        .runtime
        .get(&zone)
        .or_else(|| snapshot.permanent.get(&zone))
        .is_some_and(|details| details.masquerade);
    request_operation(
        state,
        FirewallOperation::SetMasquerade {
            zone,
            enabled: !enabled,
            target: state.target,
        },
    )
}

fn toggle_forward(state: &mut UiState) -> Vec<Effect> {
    let (Some(zone), Some(snapshot)) = (zone_for_action(state), state.snapshot.clone()) else {
        state.toast(ToastKind::Info, "no zone data yet");
        return Vec::new();
    };
    let enabled = snapshot
        .runtime
        .get(&zone)
        .or_else(|| snapshot.permanent.get(&zone))
        .is_some_and(|details| details.forward);
    request_operation(
        state,
        FirewallOperation::SetForward {
            zone,
            enabled: !enabled,
            target: state.target,
        },
    )
}

fn toggle_icmp_block_inversion(state: &mut UiState) -> Vec<Effect> {
    let (Some(zone), Some(snapshot)) = (zone_for_action(state), state.snapshot.clone()) else {
        state.toast(ToastKind::Info, "no zone data yet");
        return Vec::new();
    };
    let enabled = snapshot
        .runtime
        .get(&zone)
        .or_else(|| snapshot.permanent.get(&zone))
        .is_some_and(|details| details.icmp_block_inversion);
    request_operation(
        state,
        FirewallOperation::SetIcmpBlockInversion {
            zone,
            enabled: !enabled,
            target: state.target,
        },
    )
}

fn set_default_zone(state: &mut UiState) -> Vec<Effect> {
    let Some(zone) = zone_for_action(state) else {
        state.toast(ToastKind::Info, "no zone data yet");
        return Vec::new();
    };
    request_operation(state, FirewallOperation::SetDefaultZone { zone })
}

/// If a reload would cut the SSH session — the zone carrying it differs between
/// runtime and permanent, so activating permanent drops the protection — returns
/// the warning to show. Reload has no inverse, so there is no auto-revert.
fn reload_ssh_lockout_warning(state: &UiState, operation: &FirewallOperation) -> Option<String> {
    if !matches!(operation, FirewallOperation::Reload) || !state.ssh_session {
        return None;
    }
    let (ssh_zone, reason) = state.ssh_zone_with_reason()?;
    let snapshot = state.snapshot.as_ref()?;
    if snapshot.runtime.get(&ssh_zone) == snapshot.permanent.get(&ssh_zone) {
        return None;
    }
    Some(format!(
        "⚠ reload replaces the runtime config with the permanent one; zone \
         `{ssh_zone}` protects your SSH session ({reason}) and differs between \
         runtime and permanent — this may cut your connection with no auto-revert"
    ))
}

/// Central mutation gate: read-only check, snapshot validation, then the
/// confirmation modal (or direct dispatch when confirmations are disabled).
fn request_operation(state: &mut UiState, operation: FirewallOperation) -> Vec<Effect> {
    if blocked_read_only(state) || blocked_stale(state) {
        return Vec::new();
    }
    let Some(snapshot) = state.snapshot.clone() else {
        state.toast(ToastKind::Warning, "no firewall data yet — refresh first");
        return Vec::new();
    };

    // A freshly created zone exists only in the permanent config until a
    // reload. A runtime invocation against it would die with INVALID_ZONE, so
    // narrow the target to permanent (and say so), or reject a runtime-only ask.
    let mut permanent_only_note = false;
    let operation = match operation.zone() {
        Some(zone)
            if !snapshot.runtime.contains_key(zone)
                && snapshot.permanent.contains_key(zone)
                && operation.target() != ConfigurationTarget::Permanent =>
        {
            let retargeted = if operation.target() == ConfigurationTarget::RuntimeAndPermanent {
                operation.with_target(ConfigurationTarget::Permanent)
            } else {
                None // an explicit runtime-only ask cannot be honored
            };
            if let Some(retargeted) = retargeted {
                permanent_only_note = true;
                retargeted
            } else {
                state.toast(
                    ToastKind::Warning,
                    format!(
                        "zone `{zone}` exists only in the permanent config — \
                         reload (ctrl-r) first"
                    ),
                );
                return Vec::new();
            }
        }
        _ => operation,
    };
    // Desired-state narrowing: a Both-targeted edit shrinks to the scope that
    // actually needs it, so drift repair works and no doomed command is issued.
    let operation = operation.narrowed_for(&snapshot);

    if let Err(err) = operation.validate(&snapshot) {
        state.toast(ToastKind::Warning, err.to_string());
        return Vec::new();
    }
    if !state.confirm_destructive {
        return update(state, UiAction::ApplyOperation(operation));
    }
    let mut body = vec![
        operation.describe(),
        format!("target: {}", operation.target().label()),
    ];
    if permanent_only_note {
        body.push(
            "zone is not active yet — applying to permanent; reload (ctrl-r) to activate"
                .to_owned(),
        );
    }
    if let Some(warning) = operation.connectivity_warning() {
        body.push(format!("⚠ {warning}"));
        if state.ssh_session {
            // Precise when the effective SSH zone (source match → interface →
            // default) is the one being touched; a blanket warning otherwise.
            match (state.ssh_zone_with_reason(), operation.zone()) {
                (Some((ssh_zone, reason)), Some(op_zone)) if ssh_zone == *op_zone => {
                    body.push(format!(
                        "⚠ zone `{ssh_zone}` protects your SSH session ({reason}) — \
                         you may cut your own connection"
                    ));
                }
                (Some((ssh_zone, reason)), _)
                    if matches!(operation, FirewallOperation::SetDefaultZone { .. })
                        && reason.contains("default zone") =>
                {
                    body.push(format!(
                        "⚠ your SSH session currently relies on default zone `{ssh_zone}` — \
                         changing the default re-zones it"
                    ));
                }
                _ => body.push(
                    "⚠ SSH session detected — verify this cannot cut your connection".to_owned(),
                ),
            }
        }
    }
    if let Some(warning) = reload_ssh_lockout_warning(state, &operation) {
        body.push(warning);
    }
    // Exact-command preview for the active backend (offline drives
    // `firewall-offline-cmd`, permanent only).
    body.extend(command_preview(&operation, state.offline));
    state.overlays.push(Overlay::Confirm(Confirmation {
        title: "Confirm".to_owned(),
        body,
        on_confirm: UiAction::ApplyOperation(operation),
    }));
    Vec::new()
}

/// The exact `$ …` command lines shown in a confirmation, for the active
/// backend: offline drives `firewall-offline-cmd` (permanent only), so a
/// `firewall-cmd` line the offline run would never issue is never shown.
fn command_preview(operation: &FirewallOperation, offline: bool) -> Vec<String> {
    use crate::infrastructure::firewalld::command::{self, BackendMode};
    let mode = if offline {
        BackendMode::Offline
    } else {
        BackendMode::Live
    };
    command::plan_in(
        operation,
        crate::infrastructure::process::DEFAULT_TIMEOUT,
        mode,
    )
    .into_iter()
    .map(|planned| format!("$ {} {}", mode.program(), planned.request.args.join(" ")))
    .collect()
}

fn audit_details(state: &UiState) -> DetailsContent {
    let mut lines: Vec<(String, String)> = state
        .audit
        .iter()
        .rev()
        .take(40)
        .map(|entry| {
            let detail = entry.error.as_ref().map_or_else(
                || format!("{} ({})", entry.status, entry.target),
                |err| format!("{} — {err}", entry.status),
            );
            (entry.description.clone(), detail)
        })
        .collect();
    if lines.is_empty() {
        lines.push(("audit".to_owned(), "no operations this session".to_owned()));
    }
    DetailsContent {
        title: "Session audit".to_owned(),
        lines,
    }
}

fn plan_details(state: &UiState) -> DetailsContent {
    let mut lines: Vec<(String, String)> = state
        .staged
        .iter()
        .enumerate()
        .map(|(index, op)| (format!("{}.", index + 1), op.describe()))
        .collect();
    if lines.is_empty() {
        lines.push(("plan".to_owned(), "no staged operations".to_owned()));
    } else {
        lines.push((String::new(), String::new()));
        lines.push((
            "apply".to_owned(),
            "palette: \"Apply staged plan\" · \"Discard staged plan\"".to_owned(),
        ));
    }
    DetailsContent {
        title: format!("Staged plan ({})", state.staged.len()),
        lines,
    }
}

fn step(current: usize, delta: i32, len: usize) -> usize {
    if len == 0 {
        return 0;
    }
    let current = i64::try_from(current).unwrap_or(i64::MAX);
    let max = i64::try_from(len - 1).unwrap_or(i64::MAX);
    usize::try_from((current + i64::from(delta)).clamp(0, max)).unwrap_or(0)
}

fn move_selection(state: &mut UiState, delta: i32) {
    let len = state.visible_rows().len();
    let next = step(state.view_state().selected, delta, len);
    state.view_state_mut().selected = next;
}

fn clamp_selection(state: &mut UiState) {
    let len = state.visible_rows().len();
    let view_state = state.view_state_mut();
    if len == 0 {
        view_state.selected = 0;
    } else if view_state.selected >= len {
        view_state.selected = len - 1;
    }
}

/// Edits the live filter while keeping the selection on the same underlying row
/// when it survives the new filter; otherwise falls back to the first row.
fn edit_filter(state: &mut UiState, edit: impl FnOnce(&mut String)) {
    let before = state.visible_rows();
    let selected_key = before
        .get(state.view_state().selected)
        .and_then(|row| row.first().cloned());
    edit(&mut state.view_state_mut().filter);
    let after = state.visible_rows();
    let selected = selected_key
        .and_then(|key| after.iter().position(|row| row.first() == Some(&key)))
        .unwrap_or(0);
    state.view_state_mut().selected = selected;
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::plans::restore_snapshot;
    use super::*;
    use crate::config::Config;
    use crate::domain::ServiceName;
    use crate::domain::mock;
    use crate::ui::overlays::Confirmation;

    fn state() -> UiState {
        let mut state = UiState::new(&Config::default(), "test".into(), false, None);
        state.snapshot = Some(std::sync::Arc::new(mock::sample().unwrap()));
        state
    }

    fn type_filter(s: &mut UiState, text: &str) {
        update(s, UiAction::EnterFilterMode);
        for c in text.chars() {
            update(s, UiAction::InputChar(c));
        }
    }

    fn type_palette(s: &mut UiState, text: &str) {
        update(s, UiAction::OpenPalette);
        for c in text.chars() {
            update(s, UiAction::PaletteInput(c));
        }
    }

    #[test]
    fn switching_view_clears_its_filter() {
        let mut s = state();
        update(&mut s, UiAction::SwitchView(ViewId::Services));
        type_filter(&mut s, "ssh");
        update(&mut s, UiAction::InputSubmit);
        update(&mut s, UiAction::SwitchView(ViewId::Zones));
        update(&mut s, UiAction::SwitchView(ViewId::Services));
        assert!(s.view_state().filter.is_empty());
    }

    #[test]
    fn selection_clamps_to_row_count() {
        let mut s = state();
        update(&mut s, UiAction::SelectLast);
        let last = s.view_state().selected;
        update(&mut s, UiAction::MoveSelection(5));
        assert_eq!(s.view_state().selected, last);
        update(&mut s, UiAction::MoveSelection(-1000));
        assert_eq!(s.view_state().selected, 0);
    }

    #[test]
    fn filter_narrows_rows_and_esc_clears() {
        let mut s = state();
        update(&mut s, UiAction::SwitchView(ViewId::Services));
        let all = s.visible_rows().len();
        type_filter(&mut s, "ssh");
        assert!(s.visible_rows().len() < all);
        update(&mut s, UiAction::InputCancel);
        assert!(s.view_state().filter.is_empty());
        assert_eq!(s.visible_rows().len(), all);
        assert_eq!(s.mode, InputMode::Normal);
    }

    #[test]
    fn filter_follows_selected_row_when_it_survives() {
        let mut s = state();
        update(&mut s, UiAction::SwitchView(ViewId::Services));
        let rows = s.visible_rows();
        let ssh_index = rows.iter().position(|r| r[0] == "ssh").unwrap();
        s.view_state_mut().selected = ssh_index;
        type_filter(&mut s, "ss");
        let rows = s.visible_rows();
        assert_eq!(rows[s.view_state().selected][0], "ssh");
    }

    #[test]
    fn filter_resets_selection_when_row_disappears() {
        let mut s = state();
        update(&mut s, UiAction::SwitchView(ViewId::Services));
        update(&mut s, UiAction::SelectLast);
        type_filter(&mut s, "zzz-no-match");
        assert_eq!(s.view_state().selected, 0);
        assert!(s.visible_rows().is_empty());
    }

    #[test]
    fn palette_executes_quit() {
        let mut s = state();
        type_palette(&mut s, "quit");
        assert_eq!(update(&mut s, UiAction::PaletteExecute), vec![Effect::Quit]);
        assert!(s.overlays.is_empty(), "palette closes after execution");
    }

    #[test]
    fn palette_executes_refresh() {
        let mut s = state();
        type_palette(&mut s, "refresh");
        assert_eq!(
            update(&mut s, UiAction::PaletteExecute),
            vec![Effect::Refresh]
        );
    }

    #[test]
    fn disabled_command_toasts_reason_and_keeps_palette_open() {
        let mut s = state();
        // On the Zones view, removing a forward port is impossible → disabled.
        type_palette(&mut s, "remove selected forward");
        assert!(update(&mut s, UiAction::PaletteExecute).is_empty());
        assert_eq!(s.overlays.len(), 1, "palette stays open");
        let toast = s.toasts.back().unwrap();
        assert_eq!(toast.kind, ToastKind::Warning);
        assert!(toast.text.contains("Forward view"));
    }

    #[test]
    fn palette_add_service_opens_the_form() {
        let mut s = state();
        type_palette(&mut s, "add service");
        assert!(update(&mut s, UiAction::PaletteExecute).is_empty());
        assert!(
            matches!(s.overlays.last(), Some(Overlay::Form(_))),
            "enabled mutation command must open the form"
        );
    }

    #[test]
    fn palette_selection_moves_and_clamps() {
        let mut s = state();
        update(&mut s, UiAction::OpenPalette);
        update(&mut s, UiAction::PaletteMove(3));
        update(&mut s, UiAction::PaletteMove(-100));
        assert_eq!(s.palette().unwrap().selected, 0);
    }

    #[test]
    fn confirm_accept_dispatches_carried_action() {
        let mut s = state();
        s.overlays.push(Overlay::Confirm(Confirmation {
            title: "Quit?".into(),
            body: vec!["really quit".into()],
            on_confirm: UiAction::Quit,
        }));
        assert_eq!(update(&mut s, UiAction::ConfirmAccept), vec![Effect::Quit]);
        assert!(s.overlays.is_empty());
    }

    #[test]
    fn enter_opens_details_on_rich_rules() {
        let mut s = state();
        update(&mut s, UiAction::SwitchView(ViewId::RichRules));
        update(&mut s, UiAction::ActivateRow);
        match s.overlays.last() {
            Some(Overlay::Details(content)) => assert_eq!(content.title, "Rich rule"),
            other => panic!("expected details overlay, got {other:?}"),
        }
    }

    #[test]
    fn inspect_zone_opens_zone_details() {
        let mut s = state();
        update(&mut s, UiAction::InspectZone);
        match s.overlays.last() {
            Some(Overlay::Details(content)) => assert!(content.title.contains("public")),
            other => panic!("expected details overlay, got {other:?}"),
        }
    }

    #[test]
    fn show_drift_opens_details_overlay() {
        let mut s = state();
        update(&mut s, UiAction::ShowDrift);
        match s.overlays.last() {
            Some(Overlay::Details(content)) => assert!(content.title.starts_with("Drift (")),
            other => panic!("expected details overlay, got {other:?}"),
        }
    }

    #[test]
    fn error_details_require_an_error() {
        use crate::application::ports::FirewallError;
        let mut s = state();
        update(&mut s, UiAction::ShowErrorDetails);
        assert!(s.overlays.is_empty());
        s.backend_error = Some(FirewallError::DaemonNotRunning);
        update(&mut s, UiAction::ShowErrorDetails);
        assert!(matches!(s.overlays.last(), Some(Overlay::Details(_))));
    }

    #[test]
    fn toasts_expire_and_are_bounded() {
        let mut s = state();
        for i in 0..10 {
            s.toast(ToastKind::Info, format!("toast {i}"));
        }
        assert_eq!(s.toasts.len(), 4, "queue is bounded");
        for _ in 0..17 {
            update(&mut s, UiAction::Tick);
        }
        assert!(s.toasts.is_empty(), "toasts expire");
    }

    #[test]
    fn refresh_request_emits_refresh_effect() {
        let mut s = state();
        assert_eq!(
            update(&mut s, UiAction::RefreshRequested),
            vec![Effect::Refresh]
        );
    }

    #[test]
    fn refresh_error_keeps_stale_snapshot() {
        use crate::application::ports::FirewallError;
        let mut s = state();
        update(&mut s, UiAction::RefreshStarted);
        assert!(s.refreshing);
        update(
            &mut s,
            UiAction::RefreshCompleted(Err(FirewallError::DaemonNotRunning)),
        );
        assert!(!s.refreshing);
        assert!(s.snapshot.is_some(), "stale data must survive an error");
        assert_eq!(s.backend_error, Some(FirewallError::DaemonNotRunning));
    }

    #[test]
    fn successful_refresh_clears_error_and_swaps_snapshot() {
        use crate::application::ports::FirewallError;
        let mut s = state();
        s.backend_error = Some(FirewallError::DaemonNotRunning);
        let snapshot = std::sync::Arc::new(mock::sample().unwrap());
        update(&mut s, UiAction::RefreshCompleted(Ok(snapshot)));
        assert!(s.backend_error.is_none());
    }

    #[test]
    fn add_service_flow_form_confirm_apply() {
        let mut s = state();
        update(&mut s, UiAction::SwitchView(ViewId::Services));
        update(&mut s, UiAction::AddEntry);
        assert!(matches!(s.overlays.last(), Some(Overlay::Form(_))));
        for c in "mdns".chars() {
            update(&mut s, UiAction::FormInput(c));
        }
        assert!(update(&mut s, UiAction::FormSubmit).is_empty());
        // Form replaced by confirmation with target + description.
        match s.overlays.last() {
            Some(Overlay::Confirm(confirmation)) => {
                assert!(confirmation.body[0].contains("mdns"));
                assert!(confirmation.body[1].contains("runtime + permanent"));
            }
            other => panic!("expected confirmation, got {other:?}"),
        }
        let effects = update(&mut s, UiAction::ConfirmAccept);
        match &effects[..] {
            [Effect::Apply(FirewallOperation::AddService { service, .. })] => {
                assert_eq!(service.as_str(), "mdns");
            }
            other => panic!("expected apply effect, got {other:?}"),
        }
        assert!(s.overlays.is_empty());
    }

    #[test]
    fn invalid_form_input_keeps_form_open() {
        let mut s = state();
        update(&mut s, UiAction::SwitchView(ViewId::Ports));
        update(&mut s, UiAction::AddEntry);
        for c in "not-a-port".chars() {
            update(&mut s, UiAction::FormInput(c));
        }
        update(&mut s, UiAction::FormSubmit);
        assert!(matches!(s.overlays.last(), Some(Overlay::Form(_))));
        assert_eq!(s.toasts.back().map(|t| t.kind), Some(ToastKind::Warning));
    }

    #[test]
    fn mark_toggles_and_bulk_delete_stages_all() {
        let mut s = state();
        update(&mut s, UiAction::SwitchView(ViewId::Services));
        let rows = s.visible_rows();
        // Mark the first two rows.
        s.view_state_mut().selected = 0;
        update(&mut s, UiAction::ToggleMark);
        s.view_state_mut().selected = 1;
        update(&mut s, UiAction::ToggleMark);
        assert_eq!(s.view_state().marked.len(), 2);

        // `d` with marks → one confirmation staging both removals.
        update(&mut s, UiAction::DeleteEntry);
        assert!(matches!(s.overlays.last(), Some(Overlay::Confirm(_))));
        assert_eq!(s.staged.len(), 2, "both marked rows staged");
        assert!(
            s.view_state().marked.is_empty(),
            "marks cleared after delete"
        );
        let _ = rows;
    }

    #[test]
    fn mark_key_distinguishes_rows_sharing_a_first_cell() {
        // 8080/tcp and 8080/udp must not share a mark key.
        let tcp = vec!["8080".to_owned(), "tcp".to_owned(), "runtime".to_owned()];
        let udp = vec!["8080".to_owned(), "udp".to_owned(), "runtime".to_owned()];
        assert_ne!(
            crate::ui::state::row_key(&tcp),
            crate::ui::state::row_key(&udp)
        );
    }

    #[test]
    fn bulk_delete_covers_forwarding_rows() {
        let mut s = state();
        update(&mut s, UiAction::SwitchView(ViewId::Forwarding));
        if s.visible_rows().is_empty() {
            return; // mock has no forwards for the default zone — nothing to assert
        }
        update(&mut s, UiAction::ToggleMark);
        update(&mut s, UiAction::DeleteEntry);
        assert!(
            !s.staged.is_empty(),
            "marked forward row must produce a staged removal"
        );
    }

    #[test]
    fn switching_view_clears_marks() {
        let mut s = state();
        update(&mut s, UiAction::SwitchView(ViewId::Services));
        update(&mut s, UiAction::ToggleMark);
        assert_eq!(s.view_state().marked.len(), 1);
        update(&mut s, UiAction::SwitchView(ViewId::Ports));
        update(&mut s, UiAction::SwitchView(ViewId::Services));
        assert!(s.view_state().marked.is_empty());
    }

    #[test]
    fn masquerade_moved_to_m_key() {
        let mut s = state();
        update(&mut s, UiAction::SwitchView(ViewId::Zones));
        // space now marks, does not toggle masquerade
        update(&mut s, UiAction::ToggleMark);
        assert!(s.overlays.is_empty());
        assert_eq!(s.view_state().marked.len(), 1);
    }

    #[test]
    fn toggle_forward_opens_a_confirmation_for_the_effective_zone() {
        let mut s = state();
        update(&mut s, UiAction::ToggleForwardRequested);
        match s.overlays.last() {
            Some(Overlay::Confirm(c)) => assert!(matches!(
                c.on_confirm,
                UiAction::ApplyOperation(FirewallOperation::SetForward { .. })
            )),
            other => panic!("expected a SetForward confirmation, got {other:?}"),
        }
    }

    #[test]
    fn set_zone_target_form_builds_a_permanent_operation() {
        let mut s = state();
        update(&mut s, UiAction::OpenForm(FormKind::SetZoneTarget));
        for c in "DROP".chars() {
            update(&mut s, UiAction::FormInput(c));
        }
        update(&mut s, UiAction::FormSubmit);
        match s.overlays.last() {
            Some(Overlay::Confirm(c)) => assert!(matches!(
                c.on_confirm,
                UiAction::ApplyOperation(FirewallOperation::SetZoneTarget { .. })
            )),
            other => panic!("expected a SetZoneTarget confirmation, got {other:?}"),
        }
    }

    #[test]
    fn delete_narrows_target_to_actual_scope() {
        let mut s = state();
        update(&mut s, UiAction::SwitchView(ViewId::Services));
        // `http` is runtime-only in the mock → target must narrow to Runtime.
        let rows = s.visible_rows();
        let http = rows.iter().position(|r| r[0] == "http").unwrap();
        s.view_state_mut().selected = http;
        update(&mut s, UiAction::DeleteEntry);
        match s.overlays.last() {
            Some(Overlay::Confirm(confirmation)) => {
                assert_eq!(
                    confirmation.on_confirm,
                    UiAction::ApplyOperation(FirewallOperation::RemoveService {
                        zone: ZoneName::parse("public").unwrap(),
                        service: ServiceName::parse("http").unwrap(),
                        target: ConfigurationTarget::Runtime,
                    })
                );
                assert!(confirmation.body.iter().any(|l| l.contains("⚠")));
            }
            other => panic!("expected confirmation, got {other:?}"),
        }
    }

    #[test]
    fn read_only_blocks_mutations_with_a_toast() {
        let mut s = state();
        s.read_only = true;
        assert!(update(&mut s, UiAction::ReloadRequested).is_empty());
        assert!(s.overlays.is_empty());
        assert!(s.toasts.back().unwrap().text.contains("read-only"));
    }

    #[test]
    fn nothing_to_do_operations_are_rejected_before_confirm() {
        let mut s = state();
        // `https` already enabled in both configs in the mock.
        let op = FirewallOperation::AddService {
            zone: ZoneName::parse("public").unwrap(),
            service: ServiceName::parse("https").unwrap(),
            target: ConfigurationTarget::RuntimeAndPermanent,
        };
        update(&mut s, UiAction::RequestOperation(op));
        assert!(s.overlays.is_empty());
        assert_eq!(s.toasts.back().map(|t| t.kind), Some(ToastKind::Warning));
    }

    #[test]
    fn skip_confirmation_when_configured_off() {
        let mut s = state();
        s.confirm_destructive = false;
        let effects = update(&mut s, UiAction::ReloadRequested);
        assert!(matches!(
            &effects[..],
            [Effect::Apply(FirewallOperation::Reload)]
        ));
        assert!(s.overlays.is_empty());
    }

    #[test]
    fn applied_outcome_toasts_success() {
        use crate::application::ports::{OperationOutcome, StepReport};
        let mut s = state();
        let operation = FirewallOperation::Reload;
        update(
            &mut s,
            UiAction::OperationFinished {
                op_id: 1,
                outcome: OperationOutcome::Applied {
                    operation,
                    steps: vec![StepReport {
                        target: "global",
                        invocation: vec!["--reload".to_owned()],
                        result: Ok(()),
                    }],
                },
            },
        );
        assert_eq!(s.toasts.back().map(|t| t.kind), Some(ToastKind::Success));
    }

    #[test]
    fn partial_failure_opens_details_overlay() {
        use crate::application::ports::{FirewallError, OperationOutcome, StepReport};
        let mut s = state();
        let operation = FirewallOperation::AddService {
            zone: ZoneName::parse("public").unwrap(),
            service: ServiceName::parse("http").unwrap(),
            target: ConfigurationTarget::RuntimeAndPermanent,
        };
        let outcome = OperationOutcome::PartiallyApplied {
            rollback_hint: operation.inverse_runtime(),
            operation,
            steps: vec![
                StepReport {
                    target: "runtime",
                    invocation: vec!["--zone=public".to_owned()],
                    result: Ok(()),
                },
                StepReport {
                    target: "permanent",
                    invocation: vec!["--permanent".to_owned()],
                    result: Err(FirewallError::PermissionDenied {
                        detail: "Authorization failed".to_owned(),
                    }),
                },
            ],
        };
        update(&mut s, UiAction::OperationFinished { op_id: 1, outcome });
        assert_eq!(s.toasts.back().map(|t| t.kind), Some(ToastKind::Error));
        match s.overlays.last() {
            Some(Overlay::Details(content)) => {
                assert!(content.title.contains("PARTIAL"));
                assert!(content.lines.iter().any(|(k, _)| k == "rollback"));
            }
            other => panic!("expected details overlay, got {other:?}"),
        }
    }

    #[test]
    fn logs_receive_counts_denied_and_caps_buffer() {
        use crate::domain::{LogAction, LogEntry};
        let mut s = state();
        let entry = |action: LogAction| LogEntry {
            time: "10:00:00".into(),
            action,
            src: "1.2.3.4".into(),
            dst: "5.6.7.8".into(),
            dport: "22".into(),
            proto: "TCP".into(),
            iface: "eth0".into(),
        };
        let mut batch = vec![entry(LogAction::Reject), entry(LogAction::Accept)];
        for _ in 0..1200 {
            batch.push(entry(LogAction::Drop));
        }
        update(&mut s, UiAction::LogsReceived(batch));
        assert_eq!(s.log_buffer.len(), 1000, "ring buffer is bounded");
        assert_eq!(s.denied_session, 1201);
        update(&mut s, UiAction::SwitchView(ViewId::Logs));
        assert_eq!(s.visible_rows().len(), 1000);
    }

    #[test]
    fn clone_prefills_the_add_form() {
        let mut s = state();
        update(&mut s, UiAction::SwitchView(ViewId::Ports));
        update(&mut s, UiAction::CloneEntry);
        match s.overlays.last() {
            Some(Overlay::Form(form)) => {
                assert_eq!(form.kind, FormKind::AddPort);
                assert!(form.buffer.contains('/'), "port prefilled as port/proto");
            }
            other => panic!("expected prefilled form, got {other:?}"),
        }
    }

    #[test]
    fn temporary_service_form_builds_runtime_timeout_op() {
        let mut s = state();
        update(
            &mut s,
            UiAction::OpenForm(super::FormKind::AddTemporaryService),
        );
        for c in "ftp 300".chars() {
            update(&mut s, UiAction::FormInput(c));
        }
        update(&mut s, UiAction::FormSubmit);
        match s.overlays.last() {
            Some(Overlay::Confirm(c)) => {
                assert!(c.body.iter().any(|l| l.contains("temporarily")));
                assert!(c.body.iter().any(|l| l.contains("--timeout=300s")));
            }
            other => panic!("expected confirmation, got {other:?}"),
        }
    }

    #[test]
    fn armed_op_is_not_undoable_until_kept() {
        use crate::application::ports::{OperationOutcome, StepReport};
        let mut s = state();
        s.rollback_ticks = 4;
        // A risky, reversible op (remove ssh) applies and arms a rollback.
        let op = FirewallOperation::RemoveService {
            zone: ZoneName::parse("public").unwrap(),
            service: ServiceName::parse("ssh").unwrap(),
            target: ConfigurationTarget::Runtime,
        };
        // Pre-armed at apply time; the successful outcome keeps it armed.
        update(&mut s, UiAction::ApplyOperation(op.clone()));
        update(
            &mut s,
            UiAction::OperationFinished {
                op_id: 1,
                outcome: OperationOutcome::Applied {
                    operation: op.clone(),
                    steps: vec![StepReport {
                        target: "runtime",
                        invocation: vec!["x".to_owned()],
                        result: Ok(()),
                    }],
                },
            },
        );
        assert!(!s.pending_rollback.is_empty(), "risky op arms rollback");
        // A refresh must NOT promote an armed op to undoable.
        let snap = std::sync::Arc::new(mock::sample().unwrap());
        update(&mut s, UiAction::RefreshCompleted(Ok(snap)));
        assert!(
            s.undo_stack.is_empty(),
            "armed op must not also be undoable"
        );
        // Keeping the change resolves the countdown and makes it undoable.
        update(&mut s, UiAction::KeepChanges);
        assert!(s.pending_rollback.is_empty());
        assert_eq!(s.undo_stack.last(), Some(&op));
    }

    #[test]
    fn undo_stack_reverts_operations_newest_first() {
        let mut s = state();
        s.rollback_ticks = 120;
        // Two risky, reversible ops; keeping resolves both onto the undo stack.
        let a = FirewallOperation::RemoveService {
            zone: ZoneName::parse("public").unwrap(),
            service: ServiceName::parse("ssh").unwrap(),
            target: ConfigurationTarget::Runtime,
        };
        let b = FirewallOperation::RemovePort {
            zone: ZoneName::parse("public").unwrap(),
            port: "8080/tcp".parse().unwrap(),
            target: ConfigurationTarget::Runtime,
        };
        update(&mut s, UiAction::ApplyOperation(a.clone()));
        update(&mut s, UiAction::ApplyOperation(b.clone()));
        update(&mut s, UiAction::KeepChanges);

        // Both undoable, newest (the port) on top.
        assert_eq!(s.undo_stack.len(), 2);
        assert_eq!(s.undo_stack.last(), Some(&b), "newest kept is on top");

        // Undo pops the most recent first, leaving the older one.
        update(&mut s, UiAction::UndoLastOperation);
        assert_eq!(s.undo_stack.len(), 1);
        assert_eq!(s.undo_stack.last(), Some(&a));
    }

    #[test]
    fn global_search_jumps_to_a_matching_row() {
        let mut s = state();
        update(&mut s, UiAction::OpenGlobalSearch);
        for c in "8080".chars() {
            update(&mut s, UiAction::GlobalSearchInput(c));
        }
        update(&mut s, UiAction::GlobalSearchExecute);
        assert!(s.overlays.is_empty(), "search overlay closes on execute");
        // The selected row of the jumped-to view contains the query.
        let rows = s.visible_rows();
        let selected = s.view_state().selected;
        assert!(
            rows.get(selected)
                .is_some_and(|row| row.iter().any(|cell| cell.contains("8080"))),
            "landed on a row that matches the query"
        );
    }

    #[test]
    fn session_diff_needs_a_baseline_then_shows_read_only() {
        let mut s = state();
        // No baseline captured yet → informative toast, no overlay.
        update(&mut s, UiAction::ShowSessionDiff);
        assert!(s.overlays.is_empty());
        assert!(s.toasts.back().is_some_and(|t| t.text.contains("baseline")));

        // Capture a baseline (as the first refresh would) → diff opens read-only.
        s.session_baseline = s.snapshot.clone();
        update(&mut s, UiAction::ShowSessionDiff);
        match s.overlays.last() {
            Some(Overlay::Details(c)) => assert!(c.title.contains("Session diff")),
            other => panic!("expected a session-diff overlay, got {other:?}"),
        }
    }

    #[test]
    fn snapshot_diff_loaded_opens_read_only_overlay_without_staging() {
        let mut s = state();
        let snap = Box::new(mock::sample().unwrap());
        update(
            &mut s,
            UiAction::SnapshotDiffLoaded {
                name: "snapshot-1.json".to_owned(),
                result: Ok(snap),
            },
        );
        match s.overlays.last() {
            Some(Overlay::Details(c)) => assert!(c.title.contains("Diff vs snapshot")),
            other => panic!("expected a snapshot-diff overlay, got {other:?}"),
        }
        assert!(s.staged.is_empty(), "diff never stages");
    }

    #[test]
    fn counters_loaded_opens_overlay_and_errors_toast() {
        use crate::domain::ChainCounter;
        let mut s = state();
        update(
            &mut s,
            UiAction::CountersLoaded(Ok(vec![ChainCounter {
                chain: "filter_IN_public".to_owned(),
                packets: 42,
                bytes: 3200,
            }])),
        );
        match s.overlays.last() {
            Some(Overlay::Details(c)) => assert!(c.title.contains("Rule-hit counters")),
            other => panic!("expected a counters overlay, got {other:?}"),
        }

        // The error path toasts and opens nothing.
        let mut s = state();
        update(
            &mut s,
            UiAction::CountersLoaded(Err("nft unavailable".to_owned())),
        );
        assert!(
            s.toasts
                .back()
                .is_some_and(|t| t.text.contains("counters unavailable"))
        );
        assert!(!matches!(s.overlays.last(), Some(Overlay::Details(_))));
    }

    #[test]
    fn snapshot_diff_load_failure_toasts_error() {
        let mut s = state();
        update(
            &mut s,
            UiAction::SnapshotDiffLoaded {
                name: "missing.json".to_owned(),
                result: Err("not found".to_owned()),
            },
        );
        assert!(
            s.toasts
                .back()
                .is_some_and(|t| t.text.contains("load failed"))
        );
        assert!(!matches!(s.overlays.last(), Some(Overlay::Details(_))));
    }

    #[test]
    fn undo_without_history_toasts() {
        let mut s = state();
        update(&mut s, UiAction::UndoLastOperation);
        assert!(
            s.toasts
                .back()
                .is_some_and(|t| t.text.contains("nothing to undo"))
        );
    }

    #[test]
    fn rich_builder_assembles_and_confirms() {
        let mut s = state();
        update(&mut s, UiAction::OpenRichBuilder);
        // family, source, element, action
        // Distinct from the mock zone's existing rich rule, or validate()
        // rejects it as a duplicate before the confirmation.
        for word in ["ipv4", "198.51.100.0/24", "", "accept"] {
            for c in word.chars() {
                update(&mut s, UiAction::RichBuilderInput(c));
            }
            update(&mut s, UiAction::RichBuilderCommit);
        }
        // Final commit routes into the add-rich-rule confirmation.
        match s.overlays.last() {
            Some(Overlay::Confirm(c)) => {
                assert!(c.body.iter().any(|l| l.contains("rich rule")));
            }
            other => panic!("expected confirmation, got {other:?}"),
        }
    }

    #[test]
    fn add_on_rich_rules_opens_rich_rule_form() {
        let mut s = state();
        update(&mut s, UiAction::SwitchView(ViewId::RichRules));
        update(&mut s, UiAction::AddEntry);
        match s.overlays.last() {
            Some(Overlay::Form(form)) => assert_eq!(form.kind, FormKind::AddRichRule),
            other => panic!("expected form, got {other:?}"),
        }
    }

    #[test]
    fn delete_on_interfaces_follows_the_perspective() {
        let mut s = state();
        update(&mut s, UiAction::SwitchView(ViewId::Interfaces));
        update(&mut s, UiAction::DeleteEntry);
        match s.overlays.last() {
            Some(Overlay::Confirm(confirmation)) => match &confirmation.on_confirm {
                UiAction::ApplyOperation(FirewallOperation::RemoveInterface { target, .. }) => {
                    assert_eq!(*target, ConfigurationTarget::Runtime);
                }
                other => panic!("unexpected operation: {other:?}"),
            },
            other => panic!("expected confirmation, got {other:?}"),
        }
    }

    #[test]
    fn toggle_config_view_flips_perspective() {
        let mut s = state();
        assert_eq!(s.config_view, ConfigurationTarget::Runtime);
        update(&mut s, UiAction::ToggleConfigView);
        assert_eq!(s.config_view, ConfigurationTarget::Permanent);
        update(&mut s, UiAction::ToggleConfigView);
        assert_eq!(s.config_view, ConfigurationTarget::Runtime);
    }

    #[test]
    fn create_zone_flow_via_form() {
        let mut s = state();
        update(&mut s, UiAction::AddEntry); // Zones view is the default
        match s.overlays.last() {
            Some(Overlay::Form(form)) => assert_eq!(form.kind, FormKind::CreateZone),
            other => panic!("expected form, got {other:?}"),
        }
        for c in "staging".chars() {
            update(&mut s, UiAction::FormInput(c));
        }
        update(&mut s, UiAction::FormSubmit);
        match s.overlays.last() {
            Some(Overlay::Confirm(confirmation)) => {
                assert_eq!(
                    confirmation.on_confirm,
                    UiAction::ApplyOperation(FirewallOperation::CreateZone {
                        zone: ZoneName::parse("staging").unwrap(),
                    })
                );
            }
            other => panic!("expected confirmation, got {other:?}"),
        }
    }

    #[test]
    fn ipset_entry_flow_uses_selected_set() {
        let mut s = state();
        update(&mut s, UiAction::SwitchView(ViewId::IpSets));
        update(&mut s, UiAction::AddEntry); // rows exist → entry form
        match s.overlays.last() {
            Some(Overlay::Form(form)) => assert_eq!(form.kind, FormKind::AddIpSetEntry),
            other => panic!("expected form, got {other:?}"),
        }
        for c in "198.51.100.44".chars() {
            update(&mut s, UiAction::FormInput(c));
        }
        update(&mut s, UiAction::FormSubmit);
        match s.overlays.last() {
            Some(Overlay::Confirm(confirmation)) => match &confirmation.on_confirm {
                UiAction::ApplyOperation(FirewallOperation::AddIpSetEntry { name, .. }) => {
                    assert_eq!(name.as_str(), "blocklist");
                }
                other => panic!("unexpected operation: {other:?}"),
            },
            other => panic!("expected confirmation, got {other:?}"),
        }
    }

    #[test]
    fn delete_on_ipsets_deletes_the_set_with_confirm() {
        let mut s = state();
        update(&mut s, UiAction::SwitchView(ViewId::IpSets));
        update(&mut s, UiAction::DeleteEntry);
        match s.overlays.last() {
            Some(Overlay::Confirm(confirmation)) => {
                assert!(confirmation.body[0].contains("delete ipset `blocklist`"));
            }
            other => panic!("expected confirmation, got {other:?}"),
        }
    }

    #[test]
    fn ops_on_permanent_only_zones_narrow_to_permanent() {
        let mut s = state();
        // Simulate a freshly created zone: permanent config only.
        let mut snapshot = mock::sample().unwrap();
        let staging = ZoneName::parse("staging").unwrap();
        snapshot.permanent.insert(
            staging.clone(),
            crate::domain::ZoneDetails::empty(staging.clone()),
        );
        s.snapshot = Some(std::sync::Arc::new(snapshot));

        let op = FirewallOperation::AddService {
            zone: staging.clone(),
            service: ServiceName::parse("https").unwrap(),
            target: ConfigurationTarget::RuntimeAndPermanent,
        };
        update(&mut s, UiAction::RequestOperation(op));
        match s.overlays.last() {
            Some(Overlay::Confirm(confirmation)) => {
                match &confirmation.on_confirm {
                    UiAction::ApplyOperation(FirewallOperation::AddService { target, .. }) => {
                        assert_eq!(*target, ConfigurationTarget::Permanent, "must narrow");
                    }
                    other => panic!("unexpected operation: {other:?}"),
                }
                assert!(
                    confirmation
                        .body
                        .iter()
                        .any(|l| l.contains("not active yet")),
                    "modal must explain the narrowing"
                );
            }
            other => panic!("expected confirmation, got {other:?}"),
        }

        // Runtime-only ask on a permanent-only zone is impossible → clear toast.
        let op = FirewallOperation::AddService {
            zone: staging,
            service: ServiceName::parse("https").unwrap(),
            target: ConfigurationTarget::Runtime,
        };
        s.overlays.clear();
        update(&mut s, UiAction::RequestOperation(op));
        assert!(s.overlays.is_empty());
        assert!(
            s.toasts
                .back()
                .unwrap()
                .text
                .contains("reload (ctrl-r) first")
        );
    }

    #[test]
    fn deleting_the_default_zone_is_rejected() {
        let mut s = state();
        type_filter(&mut s, "public");
        update(&mut s, UiAction::InputSubmit);
        update(&mut s, UiAction::DeleteEntry);
        assert!(s.overlays.is_empty(), "validation must reject before modal");
        assert!(s.toasts.back().unwrap().text.contains("default zone"));
    }

    #[test]
    fn ssh_session_adds_warning_to_destructive_confirms() {
        let mut s = state();
        s.ssh_session = true;
        update(&mut s, UiAction::ReloadRequested);
        match s.overlays.last() {
            Some(Overlay::Confirm(confirmation)) => {
                assert!(confirmation.body.iter().any(|l| l.contains("SSH")));
            }
            other => panic!("expected confirmation, got {other:?}"),
        }
    }

    #[test]
    fn ssh_guard_is_precise_when_op_targets_the_ssh_zone() {
        let mut s = state();
        s.ssh_session = true;
        // eth0 is bound to `public` in the mock; pretend that's our SSH iface.
        s.ssh_interface = Some(crate::domain::InterfaceName::parse("eth0").unwrap());
        // A destructive op on `public` must name the SSH interface precisely.
        let op = FirewallOperation::RemoveService {
            zone: ZoneName::parse("public").unwrap(),
            service: ServiceName::parse("http").unwrap(),
            target: ConfigurationTarget::Runtime,
        };
        update(&mut s, UiAction::RequestOperation(op));
        match s.overlays.last() {
            Some(Overlay::Confirm(c)) => {
                assert!(
                    c.body
                        .iter()
                        .any(|l| l.contains("protects your SSH session") && l.contains("`eth0`")),
                    "precise warning expected, got: {:?}",
                    c.body
                );
                assert!(c.body.iter().any(|l| l.contains("eth0")));
            }
            other => panic!("expected confirmation, got {other:?}"),
        }
        // A destructive op on a different zone gets the blanket warning only.
        s.overlays.clear();
        let op = FirewallOperation::RemoveService {
            zone: ZoneName::parse("home").unwrap(),
            service: ServiceName::parse("ssh").unwrap(),
            target: ConfigurationTarget::Runtime,
        };
        update(&mut s, UiAction::RequestOperation(op));
        match s.overlays.last() {
            Some(Overlay::Confirm(c)) => {
                assert!(c.body.iter().any(|l| l.contains("SSH session detected")));
                assert!(!c.body.iter().any(|l| l.contains("governs")));
            }
            other => panic!("expected confirmation, got {other:?}"),
        }
    }

    #[test]
    fn risky_operation_arms_rollback_and_keep_disarms() {
        use crate::application::ports::{OperationOutcome, StepReport};
        let mut s = state();
        s.rollback_ticks = 120; // 30s
        // RemoveService is risky (connectivity_warning) and reversible.
        let operation = FirewallOperation::RemoveService {
            zone: ZoneName::parse("public").unwrap(),
            service: ServiceName::parse("http").unwrap(),
            target: ConfigurationTarget::RuntimeAndPermanent,
        };
        // Pre-armed at apply time, before the outcome comes back.
        update(&mut s, UiAction::ApplyOperation(operation.clone()));
        assert!(
            !s.pending_rollback.is_empty(),
            "risky op must pre-arm rollback"
        );
        // The apply succeeds → the rollback stays armed for the countdown.
        update(
            &mut s,
            UiAction::OperationFinished {
                op_id: 1,
                outcome: OperationOutcome::Applied {
                    operation,
                    steps: vec![StepReport {
                        target: "runtime",
                        invocation: vec!["x".to_owned()],
                        result: Ok(()),
                    }],
                },
            },
        );
        assert!(
            !s.pending_rollback.is_empty(),
            "stays armed after a successful apply"
        );
        update(&mut s, UiAction::KeepChanges);
        assert!(s.pending_rollback.is_empty(), "keep disarms");
    }

    #[test]
    fn clean_failure_retracts_the_pre_armed_rollback() {
        use crate::application::ports::{FirewallError, OperationOutcome, StepReport};
        let mut s = state();
        s.rollback_ticks = 120;
        let operation = FirewallOperation::RemoveService {
            zone: ZoneName::parse("public").unwrap(),
            service: ServiceName::parse("http").unwrap(),
            target: ConfigurationTarget::RuntimeAndPermanent,
        };
        update(&mut s, UiAction::ApplyOperation(operation.clone()));
        assert!(!s.pending_rollback.is_empty(), "pre-armed before apply");
        // The apply failed at the first step → nothing changed, so the
        // pre-armed watchdog must be retracted (else it fires a stale inverse).
        let effects = update(
            &mut s,
            UiAction::OperationFinished {
                op_id: 1,
                outcome: OperationOutcome::Failed {
                    operation,
                    steps: vec![StepReport {
                        target: "runtime",
                        invocation: vec!["x".to_owned()],
                        result: Err(FirewallError::DaemonNotRunning),
                    }],
                },
            },
        );
        assert!(
            s.pending_rollback.is_empty(),
            "a clean failure retracts the rollback"
        );
        assert!(
            effects
                .iter()
                .any(|e| matches!(e, Effect::DisarmWatchdog { .. })),
            "the stale watchdog must be disarmed"
        );
    }

    #[test]
    fn rollback_fires_on_deadline_and_applies_inverse() {
        let mut s = state();
        s.rollback_ticks = 2;
        let op = FirewallOperation::RemovePort {
            zone: ZoneName::parse("public").unwrap(),
            port: "8080/tcp".parse().unwrap(),
            target: ConfigurationTarget::Runtime,
        };
        // Apply arms the rollback (its countdown is not started yet)...
        update(&mut s, UiAction::ApplyOperation(op.clone()));
        // ...the applied outcome lands, which starts the countdown from now...
        update(
            &mut s,
            UiAction::OperationFinished {
                op_id: 1,
                outcome: crate::application::ports::OperationOutcome::Applied {
                    operation: op,
                    steps: Vec::new(),
                },
            },
        );
        // ...the operator walks away: two ticks reach the deadline → the
        // watchdog is disarmed (we revert in-process) and the inverse applies.
        update(&mut s, UiAction::Tick);
        let effects = update(&mut s, UiAction::Tick);
        match &effects[..] {
            [
                Effect::DisarmWatchdog { .. },
                Effect::Apply(FirewallOperation::AddPort { .. }),
            ] => {}
            other => panic!("expected disarm + inverse AddPort, got {other:?}"),
        }
        assert!(s.pending_rollback.is_empty());
    }

    #[test]
    fn partial_failure_keeps_the_rollback_armed() {
        let mut s = state();
        let op = FirewallOperation::RemovePort {
            zone: ZoneName::parse("public").unwrap(),
            port: "8080/tcp".parse().unwrap(),
            target: ConfigurationTarget::RuntimeAndPermanent,
        };
        update(&mut s, UiAction::ApplyOperation(op.clone()));
        assert!(
            !s.pending_rollback.is_empty(),
            "a risky op arms the rollback"
        );
        update(
            &mut s,
            UiAction::OperationFinished {
                op_id: 1,
                outcome: crate::application::ports::OperationOutcome::PartiallyApplied {
                    operation: op,
                    steps: Vec::new(),
                    rollback_hint: None,
                },
            },
        );
        assert!(
            !s.pending_rollback.is_empty(),
            "runtime changed on a partial failure — the rollback must stay armed"
        );
    }

    #[test]
    fn indeterminate_outcome_keeps_the_rollback_armed() {
        let mut s = state();
        let op = FirewallOperation::RemovePort {
            zone: ZoneName::parse("public").unwrap(),
            port: "8080/tcp".parse().unwrap(),
            target: ConfigurationTarget::Runtime,
        };
        update(&mut s, UiAction::ApplyOperation(op.clone()));
        update(
            &mut s,
            UiAction::OperationFinished {
                op_id: 1,
                outcome: crate::application::ports::OperationOutcome::Indeterminate {
                    operation: op,
                    steps: Vec::new(),
                },
            },
        );
        assert!(
            !s.pending_rollback.is_empty(),
            "a timeout may have applied the change — the rollback must stay armed"
        );
    }

    #[test]
    fn arming_emits_a_watchdog_with_the_grace_delay() {
        let mut s = state();
        s.rollback_ticks = 40;
        let effects = update(
            &mut s,
            UiAction::ApplyOperation(FirewallOperation::RemovePort {
                zone: ZoneName::parse("public").unwrap(),
                port: "8080/tcp".parse().unwrap(),
                target: ConfigurationTarget::Runtime,
            }),
        );
        let delay = effects.iter().find_map(|effect| match effect {
            Effect::ArmWatchdog { delay_secs, .. } => Some(*delay_secs),
            _ => None,
        });
        // The out-of-process net fires rollback_ticks/4 + 15s after arming, a
        // grace margin past the in-process deadline.
        assert_eq!(delay, Some(40 / 4 + 15), "watchdog grace delay formula");
    }

    #[test]
    fn non_risky_operation_does_not_arm_rollback() {
        let mut s = state();
        s.rollback_ticks = 120;
        update(
            &mut s,
            UiAction::ApplyOperation(FirewallOperation::AddService {
                zone: ZoneName::parse("public").unwrap(),
                service: ServiceName::parse("mdns").unwrap(),
                target: ConfigurationTarget::RuntimeAndPermanent,
            }),
        );
        assert!(
            s.pending_rollback.is_empty(),
            "adding a service is not risky"
        );
    }

    #[test]
    fn stage_then_apply_plan() {
        let mut s = state();
        // Stage via the confirmation modal's `s`.
        update(&mut s, UiAction::SwitchView(ViewId::Services));
        let rows = s.visible_rows();
        let http = rows.iter().position(|r| r[0] == "http").unwrap();
        s.view_state_mut().selected = http;
        update(&mut s, UiAction::DeleteEntry); // opens confirm
        update(&mut s, UiAction::ConfirmStage);
        assert_eq!(s.staged.len(), 1);
        assert!(s.overlays.is_empty(), "stage closes the modal");

        // Applying a plan confirms first — it never skips the safety net.
        let effects = apply_staged_plan(&mut s);
        assert!(effects.is_empty(), "apply opens a confirmation");
        assert!(
            matches!(s.overlays.last(), Some(Overlay::Confirm(_))),
            "plan apply confirms before touching the firewall"
        );
        assert_eq!(s.staged.len(), 1, "plan stays staged until confirmed");

        // Confirming arms the dead-man's switch (removing http is risky) and
        // dispatches the batch, draining the staging area.
        let effects = update(&mut s, UiAction::ConfirmAccept);
        assert!(
            effects.iter().any(|e| matches!(e, Effect::ApplyPlan(_))),
            "the confirmed plan is dispatched"
        );
        assert!(
            !s.pending_rollback.is_empty(),
            "a risky plan arms the rollback, just like a single risky op"
        );
        assert!(s.staged.is_empty(), "plan drained after apply");
    }

    #[test]
    fn expired_rollback_fires_without_cutting_a_newer_countdown() {
        use crate::ui::state::PendingRollback;
        let mut s = state();
        let remove = |svc: &str| FirewallOperation::RemoveService {
            zone: ZoneName::parse("public").unwrap(),
            service: ServiceName::parse(svc).unwrap(),
            target: ConfigurationTarget::Runtime,
        };
        s.tick = 100;
        // Two independent countdowns: one already due, one still live.
        s.pending_rollback.push(PendingRollback {
            forward: remove("http"),
            inverse: remove("http").inverse().unwrap(),
            deadline_tick: 100,
            description: "due".to_owned(),
            watchdog_unit: None,
        });
        s.pending_rollback.push(PendingRollback {
            forward: remove("https"),
            inverse: remove("https").inverse().unwrap(),
            deadline_tick: 500,
            description: "live".to_owned(),
            watchdog_unit: None,
        });
        let effects = update(&mut s, UiAction::Tick);
        assert_eq!(
            effects
                .iter()
                .filter(|e| matches!(e, Effect::Apply(_)))
                .count(),
            1,
            "only the due countdown fires"
        );
        assert_eq!(
            s.pending_rollback.len(),
            1,
            "the live countdown is retained"
        );
        assert_eq!(s.pending_rollback[0].description, "live");
    }

    #[test]
    fn mutations_are_blocked_while_the_snapshot_is_stale() {
        use crate::application::ports::FirewallError;
        let mut s = state();
        // Last refresh failed → the snapshot on screen is stale.
        s.backend_error = Some(FirewallError::DaemonNotRunning);

        // Single-op path: refused, with a stale-data toast and no confirmation.
        let effects = request_operation(
            &mut s,
            FirewallOperation::SetDefaultZone {
                zone: ZoneName::parse("public").unwrap(),
            },
        );
        assert!(effects.is_empty(), "no mutation issued while stale");
        assert!(
            s.toasts.back().is_some_and(|t| t.text.contains("stale")),
            "operator is told why"
        );
        assert!(
            !matches!(s.overlays.last(), Some(Overlay::Confirm(_))),
            "no confirmation modal opens on stale data"
        );

        // Staged-plan path is gated too.
        s.staged.push(FirewallOperation::SetDefaultZone {
            zone: ZoneName::parse("public").unwrap(),
        });
        assert!(
            apply_staged_plan(&mut s).is_empty(),
            "staged plan refused while stale"
        );
        assert_eq!(s.staged.len(), 1, "the plan is preserved, not dropped");
    }

    #[test]
    fn invalid_staged_op_is_not_swallowed_as_satisfied() {
        let mut s = state();
        // A service edit against a zone that does not exist → UnknownZone, a
        // real error — NOT "already satisfied". It must surface, not vanish.
        s.staged.push(FirewallOperation::AddService {
            zone: ZoneName::parse("ghost").unwrap(),
            service: ServiceName::parse("https").unwrap(),
            target: ConfigurationTarget::RuntimeAndPermanent,
        });
        let effects = apply_staged_plan(&mut s);
        assert!(effects.is_empty(), "an invalid plan applies nothing");
        assert_eq!(s.staged.len(), 1, "plan stays staged to be fixed");
        assert!(
            s.toasts.back().is_some_and(|t| t.text.contains("invalid")),
            "the operator is told the plan is invalid, not that it was satisfied"
        );
    }

    #[test]
    fn every_applied_op_in_a_plan_is_queued_for_verification() {
        use crate::application::ports::{OperationOutcome, StepReport};
        let mut s = state();
        // Two applied operations back-to-back (a plan). Both must be queued for
        // postcondition verification — a single slot would keep only the last.
        for svc in ["mdns", "samba-client"] {
            update(
                &mut s,
                UiAction::OperationFinished {
                    op_id: 1,
                    outcome: OperationOutcome::Applied {
                        operation: FirewallOperation::AddService {
                            zone: ZoneName::parse("public").unwrap(),
                            service: ServiceName::parse(svc).unwrap(),
                            target: ConfigurationTarget::Runtime,
                        },
                        steps: vec![StepReport {
                            target: "runtime",
                            invocation: vec!["x".to_owned()],
                            result: Ok(()),
                        }],
                    },
                },
            );
        }
        assert_eq!(
            s.verify_next_refresh.len(),
            2,
            "both ops queued for verification, not just the last"
        );
    }

    #[test]
    fn yank_copies_the_richest_cell() {
        let mut s = state();
        update(&mut s, UiAction::SwitchView(ViewId::RichRules));
        let effects = update(&mut s, UiAction::YankRow);
        match &effects[..] {
            [Effect::CopyToClipboard(text)] => {
                assert!(text.contains("rule family"), "should copy the full rule");
            }
            other => panic!("expected clipboard effect, got {other:?}"),
        }
    }

    #[test]
    fn export_requires_staged_operations() {
        use crate::infrastructure::firewalld::command::ExportFormat;
        let mut s = state();
        update(&mut s, UiAction::ExportStagedPlan(ExportFormat::Script));
        assert_eq!(s.toasts.back().map(|t| t.kind), Some(ToastKind::Info));
        assert!(s.toasts.back().unwrap().text.contains("no staged"));
    }

    #[test]
    fn restore_requests_a_load_effect() {
        let mut s = state();
        s.snapshot = Some(std::sync::Arc::new(mock::sample().unwrap()));
        // With data, restore defers the read to the shell as an effect.
        let effects = restore_snapshot(&mut s, "snap.json");
        assert!(matches!(
            effects.as_slice(),
            [Effect::LoadSnapshotForRestore(name)] if name == "snap.json"
        ));
    }

    #[test]
    fn snapshot_load_failure_toasts_error() {
        let mut s = state();
        s.snapshot = Some(std::sync::Arc::new(mock::sample().unwrap()));
        update(
            &mut s,
            UiAction::SnapshotLoaded {
                name: "gone.json".to_owned(),
                result: Err("not found".to_owned()),
            },
        );
        assert_eq!(s.toasts.back().map(|t| t.kind), Some(ToastKind::Error));
    }

    #[test]
    fn browse_snapshots_requests_a_list_effect() {
        let mut s = state();
        // BrowseSnapshots defers the read; the overlay opens on SnapshotsListed.
        let effects = update(&mut s, UiAction::BrowseSnapshots);
        assert!(matches!(effects.as_slice(), [Effect::ListSnapshots]));
        update(&mut s, UiAction::SnapshotsListed(Vec::new()));
        assert!(matches!(s.overlays.last(), Some(Overlay::Details(_))));
    }

    #[test]
    fn save_snapshot_without_data_toasts() {
        let mut s = state();
        s.snapshot = None;
        update(&mut s, UiAction::SaveSnapshot);
        assert!(s.toasts.back().unwrap().text.contains("no data"));
    }

    #[test]
    fn operation_finished_records_audit() {
        use crate::application::ports::{OperationOutcome, StepReport};
        let mut s = state();
        update(
            &mut s,
            UiAction::OperationFinished {
                op_id: 1,
                outcome: OperationOutcome::Applied {
                    operation: FirewallOperation::Reload,
                    steps: vec![StepReport {
                        target: "global",
                        invocation: vec!["--reload".to_owned()],
                        result: Ok(()),
                    }],
                },
            },
        );
        assert_eq!(s.audit.len(), 1);
        assert_eq!(s.audit[0].status, "applied");
    }

    #[test]
    fn enter_on_zones_selects_zone() {
        let mut s = state();
        type_filter(&mut s, "dmz");
        update(&mut s, UiAction::InputSubmit);
        update(&mut s, UiAction::ActivateRow);
        assert_eq!(s.selected_zone.as_ref().unwrap().as_str(), "dmz");
    }
}
