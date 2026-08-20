//! Terminal lifecycle and the async event loop. The loop owns the `UiState`,
//! translates terminal and engine events into actions, runs the reducer, and
//! renders. All firewalld I/O happens in the engine task — this loop never
//! blocks on anything but the `select!` below.

pub mod action;
pub mod components;
pub mod details;
pub mod fuzzy;
pub mod keymap;
pub(super) mod outbox;
pub mod overlays;
pub mod palette;
pub mod render;
pub mod rich_builder;
pub mod search;
pub mod state;
pub mod theme;
pub mod update;
pub mod views;

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use crossterm::event::{Event, EventStream};
use futures_util::{Stream, StreamExt};

use tokio::sync::mpsc;

use crate::application::api::{EngineEvent, EngineHandle, RefreshPriority, RollbackRequest};
use crate::application::ports::FirewallError;
use crate::config::Config;
use crate::error::AppError;
use std::ops::ControlFlow;

use crate::domain::LogEntry;

use action::{Effect, UiAction};
use outbox::{EngineEffectDisposition, EngineOutbox, OutboxEnqueueError};
use state::UiState;
use theme::Theme;

const TICK_INTERVAL: Duration = Duration::from_millis(250);

/// Runs the TUI until quit. `ratatui::init` installs a panic hook that restores
/// the terminal, and `restore` runs on every exit path of this function.
pub async fn run(
    config: &Config,
    hostname: String,
    ssh_session: bool,
    ssh_interface: Option<crate::domain::InterfaceName>,
    engine: EngineHandle,
    logs: mpsc::Receiver<LogEntry>,
) -> Result<(), AppError> {
    let mut terminal = ratatui::init();
    let result = event_loop(
        &mut terminal,
        config,
        hostname,
        ssh_session,
        ssh_interface,
        engine,
        logs,
    )
    .await;
    ratatui::restore();
    result
}

#[allow(clippy::too_many_lines)] // one arm per effect; splitting hurts readability
async fn event_loop(
    terminal: &mut ratatui::DefaultTerminal,
    config: &Config,
    hostname: String,
    ssh_session: bool,
    ssh_interface: Option<crate::domain::InterfaceName>,
    mut engine: EngineHandle,
    mut logs: mpsc::Receiver<LogEntry>,
) -> Result<(), AppError> {
    let variant = theme::Variant::parse(&config.theme).unwrap_or(theme::Variant::Dracula);
    let theme = Theme::detect(variant, config.color);
    let mut state = UiState::new(config, hostname, ssh_session, ssh_interface);
    let mut events = EventStream::new();
    let mut tick = tokio::time::interval(TICK_INTERVAL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);
    let mut engine_alive = true;
    let mut specific_engine_error = None;
    let mut logs_alive = true;
    let mut log_batch: Vec<LogEntry> = Vec::new();
    let mut outbox = EngineOutbox::new();
    let mut published_priority = RefreshPriority::default();
    publish_refresh_priority(&engine, &state, &mut published_priority);

    loop {
        terminal.draw(|f| render::render(f, &mut state, &theme))?;

        let action = next_event_loop_action(
            ctrl_c.as_mut(),
            &mut engine,
            &mut outbox,
            &mut tick,
            &mut events,
            &state,
            &mut engine_alive,
            &mut specific_engine_error,
            &mut logs,
            &mut logs_alive,
            &mut log_batch,
        )
        .await?;

        let Some(action) = action else { continue };
        let control = process_action_worklist(
            &mut state,
            &mut outbox,
            std::collections::VecDeque::from([action]),
            config.retention,
        )
        .await;
        publish_refresh_priority(&engine, &state, &mut published_priority);
        if control.is_break() {
            // A clean quit must not abandon armed rollbacks: fire the inverses
            // and wait (bounded) for the engine to run them. Crash/SIGKILL/
            // connection-loss is covered by the out-of-process watchdog.
            drain_rollbacks_on_exit(&mut state, &mut outbox, &mut engine).await;
            return Ok(());
        }
    }
}

/// Polls one fair turn of the production event loop. Keeping the engine
/// dispatcher as one branch means a blocked sender never owns the shell.
#[allow(clippy::too_many_arguments)] // Explicitly borrows the independently-owned loop sources.
async fn next_event_loop_action<C, I>(
    mut ctrl_c: Pin<&mut C>,
    engine: &mut EngineHandle,
    outbox: &mut EngineOutbox,
    tick: &mut tokio::time::Interval,
    events: &mut I,
    state: &UiState,
    engine_alive: &mut bool,
    specific_engine_error: &mut Option<FirewallError>,
    logs: &mut mpsc::Receiver<LogEntry>,
    logs_alive: &mut bool,
    log_batch: &mut Vec<LogEntry>,
) -> Result<Option<UiAction>, AppError>
where
    C: Future<Output = std::io::Result<()>>,
    I: Stream<Item = std::io::Result<Event>> + Unpin,
{
    let can_dispatch = outbox.has_dispatchable();
    let action = tokio::select! {
        // SIGINT is the emergency exit — never gate it behind a modal.
        _ = &mut ctrl_c => Some(UiAction::QuitConfirmed),
        dispatch = outbox.dispatch_one(
            &engine.rollbacks,
            &engine.manual_refreshes,
            &engine.requests,
        ), if can_dispatch => {
            let action = dispatch.into_ui_action();
            if let UiAction::EngineStopped(error) = &action {
                // Buffered outcomes can remain after the engine drops its
                // senders, so keep draining events while preserving identity.
                *specific_engine_error = Some(error.clone());
            }
            Some(action)
        },
        event = engine.events.recv(), if *engine_alive => if let Some(event) = event {
            observe_engine_event(outbox, &event);
            Some(engine_event_action(event))
        } else {
            *engine_alive = false;
            Some(UiAction::EngineStopped(
                specific_engine_error.take().unwrap_or_else(|| FirewallError::Process(
                    "engine task stopped unexpectedly".to_owned(),
                )),
            ))
        },
        _ = tick.tick() => Some(UiAction::Tick),
        maybe_event = events.next() => match maybe_event {
            Some(Ok(Event::Key(key))) => keymap::translate(state, key),
            Some(Ok(Event::Resize(width, height))) => Some(UiAction::Resize(width, height)),
            Some(Ok(_)) => None,
            Some(Err(err)) => return Err(AppError::Terminal(err)),
            // Input stream gone: no terminal left to ask anything on.
            None => Some(UiAction::QuitConfirmed),
        },
        received = logs.recv_many(log_batch, 64), if *logs_alive => {
            if received == 0 {
                *logs_alive = false; // tailer ended; stop polling a closed channel
                None
            } else {
                Some(UiAction::LogsReceived(std::mem::take(log_batch)))
            }
        },
    };
    Ok(action)
}

fn observe_engine_event(outbox: &mut EngineOutbox, event: &EngineEvent) {
    if let EngineEvent::OperationFinished(result) = event
        && let Some(id) = result.completed_rollback
    {
        outbox.complete_rollback(id);
    }
}

/// Maps an engine event to the UI action that handles it.
fn engine_event_action(event: EngineEvent) -> UiAction {
    match event {
        EngineEvent::RefreshStarted { id, trigger } => UiAction::RefreshStarted { id, trigger },
        EngineEvent::RefreshOverviewReady { id, overview } => {
            UiAction::RefreshOverviewReady { id, overview }
        }
        EngineEvent::RefreshFinished {
            schedule,
            result,
            observation,
        } => UiAction::RefreshCompleted {
            schedule,
            result,
            observation,
        },
        EngineEvent::RefreshCancelled {
            schedule,
            reason,
            elapsed,
        } => UiAction::RefreshCancelled {
            schedule,
            reason,
            elapsed,
        },
        EngineEvent::ManualDemandRejected { count } => UiAction::ManualDemandRejected { count },
        EngineEvent::OperationFinished(result) => UiAction::OperationFinished(result),
        EngineEvent::PlanFinished {
            id,
            applied,
            remaining,
        } => UiAction::PlanFinished {
            id,
            applied,
            remaining,
        },
    }
}

/// Publishes only a changed latest-value hint; this never touches the engine outbox.
fn publish_refresh_priority(
    engine: &EngineHandle,
    state: &UiState,
    published: &mut RefreshPriority,
) {
    let next = state.refresh_priority();
    if next != *published {
        engine.refresh_priority.publish(next.clone());
        *published = next;
    }
}

/// Runs reducer follow-up actions without awaiting engine capacity. Engine-bound
/// effects move synchronously into the bounded shell outbox; only non-engine
/// effects are executed inline.
async fn process_action_worklist(
    state: &mut state::UiState,
    outbox: &mut EngineOutbox,
    mut pending: std::collections::VecDeque<UiAction>,
    retention: crate::config::RetentionConfig,
) -> ControlFlow<()> {
    while let Some(action) = pending.pop_front() {
        for effect in update::update(state, action) {
            let before = (outbox.normal_pending(), outbox.rollback_pending());
            match outbox::enqueue_engine_effect(outbox, effect) {
                Ok(EngineEffectDisposition::Queued) => {
                    let after = (outbox.normal_pending(), outbox.rollback_pending());
                    if after != before {
                        pending.push_back(UiAction::EngineOutboxChanged {
                            normal_pending: after.0,
                            rollback_pending: after.1,
                        });
                    }
                }
                Ok(EngineEffectDisposition::NotEngineBound(effect)) => {
                    if execute_effect(effect, state, &mut pending, retention)
                        .await
                        .is_break()
                    {
                        return ControlFlow::Break(());
                    }
                }
                Err(error) => surface_outbox_enqueue_error(state, error),
            }
        }
    }
    ControlFlow::Continue(())
}

fn surface_outbox_enqueue_error(state: &mut state::UiState, error: OutboxEnqueueError) {
    let message = match error {
        OutboxEnqueueError::Normal(outbox::NormalEnqueueError::Full(request)) => match request {
            crate::application::EngineRequest::Apply(request) => format!(
                "internal error: confirmed operation exceeded the UI outbox: {}",
                request.operation.describe()
            ),
            crate::application::EngineRequest::ApplyPlan(plan) => format!(
                "internal error: confirmed plan of {} operation(s) exceeded the UI outbox",
                plan.operations.len()
            ),
        },
        OutboxEnqueueError::Manual(outbox::ManualEnqueueError::CountOverflow) => {
            "manual refresh demand limit reached — request not queued".to_owned()
        }
        OutboxEnqueueError::Rollback(outbox::RollbackEnqueueError::Full(request)) => format!(
            "internal error: rollback safety outbox is full — rollback {} not queued: {}",
            request.id.get(),
            request.operation.describe()
        ),
    };
    tracing::error!(message, "bounded engine outbox rejected confirmed work");
    state.toast(state::ToastKind::Error, message);
}

/// Executes one effect. Reads run off the event-loop thread and feed their
/// result back as a follow-up action on `pending`. Returns `Break` only for
/// `Effect::Quit`, which the caller turns into a clean shutdown.
#[allow(clippy::too_many_lines)] // one arm per effect
async fn execute_effect(
    effect: Effect,
    state: &mut state::UiState,
    pending: &mut std::collections::VecDeque<UiAction>,
    retention: crate::config::RetentionConfig,
) -> ControlFlow<()> {
    match effect {
        Effect::Quit => return ControlFlow::Break(()),
        Effect::Refresh
        | Effect::Apply(_)
        | Effect::ApplyRollback { .. }
        | Effect::ApplyPlan(_) => {
            tracing::error!("engine-bound effect escaped the bounded UI outbox");
        }
        Effect::CopyToClipboard(text) => copy_to_clipboard(&text),
        Effect::SaveSnapshot(snapshot) => {
            // fsync + rename off the event-loop thread (matters on a slow home).
            let result = tokio::task::spawn_blocking(move || {
                crate::infrastructure::snapshot_store::save(&snapshot)
            })
            .await
            .unwrap_or_else(|join| Err(format!("snapshot task failed: {join}")));
            match result {
                Ok(path) => {
                    let prune = tokio::task::spawn_blocking(move || {
                        crate::infrastructure::retention::prune(
                            &retention,
                            crate::infrastructure::retention::RetentionScope::Snapshots,
                        )
                    })
                    .await
                    .unwrap_or_else(|join| Err(format!("snapshot retention task failed: {join}")));
                    surface_prune_result(state, "snapshot", prune);
                    state.toast(
                        state::ToastKind::Success,
                        format!("snapshot saved to {path}"),
                    );
                }
                Err(err) => {
                    state.toast(state::ToastKind::Error, format!("snapshot failed: {err}"));
                }
            }
        }
        Effect::ListSnapshots => {
            let entries = tokio::task::spawn_blocking(crate::infrastructure::snapshot_store::list)
                .await
                .unwrap_or_default();
            pending.push_back(UiAction::SnapshotsListed(entries));
        }
        Effect::LoadSnapshotForRestore(name) => {
            let loaded = tokio::task::spawn_blocking({
                let name = name.clone();
                move || crate::infrastructure::snapshot_store::load(&name)
            })
            .await
            .unwrap_or_else(|join| Err(format!("load task failed: {join}")));
            pending.push_back(UiAction::SnapshotLoaded {
                name,
                result: loaded.map(Box::new),
            });
        }
        Effect::LoadSnapshotForDiff(name) => {
            let loaded = tokio::task::spawn_blocking({
                let name = name.clone();
                move || crate::infrastructure::snapshot_store::load(&name)
            })
            .await
            .unwrap_or_else(|join| Err(format!("load task failed: {join}")));
            pending.push_back(UiAction::SnapshotDiffLoaded {
                name,
                result: loaded.map(Box::new),
            });
        }
        Effect::LoadCounters => {
            let result = crate::infrastructure::counters::read().await;
            pending.push_back(UiAction::CountersLoaded(result));
        }
        Effect::RecordAudit { op_id, outcome } => {
            let audit_retention = retention.audit;
            let result = tokio::task::spawn_blocking(move || {
                crate::infrastructure::audit::record(op_id, &outcome, audit_retention)
            })
            .await
            .unwrap_or_else(|join| Err(format!("audit task failed: {join}")));
            if let Err(err) = result {
                // An unrecorded mutation is an incident, not a debug line.
                state.toast(
                    state::ToastKind::Error,
                    format!("AUDIT WRITE FAILED: {err}"),
                );
            } else {
                let prune = tokio::task::spawn_blocking(move || {
                    crate::infrastructure::retention::prune(
                        &retention,
                        crate::infrastructure::retention::RetentionScope::Audit,
                    )
                })
                .await
                .unwrap_or_else(|join| Err(format!("audit retention task failed: {join}")));
                surface_prune_result(state, "audit", prune);
            }
        }
        Effect::ExportPlan(format, rendered) => {
            let result = tokio::task::spawn_blocking(move || {
                crate::infrastructure::export_write(format, &rendered)
            })
            .await
            .unwrap_or_else(|join| Err(format!("export task failed: {join}")));
            match result {
                Ok(path) => {
                    let prune = tokio::task::spawn_blocking(move || {
                        crate::infrastructure::retention::prune(
                            &retention,
                            crate::infrastructure::retention::RetentionScope::Exports,
                        )
                    })
                    .await
                    .unwrap_or_else(|join| Err(format!("export retention task failed: {join}")));
                    surface_prune_result(state, "export", prune);
                    state.toast(state::ToastKind::Success, format!("exported to {path}"));
                }
                Err(err) => state.toast(state::ToastKind::Error, format!("export failed: {err}")),
            }
        }
        Effect::DisarmWatchdog { unit } => {
            if let Err(error) = crate::infrastructure::rollback::disarm_watchdog(&unit).await {
                tracing::warn!(unit, error = %error, "failed to disarm rollback watchdog");
                state.toast(
                    state::ToastKind::Warning,
                    format!("could not disarm crash watchdog `{unit}`: {error}"),
                );
            }
        }
    }
    ControlFlow::Continue(())
}

fn surface_prune_result(
    state: &mut state::UiState,
    collection: &str,
    result: Result<crate::infrastructure::retention::PruneReport, String>,
) {
    match result {
        Ok(report) => {
            if !report.removed.is_empty() {
                tracing::info!(
                    collection,
                    removed = report.removed.len(),
                    reclaimed_bytes = report.reclaimed_bytes,
                    "retention pruned local state"
                );
            }
            if !report.failures.is_empty() {
                state.toast(
                    state::ToastKind::Warning,
                    format!(
                        "{collection} retention had {} cleanup failure(s)",
                        report.failures.len()
                    ),
                );
            }
        }
        Err(err) => state.toast(
            state::ToastKind::Warning,
            format!("{collection} retention check failed: {err}"),
        ),
    }
}

/// Fires every armed rollback inverse and waits (max ~5 s) for the engine to
/// report each finished, so quitting inside a dead-man's-switch window reverts
/// the risky change instead of abandoning it.
async fn drain_rollbacks_on_exit(
    state: &mut state::UiState,
    outbox: &mut EngineOutbox,
    engine: &mut EngineHandle,
) {
    if state.pending_rollback.is_empty()
        && outbox.rollback_pending() == 0
        && outbox.rollback_in_flight_ids().is_empty()
        && state.rollback_reservations == 0
    {
        return;
    }
    // Confirmed quit may abandon ordinary/manual work, but never lets either
    // class delay an already-armed safety inverse.
    if let Some(request) = outbox.abandon_non_rollbacks() {
        release_abandoned_request_reservations(state, request);
    }
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut expected = outbox.rollback_in_flight_ids();
    let mut completed = std::collections::HashSet::new();
    let mut deferred = std::collections::VecDeque::new();
    collect_armed_rollbacks(state, &mut deferred);
    fill_rollback_outbox(outbox, &mut deferred);

    while !deferred.is_empty()
        || outbox.rollback_pending() != 0
        || !expected.is_subset(&completed)
        || state.rollback_reservations != 0
    {
        if outbox.rollback_pending() != 0 && !outbox.has_dispatchable_rollback() {
            tracing::error!(
                pending = outbox.rollback_pending(),
                "clean exit could not deliver rollback: engine rollback lane is closed"
            );
            break;
        }
        let can_dispatch = outbox.has_dispatchable_rollback();
        tokio::select! {
            dispatch = outbox.dispatch_one(
                &engine.rollbacks,
                &engine.manual_refreshes,
                &engine.requests,
            ), if can_dispatch => {
                if let Some(id) = dispatch.rollback_id() {
                    expected.insert(id);
                } else if matches!(dispatch.kind(), outbox::DispatchKind::Rollback) {
                    tracing::error!(
                        pending = outbox.rollback_pending(),
                        "clean exit could not deliver rollback: engine rollback lane closed"
                    );
                }
                fill_rollback_outbox(outbox, &mut deferred);
            }
            event = engine.events.recv() => if let Some(event) = event {
                if let EngineEvent::OperationFinished(result) = &event
                    && let Some(id) = result.completed_rollback
                {
                    completed.insert(id);
                }
                observe_engine_event(outbox, &event);
                absorb_shutdown_engine_event(state, outbox, event, &mut deferred);
                collect_armed_rollbacks(state, &mut deferred);
                fill_rollback_outbox(outbox, &mut deferred);
            } else {
                tracing::error!("clean exit lost the engine event channel before rollback completion");
                break;
            },
            () = tokio::time::sleep_until(deadline) => {
                tracing::error!(
                    pending = outbox.rollback_pending(),
                    incomplete = expected.difference(&completed).count(),
                    "clean exit timed out waiting for rollback delivery"
                );
                break;
            }
        }
    }
}

fn release_abandoned_request_reservations(
    state: &mut UiState,
    request: crate::application::EngineRequest,
) {
    match request {
        crate::application::EngineRequest::Apply(request) => {
            let risky =
                state.rollback_ticks != 0 && request.operation.connectivity_warning().is_some();
            if risky && !update::consume_rollback_reservation(state) {
                tracing::error!(
                    operation = %request.operation.describe(),
                    "clean exit abandoned a risky request without its rollback reservation"
                );
            }
        }
        crate::application::EngineRequest::ApplyPlan(plan) => {
            let effects = update::update(
                state,
                UiAction::PlanFinished {
                    id: plan.id,
                    applied: 0,
                    remaining: plan.operations,
                },
            );
            if !effects.is_empty() {
                tracing::error!(
                    count = effects.len(),
                    "clean exit plan release unexpectedly produced effects"
                );
            }
        }
    }
}

fn absorb_shutdown_engine_event(
    state: &mut UiState,
    outbox: &mut EngineOutbox,
    event: EngineEvent,
    deferred: &mut std::collections::VecDeque<RollbackRequest>,
) {
    for effect in update::update(state, engine_event_action(event)) {
        match outbox::enqueue_engine_effect(outbox, effect) {
            Ok(EngineEffectDisposition::Queued | EngineEffectDisposition::NotEngineBound(_)) => {}
            Err(OutboxEnqueueError::Rollback(outbox::RollbackEnqueueError::Full(request))) => {
                // Keep the exact identity until an earlier rollback leaves the
                // bounded outbox; shutdown never turns overflow into loss.
                deferred.push_front(request);
            }
            Err(error) => surface_outbox_enqueue_error(state, error),
        }
    }
}

fn collect_armed_rollbacks(
    state: &mut UiState,
    deferred: &mut std::collections::VecDeque<RollbackRequest>,
) {
    let pending: Vec<_> = state.pending_rollback.drain(..).collect();
    for rollback in pending.into_iter().rev() {
        tracing::warn!(operation = %rollback.description, "quit inside rollback window — reverting");
        deferred.push_back(RollbackRequest {
            id: rollback.id,
            operation: rollback.inverse,
            watchdog_unit: rollback.watchdog_unit,
        });
    }
}

fn fill_rollback_outbox(
    outbox: &mut EngineOutbox,
    deferred: &mut std::collections::VecDeque<RollbackRequest>,
) {
    while let Some(request) = deferred.pop_front() {
        match outbox.enqueue_rollback(request) {
            Ok(()) => {}
            Err(outbox::RollbackEnqueueError::Full(request)) => {
                deferred.push_front(request);
                break;
            }
        }
    }
}

/// Copies `text` to the system clipboard via the OSC 52 escape sequence, which
/// terminals forward to the local clipboard even over SSH. Best-effort: a
/// terminal that ignores OSC 52 simply does nothing.
fn copy_to_clipboard(text: &str) {
    use std::io::Write as _;
    let encoded = base64_encode(text.as_bytes());
    let mut stdout = std::io::stdout();
    // ESC ] 52 ; c ; <base64> BEL
    let _ = write!(stdout, "\x1b]52;c;{encoded}\x07");
    let _ = stdout.flush();
}

/// Minimal standard base64 (no dependency — clipboard is the only user).
fn base64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = chunk.get(1).copied().unwrap_or(0) as usize;
        let b2 = chunk.get(2).copied().unwrap_or(0) as usize;
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(triple >> 18) & 0x3f] as char);
        out.push(ALPHABET[(triple >> 12) & 0x3f] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(triple >> 6) & 0x3f] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[triple & 0x3f] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use std::collections::VecDeque;
    use std::num::NonZeroU64;
    use std::ops::ControlFlow;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use crossterm::event::Event;
    use tokio::sync::{Semaphore, mpsc};

    use crate::application::api::REQUEST_CAPACITY;
    use crate::application::ports::{
        FirewallBackend, FirewallError, OperationOutcome, RollbackGuard, RollbackGuardError,
        RollbackGuardId, SnapshotRead, StepReport,
    };
    use crate::application::{
        EngineEvent, EngineHandle, EngineRequest, ManualRefreshRequest, MutationRequest,
        RefreshCancellationReason, RefreshId, RefreshScheduleObservation, RefreshTrigger,
        RollbackRequest,
    };
    use crate::config::Config;
    use crate::domain::{
        ConfigurationTarget, FirewallOperation, FirewallSnapshot, FirewallStatus,
        RefreshObservation, ServiceName, ZoneName, mock,
    };
    use crate::ui::action::UiAction;
    use crate::ui::outbox::{DispatchKind, EngineOutbox};
    use crate::ui::state::{PendingRollback, UiState};

    use super::{
        TICK_INTERVAL, base64_encode, drain_rollbacks_on_exit, engine_event_action,
        next_event_loop_action, process_action_worklist, publish_refresh_priority,
    };

    struct TestRollbackGuard;

    impl RollbackGuard for TestRollbackGuard {
        async fn arm(
            &self,
            _id: RollbackGuardId,
            _operation: &FirewallOperation,
            _delay: Duration,
        ) -> Result<Option<String>, RollbackGuardError> {
            Ok(None)
        }

        async fn disarm(&self, _unit: &str) -> Result<(), RollbackGuardError> {
            Ok(())
        }
    }

    struct ActiveSnapshotGuard {
        active: Arc<AtomicUsize>,
    }

    impl Drop for ActiveSnapshotGuard {
        fn drop(&mut self) {
            self.active.fetch_sub(1, Ordering::SeqCst);
        }
    }

    #[derive(Clone)]
    struct ControlledSnapshotBackend {
        active_snapshots: Arc<AtomicUsize>,
        snapshot_calls: Arc<AtomicUsize>,
        snapshot_started: Arc<Semaphore>,
        snapshot_release: Arc<Semaphore>,
        active_snapshots_at_apply: Arc<Mutex<Vec<usize>>>,
        applied_operations: Arc<Mutex<Vec<FirewallOperation>>>,
    }

    impl ControlledSnapshotBackend {
        fn new() -> Self {
            Self {
                active_snapshots: Arc::new(AtomicUsize::new(0)),
                snapshot_calls: Arc::new(AtomicUsize::new(0)),
                snapshot_started: Arc::new(Semaphore::new(0)),
                snapshot_release: Arc::new(Semaphore::new(0)),
                active_snapshots_at_apply: Arc::new(Mutex::new(Vec::new())),
                applied_operations: Arc::new(Mutex::new(Vec::new())),
            }
        }

        async fn wait_for_snapshot_start(&self) {
            tokio::time::timeout(Duration::from_secs(1), self.snapshot_started.acquire())
                .await
                .unwrap()
                .unwrap()
                .forget();
        }

        fn release_snapshot(&self) {
            self.snapshot_release.add_permits(1);
        }
    }

    impl FirewallBackend for ControlledSnapshotBackend {
        async fn probe(&self) -> Result<FirewallStatus, FirewallError> {
            Err(FirewallError::DaemonNotRunning)
        }

        async fn snapshot(&self) -> Result<FirewallSnapshot, FirewallError> {
            mock::sample().map_err(|error| FirewallError::Parse(error.to_string()))
        }

        fn snapshot_observed(&self) -> impl std::future::Future<Output = SnapshotRead> + Send {
            let active = Arc::clone(&self.active_snapshots);
            let calls = Arc::clone(&self.snapshot_calls);
            let started = Arc::clone(&self.snapshot_started);
            let release = Arc::clone(&self.snapshot_release);
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                active.fetch_add(1, Ordering::SeqCst);
                let _guard = ActiveSnapshotGuard { active };
                started.add_permits(1);
                release.acquire().await.unwrap().forget();
                SnapshotRead {
                    result: mock::sample().map_err(|error| FirewallError::Parse(error.to_string())),
                    observation: RefreshObservation::total_only(Duration::ZERO),
                }
            }
        }

        async fn apply(&self, operation: &FirewallOperation) -> OperationOutcome {
            self.active_snapshots_at_apply
                .lock()
                .unwrap()
                .push(self.active_snapshots.load(Ordering::SeqCst));
            self.applied_operations
                .lock()
                .unwrap()
                .push(operation.clone());
            OperationOutcome::Applied {
                operation: operation.clone(),
                steps: vec![StepReport {
                    target: "runtime",
                    invocation: vec!["--fake".to_owned()],
                    result: Ok(()),
                }],
            }
        }
    }

    #[derive(Clone)]
    struct ControlledApplyBackend {
        apply_calls: Arc<AtomicUsize>,
        first_apply_started: Arc<Semaphore>,
        first_apply_release: Arc<Semaphore>,
        applied_operations: Arc<Mutex<Vec<FirewallOperation>>>,
    }

    impl ControlledApplyBackend {
        fn new() -> Self {
            Self {
                apply_calls: Arc::new(AtomicUsize::new(0)),
                first_apply_started: Arc::new(Semaphore::new(0)),
                first_apply_release: Arc::new(Semaphore::new(0)),
                applied_operations: Arc::new(Mutex::new(Vec::new())),
            }
        }

        async fn wait_for_first_apply(&self) {
            tokio::time::timeout(Duration::from_secs(1), self.first_apply_started.acquire())
                .await
                .unwrap()
                .unwrap()
                .forget();
        }

        fn release_first_apply(&self) {
            self.first_apply_release.add_permits(1);
        }
    }

    impl FirewallBackend for ControlledApplyBackend {
        async fn probe(&self) -> Result<FirewallStatus, FirewallError> {
            Err(FirewallError::DaemonNotRunning)
        }

        async fn snapshot(&self) -> Result<FirewallSnapshot, FirewallError> {
            mock::sample().map_err(|error| FirewallError::Parse(error.to_string()))
        }

        async fn apply(&self, operation: &FirewallOperation) -> OperationOutcome {
            if self.apply_calls.fetch_add(1, Ordering::SeqCst) == 0 {
                self.first_apply_started.add_permits(1);
                self.first_apply_release.acquire().await.unwrap().forget();
            }
            self.applied_operations
                .lock()
                .unwrap()
                .push(operation.clone());
            OperationOutcome::Applied {
                operation: operation.clone(),
                steps: vec![StepReport {
                    target: "runtime",
                    invocation: vec!["--fake".to_owned()],
                    result: Ok(()),
                }],
            }
        }
    }

    fn reviewed(operation: FirewallOperation) -> MutationRequest {
        MutationRequest::new(operation, Arc::new(mock::sample().unwrap()))
    }

    fn numbered_port_operation(index: usize) -> FirewallOperation {
        FirewallOperation::AddPort {
            zone: ZoneName::parse("public").unwrap(),
            port: format!("{}/tcp", 40_000 + index).parse().unwrap(),
            target: ConfigurationTarget::Runtime,
        }
    }

    async fn process_action(state: &mut UiState, outbox: &mut EngineOutbox, action: UiAction) {
        assert_eq!(
            process_action_worklist(
                state,
                outbox,
                VecDeque::from([action]),
                Config::default().retention,
            )
            .await,
            ControlFlow::Continue(())
        );
    }

    async fn recv_event(engine: &mut EngineHandle) -> EngineEvent {
        tokio::time::timeout(Duration::from_secs(1), engine.events.recv())
            .await
            .unwrap()
            .unwrap()
    }

    #[test]
    fn base64_matches_known_vectors() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn manual_demand_rejection_maps_to_notification_action() {
        use crate::application::EngineEvent;
        use crate::ui::action::UiAction;
        use std::num::NonZeroU64;

        let count = NonZeroU64::new(7).unwrap();
        assert_eq!(
            engine_event_action(EngineEvent::ManualDemandRejected { count }),
            UiAction::ManualDemandRejected { count }
        );
    }

    #[test]
    fn plan_finished_preserves_identity() {
        let id = crate::application::PlanId::new(23);

        assert!(matches!(
            engine_event_action(EngineEvent::PlanFinished {
                id,
                applied: 2,
                remaining: Vec::new(),
            }),
            UiAction::PlanFinished {
                id: mapped,
                applied: 2,
                remaining,
            } if mapped == id && remaining.is_empty()
        ));
    }

    #[test]
    fn overview_event_maps_without_blocking_the_following_engine_event() {
        let snapshot = mock::sample().unwrap();
        let overview = crate::application::RefreshOverview {
            status: snapshot.status,
            default_zone: snapshot.default_zone,
            active: snapshot.active,
            runtime: snapshot.runtime,
            permanent: snapshot.permanent,
            available_services: snapshot.available_services,
            policy_names: crate::domain::Scoped {
                runtime: snapshot.policies.runtime.into_keys().collect(),
                permanent: snapshot.policies.permanent.into_keys().collect(),
            },
            degraded: snapshot.degraded,
        };
        let count = NonZeroU64::new(7).unwrap();

        let overview = Arc::new(overview);
        assert_eq!(
            engine_event_action(EngineEvent::RefreshOverviewReady {
                id: RefreshId::new(1),
                overview: Arc::clone(&overview),
            }),
            UiAction::RefreshOverviewReady {
                id: RefreshId::new(1),
                overview,
            }
        );
        assert_eq!(
            engine_event_action(EngineEvent::ManualDemandRejected { count }),
            UiAction::ManualDemandRejected { count }
        );
    }

    #[test]
    fn selection_updates_replace_the_engine_priority_without_queueing() {
        let config = Config::default();
        let mut state = UiState::new(&config, "test".to_owned(), false, None);
        state.snapshot = Some(Arc::new(mock::sample().unwrap()));
        state.view = crate::ui::views::ViewId::Services;
        state.selected_zone = Some(ZoneName::parse("public").unwrap());
        state.view_state_mut().selected = state
            .visible_rows()
            .iter()
            .position(|row| matches!(&row.id, crate::ui::views::RowId::Service { service, .. } if service.as_str() == "http"))
            .unwrap();
        let (refresh_priority, source) = crate::application::refresh_priority_channel();
        let (request_tx, _request_rx) = mpsc::channel(1);
        let (manual_tx, _manual_rx) = mpsc::channel(1);
        let (rollback_tx, _rollback_rx) = mpsc::channel(1);
        let (_event_tx, event_rx) = mpsc::channel(1);
        let engine = EngineHandle {
            requests: request_tx,
            manual_refreshes: manual_tx,
            rollbacks: rollback_tx,
            events: event_rx,
            refresh_priority,
        };
        let mut published = crate::application::RefreshPriority::default();
        let lane_capacities = (
            engine.requests.capacity(),
            engine.manual_refreshes.capacity(),
            engine.rollbacks.capacity(),
        );

        publish_refresh_priority(&engine, &state, &mut published);
        assert_eq!(
            source
                .latest()
                .service
                .as_ref()
                .map(crate::domain::ServiceName::as_str),
            Some("http")
        );
        assert_eq!(
            source.latest().zone,
            Some(ZoneName::parse("public").unwrap())
        );
        state.view = crate::ui::views::ViewId::Policies;
        state.selected_zone = Some(ZoneName::parse("work").unwrap());
        publish_refresh_priority(&engine, &state, &mut published);

        assert_eq!(source.latest(), state.refresh_priority());
        assert_eq!(source.latest().zone, Some(ZoneName::parse("work").unwrap()));
        assert_eq!(
            source
                .latest()
                .policy
                .as_ref()
                .map(crate::domain::PolicyName::as_str),
            Some("mypolicy")
        );
        assert_eq!(
            (
                engine.requests.capacity(),
                engine.manual_refreshes.capacity(),
                engine.rollbacks.capacity(),
            ),
            lane_capacities
        );
    }

    #[tokio::test]
    async fn manual_batch_dispatches_during_normal_backpressure() {
        let config = Config::default();
        let mut state = UiState::new(&config, "test".to_owned(), false, None);
        state.snapshot = Some(Arc::new(mock::sample().unwrap()));
        let mut outbox = EngineOutbox::new();
        let (request_tx, _request_rx) = mpsc::channel(1);
        request_tx
            .send(EngineRequest::Apply(reviewed(FirewallOperation::Reload)))
            .await
            .unwrap();
        let (manual_tx, mut manual_rx) = tokio::sync::mpsc::channel(1);
        let (rollback_tx, _rollback_rx) = mpsc::channel(1);

        process_action(
            &mut state,
            &mut outbox,
            UiAction::ApplyOperation(reviewed(numbered_port_operation(100))),
        )
        .await;
        assert!(state.engine_normal_backpressured);
        for _ in 0..7 {
            process_action(&mut state, &mut outbox, UiAction::RefreshRequested).await;
        }

        let dispatch = tokio::time::timeout(
            Duration::from_secs(1),
            outbox.dispatch_one(&rollback_tx, &manual_tx, &request_tx),
        )
        .await
        .unwrap();
        assert_eq!(dispatch.kind(), DispatchKind::Manual);
        process_action(&mut state, &mut outbox, dispatch.into_ui_action()).await;
        assert_eq!(
            manual_rx.recv().await.map(ManualRefreshRequest::count),
            NonZeroU64::new(7)
        );
        assert!(outbox.normal_pending());
        assert!(state.engine_normal_backpressured);
    }

    #[allow(clippy::too_many_lines)]
    #[tokio::test]
    async fn closed_outbox_lane_surfaces_engine_stopped_without_silent_loss() {
        let config = Config::default();
        let mut state = UiState::new(&config, "test".to_owned(), false, None);
        let mut outbox = EngineOutbox::new();
        let (request_tx, request_rx) = mpsc::channel(1);
        let (manual_tx, _manual_rx) = mpsc::channel(1);
        let (rollback_tx, _rollback_rx) = mpsc::channel(1);
        let (event_tx, event_rx) = mpsc::channel(2);
        let (refresh_priority, _refresh_priority_source) =
            crate::application::refresh_priority_channel();
        let mut engine = EngineHandle {
            requests: request_tx,
            manual_refreshes: manual_tx,
            rollbacks: rollback_tx,
            events: event_rx,
            refresh_priority,
        };

        let waiting = numbered_port_operation(200);
        process_action(
            &mut state,
            &mut outbox,
            UiAction::ApplyOperation(reviewed(waiting.clone())),
        )
        .await;
        drop(request_rx);

        let ctrl_c = std::future::pending::<std::io::Result<()>>();
        tokio::pin!(ctrl_c);
        let mut input = futures_util::stream::pending::<std::io::Result<Event>>();
        let mut tick = tokio::time::interval_at(
            tokio::time::Instant::now() + Duration::from_secs(60),
            Duration::from_secs(60),
        );
        let (_log_tx, mut log_rx) = mpsc::channel(1);
        let mut engine_alive = true;
        let mut specific_engine_error = None;
        let mut logs_alive = true;
        let mut log_batch = Vec::new();
        let action = tokio::time::timeout(
            Duration::from_secs(1),
            next_event_loop_action(
                ctrl_c.as_mut(),
                &mut engine,
                &mut outbox,
                &mut tick,
                &mut input,
                &state,
                &mut engine_alive,
                &mut specific_engine_error,
                &mut log_rx,
                &mut logs_alive,
                &mut log_batch,
            ),
        )
        .await
        .unwrap()
        .unwrap()
        .unwrap();
        process_action(&mut state, &mut outbox, action).await;

        assert!(matches!(
            state.backend_error.as_ref(),
            Some(FirewallError::Process(message))
                if message.contains("operation") && message.contains(&waiting.describe())
        ));
        assert!(
            outbox.normal_pending(),
            "confirmed identity must be retained"
        );
        assert!(
            !outbox.has_dispatchable(),
            "the closed lane must not be polled again"
        );
        assert!(engine_alive, "buffered engine events must remain drainable");
        assert!(matches!(
            specific_engine_error.as_ref(),
            Some(FirewallError::Process(message)) if message.contains(&waiting.describe())
        ));

        let refresh_id = RefreshId::new(77);
        event_tx
            .send(EngineEvent::RefreshStarted {
                id: refresh_id,
                trigger: RefreshTrigger::Periodic,
            })
            .await
            .unwrap();
        event_tx
            .send(EngineEvent::RefreshFinished {
                schedule: RefreshScheduleObservation {
                    id: refresh_id,
                    trigger: RefreshTrigger::Periodic,
                    merged_manual_requests: 0,
                    coalesced_periodic_ticks: 0,
                },
                result: mock::sample()
                    .map(Arc::new)
                    .map(|snapshot| {
                        crate::application::ObservedSnapshot::new(
                            crate::application::SnapshotIdentity::new(
                                refresh_id,
                                crate::application::SnapshotGeneration::new(
                                    std::num::NonZeroU64::MIN,
                                ),
                            ),
                            snapshot,
                        )
                    })
                    .map_err(|error| FirewallError::Parse(error.to_string())),
                observation: RefreshObservation::total_only(Duration::ZERO),
            })
            .await
            .unwrap();
        drop(event_tx);
        for _ in 0..3 {
            let action = tokio::time::timeout(
                Duration::from_secs(1),
                next_event_loop_action(
                    ctrl_c.as_mut(),
                    &mut engine,
                    &mut outbox,
                    &mut tick,
                    &mut input,
                    &state,
                    &mut engine_alive,
                    &mut specific_engine_error,
                    &mut log_rx,
                    &mut logs_alive,
                    &mut log_batch,
                ),
            )
            .await
            .unwrap()
            .unwrap();
            if let Some(action) = action {
                process_action(&mut state, &mut outbox, action).await;
            }
        }
        assert!(!engine_alive);
        assert!(matches!(
            state.backend_error.as_ref(),
            Some(FirewallError::Process(message)) if message.contains(&waiting.describe())
        ));
    }

    #[allow(clippy::too_many_lines)]
    #[tokio::test(start_paused = true)]
    async fn tick_dispatches_rollback_while_normal_outbox_waits_on_full_engine() {
        let config = Config::default();
        let mut state = UiState::new(&config, "test".to_owned(), false, None);
        state.snapshot = Some(Arc::new(mock::sample().unwrap()));
        let backend = ControlledSnapshotBackend::new();
        let mut engine = crate::application::api::spawn(
            backend.clone(),
            TestRollbackGuard,
            Duration::from_secs(3_600),
            false,
            Duration::from_secs(30),
        );
        let mut outbox = EngineOutbox::new();

        assert!(matches!(
            recv_event(&mut engine).await,
            EngineEvent::RefreshStarted {
                trigger: RefreshTrigger::Initial,
                ..
            }
        ));
        backend.wait_for_snapshot_start().await;

        let first = FirewallOperation::Reload;
        engine
            .requests
            .send(EngineRequest::Apply(reviewed(first.clone())))
            .await
            .unwrap();
        assert!(matches!(
            recv_event(&mut engine).await,
            EngineEvent::RefreshCancelled {
                reason: RefreshCancellationReason::MutationPreempted,
                ..
            }
        ));
        assert!(matches!(
            recv_event(&mut engine).await,
            EngineEvent::OperationFinished(result)
                if result.outcome.operation() == &first
        ));
        assert!(matches!(
            recv_event(&mut engine).await,
            EngineEvent::RefreshStarted {
                trigger: RefreshTrigger::PostMutation,
                ..
            }
        ));
        backend.wait_for_snapshot_start().await;

        let earlier: Vec<_> = (0..REQUEST_CAPACITY * 2)
            .map(numbered_port_operation)
            .collect();
        tokio::time::timeout(Duration::from_secs(1), async {
            for operation in &earlier {
                engine
                    .requests
                    .send(EngineRequest::Apply(reviewed(operation.clone())))
                    .await
                    .unwrap();
            }
        })
        .await
        .unwrap();
        // With the mandatory read blocked, accepting exactly twice the shared
        // bound proves 32 requests reached the local FIFO and 32 fill the lane.
        assert_eq!(engine.requests.capacity(), 0);

        let waiting = numbered_port_operation(REQUEST_CAPACITY * 2);
        process_action(
            &mut state,
            &mut outbox,
            UiAction::ApplyOperation(reviewed(waiting.clone())),
        )
        .await;
        assert!(outbox.normal_pending());
        assert!(state.engine_normal_backpressured);

        let rollback_id = RollbackGuardId::new(9_001);
        let rollback = FirewallOperation::AddService {
            zone: ZoneName::parse("public").unwrap(),
            service: ServiceName::parse("ssh").unwrap(),
            target: ConfigurationTarget::Runtime,
        };
        let forward = rollback.inverse().unwrap();
        state.pending_rollback.push(PendingRollback {
            id: rollback_id,
            forward,
            inverse: rollback.clone(),
            deadline_tick: 1,
            description: "test connectivity rollback".to_owned(),
            watchdog_unit: None,
        });

        let mut tick =
            tokio::time::interval_at(tokio::time::Instant::now() + TICK_INTERVAL, TICK_INTERVAL);
        let ctrl_c = std::future::pending::<std::io::Result<()>>();
        tokio::pin!(ctrl_c);
        let mut input = futures_util::stream::pending::<std::io::Result<Event>>();
        let (_log_tx, mut log_rx) = mpsc::channel(1);
        let mut engine_alive = true;
        let mut specific_engine_error = None;
        let mut logs_alive = true;
        let mut log_batch = Vec::new();
        tokio::time::advance(TICK_INTERVAL).await;
        let action = tokio::time::timeout(
            Duration::from_secs(1),
            next_event_loop_action(
                ctrl_c.as_mut(),
                &mut engine,
                &mut outbox,
                &mut tick,
                &mut input,
                &state,
                &mut engine_alive,
                &mut specific_engine_error,
                &mut log_rx,
                &mut logs_alive,
                &mut log_batch,
            ),
        )
        .await
        .unwrap()
        .unwrap()
        .unwrap();
        assert_eq!(action, UiAction::Tick);
        process_action(&mut state, &mut outbox, action).await;
        assert!(state.pending_rollback.is_empty());
        assert_eq!(outbox.rollback_pending(), 1);
        assert!(outbox.normal_pending());
        assert_eq!(engine.requests.capacity(), 0);

        let action = tokio::time::timeout(
            Duration::from_secs(1),
            next_event_loop_action(
                ctrl_c.as_mut(),
                &mut engine,
                &mut outbox,
                &mut tick,
                &mut input,
                &state,
                &mut engine_alive,
                &mut specific_engine_error,
                &mut log_rx,
                &mut logs_alive,
                &mut log_batch,
            ),
        )
        .await
        .unwrap()
        .unwrap()
        .unwrap();
        process_action(&mut state, &mut outbox, action).await;
        assert!(outbox.normal_pending());
        assert_eq!(engine.requests.capacity(), 0);

        assert!(matches!(
            recv_event(&mut engine).await,
            EngineEvent::RefreshCancelled {
                reason: RefreshCancellationReason::RollbackPreempted,
                ..
            }
        ));
        assert!(matches!(
            recv_event(&mut engine).await,
            EngineEvent::OperationFinished(result)
                if result.completed_rollback == Some(rollback_id)
                    && result.outcome.operation() == &rollback
        ));
        assert_eq!(backend.active_snapshots_at_apply.lock().unwrap()[1], 0);
        assert_eq!(
            *backend.applied_operations.lock().unwrap(),
            [first.clone(), rollback.clone()]
        );

        assert!(matches!(
            recv_event(&mut engine).await,
            EngineEvent::RefreshStarted {
                trigger: RefreshTrigger::PostMutation,
                ..
            }
        ));
        backend.wait_for_snapshot_start().await;
        assert_eq!(backend.snapshot_calls.load(Ordering::SeqCst), 3);
        backend.release_snapshot();
        assert!(matches!(
            recv_event(&mut engine).await,
            EngineEvent::RefreshFinished {
                schedule,
                result: Ok(_),
                ..
            } if schedule.trigger == RefreshTrigger::PostMutation
        ));

        // The first queued request must leave the engine channel before the
        // waiting UI request can reserve its slot. Its completion may race
        // that reserve, so absorb either order without consuming later proof.
        let mut first_queued_result = None;
        let mut first_refresh_started = false;
        for _ in 0..8 {
            let action = tokio::time::timeout(
                Duration::from_secs(1),
                next_event_loop_action(
                    ctrl_c.as_mut(),
                    &mut engine,
                    &mut outbox,
                    &mut tick,
                    &mut input,
                    &state,
                    &mut engine_alive,
                    &mut specific_engine_error,
                    &mut log_rx,
                    &mut logs_alive,
                    &mut log_batch,
                ),
            )
            .await
            .unwrap()
            .unwrap()
            .unwrap();
            match action {
                UiAction::EngineOutboxChanged { .. } => {
                    process_action(&mut state, &mut outbox, action).await;
                    if !outbox.normal_pending() {
                        break;
                    }
                }
                UiAction::OperationFinished(result)
                    if result.outcome.operation() == &earlier[0]
                        && result.completed_rollback.is_none() =>
                {
                    process_action(
                        &mut state,
                        &mut outbox,
                        UiAction::OperationFinished(result.clone()),
                    )
                    .await;
                    first_queued_result = Some(result);
                }
                action @ UiAction::RefreshStarted {
                    trigger: RefreshTrigger::PostMutation,
                    ..
                } => {
                    process_action(&mut state, &mut outbox, action).await;
                    first_refresh_started = true;
                }
                action => panic!("normal dispatch was unexpectedly preceded by {action:?}"),
            }
        }
        assert!(!outbox.normal_pending());
        assert!(!state.engine_normal_backpressured);

        let mut all_normal = earlier.clone();
        all_normal.push(waiting.clone());
        for (index, expected) in all_normal.iter().enumerate() {
            if index == 0 {
                if let Some(result) = first_queued_result.take() {
                    assert_eq!(result.outcome.operation(), expected);
                    assert!(result.completed_rollback.is_none());
                } else {
                    assert!(matches!(
                        recv_event(&mut engine).await,
                        EngineEvent::OperationFinished(result)
                            if result.outcome.operation() == expected
                                && result.completed_rollback.is_none()
                    ));
                }
            } else {
                assert!(matches!(
                    recv_event(&mut engine).await,
                    EngineEvent::OperationFinished(result)
                        if result.outcome.operation() == expected
                            && result.completed_rollback.is_none()
                ));
            }
            if index == 0 && first_refresh_started {
                first_refresh_started = false;
            } else {
                assert!(matches!(
                    recv_event(&mut engine).await,
                    EngineEvent::RefreshStarted {
                        trigger: RefreshTrigger::PostMutation,
                        ..
                    }
                ));
            }
            backend.wait_for_snapshot_start().await;
            backend.release_snapshot();
            assert!(matches!(
                recv_event(&mut engine).await,
                EngineEvent::RefreshFinished {
                    schedule,
                    result: Ok(_),
                    ..
                } if schedule.trigger == RefreshTrigger::PostMutation
            ));
        }

        let mut expected = vec![first, rollback.clone()];
        expected.extend(all_normal);
        assert_eq!(*backend.applied_operations.lock().unwrap(), expected);
        assert_eq!(
            backend
                .applied_operations
                .lock()
                .unwrap()
                .iter()
                .filter(|operation| *operation == &rollback)
                .count(),
            1
        );
        assert!(
            backend
                .active_snapshots_at_apply
                .lock()
                .unwrap()
                .iter()
                .all(|active| *active == 0)
        );
        assert_eq!(
            backend.snapshot_calls.load(Ordering::SeqCst),
            3 + REQUEST_CAPACITY * 2 + 1
        );
    }

    #[tokio::test]
    async fn clean_exit_rolls_back_unobserved_risky_forward_completion() {
        let config = Config::default();
        let mut state = UiState::new(&config, "test".to_owned(), false, None);
        state.snapshot = Some(Arc::new(mock::sample().unwrap()));
        let backend = ControlledApplyBackend::new();
        let mut engine = crate::application::api::spawn(
            backend.clone(),
            TestRollbackGuard,
            Duration::from_secs(3_600),
            false,
            Duration::from_secs(30),
        );
        let mut outbox = EngineOutbox::new();

        assert!(matches!(
            recv_event(&mut engine).await,
            EngineEvent::RefreshStarted {
                trigger: RefreshTrigger::Initial,
                ..
            }
        ));
        assert!(matches!(
            recv_event(&mut engine).await,
            EngineEvent::RefreshFinished { result: Ok(_), .. }
        ));

        let forward = FirewallOperation::SetPanicMode { enabled: true };
        let inverse = forward.inverse().unwrap();
        process_action(
            &mut state,
            &mut outbox,
            UiAction::ApplyOperation(reviewed(forward.clone())),
        )
        .await;
        assert_eq!(state.rollback_reservations, 1);

        let dispatch = tokio::time::timeout(
            Duration::from_secs(1),
            outbox.dispatch_one(
                &engine.rollbacks,
                &engine.manual_refreshes,
                &engine.requests,
            ),
        )
        .await
        .unwrap();
        process_action(&mut state, &mut outbox, dispatch.into_ui_action()).await;
        backend.wait_for_first_apply().await;

        // Simulate Ctrl-C while the forward outcome has not been consumed by
        // the UI. With no external watchdog, shutdown must recover its inverse.
        backend.release_first_apply();
        tokio::time::timeout(
            Duration::from_secs(2),
            drain_rollbacks_on_exit(&mut state, &mut outbox, &mut engine),
        )
        .await
        .unwrap();

        assert_eq!(state.rollback_reservations, 0);
        assert!(state.pending_rollback.is_empty());
        assert_eq!(outbox.rollback_pending(), 0);
        assert_eq!(
            *backend.applied_operations.lock().unwrap(),
            [forward, inverse.clone()]
        );
        assert_eq!(
            backend
                .applied_operations
                .lock()
                .unwrap()
                .iter()
                .filter(|operation| *operation == &inverse)
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn clean_exit_waits_for_the_matching_rollback_id() {
        let forward = FirewallOperation::RemovePort {
            zone: ZoneName::parse("public").unwrap(),
            port: "8080/tcp".parse().unwrap(),
            target: ConfigurationTarget::Runtime,
        };
        let inverse = forward.inverse().unwrap();
        let rollback_id = RollbackGuardId::new(42);
        let mut state = UiState::new(&Config::default(), "test".to_owned(), false, None);
        state.pending_rollback.push(PendingRollback {
            id: rollback_id,
            forward,
            inverse: inverse.clone(),
            deadline_tick: 100,
            description: "test rollback".to_owned(),
            watchdog_unit: None,
        });

        let (request_tx, _request_rx) = tokio::sync::mpsc::channel(1);
        let (manual_tx, _manual_rx) = tokio::sync::mpsc::channel(1);
        let (rollback_tx, mut rollback_rx) = tokio::sync::mpsc::channel(1);
        let (event_tx, event_rx) = tokio::sync::mpsc::channel(4);
        let (refresh_priority, _refresh_priority_source) =
            crate::application::refresh_priority_channel();
        let mut engine = EngineHandle {
            requests: request_tx,
            manual_refreshes: manual_tx,
            rollbacks: rollback_tx,
            events: event_rx,
            refresh_priority,
        };
        let mut outbox = EngineOutbox::new();
        let responder = tokio::spawn(async move {
            let request = rollback_rx.recv().await.unwrap();
            assert!(matches!(
                request,
                RollbackRequest { id, .. } if id == rollback_id
            ));
            event_tx
                .send(EngineEvent::OperationFinished(Box::new(
                    crate::application::OperationResult {
                        op_id: 1,
                        outcome: OperationOutcome::Applied {
                            operation: FirewallOperation::Reload,
                            steps: Vec::new(),
                        },
                        rollback: None,
                        guard_warning: None,
                        completed_rollback: None,
                    },
                )))
                .await
                .unwrap();
            event_tx
                .send(EngineEvent::OperationFinished(Box::new(
                    crate::application::OperationResult {
                        op_id: 2,
                        outcome: OperationOutcome::Applied {
                            operation: inverse,
                            steps: Vec::new(),
                        },
                        rollback: None,
                        guard_warning: None,
                        completed_rollback: Some(rollback_id),
                    },
                )))
                .await
                .unwrap();
        });

        drain_rollbacks_on_exit(&mut state, &mut outbox, &mut engine).await;
        responder.await.unwrap();
        assert!(state.pending_rollback.is_empty());
    }
}
