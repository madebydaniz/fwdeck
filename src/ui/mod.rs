//! Terminal lifecycle and the async event loop. The loop owns the `UiState`,
//! translates terminal and engine events into actions, runs the reducer, and
//! renders. All firewalld I/O happens in the engine task — this loop never
//! blocks on anything but the `select!` below.

pub mod action;
pub mod components;
pub mod details;
pub mod fuzzy;
pub mod keymap;
pub mod overlays;
pub mod palette;
pub mod render;
pub mod rich_builder;
pub mod search;
pub mod state;
pub mod theme;
pub mod update;
pub mod views;

use std::time::Duration;

use crossterm::event::{Event, EventStream};
use futures_util::StreamExt;

use tokio::sync::mpsc;

use crate::application::api::{EngineEvent, EngineHandle, EngineRequest};
use crate::application::ports::FirewallError;
use crate::config::Config;
use crate::error::AppError;
use std::ops::ControlFlow;

use crate::domain::LogEntry;

use action::{Effect, UiAction};
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
    let mut logs_alive = true;
    let mut log_batch: Vec<LogEntry> = Vec::new();

    loop {
        terminal.draw(|f| render::render(f, &mut state, &theme))?;

        let action = tokio::select! {
            maybe_event = events.next() => match maybe_event {
                Some(Ok(Event::Key(key))) => keymap::translate(&state, key),
                Some(Ok(Event::Resize(width, height))) => Some(UiAction::Resize(width, height)),
                Some(Ok(_)) => None,
                Some(Err(err)) => return Err(AppError::Terminal(err)),
                // Input stream gone: no terminal left to ask anything on.
                None => Some(UiAction::QuitConfirmed),
            },
            event = engine.events.recv(), if engine_alive => if let Some(event) = event {
                Some(engine_event_action(event))
            } else {
                engine_alive = false;
                Some(UiAction::RefreshCompleted(Err(FirewallError::Process(
                    "engine task stopped unexpectedly".to_owned(),
                ))))
            },
            received = logs.recv_many(&mut log_batch, 64), if logs_alive => {
                if received == 0 {
                    logs_alive = false; // tailer ended; stop polling a closed channel
                    None
                } else {
                    Some(UiAction::LogsReceived(std::mem::take(&mut log_batch)))
                }
            },
            _ = tick.tick() => Some(UiAction::Tick),
            // SIGINT is the emergency exit — never gate it behind a modal.
            _ = &mut ctrl_c => Some(UiAction::QuitConfirmed),
        };

        let Some(action) = action else { continue };
        // Worklist: an effect may produce a follow-up action (a snapshot read
        // returns its result as an action), processed in the same frame.
        let mut pending: std::collections::VecDeque<UiAction> =
            std::collections::VecDeque::from([action]);
        while let Some(action) = pending.pop_front() {
            for effect in update::update(&mut state, action) {
                match execute_effect(effect, &mut state, &mut engine, &mut pending).await {
                    ControlFlow::Continue(()) => {}
                    ControlFlow::Break(()) => {
                        // A clean quit must not abandon armed rollbacks: fire
                        // the inverses and wait (bounded) for the engine to run
                        // them. Crash/SIGKILL/connection-loss is covered by the
                        // out-of-process watchdog.
                        drain_rollbacks_on_exit(&mut state, &mut engine).await;
                        return Ok(());
                    }
                }
            }
        }
    }
}

/// Maps an engine event to the UI action that handles it.
fn engine_event_action(event: EngineEvent) -> UiAction {
    match event {
        EngineEvent::RefreshStarted => UiAction::RefreshStarted,
        EngineEvent::RefreshFinished(result) => UiAction::RefreshCompleted(result),
        EngineEvent::OperationFinished(result) => UiAction::OperationFinished(result),
        EngineEvent::PlanFinished { applied, remaining } => {
            UiAction::PlanFinished { applied, remaining }
        }
    }
}

/// Sends a request to the engine, draining engine events while waiting for a
/// queue slot. Reserving (instead of a plain blocking send) means a momentarily
/// full requests queue cannot deadlock against a full events queue — each side
/// blocked on the other. Returns false if the engine is gone; drained events
/// run as follow-up actions so no outcome is lost.
async fn send_request(
    engine: &mut EngineHandle,
    pending: &mut std::collections::VecDeque<UiAction>,
    request: EngineRequest,
) -> bool {
    let requests = &mut engine.requests;
    let events = &mut engine.events;
    loop {
        tokio::select! {
            permit = requests.reserve() => {
                return match permit {
                    Ok(permit) => {
                        permit.send(request);
                        true
                    }
                    Err(_) => false,
                };
            }
            Some(event) = events.recv() => {
                pending.push_back(engine_event_action(event));
            }
        }
    }
}

/// Executes one effect. Reads run off the event-loop thread and feed their
/// result back as a follow-up action on `pending`. Returns `Break` only for
/// `Effect::Quit`, which the caller turns into a clean shutdown.
#[allow(clippy::too_many_lines)] // one arm per effect
async fn execute_effect(
    effect: Effect,
    state: &mut state::UiState,
    engine: &mut EngineHandle,
    pending: &mut std::collections::VecDeque<UiAction>,
) -> ControlFlow<()> {
    match effect {
        Effect::Quit => return ControlFlow::Break(()),
        Effect::Refresh => {
            // A full queue already guarantees a refresh is coming.
            let _ = engine.requests.try_send(EngineRequest::Refresh);
        }
        Effect::Apply(operation) => {
            // Reserving-send drains events while it waits, so a momentarily full
            // queue can't drop a mutation (rollbacks especially) or deadlock.
            if !send_request(engine, pending, EngineRequest::Apply(operation)).await {
                state.toast(state::ToastKind::Error, "engine is gone — operation lost");
            }
        }
        Effect::ApplyRollback {
            id,
            operation,
            watchdog_unit,
        } => {
            if !send_request(
                engine,
                pending,
                EngineRequest::Rollback {
                    id,
                    operation,
                    watchdog_unit,
                },
            )
            .await
            {
                state.toast(
                    state::ToastKind::Error,
                    "engine is gone — rollback not sent",
                );
            }
        }
        Effect::ApplyPlan(operations) => {
            if !send_request(engine, pending, EngineRequest::ApplyPlan(operations)).await {
                state.toast(state::ToastKind::Error, "engine is gone — plan not sent");
            }
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
            let result = tokio::task::spawn_blocking(crate::infrastructure::counters::read)
                .await
                .unwrap_or_else(|join| Err(format!("counter task failed: {join}")));
            pending.push_back(UiAction::CountersLoaded(result));
        }
        Effect::RecordAudit { op_id, outcome } => {
            if let Err(err) = crate::infrastructure::audit::record(op_id, &outcome) {
                // An unrecorded mutation is an incident, not a debug line.
                state.toast(
                    state::ToastKind::Error,
                    format!("AUDIT WRITE FAILED: {err}"),
                );
            }
        }
        Effect::ExportPlan(format, rendered) => {
            match crate::infrastructure::export_write(format, &rendered) {
                Ok(path) => state.toast(state::ToastKind::Success, format!("exported to {path}")),
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

/// Fires every armed rollback inverse and waits (max ~5 s) for the engine to
/// report each finished, so quitting inside a dead-man's-switch window reverts
/// the risky change instead of abandoning it.
async fn drain_rollbacks_on_exit(state: &mut state::UiState, engine: &mut EngineHandle) {
    if state.pending_rollback.is_empty() {
        return;
    }
    let pending: Vec<_> = state.pending_rollback.drain(..).collect();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut expected = std::collections::HashSet::new();
    let mut completed = std::collections::HashSet::new();
    for rollback in pending.into_iter().rev() {
        tracing::warn!(operation = %rollback.description, "quit inside rollback window — reverting");
        let id = rollback.id;
        let mut request = Some(EngineRequest::Rollback {
            id,
            operation: rollback.inverse,
            watchdog_unit: rollback.watchdog_unit,
        });
        loop {
            tokio::select! {
                permit = engine.requests.reserve() => {
                    let Ok(permit) = permit else { return };
                    if let Some(request) = request.take() {
                        permit.send(request);
                        expected.insert(id);
                    }
                    break;
                }
                event = engine.events.recv() => match event {
                    Some(EngineEvent::OperationFinished(result)) => {
                        if let Some(id) = result.completed_rollback {
                            completed.insert(id);
                        }
                    }
                    Some(_) => {}
                    None => return,
                },
                () = tokio::time::sleep_until(deadline) => return,
            }
        }
    }
    while !expected.is_subset(&completed) {
        match tokio::time::timeout_at(deadline, engine.events.recv()).await {
            Ok(Some(EngineEvent::OperationFinished(result))) => {
                if let Some(id) = result.completed_rollback {
                    completed.insert(id);
                }
            }
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => break,
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
    use super::{base64_encode, drain_rollbacks_on_exit};

    #[test]
    fn base64_matches_known_vectors() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[tokio::test]
    async fn clean_exit_waits_for_the_matching_rollback_id() {
        use crate::application::api::{EngineEvent, EngineHandle, EngineRequest, OperationResult};
        use crate::application::ports::{OperationOutcome, RollbackGuardId};
        use crate::config::Config;
        use crate::domain::{ConfigurationTarget, FirewallOperation, ZoneName};
        use crate::ui::state::{PendingRollback, UiState};

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

        let (request_tx, mut request_rx) = tokio::sync::mpsc::channel(1);
        let (event_tx, event_rx) = tokio::sync::mpsc::channel(4);
        let mut engine = EngineHandle {
            requests: request_tx,
            events: event_rx,
        };
        let responder = tokio::spawn(async move {
            let request = request_rx.recv().await.unwrap();
            assert!(matches!(
                request,
                EngineRequest::Rollback { id, .. } if id == rollback_id
            ));
            event_tx
                .send(EngineEvent::OperationFinished(Box::new(OperationResult {
                    op_id: 1,
                    outcome: OperationOutcome::Applied {
                        operation: FirewallOperation::Reload,
                        steps: Vec::new(),
                    },
                    rollback: None,
                    guard_warning: None,
                    completed_rollback: None,
                })))
                .await
                .unwrap();
            event_tx
                .send(EngineEvent::OperationFinished(Box::new(OperationResult {
                    op_id: 2,
                    outcome: OperationOutcome::Applied {
                        operation: inverse,
                        steps: Vec::new(),
                    },
                    rollback: None,
                    guard_warning: None,
                    completed_rollback: Some(rollback_id),
                })))
                .await
                .unwrap();
        });

        drain_rollbacks_on_exit(&mut state, &mut engine).await;
        responder.await.unwrap();
        assert!(state.pending_rollback.is_empty());
    }
}
