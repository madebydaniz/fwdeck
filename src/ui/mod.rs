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

use crate::infrastructure::logs::LogEntry;

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
                None => Some(UiAction::Quit),
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
            _ = &mut ctrl_c => Some(UiAction::Quit),
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
        EngineEvent::OperationFinished { op_id, outcome } => {
            UiAction::OperationFinished { op_id, outcome }
        }
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
        Effect::ArmWatchdog {
            unit,
            delay_secs,
            args,
        } => arm_watchdog(state, &unit, delay_secs, &args).await,
        Effect::DisarmWatchdog { unit } => disarm_watchdog(&unit).await,
    }
    ControlFlow::Continue(())
}

/// Pre-arms the out-of-process rollback: a systemd transient timer that runs
/// the runtime inverse even if this process dies. Needs root and `systemd-run`;
/// silently degrades to in-process-only protection otherwise (with one toast).
async fn arm_watchdog(state: &mut state::UiState, unit: &str, delay_secs: u64, args: &[String]) {
    use crate::infrastructure::process::resolve_trusted;
    let systemd_run = resolve_trusted("systemd-run");
    let firewall_cmd = resolve_trusted("firewall-cmd");
    // Both binaries must resolve to an absolute trusted path: the watchdog runs
    // as root, so a relative name that could be resolved via a poisoned PATH
    // must never be armed — fall back to in-process rollback instead.
    if crate::infrastructure::process_uid() != 0
        || !systemd_run.is_absolute()
        || !firewall_cmd.is_absolute()
    {
        state.toast(
            state::ToastKind::Info,
            "watchdog unavailable (needs root + systemd) — in-process rollback only",
        );
        return;
    }
    let mut command = tokio::process::Command::new(systemd_run);
    command
        .arg("--collect")
        .arg(format!("--unit={unit}"))
        .arg(format!("--on-active={delay_secs}s"))
        .arg("--timer-property=AccuracySec=1s")
        .arg(firewall_cmd)
        .args(args)
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    match command.status().await {
        Ok(status) if status.success() => {
            tracing::info!(unit, delay_secs, "rollback watchdog armed");
        }
        Ok(status) => {
            tracing::warn!(unit, ?status, "systemd-run refused the watchdog");
            state.toast(
                state::ToastKind::Warning,
                "could not arm the crash watchdog — in-process rollback only",
            );
        }
        Err(err) => {
            tracing::warn!(unit, error = %err, "failed to spawn systemd-run");
            state.toast(
                state::ToastKind::Warning,
                "could not arm the crash watchdog — in-process rollback only",
            );
        }
    }
}

/// Cancels a previously armed watchdog timer (best-effort).
async fn disarm_watchdog(unit: &str) {
    use crate::infrastructure::process::resolve_trusted;
    let systemctl = resolve_trusted("systemctl");
    if !systemctl.is_absolute() {
        return;
    }
    let _ = tokio::process::Command::new(systemctl)
        .arg("stop")
        .arg(format!("{unit}.timer"))
        .env_clear()
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await;
}

/// Fires every armed rollback inverse and waits (max ~5 s) for the engine to
/// report each finished, so quitting inside a dead-man's-switch window reverts
/// the risky change instead of abandoning it.
async fn drain_rollbacks_on_exit(state: &mut state::UiState, engine: &mut EngineHandle) {
    if state.pending_rollback.is_empty() {
        return;
    }
    let pending: Vec<_> = state.pending_rollback.drain(..).collect();
    let mut awaiting = 0usize;
    for rollback in pending.into_iter().rev() {
        tracing::warn!(operation = %rollback.description, "quit inside rollback window — reverting");
        if let Some(unit) = rollback.watchdog_unit {
            disarm_watchdog(&unit).await;
        }
        if engine
            .requests
            .send(EngineRequest::Apply(rollback.inverse))
            .await
            .is_ok()
        {
            awaiting += 1;
        }
    }
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    while awaiting > 0 {
        match tokio::time::timeout_at(deadline, engine.events.recv()).await {
            Ok(Some(EngineEvent::OperationFinished { .. })) => awaiting -= 1,
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
mod tests {
    use super::base64_encode;

    #[test]
    fn base64_matches_known_vectors() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }
}
