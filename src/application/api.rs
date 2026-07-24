//! Channel-based handle connecting the UI loop to the engine task. The UI
//! depends on these types only — never on `FirewallBackend` implementations.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;

use crate::domain::{FirewallOperation, FirewallSnapshot};

use super::engine;
use super::ports::{FirewallBackend, FirewallError, OperationOutcome};

/// UI → engine commands. Sent over the bounded request channel.
#[derive(Debug, Clone, PartialEq)]
pub enum EngineRequest {
    /// Take a fresh snapshot now. Queued refreshes are coalesced into one pass.
    Refresh,
    /// Execute one operation (runtime step first, then permanent — ADR-3),
    /// followed by an automatic refresh.
    Apply(FirewallOperation),
    /// Execute a staged plan as one sequential transaction: fail-fast on the
    /// first non-applied outcome, one refresh at the end, unexecuted
    /// operations returned via [`EngineEvent::PlanFinished`].
    ApplyPlan(Vec<FirewallOperation>),
}

/// Engine → UI notifications. Delivered in order over the bounded event channel.
#[derive(Debug, Clone)]
pub enum EngineEvent {
    /// A snapshot pass began — lets the UI show a spinner immediately.
    RefreshStarted,
    /// The snapshot pass ended. `Arc` because the UI keeps the previous
    /// snapshot alive while diffing against the new one.
    RefreshFinished(Result<Arc<FirewallSnapshot>, FirewallError>),
    /// One operation completed with its honest [`OperationOutcome`]
    /// (applied / partially applied / failed — never a swallowed partial),
    /// plus the correlation id shared with tracing and the audit line.
    OperationFinished {
        /// Correlation id (see [`super::engine::next_op_id`]).
        op_id: u64,
        /// The honest outcome.
        outcome: OperationOutcome,
    },
    /// A staged plan finished (or halted on its first failure). `remaining`
    /// holds the operations that were never executed so the UI can re-stage
    /// them instead of losing them.
    PlanFinished {
        /// Number of operations that were fully applied before the plan
        /// ended or halted.
        applied: usize,
        /// Operations never executed because the plan halted fail-fast.
        remaining: Vec<FirewallOperation>,
    },
}

/// The UI's only connection to the engine task: send requests, receive events.
pub struct EngineHandle {
    /// Bounded request channel into the engine (capacity 32).
    pub requests: mpsc::Sender<EngineRequest>,
    /// Bounded event channel out of the engine (capacity 64).
    pub events: mpsc::Receiver<EngineEvent>,
}

/// Spawns the engine task owning `backend`. Bounded channels: a slow UI applies
/// backpressure instead of growing queues. `read_only` is enforced here, in the
/// application layer — the UI merely reflects it.
pub fn spawn<B: FirewallBackend>(
    backend: B,
    refresh_interval: Duration,
    read_only: bool,
) -> EngineHandle {
    let (request_tx, request_rx) = mpsc::channel(32);
    let (event_tx, event_rx) = mpsc::channel(64);
    tokio::spawn(engine::run(
        backend,
        request_rx,
        event_tx,
        refresh_interval,
        read_only,
    ));
    EngineHandle {
        requests: request_tx,
        events: event_rx,
    }
}
