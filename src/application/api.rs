//! Channel-based handle connecting the UI loop to the engine task. The UI
//! depends on these types only — never on `FirewallBackend` implementations.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;

use crate::domain::{FirewallOperation, FirewallSnapshot};

use super::engine;
use super::ports::{
    FirewallBackend, FirewallError, OperationOutcome, RollbackGuard, RollbackGuardId,
};

/// A risky operation whose inverse must remain available until the operator
/// keeps the change or the rollback countdown fires.
#[derive(Debug, Clone, PartialEq)]
pub struct RollbackRegistration {
    /// Unique identity shared with the out-of-process guard.
    pub id: RollbackGuardId,
    /// Operation that restores the pre-mutation state.
    pub inverse: FirewallOperation,
    /// systemd transient unit, when the host supports the crash guard.
    pub watchdog_unit: Option<String>,
}

/// Completed mutation plus its audit correlation and rollback safety state.
/// Boxed in channel/UI enums to keep their common variants compact.
#[derive(Debug, Clone, PartialEq)]
pub struct OperationResult {
    /// Correlation id shared with tracing and the durable audit line.
    pub op_id: u64,
    /// Honest applied/partial/failed/indeterminate outcome.
    pub outcome: OperationOutcome,
    /// Armed inverse for a risky operation that may have changed live state.
    pub rollback: Option<RollbackRegistration>,
    /// Safety subsystem warning that must be visible to the operator.
    pub guard_warning: Option<String>,
    /// Rollback request completed by this result, when this was an explicit,
    /// countdown, or clean-exit inverse rather than a forward mutation.
    pub completed_rollback: Option<RollbackGuardId>,
}

/// UI → engine commands. Sent over the bounded request channel.
#[derive(Debug, Clone, PartialEq)]
pub enum EngineRequest {
    /// Take a fresh snapshot now. Queued refreshes are coalesced into one pass.
    Refresh,
    /// Execute one operation (runtime step first, then permanent — ADR-3),
    /// followed by an automatic refresh.
    Apply(FirewallOperation),
    /// Execute a previously armed inverse, then best-effort disarm its external
    /// watchdog. Applying the inverse never depends on disarm success.
    Rollback {
        /// Correlates completion during bounded clean shutdown.
        id: RollbackGuardId,
        /// Connectivity-restoring inverse.
        operation: FirewallOperation,
        /// External watchdog to stop after the inverse has run.
        watchdog_unit: Option<String>,
    },
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
    /// Clean failures are disarmed in the engine before this result is sent.
    OperationFinished(Box<OperationResult>),
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
pub fn spawn<B: FirewallBackend, G: RollbackGuard>(
    backend: B,
    rollback_guard: G,
    refresh_interval: Duration,
    read_only: bool,
    rollback_timeout: Duration,
) -> EngineHandle {
    let (request_tx, request_rx) = mpsc::channel(32);
    let (event_tx, event_rx) = mpsc::channel(64);
    tokio::spawn(engine::run(
        backend,
        rollback_guard,
        request_rx,
        event_tx,
        refresh_interval,
        read_only,
        rollback_timeout,
    ));
    EngineHandle {
        requests: request_tx,
        events: event_rx,
    }
}
