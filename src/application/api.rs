//! Channel-based handle connecting the UI loop to the engine task. The UI
//! depends on these types only — never on `FirewallBackend` implementations.

use std::collections::BTreeMap;
use std::num::NonZeroU64;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, watch};

use crate::domain::{
    ActiveZone, DegradedSection, FirewallOperation, FirewallSnapshot, FirewallStatus, PolicyName,
    RefreshObservation, Scoped, ServiceName, ZoneDetails, ZoneName,
};

use super::engine;
use super::ports::{
    FirewallBackend, FirewallError, OperationOutcome, RollbackGuard, RollbackGuardId,
};

pub(crate) const REQUEST_CAPACITY: usize = 32;
const MANUAL_REFRESH_CAPACITY: usize = REQUEST_CAPACITY;
const ROLLBACK_CAPACITY: usize = 1;
const EVENT_CAPACITY: usize = 64;

/// One reviewed mutation together with the exact observed state it was
/// validated and confirmed against. The engine re-reads firewalld immediately
/// before execution and rejects the request if that state has changed.
#[derive(Debug, Clone, PartialEq)]
pub struct MutationRequest {
    /// Operation reviewed by the operator.
    pub operation: FirewallOperation,
    /// Snapshot visible when the operation was validated and confirmed.
    pub expected: Arc<FirewallSnapshot>,
}

impl MutationRequest {
    /// Couples an operation to the snapshot it was reviewed against.
    #[must_use]
    pub fn new(operation: FirewallOperation, expected: Arc<FirewallSnapshot>) -> Self {
        Self {
            operation,
            expected,
        }
    }
}

/// A reviewed staged plan with one start-of-batch observed-state precondition.
/// The engine owns the backend serially after the precondition succeeds.
#[derive(Debug, Clone, PartialEq)]
pub struct MutationPlan {
    /// Operations to execute sequentially and fail-fast.
    pub operations: Vec<FirewallOperation>,
    /// Snapshot visible when the batch was validated and confirmed.
    pub expected: Arc<FirewallSnapshot>,
}

impl MutationPlan {
    /// Couples a staged plan to the snapshot it was reviewed against.
    #[must_use]
    pub fn new(operations: Vec<FirewallOperation>, expected: Arc<FirewallSnapshot>) -> Self {
        Self {
            operations,
            expected,
        }
    }
}

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RefreshId(u64);

impl RefreshId {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshTrigger {
    Initial,
    Periodic,
    Manual,
    PostMutation,
}

impl RefreshTrigger {
    #[must_use]
    pub const fn is_preemptible(self) -> bool {
        !matches!(self, Self::PostMutation)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RefreshScheduleObservation {
    pub id: RefreshId,
    pub trigger: RefreshTrigger,
    pub merged_manual_requests: u64,
    pub coalesced_periodic_ticks: u64,
}

/// UI selection that should be fetched first while a staged refresh hydrates.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RefreshPriority {
    pub zone: Option<ZoneName>,
    pub service: Option<ServiceName>,
    pub policy: Option<PolicyName>,
}

/// Sends the most recent refresh target without accumulating stale demand.
#[derive(Clone)]
pub struct RefreshPriorityPublisher(watch::Sender<RefreshPriority>);

/// Reads the most recently requested refresh target.
#[derive(Clone)]
pub struct RefreshPrioritySource(watch::Receiver<RefreshPriority>);

/// Creates the single-latest-value channel used by staged refresh consumers.
#[must_use]
pub fn refresh_priority_channel() -> (RefreshPriorityPublisher, RefreshPrioritySource) {
    let (publisher, source) = watch::channel(RefreshPriority::default());
    (
        RefreshPriorityPublisher(publisher),
        RefreshPrioritySource(source),
    )
}

impl RefreshPriorityPublisher {
    /// Replaces any previously requested target with the current UI priority.
    pub fn publish(&self, priority: RefreshPriority) {
        self.0.send_replace(priority);
    }
}

impl RefreshPrioritySource {
    /// Returns the current priority without waiting for a future update.
    #[must_use]
    pub fn latest(&self) -> RefreshPriority {
        self.0.borrow().clone()
    }
}

/// The cheap snapshot stage used to decide which details need hydration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshOverview {
    pub status: FirewallStatus,
    pub default_zone: ZoneName,
    pub active: BTreeMap<ZoneName, ActiveZone>,
    pub runtime: BTreeMap<ZoneName, ZoneDetails>,
    pub permanent: BTreeMap<ZoneName, ZoneDetails>,
    pub available_services: Vec<ServiceName>,
    pub policy_names: Scoped<Vec<PolicyName>>,
    pub degraded: Vec<DegradedSection>,
}

impl RefreshOverview {
    /// Sorted union of service names referenced by any overview zone.
    #[must_use]
    pub fn referenced_services(&self) -> Vec<ServiceName> {
        let mut names: Vec<ServiceName> = self
            .runtime
            .values()
            .chain(self.permanent.values())
            .flat_map(|zone| zone.services.iter().cloned())
            .collect();
        names.sort();
        names.dedup();
        names
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshCancellationReason {
    MutationPreempted,
    RollbackPreempted,
}

/// One or more coalescible manual refresh requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManualRefreshRequest(NonZeroU64);

impl ManualRefreshRequest {
    #[must_use]
    pub const fn new(count: NonZeroU64) -> Self {
        Self(count)
    }

    #[must_use]
    pub const fn count(self) -> NonZeroU64 {
        self.0
    }
}

/// A safety rollback sent over its dedicated bounded priority lane.
#[derive(Debug, Clone, PartialEq)]
pub struct RollbackRequest {
    /// Correlates completion during bounded clean shutdown.
    pub id: RollbackGuardId,
    /// Connectivity-restoring inverse.
    pub operation: FirewallOperation,
    /// External watchdog to stop after the inverse has run.
    pub watchdog_unit: Option<String>,
}

/// UI → engine normal mutation commands. Sent over the bounded request channel.
#[derive(Debug, Clone, PartialEq)]
pub enum EngineRequest {
    /// Verify the reviewed snapshot is still current, execute one operation
    /// (runtime step first, then permanent — ADR-3), then refresh.
    Apply(MutationRequest),
    /// Verify the reviewed start state, then execute a staged plan as one
    /// sequential transaction: fail-fast on the first non-applied outcome,
    /// one refresh at the end, unexecuted operations returned via
    /// [`EngineEvent::PlanFinished`].
    ApplyPlan(MutationPlan),
}

/// Engine → UI notifications. Delivered in order over the bounded event channel.
#[derive(Debug, Clone)]
pub enum EngineEvent {
    /// A snapshot pass began — lets the UI track the exact active lifecycle.
    RefreshStarted {
        /// Monotonic process-local lifecycle identity.
        id: RefreshId,
        /// Demand that started this refresh.
        trigger: RefreshTrigger,
    },
    /// The snapshot pass ended. `Arc` because the UI keeps the previous
    /// snapshot alive while diffing against the new one.
    RefreshFinished {
        /// Scheduler metadata for the completed lifecycle.
        schedule: RefreshScheduleObservation,
        /// Fresh snapshot, or the categorized backend failure.
        result: Result<Arc<FirewallSnapshot>, FirewallError>,
        /// Exact telemetry for this snapshot attempt.
        observation: RefreshObservation,
    },
    /// A snapshot read was dropped so a queued mutation or safety rollback can run.
    RefreshCancelled {
        /// Scheduler metadata accumulated before cancellation.
        schedule: RefreshScheduleObservation,
        /// Why the lifecycle was cancelled.
        reason: RefreshCancellationReason,
        /// Deterministic Tokio-clock duration before cancellation.
        elapsed: Duration,
    },
    /// A manual batch could not be represented without overflowing lifecycle metadata.
    ManualDemandRejected {
        /// Exact rejected demand; the active lifecycle remains valid.
        count: NonZeroU64,
    },
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
    /// Bounded normal mutation channel into the engine (capacity 32).
    pub requests: mpsc::Sender<EngineRequest>,
    /// Bounded manual-demand lane (capacity 32); active demand is coalesced.
    pub manual_refreshes: mpsc::Sender<ManualRefreshRequest>,
    /// Bounded safety-priority rollback lane (capacity 1).
    pub rollbacks: mpsc::Sender<RollbackRequest>,
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
    let (request_tx, request_rx) = mpsc::channel(REQUEST_CAPACITY);
    let (manual_refresh_tx, manual_refresh_rx) = mpsc::channel(MANUAL_REFRESH_CAPACITY);
    let (rollback_tx, rollback_rx) = mpsc::channel(ROLLBACK_CAPACITY);
    let (event_tx, event_rx) = mpsc::channel(EVENT_CAPACITY);
    tokio::spawn(engine::run(
        backend,
        rollback_guard,
        engine::EngineReceivers::new(request_rx, manual_refresh_rx, rollback_rx),
        event_tx,
        refresh_interval,
        read_only,
        rollback_timeout,
    ));
    EngineHandle {
        requests: request_tx,
        manual_refreshes: manual_refresh_tx,
        rollbacks: rollback_tx,
        events: event_rx,
    }
}

#[cfg(test)]
mod tests {
    use crate::domain::ZoneName;

    use super::*;

    #[test]
    fn refresh_priority_source_keeps_only_the_latest_value() {
        let (publisher, source) = refresh_priority_channel();
        let public = ZoneName::parse("public").unwrap();
        let work = ZoneName::parse("work").unwrap();

        publisher.publish(RefreshPriority {
            zone: Some(public),
            service: None,
            policy: None,
        });
        publisher.publish(RefreshPriority {
            zone: Some(work.clone()),
            service: None,
            policy: None,
        });

        assert_eq!(source.latest().zone, Some(work));
    }

    #[test]
    fn refresh_schedule_observation_preserves_identity_trigger_and_counts() {
        let observation = RefreshScheduleObservation {
            id: RefreshId::new(7),
            trigger: RefreshTrigger::Manual,
            merged_manual_requests: 4,
            coalesced_periodic_ticks: 3,
        };

        assert_eq!(observation.id.get(), 7);
        assert_eq!(observation.trigger, RefreshTrigger::Manual);
        assert_eq!(observation.merged_manual_requests, 4);
        assert_eq!(observation.coalesced_periodic_ticks, 3);
        assert!(RefreshTrigger::Initial.is_preemptible());
        assert!(!RefreshTrigger::PostMutation.is_preemptible());
    }
}
