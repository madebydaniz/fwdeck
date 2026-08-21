//! The backend port. Owned by the application layer (dependency inversion):
//! infrastructure implements this trait, the UI never sees it.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use crate::domain::{FirewallOperation, FirewallSnapshot, FirewallStatus, RefreshObservation};

use super::api::{RefreshOverview, RefreshPrioritySource};

/// Stable identity for one rollback guard. It is assigned immediately before
/// the matching operation runs, so duplicate operations never share lifecycle
/// state or a systemd unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RollbackGuardId(u64);

impl RollbackGuardId {
    /// Builds an id from the process-local monotonic sequence.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the numeric value used in external guard names.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Failure while arming or disarming the out-of-process rollback guard.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RollbackGuardError {
    /// The guard command could not be spawned or did not produce a result.
    #[error("rollback guard process failed: {0}")]
    Process(String),
    /// The guard command exited unsuccessfully.
    #[error("rollback guard command failed (exit {code}): {stderr}")]
    CommandFailed {
        /// Exit status, or `-1` when terminated by a signal.
        code: i32,
        /// Trimmed diagnostic output.
        stderr: String,
    },
}

/// Out-of-process dead-man's-switch port. The engine invokes `arm` immediately
/// before each risky operation, including each individual staged-plan item.
pub trait RollbackGuard: Send + Sync + 'static {
    /// Arms a runtime inverse after `delay`. `Ok(None)` means this host cannot
    /// provide an out-of-process guard; the UI still provides its in-process
    /// countdown.
    fn arm(
        &self,
        id: RollbackGuardId,
        operation: &FirewallOperation,
        delay: Duration,
    ) -> impl Future<Output = Result<Option<String>, RollbackGuardError>> + Send;

    /// Cancels an armed unit. Implementations must enforce a hard timeout.
    fn disarm(&self, unit: &str) -> impl Future<Output = Result<(), RollbackGuardError>> + Send;
}

/// Errors crossing the backend boundary, categorized so the UI can react
/// meaningfully instead of showing "command failed".
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FirewallError {
    /// The client binary (`firewall-cmd`) could not be found at all.
    #[error("firewall-cmd not found — is firewalld installed?")]
    NotInstalled,
    /// The daemon is down (exit 252 / `NOT_RUNNING`, or no bus name on D-Bus).
    #[error("firewalld daemon is not running")]
    DaemonNotRunning,
    /// Polkit/root denial (exit 253 / `NOT_AUTHORIZED`).
    #[error("not authorized: {detail}")]
    PermissionDenied {
        /// Human-readable line extracted from stderr or the D-Bus error.
        detail: String,
    },
    /// The child process exceeded its per-invocation timeout and was killed.
    #[error("firewall-cmd timed out after {0:?}")]
    Timeout(Duration),
    /// Output did not match the pinned format (see `tests/fixtures/firewall_cmd/`).
    #[error("could not parse firewall-cmd output: {0}")]
    Parse(String),
    /// Non-zero exit not covered by a more specific category above.
    #[error("firewall-cmd failed (exit {code}): {stderr}")]
    CommandFailed {
        /// Raw exit code (`-1` when killed by a signal).
        code: i32,
        /// Trimmed stderr, truncated to a display-friendly length.
        stderr: String,
    },
    /// Spawn/IO/transport failure — the command never produced a usable result.
    #[error("process error: {0}")]
    Process(String),
    /// Mutation rejected because the engine runs with `read_only` enforced.
    #[error("fwdeck is in read-only mode")]
    ReadOnlyMode,
    /// The observed state changed after validation/confirmation but before the
    /// engine reached the mutation boundary.
    #[error("firewall state changed after confirmation — refreshed; review and retry")]
    StaleSnapshot,
    /// The engine's defense-in-depth validation rejected a request before any
    /// backend command or rollback guard was started.
    #[error("operation rejected by validation: {0}")]
    Validation(String),
}

/// One executed step of an operation, with the exact invocation for
/// diagnostics (argv for the CLI backend; method names for the D-Bus one).
#[derive(Debug, Clone, PartialEq)]
pub struct StepReport {
    /// Which configuration the step touched: `"runtime"`, `"permanent"`,
    /// `"global"`, `"offline"`, `"policy"` (read-only rejection), or
    /// `"precondition"` (no mutation was attempted).
    pub target: &'static str,
    /// Exact argv (CLI backend) or D-Bus method + args, for audit/display.
    pub invocation: Vec<String>,
    /// Per-step result; the outcome as a whole is derived from these.
    pub result: Result<(), FirewallError>,
}

impl StepReport {
    /// Whether this step completed without error.
    #[must_use]
    pub fn succeeded(&self) -> bool {
        self.result.is_ok()
    }
}

/// The honest result of a mutation. A partial failure is never reported as
/// success (ADR-3); `rollback_hint` carries the inverse for the rollback flow.
#[derive(Debug, Clone, PartialEq)]
pub enum OperationOutcome {
    /// Every planned step succeeded.
    Applied {
        /// The operation that was executed.
        operation: FirewallOperation,
        /// All executed steps, in order.
        steps: Vec<StepReport>,
    },
    /// Some steps succeeded before one failed — typically the runtime step
    /// applied but the permanent step did not (runtime-first ordering, ADR-3).
    PartiallyApplied {
        /// The operation that was executed.
        operation: FirewallOperation,
        /// All executed steps, including the failing one.
        steps: Vec<StepReport>,
        /// Inverse runtime operation that would undo the applied half, when
        /// one exists. Display-only here; the rollback flow lives in the UI.
        rollback_hint: Option<FirewallOperation>,
    },
    /// The first step failed — nothing changed.
    Failed {
        /// The operation that was attempted.
        operation: FirewallOperation,
        /// The executed steps (usually just the failing first one).
        steps: Vec<StepReport>,
    },
    /// A step timed out: the command may or may not have taken effect (the
    /// daemon could have applied it after the response was lost). No automatic
    /// retry or inverse is safe here — refresh and verify against the new
    /// snapshot first.
    Indeterminate {
        /// The operation whose result is unknown.
        operation: FirewallOperation,
        /// The executed steps, including the timed-out one.
        steps: Vec<StepReport>,
    },
}

/// Whether a completed backend outcome can be represented as one full projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationProjectionStatus {
    /// Every mutation step applied and the operation may be projected as a whole.
    FullyApplied,
    /// The first mutation step failed, so no operation effect was applied.
    NotApplied,
    /// Observed steps must be reconciled against a fresh authoritative snapshot.
    RequiresAuthoritativeReconciliation,
}

impl OperationOutcome {
    /// The operation this outcome belongs to, whatever the result.
    #[must_use]
    pub fn operation(&self) -> &FirewallOperation {
        match self {
            Self::Applied { operation, .. }
            | Self::PartiallyApplied { operation, .. }
            | Self::Failed { operation, .. }
            | Self::Indeterminate { operation, .. } => operation,
        }
    }

    /// The executed steps, in order, whatever the result.
    #[must_use]
    pub fn steps(&self) -> &[StepReport] {
        match self {
            Self::Applied { steps, .. }
            | Self::PartiallyApplied { steps, .. }
            | Self::Failed { steps, .. }
            | Self::Indeterminate { steps, .. } => steps,
        }
    }

    /// The first error, if any step failed.
    #[must_use]
    pub fn first_error(&self) -> Option<&FirewallError> {
        self.steps()
            .iter()
            .find_map(|step| step.result.as_ref().err())
    }

    /// Honest projection disposition for this backend outcome.
    #[must_use]
    pub const fn projection_status(&self) -> OperationProjectionStatus {
        match self {
            Self::Applied { .. } => OperationProjectionStatus::FullyApplied,
            Self::Failed { .. } => OperationProjectionStatus::NotApplied,
            Self::PartiallyApplied { .. } | Self::Indeterminate { .. } => {
                OperationProjectionStatus::RequiresAuthoritativeReconciliation
            }
        }
    }
}

/// One snapshot attempt together with operational telemetry from the same
/// backend boundary. The observation is available even when the read fails.
#[derive(Debug, Clone, PartialEq)]
pub struct SnapshotRead {
    /// Fresh firewall state, or the categorized backend failure.
    pub result: Result<FirewallSnapshot, FirewallError>,
    /// Exact latency plus adapter-specific process/section measurements.
    pub observation: RefreshObservation,
}

/// Result of the low-latency overview phase of a staged refresh.
#[derive(Debug, Clone, PartialEq)]
pub struct OverviewRead {
    /// Overview state, when the backend supports staged refresh reads.
    pub result: Result<Option<Arc<RefreshOverview>>, FirewallError>,
    /// Exact latency plus adapter-specific process/section measurements.
    pub observation: RefreshObservation,
}

/// The firewalld backend: reads (`probe`, `snapshot`) and mutations (`apply`,
/// `reload`). Native async-fn-in-trait with explicit `Send` bounds (ADR-1).
pub trait FirewallBackend: Send + Sync + 'static {
    /// Cheap health check: daemon state, client version, netfilter backend.
    fn probe(&self) -> impl Future<Output = Result<FirewallStatus, FirewallError>> + Send;

    /// Full state in a handful of process calls, independent of zone count (ADR-2).
    fn snapshot(&self) -> impl Future<Output = Result<FirewallSnapshot, FirewallError>> + Send;

    /// Full state plus refresh telemetry. Adapters can override this to report
    /// subprocess and per-section metrics; the default remains total-only.
    /// The returned future must be cancellation-safe: dropping it must not mutate
    /// firewall state, detach unbounded work, or leave a child process running.
    /// The engine may drop ordinary refreshes before a confirmed mutation.
    fn snapshot_observed(&self) -> impl Future<Output = SnapshotRead> + Send {
        async move {
            let started = std::time::Instant::now();
            let result = self.snapshot().await;
            SnapshotRead {
                result,
                observation: RefreshObservation::total_only(started.elapsed()),
            }
        }
    }

    /// Reads the low-latency overview stage, when the backend supports it.
    fn snapshot_overview(
        &self,
        _priority: &RefreshPrioritySource,
    ) -> impl Future<Output = OverviewRead> + Send {
        async {
            OverviewRead {
                result: Ok(None),
                observation: RefreshObservation::total_only(Duration::ZERO),
            }
        }
    }

    /// Hydrates a staged overview into the complete firewall snapshot.
    fn snapshot_hydrated(
        &self,
        _overview: Option<Arc<RefreshOverview>>,
        _priority: &RefreshPrioritySource,
    ) -> impl Future<Output = SnapshotRead> + Send {
        self.snapshot_observed()
    }

    /// Reads state for a mutation precondition, bypassing any refresh cache.
    /// Backends without a cache can use the default implementation.
    fn snapshot_fresh(
        &self,
    ) -> impl Future<Output = Result<FirewallSnapshot, FirewallError>> + Send {
        self.snapshot()
    }

    /// Executes one operation (runtime step first, then permanent). Partial
    /// failure is an outcome, never an `Err` — callers must not lose it.
    fn apply(&self, operation: &FirewallOperation)
    -> impl Future<Output = OperationOutcome> + Send;
}
