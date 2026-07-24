//! The backend port. Owned by the application layer (dependency inversion):
//! infrastructure implements this trait, the UI never sees it.

use std::future::Future;
use std::time::Duration;

use crate::domain::{FirewallOperation, FirewallSnapshot, FirewallStatus};

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
}

/// One executed step of an operation, with the exact invocation for
/// diagnostics (argv for the CLI backend; method names for the D-Bus one).
#[derive(Debug, Clone, PartialEq)]
pub struct StepReport {
    /// Which configuration the step touched: `"runtime"`, `"permanent"`,
    /// `"global"`, `"offline"`, or `"policy"` (read-only rejection).
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
}

/// The firewalld backend: reads (`probe`, `snapshot`) and mutations (`apply`,
/// `reload`). Native async-fn-in-trait with explicit `Send` bounds (ADR-1).
pub trait FirewallBackend: Send + Sync + 'static {
    /// Cheap health check: daemon state, client version, netfilter backend.
    fn probe(&self) -> impl Future<Output = Result<FirewallStatus, FirewallError>> + Send;

    /// Full state in a handful of process calls, independent of zone count (ADR-2).
    fn snapshot(&self) -> impl Future<Output = Result<FirewallSnapshot, FirewallError>> + Send;

    /// Executes one operation (runtime step first, then permanent). Partial
    /// failure is an outcome, never an `Err` — callers must not lose it.
    fn apply(&self, operation: &FirewallOperation)
    -> impl Future<Output = OperationOutcome> + Send;
}
