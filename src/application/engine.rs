//! The engine task: single owner of the backend. Requests are processed
//! serially (mutations serialize structurally), refreshes are
//! coalesced, and events reach the UI in order — no stale-result races.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;

use std::sync::atomic::{AtomicU64, Ordering};

use crate::domain::FirewallSnapshot;

use super::api::{
    EngineEvent, EngineRequest, MutationPlan, MutationRequest, OperationResult,
    RollbackRegistration,
};
use super::ports::{
    FirewallBackend, FirewallError, OperationOutcome, RollbackGuard, RollbackGuardId, StepReport,
};

/// Process-wide operation counter. The id it mints is logged via tracing and
/// written to the audit line for the same operation, so `fwdeck.log` and
/// `audit.jsonl` can be joined on one field even across identical retries.
static OP_SEQ: AtomicU64 = AtomicU64::new(1);
static ROLLBACK_SEQ: AtomicU64 = AtomicU64::new(1);

/// The next correlation id for an operation.
pub fn next_op_id() -> u64 {
    OP_SEQ.fetch_add(1, Ordering::Relaxed)
}

pub(crate) async fn run<B: FirewallBackend, G: RollbackGuard>(
    backend: B,
    rollback_guard: G,
    mut requests: mpsc::Receiver<EngineRequest>,
    events: mpsc::Sender<EngineEvent>,
    refresh_interval: Duration,
    read_only: bool,
    rollback_timeout: Duration,
) {
    let mut interval = tokio::time::interval(refresh_interval);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            request = requests.recv() => match request {
                None => break, // UI dropped the handle: shut down
                Some(EngineRequest::Refresh) => {
                    // Coalesce queued refreshes into one pass. Apply requests
                    // are never coalesced away: try_recv only drops Refresh.
                    while let Ok(queued) = requests.try_recv() {
                        if execute_request(
                            &backend,
                            &rollback_guard,
                            &events,
                            queued,
                            read_only,
                            rollback_timeout,
                        )
                        .await
                        .is_err()
                        {
                            return;
                        }
                    }
                    interval.reset();
                    if refresh(&backend, &events).await.is_err() {
                        break;
                    }
                }
                Some(request) => {
                    if execute_request(
                        &backend,
                        &rollback_guard,
                        &events,
                        request,
                        read_only,
                        rollback_timeout,
                    )
                    .await
                    .is_err()
                    {
                        break;
                    }
                    // One post-mutation refresh even for a failure or a whole
                    // plan: the daemon may have changed before reporting it.
                    interval.reset();
                    if refresh(&backend, &events).await.is_err() {
                        break;
                    }
                }
            },
            // First tick fires immediately: the initial refresh needs no request.
            _ = interval.tick() => {
                if refresh(&backend, &events).await.is_err() {
                    break;
                }
            }
        }
    }
}

async fn execute_request<B: FirewallBackend, G: RollbackGuard>(
    backend: &B,
    rollback_guard: &G,
    events: &mpsc::Sender<EngineEvent>,
    request: EngineRequest,
    read_only: bool,
    rollback_timeout: Duration,
) -> Result<(), ()> {
    match request {
        EngineRequest::Refresh => Ok(()),
        EngineRequest::Apply(request) => {
            apply(
                backend,
                rollback_guard,
                events,
                request,
                read_only,
                rollback_timeout,
            )
            .await
        }
        EngineRequest::Rollback {
            id,
            operation,
            watchdog_unit,
        } => {
            apply_rollback(
                backend,
                rollback_guard,
                events,
                id,
                operation,
                watchdog_unit,
                read_only,
            )
            .await
        }
        EngineRequest::ApplyPlan(plan) => {
            apply_plan(
                backend,
                rollback_guard,
                events,
                plan,
                read_only,
                rollback_timeout,
            )
            .await
        }
    }
}

/// Executes a staged plan sequentially, halting on the first outcome that is
/// not fully applied (fail-fast: continuing after a partial failure could
/// compound damage). Every per-operation outcome still flows to the UI as
/// `OperationFinished`; unexecuted operations are returned in `PlanFinished`
/// so nothing is silently lost. Returns `Err(())` when the UI is gone.
async fn apply_plan<B: FirewallBackend, G: RollbackGuard>(
    backend: &B,
    rollback_guard: &G,
    events: &mpsc::Sender<EngineEvent>,
    plan: MutationPlan,
    read_only: bool,
    rollback_timeout: Duration,
) -> Result<(), ()> {
    let MutationPlan {
        operations,
        expected,
    } = plan;
    let total = operations.len();
    if !read_only {
        let observed = match mutation_precondition(backend, &expected).await {
            Ok(observed) => observed,
            Err(error) => return reject_plan_preflight(events, operations, error).await,
        };
        if let Some(error) = operations
            .iter()
            .find_map(|operation| operation.validate(&observed).err())
        {
            return reject_plan_preflight(
                events,
                operations,
                FirewallError::Validation(error.to_string()),
            )
            .await;
        }
    }
    let mut iter = operations.into_iter();
    let mut applied = 0usize;
    let mut halted = false;
    for operation in iter.by_ref() {
        let (op_id, outcome, rollback, guard_warning) = execute_operation(
            backend,
            rollback_guard,
            operation,
            read_only,
            rollback_timeout,
            true,
        )
        .await;
        let fully_applied = matches!(outcome, OperationOutcome::Applied { .. });
        if events
            .send(EngineEvent::OperationFinished(Box::new(OperationResult {
                op_id,
                outcome,
                rollback,
                guard_warning,
                completed_rollback: None,
            })))
            .await
            .is_err()
        {
            return Err(());
        }
        if fully_applied {
            applied += 1;
        } else {
            halted = true;
            break;
        }
    }
    let remaining: Vec<_> = iter.collect();
    tracing::info!(applied, total, halted, "plan finished");
    events
        .send(EngineEvent::PlanFinished { applied, remaining })
        .await
        .map_err(|_| ())
}

/// Returns `Err(())` when the event channel is closed (UI is gone).
async fn apply<B: FirewallBackend, G: RollbackGuard>(
    backend: &B,
    rollback_guard: &G,
    events: &mpsc::Sender<EngineEvent>,
    request: MutationRequest,
    read_only: bool,
    rollback_timeout: Duration,
) -> Result<(), ()> {
    let MutationRequest {
        operation,
        expected,
    } = request;
    let (op_id, outcome, rollback, guard_warning) = if read_only {
        execute_operation(
            backend,
            rollback_guard,
            operation,
            true,
            rollback_timeout,
            false,
        )
        .await
    } else {
        match mutation_precondition(backend, &expected).await {
            Ok(observed) => match operation.validate(&observed) {
                Ok(()) => {
                    execute_operation(
                        backend,
                        rollback_guard,
                        operation,
                        false,
                        rollback_timeout,
                        false,
                    )
                    .await
                }
                Err(error) => {
                    rejected_operation(operation, FirewallError::Validation(error.to_string()))
                }
            },
            Err(error) => rejected_operation(operation, error),
        }
    };
    match &outcome {
        OperationOutcome::Applied { .. } => {
            tracing::info!(operation = %outcome.operation().describe(), "operation applied");
        }
        OperationOutcome::PartiallyApplied { .. }
        | OperationOutcome::Failed { .. }
        | OperationOutcome::Indeterminate { .. } => {
            tracing::warn!(operation = %outcome.operation().describe(), outcome = ?outcome, "operation not fully applied");
        }
    }
    events
        .send(EngineEvent::OperationFinished(Box::new(OperationResult {
            op_id,
            outcome,
            rollback,
            guard_warning,
            completed_rollback: None,
        })))
        .await
        .map_err(|_| ())
}

/// Re-reads every backend section at the mutation boundary and compares it to
/// the state reviewed by the operator. Returning the fresh snapshot also lets
/// the caller repeat domain validation without a third read.
async fn mutation_precondition<B: FirewallBackend>(
    backend: &B,
    expected: &FirewallSnapshot,
) -> Result<FirewallSnapshot, FirewallError> {
    let observed = backend.snapshot_fresh().await?;
    if observed == *expected {
        Ok(observed)
    } else {
        Err(FirewallError::StaleSnapshot)
    }
}

fn rejected_operation(
    operation: crate::domain::FirewallOperation,
    error: FirewallError,
) -> (
    u64,
    OperationOutcome,
    Option<RollbackRegistration>,
    Option<String>,
) {
    (
        next_op_id(),
        OperationOutcome::Failed {
            operation,
            steps: vec![StepReport {
                target: "precondition",
                invocation: Vec::new(),
                result: Err(error),
            }],
        },
        None,
        None,
    )
}

async fn reject_plan_preflight(
    events: &mpsc::Sender<EngineEvent>,
    operations: Vec<crate::domain::FirewallOperation>,
    error: FirewallError,
) -> Result<(), ()> {
    let Some(first) = operations.first().cloned() else {
        return events
            .send(EngineEvent::PlanFinished {
                applied: 0,
                remaining: Vec::new(),
            })
            .await
            .map_err(|_| ());
    };
    let (op_id, outcome, rollback, guard_warning) = rejected_operation(first, error);
    events
        .send(EngineEvent::OperationFinished(Box::new(OperationResult {
            op_id,
            outcome,
            rollback,
            guard_warning,
            completed_rollback: None,
        })))
        .await
        .map_err(|_| ())?;
    events
        .send(EngineEvent::PlanFinished {
            applied: 0,
            remaining: operations,
        })
        .await
        .map_err(|_| ())
}

async fn apply_rollback<B: FirewallBackend, G: RollbackGuard>(
    backend: &B,
    rollback_guard: &G,
    events: &mpsc::Sender<EngineEvent>,
    id: RollbackGuardId,
    operation: crate::domain::FirewallOperation,
    watchdog_unit: Option<String>,
    read_only: bool,
) -> Result<(), ()> {
    let op_id = next_op_id();
    tracing::warn!(op_id, rollback_id = id.get(), operation = %operation.describe(), "applying rollback inverse");
    let outcome = if read_only {
        OperationOutcome::Failed {
            operation,
            steps: vec![StepReport {
                target: "policy",
                invocation: Vec::new(),
                result: Err(FirewallError::ReadOnlyMode),
            }],
        }
    } else {
        backend.apply(&operation).await
    };

    let mut guard_warning = None;
    if matches!(outcome, OperationOutcome::Applied { .. }) {
        if let Some(unit) = watchdog_unit
            && let Err(error) = rollback_guard.disarm(&unit).await
        {
            guard_warning = Some(format!(
                "rollback applied but crash watchdog `{unit}` could not be disarmed: {error}"
            ));
        }
    } else if watchdog_unit.is_some() {
        guard_warning = Some(
            "rollback did not fully apply — crash watchdog remains armed as a safety fallback"
                .to_owned(),
        );
    }
    events
        .send(EngineEvent::OperationFinished(Box::new(OperationResult {
            op_id,
            outcome,
            rollback: None,
            guard_warning,
            completed_rollback: Some(id),
        })))
        .await
        .map_err(|_| ())
}

async fn execute_operation<B: FirewallBackend, G: RollbackGuard>(
    backend: &B,
    rollback_guard: &G,
    operation: crate::domain::FirewallOperation,
    read_only: bool,
    rollback_timeout: Duration,
    plan_item: bool,
) -> (
    u64,
    OperationOutcome,
    Option<RollbackRegistration>,
    Option<String>,
) {
    let op_id = next_op_id();
    if read_only {
        return (
            op_id,
            OperationOutcome::Failed {
                operation,
                steps: vec![StepReport {
                    target: "policy",
                    invocation: Vec::new(),
                    result: Err(FirewallError::ReadOnlyMode),
                }],
            },
            None,
            None,
        );
    }

    let (mut rollback, mut guard_warning) =
        prepare_rollback(rollback_guard, &operation, rollback_timeout).await;
    if plan_item {
        tracing::info!(op_id, operation = %operation.describe(), "applying plan operation");
    } else {
        tracing::info!(op_id, operation = %operation.describe(), "applying operation");
    }
    let outcome = backend.apply(&operation).await;

    if matches!(outcome, OperationOutcome::Failed { .. }) {
        if let Some(unit) = rollback
            .as_ref()
            .and_then(|registration| registration.watchdog_unit.as_deref())
            && let Err(error) = rollback_guard.disarm(unit).await
        {
            append_warning(
                &mut guard_warning,
                format!("failed to disarm rollback guard `{unit}` after a clean failure: {error}"),
            );
        }
        rollback = None;
    }

    (op_id, outcome, rollback, guard_warning)
}

async fn prepare_rollback<G: RollbackGuard>(
    rollback_guard: &G,
    operation: &crate::domain::FirewallOperation,
    rollback_timeout: Duration,
) -> (Option<RollbackRegistration>, Option<String>) {
    if rollback_timeout.is_zero() || operation.connectivity_warning().is_none() {
        return (None, None);
    }
    let Some(inverse) = operation.inverse() else {
        return (None, None);
    };
    let id = RollbackGuardId::new(ROLLBACK_SEQ.fetch_add(1, Ordering::Relaxed));
    match rollback_guard.arm(id, operation, rollback_timeout).await {
        Ok(Some(watchdog_unit)) => (
            Some(RollbackRegistration {
                id,
                inverse,
                watchdog_unit: Some(watchdog_unit),
            }),
            None,
        ),
        Ok(None) => (
            Some(RollbackRegistration {
                id,
                inverse,
                watchdog_unit: None,
            }),
            Some(
                "crash watchdog unavailable for this operation — in-process rollback only"
                    .to_owned(),
            ),
        ),
        Err(error) => (
            Some(RollbackRegistration {
                id,
                inverse,
                watchdog_unit: None,
            }),
            Some(format!(
                "could not arm the crash watchdog — in-process rollback only: {error}"
            )),
        ),
    }
}

fn append_warning(current: &mut Option<String>, warning: String) {
    if let Some(existing) = current {
        existing.push_str("; ");
        existing.push_str(&warning);
    } else {
        *current = Some(warning);
    }
}

/// Returns `Err(())` when the event channel is closed (UI is gone).
async fn refresh<B: FirewallBackend>(
    backend: &B,
    events: &mpsc::Sender<EngineEvent>,
) -> Result<(), ()> {
    events
        .send(EngineEvent::RefreshStarted)
        .await
        .map_err(|_| ())?;
    let read = backend.snapshot_observed().await;
    let result = read.result.map(Arc::new);
    let observation = read.observation;
    match &result {
        Ok(snapshot) => tracing::debug!(
            zones = snapshot.runtime.len(),
            elapsed_ms = observation.elapsed.as_millis(),
            process_count = observation.process_count,
            "refresh finished"
        ),
        Err(err) => tracing::warn!(
            error = %err,
            elapsed_ms = observation.elapsed.as_millis(),
            process_count = observation.process_count,
            "refresh failed"
        ),
    }
    events
        .send(EngineEvent::RefreshFinished {
            result,
            observation,
        })
        .await
        .map_err(|_| ())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::application::ports::{
        FirewallBackend, FirewallError, RollbackGuardError, RollbackGuardId,
    };
    use crate::domain::{FirewallOperation, FirewallSnapshot, FirewallStatus, mock};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
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

    #[derive(Debug, Default)]
    struct GuardLog {
        armed: Vec<(RollbackGuardId, FirewallOperation)>,
        disarmed: Vec<String>,
    }

    #[derive(Clone, Default)]
    struct RecordingRollbackGuard {
        log: Arc<Mutex<GuardLog>>,
    }

    impl RollbackGuard for RecordingRollbackGuard {
        async fn arm(
            &self,
            id: RollbackGuardId,
            operation: &FirewallOperation,
            _delay: Duration,
        ) -> Result<Option<String>, RollbackGuardError> {
            self.log.lock().unwrap().armed.push((id, operation.clone()));
            Ok(Some(format!("fwdeck-rollback-test-{}", id.get())))
        }

        async fn disarm(&self, unit: &str) -> Result<(), RollbackGuardError> {
            self.log.lock().unwrap().disarmed.push(unit.to_owned());
            Ok(())
        }
    }

    struct FailingArmGuard;

    impl RollbackGuard for FailingArmGuard {
        async fn arm(
            &self,
            _id: RollbackGuardId,
            _operation: &FirewallOperation,
            _delay: Duration,
        ) -> Result<Option<String>, RollbackGuardError> {
            Err(RollbackGuardError::Process("arm timeout".to_owned()))
        }

        async fn disarm(&self, _unit: &str) -> Result<(), RollbackGuardError> {
            Ok(())
        }
    }

    struct FailingDisarmGuard;

    impl RollbackGuard for FailingDisarmGuard {
        async fn arm(
            &self,
            id: RollbackGuardId,
            _operation: &FirewallOperation,
            _delay: Duration,
        ) -> Result<Option<String>, RollbackGuardError> {
            Ok(Some(format!("fwdeck-rollback-test-{}", id.get())))
        }

        async fn disarm(&self, _unit: &str) -> Result<(), RollbackGuardError> {
            Err(RollbackGuardError::Process("disarm timeout".to_owned()))
        }
    }

    struct FakeBackend {
        calls: AtomicUsize,
        fail: bool,
    }

    impl FirewallBackend for FakeBackend {
        async fn probe(&self) -> Result<FirewallStatus, FirewallError> {
            Err(FirewallError::DaemonNotRunning)
        }

        async fn snapshot(&self) -> Result<FirewallSnapshot, FirewallError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail {
                Err(FirewallError::DaemonNotRunning)
            } else {
                mock::sample().map_err(|e| FirewallError::Parse(e.to_string()))
            }
        }

        async fn apply(&self, operation: &FirewallOperation) -> OperationOutcome {
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

    struct LargeBackend;

    impl FirewallBackend for LargeBackend {
        async fn probe(&self) -> Result<FirewallStatus, FirewallError> {
            mock::sample()
                .map(|snapshot| snapshot.status)
                .map_err(|error| FirewallError::Parse(error.to_string()))
        }

        async fn snapshot(&self) -> Result<FirewallSnapshot, FirewallError> {
            mock::large().map_err(|error| FirewallError::Parse(error.to_string()))
        }

        async fn apply(&self, operation: &FirewallOperation) -> OperationOutcome {
            OperationOutcome::Applied {
                operation: operation.clone(),
                steps: Vec::new(),
            }
        }
    }

    struct DriftingBackend {
        snapshot_calls: Arc<AtomicUsize>,
        apply_calls: Arc<AtomicUsize>,
    }

    impl FirewallBackend for DriftingBackend {
        async fn probe(&self) -> Result<FirewallStatus, FirewallError> {
            Err(FirewallError::DaemonNotRunning)
        }

        async fn snapshot(&self) -> Result<FirewallSnapshot, FirewallError> {
            let call = self.snapshot_calls.fetch_add(1, Ordering::SeqCst);
            let mut snapshot = mock::sample().map_err(|e| FirewallError::Parse(e.to_string()))?;
            if call > 0 {
                snapshot.status.panic_mode = !snapshot.status.panic_mode;
            }
            Ok(snapshot)
        }

        async fn apply(&self, operation: &FirewallOperation) -> OperationOutcome {
            self.apply_calls.fetch_add(1, Ordering::SeqCst);
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

    fn reviewed_plan(operations: Vec<FirewallOperation>) -> MutationPlan {
        MutationPlan::new(operations, Arc::new(mock::sample().unwrap()))
    }

    #[tokio::test]
    async fn initial_refresh_happens_without_a_request() {
        let (_request_tx, request_rx) = mpsc::channel(8);
        let (event_tx, mut event_rx) = mpsc::channel(8);
        let backend = FakeBackend {
            calls: AtomicUsize::new(0),
            fail: false,
        };
        tokio::spawn(run(
            backend,
            TestRollbackGuard,
            request_rx,
            event_tx,
            Duration::from_secs(3600),
            false,
            Duration::from_secs(30),
        ));

        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshStarted
        ));
        match event_rx.recv().await.unwrap() {
            EngineEvent::RefreshFinished {
                result: Ok(snapshot),
                observation,
            } => {
                assert_eq!(snapshot.default_zone.as_str(), "public");
                assert_eq!(observation.process_count, None);
                assert!(observation.sections.is_empty());
            }
            other => panic!("expected successful refresh, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn errors_are_reported_not_swallowed() {
        let (_request_tx, request_rx) = mpsc::channel(8);
        let (event_tx, mut event_rx) = mpsc::channel(8);
        let backend = FakeBackend {
            calls: AtomicUsize::new(0),
            fail: true,
        };
        tokio::spawn(run(
            backend,
            TestRollbackGuard,
            request_rx,
            event_tx,
            Duration::from_secs(3600),
            false,
            Duration::from_secs(30),
        ));

        event_rx.recv().await.unwrap(); // started
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshFinished {
                result: Err(FirewallError::DaemonNotRunning),
                ..
            }
        ));
    }

    #[tokio::test]
    async fn apply_reports_outcome_then_refreshes() {
        let (request_tx, request_rx) = mpsc::channel(8);
        let (event_tx, mut event_rx) = mpsc::channel(8);
        let backend = FakeBackend {
            calls: AtomicUsize::new(0),
            fail: false,
        };
        tokio::spawn(run(
            backend,
            TestRollbackGuard,
            request_rx,
            event_tx,
            Duration::from_secs(3600),
            false,
            Duration::from_secs(30),
        ));
        // initial refresh
        event_rx.recv().await.unwrap();
        event_rx.recv().await.unwrap();

        request_tx
            .send(EngineRequest::Apply(reviewed(FirewallOperation::Reload)))
            .await
            .unwrap();
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::OperationFinished(result)
                if matches!(result.outcome, OperationOutcome::Applied { .. })
        ));
        // post-mutation refresh follows automatically
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshStarted
        ));
    }

    #[tokio::test]
    async fn stale_single_operation_is_rejected_before_apply_or_rollback_arm() {
        let (request_tx, request_rx) = mpsc::channel(8);
        let (event_tx, mut event_rx) = mpsc::channel(8);
        let snapshot_calls = Arc::new(AtomicUsize::new(0));
        let apply_calls = Arc::new(AtomicUsize::new(0));
        let guard = RecordingRollbackGuard::default();
        let guard_log = Arc::clone(&guard.log);
        tokio::spawn(run(
            DriftingBackend {
                snapshot_calls: Arc::clone(&snapshot_calls),
                apply_calls: Arc::clone(&apply_calls),
            },
            guard,
            request_rx,
            event_tx,
            Duration::from_secs(3600),
            false,
            Duration::from_secs(30),
        ));

        event_rx.recv().await.unwrap();
        let expected = match event_rx.recv().await.unwrap() {
            EngineEvent::RefreshFinished {
                result: Ok(snapshot),
                ..
            } => snapshot,
            other => panic!("expected initial snapshot, got {other:?}"),
        };
        let operation = FirewallOperation::RemovePort {
            zone: crate::domain::ZoneName::parse("public").unwrap(),
            port: "8080/tcp".parse().unwrap(),
            target: crate::domain::ConfigurationTarget::Runtime,
        };
        request_tx
            .send(EngineRequest::Apply(MutationRequest::new(
                operation, expected,
            )))
            .await
            .unwrap();

        match event_rx.recv().await.unwrap() {
            EngineEvent::OperationFinished(result) => {
                assert_eq!(
                    result.outcome.first_error(),
                    Some(&FirewallError::StaleSnapshot)
                );
                assert!(result.rollback.is_none());
            }
            other => panic!("expected rejected operation, got {other:?}"),
        }
        assert_eq!(apply_calls.load(Ordering::SeqCst), 0);
        assert!(guard_log.lock().unwrap().armed.is_empty());
        assert!(snapshot_calls.load(Ordering::SeqCst) >= 2);
    }

    #[tokio::test]
    async fn stale_plan_rejects_the_batch_and_returns_every_operation() {
        let (request_tx, request_rx) = mpsc::channel(8);
        let (event_tx, mut event_rx) = mpsc::channel(16);
        let snapshot_calls = Arc::new(AtomicUsize::new(0));
        let apply_calls = Arc::new(AtomicUsize::new(0));
        tokio::spawn(run(
            DriftingBackend {
                snapshot_calls,
                apply_calls: Arc::clone(&apply_calls),
            },
            TestRollbackGuard,
            request_rx,
            event_tx,
            Duration::from_secs(3600),
            false,
            Duration::from_secs(30),
        ));

        event_rx.recv().await.unwrap();
        let expected = match event_rx.recv().await.unwrap() {
            EngineEvent::RefreshFinished {
                result: Ok(snapshot),
                ..
            } => snapshot,
            other => panic!("expected initial snapshot, got {other:?}"),
        };
        let operations = vec![FirewallOperation::Reload, FirewallOperation::Reload];
        request_tx
            .send(EngineRequest::ApplyPlan(MutationPlan::new(
                operations.clone(),
                expected,
            )))
            .await
            .unwrap();

        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::OperationFinished(result)
                if result.outcome.first_error() == Some(&FirewallError::StaleSnapshot)
        ));
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::PlanFinished {
                applied: 0,
                remaining,
            } if remaining == operations
        ));
        assert_eq!(apply_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn read_only_engine_rejects_mutations() {
        let (request_tx, request_rx) = mpsc::channel(8);
        let (event_tx, mut event_rx) = mpsc::channel(8);
        let backend = FakeBackend {
            calls: AtomicUsize::new(0),
            fail: false,
        };
        tokio::spawn(run(
            backend,
            TestRollbackGuard,
            request_rx,
            event_tx,
            Duration::from_secs(3600),
            true,
            Duration::from_secs(30),
        ));
        event_rx.recv().await.unwrap();
        event_rx.recv().await.unwrap();

        request_tx
            .send(EngineRequest::Apply(reviewed(FirewallOperation::Reload)))
            .await
            .unwrap();
        match event_rx.recv().await.unwrap() {
            EngineEvent::OperationFinished(result) => {
                assert_eq!(
                    result.outcome.first_error(),
                    Some(&FirewallError::ReadOnlyMode)
                );
            }
            other => panic!("expected OperationFinished, got {other:?}"),
        }
    }

    /// A backend that succeeds on every `apply` except the Nth call, which it
    /// fails — enough to drive the engine's fail-fast plan logic to a known
    /// halt point without depending on any operation's semantics.
    struct CountingBackend {
        apply_calls: AtomicUsize,
        /// 1-indexed apply call that returns `Failed`; `0` never fails.
        fail_at: usize,
    }

    impl FirewallBackend for CountingBackend {
        async fn probe(&self) -> Result<FirewallStatus, FirewallError> {
            Err(FirewallError::DaemonNotRunning)
        }

        async fn snapshot(&self) -> Result<FirewallSnapshot, FirewallError> {
            mock::sample().map_err(|e| FirewallError::Parse(e.to_string()))
        }

        async fn apply(&self, operation: &FirewallOperation) -> OperationOutcome {
            let call = self.apply_calls.fetch_add(1, Ordering::SeqCst) + 1;
            let step = |result: Result<(), FirewallError>| StepReport {
                target: "runtime",
                invocation: vec!["--fake".to_owned()],
                result,
            };
            if call == self.fail_at {
                OperationOutcome::Failed {
                    operation: operation.clone(),
                    steps: vec![step(Err(FirewallError::DaemonNotRunning))],
                }
            } else {
                OperationOutcome::Applied {
                    operation: operation.clone(),
                    steps: vec![step(Ok(()))],
                }
            }
        }
    }

    #[tokio::test]
    async fn engine_validation_rejects_a_forged_request_before_apply() {
        let backend = CountingBackend {
            apply_calls: AtomicUsize::new(0),
            fail_at: 0,
        };
        let (event_tx, mut event_rx) = mpsc::channel(4);
        let operation = FirewallOperation::AddService {
            zone: crate::domain::ZoneName::parse("public").unwrap(),
            service: crate::domain::ServiceName::parse("https").unwrap(),
            target: crate::domain::ConfigurationTarget::RuntimeAndPermanent,
        };

        apply(
            &backend,
            &TestRollbackGuard,
            &event_tx,
            reviewed(operation),
            false,
            Duration::from_secs(30),
        )
        .await
        .unwrap();

        match event_rx.recv().await.unwrap() {
            EngineEvent::OperationFinished(result) => assert!(matches!(
                result.outcome.first_error(),
                Some(FirewallError::Validation(_))
            )),
            other => panic!("expected validation failure, got {other:?}"),
        }
        assert_eq!(backend.apply_calls.load(Ordering::SeqCst), 0);
    }

    async fn drain_initial_refresh(rx: &mut mpsc::Receiver<EngineEvent>) {
        rx.recv().await.unwrap(); // RefreshStarted
        rx.recv().await.unwrap(); // RefreshFinished
    }

    #[tokio::test]
    async fn plan_halts_on_first_failure_and_returns_the_remainder() {
        let (request_tx, request_rx) = mpsc::channel(8);
        let (event_tx, mut event_rx) = mpsc::channel(16);
        let backend = CountingBackend {
            apply_calls: AtomicUsize::new(0),
            fail_at: 2, // the second operation fails
        };
        tokio::spawn(run(
            backend,
            TestRollbackGuard,
            request_rx,
            event_tx,
            Duration::from_secs(3600),
            false,
            Duration::from_secs(30),
        ));
        drain_initial_refresh(&mut event_rx).await;

        let plan = vec![
            FirewallOperation::Reload,
            FirewallOperation::Reload,
            FirewallOperation::Reload,
            FirewallOperation::Reload,
        ];
        request_tx
            .send(EngineRequest::ApplyPlan(reviewed_plan(plan)))
            .await
            .unwrap();

        // op1 applied, op2 failed — then the plan stops.
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::OperationFinished(result)
                if matches!(result.outcome, OperationOutcome::Applied { .. })
        ));
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::OperationFinished(result)
                if matches!(result.outcome, OperationOutcome::Failed { .. })
        ));
        match event_rx.recv().await.unwrap() {
            EngineEvent::PlanFinished { applied, remaining } => {
                assert_eq!(applied, 1, "only the first op fully applied");
                assert_eq!(
                    remaining.len(),
                    2,
                    "the two unexecuted ops must be returned, not dropped"
                );
            }
            other => panic!("expected PlanFinished, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn plan_arms_only_the_current_item_and_uses_unique_guard_ids() {
        let (request_tx, request_rx) = mpsc::channel(8);
        let (event_tx, mut event_rx) = mpsc::channel(16);
        let backend = CountingBackend {
            apply_calls: AtomicUsize::new(0),
            fail_at: 2,
        };
        let guard = RecordingRollbackGuard::default();
        let guard_log = Arc::clone(&guard.log);
        tokio::spawn(run(
            backend,
            guard,
            request_rx,
            event_tx,
            Duration::from_secs(3600),
            false,
            Duration::from_secs(30),
        ));
        drain_initial_refresh(&mut event_rx).await;

        let operation = FirewallOperation::RemovePort {
            zone: crate::domain::ZoneName::parse("public").unwrap(),
            port: "8080/tcp".parse().unwrap(),
            target: crate::domain::ConfigurationTarget::Runtime,
        };
        request_tx
            .send(EngineRequest::ApplyPlan(reviewed_plan(vec![
                operation.clone(),
                operation.clone(),
                operation.clone(),
            ])))
            .await
            .unwrap();

        let first_id = match event_rx.recv().await.unwrap() {
            EngineEvent::OperationFinished(result)
                if matches!(result.outcome, OperationOutcome::Applied { .. }) =>
            {
                result.rollback.unwrap().id
            }
            other => panic!("expected first applied item with rollback, got {other:?}"),
        };
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::OperationFinished(result)
                if matches!(result.outcome, OperationOutcome::Failed { .. })
                    && result.rollback.is_none()
        ));
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::PlanFinished {
                applied: 1,
                ref remaining,
            } if remaining.len() == 1
        ));

        let log = guard_log.lock().unwrap();
        assert_eq!(
            log.armed.len(),
            2,
            "the unexecuted third item stays unarmed"
        );
        assert_eq!(log.armed[0].1, operation);
        assert_eq!(log.armed[1].1, operation);
        assert_eq!(log.armed[0].0, first_id);
        assert_ne!(
            log.armed[0].0, log.armed[1].0,
            "duplicate operations must not share guard identity"
        );
        assert_eq!(
            log.disarmed,
            [format!("fwdeck-rollback-test-{}", log.armed[1].0.get())],
            "the cleanly failed current item is disarmed"
        );
    }

    #[tokio::test]
    async fn guard_arm_failure_keeps_in_process_rollback_available() {
        let backend = CountingBackend {
            apply_calls: AtomicUsize::new(0),
            fail_at: 0,
        };
        let operation = FirewallOperation::RemovePort {
            zone: crate::domain::ZoneName::parse("public").unwrap(),
            port: "8080/tcp".parse().unwrap(),
            target: crate::domain::ConfigurationTarget::Runtime,
        };

        let (_, outcome, rollback, warning) = execute_operation(
            &backend,
            &FailingArmGuard,
            operation.clone(),
            false,
            Duration::from_secs(30),
            false,
        )
        .await;

        assert!(matches!(outcome, OperationOutcome::Applied { .. }));
        let Some(rollback) = rollback else {
            panic!("in-process rollback must remain registered");
        };
        assert_eq!(rollback.inverse, operation.inverse().unwrap());
        assert!(rollback.watchdog_unit.is_none());
        assert!(warning.is_some_and(|message| message.contains("arm timeout")));
    }

    #[tokio::test]
    async fn clean_failure_reports_disarm_error_without_registering_inverse() {
        let backend = CountingBackend {
            apply_calls: AtomicUsize::new(0),
            fail_at: 1,
        };
        let operation = FirewallOperation::RemovePort {
            zone: crate::domain::ZoneName::parse("public").unwrap(),
            port: "8080/tcp".parse().unwrap(),
            target: crate::domain::ConfigurationTarget::Runtime,
        };

        let (_, outcome, rollback, warning) = execute_operation(
            &backend,
            &FailingDisarmGuard,
            operation,
            false,
            Duration::from_secs(30),
            false,
        )
        .await;

        assert!(matches!(outcome, OperationOutcome::Failed { .. }));
        assert!(rollback.is_none(), "clean failure never exposes an inverse");
        assert!(warning.is_some_and(|message| message.contains("disarm timeout")));
    }

    #[tokio::test]
    async fn rollback_applies_even_when_watchdog_disarm_fails() {
        let backend = CountingBackend {
            apply_calls: AtomicUsize::new(0),
            fail_at: 0,
        };
        let (event_tx, mut event_rx) = mpsc::channel(2);
        let id = RollbackGuardId::new(700);
        let operation = FirewallOperation::AddPort {
            zone: crate::domain::ZoneName::parse("public").unwrap(),
            port: "8080/tcp".parse().unwrap(),
            target: crate::domain::ConfigurationTarget::Runtime,
        };

        apply_rollback(
            &backend,
            &FailingDisarmGuard,
            &event_tx,
            id,
            operation,
            Some("fwdeck-rollback-test-700".to_owned()),
            false,
        )
        .await
        .unwrap();

        match event_rx.recv().await.unwrap() {
            EngineEvent::OperationFinished(result) => {
                assert!(matches!(result.outcome, OperationOutcome::Applied { .. }));
                assert_eq!(result.completed_rollback, Some(id));
                assert!(
                    result
                        .guard_warning
                        .is_some_and(|message| message.contains("disarm timeout"))
                );
            }
            other => panic!("expected rollback result, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn failed_rollback_leaves_watchdog_armed() {
        let backend = CountingBackend {
            apply_calls: AtomicUsize::new(0),
            fail_at: 1,
        };
        let guard = RecordingRollbackGuard::default();
        let guard_log = Arc::clone(&guard.log);
        let (event_tx, mut event_rx) = mpsc::channel(2);
        let id = RollbackGuardId::new(701);
        let operation = FirewallOperation::AddPort {
            zone: crate::domain::ZoneName::parse("public").unwrap(),
            port: "8080/tcp".parse().unwrap(),
            target: crate::domain::ConfigurationTarget::Runtime,
        };

        apply_rollback(
            &backend,
            &guard,
            &event_tx,
            id,
            operation,
            Some("fwdeck-rollback-test-701".to_owned()),
            false,
        )
        .await
        .unwrap();

        match event_rx.recv().await.unwrap() {
            EngineEvent::OperationFinished(result) => {
                assert!(matches!(result.outcome, OperationOutcome::Failed { .. }));
                assert_eq!(result.completed_rollback, Some(id));
                assert!(
                    result
                        .guard_warning
                        .is_some_and(|message| message.contains("remains armed"))
                );
            }
            other => panic!("expected rollback result, got {other:?}"),
        }
        assert!(
            guard_log.lock().unwrap().disarmed.is_empty(),
            "failed inverse must not cancel its external fallback"
        );
    }

    #[tokio::test]
    async fn plan_applies_every_step_when_all_succeed() {
        let (request_tx, request_rx) = mpsc::channel(8);
        let (event_tx, mut event_rx) = mpsc::channel(16);
        let backend = CountingBackend {
            apply_calls: AtomicUsize::new(0),
            fail_at: 0, // never fails
        };
        tokio::spawn(run(
            backend,
            TestRollbackGuard,
            request_rx,
            event_tx,
            Duration::from_secs(3600),
            false,
            Duration::from_secs(30),
        ));
        drain_initial_refresh(&mut event_rx).await;

        let plan = vec![FirewallOperation::Reload, FirewallOperation::Reload];
        request_tx
            .send(EngineRequest::ApplyPlan(reviewed_plan(plan)))
            .await
            .unwrap();

        for _ in 0..2 {
            assert!(matches!(
                event_rx.recv().await.unwrap(),
                EngineEvent::OperationFinished(result)
                    if matches!(result.outcome, OperationOutcome::Applied { .. })
            ));
        }
        match event_rx.recv().await.unwrap() {
            EngineEvent::PlanFinished { applied, remaining } => {
                assert_eq!(applied, 2);
                assert!(remaining.is_empty(), "nothing left when the plan succeeds");
            }
            other => panic!("expected PlanFinished, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn apply_is_not_coalesced_away_by_surrounding_refreshes() {
        let (request_tx, request_rx) = mpsc::channel(16);
        let (event_tx, mut event_rx) = mpsc::channel(32);
        let backend = CountingBackend {
            apply_calls: AtomicUsize::new(0),
            fail_at: 0,
        };
        tokio::spawn(run(
            backend,
            TestRollbackGuard,
            request_rx,
            event_tx,
            Duration::from_secs(3600),
            false,
            Duration::from_secs(30),
        ));
        drain_initial_refresh(&mut event_rx).await;

        // A burst with refreshes on both sides of an Apply. Queued refreshes may
        // coalesce into one; the Apply must survive and execute exactly once.
        request_tx.send(EngineRequest::Refresh).await.unwrap();
        request_tx
            .send(EngineRequest::Apply(reviewed(FirewallOperation::Reload)))
            .await
            .unwrap();
        request_tx.send(EngineRequest::Refresh).await.unwrap();

        // Bounded drain: a coalescing bug that swallowed the Apply would let this
        // loop finish without ever seeing the outcome.
        let mut applied = 0;
        for _ in 0..16 {
            if let EngineEvent::OperationFinished(result) = event_rx.recv().await.unwrap()
                && matches!(result.outcome, OperationOutcome::Applied { .. })
            {
                applied += 1;
                break;
            }
        }
        assert_eq!(applied, 1, "the Apply must survive refresh coalescing");
    }

    #[tokio::test]
    async fn manual_refresh_request_triggers_refresh() {
        let (request_tx, request_rx) = mpsc::channel(8);
        let (event_tx, mut event_rx) = mpsc::channel(8);
        let backend = FakeBackend {
            calls: AtomicUsize::new(0),
            fail: false,
        };
        tokio::spawn(run(
            backend,
            TestRollbackGuard,
            request_rx,
            event_tx,
            Duration::from_secs(3600),
            false,
            Duration::from_secs(30),
        ));

        // initial refresh
        event_rx.recv().await.unwrap();
        event_rx.recv().await.unwrap();

        request_tx.send(EngineRequest::Refresh).await.unwrap();
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshStarted
        ));
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshFinished { result: Ok(_), .. }
        ));
    }

    #[tokio::test]
    async fn performance_budget_large_snapshot_refresh_stays_under_two_seconds() {
        let (_request_tx, request_rx) = mpsc::channel(8);
        let (event_tx, mut event_rx) = mpsc::channel(8);
        let started = std::time::Instant::now();
        tokio::spawn(run(
            LargeBackend,
            TestRollbackGuard,
            request_rx,
            event_tx,
            Duration::from_secs(3600),
            false,
            Duration::from_secs(30),
        ));

        let result = tokio::time::timeout(Duration::from_secs(2), async {
            assert!(matches!(
                event_rx.recv().await.unwrap(),
                EngineEvent::RefreshStarted
            ));
            event_rx.recv().await.unwrap()
        })
        .await
        .unwrap();

        assert!(matches!(
            result,
            EngineEvent::RefreshFinished {
                result: Ok(snapshot),
                ..
            } if snapshot.zone_names().len() == 100
        ));
        assert!(started.elapsed() < Duration::from_secs(2));
    }
}
