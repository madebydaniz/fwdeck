//! The engine task: single owner of the backend. Requests are processed
//! serially (mutations serialize structurally), refreshes are
//! coalesced, and events reach the UI in order — no stale-result races.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;

use std::sync::atomic::{AtomicU64, Ordering};

use super::api::{EngineEvent, EngineRequest};
use super::ports::{FirewallBackend, FirewallError, OperationOutcome, StepReport};

/// Process-wide operation counter. The id it mints is logged via tracing and
/// written to the audit line for the same operation, so `fwdeck.log` and
/// `audit.jsonl` can be joined on one field even across identical retries.
static OP_SEQ: AtomicU64 = AtomicU64::new(1);

/// The next correlation id for an operation.
pub fn next_op_id() -> u64 {
    OP_SEQ.fetch_add(1, Ordering::Relaxed)
}

pub(crate) async fn run<B: FirewallBackend>(
    backend: B,
    mut requests: mpsc::Receiver<EngineRequest>,
    events: mpsc::Sender<EngineEvent>,
    refresh_interval: Duration,
    read_only: bool,
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
                    loop {
                        match requests.try_recv() {
                            Ok(EngineRequest::Refresh) => {}
                            Ok(EngineRequest::Apply(operation)) => {
                                if apply(&backend, &events, operation, read_only).await.is_err() {
                                    return;
                                }
                            }
                            Ok(EngineRequest::ApplyPlan(operations)) => {
                                if apply_plan(&backend, &events, operations, read_only)
                                    .await
                                    .is_err()
                                {
                                    return;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                    interval.reset();
                    if refresh(&backend, &events).await.is_err() {
                        break;
                    }
                }
                Some(EngineRequest::Apply(operation)) => {
                    if apply(&backend, &events, operation, read_only).await.is_err() {
                        break;
                    }
                    // Post-mutation refresh: even a failure may have changed state.
                    interval.reset();
                    if refresh(&backend, &events).await.is_err() {
                        break;
                    }
                }
                Some(EngineRequest::ApplyPlan(operations)) => {
                    if apply_plan(&backend, &events, operations, read_only).await.is_err() {
                        break;
                    }
                    // One refresh for the whole plan, not one per operation.
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

/// Executes a staged plan sequentially, halting on the first outcome that is
/// not fully applied (fail-fast: continuing after a partial failure could
/// compound damage). Every per-operation outcome still flows to the UI as
/// `OperationFinished`; unexecuted operations are returned in `PlanFinished`
/// so nothing is silently lost. Returns `Err(())` when the UI is gone.
async fn apply_plan<B: FirewallBackend>(
    backend: &B,
    events: &mpsc::Sender<EngineEvent>,
    operations: Vec<crate::domain::FirewallOperation>,
    read_only: bool,
) -> Result<(), ()> {
    let total = operations.len();
    let mut iter = operations.into_iter();
    let mut applied = 0usize;
    let mut halted = false;
    for operation in iter.by_ref() {
        let op_id = next_op_id();
        let outcome = if read_only {
            OperationOutcome::Failed {
                operation: operation.clone(),
                steps: vec![StepReport {
                    target: "policy",
                    invocation: Vec::new(),
                    result: Err(FirewallError::ReadOnlyMode),
                }],
            }
        } else {
            tracing::info!(op_id, operation = %operation.describe(), "applying plan operation");
            backend.apply(&operation).await
        };
        let fully_applied = matches!(outcome, OperationOutcome::Applied { .. });
        if events
            .send(EngineEvent::OperationFinished { op_id, outcome })
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
async fn apply<B: FirewallBackend>(
    backend: &B,
    events: &mpsc::Sender<EngineEvent>,
    operation: crate::domain::FirewallOperation,
    read_only: bool,
) -> Result<(), ()> {
    let op_id = next_op_id();
    let outcome = if read_only {
        // Enforced here, not in the UI: no code path can mutate in read-only mode.
        OperationOutcome::Failed {
            operation: operation.clone(),
            steps: vec![StepReport {
                target: "policy",
                invocation: Vec::new(),
                result: Err(FirewallError::ReadOnlyMode),
            }],
        }
    } else {
        tracing::info!(op_id, operation = %operation.describe(), "applying operation");
        backend.apply(&operation).await
    };
    match &outcome {
        OperationOutcome::Applied { .. } => {
            tracing::info!(operation = %operation.describe(), "operation applied");
        }
        OperationOutcome::PartiallyApplied { .. }
        | OperationOutcome::Failed { .. }
        | OperationOutcome::Indeterminate { .. } => {
            tracing::warn!(operation = %operation.describe(), outcome = ?outcome, "operation not fully applied");
        }
    }
    events
        .send(EngineEvent::OperationFinished { op_id, outcome })
        .await
        .map_err(|_| ())
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
    let started = std::time::Instant::now();
    let result = backend.snapshot().await.map(Arc::new);
    match &result {
        Ok(snapshot) => tracing::debug!(
            zones = snapshot.runtime.len(),
            elapsed_ms = started.elapsed().as_millis(),
            "refresh finished"
        ),
        Err(err) => tracing::warn!(error = %err, "refresh failed"),
    }
    events
        .send(EngineEvent::RefreshFinished(result))
        .await
        .map_err(|_| ())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::application::ports::{FirewallBackend, FirewallError};
    use crate::domain::{FirewallOperation, FirewallSnapshot, FirewallStatus, mock};
    use std::sync::atomic::{AtomicUsize, Ordering};

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
            request_rx,
            event_tx,
            Duration::from_secs(3600),
            false,
        ));

        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshStarted
        ));
        match event_rx.recv().await.unwrap() {
            EngineEvent::RefreshFinished(Ok(snapshot)) => {
                assert_eq!(snapshot.default_zone.as_str(), "public");
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
            request_rx,
            event_tx,
            Duration::from_secs(3600),
            false,
        ));

        event_rx.recv().await.unwrap(); // started
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshFinished(Err(FirewallError::DaemonNotRunning))
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
            request_rx,
            event_tx,
            Duration::from_secs(3600),
            false,
        ));
        // initial refresh
        event_rx.recv().await.unwrap();
        event_rx.recv().await.unwrap();

        request_tx
            .send(EngineRequest::Apply(FirewallOperation::Reload))
            .await
            .unwrap();
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::OperationFinished {
                outcome: OperationOutcome::Applied { .. },
                ..
            }
        ));
        // post-mutation refresh follows automatically
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshStarted
        ));
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
            request_rx,
            event_tx,
            Duration::from_secs(3600),
            true,
        ));
        event_rx.recv().await.unwrap();
        event_rx.recv().await.unwrap();

        request_tx
            .send(EngineRequest::Apply(FirewallOperation::Reload))
            .await
            .unwrap();
        match event_rx.recv().await.unwrap() {
            EngineEvent::OperationFinished { outcome, .. } => {
                assert_eq!(outcome.first_error(), Some(&FirewallError::ReadOnlyMode));
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
            request_rx,
            event_tx,
            Duration::from_secs(3600),
            false,
        ));
        drain_initial_refresh(&mut event_rx).await;

        let plan = vec![
            FirewallOperation::Reload,
            FirewallOperation::Reload,
            FirewallOperation::Reload,
            FirewallOperation::Reload,
        ];
        request_tx
            .send(EngineRequest::ApplyPlan(plan))
            .await
            .unwrap();

        // op1 applied, op2 failed — then the plan stops.
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::OperationFinished {
                outcome: OperationOutcome::Applied { .. },
                ..
            }
        ));
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::OperationFinished {
                outcome: OperationOutcome::Failed { .. },
                ..
            }
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
    async fn plan_applies_every_step_when_all_succeed() {
        let (request_tx, request_rx) = mpsc::channel(8);
        let (event_tx, mut event_rx) = mpsc::channel(16);
        let backend = CountingBackend {
            apply_calls: AtomicUsize::new(0),
            fail_at: 0, // never fails
        };
        tokio::spawn(run(
            backend,
            request_rx,
            event_tx,
            Duration::from_secs(3600),
            false,
        ));
        drain_initial_refresh(&mut event_rx).await;

        let plan = vec![FirewallOperation::Reload, FirewallOperation::Reload];
        request_tx
            .send(EngineRequest::ApplyPlan(plan))
            .await
            .unwrap();

        for _ in 0..2 {
            assert!(matches!(
                event_rx.recv().await.unwrap(),
                EngineEvent::OperationFinished {
                    outcome: OperationOutcome::Applied { .. },
                    ..
                }
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
            request_rx,
            event_tx,
            Duration::from_secs(3600),
            false,
        ));
        drain_initial_refresh(&mut event_rx).await;

        // A burst with refreshes on both sides of an Apply. Queued refreshes may
        // coalesce into one; the Apply must survive and execute exactly once.
        request_tx.send(EngineRequest::Refresh).await.unwrap();
        request_tx
            .send(EngineRequest::Apply(FirewallOperation::Reload))
            .await
            .unwrap();
        request_tx.send(EngineRequest::Refresh).await.unwrap();

        // Bounded drain: a coalescing bug that swallowed the Apply would let this
        // loop finish without ever seeing the outcome.
        let mut applied = 0;
        for _ in 0..16 {
            if let EngineEvent::OperationFinished {
                outcome: OperationOutcome::Applied { .. },
                ..
            } = event_rx.recv().await.unwrap()
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
            request_rx,
            event_tx,
            Duration::from_secs(3600),
            false,
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
            EngineEvent::RefreshFinished(Ok(_))
        ));
    }
}
