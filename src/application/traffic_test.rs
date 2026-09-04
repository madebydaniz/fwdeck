//! Bounded single-flight orchestration for native traffic evaluation.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::Sleep;

use crate::domain::{
    EvaluationContext, EvaluationPhase, TrafficEvaluationError, TrafficEvaluationIndex,
    TrafficReportError, TrafficScenario, TrafficSuite, TrafficTestReport, TrafficTestResult,
    TrafficValidationError, evaluate_scenario,
};

/// Maximum commands waiting at the coordinator boundary.
pub const TRAFFIC_TEST_REQUEST_CAPACITY: usize = 8;
/// Maximum application events waiting for a consumer.
pub const TRAFFIC_TEST_EVENT_CAPACITY: usize = 8;
/// Maximum distinct logical contexts retained behind the active run.
pub const TRAFFIC_TEST_PENDING_CONTEXT_CAPACITY: usize = 8;
/// Maximum scenarios evaluated between cooperative cancellation checks.
pub const TRAFFIC_TEST_CANCELLATION_INTERVAL: usize = 32;
/// Hard wall-clock budget for one complete evaluation.
pub const TRAFFIC_TEST_EVALUATION_DEADLINE: Duration = Duration::from_secs(2);
/// Maximum time an explicit shutdown waits before returning ownership to the caller.
pub const TRAFFIC_TEST_SHUTDOWN_DEADLINE: Duration = Duration::from_secs(2);

/// Evaluates one scenario without owning scheduling, publication, or mutable application state.
pub trait TrafficScenarioEvaluator: Send + Sync + 'static {
    /// Produces one bounded domain result for the supplied immutable evidence.
    fn evaluate(
        &self,
        index: &TrafficEvaluationIndex,
        scenario: &TrafficScenario,
        context: &EvaluationContext,
    ) -> Result<TrafficTestResult, TrafficEvaluationError>;
}

#[derive(Debug)]
struct NativeTrafficScenarioEvaluator;

impl TrafficScenarioEvaluator for NativeTrafficScenarioEvaluator {
    fn evaluate(
        &self,
        index: &TrafficEvaluationIndex,
        scenario: &TrafficScenario,
        context: &EvaluationContext,
    ) -> Result<TrafficTestResult, TrafficEvaluationError> {
        evaluate_scenario(index, scenario, context)
    }
}

/// One validated immutable unit of coordinator work.
#[derive(Debug)]
pub struct TrafficTestEvaluationRequest {
    context: EvaluationContext,
    suite: Arc<TrafficSuite>,
    index: TrafficEvaluationIndex,
}

impl TrafficTestEvaluationRequest {
    /// Binds a suite and target-specific index to one exact evaluation identity.
    pub fn new(
        context: EvaluationContext,
        suite: Arc<TrafficSuite>,
        index: TrafficEvaluationIndex,
    ) -> Result<Self, TrafficTestRequestError> {
        context
            .validate()
            .map_err(TrafficTestRequestError::InvalidContext)?;
        suite
            .validate()
            .map_err(TrafficTestRequestError::InvalidSuite)?;
        if suite.id != context.suite_id {
            return Err(TrafficTestRequestError::SuiteIdentityMismatch);
        }
        if suite.revision != context.suite_revision {
            return Err(TrafficTestRequestError::SuiteRevisionMismatch);
        }
        if index.target() != context.target {
            return Err(TrafficTestRequestError::TargetMismatch);
        }
        Ok(Self {
            context,
            suite,
            index,
        })
    }

    /// Returns the immutable run identity boundary.
    #[must_use]
    pub const fn context(&self) -> &EvaluationContext {
        &self.context
    }
}

/// Invalid identity or suite binding rejected before work is queued.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TrafficTestRequestError {
    /// The evaluation context is internally inconsistent.
    #[error("invalid evaluation context: {0}")]
    InvalidContext(TrafficReportError),
    /// The suite violates its persisted schema contract.
    #[error("invalid traffic suite: {0}")]
    InvalidSuite(TrafficValidationError),
    /// The suite and evaluation context name different suites.
    #[error("suite identity does not match the evaluation context")]
    SuiteIdentityMismatch,
    /// The suite and evaluation context carry different revisions.
    #[error("suite revision does not match the evaluation context")]
    SuiteRevisionMismatch,
    /// The immutable index represents a different runtime/permanent target.
    #[error("evaluation index target does not match the evaluation context")]
    TargetMismatch,
}

/// Why an accepted run ended cooperatively without a report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrafficTestCancellationReason {
    /// A newer request replaced the same logical evaluation context.
    Superseded,
    /// Snapshot, suite, mutation, plan, candidate, or target identity changed.
    StaleContext,
    /// Application ownership ended before evaluation completed.
    Shutdown,
}

/// Typed terminal failure that can never authorize a mutation gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrafficTestFailureReason {
    /// Eight different logical contexts are already pending.
    Busy,
    /// Evaluation exceeded the two-second hard deadline.
    EvaluationLimitExceeded,
    /// A scenario or report failed its domain contract.
    EvaluationFailed(String),
    /// The owned blocking worker terminated unexpectedly.
    WorkerFailed,
}

/// One bounded coordinator lifecycle event.
#[derive(Debug)]
pub enum TrafficTestEvent {
    /// The coordinator published start before spawning CPU-heavy work.
    EvaluationStarted {
        /// Exact identity that started.
        context: EvaluationContext,
    },
    /// One complete immutable aggregate report passed every freshness guard.
    EvaluationFinished {
        /// Authoritative complete publication unit.
        report: Arc<TrafficTestReport>,
    },
    /// An accepted run was cooperatively stopped.
    EvaluationCancelled {
        /// Exact identity of the stopped run.
        context: EvaluationContext,
        /// Typed cancellation cause.
        reason: TrafficTestCancellationReason,
    },
    /// An accepted request could not produce authoritative evidence.
    EvaluationFailed {
        /// Exact identity that failed.
        context: EvaluationContext,
        /// Typed fail-closed cause.
        reason: TrafficTestFailureReason,
    },
}

impl TrafficTestEvent {
    /// Returns the exact identity carried by every lifecycle event.
    #[must_use]
    pub fn context(&self) -> &EvaluationContext {
        match self {
            Self::EvaluationStarted { context }
            | Self::EvaluationCancelled { context, .. }
            | Self::EvaluationFailed { context, .. } => context,
            Self::EvaluationFinished { report } => report.context(),
        }
    }
}

/// Immediate bounded-channel submission failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TrafficTestSubmissionError {
    /// The capacity-eight request boundary is full.
    #[error("traffic-test request queue is full")]
    Busy,
    /// Coordinator ownership has ended.
    #[error("traffic-test coordinator is closed")]
    Closed,
    /// An invalid context cannot invalidate authoritative evidence.
    #[error("invalid evaluation context: {0}")]
    InvalidContext(TrafficReportError),
}

/// Explicit shutdown did not reach a terminal owned state in time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TrafficTestShutdownError {
    /// The caller retains the coordinator and may await shutdown again.
    #[error("traffic-test coordinator shutdown exceeded its deadline")]
    DeadlineExceeded,
    /// The coordinator task panicked or was aborted.
    #[error("traffic-test coordinator task failed")]
    TaskFailed,
}

enum CoordinatorCommand {
    Evaluate(TrafficTestEvaluationRequest),
    Invalidate(EvaluationContext),
}

/// Owner of the coordinator task, its bounded channels, and every blocking worker.
pub struct TrafficTestCoordinator {
    requests: mpsc::Sender<CoordinatorCommand>,
    events: mpsc::Receiver<TrafficTestEvent>,
    latest_contexts: LatestContexts,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
}

impl TrafficTestCoordinator {
    /// Starts the native evaluator on an independent bounded application lane.
    #[must_use]
    pub fn spawn() -> Self {
        Self::spawn_with_evaluator(Arc::new(NativeTrafficScenarioEvaluator))
    }

    /// Starts the coordinator with an injected pure evaluator.
    ///
    /// This extension point exists for deterministic scheduling and cancellation tests. The
    /// evaluator must remain bounded, synchronous, and free of spawned work.
    #[must_use]
    pub fn spawn_with_evaluator<E>(evaluator: Arc<E>) -> Self
    where
        E: TrafficScenarioEvaluator,
    {
        let (request_tx, request_rx) = mpsc::channel(TRAFFIC_TEST_REQUEST_CAPACITY);
        let (event_tx, event_rx) = mpsc::channel(TRAFFIC_TEST_EVENT_CAPACITY);
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let latest_contexts = Arc::new(Mutex::new(Vec::new()));
        let evaluator: Arc<dyn TrafficScenarioEvaluator> = evaluator;
        let task = tokio::spawn(run_coordinator(
            evaluator,
            request_rx,
            event_tx,
            shutdown_rx,
            latest_contexts.clone(),
        ));
        Self {
            requests: request_tx,
            events: event_rx,
            latest_contexts,
            shutdown: Some(shutdown_tx),
            task: Some(task),
        }
    }

    /// Queues an evaluation without waiting for request capacity.
    pub fn try_evaluate(
        &self,
        request: TrafficTestEvaluationRequest,
    ) -> Result<(), TrafficTestSubmissionError> {
        let key = EvaluationKey::from_context(&request.context);
        let context = request.context.clone();
        let mut latest_contexts = self
            .latest_contexts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let result = self
            .requests
            .try_send(CoordinatorCommand::Evaluate(request))
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => TrafficTestSubmissionError::Busy,
                mpsc::error::TrySendError::Closed(_) => TrafficTestSubmissionError::Closed,
            });
        if result.is_ok() {
            latest_upsert_locked(
                &mut latest_contexts,
                key,
                context,
                LatestContextCause::Evaluation,
            );
        }
        result
    }

    /// Invalidates matching active and pending evidence without scheduling replacement work.
    pub fn try_invalidate(
        &self,
        context: EvaluationContext,
    ) -> Result<(), TrafficTestSubmissionError> {
        context
            .validate()
            .map_err(TrafficTestSubmissionError::InvalidContext)?;
        let key = EvaluationKey::from_context(&context);
        let latest = context.clone();
        let mut latest_contexts = self
            .latest_contexts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let result = self
            .requests
            .try_send(CoordinatorCommand::Invalidate(context))
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => TrafficTestSubmissionError::Busy,
                mpsc::error::TrySendError::Closed(_) => TrafficTestSubmissionError::Closed,
            });
        if result.is_ok() {
            latest_upsert_locked(
                &mut latest_contexts,
                key,
                latest,
                LatestContextCause::Invalidation,
            );
        }
        result
    }

    /// Receives the next bounded lifecycle event.
    pub async fn next_event(&mut self) -> Option<TrafficTestEvent> {
        self.events.recv().await
    }

    /// Returns the fixed request-channel capacity.
    #[must_use]
    pub const fn request_capacity_limit(&self) -> usize {
        TRAFFIC_TEST_REQUEST_CAPACITY
    }

    /// Returns the fixed result-channel capacity.
    #[must_use]
    pub const fn result_capacity_limit(&self) -> usize {
        TRAFFIC_TEST_EVENT_CAPACITY
    }

    /// Returns currently available request slots.
    #[must_use]
    pub fn remaining_request_capacity(&self) -> usize {
        self.requests.capacity()
    }

    /// Returns currently available result slots.
    #[must_use]
    pub fn remaining_result_capacity(&self) -> usize {
        self.events.capacity()
    }

    /// Cancels active work and joins the owned task within the shutdown deadline.
    ///
    /// On timeout, the task handle remains retained so the caller can invoke shutdown again.
    pub async fn shutdown(&mut self) -> Result<(), TrafficTestShutdownError> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let Some(task) = self.task.as_mut() else {
            return Ok(());
        };
        match tokio::time::timeout(TRAFFIC_TEST_SHUTDOWN_DEADLINE, task).await {
            Ok(Ok(())) => {
                self.task.take();
                Ok(())
            }
            Ok(Err(_)) => {
                self.task.take();
                Err(TrafficTestShutdownError::TaskFailed)
            }
            Err(_) => Err(TrafficTestShutdownError::DeadlineExceeded),
        }
    }
}

impl Drop for TrafficTestCoordinator {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EvaluationKey {
    suite_id: crate::domain::TrafficSuiteId,
    phase: EvaluationPhase,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LatestContextCause {
    Evaluation,
    Invalidation,
}

#[derive(Debug, Clone)]
struct LatestContext {
    key: EvaluationKey,
    context: EvaluationContext,
    cause: LatestContextCause,
}

type LatestContexts = Arc<Mutex<Vec<LatestContext>>>;

fn latest_upsert_locked(
    contexts: &mut Vec<LatestContext>,
    key: EvaluationKey,
    context: EvaluationContext,
    cause: LatestContextCause,
) {
    if let Some(latest) = contexts.iter_mut().find(|latest| latest.key == key) {
        latest.context = context;
        latest.cause = cause;
    } else {
        contexts.push(LatestContext {
            key,
            context,
            cause,
        });
    }
}

fn latest_upsert(
    contexts: &LatestContexts,
    key: EvaluationKey,
    context: EvaluationContext,
    cause: LatestContextCause,
) {
    let mut contexts = contexts
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    latest_upsert_locked(&mut contexts, key, context, cause);
}

fn latest_for(contexts: &LatestContexts, key: &EvaluationKey) -> Option<LatestContext> {
    contexts
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .find(|latest| latest.key == *key)
        .cloned()
}

fn remove_latest_if(
    contexts: &LatestContexts,
    key: &EvaluationKey,
    predicate: impl Fn(&LatestContext) -> bool,
) {
    let mut contexts = contexts
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(position) = contexts
        .iter()
        .position(|latest| latest.key == *key && predicate(latest))
    {
        contexts.remove(position);
    }
}

impl EvaluationKey {
    fn from_context(context: &EvaluationContext) -> Self {
        Self {
            suite_id: context.suite_id.clone(),
            phase: context.phase,
        }
    }
}

#[derive(Default)]
struct PendingEvaluations {
    requests: VecDeque<TrafficTestEvaluationRequest>,
}

impl PendingEvaluations {
    fn upsert(
        &mut self,
        request: TrafficTestEvaluationRequest,
    ) -> Option<TrafficTestEvaluationRequest> {
        let key = EvaluationKey::from_context(&request.context);
        if let Some(existing) = self
            .requests
            .iter_mut()
            .find(|existing| EvaluationKey::from_context(&existing.context) == key)
        {
            *existing = request;
            return None;
        }
        if self.requests.len() == TRAFFIC_TEST_PENDING_CONTEXT_CAPACITY {
            return Some(request);
        }
        self.requests.push_back(request);
        None
    }

    fn remove(&mut self, key: &EvaluationKey) {
        self.requests
            .retain(|request| EvaluationKey::from_context(&request.context) != *key);
    }

    fn pop_front(&mut self) -> Option<TrafficTestEvaluationRequest> {
        self.requests.pop_front()
    }
}

struct QueuedEvent {
    event: TrafficTestEvent,
    start_after_publication: Option<TrafficTestEvaluationRequest>,
}

fn start_is_latest(queued: &QueuedEvent, latest_contexts: &LatestContexts) -> bool {
    let Some(request) = queued.start_after_publication.as_ref() else {
        return true;
    };
    let key = EvaluationKey::from_context(&request.context);
    latest_for(latest_contexts, &key).is_some_and(|latest| {
        latest.cause == LatestContextCause::Evaluation && latest.context == request.context
    })
}

fn prepare_terminal_publication(event: &mut TrafficTestEvent, latest_contexts: &LatestContexts) {
    let TrafficTestEvent::EvaluationFinished { report } = event else {
        return;
    };
    let context = report.context().clone();
    let key = EvaluationKey::from_context(&context);
    let latest = latest_for(latest_contexts, &key);
    if latest
        .as_ref()
        .is_some_and(|latest| latest.context == context)
    {
        return;
    }
    let reason = if latest.is_some_and(|latest| latest.cause == LatestContextCause::Evaluation) {
        TrafficTestCancellationReason::Superseded
    } else {
        TrafficTestCancellationReason::StaleContext
    };
    *event = TrafficTestEvent::EvaluationCancelled { context, reason };
}

struct TerminalCleanup {
    key: EvaluationKey,
    context: EvaluationContext,
    stale_invalidation: bool,
}

fn terminal_cleanup(event: &TrafficTestEvent) -> Option<TerminalCleanup> {
    if matches!(event, TrafficTestEvent::EvaluationStarted { .. }) {
        return None;
    }
    let stale_invalidation = matches!(
        event,
        TrafficTestEvent::EvaluationCancelled {
            reason: TrafficTestCancellationReason::StaleContext,
            ..
        }
    );
    let context = event.context().clone();
    Some(TerminalCleanup {
        key: EvaluationKey::from_context(&context),
        context,
        stale_invalidation,
    })
}

fn cleanup_latest(cleanup: Option<TerminalCleanup>, latest_contexts: &LatestContexts) {
    let Some(cleanup) = cleanup else { return };
    remove_latest_if(latest_contexts, &cleanup.key, |latest| {
        latest.context == cleanup.context
            || (cleanup.stale_invalidation && latest.cause == LatestContextCause::Invalidation)
    });
}

enum WorkerOutcome {
    Completed(Arc<TrafficTestReport>),
    Cancelled,
    Failed(String),
}

enum ActiveCancellation {
    Superseded,
    StaleContext,
    Deadline,
    Shutdown,
}

struct ActiveEvaluation {
    key: EvaluationKey,
    context: EvaluationContext,
    expected_context: EvaluationContext,
    cancellation: Option<ActiveCancellation>,
    cancellation_flag: Arc<AtomicBool>,
    deadline: std::pin::Pin<Box<Sleep>>,
    deadline_armed: bool,
    worker: JoinHandle<WorkerOutcome>,
}

impl ActiveEvaluation {
    fn cancel(&mut self, cancellation: ActiveCancellation) {
        if self.cancellation.is_none() {
            self.cancellation = Some(cancellation);
            self.deadline_armed = false;
            self.cancellation_flag.store(true, Ordering::Release);
        }
    }
}

async fn run_coordinator(
    evaluator: Arc<dyn TrafficScenarioEvaluator>,
    mut requests: mpsc::Receiver<CoordinatorCommand>,
    events: mpsc::Sender<TrafficTestEvent>,
    mut shutdown: oneshot::Receiver<()>,
    latest_contexts: LatestContexts,
) {
    let mut pending = PendingEvaluations::default();
    let mut queued_events = VecDeque::<QueuedEvent>::with_capacity(2);
    let mut active: Option<ActiveEvaluation> = None;

    loop {
        queue_next_start(active.as_ref(), &mut pending, &mut queued_events);

        if let Some(current) = active.as_mut() {
            tokio::select! {
                biased;
                _ = &mut shutdown => {
                    current.cancel(ActiveCancellation::Shutdown);
                    let _ = (&mut current.worker).await;
                    return;
                }
                command = requests.recv(), if queued_events.len() < TRAFFIC_TEST_EVENT_CAPACITY => {
                    let Some(command) = command else {
                        current.cancel(ActiveCancellation::Shutdown);
                        let _ = (&mut current.worker).await;
                        return;
                    };
                    accept_command(
                        command,
                        Some(current),
                        &mut pending,
                        &mut queued_events,
                        &latest_contexts,
                    );
                }
                () = current.deadline.as_mut(), if current.deadline_armed => {
                    current.cancel(ActiveCancellation::Deadline);
                }
                outcome = &mut current.worker => {
                    let Some(current) = active.take() else { return };
                    queued_events.push_back(terminal_event(current, outcome));
                }
                permit = events.reserve(), if !queued_events.is_empty() => {
                    let Ok(permit) = permit else {
                        current.cancel(ActiveCancellation::Shutdown);
                        let _ = (&mut current.worker).await;
                        return;
                    };
                    let Some(mut queued) = queued_events.pop_front() else { return };
                    debug_assert!(queued.start_after_publication.is_none());
                    prepare_terminal_publication(&mut queued.event, &latest_contexts);
                    let cleanup = terminal_cleanup(&queued.event);
                    permit.send(queued.event);
                    cleanup_latest(cleanup, &latest_contexts);
                }
            }
            continue;
        }

        if !queued_events.is_empty() {
            tokio::select! {
                biased;
                _ = &mut shutdown => return,
                command = requests.recv(), if queued_events.len() < TRAFFIC_TEST_EVENT_CAPACITY => {
                    let Some(command) = command else { return };
                    accept_command(
                        command,
                        None,
                        &mut pending,
                        &mut queued_events,
                        &latest_contexts,
                    );
                }
                permit = events.reserve() => {
                    let Ok(permit) = permit else { return };
                    let Some(mut queued) = queued_events.pop_front() else { return };
                    if !start_is_latest(&queued, &latest_contexts) {
                        continue;
                    }
                    prepare_terminal_publication(&mut queued.event, &latest_contexts);
                    let cleanup = terminal_cleanup(&queued.event);
                    permit.send(queued.event);
                    cleanup_latest(cleanup, &latest_contexts);
                    if let Some(request) = queued.start_after_publication {
                        active = Some(start_evaluation(request, evaluator.clone()));
                    }
                }
            }
            continue;
        }

        tokio::select! {
            biased;
            _ = &mut shutdown => return,
            command = requests.recv() => {
                let Some(command) = command else { return };
                accept_command(
                    command,
                    None,
                    &mut pending,
                    &mut queued_events,
                    &latest_contexts,
                );
            }
        }
    }
}

fn queue_next_start(
    active: Option<&ActiveEvaluation>,
    pending: &mut PendingEvaluations,
    queued_events: &mut VecDeque<QueuedEvent>,
) {
    if active.is_some() || !queued_events.is_empty() {
        return;
    }
    if let Some(request) = pending.pop_front() {
        queued_events.push_back(QueuedEvent {
            event: TrafficTestEvent::EvaluationStarted {
                context: request.context.clone(),
            },
            start_after_publication: Some(request),
        });
    }
}

fn accept_command(
    command: CoordinatorCommand,
    active: Option<&mut ActiveEvaluation>,
    pending: &mut PendingEvaluations,
    queued_events: &mut VecDeque<QueuedEvent>,
    latest_contexts: &LatestContexts,
) {
    match command {
        CoordinatorCommand::Evaluate(request) => {
            let key = EvaluationKey::from_context(&request.context);
            let context = request.context.clone();
            let accepted_active_context = active
                .as_ref()
                .filter(|active| active.key == key)
                .map(|active| active.expected_context.clone());
            if let Some(rejected) = pending.upsert(request) {
                let rejected_key = EvaluationKey::from_context(&rejected.context);
                let rejected_context = rejected.context.clone();
                queued_events.push_back(QueuedEvent {
                    event: TrafficTestEvent::EvaluationFailed {
                        context: rejected.context,
                        reason: TrafficTestFailureReason::Busy,
                    },
                    start_after_publication: None,
                });
                if let Some(active_context) = accepted_active_context {
                    latest_upsert(
                        latest_contexts,
                        rejected_key,
                        active_context,
                        LatestContextCause::Evaluation,
                    );
                } else {
                    remove_latest_if(latest_contexts, &rejected_key, |latest| {
                        latest.context == rejected_context
                    });
                }
                return;
            }
            if let Some(active) = active
                && active.key == key
            {
                active.expected_context = context;
                active.cancel(ActiveCancellation::Superseded);
            }
        }
        CoordinatorCommand::Invalidate(context) => {
            let key = EvaluationKey::from_context(&context);
            pending.remove(&key);
            let mut retained_for_active = false;
            if let Some(active) = active
                && active.key == key
            {
                retained_for_active = true;
                if active.expected_context != context {
                    active.expected_context = context.clone();
                    active.cancel(ActiveCancellation::StaleContext);
                }
            }
            if !retained_for_active {
                remove_latest_if(latest_contexts, &key, |latest| {
                    latest.context == context && latest.cause == LatestContextCause::Invalidation
                });
            }
        }
    }
}

fn start_evaluation(
    request: TrafficTestEvaluationRequest,
    evaluator: Arc<dyn TrafficScenarioEvaluator>,
) -> ActiveEvaluation {
    let context = request.context.clone();
    let key = EvaluationKey::from_context(&context);
    let cancellation_flag = Arc::new(AtomicBool::new(false));
    let worker_flag = cancellation_flag.clone();
    let worker = tokio::task::spawn_blocking(move || {
        evaluate_request(&request, evaluator.as_ref(), &worker_flag)
    });
    ActiveEvaluation {
        key,
        context: context.clone(),
        expected_context: context,
        cancellation: None,
        cancellation_flag,
        deadline: Box::pin(tokio::time::sleep(TRAFFIC_TEST_EVALUATION_DEADLINE)),
        deadline_armed: true,
        worker,
    }
}

fn evaluate_request(
    request: &TrafficTestEvaluationRequest,
    evaluator: &dyn TrafficScenarioEvaluator,
    cancellation: &AtomicBool,
) -> WorkerOutcome {
    let enabled: Vec<&TrafficScenario> = request
        .suite
        .scenarios
        .iter()
        .filter(|scenario| scenario.enabled)
        .collect();
    let mut results = Vec::with_capacity(enabled.len());
    for chunk in enabled.chunks(TRAFFIC_TEST_CANCELLATION_INTERVAL) {
        if cancellation.load(Ordering::Acquire) {
            return WorkerOutcome::Cancelled;
        }
        for scenario in chunk {
            match evaluator.evaluate(&request.index, scenario, &request.context) {
                Ok(result) => results.push(result),
                Err(error) => return WorkerOutcome::Failed(error.to_string()),
            }
        }
    }
    if cancellation.load(Ordering::Acquire) {
        return WorkerOutcome::Cancelled;
    }
    let report = match TrafficTestReport::new(request.context.clone(), results) {
        Ok(report) => Arc::new(report),
        Err(error) => return WorkerOutcome::Failed(error.to_string()),
    };
    if cancellation.load(Ordering::Acquire) {
        WorkerOutcome::Cancelled
    } else {
        WorkerOutcome::Completed(report)
    }
}

fn terminal_event(
    active: ActiveEvaluation,
    outcome: Result<WorkerOutcome, tokio::task::JoinError>,
) -> QueuedEvent {
    let event = match active.cancellation {
        Some(ActiveCancellation::Superseded) => TrafficTestEvent::EvaluationCancelled {
            context: active.context,
            reason: TrafficTestCancellationReason::Superseded,
        },
        Some(ActiveCancellation::StaleContext) => TrafficTestEvent::EvaluationCancelled {
            context: active.context,
            reason: TrafficTestCancellationReason::StaleContext,
        },
        Some(ActiveCancellation::Deadline) => TrafficTestEvent::EvaluationFailed {
            context: active.context,
            reason: TrafficTestFailureReason::EvaluationLimitExceeded,
        },
        Some(ActiveCancellation::Shutdown) => TrafficTestEvent::EvaluationCancelled {
            context: active.context,
            reason: TrafficTestCancellationReason::Shutdown,
        },
        None => match outcome {
            Ok(WorkerOutcome::Completed(report))
                if report.matches_active(&active.expected_context) =>
            {
                TrafficTestEvent::EvaluationFinished { report }
            }
            Ok(WorkerOutcome::Completed(_) | WorkerOutcome::Cancelled) => {
                TrafficTestEvent::EvaluationCancelled {
                    context: active.context,
                    reason: TrafficTestCancellationReason::StaleContext,
                }
            }
            Ok(WorkerOutcome::Failed(error)) => TrafficTestEvent::EvaluationFailed {
                context: active.context,
                reason: TrafficTestFailureReason::EvaluationFailed(error),
            },
            Err(_) => TrafficTestEvent::EvaluationFailed {
                context: active.context,
                reason: TrafficTestFailureReason::WorkerFailed,
            },
        },
    };
    QueuedEvent {
        event,
        start_after_publication: None,
    }
}
