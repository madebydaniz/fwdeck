//! Owned asynchronous default-suite and evaluation lifecycle.

use super::{
    LoadedTrafficSuite, ObservedSnapshot, SuiteLoadFailure, SuiteLoadOutcome, SuiteLoadToken,
    TRAFFIC_TEST_SHUTDOWN_DEADLINE, TrafficSaveExpectation, TrafficStorageError,
    TrafficSuiteStorage, TrafficTestCoordinator, TrafficTestEvaluationRequest, TrafficTestEvent,
    TrafficTestFailureReason, TrafficTestShutdownError, TrafficTestSubmissionError,
    TrafficTestWorkspace, WorkspaceError, WorkspaceEventError,
};
use crate::domain::{
    EvaluationContext, EvaluationTarget, TrafficEvaluationIndex, TrafficSuite, TrafficSuiteRevision,
};
use std::sync::Arc;
use tokio::task::JoinHandle;

/// Immediate request rejection. Rejected slot requests never change workspace state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TrafficServiceError {
    #[error("traffic test service is busy")]
    /// The single blocking slot or coordinator request lane is occupied.
    Busy,
    #[error("traffic test service is closed")]
    /// Service ownership or evaluation lane ended.
    Closed,
    #[error("traffic test input is unavailable")]
    /// A trusted load or authoritative observation is required.
    Unavailable,
    #[error("invalid traffic suite")]
    /// Draft identity, content, or revision is invalid.
    InvalidSuite,
    #[error("traffic test identity exhausted")]
    /// Revision or evaluation identity cannot advance.
    IdentityExhausted,
}

/// An accepted request may still have failed to enqueue cancellation of old work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TrafficServiceRequestStatus {
    /// Freshness invalidation has already happened and is never rolled back.
    pub cancellation_error: Option<TrafficServiceError>,
}

/// Save presentation never publishes an unpersisted edit as the loaded suite.
#[derive(Debug, Clone)]
pub enum TrafficSaveState {
    /// No save requested since the last load.
    Idle,
    /// Exact operator draft retained while blocking storage is running.
    Saving(Arc<TrafficSuite>),
    /// Exact accepted persisted suite.
    Saved(Arc<TrafficSuite>),
    /// Failed save retains the unmodified operator draft.
    Failed {
        /// Original draft, before service revision advancement.
        draft: Arc<TrafficSuite>,
        /// Bounded failure reason.
        error: TrafficStorageError,
    },
}

/// One bounded update produced by polling the owner.
#[derive(Debug)]
pub enum TrafficServiceEvent {
    /// Load finished and its matching outcome was applied.
    Loaded(Result<(), TrafficStorageError>),
    /// Save finished; accepted content may separately require cancellation.
    Saved {
        /// Whether exact persisted content was installed.
        result: Result<(), TrafficStorageError>,
        /// Failure to enqueue cancellation does not undo persisted content.
        cancellation_error: Option<TrafficServiceError>,
    },
    /// Index was submitted or a matching submission failed terminally.
    EvaluationSubmitted(Result<(), TrafficServiceError>),
    /// Prepared evidence became obsolete before index completion.
    ObsoleteIndex,
    /// Coordinator event accepted or rejected by the workspace guard.
    Evaluation(Result<(), WorkspaceEventError>),
    /// Coordinator lane has permanently closed; this is emitted only once.
    CoordinatorClosed,
}

/// Explicit shutdown retains unfinished ownership on deadline expiry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TrafficServiceShutdownError {
    #[error("traffic test service shutdown deadline exceeded")]
    /// Retain this service and retry shutdown; a write may still complete.
    DeadlineExceeded,
    #[error("traffic test service worker failed")]
    /// An owned task failed unexpectedly.
    WorkerFailed,
}

enum JobKind {
    Load(SuiteLoadToken),
    Save {
        draft: Arc<TrafficSuite>,
        persisted: Arc<TrafficSuite>,
    },
    Index(EvaluationContext),
}
enum JobOutput<V> {
    Storage(Result<LoadedTrafficSuite<V>, TrafficStorageError>),
    Index(Result<Box<TrafficTestEvaluationRequest>, super::TrafficTestRequestError>),
}
struct Job<V> {
    kind: JobKind,
    task: JoinHandle<JobOutput<V>>,
}

/// Owns all work until explicit shutdown completes.
///
/// Call `shutdown` before dropping. On timeout retain this owner and retry; blocking
/// saves cannot be aborted safely and may still write. No work starts implicitly.
pub struct TrafficTestService<S: TrafficSuiteStorage> {
    workspace: TrafficTestWorkspace,
    storage: Arc<S>,
    expected: Option<TrafficSaveExpectation<S::Version>>,
    job: Option<Job<S::Version>>,
    coordinator: TrafficTestCoordinator,
    save: TrafficSaveState,
    closing: bool,
    coordinator_closed: bool,
    coordinator_shutdown: Option<Result<(), TrafficServiceShutdownError>>,
    worker_failed: bool,
}

impl<S: TrafficSuiteStorage> TrafficTestService<S> {
    /// Creates an inert service with the native bounded coordinator.
    #[must_use]
    pub fn new(offline: bool, storage: Arc<S>) -> Self {
        Self::with_coordinator(offline, storage, TrafficTestCoordinator::spawn())
    }
    /// Injects an existing coordinator for deterministic evaluator tests.
    #[must_use]
    pub fn with_coordinator(
        offline: bool,
        storage: Arc<S>,
        coordinator: TrafficTestCoordinator,
    ) -> Self {
        Self {
            workspace: TrafficTestWorkspace::new(offline),
            storage,
            expected: None,
            job: None,
            coordinator,
            save: TrafficSaveState::Idle,
            closing: false,
            coordinator_closed: false,
            coordinator_shutdown: None,
            worker_failed: false,
        }
    }
    /// Returns immutable presentation state.
    #[must_use]
    pub const fn workspace(&self) -> &TrafficTestWorkspace {
        &self.workspace
    }
    /// Returns save presentation, including the original failed draft.
    #[must_use]
    pub const fn save_state(&self) -> &TrafficSaveState {
        &self.save
    }

    /// Accepts strictly newer evidence immediately, even while storage is busy.
    pub fn observe(&mut self, observed: ObservedSnapshot) -> Result<bool, TrafficServiceError> {
        self.ensure_open()?;
        let old = self.workspace.active_context().cloned();
        let changed = self.workspace.observe(observed);
        if changed {
            self.cancel(old)?;
        }
        Ok(changed)
    }
    /// Clears evidence immediately; cancellation failure does not restore it.
    pub fn clear_observation(&mut self) -> Result<(), TrafficServiceError> {
        self.ensure_open()?;
        let old = self.workspace.active_context().cloned();
        self.workspace.clear_observation();
        self.cancel(old)
    }
    /// Changes target immediately; cancellation failure does not restore it.
    pub fn set_target(&mut self, target: EvaluationTarget) -> Result<bool, TrafficServiceError> {
        self.ensure_open()?;
        let old = self.workspace.active_context().cloned();
        let changed = self
            .workspace
            .set_target(target)
            .map_err(|error| map_workspace(&error))?;
        if changed {
            self.cancel(old)?;
        }
        Ok(changed)
    }
    /// Loads explicitly, revoking prior save authority before touching storage.
    pub fn try_load(&mut self) -> Result<TrafficServiceRequestStatus, TrafficServiceError> {
        self.ensure_slot()?;
        let old = self.workspace.active_context().cloned();
        let token = self
            .workspace
            .begin_load()
            .map_err(|error| map_workspace(&error))?;
        self.expected = None;
        self.save = TrafficSaveState::Idle;
        let cancellation_error = self.cancel(old).err();
        let storage = Arc::clone(&self.storage);
        self.job = Some(Job {
            kind: JobKind::Load(token),
            task: tokio::task::spawn_blocking(move || JobOutput::Storage(storage.load_default())),
        });
        Ok(TrafficServiceRequestStatus { cancellation_error })
    }
    /// Saves only against a successful explicit load or preceding accepted save.
    pub fn try_save(&mut self, draft: Arc<TrafficSuite>) -> Result<(), TrafficServiceError> {
        self.ensure_slot()?;
        let expected = self
            .expected
            .clone()
            .ok_or(TrafficServiceError::Unavailable)?;
        validate_default(&draft).map_err(|_| TrafficServiceError::InvalidSuite)?;
        let mut persisted = draft.as_ref().clone();
        match &expected {
            TrafficSaveExpectation::Missing if draft.revision.get() != 1 => {
                return Err(TrafficServiceError::InvalidSuite);
            }
            TrafficSaveExpectation::Existing { revision, .. } => {
                if draft.revision != *revision {
                    return Err(TrafficServiceError::InvalidSuite);
                }
                let next = revision
                    .get()
                    .checked_add(1)
                    .ok_or(TrafficServiceError::IdentityExhausted)?;
                persisted.revision = TrafficSuiteRevision::new(next)
                    .map_err(|_| TrafficServiceError::IdentityExhausted)?;
            }
            TrafficSaveExpectation::Missing => {}
        }
        let persisted = Arc::new(persisted);
        self.save = TrafficSaveState::Saving(Arc::clone(&draft));
        let storage = Arc::clone(&self.storage);
        let saved = Arc::clone(&persisted);
        self.job = Some(Job {
            kind: JobKind::Save { draft, persisted },
            task: tokio::task::spawn_blocking(move || {
                JobOutput::Storage(storage.save_default(&saved, expected))
            }),
        });
        Ok(())
    }
    /// Prepares immutable evidence and builds its index in the single owned slot.
    pub fn try_evaluate(&mut self) -> Result<(), TrafficServiceError> {
        self.ensure_slot()?;
        if self.coordinator_closed {
            return Err(TrafficServiceError::Closed);
        }
        let prepared = self
            .workspace
            .prepare_evaluation()
            .map_err(|error| map_workspace(&error))?;
        let context = prepared.context().clone();
        self.job = Some(Job {
            kind: JobKind::Index(context),
            task: tokio::task::spawn_blocking(move || {
                let index = TrafficEvaluationIndex::new(
                    Arc::clone(prepared.observation().snapshot_arc()),
                    prepared.context().target,
                );
                JobOutput::Index(
                    TrafficTestEvaluationRequest::new(
                        prepared.context().clone(),
                        Arc::clone(prepared.suite()),
                        index,
                    )
                    .map(Box::new),
                )
            }),
        });
        Ok(())
    }
    /// Cancellation-safe polling. `None` means the coordinator is closed and no job is active.
    /// After a subsequent load or save is accepted, the caller must resume polling.
    pub async fn next_event(&mut self) -> Option<TrafficServiceEvent> {
        if self.job.is_none() && self.coordinator_closed {
            return None;
        }
        tokio::select! {
            output = async { match self.job.as_mut() { Some(job) => (&mut job.task).await, None => std::future::pending().await } }, if self.job.is_some() => {
                let job = self.job.take()?;
                Some(self.finish_job(job.kind, output))
            }
            event = self.coordinator.next_event(), if !self.coordinator_closed => {
                Some(if let Some(event) = event { self.ingest(event) } else { self.close_coordinator(); TrafficServiceEvent::CoordinatorClosed })
            }
        }
    }
    /// Joins storage and coordinator under one overall two-second deadline.
    /// On deadline expiry all unfinished handles remain available for retry.
    pub async fn shutdown(&mut self) -> Result<(), TrafficServiceShutdownError> {
        self.closing = true;
        let deadline = tokio::time::Instant::now() + TRAFFIC_TEST_SHUTDOWN_DEADLINE;
        while self.job.is_some() || self.coordinator_shutdown.is_none() {
            tokio::select! {
                output = async { match self.job.as_mut() { Some(job) => (&mut job.task).await, None => std::future::pending().await } }, if self.job.is_some() => {
                    if let Some(job) = self.job.take() { self.finish_job(job.kind, output); }
                }
                result = self.coordinator.shutdown(), if self.coordinator_shutdown.is_none() => {
                    match result {
                        Ok(()) => self.coordinator_shutdown = Some(Ok(())),
                        Err(TrafficTestShutdownError::TaskFailed) => { self.coordinator_shutdown = Some(Err(TrafficServiceShutdownError::WorkerFailed)); self.worker_failed = true; }
                        Err(TrafficTestShutdownError::DeadlineExceeded) => return Err(TrafficServiceShutdownError::DeadlineExceeded),
                    }
                    self.close_coordinator();
                }
                () = tokio::time::sleep_until(deadline) => return Err(TrafficServiceShutdownError::DeadlineExceeded),
            }
        }
        if self.worker_failed {
            Err(TrafficServiceShutdownError::WorkerFailed)
        } else {
            Ok(())
        }
    }
    fn ensure_open(&self) -> Result<(), TrafficServiceError> {
        if self.closing {
            Err(TrafficServiceError::Closed)
        } else {
            Ok(())
        }
    }
    fn ensure_slot(&self) -> Result<(), TrafficServiceError> {
        self.ensure_open()?;
        if self.job.is_some() {
            Err(TrafficServiceError::Busy)
        } else {
            Ok(())
        }
    }
    fn cancel(&self, old: Option<EvaluationContext>) -> Result<(), TrafficServiceError> {
        old.map_or(Ok(()), |context| {
            self.coordinator
                .try_invalidate(context)
                .map_err(|error| map_submission(&error))
        })
    }
    fn ingest(&mut self, event: TrafficTestEvent) -> TrafficServiceEvent {
        let context = event.context().clone();
        let result = self.workspace.ingest_event(event);
        if result == Err(WorkspaceEventError::MalformedReport) {
            self.fail_worker(context);
        }
        TrafficServiceEvent::Evaluation(result)
    }
    fn fail_worker(&mut self, context: EvaluationContext) {
        let _ = self
            .workspace
            .ingest_event(TrafficTestEvent::EvaluationFailed {
                context,
                reason: TrafficTestFailureReason::WorkerFailed,
            });
    }
    fn close_coordinator(&mut self) {
        self.coordinator_closed = true;
        if let Some(context) = self.workspace.active_context().cloned()
            && self
                .workspace
                .resolve_submission_failure(context.clone(), &TrafficTestSubmissionError::Closed)
                .is_err()
        {
            self.fail_worker(context);
        }
    }
}

fn validate_default(suite: &TrafficSuite) -> Result<(), TrafficStorageError> {
    if suite.id.as_str() != "default" || suite.validate().is_err() {
        Err(TrafficStorageError::InvalidSuite)
    } else {
        Ok(())
    }
}
fn map_workspace(error: &WorkspaceError) -> TrafficServiceError {
    match error {
        WorkspaceError::IdentityExhausted => TrafficServiceError::IdentityExhausted,
        WorkspaceError::InvalidSuite => TrafficServiceError::InvalidSuite,
        WorkspaceError::SuiteUnavailable
        | WorkspaceError::ObservationUnavailable
        | WorkspaceError::RuntimeUnavailableOffline => TrafficServiceError::Unavailable,
    }
}
fn map_submission(error: &TrafficTestSubmissionError) -> TrafficServiceError {
    match error {
        TrafficTestSubmissionError::Busy => TrafficServiceError::Busy,
        TrafficTestSubmissionError::Closed => TrafficServiceError::Closed,
        TrafficTestSubmissionError::InvalidContext(_) => TrafficServiceError::Unavailable,
    }
}

mod jobs;
#[cfg(test)]
#[path = "traffic_test_service/tests.rs"]
#[allow(
    clippy::unwrap_used,
    clippy::field_reassign_with_default,
    clippy::panic
)]
mod tests;
