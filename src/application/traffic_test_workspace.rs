//! Pure application-owned lifecycle for current-configuration traffic tests.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::domain::{
    EvaluationContext, EvaluationPhase, EvaluationSnapshotIdentity, EvaluationTarget, TrafficSuite,
    TrafficTestReport, TrafficTestRunId,
};

use super::{
    ObservedSnapshot, TrafficTestCancellationReason, TrafficTestEvent, TrafficTestFailureReason,
    TrafficTestSubmissionError,
};

static LAST_LOAD_TOKEN: AtomicU64 = AtomicU64::new(0);
static LAST_RUN_ID: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
/// Non-zero process-wide identity for one suite-load attempt.
pub struct SuiteLoadToken(u64);

impl SuiteLoadToken {
    #[must_use]
    /// Returns the numeric correlation identity.
    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Bounded reason why suite loading did not produce usable content.
pub enum SuiteLoadFailure {
    /// Decoded content violated the domain suite contract.
    InvalidSuite,
    /// The storage boundary failed without retaining its arbitrary diagnostic.
    Storage,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// One completed suite-load outcome supplied by the future storage service.
pub enum SuiteLoadOutcome {
    /// No persisted suite exists.
    Missing,
    /// A current-schema suite was decoded.
    Available(Arc<TrafficSuite>),
    /// A newer schema cannot be edited by this version.
    UnsupportedSchema(u32),
    /// Loading failed for a bounded typed reason.
    Failed(SuiteLoadFailure),
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Current application-owned suite lifecycle.
pub enum SuiteState {
    /// Loading has never been requested.
    NotLoaded,
    /// Only this attempt may complete the active load.
    Loading(SuiteLoadToken),
    /// The authoritative load found no suite.
    Missing,
    /// Valid immutable suite content is available.
    Available(Arc<TrafficSuite>),
    /// Persisted content uses a newer schema.
    UnsupportedSchema(u32),
    /// The load completed with a bounded failure.
    Failed(SuiteLoadFailure),
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Bounded evaluation failure retained by the workspace.
pub enum WorkspaceFailure {
    /// Coordinator request capacity was exhausted.
    Busy,
    /// Coordinator ownership had ended.
    Closed,
    /// Evaluation exceeded its fixed execution budget.
    EvaluationLimitExceeded,
    /// Domain evaluation failed without retaining arbitrary detail.
    EvaluationFailed,
    /// The owned worker terminated unexpectedly.
    WorkerFailed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Current evaluation lifecycle plus at most one stale completed report.
pub enum EvaluationState {
    /// No evaluation is current.
    NotRun,
    /// Prepared work awaits coordinator acceptance.
    Queued(EvaluationContext),
    /// The matching coordinator run has started.
    Running(EvaluationContext),
    /// A complete matching report is current.
    Completed(Arc<TrafficTestReport>),
    /// Matching queued or running work failed.
    Failed {
        /// Exact failed run identity.
        context: EvaluationContext,
        /// Bounded failure reason.
        reason: WorkspaceFailure,
    },
    /// Matching queued or running work was cancelled.
    Cancelled {
        /// Exact cancelled run identity.
        context: EvaluationContext,
        /// Typed cancellation reason.
        reason: TrafficTestCancellationReason,
    },
    /// The last completed report was invalidated by changed inputs.
    Stale(Arc<TrafficTestReport>),
}

#[derive(Debug)]
/// Immutable identity-bearing inputs prepared for coordinator submission.
pub struct PreparedTrafficEvaluation {
    context: EvaluationContext,
    suite: Arc<TrafficSuite>,
    observation: ObservedSnapshot,
}

impl PreparedTrafficEvaluation {
    #[must_use]
    /// Returns the exact run and evidence identity.
    pub const fn context(&self) -> &EvaluationContext {
        &self.context
    }
    #[must_use]
    /// Returns the validated suite allocation bound to this work.
    pub const fn suite(&self) -> &Arc<TrafficSuite> {
        &self.suite
    }
    #[must_use]
    /// Returns the authoritative observation bound to this work.
    pub const fn observation(&self) -> &ObservedSnapshot {
        &self.observation
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
/// Failure to mutate or prepare the pure workspace lifecycle.
pub enum WorkspaceError {
    #[error("traffic suite is not available")]
    SuiteUnavailable,
    #[error("authoritative snapshot is not available")]
    ObservationUnavailable,
    #[error("runtime evaluation is unavailable in offline mode")]
    RuntimeUnavailableOffline,
    #[error("traffic-test identity space is exhausted")]
    IdentityExhausted,
    #[error("invalid traffic suite")]
    InvalidSuite,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
/// Rejected asynchronous lifecycle event.
pub enum WorkspaceEventError {
    #[error("event does not match the active evaluation")]
    ContextMismatch,
    #[error("event is invalid for the active evaluation state")]
    InvalidTransition,
    #[error("report does not cover enabled scenarios exactly")]
    MalformedReport,
}

#[derive(Debug)]
/// Pure bounded owner of suite, observation, target, and evaluation state.
pub struct TrafficTestWorkspace {
    offline: bool,
    target: EvaluationTarget,
    suite: SuiteState,
    observation: Option<ObservedSnapshot>,
    observation_generation_high_water: u64,
    evaluation: EvaluationState,
    stale_report: Option<Arc<TrafficTestReport>>,
}

impl TrafficTestWorkspace {
    #[must_use]
    /// Creates an empty workspace with a mode-appropriate default target.
    pub const fn new(offline: bool) -> Self {
        Self {
            offline,
            target: if offline {
                EvaluationTarget::Permanent
            } else {
                EvaluationTarget::Runtime
            },
            suite: SuiteState::NotLoaded,
            observation: None,
            observation_generation_high_water: 0,
            evaluation: EvaluationState::NotRun,
            stale_report: None,
        }
    }

    #[must_use]
    /// Returns the selected evaluation target.
    pub const fn target(&self) -> EvaluationTarget {
        self.target
    }
    #[must_use]
    /// Returns the current suite lifecycle.
    pub const fn suite_state(&self) -> &SuiteState {
        &self.suite
    }
    #[must_use]
    /// Returns the current authoritative observation, if any.
    pub const fn observation(&self) -> Option<&ObservedSnapshot> {
        self.observation.as_ref()
    }
    #[must_use]
    /// Returns the current evaluation lifecycle.
    pub const fn evaluation_state(&self) -> &EvaluationState {
        &self.evaluation
    }
    #[must_use]
    /// Returns the single retained stale report, if any.
    pub const fn stale_report(&self) -> Option<&Arc<TrafficTestReport>> {
        self.stale_report.as_ref()
    }

    /// Begins a new load, superseding any prior load and evaluation.
    pub fn begin_load(&mut self) -> Result<SuiteLoadToken, WorkspaceError> {
        let token = allocate(&LAST_LOAD_TOKEN).map(SuiteLoadToken)?;
        self.suite = SuiteState::Loading(token);
        self.invalidate_evaluation();
        Ok(token)
    }

    /// Applies an outcome only when its token is the active load token.
    pub fn finish_load(&mut self, token: SuiteLoadToken, outcome: SuiteLoadOutcome) -> bool {
        if !matches!(self.suite, SuiteState::Loading(active) if active == token) {
            return false;
        }
        self.suite = match outcome {
            SuiteLoadOutcome::Missing => SuiteState::Missing,
            SuiteLoadOutcome::Available(suite) if suite.validate().is_ok() => {
                SuiteState::Available(suite)
            }
            SuiteLoadOutcome::Available(_) => SuiteState::Failed(SuiteLoadFailure::InvalidSuite),
            SuiteLoadOutcome::UnsupportedSchema(version) => SuiteState::UnsupportedSchema(version),
            SuiteLoadOutcome::Failed(failure) => SuiteState::Failed(failure),
        };
        true
    }

    /// Validates and installs locally edited suite content.
    pub fn replace_suite(&mut self, suite: Arc<TrafficSuite>) -> Result<bool, WorkspaceError> {
        suite.validate().map_err(|_| WorkspaceError::InvalidSuite)?;
        let changed = !matches!(&self.suite, SuiteState::Available(current) if current.as_ref() == suite.as_ref());
        if changed {
            self.suite = SuiteState::Available(suite);
            self.invalidate_evaluation();
        }
        Ok(changed)
    }

    /// Installs only strictly newer authoritative evidence.
    pub fn observe(&mut self, observation: ObservedSnapshot) -> bool {
        let generation = observation.identity().generation().get();
        if generation <= self.observation_generation_high_water {
            return false;
        }
        self.observation_generation_high_water = generation;
        self.observation = Some(observation);
        self.invalidate_evaluation();
        true
    }

    /// Removes current evidence without lowering the generation high-water mark.
    pub fn clear_observation(&mut self) {
        self.observation = None;
        self.invalidate_evaluation();
    }

    /// Selects a mode-compatible target and invalidates changed work.
    pub fn set_target(&mut self, target: EvaluationTarget) -> Result<bool, WorkspaceError> {
        if self.offline && target == EvaluationTarget::Runtime {
            return Err(WorkspaceError::RuntimeUnavailableOffline);
        }
        if self.target == target {
            return Ok(false);
        }
        self.target = target;
        self.invalidate_evaluation();
        Ok(true)
    }

    /// Binds immutable current suite and evidence to a never-reused run identity.
    pub fn prepare_evaluation(&mut self) -> Result<PreparedTrafficEvaluation, WorkspaceError> {
        let SuiteState::Available(suite) = &self.suite else {
            return Err(WorkspaceError::SuiteUnavailable);
        };
        let observation = self
            .observation
            .as_ref()
            .ok_or(WorkspaceError::ObservationUnavailable)?;
        let run_id = TrafficTestRunId::new(allocate(&LAST_RUN_ID)?)
            .map_err(|_| WorkspaceError::IdentityExhausted)?;
        let context = EvaluationContext {
            run_id,
            suite_id: suite.id.clone(),
            suite_revision: suite.revision,
            phase: EvaluationPhase::Current,
            target: self.target,
            authoritative_snapshot: EvaluationSnapshotIdentity::new(
                observation.identity().refresh_id().get(),
                observation.identity().generation().get(),
            )
            .map_err(|_| WorkspaceError::IdentityExhausted)?,
            base_snapshot: None,
            mutation_intent_id: None,
            plan_id: None,
            candidate_identity: None,
        };
        self.evaluation = EvaluationState::Queued(context.clone());
        Ok(PreparedTrafficEvaluation {
            context,
            suite: Arc::clone(suite),
            observation: observation.clone(),
        })
    }

    #[must_use]
    /// Returns the queued or running context that may need cancellation.
    pub fn active_context(&self) -> Option<&EvaluationContext> {
        match &self.evaluation {
            EvaluationState::Queued(context) | EvaluationState::Running(context) => Some(context),
            EvaluationState::NotRun
            | EvaluationState::Completed(_)
            | EvaluationState::Failed { .. }
            | EvaluationState::Cancelled { .. }
            | EvaluationState::Stale(_) => None,
        }
    }

    /// Applies one coordinator event after exact transition and context checks.
    pub fn ingest_event(&mut self, event: TrafficTestEvent) -> Result<(), WorkspaceEventError> {
        match event {
            TrafficTestEvent::EvaluationStarted { context } => {
                let EvaluationState::Queued(active) = &self.evaluation else {
                    return Err(WorkspaceEventError::InvalidTransition);
                };
                if &context != active {
                    return Err(WorkspaceEventError::ContextMismatch);
                }
                self.evaluation = EvaluationState::Running(context);
            }
            TrafficTestEvent::EvaluationFinished { report } => {
                let EvaluationState::Running(active) = &self.evaluation else {
                    return Err(WorkspaceEventError::InvalidTransition);
                };
                if report.context() != active {
                    return Err(WorkspaceEventError::ContextMismatch);
                }
                if !self.report_is_complete(&report) {
                    return Err(WorkspaceEventError::MalformedReport);
                }
                self.evaluation = EvaluationState::Completed(report);
            }
            TrafficTestEvent::EvaluationFailed { context, reason } => {
                self.resolve_terminal_context(&context)?;
                self.evaluation = EvaluationState::Failed {
                    context,
                    reason: map_failure(&reason),
                };
            }
            TrafficTestEvent::EvaluationCancelled { context, reason } => {
                self.resolve_terminal_context(&context)?;
                self.evaluation = EvaluationState::Cancelled { context, reason };
            }
        }
        Ok(())
    }

    /// Resolves only the matching still-queued submission.
    pub fn resolve_submission_failure(
        &mut self,
        context: EvaluationContext,
        error: &TrafficTestSubmissionError,
    ) -> Result<(), WorkspaceEventError> {
        let EvaluationState::Queued(active) = &self.evaluation else {
            return Err(WorkspaceEventError::InvalidTransition);
        };
        if &context != active {
            return Err(WorkspaceEventError::ContextMismatch);
        }
        let reason = match error {
            TrafficTestSubmissionError::Busy => WorkspaceFailure::Busy,
            TrafficTestSubmissionError::Closed => WorkspaceFailure::Closed,
            TrafficTestSubmissionError::InvalidContext(_) => WorkspaceFailure::EvaluationFailed,
        };
        self.evaluation = EvaluationState::Failed { context, reason };
        Ok(())
    }

    fn resolve_terminal_context(
        &self,
        context: &EvaluationContext,
    ) -> Result<(), WorkspaceEventError> {
        match &self.evaluation {
            EvaluationState::Queued(active) | EvaluationState::Running(active) => {
                if active == context {
                    Ok(())
                } else {
                    Err(WorkspaceEventError::ContextMismatch)
                }
            }
            _ => Err(WorkspaceEventError::InvalidTransition),
        }
    }

    fn report_is_complete(&self, report: &TrafficTestReport) -> bool {
        let SuiteState::Available(suite) = &self.suite else {
            return false;
        };
        let mut results = report.results().iter();
        for scenario in suite.scenarios.iter().filter(|scenario| scenario.enabled) {
            let Some(result) = results.next() else {
                return false;
            };
            if result.scenario_id() != &scenario.id || result.expectation() != scenario.expectation
            {
                return false;
            }
        }
        results.next().is_none()
    }

    fn invalidate_evaluation(&mut self) {
        let previous = std::mem::replace(&mut self.evaluation, EvaluationState::NotRun);
        if let EvaluationState::Completed(report) | EvaluationState::Stale(report) = previous {
            self.stale_report = Some(Arc::clone(&report));
            self.evaluation = EvaluationState::Stale(report);
        }
    }
}

fn allocate(counter: &AtomicU64) -> Result<u64, WorkspaceError> {
    counter
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
        .map(|previous| previous + 1)
        .map_err(|_| WorkspaceError::IdentityExhausted)
}

fn map_failure(reason: &TrafficTestFailureReason) -> WorkspaceFailure {
    match reason {
        TrafficTestFailureReason::Busy => WorkspaceFailure::Busy,
        TrafficTestFailureReason::EvaluationLimitExceeded => {
            WorkspaceFailure::EvaluationLimitExceeded
        }
        TrafficTestFailureReason::EvaluationFailed(_) => WorkspaceFailure::EvaluationFailed,
        TrafficTestFailureReason::WorkerFailed => WorkspaceFailure::WorkerFailed,
    }
}

#[cfg(test)]
#[path = "traffic_test_workspace/tests.rs"]
#[allow(
    clippy::field_reassign_with_default,
    clippy::match_like_matches_macro,
    clippy::unwrap_used
)]
mod tests;
