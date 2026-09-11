use super::{
    Arc, EvaluationContext, EvaluationTarget, Job, JobKind, JobOutput, TrafficAuditOutcome,
    TrafficEvaluationIndex, TrafficServiceError, TrafficServiceEvent, TrafficSuiteStorage,
    TrafficTestEvaluationRequest, TrafficTestEvent, TrafficTestFailureReason, TrafficTestService,
    WorkspaceEventError, map_submission, map_workspace,
};
use crate::application::{
    SuiteState, TrafficPreviewEvidence, TrafficPreviewFailure, TrafficPreviewPair,
    TrafficPreviewRequest, TrafficPreviewState,
};
use crate::domain::{
    CandidateIdentity, CandidateProjector, EvaluationPhase, EvaluationPlanId,
    EvaluationSnapshotIdentity, MAX_TRAFFIC_REPORT_BYTES, MutationIntentId,
    OperationTargetSequence, OrderedOperationDigest, compare_traffic_reports,
    validate_preview_report,
};
use std::sync::atomic::{AtomicU64, Ordering};
static INTENT: AtomicU64 = AtomicU64::new(0);

pub(super) struct PreviewBatch {
    evidence: Arc<TrafficPreviewEvidence>,
    run: usize,
    bytes: usize,
    started: bool,
}
impl PreviewBatch {
    pub(super) fn context(&self) -> &EvaluationContext {
        let pair = &self.evidence.pairs[self.run / 2];
        if self.run.is_multiple_of(2) {
            &pair.before_context
        } else {
            &pair.after_context
        }
    }
}
impl<S: TrafficSuiteStorage> TrafficTestService<S> {
    #[must_use]
    pub const fn preview_state(&self) -> &TrafficPreviewState {
        &self.preview
    }

    /// Accepts immutable reviewed input without executing any firewall operation.
    pub fn try_preview(
        &mut self,
        request: TrafficPreviewRequest,
    ) -> Result<(), TrafficServiceError> {
        self.ensure_slot()?;
        if self.coordinator_closed {
            return Err(TrafficServiceError::Closed);
        }
        if request.operations.is_empty() {
            return Err(TrafficServiceError::Preview(
                TrafficPreviewFailure::EmptyOperations,
            ));
        }
        let SuiteState::Available(suite) = self.workspace.suite_state() else {
            return Err(TrafficServiceError::Unavailable);
        };
        if !suite.scenarios.iter().any(|s| s.enabled) {
            return Err(TrafficServiceError::Preview(
                TrafficPreviewFailure::NoEnabledScenarios,
            ));
        }
        let Some(observation) = self.workspace.observation() else {
            return Err(TrafficServiceError::Preview(
                TrafficPreviewFailure::StaleObservation,
            ));
        };
        if observation.identity() != request.observation.identity()
            || !Arc::ptr_eq(
                observation.snapshot_arc(),
                request.observation.snapshot_arc(),
            )
        {
            return Err(TrafficServiceError::Preview(
                TrafficPreviewFailure::StaleObservation,
            ));
        }
        let suite = Arc::clone(suite);
        let mut runtime = false;
        let mut permanent = false;
        for operation in &request.operations {
            match operation.effect().targets {
                OperationTargetSequence::Runtime
                | OperationTargetSequence::RuntimeFromPermanent => runtime = true,
                OperationTargetSequence::Permanent
                | OperationTargetSequence::PermanentFromRuntime => permanent = true,
                OperationTargetSequence::RuntimeThenPermanent
                | OperationTargetSequence::RuntimeAndPermanent => {
                    runtime = true;
                    permanent = true;
                }
            }
        }
        if runtime && self.workspace.is_offline() {
            return Err(TrafficServiceError::Preview(
                TrafficPreviewFailure::OfflineTarget,
            ));
        }
        let count = 2 * (usize::from(runtime) + usize::from(permanent));
        if !self.audit.can_reserve_batch(count) {
            return Err(TrafficServiceError::AuditBackpressure);
        }
        let evidence = prepare_evidence(request, suite, runtime, permanent)?;
        let old = self.workspace.active_context().cloned();
        let _ = self.invalidate_preview();
        if let Some(context) = &old {
            let _ = self
                .workspace
                .ingest_event(TrafficTestEvent::EvaluationCancelled {
                    context: context.clone(),
                    reason: super::super::TrafficTestCancellationReason::Superseded,
                });
        }
        let _ = self.cancel(old);
        self.preview_batch = Some(PreviewBatch {
            evidence,
            run: 0,
            bytes: 0,
            started: false,
        });
        self.audit.reserve_batch(count);
        self.start_preview_run();
        Ok(())
    }

    /// Closing the owner invalidates retained evidence immediately.
    pub fn cancel_preview(&mut self) -> Result<(), TrafficServiceError> {
        self.ensure_open()?;
        self.invalidate_preview()
    }
    pub(super) fn stale_preview(&mut self) {
        self.preview_batch = None;
        if let Some(evidence) = self.preview.evidence() {
            self.preview = TrafficPreviewState::Stale(Arc::clone(evidence));
        }
    }
    pub(super) fn invalidate_preview(&mut self) -> Result<(), TrafficServiceError> {
        let context = self
            .preview_batch
            .as_ref()
            .map(|batch| batch.context().clone());
        self.stale_preview();
        self.audit.release_batch();
        context.map_or(Ok(()), |context| {
            self.audit
                .finish(&context, TrafficAuditOutcome::StaleContext, None);
            self.coordinator
                .try_invalidate(context)
                .map_err(|e| map_submission(&e))
        })
    }
    pub(super) fn fail_preview(&mut self, reason: TrafficPreviewFailure) {
        if let Some(batch) = self.preview_batch.take() {
            self.audit
                .finish(batch.context(), TrafficAuditOutcome::EvaluationFailed, None);
            self.audit.release_batch();
            self.preview = TrafficPreviewState::Failed {
                evidence: batch.evidence,
                reason,
            };
        }
    }
    fn start_preview_run(&mut self) {
        let Some(batch) = self.preview_batch.as_ref() else {
            return;
        };
        let context = batch.context().clone();
        let evidence = Arc::clone(&batch.evidence);
        self.audit.accept_reserved(
            context.clone(),
            evidence
                .suite
                .scenarios
                .iter()
                .filter(|s| s.enabled)
                .count(),
        );
        self.preview = TrafficPreviewState::Preparing(Arc::clone(&evidence));
        self.job = Some(Job {
            kind: JobKind::PreviewIndex(context.clone()),
            task: tokio::task::spawn_blocking(move || {
                let result = (|| {
                    let snapshot = if context.phase == EvaluationPhase::StagedCandidate {
                        let projection = CandidateProjector::project(
                            evidence.request.observation.snapshot_arc(),
                            context.authoritative_snapshot,
                            evidence.intent_id,
                            context.plan_id,
                            context.target,
                            &evidence.request.operations,
                        )
                        .map_err(|_| TrafficPreviewFailure::Projection)?;
                        if Some(projection.identity()) != context.candidate_identity {
                            return Err(TrafficPreviewFailure::InvalidEvidence);
                        }
                        Arc::clone(projection.snapshot_arc())
                    } else {
                        Arc::clone(evidence.request.observation.snapshot_arc())
                    };
                    TrafficTestEvaluationRequest::new(
                        context.clone(),
                        Arc::clone(&evidence.suite),
                        TrafficEvaluationIndex::new(snapshot, context.target),
                    )
                    .map(Box::new)
                    .map_err(|_| TrafficPreviewFailure::InvalidEvidence)
                })();
                JobOutput::PreviewIndex(result)
            }),
        });
    }
    pub(super) fn finish_preview_index(
        &mut self,
        context: &EvaluationContext,
        output: Result<JobOutput<S::Version>, tokio::task::JoinError>,
    ) -> TrafficServiceEvent {
        if self
            .preview_batch
            .as_ref()
            .is_none_or(|batch| batch.context() != context)
        {
            return TrafficServiceEvent::ObsoleteIndex;
        }
        if self.closing || self.coordinator_closed {
            self.fail_preview(TrafficPreviewFailure::Worker);
            return TrafficServiceEvent::ObsoleteIndex;
        }
        let request = match output {
            Ok(JobOutput::PreviewIndex(Ok(request))) => request,
            Ok(JobOutput::PreviewIndex(Err(reason))) => {
                self.fail_preview(reason);
                return TrafficServiceEvent::EvaluationSubmitted(Err(
                    TrafficServiceError::Preview(reason),
                ));
            }
            _ => {
                self.fail_preview(TrafficPreviewFailure::Worker);
                return TrafficServiceEvent::EvaluationSubmitted(Err(
                    TrafficServiceError::Preview(TrafficPreviewFailure::Worker),
                ));
            }
        };
        let result = self
            .coordinator
            .try_evaluate(*request)
            .map_err(|e| map_submission(&e));
        if result.is_err() {
            self.fail_preview(TrafficPreviewFailure::Worker);
        }
        TrafficServiceEvent::EvaluationSubmitted(result)
    }
    fn finish_preview_report(
        &mut self,
        report: Arc<crate::domain::TrafficTestReport>,
    ) -> TrafficServiceEvent {
        let Some(batch) = &mut self.preview_batch else {
            return TrafficServiceEvent::Evaluation(Err(WorkspaceEventError::ContextMismatch));
        };
        if !batch.started {
            return TrafficServiceEvent::Evaluation(Err(WorkspaceEventError::InvalidTransition));
        }
        if validate_preview_report(&report, batch.context(), &batch.evidence.suite).is_err() {
            self.audit
                .finish(report.context(), TrafficAuditOutcome::MalformedReport, None);
            self.fail_preview(TrafficPreviewFailure::InvalidEvidence);
            return TrafficServiceEvent::Evaluation(Err(WorkspaceEventError::MalformedReport));
        }
        let Some(bytes) = retained_report_bytes(batch.bytes, report.serialized_len()) else {
            self.audit.finish(
                report.context(),
                TrafficAuditOutcome::EvaluationLimitExceeded,
                None,
            );
            self.fail_preview(TrafficPreviewFailure::ReportBudget);
            return TrafficServiceEvent::Evaluation(Err(WorkspaceEventError::MalformedReport));
        };
        self.audit.finish(
            report.context(),
            TrafficAuditOutcome::Completed,
            Some(&report),
        );
        batch.bytes = bytes;
        let evidence = Arc::make_mut(&mut batch.evidence);
        let pair = &mut evidence.pairs[batch.run / 2];
        if batch.run.is_multiple_of(2) {
            pair.before = Some(report);
        } else {
            pair.after = Some(report);
        }
        if let (Some(before), Some(after)) = (&pair.before, &pair.after) {
            pair.counts = compare_traffic_reports(
                &evidence.suite,
                &pair.before_context,
                &pair.after_context,
                before,
                after,
            )
            .ok();
            if pair.counts.is_none() {
                self.fail_preview(TrafficPreviewFailure::InvalidEvidence);
                return TrafficServiceEvent::Evaluation(Err(WorkspaceEventError::MalformedReport));
            }
        }
        batch.run += 1;
        batch.started = false;
        if batch.run == batch.evidence.pairs.len() * 2 {
            self.preview = TrafficPreviewState::Completed(Arc::clone(&batch.evidence));
            self.preview_batch = None;
            self.audit.release_batch();
        } else {
            self.start_preview_run();
        }
        TrafficServiceEvent::Evaluation(Ok(()))
    }
    pub(super) fn ingest_preview(&mut self, event: TrafficTestEvent) -> TrafficServiceEvent {
        match event {
            TrafficTestEvent::EvaluationStarted { .. } => {
                if let Some(batch) = &mut self.preview_batch {
                    if batch.started {
                        return TrafficServiceEvent::Evaluation(Err(
                            WorkspaceEventError::InvalidTransition,
                        ));
                    }
                    batch.started = true;
                    self.preview = TrafficPreviewState::Running(Arc::clone(&batch.evidence));
                }
            }
            TrafficTestEvent::EvaluationFinished { report } => {
                return self.finish_preview_report(report);
            }
            TrafficTestEvent::EvaluationCancelled { context, reason } => {
                let outcome = match reason {
                    super::super::TrafficTestCancellationReason::Superseded => {
                        TrafficAuditOutcome::Superseded
                    }
                    super::super::TrafficTestCancellationReason::StaleContext => {
                        TrafficAuditOutcome::StaleContext
                    }
                    super::super::TrafficTestCancellationReason::Shutdown => {
                        TrafficAuditOutcome::Shutdown
                    }
                };
                self.audit.finish(&context, outcome, None);
                self.fail_preview(TrafficPreviewFailure::Evaluation);
            }
            TrafficTestEvent::EvaluationFailed { context, reason } => {
                let outcome = match reason {
                    TrafficTestFailureReason::Busy => TrafficAuditOutcome::Busy,
                    TrafficTestFailureReason::EvaluationLimitExceeded => {
                        TrafficAuditOutcome::EvaluationLimitExceeded
                    }
                    TrafficTestFailureReason::EvaluationFailed(_) => {
                        TrafficAuditOutcome::EvaluationFailed
                    }
                    TrafficTestFailureReason::WorkerFailed => TrafficAuditOutcome::WorkerFailed,
                };
                self.audit.finish(&context, outcome, None);
                self.fail_preview(TrafficPreviewFailure::Evaluation);
            }
        }
        TrafficServiceEvent::Evaluation(Ok(()))
    }
}

fn prepare_evidence(
    request: TrafficPreviewRequest,
    suite: Arc<crate::domain::TrafficSuite>,
    runtime: bool,
    permanent: bool,
) -> Result<Arc<TrafficPreviewEvidence>, TrafficServiceError> {
    let intent = INTENT
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
        .map_err(|_| TrafficServiceError::IdentityExhausted)?
        + 1;
    let intent_id =
        MutationIntentId::new(intent).map_err(|_| TrafficServiceError::IdentityExhausted)?;
    let identity = request.observation.identity();
    let base =
        EvaluationSnapshotIdentity::new(identity.refresh_id().get(), identity.generation().get())
            .map_err(|_| TrafficServiceError::IdentityExhausted)?;
    let encoded = request
        .operations
        .iter()
        .map(serde_json::to_vec)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| TrafficServiceError::Unavailable)?;
    let digest = OrderedOperationDigest::from_ordered_bytes(encoded.iter().map(Vec::as_slice));
    let plan = request.plan_id.map(|id| EvaluationPlanId::new(id.get()));
    let mut pairs = Vec::with_capacity(2);
    for target in [EvaluationTarget::Runtime, EvaluationTarget::Permanent]
        .into_iter()
        .filter(|target| match target {
            EvaluationTarget::Runtime => runtime,
            EvaluationTarget::Permanent => permanent,
        })
    {
        let before_context = EvaluationContext {
            run_id: super::super::traffic_test_workspace::allocate_run_id()
                .map_err(|e| map_workspace(&e))?,
            suite_id: suite.id.clone(),
            suite_revision: suite.revision,
            phase: EvaluationPhase::Current,
            target,
            authoritative_snapshot: base,
            base_snapshot: None,
            mutation_intent_id: None,
            plan_id: None,
            candidate_identity: None,
        };
        let after_context = EvaluationContext {
            run_id: super::super::traffic_test_workspace::allocate_run_id()
                .map_err(|e| map_workspace(&e))?,
            phase: EvaluationPhase::StagedCandidate,
            base_snapshot: Some(base),
            mutation_intent_id: Some(intent_id),
            plan_id: plan,
            candidate_identity: Some(CandidateIdentity::new(
                base, intent_id, plan, target, digest,
            )),
            ..before_context.clone()
        };
        pairs.push(TrafficPreviewPair {
            target,
            before_context,
            after_context,
            before: None,
            after: None,
            counts: None,
        });
    }
    let evidence = Arc::new(TrafficPreviewEvidence {
        intent_id,
        request: Arc::new(request),
        suite,
        pairs,
    });
    Ok(evidence)
}

fn retained_report_bytes(retained: usize, incoming: usize) -> Option<usize> {
    retained
        .checked_add(incoming)
        .filter(|bytes| *bytes <= MAX_TRAFFIC_REPORT_BYTES)
}

#[cfg(test)]
mod budget_tests {
    use super::{MAX_TRAFFIC_REPORT_BYTES, retained_report_bytes};

    #[test]
    fn traffic_preview_aggregate_report_budget_boundary() {
        let half = MAX_TRAFFIC_REPORT_BYTES / 2;
        assert_eq!(retained_report_bytes(0, half), Some(half));
        assert_eq!(
            retained_report_bytes(half, half),
            Some(MAX_TRAFFIC_REPORT_BYTES)
        );
        assert_eq!(retained_report_bytes(half, half + 1), None);
        assert_eq!(retained_report_bytes(MAX_TRAFFIC_REPORT_BYTES, 1), None);
        assert_eq!(retained_report_bytes(usize::MAX, 1), None);
    }
}
