use super::{
    Arc, JobKind, JobOutput, LoadedTrafficSuite, SuiteLoadFailure, SuiteLoadOutcome,
    SuiteLoadToken, TrafficSaveExpectation, TrafficSaveState, TrafficServiceError,
    TrafficServiceEvent, TrafficStorageError, TrafficSuite, TrafficSuiteStorage,
    TrafficTestService, TrafficTestSubmissionError, map_submission, validate_default,
};

impl<S: TrafficSuiteStorage> TrafficTestService<S> {
    pub(super) fn finish_job(
        &mut self,
        kind: JobKind,
        output: Result<JobOutput<S::Version>, tokio::task::JoinError>,
    ) -> TrafficServiceEvent {
        if output.is_err() {
            self.worker_failed = true;
        }
        match kind {
            JobKind::Load(token) => {
                let result = match output {
                    Ok(JobOutput::Storage(result)) => result,
                    _ => Err(TrafficStorageError::WorkerFailed),
                };
                self.finish_load(token, result)
            }
            JobKind::Save { draft, persisted } => {
                let result = match output {
                    Ok(JobOutput::Storage(result)) => result,
                    _ => Err(TrafficStorageError::WorkerFailed),
                };
                self.finish_save(draft, &persisted, result)
            }
            JobKind::Index(context) => {
                if self.workspace.active_context() != Some(&context) {
                    return TrafficServiceEvent::ObsoleteIndex;
                }
                if self.closing || self.coordinator_closed {
                    let _ = self
                        .workspace
                        .resolve_submission_failure(context, &TrafficTestSubmissionError::Closed);
                    return TrafficServiceEvent::EvaluationSubmitted(Err(
                        TrafficServiceError::Closed,
                    ));
                }
                let Ok(JobOutput::Index(Ok(request))) = output else {
                    self.fail_worker(context);
                    return TrafficServiceEvent::Evaluation(Ok(()));
                };
                let result = self.coordinator.try_evaluate(*request);
                if let Err(error) = &result {
                    let _ = self.workspace.resolve_submission_failure(context, error);
                    if *error == TrafficTestSubmissionError::Closed {
                        self.coordinator_closed = true;
                    }
                }
                TrafficServiceEvent::EvaluationSubmitted(
                    result.map_err(|error| map_submission(&error)),
                )
            }
        }
    }

    fn finish_load(
        &mut self,
        token: SuiteLoadToken,
        result: Result<LoadedTrafficSuite<S::Version>, TrafficStorageError>,
    ) -> TrafficServiceEvent {
        let result = result.and_then(|loaded| {
            if let LoadedTrafficSuite::Available { suite, .. } = &loaded {
                validate_default(suite)?;
            }
            Ok(loaded)
        });
        let (outcome, expected) = match &result {
            Ok(LoadedTrafficSuite::Missing) => (
                SuiteLoadOutcome::Missing,
                Some(TrafficSaveExpectation::Missing),
            ),
            Ok(LoadedTrafficSuite::Available { suite, fingerprint }) => (
                SuiteLoadOutcome::Available(Arc::clone(suite)),
                Some(TrafficSaveExpectation::Existing {
                    revision: suite.revision,
                    fingerprint: fingerprint.clone(),
                }),
            ),
            Ok(LoadedTrafficSuite::UnsupportedSchema(version))
            | Err(TrafficStorageError::UnsupportedSchema(version)) => {
                (SuiteLoadOutcome::UnsupportedSchema(*version), None)
            }
            Err(error) => (
                SuiteLoadOutcome::Failed(if *error == TrafficStorageError::InvalidSuite {
                    SuiteLoadFailure::InvalidSuite
                } else {
                    SuiteLoadFailure::Storage
                }),
                None,
            ),
        };
        if self.workspace.finish_load(token, outcome) {
            self.expected = expected;
        }
        TrafficServiceEvent::Loaded(result.map(|_| ()))
    }

    fn finish_save(
        &mut self,
        draft: Arc<TrafficSuite>,
        persisted: &TrafficSuite,
        result: Result<LoadedTrafficSuite<S::Version>, TrafficStorageError>,
    ) -> TrafficServiceEvent {
        let result = result.and_then(|loaded| match loaded {
            LoadedTrafficSuite::Available { suite, fingerprint }
                if suite.as_ref() == persisted && validate_default(&suite).is_ok() =>
            {
                Ok((suite, fingerprint))
            }
            _ => Err(TrafficStorageError::WorkerFailed),
        });
        match result {
            Ok((suite, fingerprint)) => {
                let old = self.workspace.active_context().cloned();
                if self.workspace.replace_suite(Arc::clone(&suite)).is_err() {
                    return self.failed_save(draft, TrafficStorageError::WorkerFailed);
                }
                self.expected = Some(TrafficSaveExpectation::Existing {
                    revision: suite.revision,
                    fingerprint,
                });
                self.save = TrafficSaveState::Saved(suite);
                TrafficServiceEvent::Saved {
                    result: Ok(()),
                    cancellation_error: self.cancel(old).err(),
                }
            }
            Err(error) => self.failed_save(draft, error),
        }
    }
    fn failed_save(
        &mut self,
        draft: Arc<TrafficSuite>,
        error: TrafficStorageError,
    ) -> TrafficServiceEvent {
        self.expected = None;
        self.save = TrafficSaveState::Failed { draft, error };
        TrafficServiceEvent::Saved {
            result: Err(error),
            cancellation_error: None,
        }
    }
}
