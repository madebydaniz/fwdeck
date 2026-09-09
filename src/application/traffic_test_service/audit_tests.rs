use super::*;
use crate::application::traffic_test_audit::{
    TrafficAuditError, TrafficAuditSink, TrafficAuditSummary,
};

#[derive(Default)]
struct Sink(Mutex<Vec<String>>);
impl TrafficAuditSink for Sink {
    fn append(&self, record: &TrafficAuditSummary) -> Result<(), TrafficAuditError> {
        self.0.lock().unwrap().push(record.to_json()?);
        Ok(())
    }
}

#[tokio::test]
async fn shutdown_during_accepted_index_persists_exact_terminal_once() {
    let storage = Arc::new(MemoryStorage::available(suite(1)));
    let sink = Arc::new(Sink::default());
    let mut service = TrafficTestService::with_audit_sink(false, storage, sink.clone());
    load(&mut service).await;
    service.observe(observation(1)).unwrap();
    assert!(sink.0.lock().unwrap().is_empty());
    service.try_evaluate().unwrap();
    let context = service.workspace.active_context().unwrap().clone();
    service.shutdown().await.unwrap();
    service.shutdown().await.unwrap();
    let records = sink.0.lock().unwrap();
    assert_eq!(records.len(), 1);
    let record: serde_json::Value = serde_json::from_str(&records[0]).unwrap();
    assert_eq!(record["context"], serde_json::to_value(context).unwrap());
    assert_eq!(record["outcome"], "cancelled");
    assert_eq!(record["reason"], "shutdown");
    assert!(record["counts"].is_null());
}

#[tokio::test]
async fn accepted_failures_cancellations_and_malformed_reports_are_typed_and_exactly_once() {
    use crate::application::TrafficTestCancellationReason as Cancel;
    for (outcome, failure, cancellation) in [
        ("busy", Some(TrafficTestFailureReason::Busy), None),
        (
            "evaluation_limit_exceeded",
            Some(TrafficTestFailureReason::EvaluationLimitExceeded),
            None,
        ),
        (
            "evaluation_failed",
            Some(TrafficTestFailureReason::EvaluationFailed(
                "private-worker-error-marker".into(),
            )),
            None,
        ),
        (
            "worker_failed",
            Some(TrafficTestFailureReason::WorkerFailed),
            None,
        ),
        ("superseded", None, Some(Cancel::Superseded)),
        ("stale_context", None, Some(Cancel::StaleContext)),
        ("shutdown", None, Some(Cancel::Shutdown)),
    ] {
        let sink = Arc::new(Sink::default());
        let mut service = TrafficTestService::with_audit_sink(
            false,
            Arc::new(MemoryStorage::available(suite(1))),
            sink.clone(),
        );
        load(&mut service).await;
        service.observe(observation(1)).unwrap();
        service.try_evaluate().unwrap();
        let context = service.workspace.active_context().unwrap().clone();
        let event = if let Some(reason) = failure {
            TrafficTestEvent::EvaluationFailed {
                context: context.clone(),
                reason,
            }
        } else {
            TrafficTestEvent::EvaluationCancelled {
                context: context.clone(),
                reason: cancellation.unwrap(),
            }
        };
        assert!(matches!(
            service.ingest(event),
            TrafficServiceEvent::Evaluation(Ok(()))
        ));
        service.ingest(TrafficTestEvent::EvaluationFailed {
            context: context.clone(),
            reason: TrafficTestFailureReason::WorkerFailed,
        });
        service.shutdown().await.unwrap();
        let records = sink.0.lock().unwrap();
        assert_eq!(records.len(), 1);
        assert!(!records[0].contains("private-worker-error-marker"));
        let record: serde_json::Value = serde_json::from_str(&records[0]).unwrap();
        assert_eq!(record["reason"], outcome);
        assert_eq!(record["context"], serde_json::to_value(context).unwrap());
        assert!(record["counts"].is_null());
    }
}

struct BlockedSink {
    entered: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    release: Mutex<std::sync::mpsc::Receiver<()>>,
    records: Mutex<Vec<String>>,
    failed: bool,
}
impl TrafficAuditSink for BlockedSink {
    fn append(&self, record: &TrafficAuditSummary) -> Result<(), TrafficAuditError> {
        if let Some(entered) = self.entered.lock().unwrap().take() {
            entered.send(()).unwrap();
            self.release.lock().unwrap().recv().unwrap();
            if self.failed {
                return Err(TrafficAuditError::Persistence);
            }
        }
        self.records.lock().unwrap().push(record.to_json()?);
        Ok(())
    }
}

#[tokio::test(flavor = "current_thread")]
async fn blocked_audit_reservations_reject_without_identity_change_and_keep_local_work_live() {
    let (entered, waiting) = tokio::sync::oneshot::channel();
    let (release, blocked) = std::sync::mpsc::channel();
    let sink = Arc::new(BlockedSink {
        entered: Mutex::new(Some(entered)),
        release: Mutex::new(blocked),
        records: Mutex::new(Vec::new()),
        failed: false,
    });
    let mut service = TrafficTestService::with_audit_sink(
        false,
        Arc::new(MemoryStorage::available(suite(1))),
        sink.clone(),
    );
    load(&mut service).await;
    service.observe(observation(1)).unwrap();
    for n in 0..64 {
        service.try_evaluate().unwrap();
        let context = service.workspace.active_context().unwrap().clone();
        if n < 63 {
            service.ingest(TrafficTestEvent::EvaluationCancelled {
                context,
                reason: crate::application::TrafficTestCancellationReason::Superseded,
            });
        }
        let job = service.job.take().unwrap();
        let output = job.task.await;
        service.finish_job(job.kind, output);
    }
    waiting.await.unwrap();
    let evaluation = service.workspace.evaluation_state().clone();
    assert_eq!(
        service.try_evaluate(),
        Err(TrafficServiceError::AuditBackpressure)
    );
    assert_eq!(*service.workspace.evaluation_state(), evaluation);
    assert!(service.audit_status().backpressure);
    service.observe(observation(2)).unwrap();
    service.try_save(suite(1)).unwrap();
    while service.job.is_some() {
        service.next_event().await.unwrap();
    }
    assert!(matches!(service.save_state(), TrafficSaveState::Saved(_)));
    assert_eq!(
        service.shutdown().await,
        Err(TrafficServiceShutdownError::DeadlineExceeded)
    );
    release.send(()).unwrap();
    service.shutdown().await.unwrap();
    service.shutdown().await.unwrap();
    assert_eq!(sink.records.lock().unwrap().len(), 64);
}

#[tokio::test]
async fn native_completed_and_malformed_report_records_never_serialize_private_inputs() {
    for malformed in [false, true] {
        let sink = Arc::new(Sink::default());
        let mut suite = scenario_suite().as_ref().clone();
        suite.name = "private-suite-name-marker".into();
        suite.scenarios[0].name = "private-scenario-name-marker".into();
        let coordinator = if malformed {
            TrafficTestCoordinator::spawn_with_evaluator(Arc::new(MalformedEvaluator))
        } else {
            TrafficTestCoordinator::spawn()
        };
        let mut service = TrafficTestService::with_coordinator(
            false,
            Arc::new(MemoryStorage::available(Arc::new(suite))),
            coordinator,
        );
        service.audit =
            crate::application::traffic_test_audit::writer::AuditWriter::new(Some(sink.clone()));
        load(&mut service).await;
        service.observe(observation(1)).unwrap();
        service.try_evaluate().unwrap();
        let context = service.workspace.active_context().unwrap().clone();
        while service.workspace.active_context().is_some() {
            service.next_event().await.unwrap();
        }
        service.shutdown().await.unwrap();
        let records = sink.0.lock().unwrap();
        assert_eq!(records.len(), 1);
        for marker in [
            "private-suite-name-marker",
            "private-scenario-name-marker",
            "scenario_id",
            "trace",
            "source",
            "destination",
        ] {
            assert!(!records[0].contains(marker), "forbidden marker {marker}");
        }
        let record: serde_json::Value = serde_json::from_str(&records[0]).unwrap();
        assert_eq!(record["context"], serde_json::to_value(context).unwrap());
        assert_eq!(
            record["outcome"],
            if malformed { "failed" } else { "completed" }
        );
        assert_eq!(record["known_total"], 1);
        if malformed {
            assert!(record["counts"].is_null());
        } else {
            assert_eq!(record["counts"]["total"], 1);
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn supersede_load_target_observation_and_save_terminally_invalidate_once() {
    for trigger in ["supersede", "load", "target", "observe", "save", "closed"] {
        let sink = Arc::new(Sink::default());
        let mut service = TrafficTestService::with_audit_sink(
            false,
            Arc::new(MemoryStorage::available(suite(1))),
            sink.clone(),
        );
        load(&mut service).await;
        service.observe(observation(1)).unwrap();
        service.try_evaluate().unwrap();
        let old = service.workspace.active_context().unwrap().clone();
        let job = service.job.take().unwrap();
        let _ = job.task.await;
        match trigger {
            "supersede" => service.try_evaluate().unwrap(),
            "load" => {
                service.try_load().unwrap();
            }
            "target" => {
                service.set_target(EvaluationTarget::Permanent).unwrap();
            }
            "observe" => {
                service.observe(observation(2)).unwrap();
            }
            "save" => {
                service.try_save(suite(1)).unwrap();
                while service.job.is_some() {
                    service.next_event().await.unwrap();
                }
            }
            "closed" => service.close_coordinator(),
            _ => unreachable!(),
        }
        service.ingest(TrafficTestEvent::EvaluationFailed {
            context: old.clone(),
            reason: TrafficTestFailureReason::WorkerFailed,
        });
        service.shutdown().await.unwrap();
        let records = sink.0.lock().unwrap();
        assert_eq!(records.len(), if trigger == "supersede" { 2 } else { 1 });
        let record: serde_json::Value = serde_json::from_str(&records[0]).unwrap();
        assert_eq!(record["context"], serde_json::to_value(old).unwrap());
        assert_eq!(
            record["reason"],
            match trigger {
                "supersede" => "superseded",
                "closed" => "closed",
                _ => "stale_context",
            }
        );
    }
}

#[tokio::test]
async fn writer_failure_is_sticky_after_success_and_honest_on_shutdown() {
    let (entered, waiting) = tokio::sync::oneshot::channel();
    let (release, blocked) = std::sync::mpsc::channel();
    let sink = Arc::new(BlockedSink {
        entered: Mutex::new(Some(entered)),
        release: Mutex::new(blocked),
        records: Mutex::new(Vec::new()),
        failed: true,
    });
    let mut service = TrafficTestService::with_audit_sink(
        false,
        Arc::new(MemoryStorage::available(suite(1))),
        sink.clone(),
    );
    load(&mut service).await;
    service.observe(observation(1)).unwrap();
    service.try_evaluate().unwrap();
    service.clear_observation().unwrap();
    waiting.await.unwrap();
    release.send(()).unwrap();
    while service.audit_status().failure.is_none() {
        service.next_event().await.unwrap();
    }
    while service.job.is_some() {
        service.next_event().await.unwrap();
    }
    service.observe(observation(2)).unwrap();
    service.try_evaluate().unwrap();
    service.clear_observation().unwrap();
    assert_eq!(
        service.shutdown().await,
        Err(TrafficServiceShutdownError::AuditFailed)
    );
    assert_eq!(
        service.audit_status().failure,
        Some(TrafficAuditError::Persistence)
    );
    assert_eq!(sink.records.lock().unwrap().len(), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn accepted_index_and_submission_failures_always_have_typed_terminal_records() {
    for trigger in ["busy", "closed", "worker_failed"] {
        let sink = Arc::new(Sink::default());
        let mut service = TrafficTestService::with_audit_sink(
            false,
            Arc::new(MemoryStorage::available(suite(1))),
            sink.clone(),
        );
        load(&mut service).await;
        service.observe(observation(1)).unwrap();
        service.try_evaluate().unwrap();
        let context = service.workspace.active_context().unwrap().clone();
        let job = service.job.take().unwrap();
        let mut output = job.task.await;
        match trigger {
            "busy" => {
                for _ in 0..8 {
                    service.coordinator.try_invalidate(context.clone()).unwrap();
                }
            }
            "closed" => service.coordinator.shutdown().await.unwrap(),
            "worker_failed" => {
                output =
                    tokio::task::spawn_blocking(|| panic!("private-worker-panic-marker")).await;
            }
            _ => unreachable!(),
        }
        service.finish_job(job.kind, output);
        let shutdown = service.shutdown().await;
        if trigger == "worker_failed" {
            assert_eq!(shutdown, Err(TrafficServiceShutdownError::WorkerFailed));
        } else {
            shutdown.unwrap();
        }
        let records = sink.0.lock().unwrap();
        assert_eq!(records.len(), 1);
        assert!(!records[0].contains("private-worker-panic-marker"));
        let value: serde_json::Value = serde_json::from_str(&records[0]).unwrap();
        assert_eq!(value["outcome"], "failed");
        assert_eq!(value["reason"], trigger);
        assert_eq!(value["context"], serde_json::to_value(context).unwrap());
    }
}
