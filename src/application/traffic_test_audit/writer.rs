use super::{
    EvaluationContext, TrafficAuditError, TrafficAuditOutcome, TrafficAuditSink,
    TrafficAuditStatus, TrafficAuditSummary, TrafficTestReport, timestamp,
};
use std::sync::Arc;
use std::{collections::VecDeque, time::Instant};

pub(crate) const CAPACITY: usize = 64;
struct Accepted {
    context: EvaluationContext,
    total: usize,
    started: Instant,
}
pub(crate) struct AuditWriter {
    sink: Option<Arc<dyn TrafficAuditSink>>,
    session: String,
    active: Option<Accepted>,
    future: usize,
    pending: VecDeque<TrafficAuditSummary>,
    job: Option<tokio::task::JoinHandle<Result<(), TrafficAuditError>>>,
    status: TrafficAuditStatus,
}

impl AuditWriter {
    pub(crate) fn new(sink: Option<Arc<dyn TrafficAuditSink>>) -> Self {
        static SESSION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        Self {
            sink,
            session: format!(
                "{}-{}-{}",
                std::process::id(),
                timestamp(),
                SESSION.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ),
            active: None,
            future: 0,
            pending: VecDeque::new(),
            job: None,
            status: TrafficAuditStatus::default(),
        }
    }
    pub(crate) const fn status(&self) -> TrafficAuditStatus {
        self.status
    }
    fn reserved(&self) -> usize {
        self.pending.len()
            + usize::from(self.job.is_some())
            + usize::from(self.active.is_some())
            + self.future
    }
    pub(crate) fn can_reserve_batch(&mut self, count: usize) -> bool {
        let available = self.sink.is_none()
            || self
                .reserved()
                .saturating_sub(self.future)
                .saturating_add(count)
                <= CAPACITY;
        self.status.backpressure = !available;
        available
    }
    pub(crate) fn reserve_batch(&mut self, count: usize) {
        self.future = if self.sink.is_some() { count } else { 0 };
    }
    pub(crate) fn release_batch(&mut self) {
        self.future = 0;
    }
    pub(crate) fn accept_reserved(&mut self, context: EvaluationContext, total: usize) {
        self.future = self.future.saturating_sub(1);
        self.accept(context, total);
    }
    pub(crate) fn accept(&mut self, context: EvaluationContext, total: usize) {
        if self.sink.is_some() {
            self.cancel(TrafficAuditOutcome::Superseded);
            self.active = Some(Accepted {
                context,
                total,
                started: Instant::now(),
            });
        }
    }
    pub(crate) fn cancel(&mut self, outcome: TrafficAuditOutcome) {
        if let Some(context) = self.active.as_ref().map(|active| active.context.clone()) {
            self.finish(&context, outcome, None);
        }
    }
    pub(crate) fn finish(
        &mut self,
        context: &EvaluationContext,
        outcome: TrafficAuditOutcome,
        report: Option<&TrafficTestReport>,
    ) {
        if self
            .active
            .as_ref()
            .is_none_or(|active| &active.context != context)
        {
            return;
        }
        if let Some(active) = self.active.take() {
            self.pending.push_back(TrafficAuditSummary::new(
                &self.session,
                active.context,
                active.total,
                active.started.elapsed(),
                outcome,
                report,
            ));
        }
        self.start();
    }
    fn start(&mut self) {
        if self.job.is_none()
            && let Some(sink) = &self.sink
            && let Some(record) = self.pending.pop_front()
        {
            let sink = Arc::clone(sink);
            self.job = Some(tokio::task::spawn_blocking(move || sink.append(&record)));
        }
    }
    pub(crate) fn has_work(&self) -> bool {
        self.job.is_some() || !self.pending.is_empty()
    }
    pub(crate) async fn next_event(&mut self) -> Result<(), TrafficAuditError> {
        self.start();
        let result = match self.job.as_mut() {
            Some(job) => job.await.unwrap_or(Err(TrafficAuditError::WorkerFailed)),
            None => std::future::pending().await,
        };
        self.job = None;
        if let Err(error) = result {
            self.status.failure.get_or_insert(error);
        }
        self.status.backpressure = false;
        self.start();
        result
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct MemorySink(Mutex<Vec<String>>);
    impl TrafficAuditSink for MemorySink {
        fn append(&self, record: &TrafficAuditSummary) -> Result<(), TrafficAuditError> {
            self.0.lock().unwrap().push(record.to_json()?);
            Ok(())
        }
    }
    #[tokio::test]
    async fn accepted_terminal_is_written_once_and_late_events_cannot_change_identity() {
        let sink = Arc::new(MemorySink::default());
        let mut writer = AuditWriter::new(Some(sink.clone()));
        let context = crate::application::traffic_test_audit::tests::context();
        writer.accept(context.clone(), 9);
        writer.finish(&context, TrafficAuditOutcome::Shutdown, None);
        writer.finish(&context, TrafficAuditOutcome::WorkerFailed, None);
        writer.next_event().await.unwrap();
        let records = sink.0.lock().unwrap();
        assert_eq!(records.len(), 1);
        let record: serde_json::Value = serde_json::from_str(&records[0]).unwrap();
        assert_eq!(record["known_total"], 9);
        assert_eq!(record["counts"], serde_json::Value::Null);
        assert_eq!(record["outcome"], "cancelled");
        assert_eq!(record["reason"], "shutdown");
        assert_eq!(record["context"], serde_json::to_value(context).unwrap());
    }
    #[tokio::test]
    async fn traffic_preview_batch_reserves_future_without_phantom_completion() {
        let sink = Arc::new(MemorySink::default());
        let mut writer = AuditWriter::new(Some(sink.clone()));
        assert!(writer.can_reserve_batch(4));
        writer.reserve_batch(4);
        assert_eq!(writer.reserved(), 4);
        let context = crate::application::traffic_test_audit::tests::context();
        writer.accept_reserved(context.clone(), 1);
        assert_eq!(writer.reserved(), 4);
        writer.cancel(TrafficAuditOutcome::StaleContext);
        writer.release_batch();
        assert_eq!(writer.reserved(), 1);
        writer.finish(&context, TrafficAuditOutcome::Completed, None);
        writer.next_event().await.unwrap();
        assert_eq!(sink.0.lock().unwrap().len(), 1);
    }
    #[tokio::test]
    async fn traffic_preview_batch_backpressure_accounts_for_all_runs() {
        let sink = Arc::new(MemorySink::default());
        let mut writer = AuditWriter::new(Some(sink));
        let context = crate::application::traffic_test_audit::tests::context();
        for _ in 0..CAPACITY - 3 {
            writer.accept(context.clone(), 1);
            writer.finish(&context, TrafficAuditOutcome::Completed, None);
        }
        assert!(!writer.can_reserve_batch(4));
        assert!(writer.can_reserve_batch(3));
        while writer.has_work() {
            writer.next_event().await.unwrap();
        }
    }
}
