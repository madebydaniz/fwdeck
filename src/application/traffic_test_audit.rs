//! Privacy-minimized application lifecycle audit, separate from deterministic reports.

use crate::domain::{EvaluationContext, TrafficTestReport, TrafficTestSummary, UnknownReason};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
pub(crate) mod writer;

/// Hard serialized budget, excluding the JSONL newline.
pub const MAX_TRAFFIC_AUDIT_BYTES: usize = 16 * 1024;

/// Stable failures without paths, panic payloads, or operating-system messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TrafficAuditError {
    /// Another process owns the private write transaction.
    #[error("traffic audit writer is busy; a record could not be persisted")]
    Busy,
    /// The private path cannot be resolved or safely opened.
    #[error("traffic audit storage unavailable or unsafe")]
    Storage,
    /// Append, synchronization, rotation, or retention failed.
    #[error("traffic audit persistence failed; a record may be missing")]
    Persistence,
    /// An owned writer terminated unexpectedly.
    #[error("traffic audit writer failed; a record may be missing")]
    WorkerFailed,
    /// Typed serialization exceeded the fixed budget.
    #[error("traffic audit record exceeds its safe budget")]
    RecordTooLarge,
}

/// Persistent audit health, independent of transient presentation errors.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TrafficAuditStatus {
    /// First unacknowledged gap; subsequent successes cannot erase it.
    pub failure: Option<TrafficAuditError>,
    /// Admission was rejected until a reserved slot is released.
    pub backpressure: bool,
}

/// Bounded application terminal classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrafficAuditOutcome {
    /// A complete report passed workspace identity and content guards.
    Completed,
    /// Newer accepted evaluation replaced this run.
    Superseded,
    /// Authoritative target, observation, or suite changed.
    StaleContext,
    /// Application ownership ended.
    Shutdown,
    /// Coordinator admission was busy after application acceptance.
    Busy,
    /// Coordinator ownership ended.
    Closed,
    /// Evaluation exceeded its bounded deadline.
    EvaluationLimitExceeded,
    /// Domain evaluation failed; original text is deliberately discarded.
    EvaluationFailed,
    /// Worker or index construction failed.
    WorkerFailed,
    /// A report failed the workspace contract.
    MalformedReport,
}

#[derive(Debug, serde::Serialize)]
struct UnknownCount {
    reason: UnknownReason,
    count: u32,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum TerminalOutcome {
    Completed,
    Cancelled,
    Failed,
}

/// Fixed allowlist: no scenario inputs, names, notes, traces, or error text.
#[derive(Debug, serde::Serialize)]
pub struct TrafficAuditSummary {
    schema: u8,
    kind: &'static str,
    application_version: &'static str,
    session: String,
    timestamp_unix_ms: u128,
    context: EvaluationContext,
    outcome: TerminalOutcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<TrafficAuditOutcome>,
    elapsed_ms: u64,
    known_total: u32,
    counts: Option<TrafficTestSummary>,
    unknown_reasons: Vec<UnknownCount>,
    configuration_only: bool,
    live_connectivity_verified: bool,
}

impl TrafficAuditSummary {
    pub(crate) fn new(
        session: &str,
        context: EvaluationContext,
        total: usize,
        elapsed: Duration,
        outcome: TrafficAuditOutcome,
        report: Option<&TrafficTestReport>,
    ) -> Self {
        let mut unknown_reasons: Vec<UnknownCount> = Vec::new();
        if let Some(report) = report {
            for reason in report
                .results()
                .iter()
                .filter_map(crate::domain::TrafficTestResult::unknown_reason)
            {
                if let Some(group) = unknown_reasons
                    .iter_mut()
                    .find(|group| group.reason == reason)
                {
                    group.count += 1;
                } else {
                    unknown_reasons.push(UnknownCount { reason, count: 1 });
                }
            }
        }
        Self {
            schema: 1,
            kind: "configuration_evaluation",
            application_version: env!("CARGO_PKG_VERSION"),
            session: session.to_owned(),
            timestamp_unix_ms: timestamp(),
            context,
            outcome: match outcome {
                TrafficAuditOutcome::Completed => TerminalOutcome::Completed,
                TrafficAuditOutcome::Superseded
                | TrafficAuditOutcome::StaleContext
                | TrafficAuditOutcome::Shutdown => TerminalOutcome::Cancelled,
                _ => TerminalOutcome::Failed,
            },
            reason: (outcome != TrafficAuditOutcome::Completed).then_some(outcome),
            elapsed_ms: u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
            known_total: u32::try_from(total).unwrap_or(u32::MAX),
            counts: report.map(TrafficTestReport::summary),
            unknown_reasons,
            configuration_only: true,
            live_connectivity_verified: false,
        }
    }

    /// Serializes the only payload accepted by a durable sink.
    pub fn to_json(&self) -> Result<String, TrafficAuditError> {
        let line = serde_json::to_string(self).map_err(|_| TrafficAuditError::RecordTooLarge)?;
        if line.len() > MAX_TRAFFIC_AUDIT_BYTES {
            return Err(TrafficAuditError::RecordTooLarge);
        }
        Ok(line)
    }
}

/// Synchronous durability port; service ownership moves calls off the UI thread.
pub trait TrafficAuditSink: Send + Sync + 'static {
    /// Returns success only after the accepted record has been persisted.
    fn append(&self, summary: &TrafficAuditSummary) -> Result<(), TrafficAuditError>;
}

fn timestamp() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub(crate) mod tests {
    use crate::domain::*;

    #[test]
    fn terminal_outcome_and_reason_are_independent_stable_fields() {
        use super::{TrafficAuditOutcome as O, TrafficAuditSummary};
        for (code, outcome, reason) in [
            (O::Completed, "completed", None),
            (O::Shutdown, "cancelled", Some("shutdown")),
            (O::Superseded, "cancelled", Some("superseded")),
            (O::StaleContext, "cancelled", Some("stale_context")),
            (O::WorkerFailed, "failed", Some("worker_failed")),
        ] {
            let summary = TrafficAuditSummary::new(
                "test",
                context(),
                2,
                std::time::Duration::from_millis(10),
                code,
                None,
            );
            let value: serde_json::Value =
                serde_json::from_str(&summary.to_json().unwrap()).unwrap();
            assert_eq!(value["outcome"], outcome);
            assert_eq!(
                value.get("reason").and_then(serde_json::Value::as_str),
                reason
            );
        }
    }

    #[test]
    fn terminal_summary_retains_counts_and_identity_without_scenario_data() {
        let context = context();
        let report = TrafficTestReport::new(
            context.clone(),
            vec![
                TrafficTestResult::new(
                    TrafficScenarioId::parse("private-scenario-marker").unwrap(),
                    TrafficExpectation::Allow,
                    FirewallDecision::Unknown,
                    Some(UnknownReason::IncompleteSnapshot),
                    Vec::new(),
                )
                .unwrap(),
            ],
        )
        .unwrap();
        let value = summary_fixture(&report);
        assert_eq!(value["kind"], "configuration_evaluation");
        assert_eq!(value["context"], serde_json::to_value(context).unwrap());
        assert_eq!(value["elapsed_ms"], 25);
        assert_eq!(value["counts"]["total"], 1);
        assert_eq!(value["counts"]["indeterminate"], 1);
        assert_eq!(value["unknown_reasons"][0]["reason"], "incomplete_snapshot");
        assert_eq!(value["unknown_reasons"][0]["count"], 1);
        assert_eq!(value["live_connectivity_verified"], false);
        assert!(!value.to_string().contains("private-scenario-marker"));
        let keys: std::collections::BTreeSet<_> = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            [
                "schema",
                "kind",
                "application_version",
                "session",
                "timestamp_unix_ms",
                "context",
                "outcome",
                "elapsed_ms",
                "known_total",
                "counts",
                "unknown_reasons",
                "configuration_only",
                "live_connectivity_verified"
            ]
            .into_iter()
            .collect()
        );
    }

    #[test]
    fn fixed_record_budget_rejects_oversize_and_elapsed_saturates_safely() {
        let record = super::TrafficAuditSummary::new(
            &"x".repeat(super::MAX_TRAFFIC_AUDIT_BYTES),
            context(),
            1,
            std::time::Duration::MAX,
            super::TrafficAuditOutcome::Shutdown,
            None,
        );
        assert_eq!(record.elapsed_ms, u64::MAX);
        assert_eq!(
            record.to_json(),
            Err(super::TrafficAuditError::RecordTooLarge)
        );
    }

    pub(crate) fn context() -> EvaluationContext {
        EvaluationContext {
            run_id: TrafficTestRunId::new(7).unwrap(),
            suite_id: TrafficSuiteId::parse("default").unwrap(),
            suite_revision: TrafficSuiteRevision::new(3).unwrap(),
            phase: EvaluationPhase::Current,
            target: EvaluationTarget::Runtime,
            authoritative_snapshot: EvaluationSnapshotIdentity::new(10, 4).unwrap(),
            base_snapshot: None,
            mutation_intent_id: None,
            plan_id: None,
            candidate_identity: None,
        }
    }

    fn summary_fixture(report: &TrafficTestReport) -> serde_json::Value {
        serde_json::from_str(
            &super::TrafficAuditSummary::new(
                "test-session",
                report.context().clone(),
                1,
                std::time::Duration::from_millis(25),
                super::TrafficAuditOutcome::Completed,
                Some(report),
            )
            .to_json()
            .unwrap(),
        )
        .unwrap()
    }
}
